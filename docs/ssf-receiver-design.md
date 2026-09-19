# Post-v1 SSF receiver design

Status: design note only. Asterius v1 is an SSF transmitter, not a receiver.
This document records the boundary to re-evaluate after v1; it does not commit
an endpoint, configuration shape, database migration or conformance claim.

## Specification baseline

The receiver must be designed against the
[OpenID Shared Signals Framework 1.0](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
and the
[CAEP Interoperability Profile 1.0](https://openid.net/specs/openid-caep-interoperability-profile-1_0.html).
The interoperability profile has an approved Implementer's Draft 1. Its latest
published text is Draft 01; its proposed Final review was restarted in
September 2026 so that further changes could be made. The implementation must
therefore re-read the then-current text before work begins.

The first supported use case should be an upstream identity provider sending
`session-revoked` or `credential-change`. A verified signal may revoke local
sessions or grants, but it must never create or strengthen authority. Device
compliance and other event families remain later, explicit policy mappings.

## Existing boundaries to preserve

- `asterius-ssf` is an issuance-only protocol crate. It builds and signs SETs,
  but deliberately performs no I/O and accepts no incoming token. Receiver
  parsing and validation belong beside that code as a separate profile, not in
  an HTTP handler.
- `asterius-jose::verify` already separates compact-JWS verification policy
  from key resolution. A receiver-specific SET verifier should reuse that
  boundary with an upstream JWKS resolver. The `jsonwebtoken` verifier in
  `crates/ssf/tests/issuance.rs` is an independent interoperability test, not a
  production receiver.
- The transactional outbox is outbound delivery. An incoming SET is not an
  outbox row and must never enter it before verification. Receiver ingestion
  needs a durable inbox keyed by transmitter and `jti`. Once a SET is verified,
  the inbox record, local revocation, audit record, and any resulting existing
  outbox rows must commit in one database transaction.
- `SubjectResolver` maps Asterius users to identifiers for outgoing signals.
  Receiving needs the inverse operation, scoped to one configured upstream
  transmitter. It must not search every tenant or treat an email address as a
  globally authoritative account key.

## Proposed processing boundary

```text
push endpoint or poll worker
  -> bounded compact-JWS input
  -> receiver SET verifier + trusted upstream JWKS
  -> event and subject parser
  -> durable inbox / replay decision
  -> tenant-scoped subject mapping and event policy
  -> state mutation + audit + outbound outbox rows (one transaction)
  -> delivery acknowledgement
```

Transport code owns RFC 8935 push responses or RFC 8936 poll acknowledgements.
It hands an opaque compact JWS and the configured stream identity to the
protocol layer; it does not inspect claims to select a tenant, key or action.

### Stream establishment

Each upstream relationship is operator-configured and tenant-scoped. Store the
trusted transmitter issuer, metadata URL, stream identifier, expected receiver
audience, delivery method, OAuth client reference, status, and the subject
identifier formats and event types the tenant elected to process. Secrets use
the existing KEK-backed configuration pattern and never appear in logs.

The stream client obtains transmitter metadata over the repository's guarded
outbound HTTPS path, validates it as SSF 1.0 §7.2.4 requires, and uses OAuth
when calling stream-management APIs. The current interoperability profile
requires a receiver to:

- choose push or poll delivery;
- obtain signing keys from the metadata `jwks_uri`;
- create, read, verify and delete its stream, and read stream status;
- initiate stream verification and process the returned verification event;
- accept `email` and `iss_sub` subjects, plus `opaque` for verification.

The profile currently assumes subjects are implicitly included in a stream.
That differs from Asterius's transmitter choice of `default_subjects: NONE` and
is another reason not to reuse transmitter stream rows for receiver state.

### SET verification before effects

The receiver verifier must return a typed, verified SET. No caller may access
the event or subject from an unverified token. Its policy must at least:

1. bound the compact token, decoded header, claims and event object before
   expensive parsing or a network key lookup;
2. require `typ: secevent+jwt`, reject `alg: none`, and allow only the
   algorithms selected for this receiver profile;
3. resolve `kid` only against the `jwks_uri` obtained from the already trusted
   transmitter metadata, with guarded fetching, bounded caching and key
   refresh on an unknown `kid`;
4. verify the signature, then require `iss` to equal both the configured stream
   issuer and the issuer from which metadata was obtained;
5. require the configured receiver identifier in `aud`, reject `sub` and
   `exp`, and validate `iat`, `jti`, `txn`, `sub_id` and the single event shape;
6. parse all subject members, ignore unknown non-critical members, and discard
   the event if any critical member cannot be processed (SSF §3.6); and
7. expose the verified issuer, `jti`, event timestamp, event type, subject and
   payload without retaining or logging the compact token.

There is one known compatibility decision. Draft 01 of the interoperability
profile requires RS256 with a key of at least 2048 bits. ADR-0003 deliberately
excludes RS256 globally in favour of EdDSA, ES256 and PS256. Receiver work must
not quietly add RS256 or advertise interoperability-profile conformance. After
the profile becomes Final, decide explicitly whether to support RS256 only for
configured upstream SET verification, wait for a profile revision, or decline
that conformance target.

### Inbox, ordering and the existing outbox

Delivery is at least once. Insert `(tenant_id, transmitter_issuer, jti)` into a
receiver inbox under a unique constraint before applying an effect. A duplicate
that already reached a terminal result is acknowledged without running its
effect again. A concurrent duplicate loses the same insert race and observes
the recorded result; application-level read-then-write deduplication is not
sufficient.

Record the event type, stream, `iat`, event timestamp, processing outcome and a
bounded refusal code, but not the compact SET or raw personal identifiers. A
failed signature or issuer/audience check is not inserted as a trusted event;
rate-limited security telemetry records the refusal separately.

For one mapped subject, process by `event_timestamp` rather than arrival time.
An older event may be recorded as stale and acknowledged, but must not undo a
newer security state. When a verified event changes local state, the storage
adapter performs these steps in one transaction:

1. reserve the inbox identity;
2. lock and update the affected sessions, credentials or grants;
3. append the audit event naming the upstream transmitter and event type;
4. enqueue resulting local back-channel logout or SSF transmitter messages in
   the existing transactional outbox; and
5. mark the inbox row applied, ignored or refused.

This preserves the outbox's current guarantee: a committed local revocation
cannot lose the notifications it caused. It also avoids turning the outbox
worker into an inbound trust boundary or a replay engine for unverified SETs.

### Subject and event policy

Subject mapping is configured per upstream and tenant. `iss_sub` is the
preferred account key because it binds the upstream issuer to its subject.
Email mapping is permitted only when an operator explicitly trusts that
upstream to assert the tenant's normalized, verified email addresses; ambiguous
or absent matches are audited and acknowledged without an effect. The
verification event's `opaque` subject must equal the stream identifier and is
never mapped to a user.

The event policy is an allow-list of typed actions. Initial mappings should be:

- `session-revoked`: revoke the named mapped session, or all mapped sessions
  only when the event semantics and tenant policy explicitly say so;
- `credential-change`: revoke affected sessions and grants for compromise or
  removal cases selected by policy; never create a local credential from the
  event; and
- SSF verification: compare the returned `state` in constant time with the
  pending bounded nonce, mark the stream healthy, and perform no user action.

Unknown events are retained only as bounded outcome metadata and acknowledged;
they do not become generic commands. Unknown enum values inside a supported
event fail that event's policy mapping rather than inheriting the nearest local
action.

## Security and operational gates

- The push endpoint is authenticated by SET signature and stream binding, not
  by a claim read before verification. Apply endpoint and per-stream limits
  before cryptographic work.
- Metadata and JWKS fetching use the outbound-URL SSRF policy, TLS certificate
  validation, response-size limits, timeouts, and redirects disabled or
  revalidated at every hop.
- Keep last-known-good keys only within a bounded cache policy. An unknown
  `kid` permits one controlled refresh, not an unbounded fetch per request.
- Metrics label only tenant, configured transmitter and outcome; logs contain
  no SET, subject identifier, OAuth credential or JWKS URL query.
- Stream verification proves end-to-end delivery and SET validation. It does
  not prove that a user event maps to the intended local account, so subject
  mapping has separate integration tests and audit evidence.

## Re-evaluation and acceptance plan

Before implementation, re-check the Final interoperability profile, the SSF
errata, delivery RFCs, the algorithm conflict, and whether push or poll is the
smaller operable first slice. Then require tests for:

- valid and forged SETs, wrong `typ`, issuer, audience, `kid`, forbidden claims
  and critical subject members;
- JWKS rotation, guarded fetch failures and bounded refresh;
- duplicate and concurrent `jti` delivery, stale event ordering, and crash
  recovery around the inbox transaction;
- every supported subject mapping, including ambiguous email and cross-tenant
  isolation;
- verification-event `state` matching and stream health; and
- atomic local mutation plus existing outbox enqueueing.

Until those gates and the algorithm decision are complete, Asterius must
continue to describe itself as an SSF transmitter only.
