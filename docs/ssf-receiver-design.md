# Post-v1 SSF receiver design

Status: bounded push receiver and explicit operator-triggered upstream poll
stream setup in `ast-s36.26`. This is not a claim of full SSF or CAEP
Interoperability Profile conformance. The implementation accepts configured
OAuth client peers, three lifecycle event types, and operator-provisioned
per-peer subject mappings. Upstream subject enrollment, automatic polling,
and interoperability evidence remain outstanding.

## Specification baseline

The full receiver must be designed against the
[OpenID Shared Signals Framework 1.0 Final](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html)
and the
[CAEP Interoperability Profile 1.0](https://openid.net/specs/openid-caep-interoperability-profile-1_0.html).
The interoperability profile's latest published text is Draft 01 (1 September
2026). It still requires RS256 signatures, while ADR-0003 excludes RS256.
Re-read the then-current text before claiming interoperability conformance.

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

## Implemented push slice (`ast-s36.26`)

`POST /ssf/receiver` accepts a bounded compact SET. Its unverified `iss` is
used only to find an active tenant client that explicitly holds `ssf.receive`;
the signature verifier uses only that client's registered JWKS through the
existing guarded client-key cache. JWT-directed `jku` and `x5u` are rejected.
The receiver requires `secevent+jwt`, the pinned issuer, this receiver's
audience, `iat`, `jti`, `txn`, a valid `sub_id`, and exactly one supported
event. It rejects top-level `sub` and `exp` per the SET profile and accepts
tokens only within a five-minute `iat` window. The replay key is tenant,
configured peer and `jti`; the durable inbox insert and local action share one
database transaction.

The current actions are `session-revoked` with `ssf.receive` and
`account-disabled` with the additional `ssf.receive.account-disable` scope.
`account-enabled` is deliberately refused because a remote event must not
reverse a local administrative disable. Subjects never fall back to email or
username: an administrator binds a parsed RFC 9493 subject to a local user
through `PUT` or `DELETE /admin/ssf/receiver/subjects`, under
`admin.ssf:write`. The canonical identifier is not included in audit detail.

`credential-change` is accepted with `ssf.receive`: creation/update is recorded
without local credential mutation, while revoke/delete revokes sessions only.
The upstream credential identifier is never treated as a local credential
identifier. Events require a valid CAEP `event_timestamp`; older events are
durably marked stale and acknowledged without applying an action. Ordering is
tracked per tenant, peer and canonical subject binding, independently of
bounded replay tombstones. A timestamp more than ten seconds ahead of the
receiver clock is rejected before it can become the subject's ordering high-water mark. For each
of the ten standard CAEP credential types, `create` and `update` are observe-only;
`revoke` and `delete` revoke local sessions. Unknown type and change values are
rejected, and no inbound event writes local credential records. These verified
actions and audit-chain records share a transaction with the durable inbox.

Configured peers now have bounded metadata discovery with exact issuer and
registered JWKS URI checks. The metadata cache retains the validated
configuration/status endpoints and delivery methods. A tenant-scoped table can
record the exact upstream stream identity and its pinned endpoints, and a
response validator refuses a stream with a changed issuer, audience, event
set, or delivery method. By default it requires `default_subjects: NONE`.
An operator can set `allow_all_subjects = true` on that configured peer to
accept `default_subjects: ALL`; this expressly permits delivery for every
subject the transmitter considers eligible. Setup, readback and polling
recheck the discovered metadata against this policy. A `NONE` stream still
needs separate subject enrollment at the transmitter before it can deliver
user events.

An operator may now configure `tenant.ssf_upstream_peer` with a canonical
issuer, a bearer token file, and an optional exact `expected_audience` pin for
outbound OAuth management. The receiver omits transmitter-owned `aud` from
stream creation and validates the returned value against the pin (defaulting
to this tenant's `/ssf/receiver` URL); that same value is pinned for later SETs.
The credential
is read only for an explicit management call and is sent only to same-origin
configuration and status endpoints retained from verified metadata, through
the guarded HTTPS transport. The create service checks a 201 JSON stream
configuration, then a 200 JSON status response for the exact stream ID before
recording the stream. A durable, tenant-scoped setup intent commits before the
remote POST. A retry reads the authenticated configuration list and adopts
only a single stream whose issuer, audience, event set and poll delivery match
the intent; it never sends a second POST. Ambiguous or empty retry lists leave
the intent pending for operator review. Stream persistence and intent removal
commit in one local transaction. Authenticated admin operations now expose
configured peers, pending review, setup and an explicit one-shot poll. Polling
validates at most one bounded SET, applies it before ACK, and reports
classifiable invalid SETs with RFC 8936 `setErrs`. Queued SETs have a local
seven-day age limit; push keeps five minutes. There is no automatic poll worker
or outbound subject-enrollment call. Explicit upstream deletion writes a
durable pending marker before the guarded DELETE with the exact stream ID.
An interrupted call reads the authenticated remote stream list on retry; only
the absence of the exact recorded stream ID permits local removal. Other
streams managed by the same credential do not block verification or deletion
of this recorded stream. Readback still validates the recorded stream's pins
and refuses malformed or duplicate stream identities, since such a list cannot
prove absence safely. Pending-create reconciliation remains conservative: it
requires a single matching stream because the new stream ID is not yet known. While deletion is pending, new polls are
refused and peer summaries expose `deletion_pending`. The admin operation is
`POST /ssf/upstream/delete` with the configured `peer_client_id` and
`admin.ssf:write` authority.
`POST /ssf/upstream/request-verification` first checks the pinned stream,
stores a 15-minute hash of a random correlation state, then asks the
transmitter to send an asynchronous verification SET. The one-shot poll checks
the signed event's opaque stream subject and state before recording health and
ACKing; duplicate JTIs remain ACKable for the seven-day replay window.
`last_verified_at` records any valid verification SET. A transmitter may send
one without a `state`; that proves liveness but leaves a receiver challenge
pending. Only a matching state advances `last_challenge_verified_at`, which is
also visible in the peer summary. An incorrect state is reported as
`invalid_state`, without a user lifecycle effect.
Pending intents and established stream identities survive local client
deletion, so re-registering the same issuer cannot erase the evidence of a
remote stream that may still exist.
The token file is re-read for each operation but has no automatic OAuth refresh;
operators must rotate it before expiry and retain the upstream peer config,
its active `ssf.receive` client registration, and the credential until the
remote stream is deleted. A removed peer cannot safely
authorize or validate cleanup from the retained tombstone alone. Neither inbound `ssf.receive` scope nor
a peer's registered signing key authorizes outbound management. Explicit
subject enrollment and the complete CAEP event vocabulary remain incomplete.
Local lifecycle,
audit, and resulting outbound notifications now commit atomically. The CAEP
Interoperability Profile's RS256 requirement remains unresolved against
ADR-0003; this receiver accepts only EdDSA and ES256 and makes no profile
conformance claim.

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

Draft 01 requires Receivers to assume every subject is implicitly in the
stream, without Add Subject calls (§2.4.4). Asterius permits upstream
`default_subjects: ALL` only when that peer has `allow_all_subjects = true`.
Without it, setup accepts `NONE`, for which an operator must separately enroll
subjects at the transmitter. The receiver still makes no outbound Add Subject
call and has no end-to-end verification evidence, so no interoperability claim
follows from this opt-in alone.

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

Until those gates and the algorithm decision are complete, describe Asterius as
an SSF transmitter with a bounded, operator-controlled receiver slice, without
claiming CAEP Interoperability Profile conformance.

## Conformance audit, 26 September 2026

- The transmitter's `spec_version: 1_0`, issuer, JWKS URL, OAuth scheme and
  operational push/poll endpoint advertisement are generated from mounted
  routes. Empty `critical_subject_members` is omitted as required by
  [SSF 1.0 Final §7.2.3](https://openid.net/specs/openid-sharedsignals-framework-1_0-final.html).
- Receiver setup validates pinned issuer and JWKS, then creates and checks one
  poll stream through guarded HTTPS. A configured poll-only peer need not
  advertise push; push delivery from that peer is refused. The validator still
  requires several metadata fields that SSF Final does not universally
  require, so it supports a narrower peer profile. No cross-implementation
  setup or delivery result has been recorded. An authenticated operator can
  read back a recorded upstream poll stream, requiring the exact pinned
  metadata, stream identity, delivery endpoint, audience, event set and status
  ID. The check is read-only and currently refuses transmitter lists with
  more than one stream for that receiver.
- [CAEP Interoperability Profile Draft 01 §2.6](https://openid.net/specs/openid-caep-interoperability-profile-1_0.html)
  requires RS256. ADR-0003 excludes it, and incoming SET verification accepts
  EdDSA and ES256 only. `ast-s36.26.4.8` owns the explicit policy decision.
- Draft 01 §2.4.4 assumes implicit inclusion of all subjects. Operators may
  explicitly allow upstream `default_subjects: ALL`; `NONE` still needs
  external enrollment. Outbound subject enrollment remains absent. The static bearer
  file is re-read per operator request, but access-token acquisition and
  automatic refresh are outside this explicit operator-managed peer profile.
  No cross-implementation verification or delivery evidence has been recorded.
