# ADR: Bounded outbound SCIM ownership and reconciliation

- Status: Proposed for review
- Date: 2026-10-03
- Bead: ast-dd1y.6.2
- Implementation: ast-dd1y.6.3

## Context

Inbound SCIM is a tenant/client-owned, DPoP-only profile with conditional writes.
The [Entra verification](../integrations/entra-scim-compatibility.md) establishes
that a generic native Entra connector cannot authenticate to it. Outbound
provisioning needs its own explicit authority, durable source/target identities,
and recovery rules; HTTP success alone cannot establish ownership.

The existing transactional outbox already claims bounded batches, preserves
ordering keys, retries transient failures and exposes redacted dead letters.
`QueuedEvent` and `OutboxEvent` live in the domain, PostgreSQL owns transactional
queueing, and the server registers one deliverer per event family. Existing
`HttpsPoster` shares the vetted DNS/address/TLS path with `HttpsClientUrlFetcher`.
It currently lacks the complete authenticated SCIM method/header/ETag contract;
that extension belongs in `server::outbound`, under [ADR-0006](0006-outbound-fetches-of-client-supplied-urls.md).
There is no existing connector catalogue, target mapping or automatic SCIM source
projection. These are implementation requirements, not currently supported APIs.

## Decision

The first supported target is **another explicitly enabled Asterius tenant**
using the current bounded SCIM v2 profile, private-key JWT client credentials and
DPoP. The configured target issuer must differ from the source tenant issuer.
This selects an interoperable, testable profile without changing inbound SCIM or
claiming generic SaaS/Entra support. Future targets require their own reviewed
profile and interoperability evidence.

A tenant admin explicitly creates a disabled connector, pins target issuer/client,
references a deployment-provided signing credential, previews its assignments,
and enables it. No discovery automatically enables a destination. Connector
setup/status, assignments, bounded reconciliation, dry-run and manual retry use
dedicated `admin.outbound_scim:read`/`:write` scopes and the corresponding browser
admin authority. Tenant routing and audit follow existing admin API enforcement.
Source users and groups are explicitly selected; there is no tenant-wide default
export or implicit role-to-group mapping.

### Ownership and identifiers

A connector has a server-generated UUID scoped to its source tenant. A persisted
assignment generation links `(tenant, connector, kind, source UUID)` to a target
UUID, last observed ETag, desired source generation and delivery state. Target
UUIDs are never derived from a response Location URL or user input. Successful
responses must identify the configured profile's UUID resource, correct SCIM
schema, expected externalId and owned immutable alias.

The first profile assigns immutable target aliases such as
`ast-<connector-short-id>-<source-uuid>-<assignment-generation-short-id>`.
The stable alias and a namespaced externalId are chosen and stored before the
first POST. Users use that alias as `userName`; Groups use it as `displayName`.
These are intentionally separate from mutable source display names. The local
console shows source names beside mappings. Retrying an uncertain create queries
only the exact alias filter, verifies the externalId, then records the existing
remote UUID. More than one match or a different externalId is an ownership
conflict. An object already present under another identity is never adopted.

ExternalId identifies the source tenant, connector, kind, source UUID and
assignment generation. Remote client ID is immutable while mappings exist;
changing the provisioning principal requires a separate connector and an explicit
handoff, not adoption or changing owners behind an existing mapping.

### Authoritative projection

| Resource | Source-authoritative target fields | Excluded authority |
| --- | --- | --- |
| User | immutable generated userName/externalId, one work email, active | passwords, authenticators, roles, grants, names/extensions unsupported by current profile |
| Group | immutable generated displayName/externalId, direct assigned active User members | application role bindings, nested groups, implicit group discovery |

Only local accounts/groups selected by the source tenant administrator are
eligible. The first profile refuses SCIM-owned source objects, preventing a
provisioned object from reflecting through another connector loop. Group members
must belong to the same source tenant and explicit User assignments. Selection is
bounded to 100 Users plus 100 Groups per connector and 100 selected direct members
per Group. Larger exports require a separately tested pagination/capacity profile.

Source disabled/locked/deleted Users project `active=false`; source absence or
removal from an assignment never means an unreviewed target DELETE. A target
administrator's security lock cannot be cleared, including the two-step
disable/reactivate case corrected in `ast-xxt7`. A conflict protecting that lock
stops the job and is visible to the source operator. SCIM outcomes never change
source passwords, credentials, account status, groups, consent or grants.

### Credentials and guarded URLs

Store an opaque credential reference and rotation generation, never private key
material, access tokens or DPoP keys in connector rows/outbox/audit/API responses.
The reference must resolve through a deployment-configured signing registry.
Each entry is pinned to its allowed source tenant, exact target issuer and client
ID, the exact target admin resource (`<issuer>/admin/api/v1`) and the derived SCIM
origin. Registry lookup takes this complete validated scope; it is never a generic
SecretRef/path/environment/network resolver. A connector must match every binding
before any signing or network call. Knowing another tenant's reference does not
authorize its use, even if the target principal or hostname happens to match.
A tenant cannot choose a filesystem path, environment name,
URL, KMS identity or arbitrary secret. Missing/revoked references fail closed.
Rotation switches the allowed reference/generation for the same target client,
invalidates cached tokens, and retries under the new key after the remote client
has registered its public key. No key is generated by the console.

Authenticate with fresh bounded private-key JWT assertions and fresh DPoP proofs,
correct issuer audience, method/absolute URL, unique jti and access-token hash.
Require `token_type=DPoP`, bounded positive expiry and the dedicated target
`admin.scim:read`/`:write` scopes for `<target issuer>/admin/api/v1`. Access tokens
and ephemeral DPoP keys remain in memory and are reacquired after restart. Handle
one bounded nonce/token refresh retry; never fall back to Bearer or weaken TLS.

The target issuer is canonical HTTPS with no userinfo/query/fragment. Derive only
`<issuer>/token` and `<issuer>/admin/api/v1/scim/v2` routes. All requests, including
authentication and reconciliation reads, use ADR-0006's guarded transport: validate
all resolved addresses, connect to a vetted address once, use the pinned hostname
for certificate verification, reject mixed/private/link-local/loopback answers,
and refuse redirects. Same-origin computed paths and validated UUIDs replace
remote Location links. Public origin changes require a disabled connector and
review; existing mappings cannot silently point to a new target.

Extend the existing guarded transport with bounded GET/POST/PUT/PATCH/DELETE,
Authorization, DPoP and If-Match/ETag/DPoP-Nonce headers. Bodies are at most 64 KiB;
headers and responses are bounded. A job has a total deadline below the outbox
lease and at most bounded authentication/nonce retries. Tests inject a controlled
transport; no private-address bypass ships in the server. Real interoperability
uses a disposable public HTTPS fixture with the same production guard.

### Delivery, retries and drift

Persist selected assignments and initial desired intents atomically with their
outbox rows. Local User/profile/status and Group/member changes mark existing
assignments dirty and enqueue `outbound_scim.*` intents in the same transaction.
The payload holds connector/source IDs and generation only; the deliverer reads
current authoritative source state instead of replaying stale credentials or
personal-data snapshots. Preserve mappings/tombstones across source deletion so
an intent can disable a previously provisioned target after its source row ends.

Use an ordering key per connector/resource assignment. Every create includes
its stable externalId. The supported Asterius target enforces uniqueness on
`(tenant, client, externalId)` for both Users and Groups inside the create
transaction; this target guarantee is part of the selected profile. An uncertain
request or overlapping expired lease can therefore result in one object and a
409, never two committed Groups with different UUIDs. On409, query the exact
alias, verify externalId and record the existing UUID; otherwise stop as a
conflict. DisplayName uniqueness alone is insufficient and is never assumed.

Persist each mapping before acknowledging its outbox event. A crash after remote
success is recovered by alias/externalId lookup. Mapping writes compare the
assignment incarnation and reject a different existing target UUID. Concurrent
source changes keep that incarnation's mapping and enqueue/reconcile its latest
desired state; a source disable occurring during create must still reach that
newly identified target. Do not hold a database transaction across network I/O.
Supporting a target without atomic externalId uniqueness requires a new reviewed
idempotency profile rather than assuming generic exactly-once SCIM delivery.
Groups wait for selected User mappings. Queue User dependencies under their own
ordering keys; never create an unbounded chain of remote Users inside one Group
lease. Group member PUT uses a complete bounded direct membership projection.
For updates, read the resource, verify its alias/externalId, and use the returned
ETag in If-Match. A successful response advances stored observed state. A 412
forces an explicit reconciliation/conflict decision; it never strips If-Match or
blindly forces a write. Drift in owned fields is shown in preview and repaired only
by an enabled source-authoritative reconciliation job with a newly observed ETag.

Retry network/429/5xx with the existing bounded outbox backoff; classify malformed
responses, ownership mismatch, unsupported schema, revoked credentials and
permission/security-lock refusals as operator-visible failures. A dead letter
contains only connector/job identifiers and fixed safe codes, never response
bodies, URLs/query strings, email, tokens or key data. Manual retry uses existing
outbox operations and re-evaluates current source state and current credentials.
Pausing a connector stops network delivery; resume explicitly reconciles dirty
assignments. There is no success receipt for work that was merely paused.

Manual dry-run authenticates with target read scope and performs bounded reads;
it never POSTs/PUTs/PATCHes/DELETEs a SCIM resource or stores a new remote mapping.
It returns resource identifiers, operation counts, changed field names and fixed
conflict codes, not credentials or arbitrary downstream diagnostics. Each
reconciliation page handles at most 25 assignments and has an explicit cursor;
periodic reconciliation has a bounded pace and complements transactional intents.

### Deprovision and disappearance

Default deprovision disables owned Users and removes them from owned Group member
sets. Retain the target account and mapping. Empty or unassigned Groups are
retained with empty membership. Connector disable/removal retains downstream
objects; it is never a cascading remote delete. Source deletion cannot silently
remove a downstream account. No bulk-delete endpoint is part of the first profile.

An explicit reviewed target-delete job may delete only an already disabled owned
User or empty owned Group after a fresh ownership check and current If-Match. The
operator must separately enable that connector's deletion policy and confirm the
specific mapped resource. Record a durable tombstone. An ambiguous delete retry
reads the saved target UUID:404 completes that same reviewed delete, while a
matching live object is retried conditionally. It never addresses a replacement
UUID. Source authority failures cannot authorize deletion.

A mapped target404 outside such a delete job is a conflict, not permission to
recreate/adopt. An explicit administrator recreate action starts a fresh persisted
assignment generation/alias and preserves the prior tombstone. No scheduled job
recreates a deleted target or revives a target security-locked account.

## Alternatives

- Native Entra first: observed Bearer incompatibility requires an additional auth
  decision; fails the current-profile requirement.
- Generic arbitrary SCIM: increases supported auth, schema, filter and conditional
  write variants without real interoperability evidence.
- External bridge: could support other clients, but introduces its own credential,
  retry and ownership boundary; keep it a separate reviewed integration.
- Username mirroring and target adoption: renames make uncertain creates ambiguous
  and could claim an existing employee; immutable aliases preserve bounded recovery.
- Immediate delete on unassignment: turns source outage/drift into irreversible
  downstream removal; default disable/retain preserves recovery.

## Normative sources and implementation gate

Relevant primary text: [RFC7644 authentication, create/query, update/delete and
resource versions](https://www.rfc-editor.org/rfc/rfc7644.html),
[RFC7523 client authentication assertions](https://www.rfc-editor.org/rfc/rfc7523.html),
[RFC9449 proof validation, access-token binding and nonce handling](https://www.rfc-editor.org/rfc/rfc9449.html).
This is a bounded implementation profile, not a claim of general SCIM conformance.
The existing inbound/FAPI and SSRF policies remain authoritative. The protocol's
normative review requirement must be recorded before claiming implementation
completion; a target is enabled only by its administrator after preview.

Acceptance of this decision selects the target, ownership and guardrails above.
Implementation must add the actual catalogue/domain ports/store/event producer,
guarded authenticated transport/worker, admin setup/status/recovery and real
source-to-target lifecycle fixture. Docs or a facade alone cannot close ast-dd1y.6.3.
