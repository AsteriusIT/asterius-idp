# Kubernetes online candidate preparation

The proposed ADR remains under its existing human review. The candidate domain
parser is not exported, no endpoint/profile is enabled, and its tests have not
compiled or run. Only the controlled Go zero-value wire-shape reproduction has
executed; that is not Kubernetes authentication acceptance.

The closed TokenReview request bounds are 65536 JSON bytes, 16384 opaque token
bytes, and 1–16 distinct nonempty audiences of at most 2048 bytes. Unsupported
version/kind, duplicate known keys, unknown fields and populated input status
fail generically without echoing input. Actual Kubernetes zero metadata and
`status.user:{}` are discarded as wire scaffolding. The credential uses
`Secret<String>` (redacted Debug, zeroize on drop); requests have no Serialize
implementation. Responses have no spec, token, arbitrary extra or email and
return only the independently pinned route audience. A parsed request or a
response constructor establishes no source/token/identity authority.

## Issuance-established digest binding (migration 0160 reserved)

| Field | Required source |
| --- | --- |
| Tenant and human client | Exact routed tenant and approved current cluster registration |
| SHA-256 compact-token digest (`bytea`, exactly 32 bytes) | Entire successfully signed compact ID token that will actually be returned; never payload/header-only or a JWT-supplied identifier |
| Grant ID and local user | Exact `ClaimedGrant` and corresponding authoritative current grant, never another active grant for the user |
| Public session ID | Issuance's stable public `sid`, matching that exact grant/session/user; never the rotating secret lookup digest |
| Signed subject and issued/expiry timestamps | Exact server-signed ID token; expiry must be current and lifetime at most 300 seconds |
| Current profile/reviewer association | Selected same-tenant online profile and distinct confidential FAPI reviewer; current configuration remains authoritative at review |

Primary identity is `(tenant_id, token_digest)`. Binding expiry follows the token;
tenant/client deletion cascades; no raw JWT, invented JTI or complete token
claims are persisted. A conflicting digest association is refused, never
rewritten to another grant. Old unbound offline tokens cannot be enrolled by a
review request. Opt-in requires a fresh login. Online human tokens are plaintext
ES256 compact JWS; `encrypt_id_token` cannot enable an unverifiable JWE profile.

Only successful signature completion may establish a binding, and storage must
succeed before releasing the token response. Both authorization-code and refresh
ID-token paths must pass this same boundary. Unsupported ID-token paths must
fail closed. Use the supplied `PolicyPublicationFence` PostgreSQL connection
for parent/current-state checks and insert, not a second held-transaction pool
checkout. The existing prepared signing key/decorator/admission behavior stays
intact. A failed binding insert refuses online issuance rather than returning an
unbound credential. No protocol claim is added.

## Live review boundary

The complete route deadline is three seconds, covering route/tenant lookup,
reviewer authentication, cryptographic verification, lock waits and authoritative
primary-database reads. A three-second query-only timeout is insufficient.
Authenticated cluster mTLS transport selects the route/pins; token claims and
request audiences cannot select a tenant, human registration or reviewer.
Independent reviewer authentication retains the selected FAPI client-credentials,
private-key JWT and DPoP requirements. No positive identity cache is added.

Verify the token's issuer, ES256, exact single human audience, five-minute
lifetime, expiry and subject before accepting its digest binding. Under the
provided current-state connection, require active tenant/client/profile/user,
that exact live grant and the same stable public session ID for that user/client.
Check time after lock/context waits. Read sessions directly; never call
`record_use`, extend idle deadlines, rotate lookup credentials or create state.
Session rotation preserves the public identity; logout/disable/revocation deny.
Another active grant/session cannot repair a revoked binding. Release groups
only from signed groups intersected with the current profile allow-list and
current directory membership; adding a group cannot widen a held token.

The optional `.5.3` JIT principal alias profile changes username/group semantics.
Online review plus JIT on one profile must remain unsupported and fail closed
until its separate composition is explicitly reviewed. Returning ordinary
baseline groups for a JIT principal would silently change authority and is not
an acceptable fallback.

The inner webhook cache is disabled (`0s`). Kubernetes 1.35 retains a global
10-second success cache and a detached 30-second upstream lookup/HTTP timeout.
An already successful response delayed in transport can populate that cache
after revocation; the conservative bound is 40 seconds plus measured scheduling
and transport margin. The adapter's local 3-second deadline does not establish a
shorter wire-level bound. This source-derived bound is not measured evidence.
Multiple identical stateless adapters need verified TLS and
primary-backed Asterius replicas; all-replica outage yields no new uncached
identity. Remove this profile's equivalent native offline OIDC authenticator,
otherwise the offline path bypasses live revocation.

## Required future acceptance

| Boundary | Control (all not_run) |
| --- | --- |
| Wire | Actual Kubernetes 1.35 serialized v1 request accepted; beta/wrong kind/malformed/status injection/duplicate fields/limits refused |
| Route authority | Wrong cluster certificate pin, issuer, tenant, human audience, reviewer, delegated reviewer and missing requested audience deny |
| Exact issuance | Code + refresh bind the returned complete token; missing session/store failure refuses release; unbound old token cannot enroll |
| Grant/session | Revoke one of two same-user grants; held token for revoked grant denies; other legitimate grant remains valid; rotation preserves stable public sid; logout denies |
| Groups | Current removal immediately narrows uncached groups; later additions never widen old signed release; JIT composition fails closed |
| Availability | Entire-route timeout, primary DB outage, bad upstream response and all adapter replicas unavailable deny without stale identity |
| Freshness | Real disposable Kubernetes 1.35 + kubectl records native configured cache and held-token disable/revoke denial latency; no instant/offline revocation claim |
| Side effects/privacy | Repeated review does not change session activity/expiry, create grants, log raw token or echo request status/spec |

Only after candidate implementation, coordinated targeted verification and
actual controlled runtime evidence may these statuses change. Human delivery
review remains a separate required gate before main merge/completion/enabling.

The dedicated reviewer scope also requires a private SHA-256 JTI receipt recorded
only after successful client_credentials signing with the exact fresh root grant.
Current receipt lookup checks that grant, client status and exclusive CC
registration; matching public `sub == client_id` alone cannot turn a historical
workload, delegated or task credential into reviewer authority. The receipt
contains no bearer token and expires through the bounded retention sweep.
