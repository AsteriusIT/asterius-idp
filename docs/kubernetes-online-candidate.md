# Kubernetes online candidate preparation

The proposed ADR remains under its existing human review. The exported parser,
optional API ports and signing/store adapters are composed in the isolated
candidate worktree. The frozen 116-migration source `fd2c8ae1` passed formatting,
strict Clippy, 628 targeted nextest tests, workspace/all-target SQLx preparation,
and 119 fuzz-target registry, format, build and lint checks. Actual Kubernetes
1.35 acceptance passed 18 controlled runtime checks. No main delivery or shared
deployment activation has occurred.

The [aggregate candidate record](testing/modern-idp-candidate-2026-10-04.json)
identifies the verified source, binary and pending review document hashes. The
[Kubernetes runtime receipt](testing/kubernetes-online-final116-acceptance.json)
records the individual controls, measurements and fixture limits. These are
existing verification results from 2026-10-04, not new runs.

The closed TokenReview request bounds are 65536 JSON bytes, 16384 opaque token
bytes, and 1–16 distinct nonempty audiences of at most 2048 bytes. Unsupported
version/kind, duplicate known keys, unknown fields and populated input status
fail generically without echoing input. Actual Kubernetes zero metadata and
`status.user:{}` are discarded as wire scaffolding. The credential uses
`Secret<String>` (redacted Debug, zeroize on drop); requests have no Serialize
implementation. Responses have no spec, token, arbitrary extra or email and
return only the independently pinned route audience. A parsed request or a
response constructor establishes no source/token/identity authority.

## Issuance-established digest binding (candidate migration 0160)

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

## Acceptance boundaries

| Boundary | Recorded evidence and limits |
| --- | --- |
| Wire | Actual Kubernetes 1.35 requests accepted through production adapters; parser-negative cases retain focused test coverage rather than an exhaustive runtime claim |
| Route authority | Controlled route/audience/reviewer authority, service-only DPoP, exact reviewer grant receipt, mTLS and SPKI checks passed |
| Exact issuance | Real PAR/PKCE code and refresh digest registration passed; signature/storage concurrency races remain untested in this runtime fixture |
| Grant/session | Exact grant revocation with another grant surviving, stable public SID across real password session rotation, user disable and browser logout passed |
| Groups | Signed-group intersection with current membership and refusal to widen after additions passed; this receipt does not establish online/JIT composition |
| Availability | Two-adapter failover, entire three-second route timeout under table lock, primary DB outage/recovery and all-adapter outage without native fallback passed; DB replication remains untested |
| Freshness | Warm revocation denial measured 10.232s; opaque 25s delayed response plus outer cache measured 31.672s from revocation to denial; a response released after the native 30s timeout was not cached; the full 40s boundary was not saturated |
| Side effects/privacy | Read-only review passed; transport retained opaque TLS without certificate termination or claim changes; browser/session proofs were seeded, with no new WebAuthn ceremony in this fixture |

The receipt covers its listed controls, rather than every possible negative or
concurrent case. Ignored PostgreSQL concurrency regressions remain CI-only and
were not executed locally. Human delivery review remains a separate required
gate before main merge/completion/enabling.

The dedicated reviewer scope also requires a private SHA-256 JTI receipt recorded
only after successful client_credentials signing with the exact fresh root grant.
Current receipt lookup checks that grant, client status and exclusive CC
registration; matching public `sub == client_id` alone cannot turn a historical
workload, delegated or task credential into reviewer authority. The receipt
contains no bearer token and expires through the bounded retention sweep.
