# External workload trust and token exchange

- **Status:** Accepted design; runtime implementation tracked separately
- **Date:** 2026-10-03
- **Bead:** ast-dd1y.2.1
- **Deciders:** User approval in the epic implementation session, 2026-10-03
- **Refines:** ADR-0003, ADR-0006, ADR-0014

## Context and current implementation

`crates/server/src/http/token_exchange.rs::subject` accepts local access tokens
(and the generic RFC 8693 JWT spelling as a local access token), verifies tenant
keys, live grants, revocation and sender binding. Separate native SSO and ID-JAG
profiles do not establish general external workload trust. The ordinary exchange
narrows scopes, resources and expiry and preserves an actor chain. None of these
checks may be replaced by an unverified external claim.

`crates/server/src/client_auth.rs` authenticates registered clients independently.
`crates/jose/src/client_keys.rs` does not accept RS256 for FAPI client assertions.
`crates/server/src/outbound/jwks.rs` already provides guarded HTTPS retrieval
(no redirects, guarded DNS and connection addresses, 64 KiB body and five-second
whole-request timeout). Its client-key cache is not a workload trust registry.

## Decision

Use an explicit, disabled-by-default tenant workload exchange profile on the
existing RFC 8693 token endpoint. A workload JWT is a **subject token**, never
`client_assertion`, an enrollment credential or human authentication. The caller
must remain an independently registered confidential client authenticating with
existing `private_key_jwt` or mTLS. Output is sender constrained, with the existing
DPoP or mTLS enforcement; DPoP does not authenticate a client or prove that a
bearer subject token was issued to its presenting key.

The profile accepts only `subject_token_type=urn:ietf:params:oauth:token-type:jwt`
for external tokens and returns an access token, never refresh or ID tokens.
Local issuer tokens continue through the existing local verifier without fallback
into external verification. External access-token and ID-token spellings cannot
select this profile. Unknown or ambiguous issuer/mapping selection fails closed.
Actor tokens and impersonation are prohibited for this workload profile.

### Trust and principal mapping

An operator-created trust record belongs to exactly one routed tenant and binds
an exact issuer, exact exchange audience, provider profile, explicit allowed
client IDs, exact subject/required claims, stable non-human principal ID, allowed
scopes/resources/actions, algorithm allowlist, enabled state and version.
There is no wildcard issuer, caller-selected JWKS URL, email mapping, first-use
enrollment, human consent record or automatic assignment of human permissions.
The exchange audience is a tenant-and-trust-specific URI, separate from the
requested resource audience. Require a single matching audience value to avoid
cross-service reuse. Administrative CRUD requires tenant administration authority
and records actor, tenant, trust ID and version in the audit trail.

Kubernetes mapping pins cluster issuer, namespace, ServiceAccount name and
ServiceAccount UID; require pod-bound projected tokens and pod UID. Claims must
agree with `system:serviceaccount:<namespace>:<name>`. Name reuse alone cannot
inherit access. GitHub mapping pins numeric `repository_id` and
`repository_owner_id`, exact `sub`, environment, ref, event and workflow
identity; reusable workflows additionally pin `job_workflow_ref` and
`job_workflow_sha`. Default policy rejects `pull_request` and
`pull_request_target`; repository names are diagnostic rather than authority.
Renames retain numeric identity but exact textual policy fails closed until the
operator updates it. No fork or event policy is inferred from `sub` alone.

### Validation limits

These limits are local policy, not claims of RFC requirements. Bound compact
JWTs to the existing 8 KiB subject-token limit, decoded claims to 4 KiB, claim
nesting to eight levels, and string claim lengths to 1 KiB. Reject duplicate JSON
members, malformed encodings, unsupported critical headers, `none`, HMAC,
embedded/private keys and token-supplied `jku`/`x5u`. Require `kid` (at most 128
bytes), verified exact `iss`, `sub`, `aud`, integer `iat`, `exp`, optional integer
`nbf`, and provider-specific typed claims. No authorization consumes unverified
claims; bounded unverified issuer parsing can only select an existing trust.

Pin an explicit subset of RS256, PS256, ES256 and EdDSA for external signatures,
including RSA modulus 2048–8192 bits. RS256 support is confined to this external
non-FAPI credential validation boundary; it does not widen client authentication,
output signing or the FAPI conformance claim. This boundary requires human review.
Reject JWTs issued more than 300 seconds ago or more than 30 seconds in the
future; reject expired tokens without expiry grace. Kubernetes projected tokens
may have `exp-iat` up to 3600 seconds; GitHub tokens at most 600 seconds.
Require `exp>iat` and `nbf<=exp`; all other providers remain unsupported.

### Replay, freshness and output

Atomically consume SHA-256 of the exact compact subject token in a shared durable
store, keyed by tenant and trust, until its expiry. Consumption and child-grant
creation must be one transaction; a failed mint has documented retry behavior
and cannot create parallel grants. Do not rely on optional upstream `jti`,
per-process memory or DPoP replay state to prevent subject-token replay.
A retried consumed assertion is `invalid_grant`; callers request a fresh
GitHub assertion or obtain a fresh Kubernetes TokenRequest assertion. Merely
reloading a projected file does not renew a consumed token: kubelet rotation
occurs independently and a typical one-hour projection also exceeds this
profile's five-minute freshness window before rotation. A client that only reads
a projected file cannot sustain continuous access under this proposal. Resolving
renewal (explicit TokenRequest permissions, a reviewed first-use key binding
policy, or different freshness limits) is an additional acceptance gap for
ast-dd1y.2.3; its sample must not promise transparent renewal. Audit never includes the
JWT, assertion, certificate secret, DPoP proof or raw external claim document.

Output lifetime is at most the minimum of 300 seconds, remaining subject-token
life, tenant policy and client policy. Its principal is the mapped workload,
its authenticated client remains visible in `act`, and scopes/resources/actions
are intersections of explicit trust and client policies. No `openid` or
`offline_access`. Trust disable is read from the authoritative database on each
mint, without an authorization cache; transactions serialize mint against disable.
Previously issued JWT access tokens retain authority for at most 300 seconds
unless the resource server uses online revocation/introspection. Do not claim
instant offline revocation.

Choose offline Kubernetes signature validation for this initial profile, not
live TokenReview. A deleted pod or ServiceAccount is not immediately observed:
new exchange stops at `min(exp, iat+300s)`, and existing output expires at most
another 300 seconds later. Thus the documented worst-case deletion validity is
600 seconds, ignoring only bounded clock error. A deployment requiring stronger
freshness must use a separately implemented, pinned TokenReview adapter; no
unimplemented online revocation guarantee is advertised.

### Keys and disable bounds

Trust may use operator-managed public inline JWKS or an exact pinned HTTPS JWKS
URI. Kubernetes private-address endpoints require an explicitly reviewed adapter
or public keys installed by the operator; do not bypass ADR-0006. Do not perform
issuer discovery from the token. Bound JWKS to 64 KiB and 16 public keys, reject
ambiguous duplicate `kid`, key/algorithm mismatches and private material.
Administrative reads return metadata and public fingerprints, not raw credential
or key material. Inline rotation and disable take effect at the next serialized
mint. Version-keyed caches cannot authorize using a previous trust version.

Remote JWKS snapshots expire after 60 seconds regardless of upstream cache
headers. Refresh on unknown `kid` at most once per trust per 30 seconds and
single-flight concurrent fetches. A removed remote key can authorize issuance
for at most 60 seconds after removal, and issued access expires within another
300 seconds. Failed refresh never extends an expired snapshot. Explicit operator
revocation/version changes invalidate snapshots immediately. Fetch outage is
fail closed, not indefinite use of stale keys.

## Bootstrap and alternatives

Independent authentication is selected because a stolen external bearer JWT
must not itself register a key or impersonate a confidential client. Pods can
use independently provisioned certificates or private keys without an OAuth
client secret; this still requires a credential provisioning mechanism. GitHub
hosted runners have no independent trusted asymmetric credential by default.
A pre-existing broker may authenticate with its own key after validating the
workflow, but building that broker is additional work with its own threat model.
This ADR does **not** claim secretless direct GitHub onboarding is solved.

Rejected here: treating a GitHub/ServiceAccount bearer JWT as `private_key_jwt`,
registering a caller's ephemeral key from that JWT, unauthenticated exchange,
or accepting possession of an arbitrary DPoP key as client authentication.
A separately named non-FAPI workload client authentication profile could solve
credentialless bootstrap, but must be approved explicitly and must not inherit
FAPI claims. It is outside this selection.

## Threat model and implementation gates

Confused deputy and cross-tenant exchange are bounded by explicit tenant, issuer,
audience, client and principal binding. SSRF/key substitution is bounded by
operator-pinned locations and the existing guarded fetcher. Stolen bearer subject
tokens remain replayable to an authorized client before first consumption; client
credentials and output sender constraint do not remove that risk. Durable atomic
consumption bounds subsequent reuse. Compromised issuer signing keys can mint
identities until disable/key removal bounds above; short output TTL is necessary.
Token theft from logs is addressed by redaction and structured metadata-only audit.

The user approved this document on 2026-10-03 ("ok pour les deux documents"),
satisfying the human review prerequisite. Implementation tickets
ast-dd1y.2.2–.2.4 retain their runtime acceptance criteria. Required evidence includes negative validation and
cross-tenant tests, concurrent replay/disable tests, rotation/outage tests,
provider controlled flows, parser fuzzing, OpenAPI and operator documentation.
A documentation-only review does not establish runtime enforcement or interop.

## Source review record

Published primary sources were opened by the implementing agent on 2026-10-03.
The automated source review prepared the document for human review. The user
then approved both the Kubernetes and external workload contracts on 2026-10-03.
That approval includes the explicitly documented limitations and does not claim
runtime interoperability.

| Source | Relevant boundary |
|---|---|
| [RFC 8693 §§1, 2.1, 2.2, 3, 5](https://www.rfc-editor.org/info/rfc8693/) | Exchange protocol, separate client authentication, token-type distinction and deployment trust policy |
| [RFC 8725 §§3.1, 3.8–3.12](https://www.rfc-editor.org/rfc/rfc8725.html) | Algorithm, issuer/audience and mutually exclusive validation policies |
| [RFC 9449 §§4, 7, 11](https://www.rfc-editor.org/rfc/rfc9449.html) | DPoP verification, sender constraint and replay limitations |
| [FAPI 2.0 SP §5.3.2.1](https://openid.net/specs/fapi-security-profile-2_0-final.html) | Preserve asymmetric confidential-client authentication and sender constraint |
| [Kubernetes projected tokens](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/) | Explicit audience, projected token expiry and rotation |
| [Kubernetes ServiceAccount validation](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/) | Offline verification versus TokenReview and bound-object freshness |
| [GitHub OIDC claims](https://docs.github.com/en/actions/reference/security/oidc) | Numeric repository/owner IDs and workflow/environment/ref identity |

The approved design preserves independent client bootstrap limitations, external
RS256 isolation, issuer freshness/replay bounds, offline Kubernetes deletion
bounds and the non-human principal authorization model. A secretless direct
GitHub bootstrap needs a separate reviewed design before it is advertised.
