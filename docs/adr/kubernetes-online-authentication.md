# Kubernetes online authentication uses a bounded TokenReview adapter

- **Status:** Proposed; normative human review required by ast-dd1y.1.5
- **Date:** 2026-10-03
- **Bead:** ast-dd1y.1.5
- **Refines:** [Kubernetes human access](kubernetes-human-access.md)

## Problem and existing evidence

The completed Kubernetes interoperability run measured native acceptance of a
held ID token for approximately five minutes after account disable or logout.
Those results are recorded in
[the public evidence](../testing/kubernetes-interoperability-evidence.json).
An optional mode must consult live state without changing the existing default
offline profile, making Kubernetes understand DPoP, or calling this CAEP.

`http/issuance.rs` signs ID tokens from a `ClaimedGrant`. Its `sid` is a stable
public browser-session identifier; the session lookup digest rotates. ID tokens
do not currently identify their exact authorization grant. Checking whether an
account has *any* active grant would consequently accept a revoked grant's
credential whenever another grant remained active. JWT-supplied identity and
grant identifiers cannot substitute for an issuance-established association.

## Decision

Opt in explicitly on a Kubernetes client profile to online authentication and
select a distinct confidential FAPI service client as its allowed reviewer.
Keep the human client's approved confidential OIDC broker registration, PAR,
PKCE, ES256, isolated audience and upstream DPoP requirements unchanged.
The reviewer requires `client_credentials`, `private_key_jwt`, DPoP and a
dedicated Kubernetes review scope; it cannot be the human client. A reviewer
from another tenant, a deployment-wide principal, or an unselected reviewer
cannot obtain this profile's identity results. Profile changes retain optimistic
concurrency checks and existing tenant administration authorization.

At successful issuance for an online profile, persist SHA-256 of the complete
compact ID token, tenant, client, exact claimed grant, stable public session ID,
subject and signed expiry before returning the token response. No raw token is
stored. Missing session or failure to establish this association refuses online
issuance. The binding does not add a claim or a new token format. Bindings expire
with their tokens and are removed on tenant/client deletion. Old offline tokens
without bindings require fresh login after opt-in; they are never enrolled by a
review request. Authorization-code and refresh issuance must both establish the
association. Unsupported issuance paths cannot bypass online binding.

An operator-run stateless HTTPS adapter accepts only
`authentication.k8s.io/v1` TokenReview POSTs. It authenticates the API server
using a dedicated client CA plus an explicit client-certificate public-key pin
selected for the configured cluster route. The route pins issuer, human client
and reviewer independently of request claims. The adapter obtains its own
sender-constrained service credential and calls Asterius over verified HTTPS
with DPoP. Its keys remain operator secrets. Kubernetes receives no DPoP key.

Asterius verifies the exact issuer, ES256 signature, single cluster audience,
bounded five-minute lifetime, subject and expiry, then checks the exact digest
binding. It reads authoritative primary-database tenant/client/profile/user,
grant and session state without directory caches or side effects. Tenant/client
must be active, account must be able to authenticate, grant must be active and
belong to the bound tenant/client/account, and the public session must still be
live for that account. Session lookup never prolongs its idle lifetime. Missing
rows, revocation, expiry and profile/reviewer mismatch deny authentication.

Return the same stable username/group prefixes as the offline profile. Released
groups are the intersection of signed issued groups, the current profile
allow-list, and current directory membership. Adding membership never widens an
old token; removal narrows it immediately on the next uncached review. Do not
return email, unselected attributes, arbitrary `extra`, or caller-supplied
identities. Review does not create grants, subjects, sessions or policy objects.

## TokenReview and operator contract

Reject malformed JSON, unsupported version/kind, oversized tokens, excessive
audiences and caller-populated authentication status. Require nonempty `spec.audiences`, at most
16 bounded strings, with the configured client audience present. This deliberately
stricter deployment contract avoids an ambiguous default audience. A successful
response returns only that configured audience in `status.audiences`,
`authenticated: true`, and the validated user. A denied review has no user.
Never echo the submitted bearer token in the response, logs or errors.

### Proposed wire-compatibility correction for the same pending review

Kubernetes 1.35 creates a zero-status TokenReview and serializes through Go's
standard JSON encoder. Its non-pointer status/user structs can emit
`status: {"user": {}}`; zero metadata emits
`metadata: {"creationTimestamp": null}`. Rejecting the presence of every status
field would reject this upstream request. The prepared candidate accepts only
absent status or this exact empty-user shape, discards it, and rejects populated
authenticated/user/audiences/error fields and null status. Metadata is closed to
the absent/empty/zero-creationTimestamp shapes; it is never an identity hint.

This refines the earlier phrase "caller-supplied status" and must be included in
the still-pending human review. It changes no authentication authority. See the
[controlled serialization evidence](../testing/kubernetes-tokenreview-wire-evidence.json),
[upstream v1 types](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/api/authentication/v1/types.go),
[webhook construction](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/webhook/webhook.go),
and [serializer delegation](https://github.com/kubernetes/apimachinery/blob/v0.35.0/pkg/runtime/serializer/json/json.go).
The evidence reproduces wire shape, not real Kubernetes authentication or
revocation.


Configure `--authentication-token-webhook-version=v1`,
`--api-audiences=<human-client-id>` and
`--authentication-token-webhook-cache-ttl=0s`, with a kubeconfig that
verifies the adapter CA and supplies the dedicated API-server certificate.
The webhook replaces native OIDC authentication for this exact issuer/client;
leaving the equivalent offline JWT authenticator enabled bypasses online
revocation. Existing service-account and certificate authenticators remain
independent. Generated configuration must make this replacement explicit.

The configured webhook URL ends in `/review`. Kubernetes 1.35 client-go adds
`?timeout=30s` from its configured transport timeout. The adapter accepts only
an empty query or that exact bounded transport query; it ignores the parameter
for its own deadline and rejects duplicate/unknown/alternate values. This carries
no identity or audience authority. See the pinned
[client-go request construction](https://github.com/kubernetes/client-go/blob/v0.35.0/rest/request.go)
and [webhook timeout configuration](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/apiserver/pkg/util/webhook/webhook.go).
This compatibility refinement is part of the same pending normative review.

No adapter or backend positive identity cache is permitted. The adapter gives
each complete review a three-second deadline, including service authentication
and live-state lookup. Timeout, storage error, invalid upstream result and
outage return an unauthenticated result without stale identity. Failed transport
also grants no identity. Kubernetes 1.35 still wraps all authenticators in a global ten-second success
cache; setting the inner webhook TTL to zero disables only that inner cache.
Its shared lookup detaches from the caller with a thirty-second timeout, and
the upstream webhook HTTP client also has a thirty-second timeout. A successful
response already in flight can therefore arrive after revocation and populate
the outer cache. The conservative supported bound is **40 seconds plus measured
scheduling/transport margin**, rather than the adapter's local three-second
deadline plus a cache TTL. This is a source-derived design bound, **not measured
acceptance evidence**; healthy-network measurements do not establish the worst
case. Acceptance must exercise delayed transport and the actual target settings.
See the pinned [outer cache implementation](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/apiserver/pkg/authentication/token/cache/cached_token_authenticator.go),
[authenticator composition](https://github.com/kubernetes/kubernetes/blob/v1.35.0/pkg/kubeapiserver/authenticator/config.go)
and [webhook transport timeout](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/apiserver/pkg/util/webhook/webhook.go).

Deploy multiple stateless adapter instances with identical pins and routes,
verified TLS, primary-database-backed Asterius replicas, dedicated least-privilege
credentials and adequate capacity. Load balancer failover must retain client
certificate authentication or provide authenticated end-to-end passthrough.
Never use unauthenticated forwarded certificate headers. Renew certificates and
reviewer keys with an explicit overlap window. When all replicas fail, new
uncached human authentication fails; globally cached identities remain the
documented availability/revocation trade-off. RBAC continues to authorize each
request separately after authentication.

Signing-key withdrawal retains the existing shared signer limitation: its cached
private-key lease lasts at most sixty seconds from loading, and a prepared
signature does not recheck emergency retirement or purge in the database. Normal
rotation deliberately keeps a retiring key published for overlap. Emergency
withdrawal can therefore race final signing and digest registration until that
lease expires; this candidate does not provide an immediate key-withdrawal fence.
Whether such a token authenticates also depends on the verifier's current
published-key resolution and JWKS cache. These are separate limits from the
forty-second Kubernetes authentication cache bound. The shared-signer correction
is tracked as `ast-psi2`; human review of this candidate remains pending.

## Normative review and verification

Human review must cover the v1 request/response and audience intersection rules
in the [Kubernetes authentication documentation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication)
and [TokenReview schema](https://kubernetes.io/docs/reference/kubernetes-api/definitions/token-review-v1-authentication/).
Implementation is pinned to the actual Kubernetes 1.35
[webhook authenticator](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/apiserver/plugin/pkg/authenticator/token/webhook/webhook.go)
and [v1 API types](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/api/authentication/v1/types.go).
The authenticated Asterius service hop follows
[RFC 9449 §7](https://www.rfc-editor.org/rfc/rfc9449.html#section-7);
this proof does not constrain the human bearer token at the API server.

Required evidence includes wrong audience/tenant/reviewer/certificate denial,
revocation of one grant while another remains active, session rotation and
logout, account disable, current group removal, unsupported and malformed review
inputs, expiry, upstream timeout/outage and replica behavior. A distinct
throwaway Kubernetes 1.35 cluster must demonstrate real kubectl access and
measure held-token denial with the disabled inner webhook cache and the global ten-second success cache. Bounded parser
mutation coverage, targeted Rust verification, operator documentation, OpenAPI
and threat-model updates accompany implementation. This proposed document alone
does not satisfy runtime acceptance or close the ticket.
