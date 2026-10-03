# Native Kubernetes RBAC for approved temporary privilege

Status: proposed normative extension; human review and interoperability acceptance pending.
Refs: ast-dd1y.5.3; approved baseline login ast-dd1y.1.1; temporary lifecycle ast-dd1y.5.1.

A temporary RoleBinding must never use the ordinary Kubernetes username. Otherwise
an unavailable controller leaves a binding that newly issued ordinary tokens can
reuse indefinitely. This decision adds a signed, temporary-only identity channel
and a separate username generation. The existing baseline subject/group contract,
ES256 signing, confidential broker, PAR/PKCE and DPoP remain unchanged.

The human review delta is the private ID-token provenance claim below, its exact
server-authority derivation, and the CEL username selection. Approval of the
baseline ADR did not approve these additions. Production enablement and main merge
are gated on this review. Source implementation and disposable acceptance can proceed.

## Signed provenance and identity

A dedicated cluster client has at most one enabled temporary entitlement mapping.
The exact same-tenant resource owner configures this mapping through an existing
Console session, CSRF and `admin.app_roles:write`, with explicit UUID CAS. It pins
the current public-subject Kubernetes profile and immutable controller client.
Any mapping mutation creates a new UUID revision. Profile/client invalidation
turns the mapping off; reenabling requires an explicit owner replacement.

Only the final ID-token signing path may add `asterius_jit`, a closed object:

```json
{
  "binding_revision": "00000000-0000-0000-0000-000000000001",
  "entitlement_id": "00000000-0000-0000-0000-000000000002",
  "client_id": "incident-cluster",
  "resource": "https://incident.example",
  "permissions": ["read"],
  "role": "incident-reader",
  "cluster": "incident",
  "namespace": "incident",
  "profile_revision": 1,
  "expires_at": 2000000000
}
```

The UUIDs and timestamp above are illustrative. The signer reads current authority
on its supplied PostgreSQL connection under the existing tenant signing fence.
It requires an enabled exact mapping/profile, the actual human nondelegated grant,
no agent/task/actor chain, exact single resource and registered resource permission
set, current activation/configuration/eligibility and original frozen strong
assurance as required by the temporary lifecycle. Missing or revoked authority
omits the claim; storage failures refuse issuance. Posted claims and builder
extension data cannot create or overwrite it.

The same snapshot must contain the mapped role in `HeldRoles.temporary_deadlines`.
A role independently supplied by current standing membership has no temporary
deadline and cannot produce this claim. This rule prevents a standing assignment
from silently becoming temporary Kubernetes authority. The ID token's signed
`exp` must be no later than the minimum activation and eligibility deadline, and
must pass the final deadline/current-authority recheck before signing. Claims are
never copied from a prior ID token or a refresh request. Refresh reevaluates the
actual narrowed grant and produces a baseline token when authority is absent.

The operator installs structured `AuthenticationConfiguration`, pinning issuer,
ES256-issuing audience, exact mapping UUID and all tuple fields. Legacy OIDC flags
cannot express this contract. The username expression selects
`asterius-jit:<mapping-revision>:<sub>` only for an exact matching private claim;
otherwise it selects the existing `asterius:<tenant>:<cluster>:<sub>` baseline
username. Both use the signed immutable public `sub`; no email, mutable user name,
posted user UUID or controller-chosen subject participates. Distinct fixed prefixes (`asterius-jit:` versus `asterius:`)
and UUID-generation pins prevent baseline/JIT collisions or stale-binding reuse
after mapping disable, replacement or recreation. Existing managed group mapping
remains unchanged. Existing baseline User bindings are untouched; their ordinary
credentials remain usable, while group-based baseline grants apply to both identities.

The concrete generated CEL must additionally validate the closed object shape,
exact permission set, positive integer deadline and `claims.exp <=
claims.asterius_jit.expires_at`. Malformed present provenance refuses authentication
rather than selecting a privileged identity. A valid claim for a different reviewed
mapping selects only the baseline identity. The generated document is tested against
an actual disposable API server, including ordinary, temporary, malformed and
foreign-tuple signed tokens. Kubernetes supports these expression mappings in its
[structured authentication configuration](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#authentication-configuration-from-a-file)
and defines the [claim mapping API](https://kubernetes.io/docs/reference/config-api/apiserver-config.v1/).

## Controller and native role ceiling

The cluster operator precreates a dedicated namespaced Role and empty RoleBinding.
The controller can GET/PATCH only that named binding and bind only that named Role.
It cannot create/delete bindings, change Roles, bind another Role/ClusterRole,
impersonate, or modify baseline bindings. Kubernetes makes `roleRef` immutable;
`resourceNames` cannot constrain top-level creation, so create is withheld. These
are the [native RBAC restrictions](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-binding-creation-or-update).
The controller pins binding name, UID, namespace and immutable roleRef locally.

Its machine read port requires the mapped same-tenant private_key_jwt/DPoP
client-credentials principal and `admin.app_roles:read`; reserved-realm automation
cannot address another tenant. It exposes no lifecycle/configuration command and
returns only mapping/revisions, one database observation time and at most 100 live
activation IDs, generation-prefixed public usernames and exclusive deadlines.
Overflow refuses a partial authorization snapshot. No reasons, account attributes,
assurance evidence or credentials are returned.

Reconciliation replaces only dedicated subjects with Kubernetes resourceVersion
CAS. Read and apply each have a 100ms–2s configured deadline; elapsed time is
subtracted from database-relative deadlines. Failed/invalid/obsolete projections
clear the dedicated binding. A bounded shutdown clear is attempted. Logging contains
no subjects or credentials. Existing baseline bindings are never addressed.

## Expiry and revocation boundaries

Healthy reconciliation removes subjects after revocation or expiry within a
measured polling/request window. An old unexpired JIT token then receives 403.
During controller or API unavailability the stale binding can remain, but all
previous JIT tokens expire no later than their activation deadline and newly issued
ordinary tokens have a different username. Thus outage residual access is bounded
by already issued token expiry, never by eventual controller recovery. Revocation
cannot immediately invalidate offline JWTs during an outage; the documented maximum
residual is the smaller of remaining activation and ID-token lifetime (five-minute
profile ceiling). No token issued after current revocation may receive JIT provenance.

Disposable acceptance must prove real code/refresh issuance, old JIT expiry and
new ordinary-token denial with the controller stopped, healthy revocation access
loss, standing-role overlap denial, exact resource/scope and foreign tuple denial,
CAS-generation replacement, preserved baseline bindings, and actual controller
ServiceAccount negatives for create, Role edits, different roleRef, other binding,
other namespace and verbs beyond the fixed Role. No existing deployment is modified.
