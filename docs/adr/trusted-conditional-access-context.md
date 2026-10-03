# Conditional access resolves trusted facts before declarative evaluation

- **Status:** Decided; enforcement is tracked by ast-dd1y.4.2
- **Date:** 2026-10-03
- **Bead:** ast-dd1y.4.1
- **Refines:** [ADR-0011](0011-a-declarative-rule-model-for-the-built-in-pdp.md)

## Context and current implementation

Keep the existing `PolicyEngine` port and bounded JSON rule model in
`crates/domain/src/policy/`. It is deterministic, reads no clock or storage,
gives explicit deny precedence, and denies when no rule matches. Context
properties supplied by a PEP are ordinary descriptive properties. The existing
`access_evaluation.rs` adapter resolves tenant groups, roles, live grants and
authentication assurance from server records; it does not trust a PEP's
authority claims. Its generic evaluation currently derives assurance from the
subject's live grants, not from a particular browser transaction.

`AcrPolicy` defines assurance as an ordered tenant ladder backed by verified
authentication methods. `http/step_up.rs` merges verified factors only for the
same user, rotates the session identifier on elevation and does not claim an
essential assurance requirement was met when it was not. `http/issuance.rs`
rechecks authentication evidence against the current ladder before releasing
claims. `server.proxy.trusted_cidrs` already identifies which immediate peers
may supply forwarded connection information. Policy revision history exists
in migration `0150_tenant_policy_revisions.sql`; history alone does not prove
which document a particular evaluation used.

One trap makes a separate trust contract necessary: today's missing attribute
test is false, but `not` of that test is true. Therefore a negated condition
cannot establish that a missing device is healthy or that unknown network
origin is outside a forbidden range.

## Decision

Add a typed, internal `TrustedAccessContext` assembled by the server adapter
before calling the existing policy port. It carries immutable facts with
provenance, observation time, expiry and availability. It is not accepted as an
OAuth parameter, JWT claim, AuthZEN request property or browser form field.
The pure evaluator receives one resolved snapshot and one captured server
time; it performs no network fetch, storage lookup or clock read.

Conditional policies are explicit tenant/application configuration, with a
bounded applicability scope of registered client IDs and enforcement actions.
There is no implicit opt-in by sending a context property. A scope's required
facts are the union of its explicitly required facts and every trusted fact
referenced by any applicable condition, including inside `not` and `any`.
Before evaluating rules, require those facts to be known and fresh. This
mandatory guard cannot be overridden by a matching permit or by negation.
A failed guard denies the whole scoped evaluation. Thus a policy that wants
an alternative without a device requirement must define a separate,
operator-reviewed scope; `any` is not an availability bypass.

After the guard succeeds, the existing deny-overrides-permit behavior applies.
A permit from conditional access is only one necessary check; it cannot bypass
client authentication, redirect validation, tenant/profile gates, PKCE, sender
constraints, scopes, consent, grant ownership or token-exchange constraints.
Do not introduce executable expressions or a second policy service.

## Internal schema and provenance

The following is an implementation contract, not a currently accepted API or
configuration document. Concrete parser/schema changes belong to ast-dd1y.4.2.

```text
TrustedAccessContext {
  tenant_id, subject_id?, client_id, action, evaluated_at,
  policy_revision, policy_document_digest,
  acr_policy_revision, client_configuration_revision,
  facts: bounded map<ClosedFactName, Fact>
}
Fact {
  state: known | absent | stale | unavailable | invalid,
  value?: closed typed value,
  source_id: server-owned source identifier,
  observed_at?: server-validated timestamp,
  expires_at?: server-validated timestamp
}
ConditionalScope {
  registered_client_ids, enforcement_actions,
  required_facts, closed_conditions, rule_ids,
  assurance_remedy?: registered_acr,
  max_authentication_age_seconds?: integer
}
```

Bounds: at most 32 fact names, 64 applicability scopes and 32 required facts per
scope, within the existing policy document byte/nesting/rule bounds. Reject
duplicate scopes with overlapping client/action applicability rather than
letting order decide which requirements disappear. Unknown fact or predicate
names and wrong value types are configuration errors at publication. Only
known facts carry a usable value. Invalid or future-dated observations never
become known; non-known states remain distinguishable for audit and remedies.

| Fact | Trusted source | Freshness and unavailable outcome |
|---|---|---|
| Authentication assurance/methods | Verified server session or grant bound to this exact tenant, subject and transaction; current `AcrPolicy` validates the evidence | Revalidate methods against current ladder on every enforcement. Missing/off-ladder evidence denies an assurance requirement; interactive remedy may request verified authentication. |
| Authentication age | Server-recorded time of the authentication that met the required assurance; current server clock | Compute age at evaluation, never from token `iat`, client `max_age`, session last-seen or last refresh. Reject future times. A scoped maximum is 60–86400 seconds; unknown/too old denies, with fresh authentication remedy for interactive users. |
| Application sensitivity | Administrative client configuration for the exact registered client; closed `standard`, `sensitive`, `critical` values | Resolve current revision at each boundary. Existing unclassified clients map to `standard` only when no protected scope requires classification; missing required classification denies. Caller naming a sensitivity has no authority. |
| Network origin/zone | Verified direct peer or existing trusted-proxy chain resolver, classified by operator CIDRs | Observation applies only to the current request. Ignore forwarded headers from an untrusted immediate peer. Malformed/ambiguous trusted-proxy information yields invalid; unavailable required origin denies. Never reuse browser-login IP for a later token request. |
| Device identity/posture | Authenticated, tenant-registered posture source and subject/device-bound assertion verified by a dedicated adapter | Cap age at 300 seconds and the source assertion's earlier expiry; require exact tenant, subject/device, relying application binding, issuer/key trust and replay handling. Missing adapter/source, revoked enrollment, bad signature/binding, expiry or timeout denies a required device fact. |
| Groups/roles/grants | Existing tenant repositories and managed membership/release rules | Resolve current active state for each enforcement snapshot. Errors deny/error the request; submitted properties cannot override them. |

Application sensitivity is not self-asserted resource sensitivity. Network
zone is a connectivity fact, not a device-management or MFA signal. User-Agent,
browser-reported OS, IP geolocation, arbitrary headers, token claims supplied by
the caller and an unauthenticated device identifier are hints only. They may
inform diagnostics or a separately documented risk observation, never satisfy
groups, roles, assurance, age or device trust. An ordinary access token proving
the caller's identity does not authenticate an external posture assertion.

External posture authentication, enrollment and credential lifecycle remain
ast-dd1y.4.4. Until that adapter exists, required device trust is unavailable;
there is no synthetic trusted device value or permissive fallback.

## Closed conditions and precedence

Use the existing group/role/grant conditions and `acr_at_least`. Extend only
the typed vocabulary necessary for sensitivity equality, known network-zone
membership, authentication age at most a configured integer, and device
compliance equal to a registered closed status. No string comparison orders
ACRs; no arbitrary arithmetic, regular expression or caller-defined property
name becomes a trusted predicate. The adapter exposes the resolved typed facts
through the existing request/context port; trusted fact metadata stays separate
from PEP properties. Any reserved trusted namespace in wire input is rejected,
including attempts to set freshness, provenance, groups or assurance.

Precedence is fixed:

1. Existing protocol, identity, grant and ownership invariants must hold.
2. Match the server-selected applicability scope and capture current revisions.
3. Validate all required facts, including negated/alternative references.
4. Evaluate all applicable rules using existing explicit-deny precedence.
5. Issue a permit only when every preceding gate permits. A remedy is never
   a permit and never overrides another matching hard deny.

Step-up remains a denied outcome with an optional bounded remedy for an
interactive user whose only failure is insufficient or expired authentication.
The target ACR must exist on the tenant's current ladder and be supported by
available authentication methods. A stale or untrusted device, unavailable
network source, missing policy, revoked grant or explicit non-assurance deny
cannot be cured by adding an MFA hint. `prompt=none` cannot display an
interaction; use the existing applicable interaction-required protocol path.
Client-credentials and unattended agents cannot perform human step-up; deny
without an interactive remedy. No retry loop or silent reduction of the
requested assurance is allowed.

## Enforcement and re-evaluation

| Boundary | Required snapshot and outcome |
|---|---|
| Authorization request and resumed interaction | Resolve the registered application and relevant current session evidence. Deny or initiate bounded authentication remedy before recording successful authorization. |
| Code/device/CIBA redemption and token issuance | Re-evaluate current scoped policy before signing or exposing a token. Do not rely only on the earlier browser decision; use the actual transaction/grant identity and current token-request network observation. |
| Refresh | Resolve current user/client/grant enablement, current policy/revisions and fresh required facts. Preserve real original authentication time; refresh does not reset authentication age. Deny refresh if authentication is too old, and require a separate interactive authorization. |
| Token exchange and agent/delegated grants | Evaluate the actual acting principal, target client/resource and delegator's independently recorded constraints. A human grant's strong ACR cannot upgrade an unrelated agent or user. All actor-chain constraints remain necessary. |
| Step-up completion | Rotate only the same-user session through the existing verified factor flow, then rebuild context and rerun policy. Completion of MFA alone does not authorize token issuance. |
| AuthZEN evaluation | Continue resolving subject authority server side. For scoped conditional evaluation, only a request bound to a specific verified session/grant may satisfy transaction assurance/age; generic subject-only requests have absent transaction facts. |

Do not choose the strongest unrelated live grant when enforcing an issuance
transaction. Preserve the existing generic AuthZEN behavior for legacy scopes;
its strongest-live-grant assurance is not a promise about the caller's current
browser session. New protected scopes require exact transaction evidence.

Policy publication, client sensitivity edits, ACR ladder changes, group/role
withdrawal, grant revocation and posture updates become effective at the next
enforcement boundary. Do not cache a permit across a revision or freshness
deadline. Capture document and revision atomically; before issuance, detect a
changed revision and rebuild the snapshot once, then deny on repeated churn.
Fact-resolution failures never fall back to the previous permit. The final
issuance boundary is necessary because changes may happen while an interaction
is waiting for user input.

This contract does not revoke an already issued offline JWT. Its accepted
lifetime bounds stale authorization at resource servers unless an existing
online check or revocation mechanism is explicitly used. Do not extend session
or token lifetime because a policy source is unavailable.

## Compatibility, audit and decision matrix

No conditional scope means the existing rule document, generic PEP property
semantics, protocol gates and FAPI defaults retain their behavior. Do not
reinterpret all existing `context` attributes as trusted. Publication of a
conditional scope is explicit administrative configuration and rejects
unsupported predicates/sources; rollback removes the scope through the same
versioned configuration path rather than making a stale permit valid.

Audit each conditional evaluation with tenant/client, enforcement action,
policy revision and digest, ACR/client configuration revisions, determining
rule/reason category, required fact availability, source identifiers and
redacted subject/grant references. Record observation/expiry times without raw
posture payloads, credentials, precise location or unnecessary IP retention.
Use server-written administrative reasons and safe user-facing reasons; do not
disclose which group or device rule an unauthenticated caller nearly passed.
Preserve the existing audit sink failure behavior (log the audit failure;
never turn a denied decision into a permit). Revision capture must describe the
actual evaluated document, not a separate later read of revision history.

| Case | Outcome |
|---|---|
| Required facts known/fresh, all protocol gates valid, matching permit, no deny | Permit |
| Permit and explicit hard deny both match | Deny; no remedy overrides the deny |
| Required device fact missing, stale, invalid or source unavailable | Deny; no MFA remedy |
| `not(device_compliant)` with absent posture, or `any` branch without the device | Required-facts guard denies before boolean evaluation |
| Required network origin missing/invalid | Deny; copied forwarding header cannot satisfy it |
| Client submits groups, ACR, auth-time or posture as properties | Cannot confer authority; reserved trusted namespace is rejected |
| Interactive user's only deficit is insufficient/old verified authentication | Deny with supported ACR/fresh-authentication remedy; rerun all gates after completion |
| Unattended client or agent has an assurance deficit | Deny without human interaction remedy |
| Refresh after authentication-age deadline or grant revocation | Deny; a fresh token cannot reset age |
| Policy/source storage error or repeated revision churn | Deny/error through the existing boundary; no cached-permit fallback |
| No conditional scope | Existing behavior, including legacy default-deny and explicit-deny precedence |

## Scope of this decision

This is a local trust and enforcement architecture decision. It introduces no
new wire protocol, cryptographic scheme or posture parser. Runtime schema,
OpenAPI/admin documentation, enforcement, parser fuzzing and matrix tests are
implementation work in ast-dd1y.4.2; authenticated posture protocol design is
ast-dd1y.4.4. Those implementations must follow the repository's applicable
normative review requirements. The decision ticket's acceptance is the
documented provenance, freshness, unavailable outcomes, enforcement boundaries
and existing-policy compatibility above; closing it does not claim runtime
conditional access is implemented.
