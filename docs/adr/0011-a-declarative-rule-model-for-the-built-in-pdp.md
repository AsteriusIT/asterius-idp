# ADR-0011: The built-in PDP evaluates declarative rules, not a policy language

- **Status:** Accepted
- **Date:** 2026-09-10
- **Bead:** ast-pj0.5
- **Deciders:** Quentin RODIC

## Context

`ast-pj0` adds an AuthZEN Policy Decision Point: Authorization API 1.0's
evaluation endpoint (`ast-pj0.1`), its boxcar sibling (`ast-pj0.2`), PDP
metadata (`ast-pj0.3`) and a `PolicyEngine` port with an engine behind it
(`ast-pj0.4`). The endpoint's shape is decided by the specification. What the
engine *is* is not: Authorization API 1.0 §2 places "policy language,
architecture, and state management aspects of a PDP" outside its scope, so the
specification will never settle this and the log has to.

Three facts in the tree bound the answer.

**This deployment is one binary and one PostgreSQL** ([ADR-0001]). An engine
that needs a second process, a sidecar or a bundle server is not a component of
this product; it is a second product an operator has to run, monitor and
upgrade in step.

**The interesting attributes are already here.** The decisions this PDP is asked
to make are about the people, clients and authorizations the IdP owns: a user's
claims, their groups, the tenant and client application roles of `ast-095`, the
administrative roles of `ast-3t8`, the client or agent profile, the active
grants of `ast-uwv.2` with their scopes, RFC 9396 `authorization_details` and
RFC 8707 resource indicators, and the `acr` the session reached under the
tenant's ladder (`ast-2vk.7`). A policy over this data needs a vocabulary for
*these* facts far more than it needs a general expression language.

**A tenant is not trusted.** Whatever the rules are, they arrive over the admin
API from an administrator of one tenant, are stored in a shared database and are
evaluated in the process that holds every tenant's signing keys. "Rules are
data" is therefore not a style preference; it is the property that keeps a
tenant from running code here.

Three options were on the table.

- **(a) A small declarative rule model** — JSON, schema-validated, with a closed
  set of conditions written in the IdP's own vocabulary.
- **(b) Embed Cedar** (the `cedar-policy` crate) behind the port. Expressive,
  formally analysed, with a validator and a decision-explaining API.
- **(c) Delegate to OPA** over HTTP or as a sidecar, with Rego as the language.

## Decision

**The built-in PDP evaluates a small declarative rule model: a per-tenant JSON
document of rules, validated against a schema on the way in, over the attributes
this IdP already owns.** The document is data at every point — parsed, bounded
and evaluated; never compiled, never executed, never `eval`'d.

Three properties are part of the decision rather than implementation detail.

- **Deterministic.** Rules are matched in document order; explicit `deny` wins
  over `permit` however they are ordered; a request that matches nothing is
  denied. No iteration over a hash map decides an outcome, no clock and no I/O
  is read during evaluation, so the same request against the same document is
  the same decision on every replica.
- **Total.** Evaluation returns a decision for every input. Bounds are applied
  once, at parse time (rule count, condition count, nesting depth, string
  lengths), so evaluation has nothing left to fail at: an unknown attribute is a
  condition that is false, not an error, and a malformed document was never a
  document.
- **Explainable.** Each rule carries the `reason_admin`, `reason_user` and
  step-up hint that §5.5.1 lets a decision's context carry, and the decision
  names the rule that produced it. A PDP that cannot say *why* is one an
  operator debugs by bisecting their own policy.

**The port is shaped for Cedar.** `PolicyEngine::evaluate` takes
`(tenant, Subject, Action, Resource, Context)` and returns a `Decision` — the
four-part shape of both Authorization API 1.0 §5 and Cedar's
`Request { principal, action, resource, context }`. `Subject` and `Resource`
carry a `type`, an `id` and typed `properties`, which is Cedar's entity
(`Type::"id"` plus attributes); the subject's groups and roles are carried as a
*set of parents* rather than as attributes, which is Cedar's entity hierarchy
and the reason `in` works there. An adapter that answers the same port with
Cedar therefore has a mapping and not a redesign: entities from the resolved
subject and resource, an action name from `Action`, a context record from
`Context`, and `Decision::permit` from Cedar's `Decision::Allow`, with
`reason_admin` rendered from the determining policy ids Cedar already returns.

The options rejected:

- **(b) Cedar now.** The expressiveness is real and so is the cost. Cedar is a
  language: an operator has to learn it, the console editor (`ast-f7m.9`) has to
  teach it, and every support conversation about "why was this denied" starts
  with a syntax the customer wrote. Its entity model also expects a *schema* and
  an entity store — this IdP would have to project users, groups, clients and
  grants into Cedar entities on every request anyway, which is the work in
  option (a) without option (a)'s simplicity. It stays the answer for
  cross-resource policies, hierarchical resources and policy analysis, and this
  decision is written so it can be adopted behind the same port without moving
  the endpoint, the storage or the admin API.
- **(c) External OPA.** Rejected on [ADR-0001]: a second runtime contradicts the
  single binary, and a network hop on the authorization path adds a failure mode
  whose only safe handling is to deny. Rego is also a language in which a tenant
  can write a non-terminating or quadratic policy, which is a tenant-supplied
  denial of service against a shared process.

## Consequences

**Easier.** The rule model is the IdP's own vocabulary, so "the subject holds an
active grant for this resource with an `authorization_details` of type `T`
permitting action `A`" is one condition rather than a dozen lines of joins
expressed in a general language. A rule document can be diffed, reviewed and
round-tripped through the admin API; the console editor validates against the
same schema the server does; a denial names the rule that caused it.

**Harder.** The model cannot express what its condition set does not name. Rules
about *relations between resources* ("the owner of the folder this document is
in"), arithmetic, or string manipulation are out of reach by construction, and
every extension is a schema change, a migration of nothing, a fuzz corpus entry
and a console change. That friction is deliberate — it is what keeps the
evaluator total — but it means the first customer who needs cross-resource
policy is the trigger to revisit this record rather than to grow the model.

**To maintain.** A JSON schema and its validator, a fuzz target for the parser
and one for evaluation, a golden catalogue of rules with their decisions, the
per-tenant storage (`tenant_policies`) and its admin API. The engine lives in
`asterius-domain`, where `scripts/check-layering.sh` guarantees it can reach no
adapter — an engine that could read a row during evaluation would be an engine
whose decisions depend on I/O, which is neither total nor deterministic.

**Operationally.** A tenant with no policy document denies everything, which is
the right default for an endpoint whose answer is authorization, and is a
support question ("why does everything deny?") rather than an incident. Decision
latency is a bounded walk over an in-memory document, which is what makes
`ast-pj0.1`'s p95 budget of 5 ms reachable without a cache that could serve a
withdrawn rule.

**Inherits work.** `ast-pj0.4` (this port and engine), `ast-pj0.1` and
`ast-pj0.2` (the endpoints that consume it), `ast-pj0.3` (metadata),
`ast-f7m.9` (the console editor and its test bench), `ast-pj0.6` (search APIs,
optional).

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| Authorization API 1.0 §2 | The policy language, architecture and state management of a PDP are out of scope; the specification governs the PEP↔PDP interface only | The rule model is a local decision, recorded here rather than derived from the specification, and it is reachable only behind the port — the wire format the specification does govern is unaffected by it |
| Authorization API 1.0 §5 | The information model is Subject (`type`, `id`, `properties`), Action (`name`, `properties`), Resource (`type`, `id`, `properties`) and Context | `PolicyEngine::evaluate` takes exactly those four, with `properties` as typed maps, so the endpoint maps its request onto the port without inventing members |
| Authorization API 1.0 §5.5.1 | A decision's context may carry `id`, `reason_admin` and `reason_user`, as localised reason objects | Every rule may carry `reason_admin`, `reason_user` and an `acr_values` step-up hint, and the decision returns them alongside the rule id |
| NIST SP 800-162 §2.2 (informative) | ABAC decides by evaluating rules over attributes of subject, object, operation and environment | The four inputs are exactly those, and the condition set names attributes, group and role membership, grant facts and the environment's `acr` |

[ADR-0001]: 0001-modular-monolith.md
