# Authorization decision diagnostics

A tenant administrator with `admin.policies:read` can submit the existing
AuthZEN-shaped request to `POST /admin/api/v1/policies/try`. The response preserves
`decision` and `context` and adds an administrative `diagnostics` object. The
public `/access/v1/evaluation` response stays unchanged.

`policy_revision` is `sha256:` followed by the digest of the canonical evaluated
document; it is null when the tenant has no stored policy. `policy_updated_at`
is the publication time in Unix nanoseconds as a decimal string. `rules` lists
stable IDs, effects, selector `applicable`, overall `matched` and condition
results in document order. Deny wins even when an earlier permit matched.

Condition `path` identifies positions such as `when.0.1`. `missing: true`
distinguishes an unavailable property/ACR from a present false condition.
`matched` always reports the engine's existing boolean outcome, including
negation; missing under a `not` can therefore yield a matching parent condition.
The trace records all bounded branches for diagnosis, even branches a normal
short-circuit evaluation need not read. Rules with nonmatching selectors have
no condition trace. No trace value is itself a reason to grant access.

The budget is 256 condition nodes total and at most 128 rules. `truncated: true`
means some condition results were omitted; the complete policy still determined
the answer. No input values, attribute names, group names or policy literals are
copied into diagnostics. The policy's existing authored decision reasons retain
their existing behavior in `context`.

`enforcement_point: admin_policy_trial` identifies this nonenforcing evaluation.
There is no trace retention. The response is `no-store`, and trials do not add
audit events. Trusted facts are resolved for the authenticated tenant, rather
than accepted as claimed group, role, grant or ACR fields from the caller.

## Controlled what-if simulation

`POST /admin/api/v1/policies/simulate` additionally requires `admin.users:read`,
`admin.clients:read` and `admin.resource_servers:read`. Supply `user_id` (the
local account UUID), `client_id`, an exact registered resource audience as
`resource_id`, `resource_type`, `action` and `expected_policy_revision` from
`GET /policies`. Send null for the revision only when there is no stored policy.
A changed revision returns 409; refresh before repeating the inspection.
Missing tenant-owned references return 404. Extra fields, including claimed
groups, roles, grants or ACR, are rejected.

Optional `hypothetical_policy` is a bounded v1 rule document, and optional
`hypothetical_context` contains context properties. The response explicitly
marks `simulation.enforced: false`, gives provenance for each input source,
the current stored revision and an explanation of the evaluated document.
Draft policy revisions can therefore differ from the current stored revision.
The console labels this result as hypothetical, separately from recorded
decisions. Its selectors expose the first 100 actual tenant users and clients;
the API supports any authorized tenant-owned reference.

Before resolving sensitive subject information, the API records a
`policy.simulated` inspection-intent audit event. Audit failure prevents the
lookup. This event records the authorized inspection, not a historical
enforcement decision or proof of the result. It contains account and client
references, never the draft, context properties or explanation.

The evaluator uses one policy snapshot and resolves group membership,
application roles, active grants and assurance through the server's existing
trusted-fact attachment. Those repository reads are separate observations,
not a transactional snapshot of all authorization facts. Pairwise subject
derivation uses the read-only path; simulation reserves no subject identifier,
saves no policy, creates no grant and issues no token. The normal enforcement
endpoints cannot accept this request dialect.
