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
