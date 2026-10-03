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

## Follow a recorded denial

Every HTTP response carries `X-Asterius-Request-ID`, a fresh server-generated
32-character lowercase hexadecimal support reference. This differs from the
AuthZEN `X-Request-ID` echo, which may be chosen by the enforcement point.
Caller headers cannot set the audit support reference. Console error messages
include this reference for support; an empty filtered page means that no retained
event names it, not that a denial was reconstructed. Background jobs have no
inherited HTTP reference. A request can produce several audit events; use
`GET /admin/api/v1/audit/events?request_id=<reference>` to follow them.

The existing tenant-scoped `admin.audit:read` permission admits the explorer and
`GET /admin/api/v1/audit/events/{id}`. The drawer links the request, session
lookup digest, grant and exchange parent grant where known. Session references
are 64-character server-side lookup digests, never browser cookies. `session`,
`request_id` and the existing `grant` filters are conjunctive and share the
existing cursor pagination and bounded export. A grant/session absent from an
event cannot be invented by correlation; request links help connect records
within one HTTP operation, while session/grant links connect separate operations
such as login, step-up, issuance, refresh, exchange and revocation.

Real single and computed boxcar PDP evaluations and configured agent issuance
checks record the exact evaluated policy revision and bounded boolean condition
outcomes. Issuance decisions served from the existing short-lived cache retain
that cached snapshot; the trace is not relabelled with the current policy.
Uncomputed short-circuit boxcar items and decisions taken without the configured
policy engine have no policy evidence. Ordinary client issuance without an agent
policy remains visible through its audit records but does not claim a policy
check. Resource servers are visible only where they integrate with the PDP.

Historical diagnostic snapshots live separately from the immutable hash-chained
trail. Snapshot and event are written in one PostgreSQL transaction. Rule IDs
are redacted using the audit credential scanner; no context values, attribute
names, policy literals, keys or tokens enter snapshots. Serialized evidence is
bounded to 64 KiB, with truncation marked; existing rule/node budgets still
apply. Snapshots expire seven days after the event, stop being readable exactly
at expiry, and the existing bounded tenant retention sweeper removes them.
Deleting a tenant cascades its snapshots. The original event remains governed by
its existing audit retention policy and contains the snapshot UUID/expiry and canonical SHA-256 integrity fingerprint.
The reader checks both fingerprint and immutable event expiry; altered evidence
is unavailable with `reason: integrity_mismatch`, and its contents are withheld.
No endpoint reconstructs old decisions using the current policy.

Event detail returns `diagnostic.status`: `recorded` includes `snapshot` and
`expires_at`; `expired`, `unavailable`, `not_recorded` and `opaque` explain why
there is no snapshot. Missing or foreign tenant events remain 404 before evidence
lookup. Unauthorized callers get the existing 401/403. Evidence failure does not
change a completed PDP decision; it is logged and the event reader fails closed
on storage outages. All detail responses use `Cache-Control: no-store`.


Run `ASTERIUS_BIN=<verified binary> ASTERIUS_ACCEPTANCE_DB_CONTAINER=<owned PostgreSQL container> ./scripts/authorization-diagnostics-acceptance.sh` for the disposable real HTTP controls. The runner creates its own database, keys and TLS server, then removes those resources; it neither builds Rust nor publishes or changes an existing deployment.
