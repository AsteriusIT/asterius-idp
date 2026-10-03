# Task authorizations in the audit console

The audit console includes a tenant-local task viewer. Its current authority snapshot is separate from recorded events. Reading requires `admin.audit:read`; withdrawing requires the existing `admin.grants:write` authority and revokes the task's immutable root grant through the owner-bound grant administration route. The confirmation states the offline JWT expiry limit. Expiry is immutable: withdraw and obtain a fresh, shorter approval instead of editing existing authority.

`GET /admin/api/v1/agents/tasks` returns one bounded page of public task metadata. Query names are closed: `limit` (1–50, default 25), `cursor` (canonical UUID), and optional exact `owner` UUID or `agent` client identifier. Duplicate, unknown and malformed parameters fail. `GET /admin/api/v1/agents/tasks/{task_id}` accepts only `limit` and `cursor` and returns a current snapshot plus one bounded grant page. Every stored ancestry path has at most ten nodes, with the root first. Stored depth and the eight-actor delegation ceiling are distinct bounds.

The snapshot uses a read-only repeatable-read database transaction. It reports immutable approved scopes, audiences and exact actions, and current issuance ceilings intersected with tenant, client, resource, ancestry and lifetime constraints. Each resource has its own scope and lifetime ceiling; a union of scope names must not be interpreted as permission for every resource. Withdrawn, expired or unavailable principal/ancestor authority yields an empty current issuance ceiling. No request-specific conditional or PDP authorization is implied: `conditional_decision` is explicitly `not_evaluated`. Recorded grant constraints are displayed within the immutable task ceiling and do not rewrite old signed JWT claims.

The UI shows its observation time, marks an observation stale after thirty seconds, and provides explicit refresh. A later lineage page replaces the earlier snapshot so observations from different database transactions are not merged into a false single authority view. UUID paths display grant ancestry; only a bounded page is loaded. The separate recorded timeline filters existing audit events by exact task UUID. Missing historical rows, pagination, opaque rows and diagnostic expiry retain the audit explorer's existing visible states; an incomplete record never establishes current authority.

Only public tenant-local task, client, grant and immutable owner identifiers are returned. User names, email addresses, raw tokens, private JTIs, keys and session credentials are excluded. A task UUID alone grants no access. All queries bind the authenticated tenant, and administrative withdrawal verifies that the grant belongs to the immutable owner in the path before mutation.

A task-specific audit index supports the exact JSON detail predicate without broad event payload expansion. The viewer does not add a new trust protocol, broker or client authentication mechanism.

The reproducible controlled acceptance extends the task withdrawal runner:

```sh
ASTERIUS_BIN=/path/to/verified/asterius \
ASTERIUS_TASK_VIEWER_ACCEPTANCE=1 ASTERIUS_TASK_VIEWER_BROWSER=1 \
./scripts/agent-task-withdrawal-acceptance.sh
```

The runner creates and removes its own local database and HTTPS listener. It uses real independently authenticated FAPI management and agent clients, verifies exact task read scopes, keyset bounds, foreign-tenant UUID refusal, public snapshot fields, intermediate/root lifecycle, and task-filtered recorded events. A real Chromium console session checks ceilings, immutable provenance, withdrawal confirmation and cancellation, actual owner-bound administrative withdrawal, terminal refresh and timeline selection. Human authorization roots, session inputs and the console owner's administrator role are controlled seeds; this does not claim a live human login ceremony. The configured Playwright installation is required for browser controls, and the console must be built into the verified binary before running them.
