# Expiring owner approvals for agent tasks

An agent task begins from an existing human-authorized grant belonging to the
agent's immutable owner. This extends the existing confidential-client grant
model; client authentication and DPoP or certificate proof remain mandatory.
There is no new broker, client assertion format, or secretless bootstrap.

The signed-in owner obtains exact root evidence from
`GET /account/agent-tasks/approval?root_grant_id=<uuid>` under the tenant mount.
The response contains the root and client IDs, permissions, the maximum
lifetime, and a session-specific CSRF token. Reading it grants no authority.
The owner must authenticate within the last 120 seconds and explicitly submit
`POST /account/agent-tasks/approve` as an application/x-www-form-urlencoded form:

```text
csrf=<preview token>
confirm=approve
root_grant_id=<root uuid>
label=<run description>
expires_in=<1..3600 seconds>
permissions=<JSON object>
```

The strict permissions object contains `scopes`, `resources`,
`authorization_details`, and `max_delegation_depth` (1..8). Scopes and resources
must be nonempty subsets of the root authorization. RFC9396 details recognize
only the registered `urn:asterius:workload-actions` dialect, with `type`,
`actions`, and `locations`. Each narrower detail must fit one approved detail;
combining an action from one location with a different approved location fails.
A JSON Schema registration alone cannot define narrowing for an arbitrary
extension, so unknown dialects and members fail closed. `device_sso` cannot
join a task because its specialized derivation has no equivalent task fence.

Approval atomically narrows the durable root to the approved scopes, resources,
details and expiry, records an immutable run ID and revision, and activates a
persistent task obligation for the initiating agent client. Until its first
explicit task approval, an existing client retains its existing behavior.
After activation, that client ID cannot mint an unbound access token. The
obligation survives removal/recreation of its registration; a replacement
requires a new owner-approved root. Client
credentials select an approved run using `task_id=<uuid>`; this selector is
not authentication. Code, device, CIBA, refresh and ordinary local token
exchange inherit stored binding. A client cannot provide a root, owner, or
approval revision in its JWT or exchange form. A replacement approval requires
a new human-authorized root/run, including when an old task has expired.

An access token lives at most 300 seconds and no longer than the task, subject
or any ancestor, or the current tenant/agent lifetime policy. Refresh absolute
and idle deadlines cannot exceed the task. Current scopes, registered resource scope/TTL policy, grant
types, action schema, agent and tenant ceilings are checked again under a
PostgreSQL fence immediately before signing. Client resource metadata supplies
default audiences; it does not replace the exact approved root/task ceiling.
Server-owned Grant Management and SSF resources reuse the same enabled audience
factories as ordinary issuance, with stored registry overrides taking priority.
Changing the owner, disabling or
removing the owner or initiating client terminates the task irreversibly;
re-enabling an account does not restore the approval.

The production signer resolves database/key-unwrapping work into a detached
in-memory key handle before acquiring any authority lock. The handle keeps
the full task-aware signing port and cannot extend the signing cache lease;
a wait beyond that lease fails closed instead of reloading a key under locks.
The signer holds principal, root, task and ancestor locks, records private
JTI-to-grant lineage and an audit event in the same transaction, and returns a
token only after commit. Signing/storage failure rolls back the child and JTI.
Optional public `grant_id` claims do not control lineage: task JWTs carry opaque
`task_id` and `task_approval_revision`, and exchange resolves them through the
private JTI mapping. The owner's application roles are not automatically copied
into task tokens. Specialized external-workload, ID-JAG and Native SSO issuance
fails closed for task-enabled clients until it can satisfy the same binding.

Audit events `agent.task.approved` and `agent.task.issued` record the immutable
approval identifiers and trusted request correlation. Issuance refusals record
a constant reason; assertions, access tokens, refresh tokens, CSRF values and
raw approval forms are never recorded. Approval and lineage records remain
with their tenant for authoritative lifecycle checks and history. Client/root
removal clears nullable references and preserves the terminal approval
correlators; deleting the tenant removes its task data.

The issuance fence and descendant withdrawal share the root lock. Authoritative
online task/token checks inspect the exact private lineage; the owner-facing
history viewer is delivered by ast-dd1y.8.4. An offline verifier continues to have only the
bounded token expiry guarantee. The complete contract is
[the task-grant ADR](adr/task-bound-agent-grants.md); HTTP shapes are in
[the account task OpenAPI document](agent-tasks-openapi.json).

The reproducible controlled HTTP acceptance uses `ASTERIUS_BIN=<verified binary>
./scripts/agent-tasks-acceptance.sh`. It creates an isolated local PostgreSQL
database and HTTPS listener, uses real private_key_jwt authentication and DPoP,
and verifies actual signed tokens, approval replay, denied expansion, delegated
refresh, elapsed expiry, a root writer racing issuance, terminal owner disable
and atomic audit/lineage. It seeds owner sessions and prior human grants; this
is explicitly not evidence of a live human login. Slow adapter integration
tests remain CI-only (`--run-ignored all`).

The sanitized recorded run is [agent task issuance evidence](testing/agent-task-issuance-evidence.json), including the executed binary digest and controlled-fixture limitations.


## Descendant withdrawal

A freshly authenticated owner posts `task_id`, `confirm=revoke` and the same
session-specific challenge from the task preview to
`/account/agent-tasks/revoke`. A task UUID supplies no authority. The operation
is idempotent for that owner; another owner or tenant receives the same missing
answer. Existing owner grant withdrawal and tenant-authorized administrative
grant withdrawal use the same fence. Revoking the root ends the whole task;
revoking an intermediate grant ends only its subtree. Siblings and independent
runs stay valid.

Authoritative online checks resolve exact private JTI lineage even when public
grant IDs are hidden. They check current task/revision, owner and initiating
client, every ancestor's status/expiry, and recipient client state. These reads
are uncached and fail closed on database failure. Introspection (both access
and refresh), PDP, UserInfo, Grant Management, SSF resources, administrative
automation, credential issuance and local token exchange use that lifecycle.
A task-enabled client cannot use a taskless JWT at these protected APIs.

First activation binds historical stored descendants under the root lock.
Child insertion and legacy descendant signing share that lock, so creation
racing activation cannot leave a valid future credential outside task lineage.
Historical JWTs issued before task activation cannot acquire signed task claims
or private JTI records retroactively: the existing legacy JWT expiry bound
continues to apply, especially where public grant IDs were hidden. New refresh,
exchange and issuance from their stored descendants inherit the current task
and cannot evade its withdrawal.

Withdrawal commits a root/task or intermediate-grant tombstone, cutoff and
`agent.task.withdrawn` audit with immutable identifiers and request correlation.
The tombstone is effective at the next uncached online read; a response already
authorized may finish. Physical descendant cleanup follows a durable cursor,
processing at most 512 candidate grants and ten ancestor rows per candidate on
one retention sweep. Cleanup marks grants and refresh credentials, writes the
existing grant cutoffs and denylist, and survives process restart. Cleanup
backlog is reported by `Sweep.more_to_do` and does not extend online authority.
Existing owner/client lifecycle transitions also enqueue cleanup when their
terminal Task tombstone is written; their account/client audit event records
the cause. Explicit Task/grant withdrawal records `agent.task.withdrawn`. Existing owner/account/session SSF
notifications retain their current meanings; no fabricated session-revoked
SET claims that withdrawing one task revoked an unrelated human session.

An external resource server must use authorized introspection for prompt
withdrawal and cap its response cache at five seconds and token expiry. An
offline task JWT verifier may accept the previously issued token for at most
its remaining lifetime (maximum 300 seconds), plus explicit clock leeway.
Outbox/event delivery is a hint and carries no hard global propagation promise.

The reproducible withdrawal acceptance uses
`ASTERIUS_BIN=<verified binary> ./scripts/agent-task-withdrawal-acceptance.sh`.
It creates only its own disposable local database/listener, uses independently
authenticated management and agent clients, and prints sanitized assertions.
The owner session and human authorization roots are controlled fixture inputs;
they are not evidence of a live human authentication ceremony. PostgreSQL
regression tests for backfill, subtree isolation and bounded cleanup remain
ignored locally and are reserved to CI.

The committed [withdrawal evidence](testing/agent-task-withdrawal-evidence.json)
records the executed binary digest, UTC time and eleven real HTTPS control
checks. The [baseline](testing/agent-task-withdrawal-baseline.json) records the
previous administrative owner-path substitution defect. Final local validation
passed strict formatting/Clippy, 198 targeted tests including mandatory source
and secret audits, and the compile/lint/registry gate for all 108 fuzz targets.
The ignored PostgreSQL concurrency, legacy activation, maximum-depth and
resumable 512-row cleanup regressions are prepared for CI, not claimed as run
locally.
