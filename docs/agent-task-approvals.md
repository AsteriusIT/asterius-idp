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

This ticket supplies the issuance fence. Descendant withdrawal and authoritative
online task/token checks are delivered by ast-dd1y.8.3, and the owner-facing
history viewer by ast-dd1y.8.4. An offline verifier continues to have only the
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
