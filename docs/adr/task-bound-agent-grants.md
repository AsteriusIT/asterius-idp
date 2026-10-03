# Task-bound agent grants and descendant revocation

- **Status:** Accepted architecture; runtime implementation pending
- **Date:** 2026-10-03
- **Bead:** ast-dd1y.8.1
- **Authority:** user request to implement ast-dd1y, including concrete architecture
- **Related implementation:** ast-dd1y.8.2, ast-dd1y.8.3

## Current evidence

`domain/src/entities/grant.rs` already models tenant, client, user, subject,
scopes, resources, authorization details, actor chain, `parent`, expiry and
revocation. `server/src/http/token_exchange.rs` derives a child grant from its
immediate local parent and narrows scopes, resources, lifetime and delegation
policy. It does not store a task approval revision or check a durable task root.

`store-pg/src/grants.rs::revoke` locks and revokes the named grant, its refresh
tokens and known access JTIs, then writes a grant cutoff for remaining tokens.
It does not recursively revoke `parent_grant_id` descendants. `introspection.rs`
consults denylist, cutoffs and the named grant when exposed; it does not traverse
ancestors. RFC 7009 token revocation and whole-grant revocation are intentionally
distinct operations in the current server and remain distinct here.

`server/src/http/agent_issuance.rs` provides the existing PDP enforcement port
and a five-second decision cache. `AgentPolicy::permits` permits when no policy
port is configured and can be configured to fail open. These behaviors cannot
substitute for task lifecycle validity. Device, CIBA, client credentials and
exchange already call this port. Authorization code and refresh do not directly
call it in current source. Device and CIBA access-token builders currently use
the tenant lifetime rather than an explicit agent TTL cap. These are verified
integration gaps, not claims that prior agent work is wholly missing.

## Decision

Extend the existing grants authorization model with a durable **task binding**.
Do not create a second consent engine or independent permission evaluator.
Each task/run has an opaque UUID scoped by tenant, one immutable owner user ID,
one initiating agent client ID, one existing root grant ID, an approval revision,
creation and absolute expiry stamps, and a terminal revocation stamp/reason.
Approval data uses existing consent/approval evidence and agent limits, with
explicit exact resource audiences, scopes and RAR authorization details.
A display label is untrusted metadata and conveys no authority.

The root grant remains the authorization. Task metadata says which bounded run
of that authorization was approved. Every task-bound grant stores a non-null
`task_id`, `task_root_grant_id` and `task_approval_revision`; exchanged children
also preserve existing `parent_grant_id`. Composite tenant foreign keys enforce
that root, task, owner, clients, parent and descendant belong to one tenant.
The root is inherited from the parent, never accepted from untrusted claims or
an exchange form. A child cannot join another task or lose its task binding.
Cycle prevention and existing delegation-depth limits apply before insertion.

Task-bound access tokens carry opaque task/run and approval-revision correlators
for authorized delegation visibility. Internal JTI-to-grant lineage is persisted
for every task token even where tenant policy hides the grant correlator.
Introspection resolves internal lineage rather than inferring it from optional
public claims. Resource servers receive only authorized task metadata; owner
identity and approval contents are not automatically published. Sender constraint
and the current actor chain remain intact. The task identifier is not a bearer
capability and cannot authorize inspection or revocation by possession alone.

### Permission and approval ceilings

Effective permissions are the intersection of the request, authenticated client
registration, tenant agent limits, agent registration limits, existing grant
permissions, every delegating ancestor's ceiling, the immutable task approval,
current resource-server policy and the existing PDP decision. Owner identity
alone gives no group/role inheritance to an agent. A task may not convert an
ownerless client-credentials grant into human delegated authority without
explicit owner approval evidence.

RAR comparison is type-aware: recognized details intersect actions, locations,
resources, identifiers and constraints using the registered type's narrowing
rules. Unknown types or fields without a defined narrowing comparator are denied,
not compared as loose JSON or silently copied. Empty task approval means no
permissions, not unrestricted permission. Approval scopes marked human-required
continue to require existing explicit human approval evidence.

Approval revisions are immutable. Expansion of any permission, resource, action,
TTL or delegation depth requires a new approval revision with fresh approver
identity and evidence; it revokes the former run and starts a new root/task.
Narrowing likewise cannot mutate a revision under existing tokens: replace the
run and revoke the old one. Neither refresh nor exchange can adopt a newer
revision automatically. No operator edit resurrects a revoked or expired run.

### Expiry and renewal

A task/run lasts at most one hour, bounded further by owner approval expiry,
root/ancestor grant expiry and tenant/client policy. Access tokens last at most
300 seconds and never beyond task, approval, grant, ancestor or subject-token
expiry. These are local policy caps, not OAuth normative values. A caller may
request a smaller lifetime. Refresh-token absolute and idle expiry are both
bounded by task expiry; refresh never extends the task. A new approved run is
required after expiry. A task bound to an agent client whose owner is removed,
disabled, moved out of the tenant, or replaced becomes terminally invalid.
Owner removal writes the fence in the same transaction as owner state changes;
later cleanup records descendant terminal states but grants no revival path.

### Concurrent mint and revocation

Use one authoritative PostgreSQL transaction for task validation, grant
claim/create, lineage and token/JTI registration. All task mints lock the root
and task, and relevant ancestor rows in a documented deterministic order.
Task/ancestor revocation and approval replacement acquire the same root/task
locks. Owner/client validity changes participate in the same fence protocol;
a read before a concurrent deletion is insufficient. Recheck current clock,
owner state, revision and all ceilings inside the transaction immediately before
committing authority. Signing occurs while authority is fenced; no signed token
is returned unless its issuance transaction commits. Failed signing rolls back.
This design intentionally serializes issuance within one task to make the
revocation ordering reviewable; optimize only with equivalent proven fencing.

Revoking a task commits its root/task tombstone and a durable lineage cutoff.
The task tombstone denies all descendants immediately at authoritative online
checks, including children concurrently attempted during revocation. Revoke
refresh credentials and each descendant grant through existing grant/cutoff
mechanisms in the transaction where feasible; larger cleanup may be asynchronous
because the root tombstone already fences use and minting. Root and lineage
records cannot be garbage-collected while any descendant credential may live.
An intermediate grant revocation invalidates its subtree but does not revoke
siblings or the whole task. Whole-task revoke is distinct from RFC 7009 revoking
a single credential. Repeated task revoke succeeds idempotently without revealing
other tenants' existence.

### Every enforcement point

| Point | Required enforcement |
|---|---|
| Task creation and human approval | Resolve tenant owner/agent; reuse existing approval evidence; freeze exact ceilings, expiry and revision; least-privilege administration |
| Authorization/PAR, device and CIBA approval completion | Bind task to stored flow and immutable approval before grant creation; refuse substituted task or client |
| Authorization code redemption | Resolve persisted task; fenced claim; current owner/revision/PDP; apply common task TTL and audit |
| Refresh redemption | Resolve original grant and task internally; fence expiry, owner, ancestor and revision; re-evaluate PDP; no task renewal |
| Client credentials | Require explicitly approved task for task-enabled agents; no user authority invented; existing client and agent ceilings still apply |
| Device/CIBA token polling | Preserve existing policy checks, add task fence, common TTL and successful task audit; consumed/expired approvals cannot mint |
| Local token exchange | Inherit task/root/revision from subject grant, verify every ancestor and sender binding, narrow permissions and append actor chain |
| Native SSO/ID-JAG and future external workload exchange | Deny task-enabled agent use until each specialized path implements equivalent inherited binding and ceilings; no generic bypass |
| Introspection | Resolve persisted JTI/grant lineage; deny revoked/expired owner, task, revision or ancestor; retain current audience and client authorization checks |
| Asterius protected APIs, UserInfo, grant management and token-consuming protocol endpoints | Use common task-aware active-token validation before authorization; task proof never replaces sender proof or audience validation |
| Task/owner/client/grant revoke and approval replace | Shared authoritative fence; correct subtree or whole-task tombstone; existing cutoffs and refresh revocation; consistent audit |
| Account/admin delegation views | Tenant/owner administrative authorization; show effective ceilings and lineage without credentials or raw token contents |
| External resource server | Verify signatures, exact audience, expiry and sender constraint; use authorized introspection when immediate task status matters |
| Session expiry/logout and cleanup | Apply existing grant/session revocation plus inherited task validity; preserve tombstones until all descendants expire |

Task lifecycle checks always fail closed and bypass the five-second PDP allow
cache. Cache keys for ordinary PDP decisions include tenant, task, approval
revision and effective requested permissions. The existing PDP fail-open setting
cannot override missing, expired, revoked or mismatched task authority. An
ordinary agent with task enforcement enabled cannot omit task metadata to use a
legacy issuance route; enablement must cover all its allowed grant types.
Legacy non-task grants retain their current behavior until explicitly migrated.

### Online and offline guarantees

Authoritative online validation observes a committed tombstone on its next
uncached read. A response already authorized before commit may finish; revocation
does not reverse actions. A remote introspection cache must be capped at five
seconds and never beyond token expiry: its validity lag is at most five seconds
plus clock/transport error, not instant global revocation. Database/check outage
denies task authority, rather than serving indefinitely cached active status.

An offline JWT verifier cannot observe task, owner or intermediate-grant
revocation. Its worst-case remaining authority is 300 seconds after revocation,
plus any explicitly configured resource-server clock leeway. Sender constraint
limits token misuse but does not shorten this bound. Existing non-task tokens
are not retroactively assigned the new bound. CAEP/events are delivery hints,
not substitutes for the fence or a promised hard propagation deadline. No UI or
operator guide may call offline subtree revocation immediate.

## Alternatives and consequences

Selected: metadata extension of existing grant authorization with durable root
and parent lineage. A separate task authorization plane would duplicate consent,
PDP and audit semantics. Stateless short JWTs alone were rejected because they
cannot prevent post-revocation refresh/exchange or expose reliable descendants.
Pure recursive descendant cleanup was rejected as the safety boundary: a child
created after the recursive snapshot could escape. Root fencing and online root
checks make cleanup an optimization rather than the authorization decision.

Threats addressed are approval reuse after expansion, descendant escape during
revoke, confused task/tenant identity, owner removal and stale PDP allows.
Operational costs are mandatory durable lineage, short access-token lifetimes,
root serialization and database dependence for immediate online enforcement.
Audit must consistently record tenant, owner, agent, task/root/parent, approval
revision, outcome and reason on successful and refused issuance/revoke without
recording access/refresh tokens, client assertions or proof keys.

## Verification and normative review record

This decision changes architecture documentation only. The implementing agent
reviewed the current source and primary specifications on 2026-10-03; it is not
human normative sign-off or runtime enforcement evidence.

- [RFC 8693 §§2, 4, 5](https://www.rfc-editor.org/info/rfc8693/) provides exchange and actor semantics; task and descendant policy are local deployment decisions.
- [RFC 7009 §2](https://www.rfc-editor.org/rfc/rfc7009.html) describes credential revocation; this decision keeps task/grant withdrawal distinct.
- [RFC 7662 §§2.2, 4](https://www.rfc-editor.org/rfc/rfc7662.html) supports online active-state checks and requires attention to cached state.
- [RFC 9396 §§2, 7](https://www.rfc-editor.org/rfc/rfc9396.html) supplies structured authorization requests; type-specific narrowing must be defined rather than assumed.
- [FAPI 2.0 SP §6.8 item 4](https://openid.net/specs/fapi-security-profile-2_0-final.html) recommends credential linking; task root/parent lineage makes that relationship durable.

The architecture acceptance criteria of ast-dd1y.8.1 are fulfilled by the chosen
references, revocation model, permission intersection and enforcement/validity
bounds above. No new authentication method, enabled protocol parser or crypto
implementation is delivered by this ADR. The ticket's explicit requirement for
human normative review of **protocol/crypto completion** remains a gate on those
parts of dependent runtime work. It does not represent a human approval already
obtained by this documentation decision. Implementation must supply race,
expiry, expansion, owner-removal, subtree and all-grant-path tests, OpenAPI,
operator docs and threat-model updates before claiming enforcement complete.
