# Temporary privilege is an internal, expiring entitlement activation

- **Status:** Decided; implementation tracked by ast-dd1y.5.2
- **Date:** 2026-10-03
- **Bead:** ast-dd1y.5.1

## Context and selected architecture

Current application roles (`crates/domain/src/entities/application_role.rs`)
are distinct from the server's closed administrative roles. Direct assignments
and managed-group assignments are standing authority; their existing storage
does not implement a temporary activation lifecycle. Managed groups are separate
from legacy claim strings (`crates/domain/src/groups.rs`); group persistence
alone does not imply policy or token authority. The PostgreSQL role adapter
explicitly rejects application-role assignments to SCIM-owned groups. Existing
OAuth grants record consent and delegation, not independent entitlement
eligibility. The approval inbox (`http/approvals.rs`) currently handles CIBA
and device entry and enforces fresh, sufficient authentication; its two-minute
authentication freshness is reusable UX precedent, not an entitlement approval.

Choose a new internal entitlement eligibility/request/activation model.
Integrate active entitlements into existing role/grant resolution; do not
materialize them as standing group memberships, administrative roles, OAuth
consent, or external SCIM group writes. Temporary privileges may name only
existing tenant application roles, preferably client-scoped roles, and explicit
registered resource/permission bounds. Eligibility is permission to request
activation, never permission to use the role. Existing standing access retains
its existing meaning and is displayed separately; activating a temporary
entitlement does not withdraw an unrelated standing assignment.

## Immutable records and owner configuration

Each entitlement has an opaque identifier, tenant, fixed client/resource and
role/permission catalogue references, resource-owner identity, approved
approver set, requester and approver ACR requirements, eligibility lifetime,
activation maximum duration, policy revision and enablement. Maximum activation
duration is fifteen minutes by default and never more than one hour. An owner
must explicitly configure the approver set and valid tenant ACRs; an empty set,
unknown ACR, deleted resource/role or disabled owner policy prevents requests.
Do not infer owners from role names, email domains or a requesting user's group.

Eligibility records identify the exact subject and entitlement and have
`not_before`, exclusive `expires_at`, status and version. Eligibility grants
are administrative resource-owner actions scoped to that entitlement. They
cannot be granted through OAuth consent or by SCIM provisioning. Removing
eligibility disables existing activations as well as future requests.

A submitted request captures immutable tenant, requester, entitlement,
eligibility identifier/version, owner-policy revision, exact client/resource,
role/permission set, requested duration, bounded nonempty reason and deadline.
Duration is positive and at most the owner's configured maximum; the pending
request deadline is five minutes. Requested resource and permissions are
displayed verbatim from validated server catalogue data. Approval authorizes
that immutable tuple only. Editing any authority-bearing part creates a new
request; approval cannot be carried across the edit. Catalogue/owner-policy
revision changes invalidate pending approval rather than silently widening it.

## Lifecycle

| State | Allowed transition and authority |
|---|---|
| Eligible | Subject may request only while current eligibility is active and within its time interval |
| Pending | Owner-selected independent approver may approve or deny; requester may cancel; deadline or eligibility/policy removal terminates it |
| Denied/cancelled/expired/invalidated request | Terminal; a new independently authorized request is required |
| Approved | Approval and activation are committed atomically; no reusable approved-but-not-activated capability exists |
| Active | Authority exists only while all live eligibility, ownership, subject and time predicates hold |
| Revoked | Requester, scoped resource owner or separately authorized security operator may terminate activation; terminal |
| Expired | Reached automatically by live time comparison at `now >= expires_at`; terminal even if cleanup has not run |

The effective activation interval is `[activated_at, expires_at)`, where
`expires_at = min(activated_at + requested_duration, eligibility.expires_at)`.
Activation cannot begin before eligibility's `not_before`. Recheck eligibility,
subject enablement, immutable request tuple, current approver authorization,
approval freshness/assurance, owner-policy revision and pending deadline in
the same transaction that consumes the request and inserts the activation.
If any changed or cannot be resolved, fail without granting privilege.

There is no auto-renewal, activation extension or reset of the original
deadline. A new reason, current eligibility, fresh requester evidence and
independent approval are required for each renewal. One active activation per
subject/entitlement is allowed; concurrent requests cannot stack duration or
union broader permissions. Requests can be submitted while an activation is
active, but approval fails until the previous activation is terminal; operators
must accept any resulting access gap rather than implement silent extension.

## Authorization and separation of duties

| Actor/action | Authorization requirement |
|---|---|
| Requester: submit/view/cancel | Exact eligible subject in the same tenant; validated requester ACR; view/cancel only own request; cancellation grants no authority |
| Approver: view/approve/deny | Current owner-selected approver membership and exact entitlement scope; same tenant; independent from requester; approved ACR and authentication age at most 120 seconds |
| Resource owner: eligibility/configuration | Existing administrative authority plus explicit ownership for the resource; cannot approve a request whose requester is that owner |
| Requester: revoke own activation | Exact owner subject; allowed even after assurance falls below activation requirements |
| Resource owner/security operator: revoke | Explicit scoped administrative/security authority; reason recorded; revocation is never restricted by requester cooperation |
| Ordinary application/SCIM client | No ability to create eligibility, approval, activation or privileged role ownership |
| Background cleanup worker | Marks already inactive records/queues notifications; cannot approve, extend or reactivate |

No self-approval means identity equality after stable server subject resolution,
not equality of email or browser accounts. The requester cannot approve through
an alternate delegated client. An eligibility/configuration editor cannot also
approve the first request enabled by that exact edit: record the editor identity
on the eligibility and owner-policy version and exclude it from the approving
set for requests using that version. If no independent approver remains, deny.
Do not manufacture an owner override when quorum is unavailable. Initial scope
uses one independent approval; adding quorum or delegated approval requires an
explicit lifecycle extension, not an interpretation of the existing inbox.

Require the requester's configured assurance at submission and at every token
issuance using the activation; expiry of authentication freshness can require
fresh authentication but never renews activation time. Approval uses verified
server session methods under the current tenant ACR ladder. Missing, stale or
insufficient evidence cannot be provided through posted claims or a callback
parameter. Interactive step-up may repair authentication only; it does not
repair missing eligibility, expired request, deleted ownership or self-approval.

Emergency access is disabled in this initial contract. A future break-glass
path must be an explicitly configured separate entitlement with independent
ownership, short expiry, fresh strong authentication, immediate security
notification and mandatory post-event review. It cannot silently bypass
self-approval or treat an unavailable approval service as permission.

## Runtime authority, propagation and visibility

Give each activation an opaque, immutable reference distinct from its request,
eligibility and OAuth grant. The reference is a lookup/audit correlation value,
never a bearer capability. No possession of an ID confers authority. Bind
issuance to the exact tenant, subject, client/resource, granted permissions and
activation interval. Existing OAuth grants remain necessary; activation can
only narrow their usable privilege, not expand consent, scopes or delegation.

Current role resolution must overlay live active entitlements for the exact
client/resource. Query expiry and current eligibility on every policy decision,
code redemption, refresh, token exchange and token issuance; no active-role
cache may outlive a revision or activation deadline. Permanent group membership
and SCIM-owned group role restrictions remain unchanged. Issuance resolves
current roles again rather than copying a prior privileged token's role set.
For privileges derived from an activation, cap resulting access/ID-token
expiry at activation expiry and omit the role when no positive lifetime
remains. Dependent exchanged tokens must not outlive or broaden the activation.
Refreshing a grant cannot reactivate expired privilege.

Revocation or eligibility removal removes authority at the next online
evaluation and prevents privileged reissuance. Already issued offline JWTs
remain usable until their capped expiry unless the resource server implements
an existing online check/revocation mechanism. Do not promise instant resource
revocation, update external SCIM as a revocation substitute or erase original
OAuth consent to hide this distinction. In particular, Kubernetes bearer JWT
authentication has the expiry limitation of its native authenticator.

The existing inbox may host a new clearly labelled entitlement request view
and fresh-authentication UX, but CIBA/device/consent decisions remain distinct
record types and authorization paths. Requesters see eligibility, pending
requests, active interval and reasons; scoped approvers see only their assigned
immutable requests; owners see their resource's eligibility and activations.
Expired/revoked records remain readable to authorized auditors with terminal
status. IDs and status cannot be probed cross-tenant; return the same safe
absence outcome for inaccessible resources.

## Clock, concurrency, retries and audit

Use one authoritative database transaction time for transition preconditions
and timestamps; replicas never use browser time or process-local time to
extend a record. Online resolution must validate against authoritative time
or a server clock whose health is known; clock uncertainty fails closed for
temporary privileges. Never add a positive expiry grace period. Expiry is a
predicate on the stored deadline, not a promise that a scheduler will run.
Cleanup lag affects notifications/history marking only.

Consume pending requests through a compare-and-swap version/status transition
under a transaction and uniqueness constraints. Duplicate approval with the
same authorized idempotency key returns the original outcome; a conflicting
decision or changed payload fails. Keys are bound to tenant, actor, operation
and immutable request digest. Lost responses cannot create a second activation
or restart its clock. Revocation and eligibility removal serialize with
activation; after their committed transition, no activation may read an older
eligibility version as current. Notification failure does not undo expiry or
reactivate authority; send notifications through the existing bounded outbox.

Record eligibility changes, request creation/cancellation, decisions,
activation, revocation, effective expiry and renewal attempts with stable
references, actor, tenant, resource/permission digest, relevant revisions,
assurance category, reason and authoritative timestamps. Commit lifecycle
changes and durable audit/outbox intent together; if persistence fails, grant
no activation. Never log credentials or raw protocol tokens. Reasons are
bounded user content, safely rendered and visible only to authorized actors.
One idempotent expiry event per activation is sufficient; authorization does
not depend on that event having been written yet.

## Decision acceptance and implementation boundary

The selected states, authorization matrix, five-minute immutable approval
window, one-hour activation ceiling and fail-closed live eligibility checks
define the accepted lifecycle contract for ast-dd1y.5.1. This local decision
adds no cryptographic or wire protocol. Runtime data model, APIs, UI, migration,
issuance integration, concurrency/expiry tests and operational documentation
are ast-dd1y.5.2; ownership and periodic reviews are ast-dd1y.5.4. Closing the
decision does not claim those implementations or propagation checks passed.
