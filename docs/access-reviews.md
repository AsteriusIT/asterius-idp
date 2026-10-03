# Standing-access ownership and reviews

The supported initial catalogue covers five standing provenance sources: one managed-group membership, one
user tenant/client application-role assignment, or one group tenant/client
application-role assignment. Administrative roles, legacy claim strings and
temporary privilege activations remain distinct authorities.

Ownership is explicit, tenant scoped and versioned. Initial owners and assigned
reviewers are active tenant administrators of the same realm; assignment alone
confers no administrative role. New `admin.governance:read` and
`admin.governance:write` operations use the existing closed-role grants
model. A read-only auditor cannot decide or apply a removal. Human decisions
use the actual verified session tenant and subject, never a posted UUID or a
fabricated automation actor. Writes remain subject to the normal console CSRF,
current authority and explicit assignment checks.

A review contains one to two hundred current assignment snapshots and one
explicit eligible reviewer, with a deadline within ninety days. Snapshots show
at most one hundred affected members per group, five hundred standing sources
and one hundred temporary lifecycle entries per user. Complete evidence is
bounded to 512 KiB per item and 4 MiB per review; exceeding a bound rejects the
entire snapshot rather than silently omitting sources. Snapshots show
current application-role provenance from direct and managed-group assignments:
deleting a group
source does not imply a separately granted direct role disappears. Temporary
activation entries describe their live lifecycle at the same database observation
time; they do not establish authority for any specific token, Grant scopes,
delegation or proof. These snapshots are not a global inventory of every policy
decision or administrative authority. A retain or
remove decision is independent from applying it. No decision grants access and
no scheduled job automatically deletes an assignment.

Each live assignment has a generation that changes on edit or deletion and
recreation. Applying removal must check the current assignment generation,
owner-policy revision, live owner and reviewer authority, target scope and
snapshot meaning in the same transaction as the existing lifecycle removal
and durable audit append. A changed or unavailable source becomes a conflict;
it cannot silently remove newly granted access. SCIM-, LDAP-, builder- or
controller-owned authority is protected: a review can propose removal, but
cannot impersonate its owner or bypass the controller's deletion protection.

Historical snapshots remain readable to authorized actors after the target,
owner configuration or user disappears. Reason text is bounded and privately
rendered; the audit records identifiers and results rather than logging reasons
or credentials. Notifications are disabled unless a separately authorized
transport is configured. Notification delivery is not configured by this workflow.

Application compares ownership revision, assignment generation and the complete
bounded context, including group membership, affected account status and application
metadata updates. Deleting and recreating a source does not revive an older decision.
The read-only report helper uses the same context shape in its caller's snapshot
without acquiring mutation locks.

Verified against an isolated PostgreSQL database and the actual server binary:
20 browser/API checks exercised a real user-verifying resident passkey enrollment,
a fresh assertion and signed assurance, all five source removals, retain, ownership
and generation drift, new group membership, controller/LDAP protection, concurrent
retry and audit rollback. The actual desktop/mobile console passed WCAG AA checks.
The targeted final gate passed formatting, strict Clippy and 63 tests including
mandatory source/secret audits; all 112 fuzz targets compiled and passed strict
linting. Slow ignored PostgreSQL integration tests remain reserved for CI.
See [the captured evidence](evidence/access-reviews-2026-10-03.json).
