# Standing-access ownership and reviews

Runtime implementation is in progress in ast-dd1y.5.4. The proposed initial
catalogue covers five provenance sources: one managed-group membership, one
user tenant/client application-role assignment, or one group tenant/client
application-role assignment. Administrative roles, legacy claim strings and
temporary privilege activations remain distinct authorities.

Ownership is explicit, tenant scoped and versioned. Initial owners and assigned
reviewers are active tenant administrators of the same realm; assignment alone
confers no administrative role. New `admin.governance:read` and
`admin.governance:write` operations will use the existing closed-role grants
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
transport is configured. This implementation preparation does not enable or
send email, Slack or other external messages.

Current preparation evidence: migration 0165 applied successfully in an owned
disposable Asterius database; ordinary assignment edits and deletion/recreation
changed generation, ownership changes invalidated revisions, and historical
review snapshots survived ownership-configuration deletion. Runtime API,
interface and final targeted verification remain required before advertising
this workflow as supported.
