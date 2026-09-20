# Managed groups and legacy claims

Migration `0090_managed_groups.sql` introduces an empty, tenant-scoped catalogue
and direct user memberships. Groups have UUID identities which survive renames;
machine names are exact lowercase ASCII (1–64 bytes, initial alphanumeric,
then `a-z0-9._:-`). Display names are 1–200 UTF-8 bytes, with no surrounding
Unicode whitespace, C0/C1 controls or bidirectional formatting characters.
They are labels only and must be rendered as text by future administration UIs.
Names are unique per tenant; the database uses C collation for exact comparison.
All listing ports require a limit of 1–200 and use exclusive UUID cursors.

## Authority cutover and compatibility

Policy evaluation, AuthZEN search and the administration policy test bench now
read only direct rows from `group_memberships`. A caller's `properties.groups`
and the legacy `user.claims["groups"]` bag cannot assert authority. There is no
automatic import, normalization or dual-read union: tenants must compare and
populate managed memberships before deploying this cutover.

Every policy membership contributes a stable `group:<uuid>` reference and its
machine name. Policies should migrate to the stable reference. When a machine
name changes, the old spelling is retained in `managed_group_aliases`, so an
existing name condition keeps its meaning. Display names are never policy input.
Deleting a group cascades aliases and memberships; recreating the same name
creates a different UUID.

Client claim release is separate from policy authority. `managed_groups_claim`
is false by default and scoped to one client registration. Opted-in ID tokens
and UserInfo responses resolve membership live and return at most 100 stable
references in `group_ids`; they never return names, display labels, aliases or
another tenant's directory. The server writes `group_ids` after stored claims,
preventing claim shadowing. Membership edits affect the next decision or response.
Signed tokens remain snapshots until `exp`, bounded by the token lifetime caps.

## Group application roles and revocation

Application roles may be assigned to a managed group. Effective roles are the
deduplicated union of direct assignments and assignments from every direct
group membership. The administration API reports every source (`direct` or a
stable group UUID), so removing one source does not disguise authority that is
still granted by another. Tenant and client ownership is enforced by composite
foreign keys; group grants use only `RoleName` and can never grant the server's
built-in console/deployment administrator `Role` values.

Membership and assignment edits are read live for every authorization
decision, authorization-code exchange, refresh, device/CIBA issuance and
UserInfo response. They therefore affect the next operation. Already-issued
JWTs are signed snapshots and remain valid until `exp`; deleting a membership
or assignment cannot rewrite them. Operators needing immediate revocation must
also revoke the user's grants/sessions (which advances token cutoffs and ends
refresh) or use opaque-token introspection at the resource server. Short access
token lifetimes remain the bounded fallback for offline JWT validation.

## Transactions and concurrency

Each create is one atomic INSERT; duplicate tenant/name or identity conflicts
are reported without overwriting metadata. Metadata updates and deletion lock
the tenant/group row and compare the caller's expected positive revision inside
the same transaction. Stale edits fail as conflicts; missing or other-tenant
identities are not found. Metadata updates retain identity and creation time.
Explicit membership changes take the same row lock and increment its revision
only if the membership actually changed. Retried add/remove calls are idempotent.
A deletion with an earlier revision cannot silently discard a concurrent add.
Concurrent group deletion cannot resurrect a group or leave orphan memberships.
Composite foreign keys enforce tenant membership even for direct SQL writers.

Deleting a group atomically cascades its memberships. Deleting a user cascades
only that user's memberships and retains group definitions and other members.
This referential cleanup does not increment group revisions: revisions detect
explicit group administration changes, not lifecycle events of deleted users.
Membership additions racing user deletion either precede the deletion and are
removed by it or fail the user foreign key. Deleting a tenant cascades both.
Database transaction errors leave no partially committed metadata/membership.
The later audited administration API (`ast-6uqw.10`) must authorize each port
call and record its effect; persistence is not itself an authorization boundary.

## Threat model and verification

The main risks are cross-tenant assignment, stale administrative changes,
authority expansion through legacy-name normalization, misleading display text,
and unbounded enumeration responses. Composite keys, row-lock/revision checks,
strict parsers and bounded keyset reads address those risks. Stable identities
prevent rename from becoming delete/recreate or transferring existing members to
an unrelated group. Nested groups, dynamic rules and SCIM are outside this
persistence ticket.

Domain tests cover parser limits, exact names and identity. The `group_metadata`
fuzz target checks accepted byte/alphabet invariants and round trips. Ignored
PostgreSQL integration tests exercise isolation, duplicate names, revision
conflicts, concurrent membership operations, cascading deletion, schema/parser
agreement and legacy-claim preservation under a complete migration.
