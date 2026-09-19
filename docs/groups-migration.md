# Managed groups and legacy claims

Migration `0090_managed_groups.sql` introduces an empty, tenant-scoped catalogue
and direct user memberships. Groups have UUID identities which survive renames;
machine names are exact lowercase ASCII (1–64 bytes, initial alphanumeric,
then `a-z0-9._:-`). Display names are 1–200 UTF-8 bytes, with no surrounding
Unicode whitespace, C0/C1 controls or bidirectional formatting characters.
They are labels only and must be rendered as text by future administration UIs.
Names are unique per tenant; the database uses C collation for exact comparison.
All listing ports require a limit of 1–200 and use exclusive UUID cursors.

## Compatibility decision

The existing `groups_of(user)` in `crates/server/src/http/protocol.rs` continues
to read `user.claims["groups"].value`. It accepts string elements of an array,
deduplicates them, and ignores non-string elements; a non-array means no groups.
Those strings have historically allowed values outside the new name alphabet.
This migration therefore **does not import, normalize, remove or rewrite them**.
No managed group or membership is consulted by policy evaluation or token claims
in this change. Existing authorization and claim release remain byte-for-byte
unchanged by installing the schema. Creating a managed group named like a legacy
group has no authority effect. This is a staged coexistence migration, not a
claim-to-membership backfill, and no automatic dual-read union is allowed.

The authority cutover belongs to `ast-6uqw.12`. Before enabling managed groups as
policy input, that change must provide a tenant-reviewed comparison of every
legacy string membership with the proposed managed membership; preserve a backup
of the legacy values/provenance; obtain an explicit mapping for nonrepresentable
names; and account for all existing policy group references and claim release
contracts. A tenant with unresolved differences must retain legacy behavior.
An automatic lowercase/trim import or union of both sources could grant access;
simply switching reads to the initially empty tables could withdraw access.
A rollback during coexistence only removes unused managed persistence and never
requires changing the existing claims. After cutover, rollback needs its own
reviewed authority reconciliation and must not re-enable stale claims blindly.

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
an unrelated group. Nested groups, dynamic rules, SCIM and inherited roles are
outside this persistence ticket. No HTTP routes are added, so OpenAPI is unchanged.

Domain tests cover parser limits, exact names and identity. The `group_metadata`
fuzz target checks accepted byte/alphabet invariants and round trips. Ignored
PostgreSQL integration tests exercise isolation, duplicate names, revision
conflicts, concurrent membership operations, cascading deletion, schema/parser
agreement and legacy-claim preservation under a complete migration.
