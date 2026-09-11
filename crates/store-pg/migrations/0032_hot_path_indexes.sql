-- Indexes the EXPLAIN review of ast-p2l.8 found missing on paths that grow.
--
-- `scripts/load/explain.sh` seeds a tenant with fifty thousand rows per
-- growing table and runs the hot statements of `.sqlx/` under
-- `EXPLAIN (ANALYZE, BUFFERS)`. Seven of them scanned a table sequentially,
-- and they fall into three kinds. docs/performance.md has the plans.
--
-- # A partial index the query cannot use
--
-- `grants_by_subject`, `grants_by_session` and `sessions_by_user` were
-- declared `where revoked_at is null`, on the reasonable thought that live
-- rows are the ones anybody looks up. The statements that look them up say no
-- such thing: `PgGrantRepository::list_for_subject` reads a person's grants
-- *including* the revoked ones — a revoked grant is a fact the Grant
-- Management API and the console report — and the back-channel logout
-- revocation joins `grants` by `session_id` with no predicate on
-- `revoked_at` either. PostgreSQL only uses a partial index when it can prove
-- the query's predicate implies the index's, and `nothing` does not imply
-- `revoked_at is null`, so the planner read the whole table and filtered.
--
-- The first of those is the consent step of every authorization: "is this
-- request covered by an earlier consent" is a `for_subject` read, so it ran
-- once per sign-in and cost one sequential scan of `grants` per tenant. The
-- review measured 4.7 ms over 50 000 rows, which is a number that grows with
-- the tenant, on the path the tenant's users wait on.
--
-- The fix is the plain index. The `revoked_at is null` narrowing saved index
-- space and nothing else; an index the planner cannot use saves nothing.
-- `session_id is not null` stays on `grants_by_session`, because
-- `session_id = $1` does imply it and half the rows (machine grants) have no
-- session.
--
-- # A lookup with no index at all
--
-- `PgGrantRepository::list_for_user` (the console's "this person's grants",
-- `ast-f7m.6`) reads by `user_id`, which no index led with. The outbox's
-- notification inbox (`kind like 'notification.%' and delivered_at is null`)
-- had `outbox_by_tenant` on `(tenant_id, created_at)`, which is the wrong
-- column for an `order by outbox_id` over a predicate that matches a handful
-- of rows in a table that keeps every delivered one until retention. Both
-- are administrative reads rather than protocol ones, and both scan a table
-- that grows with use, which is the shape this migration exists to close.
--
-- # A sweep with nothing to seek by
--
-- `retention` deletes unclaimed grants older than a day and expired recovery
-- tokens, once per period per tenant. Every other sweep seeks on an
-- `*_expiring` index; these two read the whole table to delete a handful of
-- rows. `grants_unclaimed` is partial on `claimed_at is null and revoked_at
-- is null` — exactly the sweep's predicate, so it *is* usable — and covers a
-- sliver of the table, since a grant is claimed the moment its code is
-- redeemed. `recovery_tokens_expiring` follows the pattern of its peers.
--
-- Plain `create index`, not `concurrently`: sqlx runs a migration inside a
-- transaction, where `concurrently` is refused, and every earlier index in
-- this schema was built the same way. The tables are locked against writes
-- for the length of the build, which on a deployment large enough to notice
-- is the rollout's cost, once.

drop index grants_by_subject;
create index grants_by_subject on grants (tenant_id, subject);

drop index grants_by_session;
create index grants_by_session on grants (tenant_id, session_id)
    where session_id is not null;

create index grants_by_user on grants (tenant_id, user_id)
    where user_id is not null;

create index grants_unclaimed on grants (tenant_id, created_at)
    where claimed_at is null and revoked_at is null;

drop index sessions_by_user;
create index sessions_by_user on sessions (tenant_id, user_id);

create index outbox_notifications_pending on outbox (tenant_id, outbox_id)
    where kind like 'notification.%' and delivered_at is null;

create index recovery_tokens_expiring on recovery_tokens (expires_at);
