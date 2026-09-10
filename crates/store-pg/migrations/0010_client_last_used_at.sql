-- When a client last authenticated, so that `unused_client_expiry_seconds`
-- can mean something (`ast-cu3`).
--
-- The per-tenant registration policy has stored and validated
-- `unused_client_expiry_seconds` since `ast-m9c.6` and nothing has ever read
-- it, because the schema had no column able to answer "when did this client
-- last do anything". `created_at` is not that column: a client registered a
-- year ago and used every minute since looks identical to one registered a
-- year ago and never used again, and a sweep on `created_at` would delete the
-- busiest clients in the deployment.
--
-- Nullable, and null means "not since this column existed". Backfilling it to
-- `now()` would tell the sweep that every client registered before this
-- migration was used at the moment it ran, which is false; backfilling it to
-- `created_at` would tell the sweep that every long-lived client is idle and
-- delete it on the next pass. Null is read as `created_at` by the sweep
-- statement, which is the honest reading — a client we have never seen
-- authenticate is as old as its registration — and it is safe because a tenant
-- only gets a sweep at all by setting the policy value on purpose.
--
-- Written on the authentication path, so it is deliberately *not* indexed: the
-- update is by primary key, and the sweep that reads it runs once per tenant
-- per interval over a table with one row per client. An index here would be
-- paid for on every token request to buy nothing.

alter table clients add column last_used_at timestamptz;

comment on column clients.last_used_at is
    'When this client last authenticated at the token endpoint or PAR. '
    'Coalesced with created_at by the retention sweep that honours the '
    'tenant registration policy''s unused_client_expiry_seconds. Written at '
    'most once per client per hour, by asterius_store_pg::PgClientUsage.';
