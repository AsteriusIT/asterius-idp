-- Read-only detection of serde_json sentinel member names in JSONB columns.
--
-- The two reserved names are the ones `serde_json` uses for its own private
-- types. The authoritative list is `SERDE_JSON_SENTINELS` in
-- `crates/domain/src/json_sentinel.rs`; this file repeats it because it has to
-- run where no Rust can, and `scripts/check-json-sentinels.sh` fails if the two
-- lists ever drift.
--
-- Why SQL and not a tool: a row carrying a sentinel as the *first* member of an
-- object cannot be parsed by any binary linking `serde_json` with the
-- `raw_value` feature -- which axum and sqlx turn on for the whole workspace. A
-- repair tool that loads the row to fix it cannot load the row. Member order
-- also decides whether the parse fails *today*, so this looks for rows that
-- carry a reserved name anywhere, not for rows that fail a read right now: any
-- rewrite that re-sorts the members turns the second set into the first.
--
-- Safe in production: this statement only reads. It takes ACCESS SHARE locks
-- and blocks nothing but DDL, and `scripts/check-json-sentinels.sh` runs it in
-- a read-only transaction under a statement timeout. It does sequentially scan
-- every JSONB column in the schema, so prefer off-peak, or a replica.
--
-- One result set, one row per finding:
--   finding        'sentinel' -- a row carries a reserved member name
--                  'unreviewed_column' -- a JSONB column this file does not
--                  cover, meaning the inventory below has gone stale
--   repairable     whether `json-sentinels-repair.sql` may rewrite that column
--   row_key        the primary key of the offending row, as JSON
--   sentinel_keys  the reserved names found in that column's value

with sentinels (name) as (
    values ('$serde_json::private::RawValue'),
           ('$serde_json::private::Number')
),

-- Every JSONB column in the schema, paired with the primary key identifying
-- the row it came from. The set is deliberately every column and not only the
-- tenant-facing ones: `users.claims` and `grants.claims` are where a sentinel
-- was reachable by design, but an admin API, an import or a restored dump can
-- put one anywhere, and a column left unscanned is a column nobody looks at.
--
-- `repairable` is false where a row must not be rewritten in place:
-- `audit_events` is append-only (the `audit_events_no_update` trigger) and
-- hash-chained, so editing a member would invalidate every record after it.
-- Those findings are reported for a human to decide.
docs (table_name, column_name, repairable, row_key, doc) as (
    select 'tenants', 'settings', true,
           jsonb_build_object('tenant_id', tenant_id), settings
    from tenants
    union all
    select 'clients', 'jwks', true,
           jsonb_build_object('tenant_id', tenant_id, 'client_id', client_id), jwks
    from clients
    union all
    select 'clients', 'agent_policy', true,
           jsonb_build_object('tenant_id', tenant_id, 'client_id', client_id), agent_policy
    from clients
    union all
    select 'clients', 'software_statement', true,
           jsonb_build_object('tenant_id', tenant_id, 'client_id', client_id), software_statement
    from clients
    union all
    select 'client_keys', 'jwk', true,
           jsonb_build_object('tenant_id', tenant_id, 'client_id', client_id, 'kid', kid), jwk
    from client_keys
    union all
    select 'users', 'claims', true,
           jsonb_build_object('tenant_id', tenant_id, 'user_id', user_id), claims
    from users
    union all
    -- Operator-written JSON Schema (`0004`). Nothing in the domain builds it
    -- from a `serde_json::Value` it did not validate, but it is the one JSONB
    -- column whose content an admin pastes in whole, so it is scanned like the
    -- rest.
    select 'authorization_details_types', 'schema', true,
           jsonb_build_object('tenant_id', tenant_id, 'type_name', type_name), schema
    from authorization_details_types
    union all
    select 'auth_requests', 'parameters', true,
           jsonb_build_object('tenant_id', tenant_id,
                              'request_uri_hash', encode(request_uri_hash, 'hex')),
           parameters
    from auth_requests
    union all
    select 'auth_requests', 'interaction_state', true,
           jsonb_build_object('tenant_id', tenant_id,
                              'request_uri_hash', encode(request_uri_hash, 'hex')),
           interaction_state
    from auth_requests
    union all
    -- The console's login (`ast-wr4`) keeps the same progress document in a
    -- table of its own, because it has no client and therefore no
    -- `request_uri` to be keyed by.
    select 'first_party_interactions', 'interaction_state', true,
           jsonb_build_object('tenant_id', tenant_id,
                              'interaction_id_hash', encode(interaction_id_hash, 'hex')),
           interaction_state
    from first_party_interactions
    union all
    select 'grants', 'claims', true,
           jsonb_build_object('tenant_id', tenant_id, 'grant_id', grant_id), claims
    from grants
    union all
    select 'grants', 'authorization_details', true,
           jsonb_build_object('tenant_id', tenant_id, 'grant_id', grant_id), authorization_details
    from grants
    union all
    select 'grants', 'actor_chain', true,
           jsonb_build_object('tenant_id', tenant_id, 'grant_id', grant_id), actor_chain
    from grants
    union all
    select 'signing_keys', 'public_jwk', true,
           jsonb_build_object('tenant_id', tenant_id, 'kid', kid), public_jwk
    from signing_keys
    union all
    select 'outbox', 'payload', true,
           jsonb_build_object('tenant_id', tenant_id, 'outbox_id', outbox_id), payload
    from outbox
    union all
    select 'audit_events', 'actor', false,
           jsonb_build_object('tenant_id', tenant_id, 'event_id', event_id), actor
    from audit_events
    union all
    select 'audit_events', 'actor_chain', false,
           jsonb_build_object('tenant_id', tenant_id, 'event_id', event_id), actor_chain
    from audit_events
    union all
    select 'audit_events', 'detail', false,
           jsonb_build_object('tenant_id', tenant_id, 'event_id', event_id), detail
    from audit_events
),

-- The same inventory as names only. It is spelled a second time rather than
-- selected back out of `docs` so that `docs` keeps a single reference and stays
-- inlined: referenced twice, PostgreSQL would materialise every JSONB value in
-- the database before filtering any of them.
inventory (table_name, column_name) as (
    values ('tenants', 'settings'),
           ('clients', 'jwks'),
           ('clients', 'agent_policy'),
           ('clients', 'software_statement'),
           ('client_keys', 'jwk'),
           ('users', 'claims'),
           ('authorization_details_types', 'schema'),
           ('auth_requests', 'parameters'),
           ('auth_requests', 'interaction_state'),
           ('first_party_interactions', 'interaction_state'),
           ('grants', 'claims'),
           ('grants', 'authorization_details'),
           ('grants', 'actor_chain'),
           ('signing_keys', 'public_jwk'),
           ('outbox', 'payload'),
           ('audit_events', 'actor'),
           ('audit_events', 'actor_chain'),
           ('audit_events', 'detail')
),

-- `lax $.**` walks the value and every descendant, unwrapping arrays on the
-- way. The type filter is not optional: `.keyvalue()` raises on a non-object
-- even in lax mode, which would abort the scan on the first array of strings.
hits as (
    select *
    from docs
    where jsonb_path_exists(
        doc,
        'lax $.** ? (@.type() == "object").keyvalue()
             ? (@.key == "$serde_json::private::RawValue"
             || @.key == "$serde_json::private::Number")'
    )
)

select 'sentinel'                                 as finding,
       h.table_name,
       h.column_name,
       h.repairable,
       h.row_key,
       array_agg(distinct kv.key order by kv.key) as sentinel_keys
from hits h
cross join lateral (
    select member ->> 'key' as key
    from jsonb_path_query(h.doc, 'lax $.** ? (@.type() == "object").keyvalue()') as member
) kv
where kv.key in (select name from sentinels)
group by h.table_name, h.column_name, h.repairable, h.row_key

union all

-- A JSONB column added by a later migration and never filed above would be
-- scanned by nothing at all. Reporting it is what keeps this file honest
-- between the runs of the Rust test that checks the same thing in CI.
select 'unreviewed_column',
       c.table_name::text,
       c.column_name::text,
       null::boolean,
       null::jsonb,
       null::text[]
from information_schema.columns c
where c.table_schema = current_schema()
  and c.data_type = 'jsonb'
  and (c.table_name::text, c.column_name::text) not in (
      select table_name, column_name from inventory
  )

order by 1, 2, 3, 5;
