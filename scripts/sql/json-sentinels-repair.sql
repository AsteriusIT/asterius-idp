-- Repairs rows carrying a serde_json sentinel member name, in place, in SQL.
--
-- Deliberately separate from `json-sentinels-detect.sql`: an operator looks
-- first and acts second, and a script that did both would remove the looking.
-- Run the detection, read what it found, then run this. Nothing here runs at
-- start-up and none of it is a migration -- repairing rows is an explicit act,
-- not something a deployment does behind an operator's back.
--
-- The fix is a rename, not a delete: every reserved member is renamed to
-- 'quarantined_' || <original name>. The value is untouched, the document
-- becomes parseable again, and the original name is still legible so that
-- whoever investigates can see exactly what was there and where it came from.
-- The list of reserved names mirrors `SERDE_JSON_SENTINELS` in
-- `crates/domain/src/json_sentinel.rs`; `scripts/check-json-sentinels.sh`
-- fails if the two drift.
--
-- What this does NOT touch, on purpose:
--
--   * `audit_events`. The table is append-only (`audit_events_no_update`) and
--     each record hashes its predecessor, so rewriting a member would both be
--     refused and, if it were not, would invalidate the chain from that record
--     onwards. Findings there are re-reported at the end for a human.
--
-- Rows in `tenants`, `clients`, `users` and `grants` carry an `updated_at`
-- trigger, so a repaired row's timestamp moves. That is a true statement about
-- the row and the only trace this operation leaves in the data itself; the
-- journal of what changed is the result set below, which
-- `scripts/repair-json-sentinels.sh` writes to a log file.

-- Renames every reserved member, at every depth, and leaves everything else
-- exactly as it was -- including member order, which is not a property JSONB
-- keeps anyway.
--
-- `pg_temp` so that the repair leaves no schema behind it: the function dies
-- with the session. It recurses, which a SQL-bodied function may do only with
-- the quoted body form, whose parse is deferred to the first call.
--
-- A document that already had 'quarantined_$serde_json::private::RawValue'
-- *and* the reserved name beside it would end up with one member, the later
-- one winning. That collision is reported by the detection script (both names
-- appear), and is not silently possible otherwise.
create function pg_temp.quarantine_serde_json_sentinels(doc jsonb)
returns jsonb language sql immutable as $$
    select case jsonb_typeof(doc)
        when 'object' then (
            select coalesce(
                jsonb_object_agg(
                    case
                        when member.key in ('$serde_json::private::RawValue',
                                            '$serde_json::private::Number')
                        then 'quarantined_' || member.key
                        else member.key
                    end,
                    pg_temp.quarantine_serde_json_sentinels(member.value)
                ),
                '{}'::jsonb)
            from jsonb_each(doc) as member)
        when 'array' then (
            select coalesce(
                jsonb_agg(pg_temp.quarantine_serde_json_sentinels(element) order by ordinality),
                '[]'::jsonb)
            from jsonb_array_elements(doc) with ordinality as t (element, ordinality))
        else doc
    end
$$;

-- Whether a value carries a reserved member name anywhere. Same predicate as
-- the detection script, named once here because every statement below uses it.
create function pg_temp.has_serde_json_sentinel(doc jsonb)
returns boolean language sql immutable as $$
    select jsonb_path_exists(
        doc,
        'lax $.** ? (@.type() == "object").keyvalue()
             ? (@.key == "$serde_json::private::RawValue"
             || @.key == "$serde_json::private::Number")')
$$;

-- The names this repair put in place, read back off the repaired value so the
-- journal says which reserved names were actually found in that row.
create function pg_temp.quarantined_keys(doc jsonb)
returns text[] language sql immutable as $$
    select array_agg(distinct key order by key)
    from (
        select member ->> 'key' as key
        from jsonb_path_query(doc, 'lax $.** ? (@.type() == "object").keyvalue()') as member
    ) keys
    where key like 'quarantined\_$serde\_json::private::%'
$$;

-- One statement, so the whole repair commits or none of it does, and one
-- result set, which is the journal of what it did.
with tenants_settings as (
    update tenants set settings = pg_temp.quarantine_serde_json_sentinels(settings)
    where pg_temp.has_serde_json_sentinel(settings)
    returning 'tenants' as t, 'settings' as c,
              jsonb_build_object('tenant_id', tenant_id) as k,
              pg_temp.quarantined_keys(settings) as names
),
tenant_themes_document as (
    update tenant_themes set document = pg_temp.quarantine_serde_json_sentinels(document)
    where pg_temp.has_serde_json_sentinel(document)
    returning 'tenant_themes', 'document',
              jsonb_build_object('tenant_id', tenant_id),
              pg_temp.quarantined_keys(document)
),
tenant_policies_document as (
    update tenant_policies set document = pg_temp.quarantine_serde_json_sentinels(document)
    where pg_temp.has_serde_json_sentinel(document)
    returning 'tenant_policies', 'document',
              jsonb_build_object('tenant_id', tenant_id),
              pg_temp.quarantined_keys(document)
),
clients_jwks as (
    update clients set jwks = pg_temp.quarantine_serde_json_sentinels(jwks)
    where pg_temp.has_serde_json_sentinel(jwks)
    returning 'clients', 'jwks',
              jsonb_build_object('tenant_id', tenant_id, 'client_id', client_id),
              pg_temp.quarantined_keys(jwks)
),
clients_agent_policy as (
    update clients set agent_policy = pg_temp.quarantine_serde_json_sentinels(agent_policy)
    where pg_temp.has_serde_json_sentinel(agent_policy)
    returning 'clients', 'agent_policy',
              jsonb_build_object('tenant_id', tenant_id, 'client_id', client_id),
              pg_temp.quarantined_keys(agent_policy)
),
clients_software_statement as (
    update clients set software_statement = pg_temp.quarantine_serde_json_sentinels(software_statement)
    where pg_temp.has_serde_json_sentinel(software_statement)
    returning 'clients', 'software_statement',
              jsonb_build_object('tenant_id', tenant_id, 'client_id', client_id),
              pg_temp.quarantined_keys(software_statement)
),
client_keys_jwk as (
    update client_keys set jwk = pg_temp.quarantine_serde_json_sentinels(jwk)
    where pg_temp.has_serde_json_sentinel(jwk)
    returning 'client_keys', 'jwk',
              jsonb_build_object('tenant_id', tenant_id, 'client_id', client_id, 'kid', kid),
              pg_temp.quarantined_keys(jwk)
),
users_claims as (
    update users set claims = pg_temp.quarantine_serde_json_sentinels(claims)
    where pg_temp.has_serde_json_sentinel(claims)
    returning 'users', 'claims',
              jsonb_build_object('tenant_id', tenant_id, 'user_id', user_id),
              pg_temp.quarantined_keys(claims)
),
authorization_details_types_schema as (
    update authorization_details_types
       set schema = pg_temp.quarantine_serde_json_sentinels(schema)
    where pg_temp.has_serde_json_sentinel(schema)
    returning 'authorization_details_types', 'schema',
              jsonb_build_object('tenant_id', tenant_id, 'type_name', type_name),
              pg_temp.quarantined_keys(schema)
),
auth_requests_parameters as (
    update auth_requests set parameters = pg_temp.quarantine_serde_json_sentinels(parameters)
    where pg_temp.has_serde_json_sentinel(parameters)
    returning 'auth_requests', 'parameters',
              jsonb_build_object('tenant_id', tenant_id,
                                 'request_uri_hash', encode(request_uri_hash, 'hex')),
              pg_temp.quarantined_keys(parameters)
),
auth_requests_interaction_state as (
    update auth_requests set interaction_state = pg_temp.quarantine_serde_json_sentinels(interaction_state)
    where pg_temp.has_serde_json_sentinel(interaction_state)
    returning 'auth_requests', 'interaction_state',
              jsonb_build_object('tenant_id', tenant_id,
                                 'request_uri_hash', encode(request_uri_hash, 'hex')),
              pg_temp.quarantined_keys(interaction_state)
),
-- The console's login keeps the same progress document in a table of its own
-- (`ast-wr4`), so it is repaired on exactly the same terms as the column above:
-- one stage machine writes both, and a rule that held for one of the two
-- tables and not the other would be a rule about where the row sits rather
-- than about what it holds. Missing here until `ast-sgo`, while the detection
-- script called it repairable.
--
-- The rename does not reconstruct login progress -- nothing can, an
-- interaction is a flow in mid-air -- it makes the row loadable again. What
-- the stage machine does with a quarantined member is what it does with any
-- state it cannot make sense of: the person starts the login over, and the
-- row is swept by the `first_party_interactions` retention rule at
-- `expires_at`, as expired interactions always are.
first_party_interactions_interaction_state as (
    update first_party_interactions
       set interaction_state = pg_temp.quarantine_serde_json_sentinels(interaction_state)
    where pg_temp.has_serde_json_sentinel(interaction_state)
    returning 'first_party_interactions', 'interaction_state',
              jsonb_build_object('tenant_id', tenant_id,
                                 'interaction_id_hash', encode(interaction_id_hash, 'hex')),
              pg_temp.quarantined_keys(interaction_state)
),
grants_claims as (
    update grants set claims = pg_temp.quarantine_serde_json_sentinels(claims)
    where pg_temp.has_serde_json_sentinel(claims)
    returning 'grants', 'claims',
              jsonb_build_object('tenant_id', tenant_id, 'grant_id', grant_id),
              pg_temp.quarantined_keys(claims)
),
grants_authorization_details as (
    update grants set authorization_details = pg_temp.quarantine_serde_json_sentinels(authorization_details)
    where pg_temp.has_serde_json_sentinel(authorization_details)
    returning 'grants', 'authorization_details',
              jsonb_build_object('tenant_id', tenant_id, 'grant_id', grant_id),
              pg_temp.quarantined_keys(authorization_details)
),
grants_actor_chain as (
    update grants set actor_chain = pg_temp.quarantine_serde_json_sentinels(actor_chain)
    where pg_temp.has_serde_json_sentinel(actor_chain)
    returning 'grants', 'actor_chain',
              jsonb_build_object('tenant_id', tenant_id, 'grant_id', grant_id),
              pg_temp.quarantined_keys(actor_chain)
),
device_codes_authorization_details as (
    update device_codes
       set authorization_details = pg_temp.quarantine_serde_json_sentinels(authorization_details)
    where pg_temp.has_serde_json_sentinel(authorization_details)
    returning 'device_codes', 'authorization_details',
              jsonb_build_object('tenant_id', tenant_id,
                                 'device_code_hash', encode(device_code_hash, 'hex')),
              pg_temp.quarantined_keys(authorization_details)
),
ciba_requests_authorization_details as (
    update ciba_requests
       set authorization_details = pg_temp.quarantine_serde_json_sentinels(authorization_details)
    where pg_temp.has_serde_json_sentinel(authorization_details)
    returning 'ciba_requests', 'authorization_details',
              jsonb_build_object('tenant_id', tenant_id,
                                 'auth_req_id_hash', encode(auth_req_id_hash, 'hex')),
              pg_temp.quarantined_keys(authorization_details)
),
signing_keys_public_jwk as (
    update signing_keys set public_jwk = pg_temp.quarantine_serde_json_sentinels(public_jwk)
    where pg_temp.has_serde_json_sentinel(public_jwk)
    returning 'signing_keys', 'public_jwk',
              jsonb_build_object('tenant_id', tenant_id, 'kid', kid),
              pg_temp.quarantined_keys(public_jwk)
),
outbox_payload as (
    update outbox set payload = pg_temp.quarantine_serde_json_sentinels(payload)
    where pg_temp.has_serde_json_sentinel(payload)
    returning 'outbox', 'payload',
              jsonb_build_object('tenant_id', tenant_id, 'outbox_id', outbox_id),
              pg_temp.quarantined_keys(payload)
),
repaired as (
    select * from tenants_settings
    union all select * from tenant_themes_document
    union all select * from tenant_policies_document
    union all select * from clients_jwks
    union all select * from clients_agent_policy
    union all select * from clients_software_statement
    union all select * from client_keys_jwk
    union all select * from users_claims
    union all select * from auth_requests_parameters
    union all select * from auth_requests_interaction_state
    union all select * from first_party_interactions_interaction_state
    union all select * from grants_claims
    union all select * from authorization_details_types_schema
    union all select * from grants_authorization_details
    union all select * from grants_actor_chain
    union all select * from device_codes_authorization_details
    union all select * from ciba_requests_authorization_details
    union all select * from signing_keys_public_jwk
    union all select * from outbox_payload
)
select 'repaired' as action, t as table_name, c as column_name, k as row_key, names as quarantined_keys
from repaired
order by table_name, column_name, row_key;

-- What was left alone, and has to be dealt with by a human: see the header.
select 'left_for_a_human' as action,
       'audit_events'     as table_name,
       column_name,
       row_key,
       null::text[]       as quarantined_keys
from (
    select 'actor' as column_name,
           jsonb_build_object('tenant_id', tenant_id, 'event_id', event_id) as row_key,
           actor as doc
    from audit_events
    union all
    select 'actor_chain',
           jsonb_build_object('tenant_id', tenant_id, 'event_id', event_id),
           actor_chain
    from audit_events
    union all
    select 'detail',
           jsonb_build_object('tenant_id', tenant_id, 'event_id', event_id),
           detail
    from audit_events
) audit
where pg_temp.has_serde_json_sentinel(doc)
order by column_name, row_key;
