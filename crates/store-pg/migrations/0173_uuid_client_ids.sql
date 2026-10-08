-- One-time conversion of server-assigned client IDs to public UUIDs.
-- HTTPS CIMD identifiers remain URLs: their URL is their protocol identity.
-- Historical audit rows retain the identifier that was true when recorded.
-- This is a breaking change for external clients; deploy their new IDs together
-- with this migration. No old-ID alias is admitted at OAuth endpoints.

create temporary table client_uuid_map (
    tenant_id text not null,
    old_id text not null,
    new_id text not null,
    primary key (tenant_id, old_id),
    unique (tenant_id, new_id)
) on commit drop;

insert into client_uuid_map (tenant_id, old_id, new_id)
select tenant_id, client_id, gen_random_uuid()::text
from clients
where client_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  and client_id not like 'https://%';

-- Operators need the cutover mapping to update external application configs.
-- This table is evidence only; no OAuth lookup uses it as an alias.
create table client_id_migrations (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    old_client_id text not null,
    new_client_id uuid not null,
    migrated_at timestamptz not null default now(),
    primary key (tenant_id, old_client_id),
    unique (tenant_id, new_client_id)
);
insert into client_id_migrations (tenant_id, old_client_id, new_client_id)
select tenant_id, old_id, new_id::uuid from client_uuid_map;

-- The application and user namespaces now have the same textual shape. Never
-- assign an actual user's public subject to a client in this tenant.
do $$ begin
    if exists (
        select 1 from client_uuid_map m join users u
          on u.tenant_id = m.tenant_id and u.user_id::text = m.new_id
    ) then
        raise exception 'a newly drawn client UUID matched a user UUID';
    end if;
end $$;

-- Deferring the existing foreign keys lets one transaction move a parent and
-- every child without exposing an intermediate identity to other sessions.
create temporary table client_uuid_fk_modes on commit drop as
select conrelid::regclass as relation, conname, condeferrable, condeferred
from pg_constraint where contype = 'f' and connamespace = current_schema()::regnamespace;

do $$ declare fk record; begin
    for fk in select * from client_uuid_fk_modes where not condeferrable loop
        execute format('alter table %s alter constraint %I deferrable initially deferred',
            fk.relation, fk.conname);
    end loop;
end $$;
set constraints all deferred;

create function pg_temp.rewrite_client_uuid(value jsonb, workspace text)
returns jsonb language plpgsql as $fn$
declare result jsonb; old_text text; replacement text;
begin
    if value is null then return null; end if;
    case jsonb_typeof(value)
        when 'string' then
            old_text := value #>> '{}';
            select new_id into replacement from client_uuid_map
              where tenant_id = workspace and old_id = old_text;
            return to_jsonb(coalesce(replacement, old_text));
        when 'array' then
            select coalesce(jsonb_agg(pg_temp.rewrite_client_uuid(element, workspace) order by ord), '[]'::jsonb)
              into result from jsonb_array_elements(value) with ordinality as parts(element, ord);
            return result;
        when 'object' then
            select coalesce(jsonb_object_agg(coalesce(m.new_id, entry.key),
                    pg_temp.rewrite_client_uuid(entry.value, workspace)), '{}'::jsonb)
              into result
              from jsonb_each(value) as entry(key, value)
              left join client_uuid_map m on m.tenant_id = workspace and m.old_id = entry.key;
            return result;
        else return value;
    end case;
end $fn$;

-- A declaratively owned application checks the owner key during its UPDATE.
-- Move those keys first, and keep creation-key foreign keys deferred.
update declarative_owners d
set keys = pg_temp.rewrite_client_uuid(d.keys, d.tenant_id)
where d.kind = 'application' and exists (
    select 1 from client_uuid_map m where m.tenant_id = d.tenant_id and d.keys @> to_jsonb(array[m.old_id])
);
update declarative_creation_keys d
set keys = pg_temp.rewrite_client_uuid(d.keys, d.tenant_id),
    initial_spec = pg_temp.rewrite_client_uuid(d.initial_spec, d.tenant_id)
where d.kind = 'application' and exists (
    select 1 from client_uuid_map m where m.tenant_id = d.tenant_id and d.keys @> to_jsonb(array[m.old_id])
);

update clients c set client_id = m.new_id
from client_uuid_map m where c.tenant_id = m.tenant_id and c.client_id = m.old_id;

-- All text references with a client-specific column name are rewritten in one
-- UPDATE per table, so row-level checks comparing two client columns hold.
do $$ declare item record; assignments text; predicate text; begin
    for item in
        select table_schema, table_name,
               string_agg(format('%I = coalesce((select m.new_id from client_uuid_map m where m.tenant_id = t.tenant_id and m.old_id = t.%I), t.%I)', column_name, column_name, column_name), ', ' order by ordinal_position) as assignments,
               string_agg(format('exists (select 1 from client_uuid_map m where m.tenant_id = t.tenant_id and m.old_id = t.%I)', column_name), ' or ' order by ordinal_position) as predicate
        from information_schema.columns c
        where table_schema = current_schema() and data_type = 'text'
          and (column_name like '%client_id' or column_name like '%client_reference'
               or (table_name = 'temporary_kubernetes_bindings' and column_name = 'controller_reference'))
          and table_name not in ('clients', 'audit_events', 'client_id_migrations', 'oidc_identity_providers', 'oidc_upstream_pending')
          and exists (select 1 from information_schema.columns t
                      where t.table_schema = c.table_schema and t.table_name = c.table_name
                        and t.column_name = 'tenant_id')
        group by table_schema, table_name
    loop
        assignments := item.assignments;
        predicate := item.predicate;
        execute format('update %I.%I t set %s where %s', item.table_schema, item.table_name,
            assignments, predicate);
    end loop;
end $$;

-- Client-credential grants use the client identifier as their subject.
update grants g set subject = m.new_id from client_uuid_map m
where g.tenant_id = m.tenant_id and g.subject = m.old_id;

update resource_servers r
set introspection_clients = array(
    select coalesce(m.new_id, id) from unnest(r.introspection_clients)
      with ordinality as refs(id, ord)
      left join client_uuid_map m on m.tenant_id = r.tenant_id and m.old_id = refs.id
    order by ord
)
where exists (select 1 from unnest(r.introspection_clients) id
              join client_uuid_map m on m.tenant_id = r.tenant_id and m.old_id = id);

update managed_devices d
set allowed_client_ids = array(
    select coalesce(m.new_id, id) from unnest(d.allowed_client_ids)
      with ordinality as refs(id, ord)
      left join client_uuid_map m on m.tenant_id = d.tenant_id and m.old_id = refs.id
    order by ord
)
where exists (select 1 from unnest(d.allowed_client_ids) id
              join client_uuid_map m on m.tenant_id = d.tenant_id and m.old_id = id);

-- Active JSON documents can carry IDs as either object keys or string values.
-- Signed key material, immutable audit evidence and historical snapshots are
-- excluded: rewriting a signature or past event would falsify its provenance.
do $$ declare item record; begin
    for item in
        select c.table_schema, c.table_name, c.column_name
        from information_schema.columns c
        where c.table_schema = current_schema() and c.data_type = 'jsonb'
          and c.table_name in (
            'architecture_flows', 'auth_requests', 'ciba_requests', 'clients',
            'declarative_creation_keys', 'declarative_deletion_receipts',
            'declarative_owners', 'device_codes', 'first_party_interactions',
            'grants', 'managed_device_code_proofs', 'managed_device_interaction_proofs',
            'oid4vp_transactions', 'ssf_stream_subjects',
            'temporary_entitlement_replays', 'tenant_policies', 'tenants',
            'workload_trusts'
          )
          and not (c.table_name = 'clients' and c.column_name in ('jwks', 'software_statement'))
          and not (c.table_name = 'declarative_creation_keys' and c.column_name in ('keys', 'initial_spec'))
          and not (c.table_name = 'declarative_owners' and c.column_name = 'keys')
          and exists (select 1 from information_schema.columns t where t.table_schema = c.table_schema
              and t.table_name = c.table_name and t.column_name = 'tenant_id')
    loop
        execute format('update %I.%I t set %I = pg_temp.rewrite_client_uuid(t.%I, t.tenant_id) where exists (select 1 from client_uuid_map m where m.tenant_id=t.tenant_id and position(to_jsonb(m.old_id)::text in t.%I::text) > 0)',
            item.table_schema, item.table_name, item.column_name, item.column_name,
            item.column_name);
    end loop;
end $$;

set constraints all immediate;

do $$ declare fk record; begin
    for fk in select * from client_uuid_fk_modes where not condeferrable loop
        execute format('alter table %s alter constraint %I not deferrable', fk.relation, fk.conname);
    end loop;
end $$;

-- The temporary map disappears at commit. The durable operator mapping is
-- deliberately not part of authentication: old identifiers stop working.
