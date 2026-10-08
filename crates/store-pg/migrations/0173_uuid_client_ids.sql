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

-- Existing-data cutover is terminal and must be explicitly rehearsed/approved.
-- Fresh installations have no clients yet and need no operator setting.
do $$ begin
    if exists (select 1 from client_uuid_map)
       and current_setting('asterius.client_uuid_terminal_cutover', true)
           is distinct from 'approved' then
        raise exception 'populated UUID client cutover requires a restored-backup rehearsal and asterius.client_uuid_terminal_cutover=approved';
    end if;
end $$;

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

create function client_uuid_lookup_history_immutable() returns trigger language plpgsql as $$
declare column_name text;
begin
    foreach column_name in array tg_argv loop
        if (tg_op='INSERT' and to_jsonb(new)->column_name is distinct from 'null'::jsonb)
           or (tg_op='UPDATE' and to_jsonb(new)->column_name is distinct from to_jsonb(old)->column_name) then
            raise exception 'UUID client cutover lookup history is immutable' using errcode='23514';
        end if;
    end loop;
    return new;
end $$;

do $$ declare item record; args text; snapshot_name text; begin
    for item in
        select c.table_schema,c.table_name,c.column_name
        from information_schema.columns c
        where c.table_schema=current_schema() and c.data_type='text'
          and (c.column_name like '%client_id' or c.column_name like '%client_reference')
          and c.table_name not in ('audit_events','client_id_migrations','oidc_identity_providers','oidc_upstream_pending',
              'agent_tasks','temporary_entitlements','temporary_entitlement_requests','temporary_kubernetes_bindings')
          and exists (select 1 from information_schema.columns t where t.table_schema=c.table_schema
              and t.table_name=c.table_name and t.column_name='tenant_id')
    loop
        snapshot_name:=item.column_name || '_before_uuid_cutover';
        execute format('alter table %I.%I add column %I text',item.table_schema,item.table_name,snapshot_name);
    end loop;
end $$;
alter table grants add column authority_revision_before_uuid_cutover uuid;
alter table grants add column subject_before_uuid_cutover text;

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

-- Withdraw old approved authority through its existing guarded transitions.
-- Frozen identities, permissions and captured revisions are never rewritten.
update agent_tasks t
set client_reference = null,
    revoked_at = coalesce(t.revoked_at, clock_timestamp()),
    revocation_reason = coalesce(t.revocation_reason, 'client_id_cutover')
where exists (select 1 from client_uuid_map m where m.tenant_id=t.tenant_id and m.old_id=t.initiating_client_id);

update temporary_entitlement_activations a
set revoked_at = clock_timestamp(), revocation_reason = 'client_id_cutover'
where a.revoked_at is null and exists (
    select 1 from temporary_entitlements e join client_uuid_map m
      on m.tenant_id=e.tenant_id and m.old_id=e.client_id
    where e.tenant_id=a.tenant_id and e.entitlement_id=a.entitlement_id
);
update temporary_entitlement_requests r
set status='invalidated', decided_at=clock_timestamp()
where r.status='pending' and exists (
    select 1 from client_uuid_map m where m.tenant_id=r.tenant_id and m.old_id=r.client_id
);
update temporary_entitlement_eligibility a
set revoked_at = clock_timestamp()
where a.revoked_at is null and exists (
    select 1 from temporary_entitlements e join client_uuid_map m
      on m.tenant_id=e.tenant_id and m.old_id=e.client_id
    where e.tenant_id=a.tenant_id and e.entitlement_id=a.entitlement_id
);
update temporary_kubernetes_bindings b
set enabled=false, controller_reference=null, cluster_client_reference=null
where exists (select 1 from client_uuid_map m where m.tenant_id=b.tenant_id
              and m.old_id in (b.controller_client_id,b.cluster_client_id));
update temporary_entitlements e
set enabled=false, client_reference=null, role_reference=null
where exists (select 1 from client_uuid_map m where m.tenant_id=e.tenant_id and m.old_id=e.client_id);

-- Every descendant is terminal, including a UUID/CIMD recipient whose parent
-- belonged to a converted client. Never forge new pinned parent generations.
with recursive affected(tenant_id,grant_id) as (
    select g.tenant_id,g.grant_id from grants g join client_uuid_map m
      on m.tenant_id=g.tenant_id and m.old_id=g.client_id
    union
    select g.tenant_id,g.grant_id from grants g join affected p
      on p.tenant_id=g.tenant_id and p.grant_id=g.parent_grant_id
)
update grants g
set revoked_at=clock_timestamp(), revocation_reason='client_id_cutover'
from affected a where a.tenant_id=g.tenant_id and a.grant_id=g.grant_id and g.revoked_at is null;
update refresh_tokens r set revoked_at=clock_timestamp()
where r.revoked_at is null and exists (
    select 1 from grants g where g.tenant_id=r.tenant_id and g.grant_id=r.grant_id and g.revoked_at is not null
);

-- Pending browser/device/CIBA transactions and consent codes cannot silently
-- inherit the new application identity. Retain their frozen payloads/proofs,
-- but end redemption before moving lookup FKs. Refresh/source grants above are
-- already withdrawn through their normal guarded transitions.
do $$ declare relation_name text; begin
    foreach relation_name in array array['auth_requests','authorization_codes','ciba_requests','device_codes','oid4vp_transactions'] loop
        execute format('update %I t set expires_at=least(t.expires_at,clock_timestamp()) where exists (select 1 from client_uuid_map m where m.tenant_id=t.tenant_id and m.old_id=t.client_id)',relation_name);
    end loop;
end $$;
update authorization_codes c set expires_at=least(c.expires_at,clock_timestamp())
where exists (select 1 from grants g where g.tenant_id=c.tenant_id and g.grant_id=c.grant_id and g.revoked_at is not null);
update oid4vp_transactions t set expires_at=least(t.expires_at,clock_timestamp())
where exists (select 1 from client_uuid_map m where m.tenant_id=t.tenant_id and m.old_id=t.initiator_client_id);

-- Mutable lookup columns must move with their FK targets. Keep their original
-- IDs alongside the row, under the row's normal retention, without copying
-- credentials/private material into a separate archive. Evidence columns are
-- installed before the move and protected after migration, not authentication
-- aliases. Immutable approval rows above keep their original columns instead.
do $$ declare item record; args text; snapshot_name text; begin
    for item in
        select c.table_schema,c.table_name,c.column_name
        from information_schema.columns c
        where c.table_schema=current_schema() and c.data_type='text'
          and (c.column_name like '%client_id' or c.column_name like '%client_reference')
          and c.table_name not in ('clients','audit_events','client_id_migrations','oidc_identity_providers','oidc_upstream_pending',
              'agent_tasks','temporary_entitlements','temporary_entitlement_requests','temporary_kubernetes_bindings')
          and exists (select 1 from information_schema.columns t where t.table_schema=c.table_schema
              and t.table_name=c.table_name and t.column_name='tenant_id')
    loop
        snapshot_name:=item.column_name || '_before_uuid_cutover';
        execute format('update %I.%I t set %I=t.%I where exists (select 1 from client_uuid_map m where m.tenant_id=t.tenant_id and m.old_id=t.%I)',
            item.table_schema,item.table_name,snapshot_name,item.column_name,item.column_name);
    end loop;
end $$;
do $$ declare item record; previous_owner text:=current_setting('asterius.declarative_owner',true); begin
    for item in select m.*,d.owner from client_uuid_map m left join declarative_owners d
        on d.tenant_id=m.tenant_id and d.kind='application' and d.keys=jsonb_build_array(m.old_id)
    loop
        perform set_config('asterius.declarative_owner',coalesce(item.owner,''),true);
        update clients set client_id_before_uuid_cutover=client_id
            where tenant_id=item.tenant_id and client_id=item.old_id;
    end loop;
    perform set_config('asterius.declarative_owner',coalesce(previous_owner,''),true);
end $$;

update grants g set authority_revision_before_uuid_cutover=g.authority_revision
where exists (select 1 from client_uuid_map m where m.tenant_id=g.tenant_id and m.old_id=g.client_id);

-- A declaratively owned application checks the owner key during its UPDATE.
-- Move those keys first, and keep creation-key foreign keys deferred.
update declarative_owners d
set keys = pg_temp.rewrite_client_uuid(d.keys, d.tenant_id)
where d.kind = 'application' and exists (
    select 1 from client_uuid_map m where m.tenant_id = d.tenant_id and d.keys @> to_jsonb(array[m.old_id])
);
update declarative_creation_keys d
set keys = pg_temp.rewrite_client_uuid(d.keys, d.tenant_id)
where d.kind = 'application' and exists (
    select 1 from client_uuid_map m where m.tenant_id = d.tenant_id and d.keys @> to_jsonb(array[m.old_id])
);

do $$ declare item record; previous_owner text:=current_setting('asterius.declarative_owner',true); begin
    for item in select m.*,d.owner from client_uuid_map m left join declarative_owners d
        on d.tenant_id=m.tenant_id and d.kind='application' and d.keys=jsonb_build_array(m.new_id)
    loop
        perform set_config('asterius.declarative_owner',coalesce(item.owner,''),true);
        update clients set client_id=item.new_id where tenant_id=item.tenant_id and client_id=item.old_id;
    end loop;
    perform set_config('asterius.declarative_owner',coalesce(previous_owner,''),true);
end $$;

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
          and table_name not in ('clients', 'audit_events', 'client_id_migrations', 'oidc_identity_providers', 'oidc_upstream_pending',
              'agent_tasks', 'temporary_entitlements', 'temporary_entitlement_requests', 'temporary_kubernetes_bindings')
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

update grants g set subject_before_uuid_cutover=g.subject
where exists (select 1 from client_uuid_map m where m.tenant_id=g.tenant_id and m.old_id=g.subject);

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
do $$ declare item record; controlled_row record; controlled_kind text; controlled_keys text; previous_owner text:=current_setting('asterius.declarative_owner',true); begin
    for item in
        select c.table_schema, c.table_name, c.column_name
        from information_schema.columns c
        where c.table_schema = current_schema() and c.data_type = 'jsonb'
          and c.table_name in (
            'architecture_flows', 'clients',
            'declarative_owners', 'ssf_stream_subjects',
            'tenant_policies', 'tenants',
            'workload_trusts'
          )
          and not (c.table_name = 'clients' and c.column_name in ('jwks', 'software_statement'))
          and not (c.table_name = 'declarative_creation_keys' and c.column_name in ('keys', 'initial_spec'))
          and not (c.table_name = 'declarative_owners' and c.column_name = 'keys')
          and exists (select 1 from information_schema.columns t where t.table_schema = c.table_schema
              and t.table_name = c.table_name and t.column_name = 'tenant_id')
    loop
        if item.table_name in ('clients','tenant_policies','tenants') then
            controlled_kind:=case item.table_name when 'clients' then 'application' when 'tenants' then 'tenant' else 'policy' end;
            controlled_keys:=case item.table_name when 'clients' then 'jsonb_build_array(t.client_id)' when 'tenants' then 'jsonb_build_array(t.tenant_id)' else '''["policy"]''::jsonb' end;
            for controlled_row in execute format('select t.ctid as row_id,d.owner from %I.%I t left join declarative_owners d on d.tenant_id=t.tenant_id and d.kind=%L and d.keys=%s where exists (select 1 from client_uuid_map m where m.tenant_id=t.tenant_id and position(to_jsonb(m.old_id)::text in t.%I::text)>0)',
                item.table_schema,item.table_name,controlled_kind,controlled_keys,item.column_name)
            loop
                perform set_config('asterius.declarative_owner',coalesce(controlled_row.owner,''),true);
                execute format('update %I.%I t set %I=pg_temp.rewrite_client_uuid(t.%I,t.tenant_id) where t.ctid=$1',
                    item.table_schema,item.table_name,item.column_name,item.column_name) using controlled_row.row_id;
            end loop;
            perform set_config('asterius.declarative_owner',coalesce(previous_owner,''),true);
        else
        execute format('update %I.%I t set %I = pg_temp.rewrite_client_uuid(t.%I, t.tenant_id) where exists (select 1 from client_uuid_map m where m.tenant_id=t.tenant_id and position(to_jsonb(m.old_id)::text in t.%I::text) > 0)',
            item.table_schema, item.table_name, item.column_name, item.column_name,
            item.column_name);
        end if;
    end loop;
end $$;

set constraints all immediate;

-- Protect only migration-time original lookup evidence. No existing immutable
-- trigger is disabled or widened, and newly inserted rows have null evidence.
do $$ declare item record; begin
    for item in
        select table_schema,table_name,string_agg(quote_literal(column_name),',' order by ordinal_position) as args
        from information_schema.columns
        where table_schema=current_schema() and column_name like '%_before_uuid_cutover'
        group by table_schema,table_name
    loop
        execute format('create trigger client_uuid_lookup_history_immutable before insert or update on %I.%I for each row execute function client_uuid_lookup_history_immutable(%s)',
            item.table_schema,item.table_name,item.args);
    end loop;
end $$;



do $$ declare fk record; begin
    for fk in select * from client_uuid_fk_modes where not condeferrable loop
        execute format('alter table %s alter constraint %I not deferrable', fk.relation, fk.conname);
    end loop;
end $$;

-- The temporary map disappears at commit. The durable operator mapping is
-- deliberately not part of authentication: old identifiers stop working.
