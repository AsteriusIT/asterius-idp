-- Read-only inventory for the breaking 0173 cutover. Run against a restored
-- backup first with the same search_path as the intended SQLx migrator.
\set ON_ERROR_STOP on
begin transaction isolation level repeatable read read only;

select current_database() as database_name, current_schema() as schema_name,
       current_setting('search_path') as search_path;
select version, description, success, encode(checksum, 'hex') as sha384
from _sqlx_migrations order by version;

-- Metadata inventory deliberately includes arrays, JSON and unfamiliar future
-- reference columns. A suffix-based rewrite alone cannot prove completeness.
select c.table_name, c.column_name, c.data_type
from information_schema.columns c
where c.table_schema=current_schema()
  and (c.column_name like '%client%' or c.data_type in ('ARRAY','jsonb'))
  and exists (select 1 from information_schema.columns tenant
              where tenant.table_schema=c.table_schema
                and tenant.table_name=c.table_name and tenant.column_name='tenant_id')
order by c.table_name, c.ordinal_position;
select conrelid::regclass as relation, conname,
       pg_get_constraintdef(oid) as definition
from pg_constraint
where connamespace=current_schema()::regnamespace and contype='f'
  and confrelid='clients'::regclass
order by conrelid::regclass::text, conname;
select event_object_table, trigger_name, action_statement
from information_schema.triggers
where trigger_schema=current_schema()
order by event_object_table, trigger_name;

-- Counts cover historical rows as well as currently active approvals.
with legacy as (
    select tenant_id, client_id from clients
    where client_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
      and client_id not like 'https://%'
)
select 'legacy_clients' as category, count(*) as affected from legacy
union all
select 'immutable_agent_tasks', count(*) from agent_tasks t
where exists (select 1 from legacy c where c.tenant_id=t.tenant_id and c.client_id=t.initiating_client_id)
union all
select 'immutable_entitlement_definitions', count(*) from temporary_entitlements t
where exists (select 1 from legacy c where c.tenant_id=t.tenant_id and c.client_id=t.client_id)
union all
select 'immutable_entitlement_requests', count(*) from temporary_entitlement_requests t
where exists (select 1 from legacy c where c.tenant_id=t.tenant_id and c.client_id=t.client_id)
union all
select 'immutable_kubernetes_bindings', count(*) from temporary_kubernetes_bindings t
where exists (select 1 from legacy c where c.tenant_id=t.tenant_id and c.client_id in (t.controller_client_id,t.cluster_client_id))
union all
select 'pinned_grant_derivations', count(*) from grants child
join grants parent on parent.tenant_id=child.tenant_id and parent.grant_id=child.parent_grant_id
where child.parent_authority_revision is not null
  and exists (select 1 from legacy c where c.tenant_id=child.tenant_id and c.client_id in (child.client_id,parent.client_id))
order by category;

-- Fail closed after printing the inventory: ordinary migration 0173 cannot
-- rewrite these approval identities without violating their history guards.
do $$ begin
    if exists (
        select 1 from clients c
        where c.client_id !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
          and c.client_id not like 'https://%'
          and (
            exists (select 1 from agent_tasks t where t.tenant_id=c.tenant_id and t.initiating_client_id=c.client_id)
            or exists (select 1 from temporary_entitlements t where t.tenant_id=c.tenant_id and t.client_id=c.client_id)
            or exists (select 1 from temporary_entitlement_requests t where t.tenant_id=c.tenant_id and t.client_id=c.client_id)
            or exists (select 1 from temporary_kubernetes_bindings t where t.tenant_id=c.tenant_id and c.client_id in (t.controller_client_id,t.cluster_client_id))
            or exists (select 1 from grants child join grants parent
                         on parent.tenant_id=child.tenant_id and parent.grant_id=child.parent_grant_id
                       where child.tenant_id=c.tenant_id and child.parent_authority_revision is not null
                         and c.client_id in (child.client_id,parent.client_id))
          )
    ) then
        raise exception 'UUID cutover requires an approved history-preserving terminal/reapproval plan; do not bypass immutable triggers or edit SQLx checksums';
    end if;
end $$;
rollback;
