-- Versioned configuration, never credentials. Keep the last 100 publications
-- atomically with every policy write, including deny-all deletion and rollback.
create table tenant_policy_revisions (
    id bigint generated always as identity primary key,
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    document jsonb not null check (jsonb_typeof(document) = 'object'),
    published_at timestamptz not null
);
create index tenant_policy_revisions_tenant_id on tenant_policy_revisions(tenant_id, id desc);

insert into tenant_policy_revisions(tenant_id, document, published_at)
select tenant_id, document, updated_at from tenant_policies;

create function record_tenant_policy_revision() returns trigger language plpgsql as $$
declare
    target_tenant text;
begin
    if TG_OP = 'DELETE' then
        target_tenant := OLD.tenant_id;
        -- Tenant deletion cascades through both tables; do not recreate history.
        if not exists (select 1 from tenants where tenant_id = target_tenant) then
            return OLD;
        end if;
        insert into tenant_policy_revisions(tenant_id, document, published_at)
        values (target_tenant, '{"version":1,"rules":[]}'::jsonb, clock_timestamp());
    else
        target_tenant := NEW.tenant_id;
        insert into tenant_policy_revisions(tenant_id, document, published_at)
        values (target_tenant, NEW.document, NEW.updated_at);
    end if;
    delete from tenant_policy_revisions
    where tenant_id = target_tenant and id not in (
        select id from tenant_policy_revisions where tenant_id = target_tenant
        order by id desc limit 100
    );
    return null;
end;
$$;
create trigger tenant_policy_revision after insert or update or delete on tenant_policies
for each row execute function record_tenant_policy_revision();
