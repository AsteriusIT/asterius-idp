-- Cleanup is durable and bounded; ancestor/task tombstones are the online
-- authority boundary and do not wait for this queue or external event delivery.
create table agent_task_withdrawals (
    tenant_id text not null,
    ancestor_grant_id uuid not null,
    task_id uuid not null,
    root_grant_id uuid not null,
    approval_revision bigint not null,
    withdrawn_at timestamptz not null,
    reason text not null,
    cursor_grant_id uuid,
    completed_at timestamptz,
    processed_grants bigint not null default 0 check (processed_grants>=0),
    primary key (tenant_id, ancestor_grant_id),
    foreign key (tenant_id, ancestor_grant_id) references grants on delete cascade,
    foreign key (tenant_id,task_id,root_grant_id,approval_revision)
        references agent_tasks(tenant_id,task_id,root_grant_id,approval_revision) on delete cascade
);
create index agent_task_withdrawals_pending on agent_task_withdrawals(tenant_id,withdrawn_at,ancestor_grant_id)
    where completed_at is null;

-- First activation must bind historical descendants as well as new children.
with recursive descendants as (
    select t.tenant_id,t.task_id,t.root_grant_id,t.approval_revision,
        g.grant_id,array[g.grant_id] as path
    from agent_tasks t join grants g on g.tenant_id=t.tenant_id and g.grant_id=t.root_grant_id
    union all
    select d.tenant_id,d.task_id,d.root_grant_id,d.approval_revision,g.grant_id,d.path||g.grant_id
    from descendants d join grants g on g.tenant_id=d.tenant_id and g.parent_grant_id=d.grant_id
    where cardinality(d.path)<10 and not g.grant_id=any(d.path)
)
insert into agent_task_grants(tenant_id,grant_id,task_id,root_grant_id,approval_revision)
    select tenant_id,grant_id,task_id,root_grant_id,approval_revision from descendants
    on conflict(tenant_id,grant_id) do nothing;

-- The foreign key only locks the immediate parent. A child of an existing
-- descendant must also serialize against first activation at the tree root,
-- before AFTER INSERT re-reads the immutable parent binding.
create function fence_agent_task_parent() returns trigger language plpgsql as $$
declare lineage_root uuid;
begin
    if new.parent_grant_id is null then return new; end if;
    with recursive ancestors as (
        select g.grant_id,g.parent_grant_id,array[g.grant_id] as path
        from grants g where g.tenant_id=new.tenant_id and g.grant_id=new.parent_grant_id
        union all
        select g.grant_id,g.parent_grant_id,a.path||g.grant_id
        from ancestors a join grants g on g.tenant_id=new.tenant_id and g.grant_id=a.parent_grant_id
        where cardinality(a.path)<10 and not g.grant_id=any(a.path)
    ) select grant_id into lineage_root from ancestors
        where parent_grant_id is null and cardinality(path)<10;
    if lineage_root is null then raise exception 'invalid bounded grant lineage'; end if;
    perform grant_id from grants where tenant_id=new.tenant_id and grant_id=lineage_root for key share;
    return new;
end $$;
create trigger grants_fence_agent_task_parent before insert on grants
    for each row execute function fence_agent_task_parent();

-- Existing owner/client lifecycle triggers make task revocation terminal.
-- Reuse that tombstone to enqueue bounded cleanup too; their existing account
-- or client audit event remains the cause, rather than fabricating a session
-- revocation or opening an independent audit transaction inside a trigger.
create function queue_terminal_agent_task() returns trigger language plpgsql as $$
begin
    if old.revoked_at is null and new.revoked_at is not null then
        insert into agent_task_withdrawals(tenant_id,ancestor_grant_id,task_id,
            root_grant_id,approval_revision,withdrawn_at,reason)
        select new.tenant_id,new.root_grant_id,new.task_id,new.root_grant_id,
            new.approval_revision,new.revoked_at,new.revocation_reason
        from grants g where g.tenant_id=new.tenant_id and g.grant_id=new.root_reference
        on conflict(tenant_id,ancestor_grant_id) do nothing;
    end if;
    return new;
end $$;
create trigger agent_tasks_queue_terminal after update on agent_tasks
    for each row execute function queue_terminal_agent_task();

-- A deployment can already have terminal approvals before this migration.
insert into agent_task_withdrawals(tenant_id,ancestor_grant_id,task_id,
    root_grant_id,approval_revision,withdrawn_at,reason)
select t.tenant_id,t.root_grant_id,t.task_id,t.root_grant_id,t.approval_revision,
    t.revoked_at,t.revocation_reason
from agent_tasks t join grants g on g.tenant_id=t.tenant_id and g.grant_id=t.root_reference
where t.revoked_at is not null
on conflict(tenant_id,ancestor_grant_id) do nothing;
