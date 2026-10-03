-- Immutable run approvals over existing human grant authorization.
create sequence agent_task_approval_revisions;
create table agent_task_clients (
    tenant_id text not null references tenants on delete cascade,
    client_id text not null,
    -- Mode survives client removal/recreation so deletion cannot restore an
    -- unbound legacy issuance route for an explicitly protected identity.
    primary key (tenant_id, client_id)
);
create table agent_tasks (
    tenant_id text not null references tenants on delete cascade,
    task_id uuid not null,
    root_grant_id uuid not null,
    root_reference uuid,
    owner_user_id uuid not null,
    owner_reference uuid,
    initiating_client_id text not null,
    client_reference text,
    approval_revision bigint not null default nextval('agent_task_approval_revisions'),
    permissions jsonb not null check (jsonb_typeof(permissions) = 'object'),
    label text not null check (octet_length(label) between 1 and 256),
    approved_at timestamptz not null,
    expires_at timestamptz not null,
    revoked_at timestamptz,
    revocation_reason text,
    primary key (tenant_id, task_id),
    unique (tenant_id, root_grant_id),
    unique (tenant_id, task_id, root_grant_id, approval_revision),
    foreign key (tenant_id, root_reference) references grants
        on delete set null (root_reference) deferrable initially deferred,
    check (root_reference is null or root_reference=root_grant_id),
    check (owner_reference is null or owner_reference=owner_user_id),
    check (client_reference is null or client_reference=initiating_client_id),
    foreign key (tenant_id, owner_reference) references users
        on delete set null (owner_reference) deferrable initially deferred,
    foreign key (tenant_id, client_reference) references clients
        on delete set null (client_reference) deferrable initially deferred,
    check (approval_revision > 0),
    check (expires_at > approved_at and expires_at <= approved_at + interval '1 hour'),
    check ((revoked_at is null) = (revocation_reason is null))
);
create index agent_tasks_by_owner on agent_tasks(tenant_id, owner_user_id, task_id);
create table agent_task_grants (
    tenant_id text not null,
    grant_id uuid not null,
    task_id uuid not null,
    root_grant_id uuid not null,
    approval_revision bigint not null,
    primary key (tenant_id, grant_id),
    foreign key (tenant_id, grant_id) references grants on delete cascade,
    foreign key (tenant_id, task_id, root_grant_id, approval_revision)
        references agent_tasks(tenant_id, task_id, root_grant_id, approval_revision)
);
create index agent_task_grants_by_task on agent_task_grants(tenant_id, task_id, grant_id);
create table agent_task_tokens (
    tenant_id text not null,
    jti text not null check (octet_length(jti) between 1 and 256),
    grant_id uuid not null,
    expires_at timestamptz not null,
    primary key (tenant_id, jti),
    foreign key (tenant_id, grant_id) references agent_task_grants on delete cascade
);

-- Bind every descendant, including ordinary recipient clients. No request
-- parameter or optional token claim can discard durable parent lineage.
create function inherit_agent_task() returns trigger language plpgsql as $$
declare binding agent_task_grants%rowtype;
begin
    if new.parent_grant_id is not null then
        select * into binding from agent_task_grants
            where tenant_id = new.tenant_id and grant_id = new.parent_grant_id;
        if found then
            insert into agent_task_grants(tenant_id, grant_id, task_id, root_grant_id, approval_revision)
                values(new.tenant_id, new.grant_id, binding.task_id, binding.root_grant_id, binding.approval_revision);
        end if;
    end if;
    return new;
end $$;
create trigger grants_inherit_agent_task after insert on grants
    for each row execute function inherit_agent_task();

-- Approval fields never mutate under a credential. A replacement needs a
-- new root/run/revision and explicit fresh approval, not an UPDATE.
create function immutable_agent_task() returns trigger language plpgsql as $$
begin
    if (to_jsonb(new) - array['revoked_at','revocation_reason','owner_reference','client_reference','root_reference'])
        is distinct from
       (to_jsonb(old) - array['revoked_at','revocation_reason','owner_reference','client_reference','root_reference'])
       or (new.owner_reference is not null and new.owner_reference is distinct from old.owner_reference)
       or (new.client_reference is not null and new.client_reference is distinct from old.client_reference)
       or (new.root_reference is not null and new.root_reference is distinct from old.root_reference)
       or (old.revoked_at is not null and (new.revoked_at is distinct from old.revoked_at
           or new.revocation_reason is distinct from old.revocation_reason)) then
        raise exception 'immutable agent task approval';
    end if;
    if (new.owner_reference is null or new.client_reference is null or new.root_reference is null) and new.revoked_at is null then
        new.revoked_at := clock_timestamp();
        new.revocation_reason := 'principal_removed';
    end if;
    return new;
end $$;
create trigger agent_tasks_immutable before update on agent_tasks
    for each row execute function immutable_agent_task();

create function fence_agent_tasks_for_owner() returns trigger language plpgsql as $$
begin
    if new.status <> 'active' then
        update agent_tasks set revoked_at = clock_timestamp(), revocation_reason = 'owner_disabled'
            where tenant_id = new.tenant_id and owner_user_id = new.user_id and revoked_at is null;
    end if;
    return new;
end $$;
create trigger users_fence_agent_tasks after update of status on users
    for each row execute function fence_agent_tasks_for_owner();

create function fence_agent_tasks_for_client() returns trigger language plpgsql as $$
begin
    if new.status <> 'active' or not new.is_agent or new.agent_owner_user_id is distinct from old.agent_owner_user_id then
        update agent_tasks set revoked_at = clock_timestamp(), revocation_reason = 'agent_changed'
            where tenant_id = new.tenant_id and initiating_client_id = new.client_id and revoked_at is null;
    end if;
    return new;
end $$;
create trigger clients_fence_agent_tasks after update of status, is_agent, agent_owner_user_id on clients
    for each row execute function fence_agent_tasks_for_client();

create function bound_task_refresh() returns trigger language plpgsql as $$
declare task agent_tasks%rowtype;
begin
    -- Withdrawal/rotation cleanup is permitted even after authority ends.
    if tg_op = 'UPDATE' and (new.revoked_at is not null or new.superseded_at is not null) then
        return new;
    end if;
    select t.* into task from agent_tasks t join agent_task_grants b
        using(tenant_id,task_id,root_grant_id,approval_revision)
        where b.tenant_id=new.tenant_id and b.grant_id=new.grant_id;
    if found then
        perform grant_id from grants where tenant_id=task.tenant_id and grant_id=task.root_grant_id for update;
        select * into task from agent_tasks where tenant_id=task.tenant_id and task_id=task.task_id for update;
        if task.revoked_at is not null or task.expires_at <= clock_timestamp()
            or task.owner_reference is null or task.client_reference is null or task.root_reference is null then
            raise exception 'inactive agent task';
        end if;
        new.absolute_expires_at := least(new.absolute_expires_at,task.expires_at);
        new.idle_expires_at := least(coalesce(new.idle_expires_at,task.expires_at),new.absolute_expires_at);
    end if;
    return new;
end $$;
create trigger refresh_tokens_task_bound before insert or update on refresh_tokens
    for each row execute function bound_task_refresh();

-- Parentage is immutable even for ordinary descendants. Reparenting a row
-- after the principal snapshot would otherwise change which locks fence it.
create function immutable_grant_parent() returns trigger language plpgsql as $$
begin
    if new.parent_grant_id is distinct from old.parent_grant_id then
        raise exception 'immutable grant parent';
    end if;
    return new;
end $$;
create trigger grants_immutable_parent before update of parent_grant_id on grants
    for each row execute function immutable_grant_parent();
