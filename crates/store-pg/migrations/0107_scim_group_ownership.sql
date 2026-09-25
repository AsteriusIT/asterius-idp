-- SCIM controls only groups it created. An existing administrator-owned group
-- cannot be adopted by presenting its identifier or display name.
create table scim_group_owners (
    tenant_id text not null,
    client_id text not null,
    group_id uuid not null,
    external_id text,
    created_at timestamptz not null default now(),
    primary key (tenant_id, group_id),
    -- A client cannot be removed and its identifier reassigned while its
    -- authority-bearing groups still exist. Delete those groups first.
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id)
        on delete no action deferrable initially deferred,
    foreign key (tenant_id, group_id)
        references managed_groups (tenant_id, group_id) on delete cascade,
    check (external_id is null or length(external_id) between 1 and 256)
);

create index scim_group_owners_by_client
    on scim_group_owners (tenant_id, client_id, group_id);

create unique index scim_group_external_id_unique
    on scim_group_owners (tenant_id, client_id, external_id)
    where external_id is not null;

-- Membership in a group carrying an application role is a role grant. SCIM
-- never receives that authority, even when an administrator later edits a
-- SCIM-owned group through a different API. Lock the group row so an insert
-- racing its creation waits for the ownership link to commit before deciding.
create function reject_roles_on_scim_group() returns trigger language plpgsql as $$
begin
    perform 1 from managed_groups
    where tenant_id = new.tenant_id and group_id = new.group_id for update;
    if exists (
        select 1 from scim_group_owners
        where tenant_id = new.tenant_id and group_id = new.group_id
    ) then
        raise exception 'SCIM-owned groups cannot hold application roles'
            using errcode = '23514', constraint = 'scim_group_role_boundary';
    end if;
    return new;
end;
$$;

create trigger scim_group_no_tenant_roles
    before insert or update on group_tenant_roles
    for each row execute function reject_roles_on_scim_group();

create trigger scim_group_no_client_roles
    before insert or update on group_client_roles
    for each row execute function reject_roles_on_scim_group();
