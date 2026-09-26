-- LDAP owns only accounts and groups created through the explicit sync run.
-- Existing local and SCIM resources cannot be adopted by matching names.
create table ldap_user_owners (
    tenant_id text not null,
    source_key text not null check (length(source_key) = 64),
    user_id uuid not null,
    external_id text not null check (length(external_id) between 1 and 256),
    created_at timestamptz not null default now(),
    primary key (tenant_id, user_id),
    unique (tenant_id, source_key, external_id),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id) on delete cascade
);

create table ldap_group_owners (
    tenant_id text not null,
    source_key text not null check (length(source_key) = 64),
    group_id uuid not null,
    external_id text not null check (length(external_id) between 1 and 1024),
    created_at timestamptz not null default now(),
    primary key (tenant_id, group_id),
    unique (tenant_id, source_key, external_id),
    foreign key (tenant_id, group_id) references managed_groups (tenant_id, group_id) on delete cascade
);

-- A managed LDAP group is never a vehicle for privileged application roles.
create function reject_roles_on_ldap_group() returns trigger language plpgsql as $$
begin
    perform 1 from managed_groups
    where tenant_id = new.tenant_id and group_id = new.group_id for update;
    if exists (
        select 1 from ldap_group_owners
        where tenant_id = new.tenant_id and group_id = new.group_id
    ) then
        raise exception 'LDAP-owned groups cannot hold application roles'
            using errcode = '23514', constraint = 'ldap_group_role_boundary';
    end if;
    return new;
end;
$$;

create trigger ldap_group_no_tenant_roles
    before insert or update on group_tenant_roles
    for each row execute function reject_roles_on_ldap_group();

create trigger ldap_group_no_client_roles
    before insert or update on group_client_roles
    for each row execute function reject_roles_on_ldap_group();
