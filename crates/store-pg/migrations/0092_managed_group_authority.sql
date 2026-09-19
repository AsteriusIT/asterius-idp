-- Policy references use stable `group:<uuid>` identities. Retain previous
-- machine names so existing name-based conditions survive an explicit rename
-- until the tenant rewrites them to the stable reference. Display names are
-- labels only and are never copied here.
create table managed_group_aliases (
    tenant_id text not null,
    group_id uuid not null,
    name text collate "C" not null
        check (name ~ '^[a-z0-9][a-z0-9._:-]{0,63}$'),
    created_at timestamptz not null,
    primary key (tenant_id, group_id, name),
    unique (tenant_id, name),
    foreign key (tenant_id, group_id)
        references managed_groups (tenant_id, group_id) on delete cascade
);

create index managed_group_aliases_by_group
    on managed_group_aliases (tenant_id, group_id);

-- Current and historical names share one tenant namespace. Locking the tenant
-- closes the cross-table race: a renamed name cannot be reassigned to another
-- identity while a legacy policy still resolves it to the original group.
create function managed_group_name_is_not_an_alias() returns trigger
language plpgsql as $$
begin
    perform 1 from tenants where tenant_id = new.tenant_id for update;
    if exists (select 1 from managed_group_aliases
               where tenant_id = new.tenant_id and name = new.name
                 and group_id <> new.group_id) then
        raise unique_violation using message = 'managed group name is a retained alias';
    end if;
    return new;
end;
$$;

create trigger managed_group_name_alias_guard
before insert or update of name on managed_groups
for each row execute function managed_group_name_is_not_an_alias();

create function managed_group_alias_is_not_a_name() returns trigger
language plpgsql as $$
begin
    perform 1 from tenants where tenant_id = new.tenant_id for update;
    if exists (select 1 from managed_groups
               where tenant_id = new.tenant_id and name = new.name
                 and group_id <> new.group_id) then
        raise unique_violation using message = 'managed group alias is a current name';
    end if;
    return new;
end;
$$;

create trigger managed_group_alias_name_guard
before insert on managed_group_aliases
for each row execute function managed_group_alias_is_not_a_name();
