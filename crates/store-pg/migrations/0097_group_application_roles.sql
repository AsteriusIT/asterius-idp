-- Application roles assigned to managed groups (`ast-6uqw.11`). Separate
-- tenant/client tables keep every foreign key total and make cross-tenant or
-- cross-client authority impossible at the schema boundary.
create table group_tenant_roles (
    tenant_id text not null,
    group_id uuid not null,
    name text not null,
    granted_at timestamptz not null default now(),
    primary key (tenant_id, group_id, name),
    foreign key (tenant_id, group_id)
        references managed_groups (tenant_id, group_id) on delete cascade,
    foreign key (tenant_id, name)
        references tenant_roles (tenant_id, name) on delete restrict
);

create table group_client_roles (
    tenant_id text not null,
    group_id uuid not null,
    client_id text not null,
    name text not null,
    granted_at timestamptz not null default now(),
    primary key (tenant_id, group_id, client_id, name),
    foreign key (tenant_id, group_id)
        references managed_groups (tenant_id, group_id) on delete cascade,
    foreign key (tenant_id, client_id, name)
        references client_roles (tenant_id, client_id, name) on delete restrict
);

create index group_tenant_roles_by_role on group_tenant_roles (tenant_id, name);
create index group_client_roles_by_role on group_client_roles (tenant_id, client_id, name);
