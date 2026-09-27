create table architecture_flows (
    tenant_id text not null references tenants (tenant_id) on delete cascade,
    flow_id uuid not null,
    name text not null check (length(name) between 1 and 120),
    graph jsonb not null,
    revision bigint not null default 1 check (revision > 0),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    primary key (tenant_id, flow_id)
);

create index architecture_flows_recent on architecture_flows (tenant_id, updated_at desc, flow_id);
