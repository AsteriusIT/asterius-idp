alter table architecture_flows
    add column applied_revision bigint,
    add column applied_digest text check (applied_digest ~ '^[0-9a-f]{64}$'),
    add column apply_token uuid,
    add column apply_deadline timestamptz,
    add column last_apply_error text;

create table flow_resource_links (
    tenant_id text not null,
    flow_id uuid not null,
    node_id text not null,
    resource_kind text not null,
    resource_id text not null,
    relation text not null check (relation in ('managed', 'reference')),
    state text not null check (state in ('pending', 'applied')),
    created_in_revision bigint not null,
    last_applied_revision bigint,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    primary key (tenant_id, flow_id, node_id),
    foreign key (tenant_id, flow_id) references architecture_flows (tenant_id, flow_id) on delete restrict
);

create unique index flow_managed_resource_origin
    on flow_resource_links (tenant_id, resource_kind, resource_id)
    where relation = 'managed';
