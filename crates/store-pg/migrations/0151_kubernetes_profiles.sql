-- Each registered client is one cluster audience; directory release is explicit.
create table kubernetes_profiles (
    tenant_id text not null,
    client_id text not null,
    cluster_id text collate "C" not null check (cluster_id ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    namespace text not null check (namespace ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    group_ids uuid[] not null check (cardinality(group_ids) <= 100),
    revision bigint not null check (revision > 0),
    primary key (tenant_id, client_id),
    unique (tenant_id, cluster_id),
    foreign key (tenant_id, client_id) references clients(tenant_id, client_id) on delete cascade
);
