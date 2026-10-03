-- Persist provenance independently of trust deletion; child grants retain it.
create table workload_grant_bindings (
    tenant_id text not null,
    grant_id uuid not null,
    trust_id text not null,
    trust_version bigint not null,
    provider text not null check(provider in ('kubernetes','github')),
    principal text not null,
    assertion_digest bytea not null check(octet_length(assertion_digest)=32),
    assertion_expires_at timestamptz not null,
    primary key(tenant_id,grant_id),
    foreign key(tenant_id,grant_id) references grants(tenant_id,grant_id) on delete cascade
);
