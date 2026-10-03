-- External JWT trust is operator-pinned and disabled unless explicitly enabled.
create sequence workload_trust_versions;
create table workload_trusts (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    trust_id text not null check(length(trust_id) between 1 and 63),
    version bigint not null default nextval('workload_trust_versions'),
    config jsonb not null check(jsonb_typeof(config)='object'),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key(tenant_id,trust_id)
);
create index workload_trust_issuer on workload_trusts(tenant_id,(config->>'issuer'));
-- Retain replay marks across trust deletion/recreation until assertion expiry.
-- Child grant creation and consumption use the same issuance transaction.
create table workload_assertion_consumptions (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    trust_id text not null,
    digest bytea not null check(octet_length(digest)=32),
    expires_at timestamptz not null,
    consumed_at timestamptz not null,
    primary key(tenant_id,trust_id,digest)
);
create index workload_assertion_expiry on workload_assertion_consumptions(expires_at);
