create table federation_signing_keys (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    kid text not null,
    public_jwk jsonb not null,
    ciphertext bytea not null,
    nonce bytea not null,
    kek_id text not null,
    state text not null check (state in ('pending', 'active', 'retiring', 'retired')),
    created_at timestamptz not null,
    activated_at timestamptz,
    retired_at timestamptz,
    primary key (tenant_id, kid)
);
create unique index federation_signing_keys_active on federation_signing_keys(tenant_id) where state = 'active';
create unique index federation_signing_keys_pending on federation_signing_keys(tenant_id) where state = 'pending';
create unique index federation_signing_keys_nonce on federation_signing_keys(kek_id, nonce);
