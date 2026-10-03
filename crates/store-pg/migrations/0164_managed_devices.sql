-- Candidate managed-device-relay/v1. No source is active without an explicit
-- tenant administrator registration and enable operation. UUIDs are server-owned.
create sequence managed_device_generations;
create table managed_device_sources (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    source_id uuid not null,
    client_id text not null,
    generation bigint not null default nextval('managed_device_generations'),
    revision uuid not null,
    enabled boolean not null default false,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    primary key (tenant_id, source_id),
    unique (tenant_id, client_id),
    foreign key (tenant_id, client_id) references clients(tenant_id, client_id) on delete cascade,
    check (generation > 0)
);
create table managed_devices (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    device_id uuid not null,
    source_id uuid not null,
    source_generation bigint not null,
    enrollment_generation bigint not null default nextval('managed_device_generations'),
    revision uuid not null,
    user_id uuid,
    leaf_sha256 bytea,
    allowed_client_ids text[],
    sequence bigint,
    observed_at timestamptz,
    source_expires_at timestamptz,
    managed boolean,
    compliant boolean,
    disk_encrypted boolean,
    risk text check (risk in ('low', 'medium', 'high', 'unknown')),
    created_at timestamptz not null,
    updated_at timestamptz not null,
    removed_at timestamptz,
    primary key (tenant_id, device_id),
    foreign key (tenant_id, source_id) references managed_device_sources(tenant_id, source_id) on delete cascade,
    foreign key (tenant_id, user_id) references users(tenant_id, user_id) on delete cascade,
    check (source_generation > 0 and enrollment_generation > 0),
    check (sequence is null or sequence >= 0),
    check (leaf_sha256 is null or octet_length(leaf_sha256) = 32),
    check (allowed_client_ids is null or cardinality(allowed_client_ids) <= 64),
    check ((removed_at is null and user_id is not null and leaf_sha256 is not null and allowed_client_ids is not null)
        or (removed_at is not null and user_id is null and leaf_sha256 is null and allowed_client_ids is null
            and sequence is null and observed_at is null and source_expires_at is null
            and managed is null and compliant is null and disk_encrypted is null and risk is null))
);
create unique index managed_devices_active_leaf on managed_devices(tenant_id, leaf_sha256)
    where removed_at is null;
create index managed_devices_removed on managed_devices(removed_at) where removed_at is not null;
create index managed_devices_user on managed_devices(tenant_id, user_id, device_id) where removed_at is null;

-- A replaced browser arrival has a new interaction digest. The stable PAR
-- digest alone does not authorize transfer. The winning completion must spend
-- and transfer this row under the same parent lock as the existing interaction.
create table managed_device_interaction_proofs (
    tenant_id text not null,
    request_uri_hash bytea not null check(octet_length(request_uri_hash) = 32),
    interaction_id_hash bytea not null check(octet_length(interaction_id_hash) = 32),
    device_id uuid not null,
    binding jsonb not null check(jsonb_typeof(binding) = 'object' and octet_length(binding::text) <= 8192),
    expires_at timestamptz not null,
    primary key (tenant_id, request_uri_hash),
    foreign key (tenant_id, request_uri_hash) references auth_requests(tenant_id, request_uri_hash) on delete cascade,
    foreign key (tenant_id, device_id) references managed_devices(tenant_id, device_id) on delete cascade
);
create index managed_device_interaction_expiry on managed_device_interaction_proofs(expires_at);

-- A grant may be reused by multiple consent codes: the code digest is the
-- exact authority boundary. These private sidecars are never public JWT claims.
create table managed_device_code_proofs (
    tenant_id text not null,
    code_hash bytea not null check(octet_length(code_hash) = 32),
    device_id uuid not null,
    binding jsonb not null check(jsonb_typeof(binding) = 'object' and octet_length(binding::text) <= 8192),
    expires_at timestamptz not null,
    primary key (tenant_id, code_hash),
    foreign key (tenant_id, code_hash) references authorization_codes(tenant_id, code_hash) on delete cascade,
    foreign key (tenant_id, device_id) references managed_devices(tenant_id, device_id) on delete cascade
);
create index managed_device_code_expiry on managed_device_code_proofs(expires_at);
