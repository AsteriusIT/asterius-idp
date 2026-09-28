-- Explicit upstream OIDC registrations. Endpoints are captured from validated
-- discovery; client credentials are sealed with tenant/provider bound AAD.
create table oidc_identity_providers (
    tenant_id text not null references tenants (tenant_id) on delete cascade,
    provider_id text not null,
    display_name text not null,
    issuer text not null,
    authorization_endpoint text not null,
    token_endpoint text not null,
    jwks_uri text not null,
    client_id text not null,
    client_secret_ciphertext bytea not null,
    client_secret_nonce bytea not null,
    kek_id text not null,
    enabled boolean not null default false,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (tenant_id, provider_id),
    unique (tenant_id, issuer),
    check (provider_id ~ '^[a-z0-9][a-z0-9_-]{0,62}$'),
    check (length(display_name) between 1 and 120),
    check (length(client_id) between 1 and 512),
    check (octet_length(client_secret_nonce) = 12),
    check (octet_length(client_secret_ciphertext) between 17 and 8192)
);

create unique index oidc_identity_providers_envelope_nonce
    on oidc_identity_providers (kek_id, client_secret_nonce);
