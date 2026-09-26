-- User-approved Claims Provider credentials. Both token kinds are sealed with
-- distinct row bindings; a refresh token is retained for no more than 30 days.
create table claims_provider_oauth_connections (
    tenant_id text not null,
    user_id uuid not null,
    provider_issuer text not null,
    provider_subject text not null,
    granted_scope text not null,
    access_ciphertext bytea not null,
    access_nonce bytea not null,
    access_kek_id text not null,
    access_expires_at timestamptz not null,
    refresh_ciphertext bytea,
    refresh_nonce bytea,
    refresh_kek_id text,
    refresh_expires_at timestamptz,
    revision bigint not null default 1,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (tenant_id, user_id, provider_issuer),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id) on delete cascade,
    check (length(provider_issuer) between 1 and 2048),
    check (length(provider_subject) between 1 and 256),
    check (length(granted_scope) between 1 and 512),
    check (octet_length(access_ciphertext) between 17 and 4112),
    check (octet_length(access_nonce) = 12),
    check (access_expires_at > updated_at and access_expires_at <= updated_at + interval '1 hour'),
    check ((refresh_ciphertext is null and refresh_nonce is null and refresh_kek_id is null and refresh_expires_at is null)
       or (refresh_ciphertext is not null and refresh_nonce is not null and refresh_kek_id is not null and refresh_expires_at is not null
           and octet_length(refresh_ciphertext) between 17 and 4112 and octet_length(refresh_nonce) = 12)),
    check (refresh_expires_at is null or (refresh_expires_at > updated_at and refresh_expires_at <= updated_at + interval '30 days')),
    check (revision > 0)
);

create unique index claims_provider_oauth_access_nonce_unique
    on claims_provider_oauth_connections (access_kek_id, access_nonce);
create unique index claims_provider_oauth_refresh_nonce_unique
    on claims_provider_oauth_connections (refresh_kek_id, refresh_nonce)
    where refresh_nonce is not null;
create index claims_provider_oauth_connections_expiry
    on claims_provider_oauth_connections (access_expires_at, refresh_expires_at);
