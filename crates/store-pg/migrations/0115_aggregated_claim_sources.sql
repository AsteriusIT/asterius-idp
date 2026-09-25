-- Signed UserInfo from a configured Claims Provider. The JWT is retained
-- whole because filtering a signed claim set would invalidate its signature.
create table aggregated_claim_sources (
    tenant_id text not null,
    user_id uuid not null,
    provider_issuer text not null,
    provider_subject text not null,
    signed_userinfo text not null,
    claim_names text[] not null,
    expires_at timestamptz not null,
    stored_at timestamptz not null,
    revoked_at timestamptz,
    primary key (tenant_id, user_id, provider_issuer),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id) on delete cascade,
    check (length(provider_issuer) between 1 and 2048),
    check (length(provider_subject) between 1 and 256),
    check (octet_length(signed_userinfo) between 1 and 8192),
    check (cardinality(claim_names) between 1 and 16)
);

create index aggregated_claim_sources_by_user
    on aggregated_claim_sources (tenant_id, user_id, expires_at)
    where revoked_at is null;
