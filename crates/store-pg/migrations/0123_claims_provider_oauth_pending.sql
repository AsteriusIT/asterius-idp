-- Single-use browser-bound OIDC authorization code + PKCE setup attempts.
-- No bearer or refresh token is persisted by this initial one-shot flow.
create table claims_provider_oauth_pending (
    tenant_id text not null,
    state_hash text not null,
    user_id uuid not null,
    session_digest text not null,
    provider_issuer text not null,
    provider_nonce text not null,
    verifier_ciphertext bytea not null,
    verifier_nonce bytea not null,
    verifier_kek_id text not null,
    expires_at timestamptz not null,
    primary key (tenant_id, state_hash),
    foreign key (tenant_id, user_id) references users (tenant_id, user_id) on delete cascade,
    check (length(state_hash) = 64),
    check (length(session_digest) = 64),
    check (length(provider_issuer) between 1 and 2048),
    check (length(provider_nonce) between 32 and 128),
    check (octet_length(verifier_ciphertext) between 49 and 144),
    check (octet_length(verifier_nonce) = 12)
);

create unique index claims_provider_oauth_pending_nonce_unique
    on claims_provider_oauth_pending (verifier_kek_id, verifier_nonce);

create index claims_provider_oauth_pending_expiry
    on claims_provider_oauth_pending (expires_at);
