-- One-use upstream authorization-code transactions bound to a local browser
-- interaction. The state itself and PKCE verifier never appear in cleartext.
create table oidc_upstream_pending (
    tenant_id text not null references tenants (tenant_id) on delete cascade,
    state_digest text not null,
    interaction_digest text not null,
    provider_id text not null,
    issuer text not null,
    client_id text not null,
    token_endpoint text not null,
    jwks_uri text not null,
    nonce_digest text not null,
    verifier_ciphertext bytea not null,
    verifier_nonce bytea not null,
    kek_id text not null,
    expires_at timestamptz not null,
    primary key (tenant_id, state_digest),
    unique (tenant_id, interaction_digest),
    check (length(state_digest) = 64),
    check (length(interaction_digest) = 64),
    check (length(nonce_digest) = 64),
    check (octet_length(verifier_nonce) = 12)
);

create unique index oidc_upstream_pending_envelope_nonce
    on oidc_upstream_pending (kek_id, verifier_nonce);
