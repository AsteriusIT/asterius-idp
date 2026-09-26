-- An SP-initiated AuthnRequest already verified and replay-reserved before
-- first-party authentication. Only the bound login interaction's resulting
-- session may consume it. The browser holds an independent 256-bit token;
-- only its digest is stored. No XML or browser-selected destination is kept.
create table saml_pending_logins (
    tenant_id text not null references tenants (tenant_id) on delete cascade,
    token_digest text not null,
    interaction_id_hash bytea not null,
    sp_entity_id text not null,
    acs_url text not null,
    request_id text not null,
    issued_at timestamptz not null,
    relay_state bytea,
    signing_key_der bytea,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    primary key (tenant_id, token_digest),
    unique (tenant_id, interaction_id_hash),
    foreign key (tenant_id, interaction_id_hash)
        references first_party_interactions (tenant_id, interaction_id_hash)
        on delete cascade,
    check (token_digest ~ '^[0-9a-f]{64}$'),
    check (octet_length(interaction_id_hash) = 32),
    check (length(sp_entity_id) between 1 and 1024),
    check (length(acs_url) between 1 and 2048),
    check (length(request_id) between 1 and 128),
    check (relay_state is null or octet_length(relay_state) <= 80),
    check (signing_key_der is null or octet_length(signing_key_der) <= 4096)
);

create index saml_pending_logins_expiry on saml_pending_logins (expires_at);
