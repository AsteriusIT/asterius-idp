-- A tenant's dedicated SAML IdP RSA key and public X.509 certificate.
-- No metadata or SSO route is enabled by the presence of this row.
create table saml_idp_signing_keys (
    tenant_id text primary key references tenants (tenant_id) on delete cascade,
    certificate_der bytea not null,
    certificate_sha256 bytea not null,
    private_key_ciphertext bytea not null,
    private_key_nonce bytea not null,
    kek_id text not null,
    created_at timestamptz not null default now(),
    check (octet_length(certificate_der) between 256 and 16384),
    check (octet_length(certificate_sha256) = 32),
    check (octet_length(private_key_nonce) = 12),
    check (octet_length(private_key_ciphertext) between 256 and 32768)
);

create unique index saml_idp_signing_keys_envelope_nonce
    on saml_idp_signing_keys (kek_id, private_key_nonce);
