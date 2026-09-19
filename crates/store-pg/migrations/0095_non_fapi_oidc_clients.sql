-- Explicitly gated standard OIDC clients (ADR-0014).
--
-- Existing rows remain FAPI clients. The shared-secret column contains only a
-- SHA-256 digest of a server-generated 256-bit value; null means revoked or no
-- shared secret. A standard OIDC client may authenticate asymmetrically too,
-- but only client_secret_basic may own a digest or omit a public-key source.

alter table clients
    add column compliance_profile text not null default 'fapi'
        check (compliance_profile in ('fapi', 'oidc')),
    add column client_secret_hash bytea
        check (client_secret_hash is null or octet_length(client_secret_hash) = 32);

alter table clients
    drop constraint clients_token_endpoint_auth_method_check,
    add constraint clients_token_endpoint_auth_method_is_known
        check (token_endpoint_auth_method in (
            'private_key_jwt',
            'client_secret_basic',
            'tls_client_auth',
            'self_signed_tls_client_auth'
        )),
    drop constraint clients_exactly_one_key_source,
    add constraint clients_key_source_matches_auth
        check (
            (token_endpoint_auth_method = 'client_secret_basic'
                and jwks is null
                and jwks_uri is null)
            or
            (token_endpoint_auth_method <> 'client_secret_basic'
                and (jwks is null) <> (jwks_uri is null))
        ),
    add constraint clients_fapi_has_no_shared_secret_auth
        check (
            compliance_profile = 'oidc'
            or token_endpoint_auth_method <> 'client_secret_basic'
        ),
    add constraint clients_secret_matches_auth
        check (
            client_secret_hash is null
            or token_endpoint_auth_method = 'client_secret_basic'
        );
