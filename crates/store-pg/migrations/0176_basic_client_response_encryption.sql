-- Basic authentication uses the separately stored shared-secret credential.
-- An inline public key set may independently encrypt opted-in OIDC responses;
-- it never becomes an alternative authentication credential. Repository writes
-- and reads still validate the single eligible public RSA encryption key.
ALTER TABLE clients
    DROP CONSTRAINT clients_key_source_matches_auth,
    ADD CONSTRAINT clients_key_source_matches_auth CHECK (
        (token_endpoint_auth_method = 'none'
            AND jwks IS NULL AND jwks_uri IS NULL)
        OR
        (token_endpoint_auth_method = 'client_secret_basic'
            AND jwks_uri IS NULL
            AND (jwks IS NULL OR (encrypt_id_token OR encrypt_userinfo)))
        OR
        (token_endpoint_auth_method NOT IN ('client_secret_basic', 'none')
            AND (jwks IS NULL) <> (jwks_uri IS NULL))
    );
