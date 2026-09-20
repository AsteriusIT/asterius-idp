-- Explicit non-DPoP compatibility for standard OIDC clients (ast-1gte).
-- FAPI rows remain sender-constrained; only an OIDC row may select neither
-- registered binding. Refresh rows inherit that already-validated choice.

alter table clients
    drop constraint clients_tokens_are_sender_constrained,
    add constraint clients_token_binding_matches_profile
        check (
            (dpop_bound_access_tokens <> tls_client_certificate_bound_access_tokens)
            or (
                compliance_profile = 'oidc'
                and not dpop_bound_access_tokens
                and not tls_client_certificate_bound_access_tokens
            )
        );

alter table refresh_tokens
    drop constraint refresh_tokens_are_sender_constrained,
    add constraint refresh_tokens_have_at_most_one_binding
        check (not (dpop_jkt is not null and cert_thumbprint is not null));
