-- Persist the public OAuth profile introduced by ast-s36.18.1.
--
-- Public clients have no token-endpoint credential or JWK set. They are
-- authorization-code clients whose tokens are always DPoP-bound.

alter table clients
    drop constraint clients_compliance_profile_check,
    add constraint clients_compliance_profile_check
        check (compliance_profile in ('fapi', 'oidc', 'public')),
    drop constraint clients_token_endpoint_auth_method_is_known,
    add constraint clients_token_endpoint_auth_method_is_known
        check (token_endpoint_auth_method in (
            'none',
            'private_key_jwt',
            'client_secret_basic',
            'tls_client_auth',
            'self_signed_tls_client_auth'
        )),
    drop constraint clients_key_source_matches_auth,
    add constraint clients_key_source_matches_auth
        check (
            (token_endpoint_auth_method in ('client_secret_basic', 'none')
                and jwks is null
                and jwks_uri is null)
            or
            (token_endpoint_auth_method not in ('client_secret_basic', 'none')
                and (jwks is null) <> (jwks_uri is null))
        ),
    add constraint clients_public_profile_matches_auth
        check (
            (compliance_profile = 'public'
                and token_endpoint_auth_method = 'none'
                and dpop_bound_access_tokens
                and not tls_client_certificate_bound_access_tokens
                and client_secret_hash is null)
            or
            (compliance_profile <> 'public'
                and token_endpoint_auth_method <> 'none')
        ),
    add constraint clients_public_type_matches_profile
        check (
            (compliance_profile = 'public' and client_type = 'public')
            or
            (compliance_profile <> 'public' and client_type = 'confidential')
        );

alter table clients
    drop constraint clients_client_type_check,
    add constraint clients_client_type_check
        check (client_type in ('confidential', 'public'));

create function set_client_type_from_compliance_profile() returns trigger language plpgsql as $$
begin
    new.client_type = case when new.compliance_profile = 'public'
                           then 'public' else 'confidential' end;
    return new;
end;
$$;

create trigger clients_set_client_type_from_compliance_profile
    before insert or update of compliance_profile on clients
    for each row execute function set_client_type_from_compliance_profile();
