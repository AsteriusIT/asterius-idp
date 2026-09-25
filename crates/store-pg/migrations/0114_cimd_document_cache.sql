-- Tenant-scoped CIMD fetch cache. The OAuth client row remains the source of
-- validated authorization policy; this table only bounds repeated retrieval.
create table cimd_client_documents (
    tenant_id text not null,
    client_id text not null,
    document_body bytea not null check (octet_length(document_body) <= 5120),
    document_sha256 bytea not null check (octet_length(document_sha256) = 32),
    expires_at timestamptz not null,
    updated_at timestamptz not null default now(),
    primary key (tenant_id, client_id),
    foreign key (tenant_id, client_id)
        references clients (tenant_id, client_id) on delete cascade
);

create trigger cimd_client_documents_set_updated_at
    before update on cimd_client_documents
    for each row execute function set_updated_at();

-- A URL client_id is itself the identity. Its fetched policy cannot be
-- silently replaced while codes and grants still point at the same id. Admin
-- status changes and credential management remain permitted.
create function reject_cimd_registration_change() returns trigger language plpgsql as $$
begin
    if old.client_id like 'https://%' and old.compliance_profile = 'public' and (
        new.client_name is distinct from old.client_name or
        new.compliance_profile is distinct from old.compliance_profile or
        new.token_endpoint_auth_method is distinct from old.token_endpoint_auth_method or
        new.redirect_uris is distinct from old.redirect_uris or
        new.post_logout_redirect_uris is distinct from old.post_logout_redirect_uris or
        new.grant_types is distinct from old.grant_types or
        new.response_types is distinct from old.response_types or
        new.scopes is distinct from old.scopes or
        new.resources is distinct from old.resources or
        new.jwks is distinct from old.jwks or
        new.jwks_uri is distinct from old.jwks_uri or
        new.id_token_signed_response_alg is distinct from old.id_token_signed_response_alg or
        new.application_type is distinct from old.application_type or
        new.subject_type is distinct from old.subject_type or
        new.sector_identifier_uri is distinct from old.sector_identifier_uri or
        new.request_object_signing_alg is distinct from old.request_object_signing_alg or
        new.backchannel_authentication_request_signing_alg is distinct from old.backchannel_authentication_request_signing_alg or
        new.dpop_bound_access_tokens is distinct from old.dpop_bound_access_tokens or
        new.tls_client_certificate_bound_access_tokens is distinct from old.tls_client_certificate_bound_access_tokens or
        new.authorization_details_types is distinct from old.authorization_details_types or
        new.use_mtls_endpoint_aliases is distinct from old.use_mtls_endpoint_aliases or
        new.tls_client_auth_field is distinct from old.tls_client_auth_field or
        new.tls_client_auth_value is distinct from old.tls_client_auth_value or
        new.userinfo_signed_response_alg is distinct from old.userinfo_signed_response_alg or
        new.introspection_signed_response_alg is distinct from old.introspection_signed_response_alg or
        new.backchannel_token_delivery_mode is distinct from old.backchannel_token_delivery_mode or
        new.backchannel_client_notification_endpoint is distinct from old.backchannel_client_notification_endpoint or
        new.backchannel_user_code_parameter is distinct from old.backchannel_user_code_parameter or
        new.backchannel_logout_uri is distinct from old.backchannel_logout_uri or
        new.backchannel_logout_session_required is distinct from old.backchannel_logout_session_required or
        new.roles_in_id_token is distinct from old.roles_in_id_token or
        new.managed_groups_claim is distinct from old.managed_groups_claim
    ) then
        raise exception 'CIMD client registration is immutable';
    end if;
    return new;
end;
$$;

create trigger clients_reject_cimd_registration_change
    before update on clients
    for each row execute function reject_cimd_registration_change();
