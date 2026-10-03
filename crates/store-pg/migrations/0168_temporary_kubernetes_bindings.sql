-- Only an explicit same-tenant entitlement owner can configure this projection.
-- Native RBAC ceilings remain pinned independently by the cluster operator.
create table temporary_kubernetes_bindings (
    tenant_id text not null,
    entitlement_id uuid not null,
    revision uuid not null default gen_random_uuid(),
    controller_client_id text not null,
    controller_reference text,
    cluster_client_id text not null,
    cluster_client_reference text,
    cluster_id text not null,
    namespace text not null,
    profile_revision bigint not null check (profile_revision > 0),
    enabled boolean not null,
    primary key (tenant_id, entitlement_id),
    foreign key (tenant_id, entitlement_id) references temporary_entitlements on delete cascade,
    foreign key (tenant_id, controller_reference) references clients on delete set null (controller_reference),
    foreign key (tenant_id, cluster_client_reference) references clients on delete set null (cluster_client_reference)
);
-- A single exact cluster identity selects one JIT provenance tuple.
create unique index temporary_kubernetes_one_enabled_cluster on temporary_kubernetes_bindings(tenant_id,cluster_client_id) where enabled;
create trigger temporary_kubernetes_bindings_publication_fence before insert or update or delete on temporary_kubernetes_bindings
    for each row execute function fence_temporary_entitlement_authority();
create function temporary_kubernetes_binding_revision() returns trigger language plpgsql as $$
begin
    if (new.controller_client_id,new.cluster_client_id,new.cluster_id) is distinct from
       (old.controller_client_id,old.cluster_client_id,old.cluster_id) then
        raise exception 'temporary Kubernetes binding identity is immutable' using errcode='23514';
    end if;
    if row(new.*) is distinct from row(old.*) then new.revision := gen_random_uuid(); end if;
    return new;
end; $$;
create trigger temporary_kubernetes_binding_revision before update on temporary_kubernetes_bindings
    for each row execute function temporary_kubernetes_binding_revision();

create function invalidate_temporary_kubernetes_controller() returns trigger language plpgsql as $$
begin
    if new.status <> 'active' or new.is_agent or new.token_endpoint_auth_method <> 'private_key_jwt' or not new.dpop_bound_access_tokens then
        update temporary_kubernetes_bindings set enabled=false where tenant_id=new.tenant_id and controller_reference=new.client_id and enabled;
    end if;
    return new;
end; $$;
create trigger clients_invalidate_temporary_kubernetes_controller after update of status,is_agent,token_endpoint_auth_method,dpop_bound_access_tokens on clients
    for each row execute function invalidate_temporary_kubernetes_controller();
create function invalidate_temporary_kubernetes_profile() returns trigger language plpgsql as $$
begin
    update temporary_kubernetes_bindings set enabled=false where tenant_id=old.tenant_id and cluster_client_reference=old.client_id and enabled;
    if tg_op='DELETE' then return old; end if;
    return new;
end; $$;
create trigger profiles_invalidate_temporary_kubernetes after update or delete on kubernetes_profiles
    for each row execute function invalidate_temporary_kubernetes_profile();

-- A changed role/resource/configuration cannot reuse a stale JIT username generation.
create function invalidate_temporary_kubernetes_entitlement() returns trigger language plpgsql as $$
begin
    if new.revision is distinct from old.revision or not new.enabled then
        update temporary_kubernetes_bindings set enabled=false
          where tenant_id=new.tenant_id and entitlement_id=new.entitlement_id and enabled;
    end if;
    return new;
end; $$;
create trigger entitlements_invalidate_temporary_kubernetes after update on temporary_entitlements
    for each row execute function invalidate_temporary_kubernetes_entitlement();

create function invalidate_temporary_kubernetes_cluster_client() returns trigger language plpgsql as $$
begin
    if new.status <> 'active' or new.is_agent or new.subject_type <> 'public'
       or new.compliance_profile <> 'oidc' or new.application_type <> 'web'
       or new.token_endpoint_auth_method <> 'private_key_jwt'
       or new.id_token_signed_response_alg <> 'ES256' or not new.dpop_bound_access_tokens
       or not new.managed_groups_claim or not new.roles_in_id_token
       or not ('authorization_code'=any(new.grant_types)) or not ('refresh_token'=any(new.grant_types))
       or not ('openid'=any(new.scopes)) or cardinality(new.redirect_uris) <> 1 then
        update temporary_kubernetes_bindings set enabled=false
          where tenant_id=new.tenant_id and cluster_client_reference=new.client_id and enabled;
    end if;
    return new;
end; $$;
create trigger clients_invalidate_temporary_kubernetes_cluster after update of status,is_agent,subject_type,compliance_profile,application_type,token_endpoint_auth_method,id_token_signed_response_alg,dpop_bound_access_tokens,managed_groups_claim,roles_in_id_token,grant_types,scopes,redirect_uris on clients
    for each row execute function invalidate_temporary_kubernetes_cluster_client();
