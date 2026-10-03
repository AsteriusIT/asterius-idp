-- Candidate online authentication state. No bearer JWT is retained.
create table kubernetes_online_profiles (
    tenant_id text not null,
    client_id text not null,
    reviewer_client_id text not null,
    revision uuid not null default gen_random_uuid(),
    enabled boolean not null default false,
    primary key (tenant_id, client_id),
    check (client_id <> reviewer_client_id),
    foreign key (tenant_id, client_id)
        references kubernetes_profiles (tenant_id, client_id) on delete cascade,
    foreign key (tenant_id, reviewer_client_id)
        references clients (tenant_id, client_id) on delete cascade
);

-- Every administrative update invalidates previously issued bindings, including
-- disable/re-enable and reviewer replacement. No caller supplies the new revision.
create function kubernetes_online_revision() returns trigger language plpgsql as $$
begin
    new.revision := gen_random_uuid();
    return new;
end
$$;
create trigger kubernetes_online_revision before update on kubernetes_online_profiles
    for each row execute function kubernetes_online_revision();

create function kubernetes_online_publication_fence() returns trigger language plpgsql as $$
declare target_tenant text;
begin
    if tg_op='DELETE' then target_tenant:=old.tenant_id;
    else target_tenant:=new.tenant_id;
    end if;
    perform tenant_id from tenants where tenant_id=target_tenant for no key update;
    if tg_op='DELETE' then return old; end if;
    return new;
end
$$;
create trigger kubernetes_online_publication_fence before insert or update or delete on kubernetes_online_profiles
    for each row execute function kubernetes_online_publication_fence();

-- Relevant metadata changes terminally disable the selected mode. Restoring a
-- previous configuration cannot revive an old token's profile UUID. Signing key
-- overlap does not change this policy tuple and remains independently operable.
create function kubernetes_online_client_changed() returns trigger language plpgsql as $$
begin
    if (new.status,new.is_agent,new.subject_type,new.compliance_profile,new.application_type,
        new.token_endpoint_auth_method,new.dpop_bound_access_tokens,new.id_token_signed_response_alg,
        new.encrypt_id_token,new.managed_groups_claim,new.grant_types,new.scopes,new.redirect_uris)
        is distinct from
       (old.status,old.is_agent,old.subject_type,old.compliance_profile,old.application_type,
        old.token_endpoint_auth_method,old.dpop_bound_access_tokens,old.id_token_signed_response_alg,
        old.encrypt_id_token,old.managed_groups_claim,old.grant_types,old.scopes,old.redirect_uris) then
        update kubernetes_online_profiles set enabled=false
            where tenant_id=new.tenant_id and enabled
              and (client_id=new.client_id or reviewer_client_id=new.client_id);
    end if;
    return new;
end
$$;
create trigger kubernetes_online_client_changed after update on clients
    for each row execute function kubernetes_online_client_changed();

create function kubernetes_online_cluster_changed() returns trigger language plpgsql as $$
begin
    update kubernetes_online_profiles set enabled=false
        where tenant_id=old.tenant_id and client_id=old.client_id and enabled;
    if tg_op='DELETE' then return old; end if;
    return new;
end
$$;
create trigger kubernetes_online_cluster_changed after update or delete on kubernetes_profiles
    for each row execute function kubernetes_online_cluster_changed();

create function kubernetes_online_tenant_changed() returns trigger language plpgsql as $$
begin
    if (new.status,new.issuer) is distinct from (old.status,old.issuer) then
        update kubernetes_online_profiles set enabled=false where tenant_id=new.tenant_id and enabled;
    end if;
    return new;
end
$$;
create trigger kubernetes_online_tenant_changed after update on tenants
    for each row execute function kubernetes_online_tenant_changed();

create table kubernetes_online_tokens (
    tenant_id text not null,
    token_digest bytea not null check (octet_length(token_digest) = 32),
    client_id text not null,
    grant_id uuid not null,
    user_id uuid not null,
    public_sid text not null,
    subject text not null check (octet_length(subject) between 1 and 2048),
    profile_revision uuid not null,
    cluster_profile_revision bigint not null check (cluster_profile_revision > 0),
    reviewer_client_id text not null,
    issued_at timestamptz not null,
    expires_at timestamptz not null,
    primary key (tenant_id, token_digest),
    check (expires_at > issued_at and expires_at <= issued_at + interval '300 seconds'),
    foreign key (tenant_id, client_id)
        references kubernetes_online_profiles (tenant_id, client_id) on delete cascade,
    foreign key (tenant_id, grant_id)
        references grants (tenant_id, grant_id) on delete cascade,
    foreign key (tenant_id, user_id)
        references users (tenant_id, user_id) on delete cascade,
    foreign key (tenant_id, public_sid)
        references sessions (tenant_id, public_sid) on delete cascade,
    foreign key (tenant_id, reviewer_client_id)
        references clients (tenant_id, client_id) on delete cascade
);
create index kubernetes_online_tokens_expiry on kubernetes_online_tokens (expires_at);
