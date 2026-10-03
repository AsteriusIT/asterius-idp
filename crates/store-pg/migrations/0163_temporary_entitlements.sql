-- Temporary application roles remain distinct from standing assignments and
-- OAuth consent. Every authority-bearing row is tenant scoped; live checks,
-- rather than a cleanup schedule, decide eligibility and exclusive expiry.
create table temporary_entitlements (
    tenant_id text not null references tenants on delete cascade,
    entitlement_id uuid not null,
    client_id text not null,
    resource text not null,
    role_name text not null,
    permissions text[] not null check (cardinality(permissions) between 1 and 64),
    owner_user_id uuid not null,
    owner_reference uuid,
    client_reference text,
    role_reference text,
    resource_reference text,
    editor_user_id uuid not null,
    revision uuid not null default gen_random_uuid(),
    enabled boolean not null default false,
    requester_acr text not null check (octet_length(requester_acr) between 1 and 256),
    approver_acr text not null check (octet_length(approver_acr) between 1 and 256),
    max_duration_seconds integer not null default 900 check (max_duration_seconds between 1 and 3600),
    max_eligibility_seconds integer not null default 86400 check (max_eligibility_seconds between 1 and 2592000),
    created_at timestamptz not null default clock_timestamp(),
    primary key (tenant_id, entitlement_id),
    check (owner_reference is null or owner_reference = owner_user_id),
    check (client_reference is null or client_reference = client_id),
    check (role_reference is null or role_reference = role_name),
    check (resource_reference is null or resource_reference = resource),
    check ((client_reference is null) = (role_reference is null)),
    foreign key (tenant_id, client_reference, role_reference) references client_roles on delete set null (client_reference, role_reference),
    foreign key (tenant_id, resource_reference) references resource_servers(tenant_id, identifier) on delete set null (resource_reference),
    foreign key (tenant_id, owner_reference) references users on delete set null (owner_reference)
);
create index temporary_entitlements_owner on temporary_entitlements(tenant_id, owner_user_id, entitlement_id);
create table temporary_entitlement_approvers (
    tenant_id text not null,
    entitlement_id uuid not null,
    user_id uuid not null,
    primary key (tenant_id, entitlement_id, user_id),
    foreign key (tenant_id, entitlement_id) references temporary_entitlements on delete cascade,
    foreign key (tenant_id, user_id) references users on delete cascade
);
create table temporary_entitlement_eligibility (
    tenant_id text not null,
    eligibility_id uuid not null,
    entitlement_id uuid not null,
    user_id uuid not null,
    editor_user_id uuid not null,
    revision uuid not null default gen_random_uuid(),
    not_before timestamptz not null,
    expires_at timestamptz not null check (expires_at > not_before),
    revoked_at timestamptz,
    primary key (tenant_id, eligibility_id),
    unique (tenant_id,eligibility_id,entitlement_id,user_id),
    foreign key (tenant_id, entitlement_id) references temporary_entitlements on delete cascade,
    foreign key (tenant_id, user_id) references users on delete cascade
);
create unique index temporary_entitlement_one_eligibility on temporary_entitlement_eligibility(tenant_id, entitlement_id, user_id) where revoked_at is null;
create index temporary_entitlement_eligible_user on temporary_entitlement_eligibility(tenant_id, user_id, entitlement_id);
create table temporary_entitlement_requests (
    tenant_id text not null,
    request_id uuid not null,
    entitlement_id uuid not null,
    eligibility_id uuid not null,
    eligibility_revision uuid not null,
    policy_revision uuid not null,
    requester_user_id uuid not null,
    -- Immutable display and authority snapshot; later catalogue/configuration
    -- edits never widen an already submitted request.
    client_id text not null,
    resource text not null,
    role_name text not null,
    permissions text[] not null,
    requester_acr text not null check (octet_length(requester_acr) between 1 and 256),
    approver_acr text not null check (octet_length(approver_acr) between 1 and 256),
    duration_seconds integer not null check (duration_seconds between 1 and 3600),
    reason text not null check (octet_length(reason) between 1 and 1024),
    created_at timestamptz not null,
    deadline timestamptz not null check (deadline = created_at + interval '5 minutes'),
    status text not null default 'pending' check (status in ('pending','approved','denied','cancelled','expired','invalidated')),
    decided_at timestamptz,
    decided_by uuid,
    decision_key uuid,
    primary key (tenant_id, request_id),
    unique (tenant_id,request_id,entitlement_id,requester_user_id),
    foreign key (tenant_id, entitlement_id) references temporary_entitlements on delete cascade,
    foreign key (tenant_id,eligibility_id,entitlement_id,requester_user_id) references temporary_entitlement_eligibility(tenant_id,eligibility_id,entitlement_id,user_id) on delete cascade,
    foreign key (tenant_id, requester_user_id) references users on delete cascade,
    check ((status = 'pending') = (decided_at is null)),
    check (decided_by is null or decided_by <> requester_user_id or status = 'cancelled')
);
create index temporary_entitlement_requests_inbox on temporary_entitlement_requests(tenant_id, entitlement_id, status, request_id);
create index temporary_entitlement_requests_user on temporary_entitlement_requests(tenant_id, requester_user_id, request_id);
create table temporary_entitlement_activations (
    tenant_id text not null,
    activation_id uuid not null,
    request_id uuid not null,
    entitlement_id uuid not null,
    user_id uuid not null,
    activated_at timestamptz not null,
    expires_at timestamptz not null check (expires_at > activated_at and expires_at <= activated_at + interval '1 hour'),
    revoked_at timestamptz,
    revocation_reason text check (octet_length(revocation_reason) between 1 and 1024),
    expiry_recorded_at timestamptz,
    primary key (tenant_id, activation_id),
    unique (tenant_id, request_id),
    foreign key (tenant_id,request_id,entitlement_id,user_id) references temporary_entitlement_requests(tenant_id,request_id,entitlement_id,requester_user_id) on delete cascade,
    foreign key (tenant_id, entitlement_id) references temporary_entitlements on delete cascade,
    foreign key (tenant_id, user_id) references users on delete cascade,
    check ((revoked_at is null) = (revocation_reason is null))
);
create index temporary_entitlement_live_user on temporary_entitlement_activations(tenant_id, user_id, entitlement_id, expires_at) where revoked_at is null;
create index temporary_entitlement_expiry on temporary_entitlement_activations(tenant_id, expires_at, activation_id) where expiry_recorded_at is null;

create function immutable_temporary_entitlement_request() returns trigger language plpgsql as $$
begin
    if (to_jsonb(new) - array['status','decided_at','decided_by','decision_key']) is distinct from
       (to_jsonb(old) - array['status','decided_at','decided_by','decision_key'])
       or old.status <> 'pending' then
        raise exception 'immutable temporary entitlement request';
    end if;
    return new;
end $$;
create trigger temporary_entitlement_requests_immutable before update on temporary_entitlement_requests
    for each row execute function immutable_temporary_entitlement_request();
create function immutable_temporary_entitlement_activation() returns trigger language plpgsql as $$
begin
    if (to_jsonb(new) - array['revoked_at','revocation_reason','expiry_recorded_at']) is distinct from
       (to_jsonb(old) - array['revoked_at','revocation_reason','expiry_recorded_at'])
       or (old.revoked_at is not null and (new.revoked_at is distinct from old.revoked_at or new.revocation_reason is distinct from old.revocation_reason))
       or (old.expiry_recorded_at is not null and new.expiry_recorded_at is distinct from old.expiry_recorded_at) then
        raise exception 'immutable temporary entitlement activation';
    end if;
    return new;
end $$;
create trigger temporary_entitlement_activations_immutable before update on temporary_entitlement_activations
    for each row execute function immutable_temporary_entitlement_activation();

-- These writers share the existing tenant publication fence with final token
-- signatures. Revocation/configuration cannot race a privileged signature.
create function fence_temporary_entitlement_authority() returns trigger language plpgsql as $$
begin
    perform 1 from tenants where tenant_id = coalesce(new.tenant_id,old.tenant_id) for no key update;
    if tg_op = 'DELETE' then return old; end if;
    return new;
end $$;
create trigger temporary_entitlements_fence before insert or update or delete on temporary_entitlements
    for each row execute function fence_temporary_entitlement_authority();
create trigger temporary_entitlement_approvers_fence before insert or update or delete on temporary_entitlement_approvers
    for each row execute function fence_temporary_entitlement_authority();
create trigger temporary_entitlement_eligibility_fence before insert or update or delete on temporary_entitlement_eligibility
    for each row execute function fence_temporary_entitlement_authority();
create trigger temporary_entitlement_requests_fence before insert or update or delete on temporary_entitlement_requests
    for each row execute function fence_temporary_entitlement_authority();
create trigger temporary_entitlement_activations_fence before insert or update or delete on temporary_entitlement_activations
    for each row execute function fence_temporary_entitlement_authority();

-- A configuration/eligibility edit invalidates captured approvals by revision;
-- null references are terminal tombstones and cannot attach to reused names.
create function revise_temporary_entitlement() returns trigger language plpgsql as $$
begin
    if (new.tenant_id,new.entitlement_id,new.client_id,new.resource,new.role_name,new.permissions,new.owner_user_id,new.created_at)
        is distinct from (old.tenant_id,old.entitlement_id,old.client_id,old.resource,old.role_name,old.permissions,old.owner_user_id,old.created_at)
        or (new.owner_reference is not null and new.owner_reference is distinct from old.owner_reference)
        or (new.client_reference is not null and new.client_reference is distinct from old.client_reference)
        or (new.role_reference is not null and new.role_reference is distinct from old.role_reference)
        or (new.resource_reference is not null and new.resource_reference is distinct from old.resource_reference) then
        raise exception 'immutable temporary entitlement binding';
    end if;
    new.revision := gen_random_uuid();
    if new.owner_reference is null or new.client_reference is null or new.role_reference is null or new.resource_reference is null then
        new.enabled := false;
    end if;
    return new;
end $$;
create trigger temporary_entitlements_revision before update on temporary_entitlements
    for each row execute function revise_temporary_entitlement();
create function revise_temporary_entitlement_eligibility() returns trigger language plpgsql as $$
begin
    if (new.tenant_id,new.eligibility_id,new.entitlement_id,new.user_id)
        is distinct from (old.tenant_id,old.eligibility_id,old.entitlement_id,old.user_id)
        or (old.revoked_at is not null and new.revoked_at is distinct from old.revoked_at) then
        raise exception 'immutable temporary entitlement eligibility';
    end if;
    new.revision := gen_random_uuid();
    return new;
end $$;
create trigger temporary_entitlement_eligibility_revision before update on temporary_entitlement_eligibility
    for each row execute function revise_temporary_entitlement_eligibility();
create function revise_temporary_entitlement_approvers() returns trigger language plpgsql as $$
begin
    update temporary_entitlements set revision = gen_random_uuid()
        where tenant_id = coalesce(new.tenant_id,old.tenant_id)
          and entitlement_id = coalesce(new.entitlement_id,old.entitlement_id);
    if tg_op = 'DELETE' then return old; end if;
    return new;
end $$;
create trigger temporary_entitlement_approvers_revision after insert or update or delete on temporary_entitlement_approvers
    for each row execute function revise_temporary_entitlement_approvers();

-- Re-enabling an account cannot restore a previously withdrawn activation.
create function terminal_temporary_entitlement_principal() returns trigger language plpgsql as $$
begin
    if new.status <> 'active' then
        update temporary_entitlement_eligibility set revoked_at = clock_timestamp()
            where tenant_id = new.tenant_id and user_id = new.user_id and revoked_at is null;
        update temporary_entitlements set enabled = false
            where tenant_id = new.tenant_id and owner_user_id = new.user_id and enabled;
    end if;
    return new;
end $$;
create trigger users_terminal_temporary_entitlements after update of status on users
    for each row execute function terminal_temporary_entitlement_principal();

-- Reply replay is scoped to the exact actor, operation and canonical payload.
-- This table stores response metadata, never browser credentials.
create table temporary_entitlement_replays (
    tenant_id text not null references tenants on delete cascade,
    actor_user_id uuid not null,
    operation text not null check (operation in ('request','decide','cancel','revoke','owner_revoke')),
    idempotency_key uuid not null,
    payload jsonb not null,
    response jsonb not null,
    created_at timestamptz not null,
    primary key (tenant_id,actor_user_id,operation,idempotency_key),
    foreign key (tenant_id,actor_user_id) references users on delete cascade
);

-- Catalogue narrowing and temporary disablement cannot later resurrect an
-- activation captured against an older configuration incarnation.
create function invalidate_temporary_entitlement_resource() returns trigger language plpgsql as $$
begin
    if new.scopes is distinct from old.scopes then
        update temporary_entitlements set enabled=false
            where tenant_id=new.tenant_id and resource_reference=new.identifier;
    end if;
    return new;
end $$;
create trigger resources_invalidate_temporary_entitlements after update of scopes on resource_servers
    for each row execute function invalidate_temporary_entitlement_resource();
create function invalidate_temporary_entitlement_client() returns trigger language plpgsql as $$
begin
    if new.status <> 'active' or new.is_agent then
        update temporary_entitlements set enabled=false
            where tenant_id=new.tenant_id and client_reference=new.client_id;
    end if;
    return new;
end $$;
create trigger clients_invalidate_temporary_entitlements after update of status,is_agent on clients
    for each row execute function invalidate_temporary_entitlement_client();
