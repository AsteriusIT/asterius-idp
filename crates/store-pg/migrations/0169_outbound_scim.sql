-- Prepared catalogue storage for ast-dd1y.6.3. Runtime wiring/enablement awaits
-- acceptance of docs/adr/outbound-scim-contract.md; no credential enters SQL.
create table outbound_scim_connectors (
    tenant_id text not null references tenants(tenant_id) on delete restrict,
    connector_id uuid not null default gen_random_uuid(),
    revision uuid not null default gen_random_uuid(),
    target_issuer text not null check (length(target_issuer) between 1 and 2048),
    target_client text not null check (length(target_client) between 1 and 2048),
    credential_ref text not null check (credential_ref ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'),
    credential_generation uuid not null,
    enabled boolean not null default false,
    allow_reviewed_delete boolean not null default false,
    removed_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (tenant_id, connector_id),
    check (removed_at is null or not enabled)
);

create table outbound_scim_assignments (
    tenant_id text not null,
    connector_id uuid not null,
    assignment_id uuid not null default gen_random_uuid(),
    kind text not null check (kind in ('user', 'group')),
    -- No live source FK: source disappearance must retain ownership/mapping.
    source_id uuid not null,
    generation uuid not null default gen_random_uuid(),
    immutable_alias text not null check (length(immutable_alias) between 1 and 200),
    external_id text not null check (length(external_id) between 1 and 256),
    selected boolean not null default true,
    desired_revision uuid not null default gen_random_uuid(),
    delivered_revision uuid,
    dirty boolean not null default true,
    target_id uuid,
    observed_etag text check (observed_etag is null or length(observed_etag) between 1 and 128),
    state text not null default 'pending'
        check (state in ('pending', 'waiting_dependencies', 'applied', 'paused', 'conflict', 'dead_letter', 'deleted')),
    failure_code text check (failure_code is null or failure_code in (
        'paused', 'credential_unavailable', 'credential_binding_mismatch',
        'authentication_refused', 'target_unavailable', 'ownership_mismatch',
        'target_absent', 'target_version_changed', 'source_protected',
        'source_projection_invalid', 'user_dependencies_pending',
        'snapshot_bound_exceeded', 'lease_superseded')),
    observed_at timestamptz,
    retired_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    primary key (tenant_id, assignment_id),
    foreign key (tenant_id, connector_id)
        references outbound_scim_connectors(tenant_id, connector_id) on delete restrict,
    unique (tenant_id, connector_id, immutable_alias),
    unique (tenant_id, connector_id, external_id),
    check (target_id is not null or observed_etag is null),
    check (state <> 'deleted' or not selected)
);

create unique index outbound_scim_current_source
    on outbound_scim_assignments(tenant_id, connector_id, kind, source_id)
    where retired_at is null;
create index outbound_scim_dirty_page
    on outbound_scim_assignments(tenant_id, connector_id, assignment_id)
    where dirty and retired_at is null;

create table outbound_scim_reviewed_deletes (
    tenant_id text not null,
    delete_id uuid not null default gen_random_uuid(),
    assignment_id uuid not null,
    assignment_generation uuid not null,
    connector_revision uuid not null,
    target_id uuid not null,
    -- Historical reviewer identity remains evidence after account deletion.
    reviewed_by uuid not null,
    reviewed_at timestamptz not null,
    completed_at timestamptz,
    primary key (tenant_id, delete_id),
    foreign key (tenant_id, assignment_id)
        references outbound_scim_assignments(tenant_id, assignment_id) on delete restrict,
    unique (tenant_id, assignment_id, assignment_generation, target_id)
);

create function outbound_scim_guard_connector() returns trigger language plpgsql as $$
begin
    if (new.target_issuer, new.target_client) is distinct from
       (old.target_issuer, old.target_client) and exists (
        select 1 from outbound_scim_assignments
         where tenant_id=old.tenant_id and connector_id=old.connector_id
    ) then
        raise exception 'connector principal is pinned by retained assignments'
            using errcode='23514', constraint='outbound_scim_principal_pin';
    end if;
    new.revision := gen_random_uuid();
    new.updated_at := clock_timestamp();
    return new;
end;
$$;
create trigger outbound_scim_connector_revision before update
    on outbound_scim_connectors for each row execute function outbound_scim_guard_connector();

create function outbound_scim_guard_assignment() returns trigger language plpgsql as $$
begin
    -- The parent lock serializes both selection limits and principal changes.
    perform 1 from outbound_scim_connectors
      where tenant_id=new.tenant_id and connector_id=new.connector_id for update;
    if tg_op='UPDATE' then
        if (new.tenant_id,new.connector_id,new.assignment_id,new.kind,new.source_id,
            new.generation,new.immutable_alias,new.external_id) is distinct from
           (old.tenant_id,old.connector_id,old.assignment_id,old.kind,old.source_id,
            old.generation,old.immutable_alias,old.external_id) then
            raise exception 'assignment incarnation is immutable'
                using errcode='23514', constraint='outbound_scim_assignment_incarnation';
        end if;
        if old.target_id is not null and new.target_id is distinct from old.target_id then
            raise exception 'mapping cannot adopt another target'
                using errcode='23514', constraint='outbound_scim_target_pin';
        end if;
        if old.retired_at is not null and new.retired_at is distinct from old.retired_at then
            raise exception 'retired assignment cannot be revived'
                using errcode='23514', constraint='outbound_scim_retirement_pin';
        end if;
    end if;
    if tg_op='INSERT' or (tg_op='UPDATE' and new.selected and not old.selected) then
        if new.kind='user' then
            if not exists (select 1 from users where tenant_id=new.tenant_id and user_id=new.source_id)
               or exists (select 1 from scim_user_external_ids where tenant_id=new.tenant_id and user_id=new.source_id) then
                raise exception 'source is unavailable or belongs to inbound SCIM'
                    using errcode='23514', constraint='outbound_scim_local_source';
            end if;
        else
            if not exists (select 1 from managed_groups where tenant_id=new.tenant_id and group_id=new.source_id)
               or exists (select 1 from scim_group_owners where tenant_id=new.tenant_id and group_id=new.source_id) then
                raise exception 'source is unavailable or belongs to inbound SCIM'
                    using errcode='23514', constraint='outbound_scim_local_source';
            end if;
        end if;
    end if;
    if new.selected and new.retired_at is null and (
        select count(*) from outbound_scim_assignments
         where tenant_id=new.tenant_id and connector_id=new.connector_id
           and kind=new.kind and selected and retired_at is null
           and assignment_id<>new.assignment_id
    ) >= 100 then
        raise exception 'connector selection exceeds its bounded resource profile'
            using errcode='23514', constraint='outbound_scim_selection_bound';
    end if;
    new.updated_at := clock_timestamp();
    return new;
end;
$$;
create trigger outbound_scim_assignment_guard before insert or update
    on outbound_scim_assignments for each row execute function outbound_scim_guard_assignment();
