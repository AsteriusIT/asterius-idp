-- Candidate catalogue storage for ast-dd1y.6.3. Delivery/shared enablement awaits
-- acceptance of docs/adr/outbound-scim-contract.md; no credential enters SQL.
create table outbound_scim_connectors (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
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

-- A successful read-only peer preview authorizes enabling only this exact
-- configuration revision and credential generation, for five minutes.
create table outbound_scim_previews (
    tenant_id text not null,
    connector_id uuid not null,
    connector_revision uuid not null,
    credential_generation uuid not null,
    previewed_by uuid not null,
    previewed_at timestamptz not null,
    expires_at timestamptz not null,
    primary key (tenant_id,connector_id,connector_revision,credential_generation),
    foreign key (tenant_id,connector_id) references outbound_scim_connectors(tenant_id,connector_id) on delete cascade,
    check (expires_at>previewed_at and expires_at<=previewed_at+interval '5 minutes')
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
    creation_admitted boolean not null default false,
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
        references outbound_scim_connectors(tenant_id, connector_id) on delete cascade,
    unique (tenant_id, connector_id, immutable_alias),
    unique (tenant_id, connector_id, external_id),
    check (target_id is not null or observed_etag is null),
    check (state <> 'deleted' or not selected)
);

create unique index outbound_scim_current_source
    on outbound_scim_assignments(tenant_id, connector_id, kind, source_id)
    where retired_at is null;
create unique index outbound_scim_target_mapping
    on outbound_scim_assignments(tenant_id, connector_id, kind, target_id)
    where target_id is not null;
create index outbound_scim_dirty_page
    on outbound_scim_assignments(tenant_id, connector_id, assignment_id)
    where dirty and retired_at is null;

-- Explicit approvals are immutable historical context, with a short dispatch
-- window. Completion remains replayable after expiry; it grants no new effect.
create table outbound_scim_lifecycle_requests (
    tenant_id text not null,
    request_id uuid not null default gen_random_uuid(),
    assignment_id uuid not null,
    assignment_generation uuid not null,
    connector_revision uuid not null,
    credential_generation uuid not null,
    desired_revision uuid not null,
    kind text not null check (kind in ('archive','delete','recreate')),
    target_id uuid,
    expected_etag text check (expected_etag is null or length(expected_etag) between 1 and 128),
    reviewed_by uuid not null,
    reviewed_at timestamptz not null,
    expires_at timestamptz not null,
    delete_admitted boolean not null default false,
    completed_at timestamptz,
    cancelled_at timestamptz,
    replacement_id uuid,
    failure_code text check(failure_code is null or failure_code in (
        'paused','credential_unavailable','credential_binding_mismatch','authentication_refused',
        'target_unavailable','ownership_mismatch','target_absent','target_version_changed',
        'source_protected','source_projection_invalid','user_dependencies_pending',
        'snapshot_bound_exceeded','lease_superseded')),
    primary key (tenant_id,request_id),
    foreign key (tenant_id,assignment_id) references outbound_scim_assignments(tenant_id,assignment_id) on delete cascade,
    check (expires_at>reviewed_at and expires_at<=reviewed_at+interval '5 minutes'),
    check ((target_id is null)=(expected_etag is null)),
    check (kind<>'delete' or target_id is not null),
    check (not delete_admitted or kind='delete'),
    check (replacement_id is null or kind='recreate'),
    check (completed_at is null or cancelled_at is null)
);
create unique index outbound_scim_open_lifecycle on outbound_scim_lifecycle_requests(tenant_id,assignment_id)
  where completed_at is null and cancelled_at is null;
create function outbound_scim_guard_lifecycle() returns trigger language plpgsql as $$
begin
    if (new.tenant_id,new.request_id,new.assignment_id,new.assignment_generation,
        new.connector_revision,new.credential_generation,new.desired_revision,new.kind,
        new.target_id,new.expected_etag,new.reviewed_by,new.reviewed_at,new.expires_at)
       is distinct from
       (old.tenant_id,old.request_id,old.assignment_id,old.assignment_generation,
        old.connector_revision,old.credential_generation,old.desired_revision,old.kind,
        old.target_id,old.expected_etag,old.reviewed_by,old.reviewed_at,old.expires_at)
       or (old.delete_admitted and not new.delete_admitted)
       or (old.completed_at is not null and (new.completed_at,new.replacement_id) is distinct from (old.completed_at,old.replacement_id)) then
      raise exception 'lifecycle approval and receipt are immutable'
        using errcode='23514', constraint='outbound_scim_lifecycle_pin';
    end if;
    return new;
end;
$$;
create trigger outbound_scim_lifecycle_pin before update on outbound_scim_lifecycle_requests
  for each row execute function outbound_scim_guard_lifecycle();

-- Serialize catalogue creation without upgrading the actor's tenant share lock.
create function outbound_scim_connector_bound() returns trigger language plpgsql as $$
begin
    perform pg_advisory_xact_lock(hashtextextended('outbound-scim-connectors:' || new.tenant_id,0));
    if (select count(*) from outbound_scim_connectors
      where tenant_id=new.tenant_id and removed_at is null) >= 100 then
      raise exception 'connector catalogue exceeds its bounded profile'
        using errcode='23514', constraint='outbound_scim_connector_bound';
    end if;
    return new;
end;
$$;
create trigger outbound_scim_connector_bound before insert on outbound_scim_connectors
  for each row execute function outbound_scim_connector_bound();

create function outbound_scim_guard_connector() returns trigger language plpgsql as $$
begin
    if (new.tenant_id,new.connector_id) is distinct from (old.tenant_id,old.connector_id) then
        raise exception 'connector identity is immutable'
            using errcode='23514', constraint='outbound_scim_connector_identity';
    end if;
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
        if old.creation_admitted and not new.creation_admitted then
            raise exception 'uncertain creation evidence cannot be cleared'
                using errcode='23514', constraint='outbound_scim_creation_pin';
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
    -- Quiescing mappings remain current until verified archival. Bounding all
    -- current incarnations also bounds complete resume/rotation reconciliation.
    if new.retired_at is null and (
        select count(*) from outbound_scim_assignments
          where tenant_id=new.tenant_id and connector_id=new.connector_id
            and kind=new.kind and retired_at is null
            and assignment_id<>new.assignment_id
    ) >= 100 then
        raise exception 'current assignment catalogue exceeds its bounded profile'
            using errcode='23514', constraint='outbound_scim_current_bound';
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

-- Callers already hold the connector lock before locking an assignment. The
-- payload is an incarnation locator, never a source attribute or credential.
create function outbound_scim_enqueue_assignment(p_tenant text, p_assignment uuid)
returns void language plpgsql as $$
declare item outbound_scim_assignments%rowtype;
begin
    select * into item from outbound_scim_assignments
      where tenant_id=p_tenant and assignment_id=p_assignment for update;
    if not found or item.retired_at is not null or item.state='deleted' then return; end if;
    update outbound_scim_assignments set dirty=true, desired_revision=gen_random_uuid(),
      failure_code=null, state='pending'
      where tenant_id=p_tenant and assignment_id=p_assignment;
    -- Keep at most one queued successor to an in-flight claim. Delivery always
    -- rereads the latest projection, so coalescing pending changes loses no state.
    if not exists (select 1 from outbox where tenant_id=p_tenant
      and ordering_key='outbound_scim:' || p_assignment::text
      and status in ('pending','failed')) then
        insert into outbox (tenant_id,kind,destination,payload,ordering_key)
        values (p_tenant,'outbound_scim.reconcile',item.connector_id::text,
          jsonb_build_object('assignment',item.assignment_id,'generation',item.generation),
          'outbound_scim:' || item.assignment_id::text);
    end if;
end;
$$;

-- Every ordinary writer participates, including source deletion cascades. A
-- source UUID is deliberately historical: deleting it must still deactivate its
-- mapped User or empty its mapped Group after the source transaction commits.
create function outbound_scim_dirty_source(p_tenant text, p_kind text, p_source uuid)
returns void language plpgsql as $$
declare parent uuid; item uuid;
begin
    for parent in select c.connector_id from outbound_scim_connectors c
      where c.tenant_id=p_tenant and c.removed_at is null and exists (
        select 1 from outbound_scim_assignments a
        where a.tenant_id=c.tenant_id and a.connector_id=c.connector_id
          and a.retired_at is null and a.state<>'deleted' and (
            (a.kind=p_kind and a.source_id=p_source) or
            (p_kind='user' and a.kind='group' and exists (
              select 1 from group_memberships m where m.tenant_id=p_tenant
                and m.group_id=a.source_id and m.user_id=p_source)))
      ) order by c.connector_id for update
    loop
      for item in select a.assignment_id from outbound_scim_assignments a
        where a.tenant_id=p_tenant and a.connector_id=parent
          and a.retired_at is null and a.state<>'deleted' and (
            (a.kind=p_kind and a.source_id=p_source) or
            (p_kind='user' and a.kind='group' and exists (
              select 1 from group_memberships m where m.tenant_id=p_tenant
                and m.group_id=a.source_id and m.user_id=p_source)))
        order by a.assignment_id
      loop
        perform outbound_scim_enqueue_assignment(p_tenant,item);
      end loop;
    end loop;
end;
$$;

create function outbound_scim_source_changed() returns trigger language plpgsql as $$
begin
    if tg_table_name='users' then
      if tg_op='DELETE' then
        perform outbound_scim_dirty_source(old.tenant_id,'user',old.user_id);
      elsif tg_op='INSERT' or (new.status,new.email) is distinct from (old.status,old.email) then
        perform outbound_scim_dirty_source(new.tenant_id,'user',new.user_id);
      end if;
    elsif tg_table_name='managed_groups' then
      if tg_op='DELETE' then
        perform outbound_scim_dirty_source(old.tenant_id,'group',old.group_id);
      else
        perform outbound_scim_dirty_source(new.tenant_id,'group',new.group_id);
      end if;
    else
      if tg_op in ('DELETE','UPDATE') then
        perform outbound_scim_dirty_source(old.tenant_id,'group',old.group_id);
      end if;
      if tg_op='INSERT' or (tg_op='UPDATE' and
        (new.tenant_id,new.group_id) is distinct from (old.tenant_id,old.group_id)) then
        perform outbound_scim_dirty_source(new.tenant_id,'group',new.group_id);
      end if;
    end if;
    return null;
end;
$$;
create trigger outbound_scim_user_changed after insert or update or delete on users
  for each row execute function outbound_scim_source_changed();
create trigger outbound_scim_group_changed after insert or update or delete on managed_groups
  for each row execute function outbound_scim_source_changed();
create trigger outbound_scim_membership_changed after insert or update or delete on group_memberships
  for each row execute function outbound_scim_source_changed();

-- Generic tenant cascade must not discard authority to deprovision remote objects.
-- Connector and assignment creation take tenant FOR SHARE, serializing this guard.
create function outbound_scim_tenant_delete_guard() returns trigger language plpgsql as $$
begin
    if exists (select 1 from outbound_scim_assignments
      where tenant_id=old.tenant_id and retired_at is null) then
      raise exception 'outbound assignments require explicit deprovision and archive'
        using errcode='23514', constraint='outbound_scim_tenant_live_assignments';
    end if;
    return old;
end;
$$;
create trigger outbound_scim_tenant_delete_guard before delete on tenants
  for each row execute function outbound_scim_tenant_delete_guard();

create function outbound_scim_source_authority_changed() returns trigger language plpgsql as $$
declare source_kind text; source_id uuid; source_tenant text;
begin
    source_kind := case when tg_table_name='scim_user_external_ids' then 'user' else 'group' end;
    if tg_op in ('DELETE','UPDATE') then
      source_tenant := old.tenant_id;
      source_id := (to_jsonb(old)->>(case when source_kind='user' then 'user_id' else 'group_id' end))::uuid;
      perform outbound_scim_dirty_source(source_tenant,source_kind,source_id);
    end if;
    if tg_op in ('INSERT','UPDATE') then
      source_tenant := new.tenant_id;
      source_id := (to_jsonb(new)->>(case when source_kind='user' then 'user_id' else 'group_id' end))::uuid;
      perform outbound_scim_dirty_source(source_tenant,source_kind,source_id);
    end if;
    return null;
end;
$$;
create trigger outbound_scim_user_authority_changed after insert or update or delete on scim_user_external_ids
  for each row execute function outbound_scim_source_authority_changed();
create trigger outbound_scim_group_authority_changed after insert or update or delete on scim_group_owners
  for each row execute function outbound_scim_source_authority_changed();

-- This exact reserved namespace is the outbound connector's incarnation, not a
-- generic SCIM alias. Retain its uniqueness across physical deletion/identity
-- changes so an already-admitted late collection POST cannot revive it.
create table scim_outbound_incarnation_tombstones (
    tenant_id text not null references tenants(tenant_id) on delete cascade,
    client_id text not null,
    kind text not null check(kind in ('user','group')),
    external_id text not null check(length(external_id)<=256),
    target_id uuid not null,
    retired_at timestamptz not null default clock_timestamp(),
    primary key(tenant_id,client_id,kind,external_id)
);
create function scim_outbound_reserved_external(value text,kind text)
returns boolean language sql immutable as $$
    select coalesce(value ~ ('^urn:asterius:outbound:[^:]{1,64}:' ||
      '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:' || kind || ':' ||
      '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:' ||
      '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),false)
$$;
create function scim_outbound_incarnation_guard() returns trigger language plpgsql as $$
declare
    old_value jsonb := case when tg_op='INSERT' then null else to_jsonb(old) end;
    new_value jsonb := case when tg_op='DELETE' then null else to_jsonb(new) end;
    resource_kind text := case when tg_table_name='scim_user_external_ids' then 'user' else 'group' end;
    identity_column text := case when tg_table_name='scim_user_external_ids' then 'user_id' else 'group_id' end;
    lock_name text;
    old_reserved boolean;
    new_reserved boolean;
    retire_old boolean;
begin
    old_reserved := scim_outbound_reserved_external(old_value->>'external_id',resource_kind);
    new_reserved := scim_outbound_reserved_external(new_value->>'external_id',resource_kind);
    if not old_reserved and not new_reserved then
      if tg_op='DELETE' then return old; else return new; end if;
    end if;
    -- Serialize capacity and uniqueness in a closed tenant/client/kind scope.
    -- Sorted scopes also cover the uncommon direct owner-key replacement.
    for lock_name in
      select distinct scope from (values
        (case when old_reserved then jsonb_build_array(old_value->>'tenant_id',old_value->>'client_id',resource_kind)::text end),
        (case when new_reserved then jsonb_build_array(new_value->>'tenant_id',new_value->>'client_id',resource_kind)::text end)
      ) keys(scope) where scope is not null order by scope
    loop
      perform pg_advisory_xact_lock(hashtextextended('scim-outbound-incarnations:'||lock_name,0));
    end loop;
    retire_old := old_reserved and (tg_op='DELETE' or
       (old_value->>'tenant_id',old_value->>'client_id',old_value->>identity_column,old_value->>'external_id')
         is distinct from
       (new_value->>'tenant_id',new_value->>'client_id',new_value->>identity_column,new_value->>'external_id')
       or (resource_kind='user' and old_value->>'deleted_at' is null and new_value->>'deleted_at' is not null));
    -- Whole target-tenant deletion is an explicit destructive lifecycle that
    -- also removes its credentials; no FK is recreated during that cascade.
    if retire_old and exists(select 1 from tenants where tenant_id=old_value->>'tenant_id') then
      if not exists(select 1 from scim_outbound_incarnation_tombstones t
          where tenant_id=old_value->>'tenant_id' and client_id=old_value->>'client_id'
            and t.kind=resource_kind and external_id=old_value->>'external_id') then
        if (select count(*) from scim_outbound_incarnation_tombstones t
              where tenant_id=old_value->>'tenant_id' and client_id=old_value->>'client_id'
                and t.kind=resource_kind)>=10000 then
          raise exception 'reserved incarnation retention bound reached'
            using errcode='23514',constraint='scim_outbound_tombstone_bound';
        end if;
        insert into scim_outbound_incarnation_tombstones(tenant_id,client_id,kind,external_id,target_id)
          values(old_value->>'tenant_id',old_value->>'client_id',resource_kind,old_value->>'external_id',(old_value->>identity_column)::uuid);
      end if;
    end if;
    if new_reserved and (resource_kind='group' or new_value->>'deleted_at' is null) and
      exists(select 1 from scim_outbound_incarnation_tombstones t
        where tenant_id=new_value->>'tenant_id' and client_id=new_value->>'client_id'
          and t.kind=resource_kind and external_id=new_value->>'external_id') then
      raise exception 'reserved incarnation has been retired'
        using errcode='23505',constraint='scim_outbound_incarnation_retired';
    end if;
    if tg_op='DELETE' then return old; else return new; end if;
end;
$$;
create trigger scim_outbound_incarnation_guard before insert or update or delete
  on scim_user_external_ids for each row execute function scim_outbound_incarnation_guard();
create trigger scim_outbound_incarnation_guard before insert or update or delete
  on scim_group_owners for each row execute function scim_outbound_incarnation_guard();
