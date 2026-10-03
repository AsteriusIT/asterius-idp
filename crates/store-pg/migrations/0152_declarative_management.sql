-- Durable controller identities are separate from runtime tables and flow origin.
create table declarative_owners (
    tenant_id text not null references tenants(tenant_id) on delete restrict,
    kind text not null check(kind in ('tenant','application','resource','group','membership','policy')),
    keys jsonb not null check(jsonb_typeof(keys) = 'array'),
    owner text,
    deletion_protection boolean not null default true,
    revision bigint not null default 1 check (revision > 0),
    deleted boolean not null default false,
    incarnation uuid not null default gen_random_uuid(),
    primary key(tenant_id, kind, keys)
);
create table declarative_creation_keys (
    tenant_id text not null references tenants(tenant_id) on delete restrict,
    kind text not null,
    owner text not null,
    external_key text not null check(length(external_key) between 1 and 512),
    keys jsonb not null,
    initial_spec jsonb not null,
    initial_protection boolean not null,
    incarnation uuid not null,
    primary key(tenant_id, kind, owner, external_key),
    foreign key(tenant_id, kind, keys) references declarative_owners(tenant_id, kind, keys)
);

-- Used by every live writer and management claim, including absent-row creates.
-- The hash is only a lock key; uniqueness is checked against full stored keys.
create function declarative_lock(target_tenant text, target_kind text, target_keys jsonb)
returns void language sql as $$
    select pg_advisory_xact_lock(hashtextextended(target_tenant || chr(31) || target_kind || chr(31) || target_keys::text, 0));
$$;

create function guard_declarative_resource() returns trigger language plpgsql as $$
declare
    resource jsonb;
    resource_kind text := TG_ARGV[0];
    resource_keys jsonb;
    target_tenant text;
    protected boolean;
    held_owner text;
    tombstoned boolean;
begin
    if TG_OP = 'DELETE' then resource := to_jsonb(OLD); else resource := to_jsonb(NEW); end if;
    target_tenant := resource->>'tenant_id';
    if resource_kind = 'resource' then resource_keys := jsonb_build_array(resource->>'identifier');
    elsif resource_kind = 'group' then resource_keys := jsonb_build_array(resource->>'group_id');
    elsif resource_kind = 'membership' then resource_keys := jsonb_build_array(resource->>'group_id', resource->>'user_id');
    elsif resource_kind = 'policy' then resource_keys := '["policy"]'::jsonb;
    elsif resource_kind = 'application' then resource_keys := jsonb_build_array(resource->>'client_id');
    else resource_keys := jsonb_build_array(target_tenant); end if;
    if resource_kind = 'membership' then
        perform declarative_lock(target_tenant, 'group', jsonb_build_array(resource->>'group_id'));
    end if;
    perform declarative_lock(target_tenant, resource_kind, resource_keys);
    if TG_OP = 'INSERT' then
        select owner,deleted into held_owner,tombstoned from declarative_owners
        where tenant_id = target_tenant and kind = resource_kind and keys = resource_keys;
        if coalesce(tombstoned,false) and held_owner is not null
           and held_owner is distinct from nullif(current_setting('asterius.declarative_owner',true),'') then
            raise exception using errcode='P0001',message='declarative_owner_conflict';
        end if;
    end if;
    if TG_OP = 'DELETE' or (resource_kind = 'application' and TG_OP = 'UPDATE' and resource->>'status' = 'retired') then
        select deletion_protection into protected from declarative_owners
        where tenant_id = target_tenant and kind = resource_kind and keys = resource_keys and owner is not null;
        if coalesce(protected, false) then
            raise exception using errcode = 'P0001', message = 'declarative_delete_protected';
        end if;
    end if;
    if TG_OP = 'DELETE' then return OLD; else return NEW; end if;
end;
$$;
create trigger declarative_resource_guard before insert or update or delete on resource_servers
for each row execute function guard_declarative_resource('resource');
create trigger declarative_group_guard before insert or update or delete on managed_groups
for each row execute function guard_declarative_resource('group');
create trigger declarative_membership_guard before insert or update or delete on group_memberships
for each row execute function guard_declarative_resource('membership');
create trigger declarative_policy_guard before insert or update or delete on tenant_policies
for each row execute function guard_declarative_resource('policy');
create trigger declarative_client_guard before insert or update or delete on clients
for each row execute function guard_declarative_resource('application');
create trigger declarative_tenant_guard before insert or update or delete on tenants
for each row execute function guard_declarative_resource('tenant');

-- References remain allowed, but no builder may claim a controller-owned object.
create function guard_declarative_flow_origin() returns trigger language plpgsql as $$
declare
    resource_kind text;
    resource_keys jsonb;
begin
    if NEW.relation <> 'managed' then return NEW; end if;
    resource_kind := case NEW.resource_kind when 'client' then 'application' when 'api' then 'resource' else NEW.resource_kind end;
    resource_keys := jsonb_build_array(NEW.resource_id);
    perform declarative_lock(NEW.tenant_id, resource_kind, resource_keys);
    if exists(select 1 from declarative_owners where tenant_id = NEW.tenant_id and kind = resource_kind and keys = resource_keys and owner is not null) then
        raise exception using errcode = 'P0001', message = 'declarative_owner_conflict';
    end if;
    return NEW;
end;
$$;
create trigger declarative_flow_origin_guard before insert or update on flow_resource_links
for each row execute function guard_declarative_flow_origin();

-- Monotonic generations make even same-value console writes and ABA edits visible.
create function stamp_declarative_generation() returns trigger language plpgsql as $$
declare
    resource jsonb;
    resource_kind text := TG_ARGV[0];
    resource_keys jsonb;
begin
    if TG_OP = 'DELETE' then resource := to_jsonb(OLD); else resource := to_jsonb(NEW); end if;
    if resource_kind = 'resource' then resource_keys := jsonb_build_array(resource->>'identifier');
    elsif resource_kind = 'group' then resource_keys := jsonb_build_array(resource->>'group_id');
    elsif resource_kind = 'membership' then resource_keys := jsonb_build_array(resource->>'group_id', resource->>'user_id');
    elsif resource_kind = 'policy' then resource_keys := '["policy"]'::jsonb;
    elsif resource_kind = 'application' then resource_keys := jsonb_build_array(resource->>'client_id');
    else resource_keys := jsonb_build_array(resource->>'tenant_id'); end if;
    insert into declarative_owners(tenant_id,kind,keys,owner,deletion_protection,deleted)
    values(resource->>'tenant_id', resource_kind,resource_keys,null,true,TG_OP='DELETE')
    on conflict(tenant_id,kind,keys) do update set
      revision=declarative_owners.revision+1,
      incarnation=case when TG_OP='INSERT' and declarative_owners.deleted then gen_random_uuid() else declarative_owners.incarnation end,
      deleted=TG_OP='DELETE';
    if resource_kind = 'membership' then
        update declarative_owners set revision=revision+1
        where tenant_id=resource->>'tenant_id' and kind='group'
          and keys=jsonb_build_array(resource->>'group_id');
    end if;
    return null;
end;
$$;
create trigger declarative_resource_generation after insert or update or delete on resource_servers
for each row execute function stamp_declarative_generation('resource');
create trigger declarative_group_generation after insert or update or delete on managed_groups
for each row execute function stamp_declarative_generation('group');
create trigger declarative_membership_generation after insert or update or delete on group_memberships
for each row execute function stamp_declarative_generation('membership');
create trigger declarative_policy_generation after insert or update or delete on tenant_policies
for each row execute function stamp_declarative_generation('policy');
create trigger declarative_client_generation after insert or update or delete on clients
for each row execute function stamp_declarative_generation('application');
create trigger declarative_tenant_generation after insert or update on tenants
for each row execute function stamp_declarative_generation('tenant');

-- Receipts distinguish retrying an old deletion from deleting a recreated object.
create table declarative_deletion_receipts (
    tenant_id text not null,
    kind text not null,
    keys jsonb not null,
    owner text not null,
    expected_revision text not null check(length(expected_revision)=64),
    primary key(tenant_id,kind,keys,owner,expected_revision),
    foreign key(tenant_id,kind,keys) references declarative_owners(tenant_id,kind,keys)
);
