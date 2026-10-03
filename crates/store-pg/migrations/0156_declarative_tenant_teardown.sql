-- Ordinary writes stamp unowned metadata too; RESTRICT accidentally made every
-- populated tenant undeletable. Preserve protected controller resources with a
-- tenant BEFORE guard, then remove all authority metadata in the same cascade.
alter table declarative_owners drop constraint declarative_owners_tenant_id_fkey;
alter table declarative_owners add constraint declarative_owners_tenant_id_fkey
    foreign key(tenant_id) references tenants(tenant_id) on delete cascade;
alter table declarative_creation_keys drop constraint declarative_creation_keys_tenant_id_fkey;
alter table declarative_creation_keys add constraint declarative_creation_keys_tenant_id_fkey
    foreign key(tenant_id) references tenants(tenant_id) on delete cascade;
alter table declarative_creation_keys drop constraint declarative_creation_keys_tenant_id_kind_keys_fkey;
alter table declarative_creation_keys add constraint declarative_creation_keys_tenant_id_kind_keys_fkey
    foreign key(tenant_id,kind,keys) references declarative_owners(tenant_id,kind,keys) on delete cascade;
alter table declarative_deletion_receipts drop constraint declarative_deletion_receipts_tenant_id_kind_keys_fkey;
alter table declarative_deletion_receipts add constraint declarative_deletion_receipts_tenant_id_kind_keys_fkey
    foreign key(tenant_id,kind,keys) references declarative_owners(tenant_id,kind,keys) on delete cascade;

create or replace function guard_declarative_resource() returns trigger language plpgsql as $$
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
    if resource_kind = 'tenant' and TG_OP = 'DELETE' then
        -- FK cascades can remove ownership before child DELETE guards execute.
        -- Lock every existing generation before checking protection so a racing
        -- adoption/protection update cannot slip between this check and cascade.
        perform 1 from declarative_owners
        where tenant_id = target_tenant order by kind, keys for update;
        if exists(select 1 from declarative_owners
                  where tenant_id = target_tenant and owner is not null
                    and deletion_protection) then
            raise exception using errcode='P0001',message='declarative_delete_protected';
        end if;
    end if;
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

create or replace function stamp_declarative_generation() returns trigger language plpgsql as $$
declare
    resource jsonb;
    resource_kind text := TG_ARGV[0];
    resource_keys jsonb;
begin
    if TG_OP = 'DELETE' then resource := to_jsonb(OLD); else resource := to_jsonb(NEW); end if;
    -- A tenant cascade has already removed the parent row. Do not recreate a
    -- tombstone that references that deleted authority; its metadata cascades.
    -- Ordinary child deletes keep their parent and must still stamp receipts.
    if TG_OP = 'DELETE' and not exists(
        select 1 from tenants where tenant_id = resource->>'tenant_id'
    ) then
        return null;
    end if;
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
