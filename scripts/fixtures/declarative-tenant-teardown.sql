-- Run only against an explicitly disposable, migrated fixture database.
-- Every write rolls back, including the deliberately deleted tenant.
begin;
do $$
declare
    target text := 'teardown-' || replace(gen_random_uuid()::text,'-','');
    group_key uuid := gen_random_uuid();
    revision_before bigint;
begin
    insert into tenants(tenant_id,issuer,display_name,default_resource)
    values(target,'https://fixture.invalid/t/'||target,'Teardown fixture','https://fixture.invalid/resource');
    insert into managed_groups(tenant_id,group_id,name,display_name,created_at,updated_at)
    values(target,group_key,'teardown-fixture','Teardown fixture',now(),now());
    update declarative_owners set owner='["fixture","controller"]',deletion_protection=true
    where tenant_id=target and kind='group';
    begin
        delete from tenants where tenant_id=target;
        raise exception 'protected child allowed tenant deletion';
    exception when sqlstate 'P0001' then
        if sqlerrm <> 'declarative_delete_protected' then raise; end if;
    end;
    if not exists(select 1 from managed_groups where tenant_id=target)
       or not exists(select 1 from declarative_owners where tenant_id=target and owner is not null and deletion_protection) then
        raise exception 'failed protected deletion changed live state/authority';
    end if;
    update declarative_owners set deletion_protection=false where tenant_id=target;
    select revision into revision_before from declarative_owners where tenant_id=target and kind='group';
    delete from managed_groups where tenant_id=target and group_id=group_key;
    if not exists(select 1 from declarative_owners where tenant_id=target and kind='group'
                  and deleted and revision=revision_before+1) then
        raise exception 'ordinary child delete lost its monotonic tombstone';
    end if;
    insert into declarative_creation_keys(tenant_id,kind,owner,external_key,keys,initial_spec,initial_protection,incarnation)
    select tenant_id,kind,owner,'fixture/create',keys,'{}'::jsonb,false,incarnation
    from declarative_owners where tenant_id=target and kind='group';
    insert into declarative_deletion_receipts(tenant_id,kind,keys,owner,expected_revision)
    select tenant_id,kind,keys,owner,repeat('a',64)
    from declarative_owners where tenant_id=target and kind='group';
    -- An ordinary unowned child must also cascade without recreating metadata.
    insert into managed_groups(tenant_id,group_id,name,display_name,created_at,updated_at)
    values(target,gen_random_uuid(),'ordinary-fixture','Ordinary fixture',now(),now());
    delete from tenants where tenant_id=target;
    if exists(select 1 from tenants where tenant_id=target)
       or exists(select 1 from managed_groups where tenant_id=target)
       or exists(select 1 from declarative_owners where tenant_id=target)
       or exists(select 1 from declarative_creation_keys where tenant_id=target)
       or exists(select 1 from declarative_deletion_receipts where tenant_id=target) then
        raise exception 'tenant cascade retained live state, authority, creation keys or receipts';
    end if;

    insert into tenants(tenant_id,issuer,display_name,default_resource)
    values(target,'https://fixture.invalid/t/'||target,'Teardown fixture','https://fixture.invalid/resource');
    update declarative_owners set owner='["fixture","controller"]',deletion_protection=true
    where tenant_id=target and kind='tenant';
    begin
        delete from tenants where tenant_id=target;
        raise exception 'protected tenant allowed deletion';
    exception when sqlstate 'P0001' then
        if sqlerrm <> 'declarative_delete_protected' then raise; end if;
    end;
    update declarative_owners set owner=null where tenant_id=target;
    delete from tenants where tenant_id=target;
end;
$$;
rollback;
