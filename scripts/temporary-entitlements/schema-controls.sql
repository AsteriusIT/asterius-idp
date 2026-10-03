-- Run only in an isolated, migrated fixture database; no live deployment.
\set ON_ERROR_STOP on
insert into tenants(tenant_id,issuer,display_name,default_resource) values('temporary-schema-control','https://temporary-schema.example','Fixture','https://temporary-api.example/');
insert into users(tenant_id,user_id,username) values
('temporary-schema-control','00000000-0000-4000-8000-000000000001','owner'),
('temporary-schema-control','00000000-0000-4000-8000-000000000002','requester'),
('temporary-schema-control','00000000-0000-4000-8000-000000000003','approver');
insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,jwks) values('temporary-schema-control','app','Fixture','private_key_jwt','{"keys":[]}'::jsonb);
insert into resource_servers(tenant_id,identifier,scopes) values('temporary-schema-control','https://temporary-api.example/',array['read']);
insert into client_roles(tenant_id,client_id,name) values('temporary-schema-control','app','approve');
insert into temporary_entitlements(tenant_id,entitlement_id,client_id,resource,role_name,permissions,owner_user_id,owner_reference,client_reference,role_reference,resource_reference,editor_user_id,requester_acr,approver_acr,enabled) values('temporary-schema-control','00000000-0000-4000-8000-000000000010','app','https://temporary-api.example/','approve',array['read'],'00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000001','app','approve','https://temporary-api.example/','00000000-0000-4000-8000-000000000001','urn:asterius:acr:passkey','urn:asterius:acr:passkey',true);
insert into temporary_entitlement_approvers(tenant_id,entitlement_id,user_id) values('temporary-schema-control','00000000-0000-4000-8000-000000000010','00000000-0000-4000-8000-000000000003');
insert into temporary_entitlement_eligibility(tenant_id,eligibility_id,entitlement_id,user_id,editor_user_id,not_before,expires_at) values('temporary-schema-control','00000000-0000-4000-8000-000000000020','00000000-0000-4000-8000-000000000010','00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000001',clock_timestamp()-interval '1 minute',clock_timestamp()+interval '10 minutes');
insert into temporary_entitlement_requests(tenant_id,request_id,entitlement_id,eligibility_id,eligibility_revision,policy_revision,requester_user_id,client_id,resource,role_name,permissions,requester_acr,approver_acr,duration_seconds,reason,created_at,deadline)
select e.tenant_id,'00000000-0000-4000-8000-000000000030',e.entitlement_id,el.eligibility_id,el.revision,e.revision,el.user_id,e.client_id,e.resource,e.role_name,e.permissions,e.requester_acr,e.approver_acr,60,'Fixture scope',stamp,stamp+interval '5 minutes' from temporary_entitlements e join temporary_entitlement_eligibility el using(tenant_id,entitlement_id) cross join (select clock_timestamp() stamp) t where e.tenant_id='temporary-schema-control';
do $$ begin
    begin
        update temporary_entitlement_requests set permissions=array['write'] where tenant_id='temporary-schema-control';
        raise exception 'test failure: mutable approved scope';
    exception when raise_exception then
        if sqlerrm <> 'immutable temporary entitlement request' then raise; end if;
    end;
end $$;
update temporary_entitlement_requests set status='approved',decided_at=clock_timestamp(),decided_by='00000000-0000-4000-8000-000000000003' where tenant_id='temporary-schema-control';
insert into temporary_entitlement_activations(tenant_id,activation_id,request_id,entitlement_id,user_id,activated_at,expires_at)
select 'temporary-schema-control','00000000-0000-4000-8000-000000000040','00000000-0000-4000-8000-000000000030','00000000-0000-4000-8000-000000000010','00000000-0000-4000-8000-000000000002',stamp,stamp+interval '1 minute' from (select clock_timestamp() stamp) t;
do $$ begin
    begin
        update temporary_entitlement_activations set expires_at=expires_at+interval '1 minute' where tenant_id='temporary-schema-control';
        raise exception 'test failure: activation extension';
    exception when raise_exception then
        if sqlerrm <> 'immutable temporary entitlement activation' then raise; end if;
    end;
end $$;
update resource_servers set scopes=array[]::text[] where tenant_id='temporary-schema-control';
update resource_servers set scopes=array['read'] where tenant_id='temporary-schema-control';
do $$ begin
    if exists(select 1 from temporary_entitlements where tenant_id='temporary-schema-control' and enabled) then raise exception 'test failure: catalogue ABA restored configuration'; end if;
    if exists(select 1 from temporary_entitlements e join temporary_entitlement_requests r using(tenant_id,entitlement_id) where e.tenant_id='temporary-schema-control' and e.revision=r.policy_revision) then raise exception 'test failure: catalogue change retained snapshot incarnation'; end if;
end $$;
update users set status='disabled' where tenant_id='temporary-schema-control' and username='requester';
update users set status='active' where tenant_id='temporary-schema-control' and username='requester';
do $$ begin
    if exists(select 1 from temporary_entitlement_eligibility where tenant_id='temporary-schema-control' and revoked_at is null) then raise exception 'test failure: account reenable restored eligibility'; end if;
end $$;
delete from client_roles where tenant_id='temporary-schema-control';
insert into client_roles(tenant_id,client_id,name) values('temporary-schema-control','app','approve');
do $$ begin
    if exists(select 1 from temporary_entitlements where tenant_id='temporary-schema-control' and role_reference is not null) then raise exception 'test failure: catalogue name reuse restored binding'; end if;
end $$;
delete from tenants where tenant_id='temporary-schema-control';
select 'temporary entitlement immutability/catalogue ABA/subject terminal withdrawal/role tombstone/cascade: PASS';
