insert into tenants(tenant_id,issuer,display_name,default_resource) values('cutover','https://as.example/cutover','Cutover','https://api.example/');
insert into users(tenant_id,user_id,username) values
('cutover','11111111-1111-1111-1111-111111111111','owner'),
('cutover','22222222-2222-2222-2222-222222222222','requester');
insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,scopes,resources,jwks,is_agent,agent_owner_user_id) values
('cutover','old-client','Legacy','private_key_jwt',array['client_credentials'],array['read'],array['https://api.example/'],'{"keys":[]}',true,'11111111-1111-1111-1111-111111111111'),
('cutover','old-controller','Controller','private_key_jwt',array['client_credentials'],array['read'],array['https://api.example/'],'{"keys":[]}',false,null),
('cutover','old-cluster','Cluster','private_key_jwt',array['authorization_code'],array['read'],array['https://api.example/'],'{"keys":[]}',false,null),
('cutover','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','Recipient','private_key_jwt',array['client_credentials'],array['read'],array['https://api.example/'],'{"keys":[]}',false,null),
('cutover','https://client.example/metadata.json','CIMD','private_key_jwt',array['client_credentials'],array['read'],array['https://api.example/'],'{"keys":[]}',false,null);
insert into resource_servers(tenant_id,identifier,scopes) values('cutover','https://api.example/',array['read']);
insert into client_roles(tenant_id,client_id,name) values('cutover','old-client','reader');
insert into grants(tenant_id,grant_id,client_id,user_id,subject,scopes,resources,claimed_at,expires_at,actor_chain) values
('cutover','33333333-3333-3333-3333-333333333333','old-client','11111111-1111-1111-1111-111111111111','11111111-1111-1111-1111-111111111111',array['read'],array['https://api.example/'],clock_timestamp(),clock_timestamp()+interval '1 hour','[{"client_id":"old-client"}]');
insert into grants(tenant_id,grant_id,client_id,user_id,subject,scopes,resources,parent_grant_id,parent_authority_revision,claimed_at,expires_at)
select 'cutover','44444444-4444-4444-4444-444444444444','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',user_id,subject,scopes,resources,grant_id,authority_revision,clock_timestamp(),clock_timestamp()+interval '1 hour' from grants where tenant_id='cutover';
insert into agent_task_clients values('cutover','old-client');
insert into agent_tasks(tenant_id,task_id,root_grant_id,root_reference,owner_user_id,owner_reference,initiating_client_id,client_reference,permissions,label,approved_at,expires_at)
values('cutover','55555555-5555-5555-5555-555555555555','33333333-3333-3333-3333-333333333333','33333333-3333-3333-3333-333333333333','11111111-1111-1111-1111-111111111111','11111111-1111-1111-1111-111111111111','old-client','old-client','{"actions":["read"]}','Original approval',clock_timestamp(),clock_timestamp()+interval '30 minutes');
insert into agent_task_grants(tenant_id,grant_id,task_id,root_grant_id,approval_revision)
select t.tenant_id,g.grant_id,t.task_id,t.root_grant_id,t.approval_revision from agent_tasks t join grants g using(tenant_id);
insert into refresh_tokens(tenant_id,token_hash,grant_id,client_id,dpop_jkt,absolute_expires_at)
values('cutover',decode(repeat('11',32),'hex'),'33333333-3333-3333-3333-333333333333','old-client','fixture-thumbprint',clock_timestamp()+interval '1 hour');
insert into temporary_entitlements(tenant_id,entitlement_id,client_id,client_reference,role_name,role_reference,resource,resource_reference,permissions,owner_user_id,owner_reference,editor_user_id,enabled,requester_acr,approver_acr)
values('cutover','66666666-6666-6666-6666-666666666666','old-client','old-client','reader','reader','https://api.example/','https://api.example/',array['read'],'11111111-1111-1111-1111-111111111111','11111111-1111-1111-1111-111111111111','11111111-1111-1111-1111-111111111111',true,'urn:loa:2','urn:loa:2');
insert into temporary_entitlement_eligibility(tenant_id,eligibility_id,entitlement_id,user_id,editor_user_id,not_before,expires_at)
values('cutover','77777777-7777-7777-7777-777777777777','66666666-6666-6666-6666-666666666666','22222222-2222-2222-2222-222222222222','11111111-1111-1111-1111-111111111111',clock_timestamp(),clock_timestamp()+interval '1 hour');
insert into temporary_entitlement_requests(tenant_id,request_id,entitlement_id,eligibility_id,eligibility_revision,policy_revision,requester_user_id,client_id,resource,role_name,permissions,requester_acr,approver_acr,duration_seconds,reason,created_at,deadline,status,decided_at,decided_by)
select e.tenant_id,'88888888-8888-8888-8888-888888888888',e.entitlement_id,a.eligibility_id,a.revision,e.revision,a.user_id,e.client_id,e.resource,e.role_name,e.permissions,e.requester_acr,e.approver_acr,300,'Approved original',now(),now()+interval '5 minutes','approved',now(),e.owner_user_id from temporary_entitlements e join temporary_entitlement_eligibility a using(tenant_id,entitlement_id);
insert into temporary_entitlement_requests(tenant_id,request_id,entitlement_id,eligibility_id,eligibility_revision,policy_revision,requester_user_id,client_id,resource,role_name,permissions,requester_acr,approver_acr,duration_seconds,reason,created_at,deadline)
select e.tenant_id,'99999999-9999-9999-9999-999999999999',e.entitlement_id,a.eligibility_id,a.revision,e.revision,a.user_id,e.client_id,e.resource,e.role_name,e.permissions,e.requester_acr,e.approver_acr,300,'Pending original',now(),now()+interval '5 minutes' from temporary_entitlements e join temporary_entitlement_eligibility a using(tenant_id,entitlement_id);
insert into temporary_entitlement_activations(tenant_id,activation_id,request_id,entitlement_id,user_id,activated_at,expires_at)
values('cutover','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','88888888-8888-8888-8888-888888888888','66666666-6666-6666-6666-666666666666','22222222-2222-2222-2222-222222222222',clock_timestamp(),clock_timestamp()+interval '5 minutes');
insert into temporary_kubernetes_bindings(tenant_id,entitlement_id,controller_client_id,controller_reference,cluster_client_id,cluster_client_reference,cluster_id,namespace,profile_revision,enabled)
values('cutover','66666666-6666-6666-6666-666666666666','old-controller','old-controller','old-cluster','old-cluster','cluster-one','namespace-one',1,true);
insert into auth_requests(tenant_id,request_uri_hash,client_id,parameters,expires_at)
values('cutover',decode(repeat('22',32),'hex'),'old-client','{"client_id":"old-client","captured":"original"}',clock_timestamp()+interval '1 minute');
insert into temporary_entitlement_replays(tenant_id,actor_user_id,operation,idempotency_key,payload,response,created_at)
values('cutover','22222222-2222-2222-2222-222222222222','request','cccccccc-cccc-cccc-cccc-cccccccccccc','{"client_id":"old-client"}','{"request_id":"88888888-8888-8888-8888-888888888888","client_id":"old-client"}',clock_timestamp());
insert into managed_device_sources(tenant_id,source_id,client_id,revision,enabled,created_at,updated_at)
values('cutover','dddddddd-dddd-dddd-dddd-dddddddddddd','old-controller',gen_random_uuid(),true,now(),now());
insert into managed_devices(tenant_id,device_id,source_id,source_generation,revision,user_id,leaf_sha256,allowed_client_ids,created_at,updated_at)
select tenant_id,'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee',source_id,generation,gen_random_uuid(),'22222222-2222-2222-2222-222222222222',decode(repeat('44',32),'hex'),array['old-client'],now(),now() from managed_device_sources;
insert into managed_device_interaction_proofs(tenant_id,request_uri_hash,interaction_id_hash,device_id,binding,expires_at)
values('cutover',decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee','{"client_id":"old-client","signed_origin":"original"}',clock_timestamp()+interval '1 minute');
