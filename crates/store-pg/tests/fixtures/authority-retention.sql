-- Representative lifecycle records for composed migrations.
-- Disabled sources and tombstones are retention evidence, never issuance proof.
with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into client_id_migrations (tenant_id,old_client_id,new_client_id)
select tenant,label,md5(tenant||label)::uuid from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into conditional_client_settings (tenant_id,client_id,revision)
select tenant,'billing',md5(tenant||'retention')::uuid from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into authorization_diagnostics (tenant_id,evidence_id,diagnostics,created_at,expires_at)
select tenant,md5(tenant||label)::uuid,'{}'::jsonb,expires-interval '1 hour',expires from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into workload_trusts (tenant_id,trust_id,config)
select tenant,label,'{}'::jsonb from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into workload_grant_bindings (tenant_id,grant_id,trust_id,trust_version,provider,principal,assertion_digest,assertion_expires_at)
select tenant,grant_id,label,1,'kubernetes','retention',sha256(convert_to(label,'UTF8')),expires from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into workload_spiffe_bundle_history (tenant_id,trust_id,trust_domain,snapshot)
select tenant,label,'retention.example','{}'::jsonb from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into workload_assertion_consumptions (tenant_id,trust_id,digest,expires_at,consumed_at)
select tenant,label,sha256(convert_to(label,'UTF8')),expires,expires-interval '1 hour' from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into agent_task_clients (tenant_id,client_id)
select tenant,'billing' from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into agent_tasks (tenant_id,task_id,root_grant_id,owner_user_id,initiating_client_id,permissions,label,approved_at,expires_at)
select tenant,md5(tenant||'retention')::uuid,grant_id,owner,'billing','{}'::jsonb,'Retention history',expires-interval '30 minutes',expires from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into agent_task_grants (tenant_id,grant_id,task_id,root_grant_id,approval_revision)
select f.tenant,f.grant_id,t.task_id,t.root_grant_id,t.approval_revision from f join agent_tasks t on t.tenant_id=f.tenant and t.root_grant_id=f.grant_id on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into agent_task_tokens (tenant_id,jti,grant_id,expires_at)
select tenant,label,grant_id,expires from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into agent_task_withdrawals (tenant_id,ancestor_grant_id,task_id,root_grant_id,approval_revision,withdrawn_at,reason)
select f.tenant,f.grant_id,t.task_id,t.root_grant_id,t.approval_revision,f.expires,'Retention history' from f join agent_tasks t on t.tenant_id=f.tenant and t.root_grant_id=f.grant_id on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into declarative_owners (tenant_id,kind,keys,owner)
select tenant,'group',jsonb_build_array(label),'retention' from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into declarative_creation_keys (tenant_id,kind,owner,external_key,keys,initial_spec,initial_protection,incarnation)
select f.tenant,'group','retention',f.label,d.keys,'{}'::jsonb,true,d.incarnation from f join declarative_owners d on d.tenant_id=f.tenant and d.kind='group' and d.keys=jsonb_build_array(f.label) on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into declarative_deletion_receipts (tenant_id,kind,keys,owner,expected_revision)
select tenant,'group',jsonb_build_array(label),'retention',repeat('a',64) from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into governance_ownerships (tenant_id,ownership_id,target_kind,target_keys,owner_user_id,reviewers,enabled)
select tenant,md5(tenant||label)::uuid,'membership',jsonb_build_array(label,owner),owner,array[owner],false from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into governance_reviews (tenant_id,review_id,created_by,created_at,due_at)
select tenant,md5(tenant||label)::uuid,owner,expires-interval '1 hour',expires from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into governance_review_items (tenant_id,review_id,item_id,ownership_id,ownership_revision,target_kind,target_keys,assignment_generation,assigned_reviewer,snapshot)
select f.tenant,md5(f.tenant||f.label)::uuid,md5(f.tenant||f.label)::uuid,o.ownership_id,o.revision,o.target_kind,o.target_keys,md5(f.tenant||f.label)::uuid,f.owner,'{}'::jsonb from f join governance_ownerships o on o.tenant_id=f.tenant and o.ownership_id=md5(f.tenant||f.label)::uuid on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into outbound_scim_connectors (tenant_id,connector_id,target_issuer,target_client,credential_ref,credential_generation)
select tenant,md5(tenant||label)::uuid,'https://retention.example/','retention','retention',md5(tenant||label)::uuid from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into outbound_scim_previews (tenant_id,connector_id,connector_revision,credential_generation,previewed_by,previewed_at,expires_at)
select f.tenant,c.connector_id,c.revision,c.credential_generation,f.owner,f.expires-interval '1 minute',f.expires from f join outbound_scim_connectors c on c.tenant_id=f.tenant and c.connector_id=md5(f.tenant||f.label)::uuid on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into outbound_scim_assignments (tenant_id,connector_id,assignment_id,kind,source_id,immutable_alias,external_id)
select tenant,md5(tenant||label)::uuid,md5(tenant||label)::uuid,'user',md5(tenant||label)::uuid,label,label from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into outbound_scim_lifecycle_requests (tenant_id,request_id,assignment_id,assignment_generation,connector_revision,credential_generation,desired_revision,kind,reviewed_by,reviewed_at,expires_at)
select f.tenant,md5(f.tenant||f.label)::uuid,a.assignment_id,a.generation,c.revision,c.credential_generation,a.desired_revision,'archive',f.owner,f.expires-interval '1 minute',f.expires from f join outbound_scim_connectors c on c.tenant_id=f.tenant and c.connector_id=md5(f.tenant||f.label)::uuid join outbound_scim_assignments a on a.tenant_id=c.tenant_id and a.connector_id=c.connector_id on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into scim_outbound_incarnation_tombstones (tenant_id,client_id,kind,external_id,target_id)
select tenant,'billing','user',label,md5(tenant||label)::uuid from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into managed_device_sources (tenant_id,source_id,client_id,revision,created_at,updated_at)
select tenant,md5(tenant||'retention')::uuid,'billing',md5(tenant||'retention')::uuid,expires,expires from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into managed_devices (tenant_id,device_id,source_id,source_generation,revision,created_at,updated_at,removed_at)
select f.tenant,md5(f.tenant||f.label)::uuid,s.source_id,s.generation,md5(f.tenant||f.label)::uuid,f.expires,f.expires,case when f.label='stale' then f.expires-interval '31 days' else f.expires end from f join managed_device_sources s on s.tenant_id=f.tenant and s.client_id='billing' on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into managed_device_interaction_proofs (tenant_id,request_uri_hash,interaction_id_hash,device_id,binding,expires_at)
select tenant,sha256(convert_to(label,'UTF8')),sha256(convert_to(label,'UTF8')),md5(tenant||label)::uuid,'{}'::jsonb,expires from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into managed_device_code_proofs (tenant_id,code_hash,device_id,binding,expires_at)
select tenant,sha256(convert_to(label,'UTF8')),md5(tenant||label)::uuid,'{}'::jsonb,expires from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into managed_device_relay_tokens (tenant_id,jti,grant_id,client_id,enrollments,posture,expires_at)
select tenant,label,grant_id,'billing',true,false,expires from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into kubernetes_profiles (tenant_id,client_id,cluster_id,namespace,group_ids,revision)
select tenant,'billing','retention','retention',array[]::uuid[],1 from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into kubernetes_online_profiles (tenant_id,client_id,reviewer_client_id)
select tenant,'billing','stale' from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into kubernetes_online_reviewer_tokens (tenant_id,jti_digest,grant_id,client_id,expires_at)
select tenant,sha256(convert_to(label,'UTF8')),grant_id,'stale',expires from f on conflict do nothing;

with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into kubernetes_online_tokens (tenant_id,token_digest,client_id,grant_id,user_id,public_sid,subject,profile_revision,cluster_profile_revision,reviewer_client_id,issued_at,expires_at)
select f.tenant,sha256(convert_to(f.label,'UTF8')),'billing',f.grant_id,f.owner,s.public_sid,'retention',p.revision,1,'stale',f.expires-interval '1 minute',f.expires from f join kubernetes_online_profiles p on p.tenant_id=f.tenant and p.client_id='billing' join sessions s on s.tenant_id=f.tenant and s.session_id=f.label on conflict do nothing;
