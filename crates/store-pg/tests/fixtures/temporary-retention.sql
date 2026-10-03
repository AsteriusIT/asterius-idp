-- Kept lifecycle history is not live authority; these fixtures are disabled.
with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into temporary_entitlements(tenant_id,entitlement_id,client_id,resource,role_name,permissions,owner_user_id,owner_reference,client_reference,role_reference,resource_reference,editor_user_id,requester_acr,approver_acr,created_at)
select tenant,md5(tenant||label||'entitlement')::uuid,'billing','https://api.example/','refund',array['openid'],owner,owner,'billing','refund','https://api.example/',owner,'urn:asterius:acr:passkey','urn:asterius:acr:passkey',expires-interval '1 hour' from f on conflict do nothing;
with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into temporary_entitlement_approvers(tenant_id,entitlement_id,user_id)
select tenant,md5(tenant||label||'entitlement')::uuid,md5(tenant||label)::uuid from f on conflict do nothing;
with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into temporary_entitlement_eligibility(tenant_id,eligibility_id,entitlement_id,user_id,editor_user_id,not_before,expires_at)
select tenant,md5(tenant||label||'eligibility')::uuid,md5(tenant||label||'entitlement')::uuid,owner,owner,expires-interval '1 hour',expires from f on conflict do nothing;
with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into temporary_entitlement_requests(tenant_id,request_id,entitlement_id,eligibility_id,eligibility_revision,policy_revision,requester_user_id,client_id,resource,role_name,permissions,requester_acr,approver_acr,duration_seconds,reason,created_at,deadline,status,decided_at,decided_by)
select f.tenant,md5(f.tenant||label||'request')::uuid,e.entitlement_id,el.eligibility_id,el.revision,e.revision,owner,'billing','https://api.example/','refund',array['openid'],e.requester_acr,e.approver_acr,60,'Retention fixture',expires-interval '2 minutes',expires+interval '3 minutes','approved',expires-interval '1 minute',md5(f.tenant||label)::uuid from f join temporary_entitlements e on e.tenant_id=f.tenant and e.entitlement_id=md5(f.tenant||label||'entitlement')::uuid join temporary_entitlement_eligibility el on el.tenant_id=e.tenant_id and el.entitlement_id=e.entitlement_id on conflict do nothing;
with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into temporary_entitlement_activations(tenant_id,activation_id,request_id,entitlement_id,user_id,activated_at,expires_at)
select tenant,md5(tenant||label||'activation')::uuid,md5(tenant||label||'request')::uuid,md5(tenant||label||'entitlement')::uuid,owner,expires-interval '1 minute',expires from f on conflict do nothing;
with f as (select $1::text tenant,$2::uuid owner,$3::uuid grant_id,$4::text label,$5::timestamptz expires)
insert into temporary_entitlement_replays(tenant_id,actor_user_id,operation,idempotency_key,payload,response,created_at)
select tenant,owner,'request',md5(tenant||label||'replay')::uuid,'{}'::jsonb,'{}'::jsonb,expires from f on conflict do nothing;
