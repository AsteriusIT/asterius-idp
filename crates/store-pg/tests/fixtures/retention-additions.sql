-- Additional schema fixtures: each statement shares the same five bound parameters.
with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into users (tenant_id,user_id,username)
select tenant,extra_user,label from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into clients (tenant_id,client_id,client_name,token_endpoint_auth_method,jwks,last_used_at)
select tenant,label,label,'private_key_jwt','{"keys":[]}'::jsonb,expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into claims_provider_oauth_pending (tenant_id,state_hash,user_id,session_digest,provider_issuer,provider_nonce,verifier_ciphertext,verifier_nonce,verifier_kek_id,expires_at)
select tenant,repeat(md5(label),2),owner,repeat('a',64),issuer,repeat('b',32),decode(repeat('ab',49),'hex'),nonce,'fixture',expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into claims_provider_oauth_connections (tenant_id,user_id,provider_issuer,provider_subject,granted_scope,access_ciphertext,access_nonce,access_kek_id,access_expires_at,updated_at)
select tenant,owner,issuer,'subject','openid',decode(repeat('ab',17),'hex'),nonce,'fixture',expires,expires-interval '30 minutes' from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into claims_provider_oauth_revocations (tenant_id,user_id,provider_issuer,revoked_at)
select tenant,owner,issuer,expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into aggregated_claim_sources (tenant_id,user_id,provider_issuer,provider_subject,claim_names,expires_at,stored_at,ciphertext,nonce,kek_id)
select tenant,owner,issuer,'subject',array['name'],expires,expires-interval '1 hour',decode(repeat('ab',17),'hex'),nonce,'fixture' from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into cimd_client_documents (tenant_id,client_id,document_body,document_sha256,expires_at)
select tenant,label,'{}'::bytea,decode(repeat('ab',32),'hex'),expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into id_jag_consents (tenant_id,user_id,issuer,actor_client_id,client_id,resource,scopes,granted_at,expires_at)
select tenant,owner,issuer,'actor','billing','https://api.example/',array['openid'],expires-interval '1 hour',expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into native_sso_secrets (tenant_id,secret_digest,source_client_id,source_grant_id,user_id,public_sid,expires_at)
select tenant,decode(md5(label),'hex'),'billing',v.grant_id,owner,s.public_sid,expires from v join sessions s on s.tenant_id=v.tenant and s.session_id='fresh' on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into oidc_upstream_pending (tenant_id,state_digest,interaction_digest,provider_id,issuer,client_id,token_endpoint,jwks_uri,nonce_digest,verifier_ciphertext,verifier_nonce,kek_id,expires_at)
select tenant,repeat(md5(label),2),repeat(md5(label),2),'provider',issuer,'billing',issuer || 'token',issuer || 'jwks',repeat('a',64),decode(repeat('ab',49),'hex'),nonce,'fixture',expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into totp_credentials (tenant_id,user_id,ciphertext,nonce,kek_id,state,created_at,expires_at)
select tenant,extra_user,decode(repeat('ab',32),'hex'),nonce,'fixture','pending',expires-interval '1 hour',expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into ssf_receiver_upstream_streams (tenant_id,peer_client_id,issuer,jwks_uri,configuration_endpoint,status_endpoint,stream_id,delivery_method,audience,events_requested,created_at,updated_at)
select tenant,'billing','https://upstream.example/','https://upstream.example/jwks','https://upstream.example/config','https://upstream.example/status','stream','urn:ietf:rfc:8935','https://as.example/',array['https://schemas.openid.net/secevent/caep/event-type/session-revoked'],expires,expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into ssf_receiver_upstream_verification_events (tenant_id,peer_client_id,jti,stream_id,replay_until,processed_at)
select tenant,'billing',label,'stream',expires,expires-interval '1 hour' from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into ssf_receiver_upstream_setup_intents (tenant_id,peer_client_id,issuer,jwks_uri,configuration_endpoint,status_endpoint,audience,events_requested,delivery_method,started_at)
select tenant,'pending','https://upstream.example/','https://upstream.example/jwks','https://upstream.example/config','https://upstream.example/status','https://as.example/',array['https://schemas.openid.net/secevent/caep/event-type/session-revoked'],'urn:ietf:rfc:8936',expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into architecture_flows (tenant_id,flow_id,name,graph,created_at,updated_at)
select tenant,v.grant_id,'Flow','{}'::jsonb,expires,expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into flow_resource_links (tenant_id,flow_id,node_id,resource_kind,resource_id,relation,state,created_in_revision,created_at,updated_at)
select tenant,v.grant_id,'client','client','billing','reference','applied',1,expires,expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into id_jag_subject_bindings (tenant_id,issuer,upstream_subject,user_id)
select tenant,issuer,'subject',owner from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into legacy_session_expiry_claims (tenant_id,user_id,claim_name,claim_value)
select tenant,owner,'session_expiry','123'::jsonb from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into native_sso_derivations (tenant_id,grant_id,public_sid,source_grant_id)
select tenant,v.grant_id,s.public_sid,v.grant_id from v join sessions s on s.tenant_id=v.tenant and s.session_id='fresh' on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into oidc_identity_providers (tenant_id,provider_id,display_name,issuer,authorization_endpoint,token_endpoint,jwks_uri,client_id,client_secret_ciphertext,client_secret_nonce,kek_id)
select tenant,label,'Provider',issuer,issuer || 'authorize',issuer || 'token',issuer || 'jwks','billing',decode(repeat('ab',17),'hex'),nonce,'fixture' from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into oidc_identity_bindings (tenant_id,provider_id,issuer,upstream_subject,user_id)
select tenant,label,issuer,'subject',owner from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into provider_command_subjects (tenant_id,user_id,client_id,subject,first_claimed_at)
select tenant,owner,'billing','subject',expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into verified_claim_bundles (tenant_id,user_id,bundle_id,trust_framework,verifier_issuer,verified_at,claims)
select tenant,owner,extra_user,'framework',issuer,expires,'{}'::jsonb from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into scim_user_external_ids (tenant_id,client_id,user_id,external_id)
select tenant,'billing',owner,'external' from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into ldap_user_owners (tenant_id,source_key,user_id,external_id)
select tenant,repeat('a',64),owner,'external' from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into managed_groups (tenant_id,group_id,name,display_name,created_at,updated_at)
select tenant,extra_user,label,label,expires,expires from v  on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into ldap_group_owners (tenant_id,source_key,group_id,external_id)
select tenant,repeat('a',64),extra_user,label from v where label='stale' on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, md5(tenant || label)::uuid as extra_user, decode(substr(md5(tenant || label), 1, 24), 'hex') as nonce, 'https://' || label || '.example/' as issuer from f)
insert into scim_group_owners (tenant_id,client_id,group_id,external_id)
select tenant,'billing',extra_user,label from v where label='fresh' on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, decode(substr(md5(tenant || label),1,24),'hex') as nonce from f)
insert into saml_sp_trusts (tenant_id,entity_id,acs_url)
select tenant,'https://sp.example/','https://sp.example/acs' from v on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, decode(substr(md5(tenant || label),1,24),'hex') as nonce from f)
insert into saml_authn_request_replays (tenant_id,sp_entity_id,request_id_hash,reserved_at,expires_at)
select tenant,'https://sp.example/',sha256(convert_to(label,'UTF8')),expires-interval '1 hour',expires from v on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, decode(substr(md5(tenant || label),1,24),'hex') as nonce from f)
insert into saml_idp_signing_keys (tenant_id,certificate_der,certificate_sha256,state)
select tenant,decode(repeat('ab',256),'hex'),sha256(convert_to(label,'UTF8')),'retired' from v on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, decode(substr(md5(tenant || label),1,24),'hex') as nonce from f)
insert into saml_pending_logins (tenant_id,token_digest,interaction_id_hash,sp_entity_id,acs_url,request_id,issued_at,expires_at)
select tenant,repeat(md5(label),2),sha256(convert_to('console-' || tenant || '-' || label,'UTF8')),'https://sp.example/','https://sp.example/acs',label,expires-interval '1 hour',expires from v on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, decode(substr(md5(tenant || label),1,24),'hex') as nonce from f)
insert into federation_signing_keys (tenant_id,kid,public_jwk,ciphertext,nonce,kek_id,state,created_at)
select tenant,label,'{}'::jsonb,decode(repeat('ab',32),'hex'),nonce,'fixture','retired',expires from v on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, decode(substr(md5(tenant || label),1,24),'hex') as nonce from f)
insert into ssf_receiver_subject_mappings (tenant_id,peer_client_id,subject_key,user_id)
select tenant,'billing','subject',owner from v on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, decode(substr(md5(tenant || label),1,24),'hex') as nonce from f)
insert into ssf_receiver_subject_order (tenant_id,peer_client_id,subject_key,user_id,latest_event_timestamp)
select tenant,'billing','subject',owner,expires from v on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, decode(substr(md5(tenant || label),1,24),'hex') as nonce from f)
insert into ssf_receiver_events (tenant_id,peer_client_id,jti,replay_until,user_id,event_type,event_timestamp)
select tenant,'billing',label,expires,owner,'session-revoked',expires from v on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, decode(substr(md5(tenant || label),1,24),'hex') as nonce from f)
insert into id_jag_replays (tenant_id,issuer,jti_hash,user_id,expires_at)
select tenant,'https://upstream.example/',sha256(convert_to(label,'UTF8')),owner,expires from v on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, decode(substr(md5(tenant || label),1,24),'hex') as nonce from f)
insert into oid4vci_nonces (tenant_id,nonce_digest,expires_at)
select tenant,sha256(convert_to(label,'UTF8')),expires from v on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires), v as (select *, decode(substr(md5(tenant || label),1,24),'hex') as nonce from f)
insert into oid4vp_transactions (tenant_id,state_digest,nonce,client_id,initiator_client_id,credential_id,verifier_id,expires_at)
select tenant,sha256(convert_to(label,'UTF8')),label,'billing','billing','credential','verifier',expires from v on conflict do nothing;

-- Provenance fixtures exercise retention only. no authority is inferred at runtime.
with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires)
insert into session_assurance_proofs (tenant_id,session_id,acr,assurance_authenticated_at,assurance_policy_revision,assurance_methods)
select s.tenant_id,s.session_id,s.acr,s.authenticated_at,repeat('a',64),array['pwd'] from sessions s,f
where s.tenant_id=f.tenant and s.session_id=f.label on conflict do nothing;

with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires)
insert into grant_assurance_proofs (tenant_id,grant_id,authenticated_at,acr,amr,assurance_authenticated_at,assurance_policy_revision,assurance_methods)
select g.tenant_id,g.grant_id,f.expires,g.acr,g.amr,f.expires,repeat('a',64),array['pwd'] from grants g,f
where g.tenant_id=f.tenant and g.grant_id=f.grant_id on conflict do nothing;

-- Retention-only exact lineage; never a runtime source of fresh assurance.
with f as (select $1::text as tenant, $2::uuid as owner, $3::uuid as grant_id, $4::text as label, $5::timestamptz as expires)
insert into grant_session_lineage(tenant_id,grant_id,user_id,public_sid,lookup_digest)
select g.tenant_id,g.grant_id,f.owner,s.public_sid,s.session_id from grants g,f,sessions s
where g.tenant_id=f.tenant and g.grant_id=f.grant_id and s.tenant_id=f.tenant and s.session_id=f.label
on conflict do nothing;
