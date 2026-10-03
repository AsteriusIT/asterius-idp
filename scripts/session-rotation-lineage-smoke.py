#!/usr/bin/env python3
"""Owned SQL evidence for exact lookup lineage; no server/runtime claim."""
from pathlib import Path
import os, subprocess, urllib.parse, uuid
repo=Path(__file__).resolve().parents[1]
base=os.environ.get('ASTERIUS_ACCEPTANCE_DATABASE_BASE','postgres://asterius:asterius@127.0.0.1:5433/postgres')
parsed=urllib.parse.urlsplit(base)
if parsed.hostname!='127.0.0.1' or parsed.path!='/postgres':raise RuntimeError('own local PostgreSQL database required')
name='ast_kq2m_'+uuid.uuid4().hex[:12];db=base.rsplit('/',1)[0]+'/'+name
def sql(conn,text):
 r=subprocess.run(['psql',conn,'-X','-q','-At','-v','ON_ERROR_STOP=1','-c',text],capture_output=True,text=True)
 if r.returncode:raise RuntimeError(r.stderr)
 return r.stdout.strip()
sql(base,'create database '+name)
try:
 for p in sorted((repo/'crates/store-pg/migrations').glob('*.sql')):
  r=subprocess.run(['psql',db,'-X','-q','-1','-v','ON_ERROR_STOP=1','-f',str(p)],capture_output=True,text=True)
  if r.returncode:raise RuntimeError(p.name+': '+r.stderr[-2000:])
 sql(db,"""
 insert into tenants(tenant_id,issuer,display_name,default_resource) values('one','https://one.example','One','https://api.example/');
 insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,jwks) values('one','app','App','private_key_jwt','{"keys":[]}'::jsonb);
 insert into users(tenant_id,user_id,username) values('one','00000000-0000-4000-8000-000000000001','owner');
 insert into sessions(tenant_id,session_id,public_sid,user_id,authenticated_at,expires_at,idle_expires_at,acr,amr) values
 ('one','old','public-original','00000000-0000-4000-8000-000000000001',now(),now()+interval '1 hour',now()+interval '1 hour','phr',array['pop','user']),
 ('one','other','public-unrelated','00000000-0000-4000-8000-000000000001',now(),now()+interval '1 hour',now()+interval '1 hour','phr',array['pop','user']);
 insert into session_assurance_proofs(tenant_id,session_id,acr,assurance_authenticated_at,assurance_policy_revision,assurance_methods)
 select tenant_id,session_id,acr,authenticated_at,repeat(case when session_id='old' then 'a' else 'b' end,64),amr from sessions;
 insert into grants(tenant_id,grant_id,client_id,user_id,subject,session_id,authenticated_at,acr,amr)
 select 'one',case when session_id='old' then '00000000-0000-4000-8000-000000000002'::uuid else '00000000-0000-4000-8000-000000000003'::uuid end,'app',user_id,'public-user',session_id,authenticated_at,acr,amr from sessions;
 """)
 before=sql(db,"select row_to_json(p)::text from grant_assurance_proofs p where grant_id='00000000-0000-4000-8000-000000000002'")
 assert before and sql(db,'select count(*) from grant_session_lineage')=='2'
 sql(db,"""begin;
 update sessions set session_id='new',authenticated_at=authenticated_at+interval '30 seconds' where tenant_id='one' and session_id='old' and revoked_at is null and expires_at>now() and idle_expires_at>now();
 update grants set session_id='new' where tenant_id='one' and user_id='00000000-0000-4000-8000-000000000001' and session_id='old';
 update session_assurance_proofs set assurance_policy_revision=repeat('c',64) where tenant_id='one' and session_id='new';
 commit;""")
 assert sql(db,"select row_to_json(p)::text from grant_assurance_proofs p where grant_id='00000000-0000-4000-8000-000000000002'")==before
 assert sql(db,"select session_id from grants where grant_id='00000000-0000-4000-8000-000000000002'")=='new'
 assert sql(db,"select session_id from grants where grant_id='00000000-0000-4000-8000-000000000003'")=='other'
 assert sql(db,"select public_sid||':'||lookup_digest from grant_session_lineage where grant_id='00000000-0000-4000-8000-000000000002'")=='public-original:new'
 sql(db,"update grants set session_id='other' where grant_id='00000000-0000-4000-8000-000000000002'")
 assert sql(db,"select count(*) from grant_assurance_proofs where grant_id='00000000-0000-4000-8000-000000000002'")=='0'
 assert sql(db,"select count(*) from grant_session_lineage where grant_id='00000000-0000-4000-8000-000000000002'")=='0'
 sql(db,"delete from sessions where tenant_id='one' and session_id='other'")
 assert sql(db,'select count(*) from grant_session_lineage')=='0'
 assert sql(db,"select count(*) from grant_assurance_proofs where grant_id='00000000-0000-4000-8000-000000000003'")=='1'
 print('Owned full-schema SQL smoke PASS: exact lookup move, frozen proof byte equality, unrelated same-user grant untouched, arbitrary reassignment proof/lineage refusal, session deletion lineage cascade and original proof retention')
finally:sql(base,'drop database '+name)
