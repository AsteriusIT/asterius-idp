#!/usr/bin/env python3
"""Disposable source-schema and kept-fixture validation; never a shared DB."""
from pathlib import Path
import datetime
import os
import subprocess
import urllib.parse
import uuid
base=os.environ.get('ASTERIUS_ACCEPTANCE_DATABASE_BASE','postgres://asterius:asterius@127.0.0.1:5433/postgres')
parsed=urllib.parse.urlsplit(base)
if parsed.hostname!='127.0.0.1' or parsed.path!='/postgres':raise RuntimeError('own local PostgreSQL fixture required')
name='ast_kube53_schema_'+uuid.uuid4().hex[:12]
db=base.rsplit('/',1)[0]+'/'+name
repo=Path(__file__).resolve().parents[2]
def sql(conn,statement):
    result=subprocess.run(['psql',conn,'-X','-v','ON_ERROR_STOP=1','-q','-At','-c',statement],capture_output=True,text=True)
    if result.returncode:raise RuntimeError(result.stderr.strip()[:1000])
    return result.stdout.strip()
sql(base,'create database '+name)
try:
    for migration in sorted((repo/'crates/store-pg/migrations').glob('*.sql')):
        result=subprocess.run(['psql',db,'-X','-v','ON_ERROR_STOP=1','-1','-q','-f',str(migration)],capture_output=True,text=True)
        if result.returncode:raise RuntimeError(migration.name+': '+result.stderr[-1200:])
    sql(db,"""insert into tenants(tenant_id,issuer,display_name,default_resource) values('retention','https://retention.example','Retention','https://api.example/');
insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,jwks) values('retention','billing','Billing','private_key_jwt','{"keys":[]}'::jsonb);
insert into resource_servers(tenant_id,identifier,scopes) values('retention','https://api.example/',array['openid','refund']);
insert into client_roles(tenant_id,client_id,name)values('retention','billing','refund');
insert into users(tenant_id,user_id,username)values('retention','00000000-0000-4000-8000-000000000001','owner'),('retention',md5('retentionstale')::uuid,'stale-approver'),('retention',md5('retentionfresh')::uuid,'fresh-approver');""")
    fixture=(repo/'crates/store-pg/tests/fixtures/temporary-retention.sql').read_text()
    for label,offset in [('stale',-2*86400),('fresh',3600)]:
        expiry=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=offset)).isoformat()
        for statement in fixture.split(';'):
            if not statement.strip():continue
            sql(db,"prepare own_fixture(text,uuid,uuid,text,timestamptz) as "+statement+";execute own_fixture('retention','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002','"+label+"','"+expiry+"');deallocate own_fixture;")
    assert sql(db,'select count(*) from temporary_kubernetes_bindings;')=='2'
    assert sql(db,'select count(*) from temporary_entitlement_activations;')=='2'
    print('Source migrations + kept lifecycle fixtures + disabled Kubernetes mappings PASS')
finally:
    sql(base,'drop database '+name)
