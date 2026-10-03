#!/usr/bin/env python3
"""Real PostgreSQL rotation, preserving RP lineage and discarding enrolment."""
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'integrations'))
from oidc_product_fixture import fixture, sql
with fixture(9462, 'https://localhost:9457/callback', 'session-rotation') as owned:
    database=owned['database']
    sql(database,"""
    insert into sessions(tenant_id,session_id,public_sid,user_id,authenticated_at,expires_at,idle_expires_at,acr,amr)
    select 'e2e','rotation-old','stable-public-sid',user_id,now(),now()+interval '1 hour',now()+interval '1 hour','phr',array['pop','user'] from users where tenant_id='e2e' and username='sweep@example.test';
    insert into session_clients(tenant_id,session_id,client_id) values('e2e','rotation-old','session-rotation');
    insert into passkey_enrolments(tenant_id,session_id,csrf_digest,challenge,expires_at) values('e2e','rotation-old',repeat('a',64),decode(repeat('ab',32),'hex'),now()+interval '5 minutes');
    """)
    cascades=sql(database,"select bool_or(confupdtype='c') from pg_constraint where conrelid='session_clients'::regclass and confrelid='sessions'::regclass;").strip()=='t'
    if not cascades:
        sql(database,"""do $$ begin
          begin update sessions set session_id='rotation-new' where tenant_id='e2e' and session_id='rotation-old'; raise exception 'baseline unexpectedly rotates';
          exception when foreign_key_violation then null; end;
        end $$;""")
        sql(database,(Path(__file__).resolve().parents[1]/'crates/store-pg/migrations/0167_session_rotation_dependents.sql').read_text())
    sql(database,"""
    update sessions set session_id='rotation-new' where tenant_id='e2e' and session_id='rotation-old';
    do $$ begin
      if not exists(select 1 from sessions where tenant_id='e2e' and session_id='rotation-new' and public_sid='stable-public-sid') then raise exception 'public session changed'; end if;
      if not exists(select 1 from session_clients where tenant_id='e2e' and session_id='rotation-new' and client_id='session-rotation') then raise exception 'logout participant lost'; end if;
      if exists(select 1 from passkey_enrolments where tenant_id='e2e') then raise exception 'pending enrolment survived rotation'; end if;
    end $$;
    delete from sessions where tenant_id='e2e';
    do $$ begin
      if exists(select 1 from session_clients where tenant_id='e2e') then raise exception 'orphan participant'; end if;
    end $$;
    """)
    print(json.dumps({'fixture':'real_postgresql_session_rotation','status':'pass','baseline_fk_failure_reproduced':not cascades,'controls':['same_public_sid','participants_follow_digest','pending_enrolment_invalidated','logout_deletion_cascades']}))
