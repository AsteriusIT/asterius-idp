#!/usr/bin/env python3
"""Controlled PostgreSQL provenance lifecycle; no historical proof backfill."""
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'integrations'))
from oidc_product_fixture import fixture, sql
with fixture(9459, 'https://localhost:9457/callback', 'assurance-sql') as owned:
    database=owned['database']
    if sql(database,"select to_regclass('session_assurance_proofs') is null;").strip()=='t':
        sql(database,(Path(__file__).resolve().parents[2]/'crates/store-pg/migrations/0166_assurance_provenance.sql').read_text())
    sql(database,"""
    insert into sessions(tenant_id,session_id,public_sid,user_id,authenticated_at,expires_at,idle_expires_at,acr,amr)
    select 'e2e','proof-before','controlled-proof',user_id,date_trunc('second',now()-interval '10 minutes'),now()+interval '1 hour',now()+interval '1 hour','phr',array['pop','user'] from users where tenant_id='e2e' and username='sweep@example.test';
    insert into session_assurance_proofs select tenant_id,session_id,acr,authenticated_at,repeat('a',64),amr from sessions where tenant_id='e2e' and session_id='proof-before';
    update sessions set session_id='proof-after',authenticated_at=date_trunc('second',now()),amr=array['pop','user','pwd'] where tenant_id='e2e' and session_id='proof-before';
    insert into grants(tenant_id,grant_id,client_id,user_id,subject,session_id,authenticated_at,acr,amr)
    select 'e2e','00000000-0000-4000-8000-000000000011','assurance-sql',user_id,'controlled','proof-after',authenticated_at,acr,amr from sessions where tenant_id='e2e' and session_id='proof-after';
    do $$ begin
      if (select count(*) from session_assurance_proofs where tenant_id='e2e' and session_id='proof-after') <> 1 then raise exception 'rotation cascade absent'; end if;
      if not exists(select 1 from grant_assurance_proofs where tenant_id='e2e' and assurance_authenticated_at < authenticated_at-interval '9 minutes') then raise exception 'grant proof clock was renewed'; end if;
    end $$;
    update grants set claimed_at=now() where tenant_id='e2e';
    delete from sessions where tenant_id='e2e';
    do $$ begin
      if (select count(*) from session_assurance_proofs where tenant_id='e2e')<>0 then raise exception 'orphan session proof'; end if;
      if (select count(*) from grant_assurance_proofs where tenant_id='e2e')<>1 then raise exception 'grant proof lost at session cleanup'; end if;
    end $$;
    insert into grants(tenant_id,grant_id,client_id,user_id,subject,parent_grant_id,authenticated_at,acr,amr)
    select tenant_id,'00000000-0000-4000-8000-000000000012',client_id,user_id,subject,grant_id,authenticated_at,acr,amr from grants where tenant_id='e2e' and grant_id='00000000-0000-4000-8000-000000000011';
    do $$ begin
      if (select count(*) from grant_assurance_proofs where tenant_id='e2e')<>2 then raise exception 'exact descendant proof not preserved'; end if;
    end $$;
    update grants set authenticated_at=authenticated_at+interval '1 second' where tenant_id='e2e' and grant_id='00000000-0000-4000-8000-000000000012';
    do $$ begin
      if (select count(*) from grant_assurance_proofs where tenant_id='e2e')<>1 then raise exception 'changed tuple acquired proof'; end if;
    end $$;
    delete from grants where tenant_id='e2e';
    do $$ begin
      if (select count(*) from grant_assurance_proofs where tenant_id='e2e')<>0 then raise exception 'orphan grant proof'; end if;
    end $$;
    """)
    print('ASSURANCE_SCHEMA_CONTROLS=pass rotation_cascade original_clock unchanged_claim session_cleanup exact_descendant changed_tuple grant_cleanup')
