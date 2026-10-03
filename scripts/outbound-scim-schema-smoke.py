#!/usr/bin/env python3
"""Exercise candidate producer/cleanup SQL in an owned disposable database.

The source database is read only: only its schema is dumped. No credentials,
accounts or target attributes are copied, and the owned database is removed.
This is schema evidence, not an OAuth/SCIM interoperability acceptance run.
"""
import argparse
import pathlib
import subprocess
import uuid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--container', required=True)
parser.add_argument('--source-database', default='asterius')
parser.add_argument('--database-user', default='asterius')
args = parser.parse_args()
owned_database = 'ast_outbound_smoke_' + uuid.uuid4().hex
root = pathlib.Path(__file__).resolve().parents[1]


def command(argv, body=None):
    result = subprocess.run(argv, input=body, capture_output=True, check=False)
    if result.returncode:
        # SQL fixtures contain only generated local IDs and fixed schema names.
        # Never forward source database dumps or server response bodies.
        raise RuntimeError(result.stderr.decode('utf-8', errors='replace')[:2000])
    return result.stdout


def sql(body):
    return command(['docker', 'exec', '-i', args.container, 'psql', '-U',
                    args.database_user, '-d', owned_database, '-v',
                    'ON_ERROR_STOP=1'], body.encode())


command(['docker', 'exec', args.container, 'createdb', '-U',
         args.database_user, owned_database])
try:
    schema = command(['docker', 'exec', args.container, 'pg_dump', '-U',
                      args.database_user, '--schema-only', '--no-owner',
                      '--no-acl', args.source_database])
    sql(schema.decode())
    sql((root / 'crates/store-pg/migrations/0169_outbound_scim.sql').read_text())
    sql('''
insert into tenants (tenant_id,issuer,display_name,default_resource)
values ('outbound-smoke','https://source.example/t/outbound-smoke','Smoke','https://source.example/resource');
insert into users (tenant_id,user_id,username,email)
values ('outbound-smoke','00000000-0000-0000-0000-000000000001','local','local@example.test');
insert into clients (tenant_id,client_id,client_name,token_endpoint_auth_method,jwks_uri)
values ('outbound-smoke','upstream','Fixture','private_key_jwt','https://upstream.example/jwks');
insert into managed_groups (tenant_id,group_id,name,display_name,created_at,updated_at)
values ('outbound-smoke','00000000-0000-0000-0000-000000000002','local-group','Local group',now(),now());
insert into outbound_scim_connectors (tenant_id,connector_id,target_issuer,target_client,credential_ref,credential_generation)
values ('outbound-smoke','00000000-0000-0000-0000-000000000010','https://target.example/t/target','provisioner','key','00000000-0000-0000-0000-000000000011');
insert into outbound_scim_assignments (tenant_id,connector_id,assignment_id,kind,source_id,immutable_alias,external_id)
values ('outbound-smoke','00000000-0000-0000-0000-000000000010','00000000-0000-0000-0000-000000000020','user','00000000-0000-0000-0000-000000000001','owned-user','urn:smoke:user'),
('outbound-smoke','00000000-0000-0000-0000-000000000010','00000000-0000-0000-0000-000000000021','group','00000000-0000-0000-0000-000000000002','owned-group','urn:smoke:group');
insert into group_memberships (tenant_id,group_id,user_id,created_at)
values ('outbound-smoke','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000001',now());
update users set status='disabled' where tenant_id='outbound-smoke';
insert into scim_user_external_ids (tenant_id,client_id,user_id)
values ('outbound-smoke','upstream','00000000-0000-0000-0000-000000000001');
insert into scim_group_owners (tenant_id,client_id,group_id)
values ('outbound-smoke','upstream','00000000-0000-0000-0000-000000000002');
do $$ declare constraint_name text;
begin
  if (select count(*) from outbox where tenant_id='outbound-smoke') <> 2 then
    raise exception 'source mutations must coalesce into one job per assignment';
  end if;
  if exists (select 1 from outbox where tenant_id='outbound-smoke' and
    (payload ? 'email' or payload ? 'active' or payload ? 'credential')) then
    raise exception 'outbox must contain only assignment locators';
  end if;
  begin
    delete from tenants where tenant_id='outbound-smoke';
    raise exception 'live assignment tenant deletion unexpectedly succeeded';
  exception when check_violation then
    get stacked diagnostics constraint_name = CONSTRAINT_NAME;
    if constraint_name <> 'outbound_scim_tenant_live_assignments' then raise; end if;
  end;
end $$;
delete from users where tenant_id='outbound-smoke';
delete from managed_groups where tenant_id='outbound-smoke';
do $$ begin
  if (select count(*) from outbound_scim_assignments where tenant_id='outbound-smoke') <> 2 then
    raise exception 'source deletion must retain mapping authority';
  end if;
  if (select count(*) from outbox where tenant_id='outbound-smoke') <> 2 then
    raise exception 'source deletion must preserve coalesced deprovision jobs';
  end if;
end $$;
-- Durable uncertainty cannot be erased to authorize absence-based retirement.
update outbound_scim_assignments set creation_admitted=true
where tenant_id='outbound-smoke' and kind='user';
do $$ declare constraint_name text;
begin
  begin
    update outbound_scim_assignments set creation_admitted=false
      where tenant_id='outbound-smoke' and kind='user';
    raise exception 'creation evidence unexpectedly cleared';
  exception when check_violation then
    get stacked diagnostics constraint_name = CONSTRAINT_NAME;
    if constraint_name <> 'outbound_scim_creation_pin' then raise; end if;
  end;
end $$;
-- An unselected incarnation still consumes a bounded current slot until archive.
update outbound_scim_assignments set selected=false
where tenant_id='outbound-smoke' and kind='user';
do $$ declare source uuid; constraint_name text;
begin
  for i in 1..99 loop
    source := gen_random_uuid();
    insert into users (tenant_id,user_id,username)
      values ('outbound-smoke',source,'bounded-' || source::text);
    insert into outbound_scim_assignments
      (tenant_id,connector_id,kind,source_id,immutable_alias,external_id)
      values ('outbound-smoke','00000000-0000-0000-0000-000000000010',
        'user',source,'owned-' || source::text,'urn:smoke:' || source::text);
  end loop;
  source := gen_random_uuid();
  insert into users (tenant_id,user_id,username)
    values ('outbound-smoke',source,'overflow-' || source::text);
  begin
    insert into outbound_scim_assignments
      (tenant_id,connector_id,kind,source_id,immutable_alias,external_id)
      values ('outbound-smoke','00000000-0000-0000-0000-000000000010',
        'user',source,'overflow-' || source::text,'urn:smoke:' || source::text);
    raise exception 'quiescing incarnation failed to consume its current slot';
  exception when check_violation then
    get stacked diagnostics constraint_name = CONSTRAINT_NAME;
    if constraint_name <> 'outbound_scim_current_bound' then raise; end if;
  end;
end $$;
-- Direct retirement is only a fixture for the cleanup guard, not an API command
-- or evidence of remote deprovisioning. The full acceptance must verify a peer.
update outbound_scim_assignments set selected=false,retired_at=clock_timestamp()
where tenant_id='outbound-smoke';
delete from tenants where tenant_id='outbound-smoke';
do $$ begin
  if exists (select 1 from outbound_scim_connectors where tenant_id='outbound-smoke') then
    raise exception 'quiesced tenant cleanup did not cascade';
  end if;
end $$;
''')
    print('PASS: migration, source/ownership producers, locator coalescing, retained authority, current catalogue bound, tenant guard and quiesced cleanup')
finally:
    command(['docker', 'exec', args.container, 'dropdb', '-U',
             args.database_user, owned_database])
    print('Owned disposable database removed')
