#!/usr/bin/env python3
"""Disposable source/target acceptance; no shared deployment or public exposure."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import time
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from namespace_fixture import HOSTNAME, command, namespace

ROOT = Path(__file__).resolve().parents[2]
DB_CONTAINER = os.environ['ASTERIUS_ACCEPTANCE_DB_CONTAINER']
PASSWORD_HASH = '$argon2id$v=19$m=19456,t=2,p=1$YnJvd3Nlci1zd2VlcC1zYWx0$E8awnsfATh5sLXjht+SvAdX9BEFVTWfDYThAb/+KOfs'


def quote(value):
    return "'" + value.replace("'", "''") + "'"


def sql(database, statement):
    return command(['docker', 'exec', '-i', DB_CONTAINER, 'psql', '-U', 'asterius', '-d', database,
                    '-X', '-At', '-v', 'ON_ERROR_STOP=1'], statement)


class TargetConnection(http.client.HTTPSConnection):
    def __init__(self):
        super().__init__(HOSTNAME, 9492, context=ssl.create_default_context(), timeout=2)

    def connect(self):
        self.sock = self._context.wrap_socket(socket.create_connection(('127.0.0.1', 9492), self.timeout), server_hostname=HOSTNAME)


def readiness(container, target=False):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if command(['docker', 'inspect', '--format', '{{.State.Running}}', container]) != 'true':
            raise RuntimeError('owned runtime exited before readiness; private logs withheld')
        connection = TargetConnection() if target else http.client.HTTPSConnection(
            'localhost', 9478, context=ssl._create_unverified_context(), timeout=2)
        try:
            connection.request('GET', '/readyz', headers={'Host': HOSTNAME + ':9446'} if target else {})
            response = connection.getresponse()
            response.read(65537)
            if response.status == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(0.2)
    raise RuntimeError('owned runtime readiness deadline exceeded')


def configuration(owned, database, target=False, credential=''):
    config = (ROOT / 'e2e/fixtures/asterius.toml.in').read_text()
    port = 9492 if target else 9478
    for before, after in {'@PORT@': str(port), '@CERTIFICATE@': '/fixture/cert.pem',
                          '@PRIVATE_KEY@': '/fixture/key.pem',
                          '@DATABASE_URL@': f"postgres://asterius:asterius@{owned['database_host']}:5432/{database}"}.items():
        config = config.replace(before, after)
    config = config.replace(f'bind = "127.0.0.1:{port}"', f'bind = "0.0.0.0:{port}"')
    if target:
        config = config.replace('e2e', 'target').replace(f'https://127.0.0.1:{port}', f'https://{HOSTNAME}:9446')
        config = config.replace(f'https://localhost:{port}', f'https://{HOSTNAME}:9446')
    else:
        config = config.replace(f'https://127.0.0.1:{port}', f'https://localhost:{port}')
        # Registry belongs to the first e2e tenant, not the subsequent tenant.
        marker = '\n[[tenant]]\nid = "e2e-webauthn"'
        config = config.replace(marker, '\n' + credential + marker)
    return config


def public_jwk(key):
    import base64
    numbers = key.public_key().public_numbers()
    encode = lambda value: base64.urlsafe_b64encode(value.to_bytes(32, 'big')).decode().rstrip('=')
    return {'kty': 'EC', 'crv': 'P-256', 'x': encode(numbers.x), 'y': encode(numbers.y),
            'kid': 'outbound-peer-1', 'alg': 'ES256', 'use': 'sig'}


def seed_source(database, client, secret):
    seed = (ROOT / 'e2e/fixtures/seed.sql').read_text().replace(":'tenant'", "'e2e'").replace(":'username'", "'sweep@example.test'")
    sql(database, seed.replace(":'hash'", quote(PASSWORD_HASH)))
    sql(database, f"""update tenants set settings=settings || jsonb_build_object('options',coalesce(settings->'options','{{}}'::jsonb) || '{{"allow_non_fapi_clients":true}}'::jsonb) where tenant_id='e2e';
        insert into clients(tenant_id,client_id,client_name,compliance_profile,token_endpoint_auth_method,client_secret_hash,
        grant_types,response_types,redirect_uris,scopes,resources,dpop_bound_access_tokens,tls_client_certificate_bound_access_tokens,id_token_signed_response_alg)
        values('e2e',{quote(client)},'Disposable outbound browser','oidc','client_secret_basic',decode('{hashlib.sha256(secret.encode()).hexdigest()}','hex'),
        array['authorization_code'],array['code'],array['https://localhost:9479/callback'],array['openid','email'],
        array[(select default_resource from tenants where tenant_id='e2e')],false,false,'ES256');
        insert into users(tenant_id,user_id,username,email,email_verified,status,claims)
        values('e2e','3f1d5c2a-0000-4000-8000-000000000099','owned-outbound@example.test','owned-outbound@example.test',true,'active','{{}}');""")


def main():
    databases = []
    try:
        with namespace(os.environ['ASTERIUS_BIN'], os.environ['ASTERIUS_OUTBOUND_TLS_DIRECTORY']) as owned:
            for kind in ('source', 'target'):
                database = 'ast_outbound_' + kind + '_' + uuid.uuid4().hex
                sql('postgres', 'create database "' + database + '";')
                databases.append(database)
            source_db, target_db = databases
            key = ec.generate_private_key(ec.SECP256R1())
            (owned['root'] / 'operator.der').write_bytes(key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            generation = str(uuid.uuid4())
            next_generation = str(uuid.uuid4())
            next_key = ec.generate_private_key(ec.SECP256R1())
            (owned['root'] / 'operator-next.der').write_bytes(next_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            next_jwk = public_jwk(next_key)
            next_jwk['kid'] = 'outbound-peer-2'
            credential = f'''[[tenant.outbound_scim_credential]]
reference = "owned-peer"
generation = "{generation}"
target_issuer = "{owned['target_issuer']}"
target_client = "outbound-peer"
key_file = "/fixture/operator.der"
kid = "outbound-peer-1"
algorithm = "ES256"
'''
            credential += credential.replace(generation, next_generation).replace('operator.der', 'operator-next.der').replace('outbound-peer-1', 'outbound-peer-2')
            environment = {'ASTERIUS_KEK': 'YXN0ZXJpdXMtZGV2LWtlay1ub3QtYS1zZWNyZXQhISE=',
                           'ASTERIUS_ADMIN_PASSWORD': secrets.token_urlsafe(32)}
            target = owned['start_runtime']('target', configuration(owned, target_db, target=True), environment)
            readiness(target, target=True)
            resource = owned['target_issuer'] + '/admin/api/v1'
            sql(target_db, f"""insert into resource_servers(tenant_id,identifier,scopes) values('target',{quote(resource)},null);
                insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks)
                values('target','outbound-peer','Owned outbound target','private_key_jwt',array['client_credentials'],'{{}}',
                array['admin.scim:read','admin.scim:write'],array[{quote(resource)}],{quote(json.dumps({'keys':[public_jwk(key)]}))}::jsonb);""")
            source = owned['start_runtime']('source', configuration(owned, source_db, credential=credential), environment)
            readiness(source)
            client = 'outbound-browser'
            secret = secrets.token_urlsafe(32)
            seed_source(source_db, client, secret)
            # Load the controlled browser client's tenant option at startup,
            # matching the existing real-browser fixture's cache boundary.
            command(['docker', 'restart', source])
            readiness(source)
            owned['start_relay']()
            payload = owned['root'] / 'browser.json'
            payload.write_text(json.dumps({'issuer': owned['source_issuer'], 'target_issuer': owned['target_issuer'],
                'database': source_db, 'target_database': target_db, 'db_container': DB_CONTAINER,
                'client_id': client, 'secret': secret, 'credential_generation': generation, 'next_credential_generation': next_generation, 'next_public_jwk': next_jwk,
                'tls_key': str(owned['root'] / 'key.pem'), 'tls_certificate': str(owned['root'] / 'cert.pem'),
                'fault_file': str(owned['root'] / 'fault.json'), 'relay_evidence': str(owned['root'] / 'relay.jsonl'),
                'cookie_file': str(owned['root'] / 'verified-session.json'), 'operator_key': str(owned['root'] / 'operator.der')}))
            try:
                result = command(['node', str(Path(__file__).with_name('acceptance.mjs')), str(payload)], timeout=300)
            except RuntimeError:
                if os.environ.get('ASTERIUS_OUTBOUND_DIAGNOSTIC_HOLD') == '1':
                    # Explicit controlled diagnosis only; no private values enter stdout.
                    metadata = Path('/tmp/asterius-outbound-diagnostic-owner.json')
                    metadata.write_text(json.dumps({'root': str(owned['root']), 'source_container': source,
                        'target_container': target, 'source_database': source_db, 'target_database': target_db,
                        'db_container': DB_CONTAINER, 'binary_sha256': owned['binary_sha256']}))
                    metadata.chmod(0o600)
                    print('OWNED_DIAGNOSTIC_HOLD_READY', flush=True)
                    release = owned['root'] / 'diagnostic-release'
                    deadline = time.monotonic() + 600
                    try:
                        while not release.exists() and time.monotonic() < deadline:
                            time.sleep(0.2)
                    finally:
                        metadata.unlink(missing_ok=True)
                raise
            evidence = json.loads(result)
            evidence.update({'binary_sha256': owned['binary_sha256'], 'certificate_sha256': owned['certificate_sha256'],
                             'owned_namespace_only': True, 'internet_reachability_claimed': False,
                             'public_exposure': False})
            print(json.dumps(evidence))
    finally:
        for database in reversed(databases):
            sql('postgres', 'drop database "' + database + '";')


if __name__ == '__main__':
    main()
