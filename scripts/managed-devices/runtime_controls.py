#!/usr/bin/env python3
"""Real candidate FAPI/DPoP relay and fresh-request device policy controls."""
import hashlib
import json
import os
import subprocess
from pathlib import Path
import secrets
import sys
import time
import urllib.parse
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'integrations'))
sys.path.insert(0, str(HERE.parent / 'scim'))
from oidc_product_fixture import sql
from dpop_fixture import FixtureClient, b64, sign

root, database, issuer = sys.argv[1:]
root = Path(root)
if not database.startswith('ast_device_'):
    raise RuntimeError('DEVICE_RUNTIME_STAGE=ownership')
resource = 'https://api.example/managed-device'
admin_api = issuer + '/admin/api/v1'
owner = str(uuid.uuid4())
source = str(uuid.uuid4())
revision = str(uuid.uuid4())
key = ec.generate_private_key(ec.SECP256R1())
numbers = key.public_key().public_numbers()
jwk = {'kty': 'EC', 'crv': 'P-256', 'x': b64(numbers.x.to_bytes(32, 'big')),
       'y': b64(numbers.y.to_bytes(32, 'big')), 'kid': 'managed-device-fixture', 'alg': 'ES256', 'use': 'sig'}
(root / 'client.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
quote = lambda value: "'" + str(value).replace("'", "''") + "'"
checks = []
stage = 'provision controlled inputs'

class Client(FixtureClient):
    def authenticate(self):
        pass

    def mint(self, params):
        self.token = ''
        now = int(time.time())
        assertion = sign({'alg': 'ES256', 'typ': 'JWT', 'kid': self.key_id},
                         {'iss': self.client_id, 'sub': self.client_id, 'aud': issuer,
                          'iat': now, 'exp': now + 60, 'jti': secrets.token_urlsafe(24)}, self.key)
        form = {'client_id': self.client_id, 'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': assertion, **params}
        return self.request('POST', issuer + '/token', urllib.parse.urlencode(form).encode(),
                            {'Content-Type': 'application/x-www-form-urlencoded'})

def client(name, certificate=False):
    current = Client(issuer, name, root / 'client.pem', 'managed-device-fixture', root / 'backend-ca.pem')
    if certificate:
        current.context.load_cert_chain(root / 'device-cert.pem', root / 'device-key.pem')
    return current

def policy(enabled=True):
    document = {'version': 1, 'rules': [{'id': 'baseline', 'effect': 'permit'}]}
    if enabled:
        document['conditional_scopes'] = [{'id': 'managed-device-app', 'mode': 'active',
            'clients': ['device-app'], 'actions': ['authorize', 'authorization_code', 'refresh_token', 'token_exchange', 'access_evaluation'],
            'rules': [{'id': 'current-device', 'effect': 'permit', 'when': {'device_compliance': 'compliant'}}]}]
    sql(database, "insert into tenant_policies(tenant_id,document) values('e2e'," + quote(json.dumps(document)) +
        "::jsonb) on conflict(tenant_id) do update set document=excluded.document,updated_at=clock_timestamp();")

def fresh_refresh(app):
    grant = str(uuid.uuid4())
    refresh = secrets.token_urlsafe(32)
    jkt = b64(hashlib.sha256(json.dumps(app.jwk, sort_keys=True, separators=(',', ':')).encode()).digest())
    sql(database, f"""insert into grants(tenant_id,grant_id,client_id,user_id,subject,scopes,resources,authenticated_at,amr,claimed_at,expires_at)
      values('e2e',{quote(grant)},'device-app',{quote(owner)},'controlled-human',array['device.read','offline_access'],array[{quote(resource)}],
      now(),array['pwd'],now(),now()+interval '10 minutes');
      insert into refresh_tokens(tenant_id,token_hash,grant_id,client_id,scopes,dpop_jkt,absolute_expires_at)
      values('e2e',decode({quote(hashlib.sha256(refresh.encode()).hexdigest())},'hex'),{quote(grant)},'device-app',
      array['device.read'],{quote(jkt)},now()+interval '10 minutes');""")
    return {'grant_type': 'refresh_token', 'refresh_token': refresh, 'scope': 'device.read', 'resource': resource}

try:
    sql(database, f"""insert into users(tenant_id,user_id,username,status) values('e2e',{quote(owner)},'controlled-device-owner','active');
      insert into resource_servers(tenant_id,identifier,scopes) values('e2e',{quote(resource)},array['device.read']),('e2e',{quote(admin_api)},null);
      insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks) values
      ('e2e','device-relay','Controlled relay','private_key_jwt',array['client_credentials'],array[]::text[],array[]::text[],
      array['device.enrollments:write','device.posture:write'],array[{quote(admin_api)}],{quote(json.dumps({'keys': [jwk]}))}::jsonb),
      ('e2e','device-app','Controlled application','private_key_jwt',array['authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:token-exchange'],
      array['code'],array['https://localhost:9527/callback'],array['openid','offline_access','device.read'],array[{quote(resource)}],{quote(json.dumps({'keys': [jwk]}))}::jsonb);
      insert into managed_device_sources(tenant_id,source_id,client_id,revision,enabled,created_at,updated_at)
      values('e2e',{quote(source)},'device-relay',{quote(revision)},true,now(),now());""")
    relay = client('device-relay')
    app = client('device-app', True)
    absent = client('device-app')
    stage = 'real relay client credentials'
    status, _, token = relay.mint({'grant_type': 'client_credentials', 'scope': 'device.enrollments:write device.posture:write', 'resource': admin_api})
    assert status == 200 and token['token_type'] == 'DPoP'
    relay.token = token['access_token']
    assert sql(database, "select count(*) from managed_device_relay_tokens where tenant_id='e2e';").strip() == '1'
    checks.append('successful_cc_signature_creates_private_exact_relay_receipt')
    stage = 'enrollment'
    status, _, enrolled = relay.request('POST', admin_api + '/device-sources/' + source + '/enrollments',
        {'user_id': owner, 'leaf_sha256': (root / 'device-fingerprint.txt').read_text().strip(), 'allowed_client_ids': ['device-app']},
        {'Content-Type': 'application/json'})
    assert status == 201
    device = enrolled['id']
    current = json.loads(sql(database, f"select json_build_object('source',source_generation,'enrollment',enrollment_generation)::text from managed_devices where tenant_id='e2e' and device_id={quote(device)};"))
    checks.append('authenticated_relay_enrolls_exact_user_leaf_and_application')
    def posture(sequence, compliant=True, **changes):
        now = int(time.time())
        observation = {'device_id': device, 'enrollment_generation': current['enrollment'], 'sequence': sequence,
            'observed_at': now, 'expires_at': now + 240,
            'posture': {'managed': True, 'compliant': compliant, 'disk_encrypted': True, 'risk': 'low'}, **changes}
        return relay.request('POST', admin_api + '/device-sources/' + source + '/posture',
            {'profile': 'managed-device-relay/v1', 'source_generation': current['source'], 'observations': [observation]},
            {'Content-Type': 'application/json'})[0]
    stage = 'posture ingestion'
    assert posture(1) in (200, 204)
    assert posture(1) == 409
    assert posture(2, observed_at=int(time.time()) - 301) == 400
    assert posture(2, enrollment_generation=current['enrollment'] + 1) == 409
    checks.append('sequence_replay_stale_observation_and_wrong_incarnation_refused')
    stage = 'seeded human refresh baseline'
    policy(False)
    baseline = app.mint(fresh_refresh(app))
    assert baseline[0] == 200
    checks.append('seeded_human_refresh_baseline_preserves_fapi_and_dpop')
    policy()
    stage = 'current device compliant refresh'
    status, _, issued = app.mint(fresh_refresh(app))
    if status != 200:
        # Only fixed protocol error names/status, never descriptions or tokens.
        error = issued.get('error', 'none')
        stage += ':' + str(status) + ':' + (error if error in ('invalid_grant', 'invalid_request', 'invalid_client', 'server_error', 'invalid_scope') else 'other')
        # Diagnostic codes are server-owned constants. Bound and filter them;
        # no audit actor, subject, token, client-supplied strings or attributes.
        for row in sql(database, "select detail->>'reason' from audit_events where tenant_id='e2e' order by occurred_at desc limit 5;").splitlines():
            if row and all(c.islower() or c == '_' for c in row) and len(row) < 80:
                stage += ':' + row
    assert status == 200 and issued['token_type'] == 'DPoP'
    claims = json.loads(__import__('base64').urlsafe_b64decode(issued['access_token'].split('.')[1] + '==='))
    assert not any('device' in name or name in ('leaf_sha256', 'anchor_sha256') for name in claims)
    checks.append('actual_tls_device_and_current_posture_permit_fapi_refresh_without_public_device_claim')
    stage = 'no possession refresh'
    assert absent.mint(fresh_refresh(absent))[0] == 400
    checks.append('old_grant_and_previous_success_do_not_supply_new_request_possession')
    stage = 'spoofed public leaf header'
    # FixtureClient cannot install evidence: the edge strips the caller field.
    params = fresh_refresh(absent)
    old_request = absent.request
    absent.request = lambda method, url, body=None, headers=None: old_request(method, url, body,
        {**(headers or {}), 'x-controlled-device-cert': urllib.parse.quote((root / 'device-cert.pem').read_text(), safe='')})
    assert absent.mint(params)[0] == 400
    checks.append('caller_public_certificate_header_cannot_create_possession')
    stage = 'actual device-bound browser code flow'
    password_hash = '$argon2id$v=19$m=19456,t=2,p=1$YnJvd3Nlci1zd2VlcC1zYWx0$E8awnsfATh5sLXjht+SvAdX9BEFVTWfDYThAb/+KOfs'
    sql(database, f"insert into credentials(tenant_id,credential_id,user_id,kind,password_hash,label) values('e2e',{quote(str(uuid.uuid4()))},{quote(owner)},'password',{quote(password_hash)},'Disposable device fixture');")
    browser_input = {'issuer': issuer, 'resource': resource, 'client_key': str(root / 'client.pem'),
        'node_modules': os.environ.get('ASTERIUS_E2E_NODE_MODULES', str(HERE.parents[1] / 'e2e/node_modules')),
        **{name: str(root / file) for name, file in {'ca': 'backend-ca.pem', 'edge_key': 'edge-key.pem', 'edge_cert': 'edge-cert.pem',
                                                  'device_cert': 'device-cert.pem', 'device_key': 'device-key.pem'}.items()}}
    (root / 'browser.json').write_text(json.dumps(browser_input))
    browser = subprocess.run(['node', str(HERE / 'browser_controls.mjs'), str(root / 'browser.json')],
                             capture_output=True, text=True, timeout=100)
    if browser.returncode:
        stage = next((line for line in browser.stderr.splitlines() if line.startswith('DEVICE_BROWSER_STAGE=')), 'device browser bootstrap')
        raise RuntimeError('device browser failed')
    browser_evidence = json.loads(browser.stdout)
    checks.extend(browser_evidence['checks'])
    stage = 'current noncompliance'
    assert posture(2, False) in (200, 204)
    assert app.mint(fresh_refresh(app))[0] == 400
    checks.append('latest_noncompliance_overrides_previous_compliant_authority')
    stage = 'source disable'
    assert posture(3) in (200, 204)
    sql(database, f"update managed_device_sources set enabled=false,generation=nextval('managed_device_generations'),revision={quote(str(uuid.uuid4()))} where tenant_id='e2e' and source_id={quote(source)};")
    assert app.mint(fresh_refresh(app))[0] == 400
    checks.append('current_disabled_source_and_generation_fence_refuse_new_signature')
    stage = 'revoked relay receipt'
    sql(database, "update grants set revoked_at=clock_timestamp() where tenant_id='e2e' and client_id='device-relay';")
    assert posture(4) in (401, 403, 404)
    checks.append('revoked_exact_cc_grant_invalidates_relay_authority')
    print(json.dumps({'component': 'real isolated Asterius protected TLS / FAPI DPoP', 'checks': checks,
        'passed': len(checks), 'human_authentication': 'seeded_refresh_grants_not_live_login',
        'source_registration': 'seeded_local_administration_controlled_input',
        'device_attestation': 'controlled_software_pki_not_hardware_or_live_mdm',
        'original_interaction_code_transfer': 'real_browser_password_fapi_par_pkce_and_exact_code_spend', 'owned_database_only': True}))
except Exception:
    print('DEVICE_RUNTIME_STAGE=' + stage, file=sys.stderr)
    raise SystemExit(1)
