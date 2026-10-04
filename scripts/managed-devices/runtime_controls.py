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
import urllib.request
import urllib.error
import ssl
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
pdp = issuer + '/access/v1/evaluation'
owner = str(uuid.uuid4())
foreign_user = str(uuid.uuid4())
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
      values('e2e',{quote(grant)},'device-app',{quote(owner)},'controlled-human',array['device.read','authzen.evaluate','offline_access'],array[{quote(resource)},{quote(pdp)}],
      now(),array['pwd'],now(),now()+interval '10 minutes');
      insert into refresh_tokens(tenant_id,token_hash,grant_id,client_id,scopes,dpop_jkt,absolute_expires_at)
      values('e2e',decode({quote(hashlib.sha256(refresh.encode()).hexdigest())},'hex'),{quote(grant)},'device-app',
      array['device.read','authzen.evaluate'],{quote(jkt)},now()+interval '10 minutes');""")
    return {'grant_type': 'refresh_token', 'refresh_token': refresh, 'scope': 'device.read', 'resource': resource}

try:
    sql(database, f"""insert into users(tenant_id,user_id,username,status) values('e2e',{quote(owner)},'controlled-device-owner','active');
      insert into user_roles(tenant_id,user_id,role,tenant_is_reserved) select 'e2e',{quote(owner)},'tenant_admin',is_reserved from tenants where tenant_id='e2e';
      insert into resource_servers(tenant_id,identifier,scopes) values('e2e',{quote(resource)},array['device.read']),('e2e',{quote(admin_api)},null),('e2e',{quote(pdp)},null);
      insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks) values
      ('e2e','device-relay','Controlled relay','private_key_jwt',array['client_credentials'],array[]::text[],array[]::text[],
      array['device.enrollments:write','device.posture:write'],array[{quote(admin_api)}],{quote(json.dumps({'keys': [jwk]}))}::jsonb),
      ('e2e','device-app','Controlled application','private_key_jwt',array['authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:token-exchange'],
      array['code'],array['https://localhost:9527/callback'],array['openid','offline_access','device.read','authzen.evaluate'],array[{quote(resource)},{quote(pdp)}],{quote(json.dumps({'keys': [jwk]}))}::jsonb);
      insert into managed_device_sources(tenant_id,source_id,client_id,revision,enabled,created_at,updated_at)
      values('e2e',{quote(source)},'device-relay',{quote(revision)},true,now(),now());""")
    sql(database, "insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks) select tenant_id,'device-relay-secondary','Controlled administration relay',token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks from clients where tenant_id='e2e' and client_id='device-relay';")
    foreign_source = str(uuid.uuid4())
    foreign_account = str(uuid.uuid4())
    sql(database, f"""insert into users(tenant_id,user_id,username,status) values('e2e-webauthn',{quote(foreign_account)},'controlled-other-tenant','active');
      insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks)
      select 'e2e-webauthn',client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks from clients where tenant_id='e2e' and client_id='device-relay';
      insert into managed_device_sources(tenant_id,source_id,client_id,revision,enabled,created_at,updated_at)
      values('e2e-webauthn',{quote(foreign_source)},'device-relay',{quote(str(uuid.uuid4()))},true,now(),now());""")
    relay = client('device-relay')
    app = client('device-app', True)
    absent = client('device-app')
    stage = 'real relay client credentials'
    status, _, token = relay.mint({'grant_type': 'client_credentials', 'scope': 'device.enrollments:write device.posture:write', 'resource': admin_api})
    assert status == 200 and token['token_type'] == 'DPoP'
    relay.token = token['access_token']
    assert sql(database, "select count(*) from managed_device_relay_tokens where tenant_id='e2e';").strip() == '1'
    checks.append('successful_cc_signature_creates_private_exact_relay_receipt')
    assert relay.request('POST', admin_api + '/device-sources', {'client_id': 'device-relay-secondary'}, {'Content-Type': 'application/json'})[0] == 403
    checks.append('relay_issuance_does_not_grant_human_source_administration')
    stage = 'enrollment'
    status, _, enrolled = relay.request('POST', admin_api + '/device-sources/' + source + '/enrollments',
        {'user_id': owner, 'leaf_sha256': (root / 'device-fingerprint.txt').read_text().strip(), 'allowed_client_ids': ['device-app']},
        {'Content-Type': 'application/json'})
    assert status == 201
    device = enrolled['id']
    current = json.loads(sql(database, f"select json_build_object('source',source_generation,'enrollment',enrollment_generation)::text from managed_devices where tenant_id='e2e' and device_id={quote(device)};"))
    checks.append('authenticated_relay_enrolls_exact_user_leaf_and_application')
    stage = 'cross tenant source and user enrollment'
    enrollment_input = {'user_id': owner, 'leaf_sha256': (root / 'device-fingerprint.txt').read_text().strip(), 'allowed_client_ids': ['device-app']}
    assert relay.request('POST', admin_api + '/device-sources/' + foreign_source + '/enrollments', enrollment_input, {'Content-Type': 'application/json'})[0] == 404
    assert relay.request('POST', admin_api + '/device-sources/' + source + '/enrollments', {**enrollment_input, 'user_id': foreign_account}, {'Content-Type': 'application/json'})[0] == 404
    checks.append('routed_tenant_source_and_local_user_identity_bounds_refuse_foreign_records')
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
    stage = 'whole batch atomic refusal'
    now = int(time.time())
    observation = {'device_id': device, 'enrollment_generation': current['enrollment'], 'sequence': 2,
        'observed_at': now, 'expires_at': now + 240, 'posture': {'managed': True, 'compliant': True}}
    assert relay.request('POST', admin_api + '/device-sources/' + source + '/posture',
        {'profile': 'managed-device-relay/v1', 'source_generation': current['source'],
         'observations': [observation, {**observation, 'device_id': str(uuid.uuid4())}]}, {'Content-Type': 'application/json'})[0] == 404
    assert sql(database, f"select sequence from managed_devices where tenant_id='e2e' and device_id={quote(device)};").strip() == '1'
    stage = 'posture audit atomic rollback'
    sql(database, "create function controlled_device_audit_refusal() returns trigger language plpgsql as $$begin raise exception 'controlled refusal';end$$;create trigger controlled_device_audit_refusal before insert on audit_events for each row when (new.event_type='device.posture_updated') execute function controlled_device_audit_refusal();")
    try:
        assert posture(2) == 503
    finally:
        sql(database, 'drop trigger controlled_device_audit_refusal on audit_events;drop function controlled_device_audit_refusal();')
    assert sql(database, f"select sequence from managed_devices where tenant_id='e2e' and device_id={quote(device)};").strip() == '1'
    checks.append('invalid_whole_batch_and_failed_audit_do_not_advance_posture')
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
    parent_token = issued['access_token']
    parent_grant = claims['grant_id']
    stage = 'fresh request exact-parent token exchange'
    exchange = {'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token', 'subject_token': parent_token,
        'scope': 'device.read', 'resource': resource}
    exchanged = app.mint(exchange)
    assert exchanged[0] == 200
    child = json.loads(__import__('base64').urlsafe_b64decode(exchanged[2]['access_token'].split('.')[1] + '==='))
    assert child['grant_id'] != parent_grant
    assert sql(database, f"select parent_grant_id from grants where tenant_id='e2e' and grant_id={quote(child['grant_id'])};").strip() == parent_grant
    checks.append('fresh_tls_exact_parent_preflight_and_persisted_child_final_exchange')
    exchange_without_certificate = client('device-app')
    exchange_without_certificate.dpop = app.dpop
    exchange_without_certificate.jwk = app.jwk
    assert exchange_without_certificate.mint(exchange)[0] == 400
    checks.append('parent_device_success_does_not_bootstrap_child_request_possession')
    stage = 'exact verified PDP request device context'
    status, _, online = app.mint({**fresh_refresh(app), 'scope': 'authzen.evaluate', 'resource': pdp})
    assert status == 200
    app.token = online['access_token']
    question = {'subject': {'type': 'user', 'id': 'controlled-human'}, 'action': {'name': 'read'},
        'resource': {'type': 'application', 'id': 'device-app'}}
    status, _, decision = app.request('POST', pdp, question, {'Content-Type': 'application/json'})
    assert status == 200 and decision['decision']
    online_without_certificate = client('device-app')
    online_without_certificate.dpop = app.dpop
    online_without_certificate.jwk = app.jwk
    online_without_certificate.token = app.token
    status, _, denied = online_without_certificate.request('POST', pdp, question, {'Content-Type': 'application/json'})
    assert status == 200 and not denied['decision']
    checks.append('pdp_exact_verified_grant_requires_its_own_current_tls_possession')
    stage = 'exact exchange parent revocation'
    sql(database, f"update grants set revoked_at=clock_timestamp(),revocation_reason='user_revoked' where tenant_id='e2e' and grant_id={quote(parent_grant)};")
    assert app.mint(exchange)[0] == 400
    checks.append('revoked_exact_exchange_parent_refused_without_other_grant_fallback')
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
        'cookie_file': str(root / 'browser-cookies.json'),
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
    stage = 'unknown posture and stale current observation'
    assert posture(3, None) in (200, 204)
    assert app.mint(fresh_refresh(app))[0] == 400
    assert posture(4) in (200, 204)
    # Controlled DB time perturbation represents a producer outage. It does
    # not pretend to measure a real 300-second wait or create trusted facts.
    sql(database, f"update managed_devices set observed_at=clock_timestamp()-interval '301 seconds' where tenant_id='e2e' and device_id={quote(device)};")
    assert app.mint(fresh_refresh(app))[0] == 400
    checks.append('unknown_management_compliance_and_current_stale_observation_deny')
    stage = 'owner scoped removal'
    assert posture(5) in (200, 204)
    cookies = json.loads((root / 'browser-cookies.json').read_text())
    cookie = '; '.join(item['name'] + '=' + item['value'] for item in cookies if item['domain'] == 'localhost')
    def owner_request(method, body=None):
        request = urllib.request.Request(issuer + '/account/devices',
            None if body is None else json.dumps(body).encode(),
            {'Cookie': cookie, 'Content-Type': 'application/json'}, method=method)
        try:
            response = urllib.request.urlopen(request, context=ssl.create_default_context(cafile=str(root / 'backend-ca.pem')), timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        raw = response.read(65537)
        assert len(raw) <= 65536
        return response.status, json.loads(raw) if raw else {}
    status, own = owner_request('GET')
    stage = 'owner list:' + str(status)
    assert status == 200 and len(own['devices']) == 1
    assert not any(field in json.dumps(own) for field in ('leaf_sha256', 'anchor_sha256', 'private_key'))
    selected = own['devices'][0]
    assert selected['id'] == device
    stage = 'owner invalid csrf'
    assert owner_request('POST', {'id': device, 'expected_revision': selected['revision'], 'csrf': 'invalid'})[0] == 403
    sql(database, f"insert into users(tenant_id,user_id,username,status) values('e2e',{quote(foreign_user)},'controlled-foreign-owner','active');")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    foreign_leaf = x509.load_pem_x509_certificate((root / 'unrelated-device-cert.pem').read_bytes()).fingerprint(hashes.SHA256()).hex()
    status, _, foreign = relay.request('POST', admin_api + '/device-sources/' + source + '/enrollments',
        {'user_id': foreign_user, 'leaf_sha256': foreign_leaf, 'allowed_client_ids': ['device-app']}, {'Content-Type': 'application/json'})
    stage = 'foreign controlled enrollment:' + str(status)
    assert status == 201
    foreign_revision = sql(database, f"select revision from managed_devices where tenant_id='e2e' and device_id={quote(foreign['id'])};").strip()
    stage = 'foreign owner removal refusal'
    assert owner_request('POST', {'id': foreign['id'], 'expected_revision': foreign_revision, 'csrf': own['csrf']})[0] == 404
    assert owner_request('GET')[1]['devices'][0]['id'] == device
    checks.append('owner_list_private_csrf_and_foreign_owner_removal_refused')
    started = time.monotonic()
    stage = 'actual own removal'
    removed = owner_request('POST', {'id': device, 'expected_revision': selected['revision'], 'csrf': own['csrf']})[0]
    stage += ':' + str(removed)
    assert removed == 204
    stage = 'access after actual owner removal'
    assert app.mint(fresh_refresh(app))[0] == 400
    removal_seconds = time.monotonic() - started
    assert removal_seconds < 5
    stage = 'minimal erased removal tombstone'
    assert sql(database, f"select (removed_at is not null and user_id is null and leaf_sha256 is null and allowed_client_ids is null and compliant is null)::text from managed_devices where tenant_id='e2e' and device_id={quote(device)};").strip() == 'true'
    stage = 'posture cannot recreate removed enrollment'
    assert posture(6) == 404
    checks.append('owner_removal_erases_private_state_and_refuses_new_access_within_five_seconds')
    stage = 're-enrollment incarnation'
    old_device = device
    status, _, renewed = relay.request('POST', admin_api + '/device-sources/' + source + '/enrollments',
        {'user_id': owner, 'leaf_sha256': (root / 'device-fingerprint.txt').read_text().strip(), 'allowed_client_ids': ['device-app']}, {'Content-Type': 'application/json'})
    assert status == 201 and renewed['id'] != old_device
    device = renewed['id']
    current = json.loads(sql(database, f"select json_build_object('source',source_generation,'enrollment',enrollment_generation)::text from managed_devices where tenant_id='e2e' and device_id={quote(device)};"))
    assert posture(1) in (200, 204)
    assert app.mint(fresh_refresh(app))[0] == 200
    checks.append('explicit_reenrollment_gets_fresh_server_uuid_and_generation')
    stage = 'source writer versus next signature'
    params = fresh_refresh(app)
    writer_statements = ['begin', "select tenant_id from tenants where tenant_id='e2e' for update",
        f"update managed_device_sources set enabled=false,generation=nextval('managed_device_generations'),revision={quote(str(uuid.uuid4()))} where tenant_id='e2e' and source_id={quote(source)}",
        "select 'CONTROLLED_DEVICE_FENCE_READY'", 'select pg_sleep(1)', 'commit']
    writer = subprocess.Popen(['docker', 'exec', '-i', os.environ['ASTERIUS_ACCEPTANCE_DB_CONTAINER'], 'psql', '-U', 'asterius', '-d', database, '-X', '-At', '-v', 'ON_ERROR_STOP=1',
        *[part for statement in writer_statements for part in ('-c', statement)]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        while True:
            line = writer.stdout.readline()
            assert line
            if line.strip() == 'CONTROLLED_DEVICE_FENCE_READY':
                break
        waited = time.monotonic()
        refused = app.mint(params)[0]
        duration = time.monotonic() - waited
        stage += ':status' + str(refused) + ':wait' + str(round(duration, 2))
        assert refused == 400
        assert duration >= 0.8
    finally:
        writer.communicate(timeout=10)
    assert writer.returncode == 0
    checks.append('source_writer_publication_fence_wait_then_committed_disable_refuses_signature')
    stage = 'revoked relay receipt'
    sql(database, "update grants set revoked_at=clock_timestamp() where tenant_id='e2e' and client_id='device-relay';")
    assert posture(4) in (401, 403, 404)
    checks.append('revoked_exact_cc_grant_invalidates_relay_authority')
    print(json.dumps({'component': 'real isolated Asterius protected TLS / FAPI DPoP', 'checks': checks,
        'passed': len(checks), 'human_authentication': 'seeded_refresh_grants_not_live_login',
        'source_registration': 'seeded_local_administration_controlled_input',
        'device_attestation': 'controlled_software_pki_not_hardware_or_live_mdm',
        'stale_time_test': 'controlled_database_timestamp_perturbation_not_real_300_second_wait',
        'original_interaction_code_transfer': 'real_browser_password_fapi_par_pkce_and_exact_code_spend',
        'removal_to_refusal_seconds': round(removal_seconds, 3), 'owned_database_only': True}))
except Exception:
    print('DEVICE_RUNTIME_STAGE=' + stage, file=sys.stderr)
    raise SystemExit(1)
