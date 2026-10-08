#!/usr/bin/env python3
"""Real guarded Asterius handoff to an already running owned SSFgo fixture."""
import argparse
import base64
import hashlib
import os
import tempfile
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/scim'))
from dpop_fixture import FixtureClient, sign  # noqa: E402


class Admin(FixtureClient):
    def authenticate(self):
        now = int(time.time())
        assertion = sign({'alg': 'ES256', 'typ': 'JWT', 'kid': self.key_id},
                         {'iss': self.client_id, 'sub': self.client_id, 'aud': self.issuer,
                          'iat': now, 'exp': now + 60, 'jti': secrets.token_urlsafe(24)}, self.key)
        body = urllib.parse.urlencode({'client_id': self.client_id, 'grant_type': 'client_credentials',
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': assertion, 'scope': 'admin.ssf:read admin.ssf:write',
            'resource': self.issuer + '/admin/api/v1'}).encode()
        status, _, result = self.request('POST', self.issuer + '/token', body,
                                       {'Content-Type': 'application/x-www-form-urlencoded'})
        if status != 200 or result.get('token_type', '').lower() != 'dpop':
            raise RuntimeError('Controlled admin DPoP authentication refused')
        self.token = result['access_token']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', required=True)
    p.add_argument('--automation', required=True)
    p.add_argument('--database-container', required=True)
    p.add_argument('--peer-issuer', required=True)
    p.add_argument('--bearer-file', required=True)
    p.add_argument('--ack-loss-directory', required=True, help='Owned relay config directory; private one-shot ACK fault only')
    args = p.parse_args()
    os.umask(0o077)
    manifest, config = [json.loads(Path(x).read_text()) for x in (args.manifest, args.automation)]
    if manifest['issuer'] != 'https://localhost:18444/t/e2e' or manifest['database'] != config['database'] or not re.fullmatch(r'ast_product_[a-f0-9]{32}', config['database']):
        raise RuntimeError('Exact owned product fixture required')
    if not args.peer_issuer.startswith('https://') or not re.fullmatch(r'asterius-[a-zA-Z0-9_.-]+', args.database_container):
        raise RuntimeError('Explicit owned peer and container required')
    bearer_path = Path(args.bearer_file)
    if bearer_path.stat().st_mode & 0o077:
        raise RuntimeError('Private bearer file required')
    bearer = bearer_path.read_text().strip()
    admin = Admin(config['issuer'], config['clientId'], config['keyFile'], config['keyId'], config['caFile'])
    records = []
    ack_directory = Path(args.ack_loss_directory)
    if not ack_directory.is_dir() or ack_directory.stat().st_mode & 0o077:
        raise RuntimeError('Private owned ACK fixture directory required')
    ack_flag = ack_directory / 'ssf-drop-next-ack.flag'
    if ack_flag.exists():
        raise RuntimeError('Existing ACK arm file must be reconciled first')
    peer = args.peer_issuer
    quote = lambda value: "'" + value.replace("'", "''") + "'"

    def sql(statement):
        result = subprocess.run(['docker', 'exec', '-i', args.database_container, 'psql', '-U', 'asterius',
                                 '-d', config['database'], '-v', 'ON_ERROR_STOP=1', '-At'],
                                input=statement, text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError('Owned fixture SQL control refused')
        return result.stdout.strip()

    def native(method, url, body=None, authorized=True, control=False):
        parsed = urllib.parse.urlsplit(url)
        target = ('http://127.0.0.1:9486' if control else 'http://127.0.0.1:9485') + parsed.path + ('?' + parsed.query if parsed.query else '')
        headers = {'Content-Type': 'application/json'}
        if authorized:
            headers['Authorization'] = 'Bearer ' + bearer
        req = urllib.request.Request(target, None if body is None else json.dumps(body).encode(), headers, method=method)
        try:
            response = urllib.request.urlopen(req, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        data = response.read(65537)
        if len(data) > 65536:
            raise RuntimeError('Peer response bound exceeded')
        return response.status, json.loads(data) if data else None

    def push(compact):
        request = urllib.request.Request(config['issuer'] + '/ssf/receiver', compact.encode(),
                                         {'Content-Type': 'application/secevent+jwt'}, method='POST')
        try:
            response = urllib.request.urlopen(request, context=admin.context, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        response.read(65536)
        return response.status

    def operation(label, path, status=200, method='POST', body=None):
        code, _, result = admin.request(method, config['issuer'] + '/admin/api/v1' + path,
            {'peer_client_id': peer} if body is None else body,
            {'Content-Type': 'application/json', 'Idempotency-Key': str(uuid.uuid4())})
        if code != status:
            raise RuntimeError(label + ': expected HTTP ' + str(status) + ', got ' + str(code))
        records.append({'case': label, 'status': code})
        return result

    metadata_url = peer.split('/ssf-peer')[0] + '/.well-known/ssf-configuration/ssf-peer'
    code, metadata = native('GET', metadata_url, authorized=False)
    assert code == 200 and metadata['issuer'] == peer and metadata['default_subjects'] == 'ALL'
    assert metadata['delivery_methods_supported'] == ['urn:ietf:rfc:8936']
    assert native('GET', metadata['configuration_endpoint'], authorized=False)[0] == 401
    assert sql("select count(*) from clients where tenant_id='e2e' and client_id=" + quote(peer)) == '0', 'Peer already exists; preserve previous work'
    user, session, source_subject = str(uuid.uuid4()), str(uuid.uuid4()), 'owned-ssf-' + secrets.token_hex(16)
    sql("begin; insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,jwks_uri,dpop_bound_access_tokens) values('e2e'," + quote(peer) + ",'Owned independent SSF fixture','private_key_jwt',array['client_credentials'],'{}',array['ssf.receive']," + quote(metadata['jwks_uri']) + ",true); insert into users(tenant_id,user_id,username) values('e2e'," + quote(user) + "," + quote(source_subject) + "); insert into sessions(tenant_id,session_id,public_sid,user_id,authenticated_at,expires_at,idle_expires_at) values('e2e'," + quote(session) + ',' + quote(session) + ',' + quote(user) + ",now(),now()+interval '1 hour',now()+interval '1 hour'); commit;")
    recovery = Path(tempfile.mkdtemp(prefix='asterius-ssf-lifecycle-')) / 'recovery.json'
    recovery.write_text(json.dumps({'database': config['database'], 'peer': peer, 'user': user, 'session': session}))
    baseline = native('GET', metadata['configuration_endpoint'])[1]
    baseline_ids = {x['stream_id'] for x in baseline}
    other = None
    established = False
    try:
        operation('unconfigured issuer cannot invoke upstream management', '/ssf/upstream/setup', 404, body={'peer_client_id': peer + '/unconfigured'})
        operation('guarded network stream setup', '/ssf/upstream/setup')
        established = True
        operation('authenticated exact-stream readback', '/ssf/upstream/verify')
        tenant_config = tomllib.loads(Path(manifest['config_path']).read_text())
        configured = next(t for t in tenant_config['tenant'] if t['id'] == 'e2e')
        mounted_copy = Path(next(x for x in configured['ssf_upstream_peer'] if x['issuer'] == peer)['bearer_token_file'])
        if mounted_copy.parent != Path(manifest['config_path']).parent or mounted_copy.name != 'ssf-peer-bearer.txt' or mounted_copy == bearer_path:
            raise RuntimeError('Only the explicitly owned mounted SSF credential copy may be changed')
        original_copy = mounted_copy.read_bytes()
        assert original_copy.strip().decode() == bearer
        def replace_copy(value):
            fd, temporary = tempfile.mkstemp(prefix='ssf-credential-probe-', dir=mounted_copy.parent)
            with os.fdopen(fd, 'wb') as output:
                output.write(value)
            os.replace(temporary, mounted_copy)
        streams_before = {x['stream_id'] for x in native('GET', metadata['configuration_endpoint'])[1]}
        try:
            replace_copy(secrets.token_urlsafe(48).encode())
            operation('authoritative mounted bearer reread refuses rotated wrong credential', '/ssf/upstream/verify', 503)
        finally:
            replace_copy(original_copy)
        operation('restored operator bearer recovers authenticated stream verification', '/ssf/upstream/verify')
        assert {x['stream_id'] for x in native('GET', metadata['configuration_endpoint'])[1]} == streams_before

        stream_id = sql("select stream_id from ssf_receiver_upstream_streams where tenant_id='e2e' and peer_client_id=" + quote(peer))
        recovery.write_text(json.dumps({'database': config['database'], 'peer': peer, 'user': user, 'session': session, 'stream': stream_id}))
        code, listed = native('GET', metadata['configuration_endpoint'])
        owned = next(x for x in listed if x['stream_id'] == stream_id)
        operation('signed asynchronous verification requested', '/ssf/upstream/request-verification', 202)
        operation('signed verification delivered through guarded poll', '/ssf/upstream/poll')
        assert sql("select count(*) from ssf_receiver_upstream_streams where tenant_id='e2e' and peer_client_id=" + quote(peer) + ' and last_challenge_verified_at is not null and verification_state_hash is null') == '1'
        operation('explicit mapped subject', '/ssf/receiver/subjects', method='PUT', body={'peer_client_id': peer, 'subject': {'format': 'iss_sub', 'iss': peer, 'sub': source_subject}, 'user_id': user})
        code, other = native('POST', metadata['configuration_endpoint'], {'events_requested': owned['events_requested'], 'delivery': {'method': 'urn:ietf:rfc:8936'}})
        assert code == 201
        assert native('POST', 'http://127.0.0.1:9486/emit-session-revoked', {'subject': source_subject}, control=True)[0] == 204
        code, envelope = native('POST', owned['delivery']['endpoint_url'], {'maxEvents': 1, 'returnImmediately': True})
        assert code == 200 and len(envelope['sets']) == 1
        jti, compact = next(iter(envelope['sets'].items()))
        code = push(compact)
        assert code == 400, 'Poll-only peer push refusal status=' + str(code)
        assert sql("select count(*) from sessions where tenant_id='e2e' and session_id=" + quote(session) + ' and revoked_at is null') == '1'
        records.append({'case': 'valid native SET push refused for poll-only metadata profile', 'status': code})
        ack_flag.write_text(json.dumps({'authorization_sha256': hashlib.sha256(('Bearer ' + bearer).encode()).hexdigest()}))
        ack_flag.chmod(0o600)
        operation('owned injected ACK loss after local session revocation commit', '/ssf/upstream/poll', 503)
        fault = json.loads((ack_directory / 'ssf-ack-loss-status.json').read_text())
        assert fault == {'injected': True, 'status': 503, 'forwarded': False} and not ack_flag.exists()
        assert sql("select count(*) from sessions where tenant_id='e2e' and session_id=" + quote(session) + ' and revoked_at is not null') == '1'
        retained = native('POST', owned['delivery']['endpoint_url'], {'maxEvents': 1, 'returnImmediately': True})
        assert retained[0] == 200 and list(retained[1]['sets']) == [jti]
        operation('same independently signed SET redelivered through poll and ACKed', '/ssf/upstream/poll')
        assert sql("select count(*) from sessions where tenant_id='e2e' and session_id=" + quote(session) + ' and revoked_at is not null') == '1'
        assert native('POST', owned['delivery']['endpoint_url'], {'maxEvents': 1, 'returnImmediately': True})[1]['sets'] == {}
        count_sql = "select count(*) from ssf_receiver_events where tenant_id='e2e' and peer_client_id=" + quote(peer) + ' and jti=' + quote(jti)
        assert sql(count_sql) == '1'
        code = push(compact)
        assert code == 400 and sql(count_sql) == '1', 'Native replay push refusal status=' + str(code)
        records.append({'case': 'duplicate native SET push retains poll-only refusal and one inbox row', 'status': code})
        header, payload, signature = compact.split('.')
        claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        claims['iss'] = peer + '/unregistered'
        forged = header + '.' + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip('=') + '.' + signature
        code = push(forged)
        assert code == 400 and sql(count_sql) == '1'
        records.append({'case': 'unregistered issuer cannot select native peer keys', 'status': code, 'also_invalid_signature': True})
        operation('delete exact receiver-owned remote stream', '/ssf/upstream/delete')
        established = False
        code, remaining = native('GET', metadata['configuration_endpoint'])
        assert code == 200 and all(x['stream_id'] != stream_id for x in remaining) and any(x['stream_id'] == other['stream_id'] for x in remaining)
        other_poll = native('POST', other['delivery']['endpoint_url'], {'maxEvents': 1, 'returnImmediately': True})
        assert other_poll[0] == 200 and len(other_poll[1]['sets']) == 1
        records.append({'case': 'second independently owned stream still delivers after receiver delete', 'status': other_poll[0]})
        assert sql("select count(*) from ssf_receiver_upstream_streams where tenant_id='e2e' and peer_client_id=" + quote(peer)) == '0'
        print(json.dumps({'status': 'pass', 'profile': 'SSF1Final/operator-bearer/ALL/ES256/poll', 'independentLibrary': 'IDFoundry/SSFgo',
            'independentBinarySha256': hashlib.sha256(Path('/dev/shm/asterius-protocol-ssfgo-transmitter').read_bytes()).hexdigest(),
            'libraryRevision': 'ce2353e22367c276f8dada1dbf22ec9939a255b1', 'runtimeRevision': manifest['runtime_revision'],
            'runtimeBinarySha256': manifest['binary_sha256'], 'checks': records, 'formalCAEPConformance': False,
            'limits': ['Local revocation session explicitly seeded in owned fixture, not a browser ceremony.', 'Issuer mutation control also has invalid signature; proves refusal, not isolated signed malicious-issuer test.']}, indent=2))
    finally:
        if ack_flag.exists():
            ack_flag.unlink()
        if established:
            operation('cleanup owned upstream stream', '/ssf/upstream/delete')
        if other:
            assert native('DELETE', metadata['configuration_endpoint'] + '?' + urllib.parse.urlencode({'stream_id': other['stream_id']}))[0] == 204
        remaining_ids = {x['stream_id'] for x in native('GET', metadata['configuration_endpoint'])[1]}
        if remaining_ids != baseline_ids:
            raise RuntimeError('Remote create outcome uncertain; retain own recovery file ' + str(recovery))
        sql("delete from users where tenant_id='e2e' and user_id=" + quote(user) + "; delete from clients where tenant_id='e2e' and client_id=" + quote(peer) + ';')
        recovery.unlink()
        recovery.parent.rmdir()


if __name__ == '__main__':
    main()
