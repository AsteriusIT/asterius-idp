#!/usr/bin/env python3
"""Own loopback transmitter smoke check; does not establish Asterius interoperability."""
import argparse
import base64
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


def run(binary):
    with tempfile.TemporaryDirectory(prefix='asterius-ssfgo-smoke-', dir='/dev/shm') as directory:
        root = Path(directory)
        token = secrets.token_urlsafe(48)
        credential = root / 'bearer'
        credential.write_text(token)
        credential.chmod(0o600)
        issuer = 'https://127.0.0.1:19485'
        base = 'http://127.0.0.1:19485'
        audience = 'https://receiver.example/ssf/receiver'
        with (root / 'server.log').open('w') as log:
            child = subprocess.Popen([binary, '-issuer', issuer, '-audience', audience,
                '-bind', '127.0.0.1:19485', '-control', '127.0.0.1:19486',
                '-bearer-file', str(credential)], stdout=log, stderr=log)
            try:
                def request(method, url, body=None, authorized=True):
                    parsed = urllib.parse.urlsplit(url)
                    target = base + parsed.path + ('?' + parsed.query if parsed.query else '')
                    headers = {'Content-Type': 'application/json'}
                    if authorized:
                        headers['Authorization'] = 'Bearer ' + token
                    req = urllib.request.Request(target, None if body is None else json.dumps(body).encode(), headers, method=method)
                    try:
                        response = urllib.request.urlopen(req, timeout=5)
                    except urllib.error.HTTPError as error:
                        response = error
                    data = response.read(65537)
                    assert len(data) <= 65536
                    return response.status, json.loads(data) if data else None
                for _ in range(100):
                    if child.poll() is not None:
                        raise RuntimeError('owned transmitter failed to start')
                    try:
                        code, metadata = request('GET', base + '/.well-known/ssf-configuration', authorized=False)
                        if code == 200:
                            break
                    except urllib.error.URLError:
                        pass
                    time.sleep(0.05)
                else:
                    raise RuntimeError('owned transmitter readiness deadline')
                assert metadata['spec_version'] == '1_0' and metadata['default_subjects'] == 'ALL'
                assert metadata['delivery_methods_supported'] == ['urn:ietf:rfc:8936']
                assert request('GET', metadata['configuration_endpoint'], authorized=False)[0] == 401
                def create():
                    code, stream = request('POST', metadata['configuration_endpoint'], {
                        'events_requested': ['https://schemas.openid.net/secevent/caep/event-type/session-revoked',
                            'https://schemas.openid.net/secevent/caep/event-type/credential-change'],
                        'delivery': {'method': 'urn:ietf:rfc:8936'}})
                    assert code == 201, ('create status', code, stream.get('error') if isinstance(stream, dict) else None)
                    assert stream['aud'] in (audience, [audience]) and stream['iss'] == issuer
                    return stream
                selected, other = create(), create()
                assert request('POST', metadata['verification_endpoint'], {'stream_id': selected['stream_id'], 'state': 'owned-challenge'})[0] == 204
                code, result = request('POST', selected['delivery']['endpoint_url'], {'maxEvents': 1, 'returnImmediately': True})
                assert code == 200 and len(result['sets']) == 1
                jti, compact = next(iter(result['sets'].items()))
                def decode(value):
                    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
                header, payload, signature = compact.split('.')
                claims, protected = json.loads(decode(payload)), json.loads(decode(header))
                assert protected['alg'] == 'ES256' and protected['typ'] == 'secevent+jwt'
                code, jwks = request('GET', metadata['jwks_uri'], authorized=False)
                jwk = jwks['keys'][0]
                public = ec.EllipticCurvePublicNumbers(int.from_bytes(decode(jwk['x']), 'big'), int.from_bytes(decode(jwk['y']), 'big'), ec.SECP256R1()).public_key()
                raw = decode(signature)
                der = utils.encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big'))
                public.verify(der, (header + '.' + payload).encode(), ec.ECDSA(hashes.SHA256()))
                assert claims.get('txn')
                assert claims['jti'] == jti and claims['iss'] == issuer and claims['aud'] in (audience, [audience])
                verification = claims['events']['https://schemas.openid.net/secevent/ssf/event-type/verification']
                assert verification['state'] == 'owned-challenge' and claims['sub_id']['id'] == selected['stream_id']
                assert request('POST', selected['delivery']['endpoint_url'], {'ack': [jti], 'returnImmediately': True})[1]['sets'] == {}
                delete_url = metadata['configuration_endpoint'] + '?' + urllib.parse.urlencode({'stream_id': selected['stream_id']})
                assert request('DELETE', delete_url)[0] == 204
                code, remaining = request('GET', metadata['configuration_endpoint'])
                assert code == 200 and [stream['stream_id'] for stream in remaining] == [other['stream_id']]
                print(json.dumps({'peer': 'IDFoundry/SSFgo', 'revision': 'ce2353e22367c276f8dada1dbf22ec9939a255b1',
                    'checks': ['poll-only final metadata', 'bearer refusal', 'multi-stream create', 'verification state',
                        'independent ES256 verification', 'poll acknowledgment', 'exact-stream delete'],
                    'status': 'pass', 'asterius_network_handoff': False, 'formal_conformance': False}))
            finally:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    run(str(Path(parser.parse_args().binary).resolve()))
