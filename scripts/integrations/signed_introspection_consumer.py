#!/usr/bin/env python3
"""Independent RFC9701 consumer for an explicitly owned disposable Asterius DB."""
import argparse, base64, json, os, re, secrets, ssl, subprocess, sys, time, urllib.request, urllib.error, urllib.parse, uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scim'))
from dpop_fixture import b64, sign

def verify(compact, media, jwks, issuer, audience, algorithm='EdDSA'):
    if media.split(';')[0].strip() != 'application/token-introspection+jwt':
        raise ValueError('wrong media')
    parts = compact.split('.')
    if len(parts) != 3:
        raise ValueError('invalid compact JWT')
    decode = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    header, claims = [json.loads(decode(x)) for x in parts[:2]]
    if header.get('typ') != 'token-introspection+jwt' or header.get('alg') != algorithm:
        raise ValueError('wrong protected profile')
    keys = [x for x in jwks['keys'] if x.get('kid') == header.get('kid')]
    if len(keys) != 1 or algorithm != 'EdDSA' or keys[0].get('kty') != 'OKP' or (keys[0].get('crv') != 'Ed25519'):
        raise ValueError('untrusted key')
    ed25519.Ed25519PublicKey.from_public_bytes(decode(keys[0]['x'])).verify(decode(parts[2]), '.'.join(parts[:2]).encode())
    if claims.get('iss') != issuer or claims.get('aud') != audience or (not isinstance(claims.get('iat'), int)) or (abs(time.time() - claims['iat']) > 60):
        raise ValueError('invalid issuer/audience/time')
    if 'sub' in claims or 'exp' in claims or (not isinstance(claims.get('token_introspection'), dict)):
        raise ValueError('invalid response envelope')
    return claims['token_introspection']

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', required=True)
    p.add_argument('--database-container', required=True)
    args = p.parse_args()
    os.umask(63)
    m = json.loads(Path(args.manifest).read_text())
    issuer = m['issuer']
    if issuer != 'https://localhost:18444/t/e2e' or not re.fullmatch('ast_product_[a-f0-9]{32}', m['database']) or (not re.fullmatch('asterius-[A-Za-z0-9_.-]+', args.database_container)):
        raise RuntimeError('Exact owned fixture required')
    ctx = ssl.create_default_context(cafile=m['ca_file'])
    key = ec.generate_private_key(ec.SECP256R1())
    n = key.public_key().public_numbers()
    jwk = {'kty': 'EC', 'crv': 'P-256', 'x': b64(n.x.to_bytes(32, 'big')), 'y': b64(n.y.to_bytes(32, 'big')), 'kid': 'owned-introspection-consumer'}
    producer, rs, outsider, unsigned = [str(uuid.uuid4()) for _ in range(4)]
    resource = 'https://owned-introspection.invalid/' + secrets.token_hex(16)
    q = lambda x: "'" + x.replace("'", "''") + "'"

    def sql(statement):
        r = subprocess.run(['docker', 'exec', '-i', args.database_container, 'psql', '-U', 'asterius', '-d', m['database'], '-At', '-v', 'ON_ERROR_STOP=1'], input=statement, text=True, capture_output=True)
        if r.returncode:
            raise RuntimeError('Owned fixture SQL refused')
        return r.stdout.strip()

    def assertion(client, alg='ES256'):
        now = int(time.time())
        return sign({'alg': alg, 'typ': 'JWT', 'kid': jwk['kid']}, {'iss': client, 'sub': client, 'aud': issuer, 'iat': now, 'exp': now + 60, 'jti': secrets.token_urlsafe(24)}, key)

    def request(path, form=None, headers=None):
        r = urllib.request.Request(issuer + path, None if form is None else urllib.parse.urlencode(form).encode(), headers or {})
        try:
            response = urllib.request.urlopen(r, context=ctx, timeout=20)
        except urllib.error.HTTPError as e:
            response = e
        data = response.read(65537)
        if len(data) > 65536:
            raise RuntimeError('Response exceeds bound')
        return (response.status, response.headers.get('Content-Type', ''), data.decode(), response.headers)

    def introspect(client, token, media='application/token-introspection+jwt', alg='ES256'):
        return request('/introspect', {'token': token, 'client_id': client, 'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'client_assertion': assertion(client, alg)}, {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': media})
    sql('begin;' + ''.join(("insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks,dpop_bound_access_tokens,introspection_signed_response_alg) values('e2e'," + q(c) + ",'Owned RFC9701 consumer','private_key_jwt',array['client_credentials'],'{}',array['read'],array[" + q(resource) + '],' + q(json.dumps({'keys': [jwk]})) + '::jsonb,true,' + ('null' if c == unsigned else "'EdDSA'") + ');' for c in [producer, rs, outsider, unsigned])) + "insert into resource_servers(tenant_id,identifier,scopes,introspection_clients) values('e2e'," + q(resource) + ",array['read'],array[" + q(rs) + ']);commit;')
    checks = []
    try:
        dpop = ec.generate_private_key(ec.SECP256R1())
        dn = dpop.public_key().public_numbers()
        dj = {'kty': 'EC', 'crv': 'P-256', 'x': b64(dn.x.to_bytes(32, 'big')), 'y': b64(dn.y.to_bytes(32, 'big'))}
        nonce = None
        for _ in range(2):
            claims = {'jti': secrets.token_urlsafe(24), 'htm': 'POST', 'htu': issuer + '/token', 'iat': int(time.time())}
            if nonce:
                claims['nonce'] = nonce
            code, media, data, headers = request('/token', {'client_id': producer, 'grant_type': 'client_credentials', 'scope': 'read', 'resource': resource, 'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'client_assertion': assertion(producer)}, {'Content-Type': 'application/x-www-form-urlencoded', 'DPoP': sign({'alg': 'ES256', 'typ': 'dpop+jwt', 'jwk': dj}, claims, dpop)})
            if code == 200:
                break
            if not headers.get('DPoP-Nonce'):
                raise RuntimeError('Actual producer token refused HTTP' + str(code))
            nonce = headers['DPoP-Nonce']
        if code != 200:
            raise RuntimeError('Producer refused HTTP' + str(code) + ' ' + str({k: v for k, v in json.loads(data).items() if k in ['error', 'error_description']}))
        token = json.loads(data)['access_token']
        checks.append({'case': 'dedicated producer real private_key_jwt plus DPoP token issuance', 'status': code})
        code, _, data, _ = request('/jwks')
        assert code == 200
        jwks = json.loads(data)
        code, media, data, _ = introspect(rs, token)
        assert code == 200
        facts = verify(data, media, jwks, issuer, rs)
        assert facts['active'] is True and facts['client_id'] == producer and (facts['scope'] == 'read') and (facts['aud'] == resource or facts['aud'] == [resource])
        checks.append({'case': 'independent Ed25519 signature and RFC9701 envelope/issuer/audience/iat plus active token claims', 'status': code})
        for label, client, value in [('unrecognised token', rs, 'owned-unknown-token'), ('resource-unauthorized authenticated client', outsider, token)]:
            code, media, data, _ = introspect(client, value)
            assert code == 200 and verify(data, media, jwks, issuer, client) == {'active': False}
            checks.append({'case': label + ' signed inactive-only privacy envelope', 'status': code})
        code, media, data, _ = introspect(unsigned, token)
        assert code == 406
        checks.append({'case': 'unregistered signed response algorithm refused by server', 'status': code})
        code, media, data, _ = introspect(rs, token, 'application/json')
        assert code == 200 and json.loads(data)['active'] is True
        try:
            verify(data, media, jwks, issuer, rs)
        except ValueError:
            checks.append({'case': 'independent consumer refuses JSON media downgrade', 'pass': True})
        else:
            raise RuntimeError('Media downgrade accepted')
        code, media, data, _ = introspect(rs, token)
        assert code == 200
        from cryptography.exceptions import InvalidSignature
        parts = data.split('.')
        raw = bytearray(base64.urlsafe_b64decode(parts[2] + '=' * (-len(parts[2]) % 4)))
        raw[0] ^= 1
        corrupted = '.'.join(parts[:2]) + '.' + b64(bytes(raw))
        try:
            verify(corrupted, media, jwks, issuer, rs)
        except InvalidSignature:
            checks.append({'case': 'independent consumer refuses altered signature', 'pass': True})
        else:
            raise RuntimeError('Forged signature accepted')
        for label, expected_issuer, expected_audience in [('issuer', issuer + '/other', rs), ('audience', issuer, outsider)]:
            try:
                verify(data, media, jwks, expected_issuer, expected_audience)
            except ValueError:
                checks.append({'case': 'independent consumer refuses wrong ' + label, 'pass': True})
            else:
                raise RuntimeError('Wrong claim accepted')
        try:
            verify(data, media, jwks, issuer, rs, 'ES256')
        except ValueError:
            checks.append({'case': 'independent consumer refuses unexpected protected signing algorithm', 'pass': True})
        else:
            raise RuntimeError('Unexpected algorithm accepted')
        code, _, _, _ = introspect(rs, token, alg='RS256')
        assert code == 400
        checks.append({'case': 'wrong client assertion algorithm refused before introspection', 'status': code})
        for media, expected in [('application/token-introspection+jwt', 400), ('application/json', 401)]:
            code, _, _, _ = request('/introspect', {'token': 'owned-unknown-token'}, {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': media})
            assert code == expected
            checks.append({'case': 'unauthenticated ' + media + ' refusal', 'status': code})
        print(json.dumps({'status': 'pass', 'standard': 'RFC9701', 'consumer': 'Python cryptography Ed25519 verification independent of Asterius JOSE', 'runtimeRevision': m['runtime_revision'], 'runtimeBinarySha256': m['binary_sha256'], 'checks': checks, 'limits': ['Disposable client/resource registration seeded through guarded fixture SQL; issuance and introspection use actual HTTPS client authentication.', 'This evidence alone does not certify FAPI Message Signing.']}, indent=2))
    finally:
        sql("begin; delete from resource_servers where tenant_id='e2e' and identifier=" + q(resource) + "; delete from clients where tenant_id='e2e' and client_id in (" + ','.join(map(q, [producer, rs, outsider, unsigned])) + ');commit;')
if __name__ == '__main__':
    main()
