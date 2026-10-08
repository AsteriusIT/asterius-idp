"""Owned selected-client IPSIE fixture. Environment selects the local binary/runtime and DB."""
import argparse
import json
import os
from pathlib import Path
import signal
import threading
from urllib.parse import urlsplit
import uuid

from oidc_product_fixture import fixture


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--encryption-jwks', type=Path, required=True)
    parser.add_argument('--keycloak-issuer', required=True)
    parser.add_argument('--port', type=int, default=18447)
    parser.add_argument('--callback-port', type=int, default=18448)
    args = parser.parse_args()
    peer = urlsplit(args.keycloak_issuer)
    if peer.scheme != 'https' or not peer.hostname or peer.username or peer.password or peer.query or peer.fragment:
        parser.error('an exact approved HTTPS Keycloak issuer is required')
    if not all(1024 <= value <= 65535 for value in (args.port, args.callback_port)) or args.port == args.callback_port:
        parser.error('distinct unprivileged fixture ports are required')
    jwks = json.loads(args.encryption_jwks.read_text())
    keys = jwks.get('keys', [])
    private_fields = {'d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'}
    if len(keys) != 1 or keys[0].get('kty') != 'RSA' or keys[0].get('use') != 'enc' or keys[0].get('alg') != 'RSA-OAEP-256' or private_fields.intersection(keys[0]):
        parser.error('one public RSA-OAEP-256 encryption JWK is required')
    os.umask(0o077)
    client_id = str(uuid.uuid4())
    extra = 'ipsie_https_only_client = ["' + client_id + '"]\nipsie_identity_only_client = ["' + client_id + '"]\n[[tenant.ipsie_rp_session]]\nclient_id = "' + client_id + '"\nlifetime_seconds = 300\n'
    callback = 'https://localhost:' + str(args.callback_port) + '/callback'
    native_callback = args.keycloak_issuer.rstrip('/') + '/broker/asterius-ipsie/endpoint'
    stopped = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stopped.set())
    owned = False
    try:
        with fixture(args.port, callback, client_id, hostname='localhost', config_extra=extra) as source:
            if not source['database'].startswith('ast_product_') or source['issuer'] != 'https://localhost:' + str(args.port) + '/t/e2e':
                raise ValueError('owned local product fixture required')
            issuer = source['issuer']
            source['sql']("insert into resource_servers(tenant_id,identifier,scopes) values('e2e'," + literal(issuer) + ",null) on conflict(tenant_id,identifier) do nothing;")
            source['sql']("update clients set redirect_uris=array[" + literal(callback) + ',' + literal(native_callback) + "], scopes=array['openid','profile','email'], resources=array[" + literal(issuer) + '], jwks=' + literal(json.dumps(jwks)) + "::jsonb, encrypt_id_token=true, encrypt_userinfo=true, userinfo_signed_response_alg='ES256' where tenant_id='e2e' and client_id=" + literal(client_id) + ';')
            document = {key: source[key] for key in ('issuer', 'secret', 'client_id', 'database', 'runtime_revision', 'binary_sha256')}
            document.update(ca_file=str(source['root'] / 'ca.pem'), config_path=str(source['config_path']), profile='IPSIE SL1 2026-09-29 selected client; controlled deployment, no conformance claim', callback=callback)
            with args.manifest.open('x') as output:
                owned = True
                json.dump(document, output)
            print('SELECTED_IPSIE_FIXTURE_READY', flush=True)
            stopped.wait()
    finally:
        if owned:
            args.manifest.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
