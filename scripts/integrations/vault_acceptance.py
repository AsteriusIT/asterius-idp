#!/usr/bin/env python3
"""Disposable native Vault/OpenBao OIDC and Kubernetes JWT acceptance.

Requires already-built Asterius and official product binaries. Never builds Rust,
changes a shared schema, or exports credentials in the JSON result.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from render_secret_system import render

ROOT = Path(__file__).resolve().parents[2]
CONTAINER = os.environ['ASTERIUS_ACCEPTANCE_DB_CONTAINER']
ASTERIUS = Path(os.environ['ASTERIUS_BIN']).resolve()
PRODUCT = Path(os.environ['ASTERIUS_SECRET_SYSTEM_BIN']).resolve()
KUBECONFIG = Path(os.environ['ASTERIUS_ACCEPTANCE_KUBECONFIG']).resolve()
CLUSTER = os.environ['ASTERIUS_ACCEPTANCE_CLUSTER']
if not CLUSTER.startswith('ast-dd1y66-') or not KUBECONFIG.is_file():
    raise SystemExit('explicit disposable kind cluster and kubeconfig required')
NAME = os.environ['ASTERIUS_SECRET_SYSTEM_PRODUCT']
if NAME not in ('openbao', 'vault'):
    raise SystemExit('select vault or openbao')
PORT = int(os.environ.get('ASTERIUS_ACCEPTANCE_PORT', '9452'))
SECRET_PORT = int(os.environ.get('ASTERIUS_SECRET_SYSTEM_PORT', '9453'))
os.umask(0o077)


def command(args, body=None):
    if args[0] == 'kubectl':
        args = [args[0], '--kubeconfig', str(KUBECONFIG), '--context', 'kind-'+CLUSTER, *args[1:]]
    result = subprocess.run(args, input=body, text=True, capture_output=True)
    if result.returncode:
        stage = next((line for line in result.stderr.splitlines() if line.startswith('NATIVE_BROWSER_STAGE=')), '')
        raise RuntimeError('fixture command failed: ' + Path(args[0]).name + (' '+stage if stage else ''))
    return result.stdout


def psql(database, sql):
    return command(['docker', 'exec', '-i', CONTAINER, 'psql', '-U', 'asterius',
                    '-d', database, '-v', 'ON_ERROR_STOP=1', '-At'], sql)


def request(url, method='GET', body=None, token=None, context=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['X-Vault-Token'] = token
    req = urllib.request.Request(url, json.dumps(body).encode() if body is not None else None,
                                 headers, method=method)
    try:
        with urllib.request.urlopen(req, context=context, timeout=15) as response:
            status, raw = response.status, response.read(1048576)
    except urllib.error.HTTPError as response:
        status, raw = response.code, response.read(1048576)
    return status, json.loads(raw) if raw else {}


def wait_ready(url, process, context=None):
    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError('isolated fixture server exited')
        try:
            status, _ = request(url, context=context)
            if status == 200:
                return
        except (urllib.error.URLError, TimeoutError):
            pass
        time.sleep(1)
    raise RuntimeError('isolated fixture server did not become ready')


def run():
    namespace = 'ast-dd1y66-' + secrets.token_hex(6)
    database = 'ast_secret_' + uuid.uuid4().hex
    processes, logs, cases = [], [], []
    database_created = False
    namespaces = []
    root_token = secrets.token_urlsafe(32)
    with tempfile.TemporaryDirectory(prefix='asterius-secret-acceptance.') as directory:
        run_dir = Path(directory)
        try:
            psql('postgres', f'create database "{database}";')
            database_created = True
            command(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                     '-keyout', str(run_dir/'key.pem'), '-out', str(run_dir/'ca.pem'), '-days', '1',
                     '-nodes', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'])
            config = (ROOT/'e2e/fixtures/asterius.toml.in').read_text()
            substitutions = {'@PORT@': str(PORT), '@CERTIFICATE@': str(run_dir/'ca.pem'),
                             '@PRIVATE_KEY@': str(run_dir/'key.pem'), '@DATABASE_URL@':
                             f'postgres://asterius:asterius@127.0.0.1:5433/{database}'}
            for old, new in substitutions.items():
                config = config.replace(old, new)
            (run_dir/'asterius.toml').write_text(config)
            log = (run_dir/'asterius.log').open('w'); logs.append(log)
            process = subprocess.Popen([str(ASTERIUS), '--config', str(run_dir/'asterius.toml')],
                                       env={**os.environ, 'ASTERIUS_KEK': 'YXN0ZXJpdXMtZGV2LWtlay1ub3QtYS1zZWNyZXQhISE=',
                                            'ASTERIUS_ADMIN_PASSWORD': secrets.token_urlsafe(32)}, stdout=log, stderr=log)
            processes.append(process)
            context = ssl.create_default_context(cafile=str(run_dir/'ca.pem'))
            issuer = f'https://127.0.0.1:{PORT}/t/e2e'
            wait_ready(f'https://127.0.0.1:{PORT}/readyz', process, context)
            seed = (ROOT/'e2e/fixtures/seed.sql').read_text()
            # Reuse the repository's documented disposable browser account.
            seed = seed.replace(":'tenant'", "'e2e'").replace(":'username'", "'sweep@example.test'")
            seed = seed.replace(":'hash'", "'$argon2id$v=19$m=19456,t=2,p=1$YnJvd3Nlci1zd2VlcC1zYWx0$E8awnsfATh5sLXjht+SvAdX9BEFVTWfDYThAb/+KOfs'")
            psql(database, seed)
            secret = secrets.token_urlsafe(32)
            digest = hashlib.sha256(secret.encode()).hexdigest()
            callback = issuer + '/oidc/callback'
            psql(database, f"""
                update tenants set settings=settings || jsonb_build_object('options',coalesce(settings->'options','{{}}'::jsonb) || '{{"allow_non_fapi_clients":true}}'::jsonb) where tenant_id='e2e';
                insert into clients(tenant_id,client_id,client_name,compliance_profile,token_endpoint_auth_method,
                  client_secret_hash,grant_types,response_types,redirect_uris,scopes,resources,
                  dpop_bound_access_tokens,tls_client_certificate_bound_access_tokens,id_token_signed_response_alg)
                values('e2e','secret-system-human','Disposable secret system','oidc','client_secret_basic',
                  decode('{digest}','hex'),array['authorization_code'],array['code'],array['{callback}'],
                  array['openid','email'],array[(select default_resource from tenants where tenant_id='e2e')],false,false,'ES256');
            """)
            # Restart reloads the explicitly opted-in tenant options cache.
            process.terminate(); process.wait(timeout=15)
            process = subprocess.Popen([str(ASTERIUS), '--config', str(run_dir/'asterius.toml')],
                                       env={**os.environ, 'ASTERIUS_KEK': 'YXN0ZXJpdXMtZGV2LWtlay1ub3QtYS1zZWNyZXQhISE=',
                                            'ASTERIUS_ADMIN_PASSWORD': secrets.token_urlsafe(32)}, stdout=log, stderr=log)
            processes.append(process)
            wait_ready(f'https://127.0.0.1:{PORT}/readyz', process, context)
            product_dir = run_dir/'product-tls'; product_dir.mkdir()
            product_log = (run_dir/'product.log').open('w'); logs.append(product_log)
            prefix = 'BAO' if NAME == 'openbao' else 'VAULT'
            product_process = subprocess.Popen([str(PRODUCT), 'server', '-dev', '-dev-tls',
                        '-dev-tls-cert-dir='+str(product_dir), '-dev-listen-address=127.0.0.1:'+str(SECRET_PORT)],
                        env={**os.environ, prefix+'_DEV_ROOT_TOKEN_ID': root_token},
                        stdout=product_log, stderr=product_log)
            processes.append(product_process)
            for _ in range(60):
                certs = list(product_dir.glob('*.pem'))
                if certs:
                    break
                if product_process.poll() is not None:
                    raise RuntimeError('isolated secret system exited')
                time.sleep(1)
            cert = next((p for p in certs if p.name.endswith('-ca.pem')), None)
            if cert is None:
                raise RuntimeError('product TLS certificate missing')
            product_context = ssl.create_default_context(cafile=str(cert))
            product_url = f'https://127.0.0.1:{SECRET_PORT}/v1/'
            wait_ready(product_url+'sys/health', product_process, product_context)
            def api(label, path, method='POST', body=None, wanted=(200,204), token=root_token):
                status, value = request(product_url+path, method, body, token, product_context)
                if label:
                    cases.append({'case': label, 'status': status})
                if status >= 400 and value.get('auth'):
                    raise RuntimeError('refusal unexpectedly returned authority')
                if status not in wanted:
                    raise RuntimeError('secret-system check failed: '+(label or path)+' status '+str(status))
                return value
            api(None, 'sys/mounts/fixture', body={'type':'kv','options':{'version':'2'}})
            api(None, 'fixture/data/allowed', body={'data':{'value':'disposable fixture'}})
            api(None, 'fixture/data/forbidden', body={'data':{'value':'disposable fixture'}})
            policy = 'path "fixture/data/allowed" { capabilities = ["read"] } path "auth/token/revoke-self" { capabilities = ["update"] }'
            api(None, 'sys/policies/acl/least-privilege', body={'policy':policy})
            api(None, 'sys/auth/asterius', body={'type':'oidc'})
            templates=ROOT/'integrations/secret-systems'
            config=render(templates/'human-config.json.in',{'ASTERIUS_ISSUER':issuer,
                'ASTERIUS_CA_PEM':(run_dir/'ca.pem').read_text(),'ASTERIUS_CLIENT_ID':'secret-system-human',
                'SERVER_GENERATED_CLIENT_SECRET':secret})
            api(None,'auth/asterius/config',body=config)
            role=render(templates/'human-role.json.in',{'ASTERIUS_SUBJECT':'fixture-subject-to-be-resolved',
                'ASTERIUS_CLIENT_ID':'secret-system-human','SECRET_SYSTEM_HTTPS_CALLBACK':callback})
            role.update({'token_policies':['least-privilege'],'token_ttl':30,'token_explicit_max_ttl':30})
            # The fixture first learns its verified native subject using its one
            # disposable verified email, then removes that bootstrap role.
            api(None, 'auth/asterius/role/discover-fixture-subject', body={key:value for key,value in {**role,'bound_claims':{'email':'sweep@example.test','email_verified':True}}.items() if key!='bound_subject'})
            for human_role, wanted in [('discover-fixture-subject',(200,)),('human',(200,)),('foreign-human',(400,401,403,500))]:
                client_nonce = secrets.token_urlsafe(24)
                auth = api(None,'auth/asterius/oidc/auth_url', body={'role':human_role,'redirect_uri':callback,'client_nonce':client_nonce})
                url = auth['data']['auth_url']
                query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
                if query.get('code_challenge_method') != ['S256'] or not query.get('code_challenge'):
                    raise RuntimeError('native OIDC client did not use S256 PKCE')
                browser_file = run_dir/'browser.json'; browser_file.write_text(json.dumps({'authorizationUrl':url}))
                command(['node',str(ROOT/'scripts/integrations/vault-human.mjs'),str(browser_file)])
                response_query = json.loads(browser_file.read_text())
                response_query.update({'client_nonce':client_nonce,'nonce':query['nonce'][0]})
                response = api('native OIDC '+human_role,'auth/asterius/oidc/callback?'+urllib.parse.urlencode(response_query),
                               method='GET',wanted=wanted,token=None)
                if human_role == 'discover-fixture-subject':
                    entity=api(None,'identity/entity/id/'+response['auth']['entity_id'],'GET')
                    subject=next(alias['name'] for alias in entity['data']['aliases'] if alias['mount_path']=='auth/asterius/')
                    role['bound_subject']=subject
                    api(None,'auth/asterius/role/human',body=role)
                    api(None,'auth/asterius/role/foreign-human',body={**role,'bound_subject':'unapproved-subject'})
                    api(None,'auth/asterius/role/discover-fixture-subject','DELETE')
                    api(None,'auth/token/revoke-self',token=response['auth']['client_token'])
                if human_role == 'human':
                    human_token = response['auth']['client_token']
                    api('human allowed policy read','fixture/data/allowed','GET',token=human_token)
                    api('human forbidden policy read','fixture/data/forbidden','GET',wanted=(403,),token=human_token)
                    browser_file.write_text(json.dumps({'mode':'logout','issuer':issuer}))
                    command(['node',str(ROOT/'scripts/integrations/vault-human.mjs'),str(browser_file)])
                    api('source logout does not revoke product token','fixture/data/allowed','GET',token=human_token)
                    api('human self revocation','auth/token/revoke-self',token=human_token)
                    api('revoked human token refused','fixture/data/allowed','GET',wanted=(403,),token=human_token)
            command(['kubectl','create','namespace',namespace]); namespaces.append(namespace)
            other_namespace=namespace+'-other'
            command(['kubectl','create','namespace',other_namespace]); namespaces.append(other_namespace)
            command(['kubectl','create','serviceaccount','allowed','-n',other_namespace])
            for identity in ('allowed','other'):
                command(['kubectl','create','serviceaccount',identity,'-n',namespace])
            discovery = json.loads(command(['kubectl','get','--raw','/.well-known/openid-configuration']))
            jwks = json.loads(command(['kubectl','get','--raw','/openid/v1/jwks']))
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            b64 = lambda s:int.from_bytes(base64.urlsafe_b64decode(s+'='*(-len(s)%4)),'big')
            keys=[rsa.RSAPublicNumbers(b64(k['e']),b64(k['n'])).public_key().public_bytes(
                  serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
                  for k in jwks['keys'] if k['kty']=='RSA']
            if not keys:
                raise RuntimeError('fixture cluster has no RS256 verification key')
            uid=json.loads(command(['kubectl','get','serviceaccount','allowed','-n',namespace,'-o','json']))['metadata']['uid']
            audience='urn:asterius:secret-system:workload'
            api(None,'sys/auth/kubernetes-jwt',body={'type':'jwt'})
            config=render(templates/'workload-config.json.in',{'EXACT_KUBERNETES_ISSUER':discovery['issuer'],
                'PINNED_CLUSTER_PUBLIC_KEY_PEM':keys[0]})
            config['jwt_validation_pubkeys']=keys
            api(None,'auth/kubernetes-jwt/config',body=config)
            workload_role=render(templates/'workload-role.json.in',{'NAMESPACE':namespace,
                'SERVICE_ACCOUNT':'allowed','SERVICE_ACCOUNT_UID':uid})
            workload_role.update({'token_policies':['least-privilege'],'token_ttl':5,'token_explicit_max_ttl':5})
            api(None,'auth/kubernetes-jwt/role/workload',body=workload_role)
            def projected(identity,aud,selected_namespace=namespace):
                return command(['kubectl','create','token',identity,'-n',selected_namespace,'--audience='+aud,'--duration=10m']).strip()
            jwt = projected('allowed',audience)
            answer=api('projected Kubernetes JWT login','auth/kubernetes-jwt/login',body={'role':'workload','jwt':jwt},token=None)
            workload_token=answer['auth']['client_token']
            api('workload allowed policy read','fixture/data/allowed','GET',token=workload_token)
            api('workload forbidden policy read','fixture/data/forbidden','GET',wanted=(403,),token=workload_token)
            for label, value in [('wrong audience refused',projected('allowed','urn:wrong:audience')),
                                 ('wrong ServiceAccount refused',projected('other',audience)),
                                 ('wrong namespace refused',projected('allowed',audience,other_namespace))]:
                api(label,'auth/kubernetes-jwt/login',body={'role':'workload','jwt':value},wanted=(400,403),token=None)
            command(['kubectl','delete','serviceaccount','allowed','-n',namespace])
            command(['kubectl','create','serviceaccount','allowed','-n',namespace])
            api('replacement ServiceAccount UID refused','auth/kubernetes-jwt/login',body={'role':'workload','jwt':projected('allowed',audience)},wanted=(400,403),token=None)
            api('deleted ServiceAccount JWT retains offline validity','auth/kubernetes-jwt/login',body={'role':'workload','jwt':jwt},token=None)
            api(None,'sys/auth/wrong-issuer',body={'type':'jwt'})
            api(None,'auth/wrong-issuer/config',body={'jwt_validation_pubkeys':keys,'bound_issuer':'https://wrong.example.invalid','jwt_supported_algs':['RS256']})
            api(None,'auth/wrong-issuer/role/workload',body=workload_role)
            api('wrong issuer refused','auth/wrong-issuer/login',body={'role':'workload','jwt':jwt},wanted=(400,403),token=None)
            time.sleep(6)
            api('expired product token refused','fixture/data/allowed','GET',wanted=(403,),token=workload_token)
            answer=api('valid projected JWT can reauthenticate after product expiry','auth/kubernetes-jwt/login',body={'role':'workload','jwt':jwt},token=None)
            api('new workload token allowed','fixture/data/allowed','GET',token=answer['auth']['client_token'])
            result={'product':NAME,'version':command([str(PRODUCT),'version']).strip().splitlines()[0],
                    'asterius_binary_sha256':hashlib.sha256(ASTERIUS.read_bytes()).hexdigest(),
                    'cases':cases,'human_profile':'explicit standard OIDC; S256 PKCE; ES256 ID token; client_secret_basic',
                    'workload_profile':'direct projected Kubernetes RS256 JWT; pinned issuer/key/audience/namespace/SA name+UID; no static OAuth secret',
                    'limits':['Asterius DPoP access-token JWT is not a supported direct Bearer trust input',
                              'deleted ServiceAccount JWT remains valid offline until expiry; no TokenReview or pod-deletion invalidation',
                              'identity-token expiry/source logout does not revoke an already issued secret-system token or fetched secret',
                              'no dynamic-secret lease engine exercised; KV policy and auth token expiry/revocation tested'],
                    'cleanup':'only own namespace/database/processes/private fixture files removed'}
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=15)
                    except subprocess.TimeoutExpired: process.kill();process.wait(timeout=5)
            for log in logs: log.close()
            for owned_namespace in reversed(namespaces):
                command(['kubectl','delete','namespace',owned_namespace,'--wait=true','--timeout=60s'])
            if database_created: psql('postgres',f'drop database "{database}";')
    print(json.dumps(result,indent=2))


if __name__ == '__main__':
    run()
