"""Shared disposable Asterius bootstrap for native product integration tests."""
import contextlib
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
import urllib.request
import uuid

ROOT=Path(__file__).resolve().parents[2]


def command(args,body=None):
    result=subprocess.run(args,input=body,text=True,capture_output=True,timeout=120)
    if result.returncode:
        stage=next((line for line in result.stderr.splitlines() if line.startswith(('GATEWAY_BROWSER_STAGE=','GATEWAY_CHECK='))), '')
        raise RuntimeError('controlled fixture command failed: '+Path(args[0]).name+' exit='+str(result.returncode)+(' '+stage if stage else ''))
    return result.stdout


def sql(database,body):
    return command(['docker','exec','-i',os.environ['ASTERIUS_ACCEPTANCE_DB_CONTAINER'],
                    'psql','-U','asterius','-d',database,'-v','ON_ERROR_STOP=1','-At'],body)


@contextlib.contextmanager
def fixture(port,callback,client_id,hostname='127.0.0.1',bind='127.0.0.1'):
    os.umask(0o077)
    database='ast_product_'+uuid.uuid4().hex
    binary=Path(os.environ['ASTERIUS_BIN']).resolve()
    created=False;process=None
    with tempfile.TemporaryDirectory(prefix='asterius-product-fixture.') as directory:
        root=Path(directory)
        with (root/'server.log').open('w') as log:
            try:
                sql('postgres',f'create database "{database}";');created=True
                command(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
                         '-keyout',str(root/'key.pem'),'-out',str(root/'ca.pem'),'-days','1','-nodes',
                         '-subj','/CN='+hostname,'-addext',f'subjectAltName=IP:127.0.0.1,IP:{bind},DNS:localhost,DNS:host.docker.internal'])
                config=(ROOT/'e2e/fixtures/asterius.toml.in').read_text()
                for key,value in {'@PORT@':str(port),'@CERTIFICATE@':str(root/'ca.pem'),
                     '@PRIVATE_KEY@':str(root/'key.pem'),'@DATABASE_URL@':f'postgres://asterius:asterius@127.0.0.1:5433/{database}'}.items():
                    config=config.replace(key,value)
                config=config.replace(f'bind = "127.0.0.1:{port}"',f'bind = "{bind}:{port}"')
                config=config.replace('https://127.0.0.1:',f'https://{hostname}:')
                (root/'asterius.toml').write_text(config)
                issuer=f'https://{hostname}:{port}/t/e2e'
                env={**os.environ,'ASTERIUS_KEK':'YXN0ZXJpdXMtZGV2LWtlay1ub3QtYS1zZWNyZXQhISE=',
                     'ASTERIUS_ADMIN_PASSWORD':secrets.token_urlsafe(32)}
                context=ssl.create_default_context(cafile=str(root/'ca.pem'))
                def start():
                    child=subprocess.Popen([str(binary),'--config',str(root/'asterius.toml')],env=env,stdout=log,stderr=log)
                    for _ in range(60):
                        if child.poll() is not None:raise RuntimeError('isolated Asterius exited')
                        try:
                            with urllib.request.urlopen(f'https://{bind}:{port}/readyz',context=context,timeout=1) as answer:
                                if answer.status==200:return child
                        except (urllib.error.URLError,TimeoutError):pass
                        time.sleep(1)
                    child.terminate();child.wait(timeout=15)
                    raise RuntimeError('isolated Asterius not ready')
                process=start()
                seed=(ROOT/'e2e/fixtures/seed.sql').read_text().replace(":'tenant'","'e2e'").replace(":'username'","'sweep@example.test'")
                password_hash='$argon2id$v=19$m=19456,t=2,p=1$YnJvd3Nlci1zd2VlcC1zYWx0$E8awnsfATh5sLXjht+SvAdX9BEFVTWfDYThAb/+KOfs'
                sql(database,seed.replace(":'hash'","'"+password_hash+"'"))
                # Another genuinely authenticated local user is not on the gateway allow-list.
                sql(database,f"""insert into users(tenant_id,user_id,username,email,email_verified,status,claims)
                     values('e2e','3f1d5c2a-0000-4000-8000-000000000099','denied@example.test','denied@example.test',true,'active','{{}}');
                     insert into credentials(tenant_id,credential_id,user_id,kind,password_hash,label)
                     values('e2e','3f1d5c2a-0000-4000-8000-000000000098','3f1d5c2a-0000-4000-8000-000000000099','password','{password_hash}','disposable product fixture');""")
                secret=secrets.token_urlsafe(32);digest=hashlib.sha256(secret.encode()).hexdigest()
                if not client_id.replace('-','').replace('_','').isalnum() or "'" in callback:
                    raise RuntimeError('invalid controlled fixture metadata')
                sql(database,f"""update tenants set settings=settings || jsonb_build_object('options',coalesce(settings->'options','{{}}'::jsonb) || '{{"allow_non_fapi_clients":true}}'::jsonb) where tenant_id='e2e';
                     insert into clients(tenant_id,client_id,client_name,compliance_profile,token_endpoint_auth_method,client_secret_hash,
                     grant_types,response_types,redirect_uris,scopes,resources,dpop_bound_access_tokens,tls_client_certificate_bound_access_tokens,id_token_signed_response_alg)
                     values('e2e','{client_id}','Disposable product integration','oidc','client_secret_basic',decode('{digest}','hex'),
                     array['authorization_code'],array['code'],array['{callback}'],array['openid','email'],
                     array[(select default_resource from tenants where tenant_id='e2e')],false,false,'ES256');""")
                process.terminate();process.wait(timeout=15);process=start()
                yield {'root':root,'issuer':issuer,'secret':secret,'client_id':client_id,'database':database,
                       'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=15)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                if created:sql('postgres',f'drop database "{database}";')
