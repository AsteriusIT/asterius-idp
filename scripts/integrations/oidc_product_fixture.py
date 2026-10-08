"""Shared disposable Asterius bootstrap for native product integration tests."""
import contextlib
import hashlib
import ipaddress
import re
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


def command(args,body=None,timeout=120):
    result=subprocess.run(args,input=body,text=True,capture_output=True,timeout=timeout)
    if result.returncode:
        stage=next((line for line in result.stderr.splitlines() if line.startswith(('GATEWAY_BROWSER_STAGE=','GATEWAY_CHECK=','PRODUCT_BROWSER_STAGE='))), '')
        if not stage:
            markers=['browserType.launch','SyntaxError','Target page, context or browser has been closed','TimeoutError','ENOSPC','ERR_MODULE_NOT_FOUND','page.waitForRequest','ERR_CONNECTION_REFUSED','Cannot find','undefined service','invalid compose','no such service','mount source path does not exist','permission denied','unhealthy','manifest unknown','pull access denied','invalid interpolation','failed to solve','unauthorized','no matching manifest','unsupported config']
            stage='SAFE_CHILD_DIAGNOSTIC='+','.join(marker for marker in markers if marker in result.stderr)
        raise RuntimeError('controlled fixture command failed: '+Path(args[0]).name+' exit='+str(result.returncode)+(' '+stage if stage else ''))
    return result.stdout


def sql(database,body):
    return command(['docker','exec','-i',os.environ['ASTERIUS_ACCEPTANCE_DB_CONTAINER'],
                    'psql','-U','asterius','-d',database,'-v','ON_ERROR_STOP=1','-At'],body)


@contextlib.contextmanager
def fixture(port,callback,client_id,hostname='127.0.0.1',bind='127.0.0.1', *,
            config_extra='', automation_scopes=(), readonly_paths=()):
    os.umask(0o077)
    # The fixture starts twice; preserve mount inputs across both starts.
    readonly_paths = tuple(readonly_paths)
    database='ast_product_'+uuid.uuid4().hex
    binary=Path(os.environ['ASTERIUS_BIN']).resolve()
    created=False;process=None
    image=os.environ.get('ASTERIUS_RUNTIME_IMAGE')
    revision=None
    if image:
        revision=command(['docker','image','inspect',image,'--format','{{ index .Config.Labels "org.opencontainers.image.revision" }}']).strip()
        expected_revision=os.environ.get('ASTERIUS_RUNTIME_REVISION')
        if expected_revision and revision!=expected_revision:
            raise RuntimeError('runtime image revision differs from requested source revision')
    container='asterius-product-'+uuid.uuid4().hex
    database_origin=os.environ.get('ASTERIUS_ACCEPTANCE_DATABASE_ORIGIN','postgres://asterius:asterius@127.0.0.1:5433').rstrip('/')
    if not database_origin.startswith(('postgres://','postgresql://')) or any(char in database_origin for char in '\r\n'):
        raise RuntimeError('invalid controlled database origin')
    hosts=[]
    for mapping in filter(None,os.environ.get('ASTERIUS_RUNTIME_HOSTS','').split(',')):
        host,separator,address=mapping.partition(':')
        if not separator or not re.fullmatch(r'[A-Za-z0-9.-]+',host) or not ipaddress.ip_address(address).is_global:
            raise RuntimeError('runtime hosts must map a DNS name to a public IP')
        hosts.extend(['--add-host',mapping])
    if any(not re.fullmatch(r'[A-Za-z0-9_.:-]+',scope) for scope in automation_scopes):
        raise RuntimeError('invalid controlled automation scope')
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
                     '@PRIVATE_KEY@':str(root/'key.pem'),'@DATABASE_URL@':f'{database_origin}/{database}'}.items():
                    config=config.replace(key,value)
                config=config.replace(f'bind = "127.0.0.1:{port}"',f'bind = "{bind}:{port}"')
                config=config.replace('https://127.0.0.1:',f'https://{hostname}:')
                features=os.environ.get('ASTERIUS_FIXTURE_FEATURES','').split()
                if len(features)!=len(set(features)) or any(feature not in ('ssf','dpop_nonce','request_object','advanced_claims') for feature in features):
                    raise RuntimeError('unsupported disposable protocol feature')
                if features:
                    config=config.replace('device_flow = true','device_flow = true\n'+ '\n'.join(feature+' = true' for feature in features),1)
                if config_extra:
                    # Insert inside the first (e2e) tenant, before the template's
                    # next tenant; nested SSF peer tables must belong to e2e.
                    boundary='\n[[tenant]]\nid = "e2e-webauthn"'
                    config=config.replace(boundary,'\n'+config_extra+'\n'+boundary,1)
                (root/'asterius.toml').write_text(config)
                issuer=f'https://{hostname}:{port}/t/e2e'
                env={**os.environ,'ASTERIUS_KEK':'YXN0ZXJpdXMtZGV2LWtlay1ub3QtYS1zZWNyZXQhISE=',
                     'ASTERIUS_ADMIN_PASSWORD':secrets.token_urlsafe(32)}
                context=ssl.create_default_context(cafile=str(root/'ca.pem'))
                def stop(child):
                    if image:
                        command(['docker','stop','--time','10',container],timeout=20)
                    elif child.poll() is None:
                        child.terminate()
                    try:child.wait(timeout=15)
                    except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
                def start():
                    args=[str(binary),'--config',str(root/'asterius.toml')]
                    if image:
                        args=['docker','run','--rm','--name',container,'--network','host',
                              '--user',f'{os.getuid()}:{os.getgid()}',
                              '--mount',f'type=bind,source={root},target={root},readonly',
                              '--env','ASTERIUS_KEK','--env','ASTERIUS_ADMIN_PASSWORD',*hosts]
                        for path in readonly_paths:
                            owned=Path(path).resolve(strict=True)
                            args+=['--mount',f'type=bind,source={owned},target={owned},readonly']
                        args += [image,'--config',str(root/'asterius.toml')]
                    child=subprocess.Popen(args,env=env,stdout=log,stderr=log)
                    for _ in range(60):
                        if child.poll() is not None:raise RuntimeError('isolated Asterius exited')
                        try:
                            with urllib.request.urlopen(f'https://{bind}:{port}/readyz',context=context,timeout=1) as answer:
                                if answer.status==200:return child
                        except (urllib.error.URLError,TimeoutError):pass
                        time.sleep(1)
                    stop(child)
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
                scopes=['openid','email',*automation_scopes]
                scope_sql=','.join("'"+scope+"'" for scope in scopes)
                grants="'authorization_code','client_credentials'" if automation_scopes else "'authorization_code'"
                sql(database,f"""update tenants set settings=settings || jsonb_build_object('options',coalesce(settings->'options','{{}}'::jsonb) || '{{"allow_non_fapi_clients":true}}'::jsonb) where tenant_id='e2e';
                     insert into clients(tenant_id,client_id,client_name,compliance_profile,token_endpoint_auth_method,client_secret_hash,
                     grant_types,response_types,redirect_uris,scopes,resources,dpop_bound_access_tokens,tls_client_certificate_bound_access_tokens,id_token_signed_response_alg)
                     values('e2e','{client_id}','Disposable product integration','oidc','client_secret_basic',decode('{digest}','hex'),
                     array[{grants}],array['code'],array['{callback}'],array[{scope_sql}],
                     array[(select default_resource from tenants where tenant_id='e2e')],false,false,'ES256');""")
                # Stable opaque identities are seeded only in this owned disposable DB.
                # Production obtains these identifiers from verified tokens, never local UUIDs.
                approved_sub='subject-'+secrets.token_urlsafe(32)
                denied_sub='subject-'+secrets.token_urlsafe(32)
                sql(database,f"""insert into subject_identifiers(tenant_id,user_id,sector_identifier,subject)
                     select 'e2e',user_id,'',case when username='sweep@example.test' then '{approved_sub}' else '{denied_sub}' end
                     from users where tenant_id='e2e' and username in ('sweep@example.test','denied@example.test');""")
                stop(process);process=start()
                yield {'root':root,'issuer':issuer,'secret':secret,'client_id':client_id,'database':database,
                       'approved_sub':approved_sub,'denied_sub':denied_sub,
                       'sql':lambda body:sql(database,body),'context':context,
                       'config_path':root/'asterius.toml',
                       'runtime_revision':revision,
                       'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
            finally:
                if process is not None and process.poll() is None:
                    stop(process)
                if created:sql('postgres',f'drop database "{database}";')
