#!/usr/bin/env python3
"""Native Grafana acceptance, using only owned disposable fixture resources."""
from datetime import date
import hashlib
import ipaddress
import json
import os
import secrets
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from oidc_product_fixture import ROOT,command,fixture

IMAGE='grafana/grafana:13.2.3@sha256:b28bae15e219c998fb0e0424ed724930cc61b1f61fb404d47c862f9a23f9e572'


def inspect(name):
    return json.loads(command(['docker','inspect',name]))[0]


def run():
    name='ast-grafana-'+secrets.token_hex(6)
    application_port=int(os.environ.get('ASTERIUS_APPLICATION_PORT','9457'))
    source_port=int(os.environ.get('ASTERIUS_ACCEPTANCE_PORT','9456'))
    application='https://127.0.0.1:'+str(application_port)
    bridge=inspect('bridge')['IPAM']['Config'][0]['Gateway'];ipaddress.IPv4Address(bridge)
    started=False
    had_image=subprocess.run(['docker','image','inspect',IMAGE],capture_output=True).returncode==0
    with fixture(source_port,application+'/login/generic_oauth','grafana-confidential',hostname='host.docker.internal',bind=bridge) as source:
        root=source['root'];template=ROOT/'integrations/applications/grafana.ini.in'
        try:
            configuration=template.read_text()
            for key,value in {'APPLICATION_ORIGIN':application,'ISSUER':source['issuer'],
                              'CLIENT_ID':source['client_id'],'ALLOWED_SUB':source['approved_sub']}.items():
                configuration=configuration.replace('${'+key+'}',value)
            (root/'grafana.ini').write_text(configuration)
            (root/'application.crt').write_bytes((root/'ca.pem').read_bytes())
            (root/'application.key').write_bytes((root/'key.pem').read_bytes())
            (root/'source-ca.pem').write_bytes((root/'ca.pem').read_bytes())
            (root/'client.secret').write_text(source['secret'])
            (root/'application.secret').write_text(secrets.token_urlsafe(32))
            (root/'grafana-data').mkdir()
            mounts=[]
            for file in ['grafana.ini','application.crt','application.key','source-ca.pem','client.secret','application.secret']:
                mounts.extend(['--mount','type=bind,source='+str(root/file)+',target=/cfg/'+file+',readonly'])
            command(['docker','run','-d','--name',name,'--user',str(os.getuid())+':'+str(os.getgid()),
                     '--add-host','host.docker.internal:'+bridge,'-p','127.0.0.1:'+str(application_port)+':3000',
                     '--mount','type=bind,source='+str(root/'grafana-data')+',target=/data',*mounts,
                     '-e','SSL_CERT_FILE=/cfg/source-ca.pem','-e','GF_PATHS_CONFIG=/cfg/grafana.ini','-e','GF_PATHS_DATA=/data',
                     '-e','GF_PATHS_LOGS=/data/logs','-e','GF_PATHS_PLUGINS=/data/plugins',IMAGE]);started=True
            context=ssl.create_default_context(cafile=str(root/'ca.pem'))
            for _ in range(60):
                if not inspect(name)['State']['Running']:raise RuntimeError('owned Grafana exited')
                try:
                    with urllib.request.urlopen(application+'/api/health',context=context,timeout=1) as answer:
                        if answer.status==200:break
                except (urllib.error.URLError,TimeoutError):pass
                time.sleep(1)
            else:raise RuntimeError('owned Grafana not ready')
            browser_file=root/'browser.json';browser_file.write_text(json.dumps({'application':application,'issuer':source['issuer'],
                                                                                'bridge':bridge,'approvedSub':source['approved_sub']}))
            command(['node',str(ROOT/'scripts/integrations/grafana_browser.mjs'),str(browser_file)])
            browser=json.loads(browser_file.read_text())
            result={'date':date.today().isoformat(),'product':{'image':IMAGE,'digests':inspect(IMAGE)['RepoDigests'],
                    'version':command(['docker','exec',name,'grafana','--version']).strip()},
                    'asterius_binary_sha256':source['binary_sha256'],'configuration_sha256':hashlib.sha256(template.read_bytes()).hexdigest(),
                    'source':os.environ.get('ASTERIUS_ACCEPTANCE_REVISION','Asterius identified by binary SHA256'),
                    'native':browser,'profile':'explicit confidential standard OIDC; S256 PKCE; CA and ID-token verification; exact subject Viewer',
                    'limits':['no groups/PAR/FAPI/downstream DPoP claim','Bearer UserInfo is permitted only for this explicitly unbound standard OIDC client; no SCIM or management token reuse',
                              'source logout does not immediately revoke Grafana session; thirty second native session bound',
                              'fixture stable opaque subjects seeded only in its owned disposable DB; production obtains subjects from verified ID tokens'],
                    'cleanup':'owned Grafana container/database/source process/private temporary files removed'}
        except Exception:
            if started:
                logs=command(['docker','logs',name])
                markers=['role_attribute_strict','RoleAttributeStrict','role_attribute','Failed to get user info','Failed to extract','failed to verify','failed to validate','certificate','x509: certificate signed by unknown authority','invalid_client','email','JWT','jwk','signature','UserInfo','auth.oauth','invalid_token','Access denied','Login failed']
                print('PRODUCT_NATIVE_DIAGNOSTIC='+json.dumps([marker for marker in markers if marker.lower() in logs.lower()]),file=__import__('sys').stderr)
            raise
        finally:
            if started:command(['docker','container','rm','--force',name])
            if not had_image and started:command(['docker','image','rm',IMAGE])
    print(json.dumps(result,indent=2))


if __name__=='__main__':run()
