#!/usr/bin/env python3
"""Real OAuth2 Proxy + Envoy topology, owned containers/networks/database only."""
from datetime import date
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import ssl
import time
import tomllib
import urllib.error
import urllib.request
from oidc_product_fixture import ROOT,command,fixture

PROXY='quay.io/oauth2-proxy/oauth2-proxy:v7.15.5@sha256:8498b0d0ef0a7b29686414000a08aee467f02d0299c9ed1e006a8f33fc017916'
EDGE='envoyproxy/envoy:v1.39.1@sha256:57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4'
BACKEND='python:3.13-alpine3.20'


def inspect(name):
    return json.loads(command(['docker','inspect',name]))[0]


def run():
    suffix='ast-gateway-'+secrets.token_hex(6)
    front=suffix+'-front';back=suffix+'-back';containers=[];networks=[]
    gateway_port=int(os.environ.get('ASTERIUS_GATEWAY_PORT','9455'))
    source_port=int(os.environ.get('ASTERIUS_ACCEPTANCE_PORT','9454'))
    gateway='https://127.0.0.1:'+str(gateway_port)
    bridge=inspect('bridge')['IPAM']['Config'][0]['Gateway']
    ipaddress.IPv4Address(bridge)
    uid=str(os.getuid())+':'+str(os.getgid())
    with fixture(source_port,gateway+'/oauth2/callback','gateway-confidential',hostname='host.docker.internal',bind=bridge) as source:
        root=source['root'];cases=[]
        def mount(file):
            return ['--mount','type=bind,source='+str(root/file)+',target=/cfg/'+file+',readonly']
        def launch(name,image,args,network,alias,files,extra=()):
            command(['docker','run','-d','--name',name,'--network',network,'--network-alias',alias,
                     '--user',uid,*extra,*sum((mount(f) for f in files),[]),image,*args])
            containers.append(name)
        try:
            for network,internal in ((front,False),(back,True)):
                command(['docker','network','create',*(['--internal'] if internal else []),network]);networks.append(network)
            (root/'backend.py').write_text((ROOT/'scripts/integrations/gateway_backend.py').read_text())
            launch(suffix+'-app',BACKEND,['python','/cfg/backend.py'],back,'backend',['backend.py'])
            envoy=(ROOT/'integrations/gateway/envoy.yaml.in').read_text().replace('${GATEWAY_AUTHORITY}','127.0.0.1:'+str(gateway_port))
            (root/'envoy.yaml').write_text(envoy)
            (root/'gateway.crt').write_bytes((root/'ca.pem').read_bytes())
            (root/'gateway.key').write_bytes((root/'key.pem').read_bytes())
            launch(suffix+'-edge',EDGE,['-c','/cfg/envoy.yaml','--log-level','error'],front,'edge',
                   ['envoy.yaml','gateway.crt','gateway.key'],['-p','127.0.0.1:'+str(gateway_port)+':8443'])
            edge_ip=inspect(suffix+'-edge')['NetworkSettings']['Networks'][front]['IPAddress']
            ipaddress.IPv4Address(edge_ip)
            proxy=(ROOT/'integrations/gateway/oauth2-proxy.cfg.in').read_text()
            for name,value in {'GATEWAY_ORIGIN':gateway,'ASTERIUS_ISSUER':source['issuer'],
                               'ASTERIUS_CLIENT_ID':source['client_id'],'EXACT_EDGE_PROXY_IP':edge_ip}.items():
                proxy=proxy.replace('${'+name+'}',value)
            tomllib.loads(proxy)
            (root/'oauth.cfg').write_text(proxy);(root/'client.secret').write_text(source['secret'])
            (root/'cookie.secret').write_bytes(secrets.token_bytes(32))
            (root/'allowed-emails').write_text('sweep@example.test\n')
            launch(suffix+'-oauth',PROXY,['--config','/cfg/oauth.cfg'],front,'oauth2',
                   ['oauth.cfg','ca.pem','client.secret','cookie.secret','allowed-emails'],
                   ['--add-host','host.docker.internal:'+bridge])
            command(['docker','network','connect',back,suffix+'-oauth'])
            context=ssl.create_default_context(cafile=str(root/'ca.pem'))
            for _ in range(60):
                if not all(inspect(c)['State']['Running'] for c in containers):raise RuntimeError('owned gateway container exited')
                try:
                    with urllib.request.urlopen(gateway+'/ping',context=context,timeout=1) as answer:
                        if answer.status==200:break
                except (urllib.error.URLError,TimeoutError):pass
                time.sleep(1)
            else:raise RuntimeError('owned gateway not ready')
            app=inspect(suffix+'-app');proxy_state=inspect(suffix+'-oauth')
            if any((app['NetworkSettings']['Ports'] or {}).values()) or any((proxy_state['NetworkSettings']['Ports'] or {}).values()):
                raise RuntimeError('backend/proxy unexpectedly published')
            if set(app['NetworkSettings']['Networks'])!={back}:
                raise RuntimeError('backend joined exposed network')
            backend_ip=app['NetworkSettings']['Networks'][back]['IPAddress']
            healthy="import urllib.request;assert urllib.request.urlopen('http://backend:8080/',timeout=3).status==200"
            command(['docker','run','--rm','--network',back,BACKEND,'python','-c',healthy])
            cases.append({'case':'private backend-network readiness control','status':200})
            probe="import urllib.request,urllib.error;\ntry: urllib.request.urlopen('http://"+backend_ip+":8080',timeout=2);raise SystemExit(1)\nexcept (urllib.error.URLError,TimeoutError):pass"
            command(['docker','run','--rm','--network',front,BACKEND,'python','-c',probe])
            cases.append({'case':'direct backend network access from frontend denied','result':'PASS'})
            cases.append({'case':'backend and OAuth2 Proxy have no host ports','result':'PASS'})
            browser_file=root/'browser.json'
            browser_file.write_text(json.dumps({'gateway':gateway,'issuer':source['issuer'],'bridge':bridge}))
            command(['node',str(ROOT/'scripts/integrations/gateway_browser.mjs'),str(browser_file)])
            browser=json.loads(browser_file.read_text())
            cases.extend(browser.pop('cases'))
            products=[]
            for image,arguments in ((PROXY,['--version']),(EDGE,['--version'])):
                products.append({'image':image,'digests':inspect(image)['RepoDigests'],
                                 'version':command(['docker','run','--rm',image,*arguments]).strip()})
            result={'date':date.today().isoformat(),'source':os.environ.get('ASTERIUS_ACCEPTANCE_REVISION','Asterius identified by binary SHA256'),'asterius_binary_sha256':source['binary_sha256'],
                    'products':products,'configuration_sha256':{str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted((ROOT/'integrations/gateway').glob('*.in'))},'cases':cases,'browser':browser,
                    'profile':'explicit standard OIDC confidential client; S256 PKCE/nonce/ES256; no upstream OAuth token delegation',
                    'limits':['source logout does not immediately revoke cached gateway cookie; fixture expiry30seconds bounds it',
                              'no group scope/mapping requested or authorization configured; native product can forward issuer groups if later added; backend trusts verified user/email only',
                              'host/Docker administrators and authenticated backend are trusted; isolation is not a sandbox against its owner',
                              'login callback CSRF and cross-site cookie withholding tested; application mutation CSRF is still the application responsibility',
                              'native proxy forwards sensitive gateway session cookie to trusted backend; backend must protect it from logs/disclosure/reuse'],
                    'cleanup':'only owned Docker containers/networks/database/process/keyfiles removed'}
        finally:
            for name in reversed(containers):command(['docker','container','rm','--force',name])
            for network in reversed(networks):command(['docker','network','rm',network])
    print(json.dumps(result,indent=2))


if __name__=='__main__':run()
