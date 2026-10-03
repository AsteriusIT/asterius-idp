#!/usr/bin/env python3
"""Native Harbor stack, prepared from the official pinned installer, own resources only."""
import base64
from datetime import date
import hashlib
import io
import ipaddress
import json
import os
import re
from pathlib import Path
import secrets
import ssl
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
import yaml
from oidc_product_fixture import ROOT,command,fixture

VERSION='v2.15.2'
INSTALLER_URL='https://github.com/goharbor/harbor/releases/download/'+VERSION+'/harbor-online-installer-'+VERSION+'.tgz'
INSTALLER_SHA256='88f6a7436b31890e8e472972a7433d36b7d6a36de9adeb86337fdc9fe7fb5fa3'
PREPARE='goharbor/prepare:v2.15.2@sha256:5b9428fb649b3a0e0fe497189a880d7c9f1281538b85de9ad377cb524e427bd5'


def inspect(name):
    return json.loads(command(['docker','inspect',name]))[0]


def run():
    name='ast-harbor-'+secrets.token_hex(6);project='native-private-fixture'
    application_port=int(os.environ.get('ASTERIUS_APPLICATION_PORT','9461'))
    source_port=int(os.environ.get('ASTERIUS_ACCEPTANCE_PORT','9460'))
    application='https://127.0.0.1:'+str(application_port)
    bridge=inspect('bridge')['IPAM']['Config'][0]['Gateway'];ipaddress.IPv4Address(bridge)
    compose_started=False;prepared=False;new_images=[]
    if subprocess.run(['docker','image','inspect',PREPARE],capture_output=True).returncode:
        new_images.append(PREPARE)
    with fixture(source_port,application+'/c/oidc/callback','harbor-confidential',hostname='host.docker.internal',bind=bridge) as source:
        root=source['root'];bundle=root/'harbor';bundle.mkdir();data=root/'harbor-data';data.mkdir()
        compose_file=bundle/'docker-compose.json'
        def compose(*args):
            result=subprocess.run(['docker','compose','--project-name',name,'--file',str(compose_file),*args],capture_output=True,text=True,timeout=300)
            if result.returncode:
                terms=['invalid','network','service','schema','version','env','open','denied','permission','image','digest','reference','interpolation','not found','logging','health','mount','certificate','exit','format','user','read','parse','pull','database','core','proxy','redis','registry','port','address','allocated']
                classification=[word for word in terms if word in result.stderr.lower()]
                raise RuntimeError('native compose failed; safe classification='+json.dumps(classification))
            return result.stdout
        try:
            archive=urllib.request.urlopen(INSTALLER_URL,timeout=30).read()
            if hashlib.sha256(archive).hexdigest()!=INSTALLER_SHA256:raise RuntimeError('official Harbor installer hash changed')
            # Read one fixed public template, without executing installer scripts or extracting archive paths.
            with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as installer:
                config=yaml.safe_load(installer.extractfile('harbor/harbor.yml.tmpl').read())
            admin_password=secrets.token_urlsafe(32)
            config.update({'hostname':'host.docker.internal','external_url':application,'data_volume':str(data),
                           'harbor_admin_password':admin_password,'https':{'port':application_port,'certificate':str(root/'ca.pem'),'private_key':str(root/'key.pem')},
                           'log':{'level':'warning','local':{'location':str(root/'harbor-logs'),'rotate_count':1,'rotate_size':'5M'}}})
            config['database'].update({'password':secrets.token_urlsafe(32),'max_idle_conns':2,'max_open_conns':10})
            input_dir=bundle/'input';input_dir.mkdir();(input_dir/'harbor.yml').write_text(yaml.safe_dump(config))
            config_dir=bundle/'common/config';config_dir.mkdir(parents=True)
            mounts=[]
            for host,target in [(input_dir,'/input'),(data,'/data'),(bundle,'/compose_location'),(config_dir,'/config'),(root,'/hostfs'+str(root))]:
                mounts.extend(['--mount','type=bind,source='+str(host)+',target='+target])
            prepared=True
            command(['docker','run','--rm',*mounts,PREPARE,'prepare'],timeout=300)
            compose_config=yaml.safe_load((bundle/'docker-compose.yml').read_text())
            compose_config['services'].pop('log',None)
            for key,service in compose_config['services'].items():
                digest=command(['docker','buildx','imagetools','inspect',service['image'],'--format','{{.Manifest.Digest}}']).strip()
                if not re.fullmatch(r'sha256:[a-f0-9]{64}',digest):raise RuntimeError('native image manifest digest unavailable')
                service['image']+='@'+digest
                if subprocess.run(['docker','image','inspect',service['image']],capture_output=True).returncode:
                    new_images.append(service['image'])
                service['container_name']=name+'-'+key
                service['restart']='on-failure:10'
                service['logging']={'driver':'json-file','options':{'max-size':'5m','max-file':'1'}}
                service.pop('ports',None)
                if service.get('links'):service['links']=[link for link in service['links'] if link.split(':')[0]!='log']
                if isinstance(service.get('depends_on'),list):service['depends_on']=[d for d in service['depends_on'] if d!='log']
                elif isinstance(service.get('depends_on'),dict):service['depends_on'].pop('log',None)
                # Every filesystem mount must remain beneath this fixture's private directory.
                for volume in service.get('volumes',[]):
                    host=volume.get('source') if isinstance(volume,dict) else volume.split(':',1)[0]
                    path=(bundle/host).resolve() if not Path(host).is_absolute() else Path(host).resolve()
                    if not path.is_relative_to(root):raise RuntimeError('Harbor generated mount outside owned fixture')
            compose_config['services']['proxy']['ports']=['127.0.0.1:'+str(application_port)+':8443']
            compose_config['services']['core']['extra_hosts']=['host.docker.internal:'+bridge]
            compose_config['networks']={'harbor':{'name':name+'-network'}}
            env_files=[]
            for service in compose_config['services'].values():
                declared=service.get('env_file',[])
                if isinstance(declared,str):declared=[declared]
                for entry in declared:
                    host=entry['path'] if isinstance(entry,dict) else entry
                    path=(bundle/host).resolve()
                    if not path.is_relative_to(root):raise RuntimeError('native env file outside owned fixture')
                    env_files.append('/owned/'+str(path.relative_to(root)))
            # Read native env files privately into separate host-readable copies.
            # Keep product-owned config permissions unchanged for native entrypoints.
            env_code="import json;from pathlib import Path;paths=json.loads("+repr(json.dumps(env_files))+");print(json.dumps({p:Path(p).read_text() for p in paths}))"
            native_env=json.loads(command(['docker','run','--rm','--entrypoint','python3','--mount','type=bind,source='+str(root)+',target=/owned',PREPARE,'-c',env_code]))
            readable=root/'compose-env';readable.mkdir()
            copied={}
            for index,(path,contents) in enumerate(native_env.items()):
                destination=readable/str(index);destination.write_text(contents);destination.chmod(0o600);copied[path]=str(destination)
            for service in compose_config['services'].values():
                declared=service.get('env_file',[])
                if isinstance(declared,str):declared=[declared]
                if declared:
                    service['env_file']=[copied['/owned/'+str((bundle/(entry['path'] if isinstance(entry,dict) else entry)).resolve().relative_to(root))] for entry in declared]
            compose_file.write_text(json.dumps(compose_config))
            # Native prepare owns generated directories; copy public CA with the same
            # native helper, confined to this owned fixture mount.
            trust_code="from pathlib import Path;p=Path('/owned/harbor/common/config/shared/trust-certificates');p.mkdir(parents=True,exist_ok=True);f=p/'asterius.crt';f.write_bytes(Path('/owned/ca.pem').read_bytes());f.chmod(0o644)"
            command(['docker','run','--rm','--entrypoint','python3','--mount','type=bind,source='+str(root)+',target=/owned',PREPARE,'-c',trust_code])
            data_code="import os;os.chown('/owned/harbor-data',10000,10000);os.chmod('/owned/harbor-data',0o755)"
            command(['docker','run','--rm','--entrypoint','python3','--mount','type=bind,source='+str(root)+',target=/owned',PREPARE,'-c',data_code])
            compose_started=True;compose('up','--detach')
            context=ssl.create_default_context(cafile=str(root/'ca.pem'))
            for _ in range(180):
                try:
                    with urllib.request.urlopen(application+'/api/v2.0/systeminfo',context=context,timeout=1) as response:
                        if response.status==200:version=json.load(response);break
                except (urllib.error.URLError,TimeoutError):pass
                time.sleep(1)
            else:raise RuntimeError('owned Harbor not ready')
            authorization='Basic '+base64.b64encode(('admin:'+admin_password).encode()).decode()
            def admin_api(method,path,body):
                request=urllib.request.Request(application+path,data=json.dumps(body).encode(),method=method,
                                               headers={'Authorization':authorization,'Content-Type':'application/json'})
                with urllib.request.urlopen(request,context=context,timeout=30) as response:return response.status
            if admin_api('POST','/api/v2.0/projects',{'project_name':project,'metadata':{'public':'false'}})!=201:
                raise RuntimeError('own private project creation failed')
            template=ROOT/'integrations/applications/harbor-oidc.json.in';oidc=template.read_text()
            for key,value in {'ISSUER':source['issuer'],'CLIENT_ID':source['client_id']}.items():oidc=oidc.replace('${'+key+'}',value)
            oidc=json.loads(oidc);oidc['oidc_client_secret']=source['secret'];oidc['project_creation_restriction']='adminonly'
            if admin_api('PUT','/api/v2.0/configurations',oidc)!=200:raise RuntimeError('owned OIDC setup failed')
            browser_file=root/'browser.json';browser_file.write_text(json.dumps({'application':application,'issuer':source['issuer'],
                         'bridge':bridge,'approvedSub':source['approved_sub'],'project':project,'adminPassword':admin_password}))
            browser_file.chmod(0o600)
            command(['node',str(ROOT/'scripts/integrations/harbor_browser.mjs'),str(browser_file)])
            native=json.loads(browser_file.read_text())
            images=[]
            for key,service in compose_config['services'].items():
                state=inspect(service['container_name']);image=inspect(state['Image'])
                images.append({'service':key,'image':service['image'],'imageID':state['Image'],'digests':image.get('RepoDigests',[]),'status':state['State']['Status'],'health':state['State'].get('Health',{}).get('Status'),'restart_count':state.get('RestartCount',0)})
            result={'date':date.today().isoformat(),'product':{'harbor_version':native['runtimeVersion'],'images':images,
                    'installer_url':INSTALLER_URL,'installer_sha256':INSTALLER_SHA256},
                    'asterius_binary_sha256':source['binary_sha256'],'source':os.environ.get('ASTERIUS_ACCEPTANCE_REVISION','Asterius identified by binary SHA256'),
                    'configuration_sha256':hashlib.sha256(template.read_bytes()).hexdigest(),'native':native,
                    'profile':'explicit confidential standard OIDC; native S256 PKCE; local Guest membership; no admin/group mapping',
                    'limits':['no PAR/FAPI/CLI-secret/registry-push/downstream DPoP claim','source logout alone does not immediately revoke Harbor session',
                              'native Bearer UserInfo permitted only for this explicit unbound standard OIDC client; no SCIM or management token reuse','OIDC local logout chosen; no source-wide logout/revocation claim'],
                    'cleanup':'only own Harbor compose containers/network/data, isolated DB/source process/private keyfiles removed'}
        except Exception:
            if compose_started:
                states=[]
                for key,service in compose_config['services'].items():
                    probe=subprocess.run(['docker','inspect',service['container_name']],capture_output=True,text=True)
                    if probe.returncode:continue
                    state=json.loads(probe.stdout)[0]['State']
                    logs=subprocess.run(['docker','logs',service['container_name']],capture_output=True,text=True)
                    terms=['permission denied','connection refused','no such file','failed to','fatal','panic','certificate','database','secret','config','read-only','unhealthy','timeout','error','failed opening','appendonly','dump.rdb','/etc/valkey','/etc/redis','/var/lib/redis','/var/lib/valkey','changing directory','read-only file system','unable to open']
                    image=inspect(service['image']);permissions=[]
                    for volume in service.get('volumes',[]):
                        host=volume.get('source') if isinstance(volume,dict) else volume.split(':',1)[0]
                        target=volume.get('target') if isinstance(volume,dict) else volume.split(':')[1]
                        path=(bundle/host).resolve() if not Path(host).is_absolute() else Path(host).resolve()
                        if path.is_relative_to(root) and path.exists():
                            info=path.stat();permissions.append({'target':target,'uid':info.st_uid,'gid':info.st_gid,'mode':oct(info.st_mode&0o777)})
                    states.append({'service':key,'imageUser':image['Config']['User'],'mountPermissions':permissions,'status':state['Status'],'exitCode':state['ExitCode'],'health':state.get('Health',{}).get('Status'),
                                   'safeLogMarkers':[term for term in terms if term in (logs.stdout+logs.stderr).lower()]})
                print('PRODUCT_NATIVE_DIAGNOSTIC='+json.dumps(states),file=__import__('sys').stderr)
            raise
        finally:
            if compose_started:compose('down','--volumes','--remove-orphans','--timeout','5')
            if prepared:
                # Native database files have product UIDs. Restore only this owned directory's ownership for cleanup.
                code="import os;root='/owned';uid="+str(os.getuid())+";gid="+str(os.getgid())+";\nfor base,dirs,files in os.walk(root,followlinks=False):\n os.chown(base,uid,gid,follow_symlinks=False)\n for item in dirs+files:os.chown(os.path.join(base,item),uid,gid,follow_symlinks=False)"
                command(['docker','run','--rm','--entrypoint','python3','--mount','type=bind,source='+str(root)+',target=/owned',PREPARE,'-c',code])
            for image in reversed(new_images):
                # No force: another container/reference can safely retain a shared layer.
                subprocess.run(['docker','image','rm',image],capture_output=True,timeout=30)
    print(json.dumps(result,indent=2))


if __name__=='__main__':run()
