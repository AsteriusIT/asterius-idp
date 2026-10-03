#!/usr/bin/env python3
"""Real Argo CD OIDC/RBAC on a newly created, uniquely named disposable kind cluster."""
from datetime import date
import hashlib
import ipaddress
import json
import os
import secrets
import ssl
import time
import urllib.error
import urllib.request
from oidc_product_fixture import ROOT,command,fixture

VERSION='v3.5.3'
IMAGE='quay.io/argoproj/argocd:v3.5.3@sha256:dd3f47d5a5e4da563a7a398506e892481b358a7cec50abdf320c71aa55904bfa'
MANIFEST_URL='https://raw.githubusercontent.com/argoproj/argo-cd/'+VERSION+'/manifests/install.yaml'
MANIFEST_SHA256='7efe2d6bbc03f63623640f1e4198f16c84009d510fb810ef71e56df1b7614ba9'


def run():
    name='ast-app-argocd-'+secrets.token_hex(6);namespace='argocd';project='asterius-observer';application_name='native-fixture'
    application_port=int(os.environ.get('ASTERIUS_APPLICATION_PORT','9459'))
    source_port=int(os.environ.get('ASTERIUS_ACCEPTANCE_PORT','9458'))
    application='https://127.0.0.1:'+str(application_port)
    bridge=json.loads(command(['docker','inspect','bridge']))[0]['IPAM']['Config'][0]['Gateway'];ipaddress.IPv4Address(bridge)
    # This never reads or changes the user's current Kubernetes context.
    with fixture(source_port,application+'/auth/callback','argocd-confidential',hostname='host.docker.internal',bind=bridge) as source:
        root=source['root'];kubeconfig=root/'own-kubeconfig';created=False
        def kubectl(*args,body=None):
            return command(['kubectl','--kubeconfig',str(kubeconfig),'-n',namespace,*args],body)
        try:
            kind_config={'kind':'Cluster','apiVersion':'kind.x-k8s.io/v1alpha4','nodes':[{'role':'control-plane',
                         'extraPortMappings':[{'containerPort':30443,'hostPort':application_port,'listenAddress':'127.0.0.1','protocol':'TCP'}]}]}
            (root/'kind.json').write_text(json.dumps(kind_config));created=True
            command(['kind','create','cluster','--name',name,'--kubeconfig',str(kubeconfig),
                     '--image','kindest/node:v1.35.0','--config',str(root/'kind.json'),'--wait','90s'])
            command(['kubectl','--kubeconfig',str(kubeconfig),'create','namespace',namespace])
            manifest=urllib.request.urlopen(MANIFEST_URL,timeout=30).read()
            if hashlib.sha256(manifest).hexdigest()!=MANIFEST_SHA256:raise RuntimeError('official Argo install manifest hash changed')
            kubectl('apply','--server-side','-f','-',body=manifest.decode().replace('quay.io/argoproj/argocd:'+VERSION,IMAGE))
            # Identity/RBAC fixture only: no reconciliation, repository fetch, deployment or notifications.
            kubectl('scale','deployment','argocd-dex-server','argocd-repo-server','argocd-applicationset-controller',
                    'argocd-notifications-controller','--replicas=0')
            kubectl('scale','statefulset','argocd-application-controller','--replicas=0')
            template=ROOT/'integrations/applications/argocd-configmap.yaml.in';configuration=template.read_text()
            for key,value in {'NAMESPACE':namespace,'APPLICATION_ORIGIN':application,'ISSUER':source['issuer'],
                              'CLIENT_ID':source['client_id'],'ALLOWED_SUB':source['approved_sub'],'PROJECT':project,
                              'SOURCE_CA_INDENTED':'\n'.join('      '+line for line in (root/'ca.pem').read_text().splitlines())}.items():
                configuration=configuration.replace('${'+key+'}',value)
            kubectl('apply','-f','-',body=configuration)
            secret={'apiVersion':'v1','kind':'Secret','metadata':{'name':'asterius-oidc','namespace':namespace,
                    'labels':{'app.kubernetes.io/part-of':'argocd'}},'stringData':{'client-secret':source['secret']}}
            kubectl('apply','-f','-',body=json.dumps(secret))
            tls={'apiVersion':'v1','kind':'Secret','metadata':{'name':'argocd-server-tls','namespace':namespace},'type':'kubernetes.io/tls',
                 'stringData':{'tls.crt':(root/'ca.pem').read_text(),'tls.key':(root/'key.pem').read_text()}}
            kubectl('apply','-f','-',body=json.dumps(tls))
            server_patch={'spec':{'template':{'spec':{'hostAliases':[{'ip':bridge,'hostnames':['host.docker.internal']}],
                          'containers':[{'name':'argocd-server','args':['/usr/local/bin/argocd-server','--loglevel','warn']} ]}}}}
            kubectl('patch','deployment','argocd-server','--type','strategic','-p',json.dumps(server_patch))
            service_patch={'spec':{'type':'NodePort','ports':[{'name':'https','port':443,'targetPort':8080,'nodePort':30443}]}}
            kubectl('patch','service','argocd-server','--type','merge','-p',json.dumps(service_patch))
            objects={'apiVersion':'v1','kind':'List','items':[
                {'apiVersion':'argoproj.io/v1alpha1','kind':'AppProject','metadata':{'name':project,'namespace':namespace},
                 'spec':{'sourceRepos':[],'destinations':[]}},
                {'apiVersion':'argoproj.io/v1alpha1','kind':'Application','metadata':{'name':application_name,'namespace':namespace},
                 'spec':{'project':project,'source':{'repoURL':'https://example.invalid/no-fetch','path':'fixture','targetRevision':'HEAD'},
                         'destination':{'server':'https://kubernetes.default.svc','namespace':'unconfigured'}}}]}
            kubectl('apply','-f','-',body=json.dumps(objects))
            kubectl('rollout','status','deployment/argocd-redis','--timeout=90s')
            kubectl('rollout','status','deployment/argocd-server','--timeout=90s')
            context=ssl.create_default_context(cafile=str(root/'ca.pem'))
            for _ in range(60):
                try:
                    with urllib.request.urlopen(application+'/healthz',context=context,timeout=1) as answer:
                        if answer.status==200:break
                except (urllib.error.URLError,TimeoutError):pass
                time.sleep(1)
            else:raise RuntimeError('owned Argo server not ready')
            browser_file=root/'browser.json';browser_file.write_text(json.dumps({'application':application,'issuer':source['issuer'],
                         'bridge':bridge,'approvedSub':source['approved_sub'],'applicationName':application_name}))
            command(['node',str(ROOT/'scripts/integrations/argocd_browser.mjs'),str(browser_file)])
            native=json.loads(browser_file.read_text())
            pods=json.loads(kubectl('get','pods','-l','app.kubernetes.io/name=argocd-server','-o','json'))
            images=[{'image':c['image'],'imageID':c['imageID']} for p in pods['items'] for c in p['status']['containerStatuses']]
            with urllib.request.urlopen(application+'/api/version',context=context,timeout=5) as response:version=json.load(response)
            result={'date':date.today().isoformat(),'product':{'version':version,'images':images,'installManifestUrl':MANIFEST_URL,
                    'installManifestSha256':MANIFEST_SHA256},'asterius_binary_sha256':source['binary_sha256'],
                    'source':os.environ.get('ASTERIUS_ACCEPTANCE_REVISION','Asterius identified by binary SHA256'),
                    'configuration_sha256':hashlib.sha256(template.read_bytes()).hexdigest(),'native':native,
                    'profile':'explicit standard OIDC confidential client; S256; exact subject observer of one project; no group/admin mapping',
                    'limits':['no PAR/FAPI/CLI/public-client/downstream DPoP claim','source logout does not immediately revoke Argo access; use native /auth/logout, not legacy /api/v1/session DELETE; source JWT lifetime is recorded separately',
                              'fixture disables reconciliation/repository/notification controllers; tests real server OIDC and RBAC against seeded objects, not deployment'],
                    'cleanup':'only uniquely named owned kind cluster, isolated database/source process/keyfiles removed'}
        finally:
            if created:command(['kind','delete','cluster','--name',name,'--kubeconfig',str(kubeconfig)])
    print(json.dumps(result,indent=2))


if __name__=='__main__':run()
