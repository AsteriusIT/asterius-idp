#!/usr/bin/env python3
"""Owned fixture only: real Flux, controller Pods, Terraform and Asterius.

The unauthenticated Git HTTP endpoint exports generated PUBLIC manifests only.
It exists on the disposable Docker bridge for this acceptance, never production.
"""
import base64
import datetime
import hashlib
import http.server
import json
import os
import pathlib
import subprocess
import threading
import time
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUN = pathlib.Path(os.environ['ASTERIUS_OPERATOR_FIXTURE_DIR'])
NS = 'identity-e2e'
HOST = os.environ['ASTERIUS_OPERATOR_FIXTURE_HOST']
CLUSTER = os.environ['ASTERIUS_OPERATOR_CLUSTER']
ISSUER = os.environ['ASTERIUS_OPERATOR_ISSUER']
KUBECONFIG = str(RUN / 'kubeconfig')
FLUX_VERSION = '2.9.6'
FLUX_SHA256 = 'b4d22673e9246cbd628881f1a9ef3b090085dced291e42d804555cee8e8d42c5'
CHECKS = []
IMAGES = []


def execute(args, *, input=None, cwd=None, env=None, expected=0, timeout=180):
    result = subprocess.run(args, input=input, capture_output=True, cwd=cwd, env=env, timeout=timeout)
    if result.returncode not in (expected if isinstance(expected, tuple) else (expected,)):
        # Inputs/output may include Kubernetes credentials or Terraform state. Keep private.
        (RUN / 'failed-command.stdout').write_bytes(result.stdout)
        (RUN / 'failed-command.stderr').write_bytes(result.stderr)
        safe = (result.stderr+result.stdout).decode(errors='replace')[-2500:] if pathlib.Path(args[0]).name in ('helm','kind','go','terraform') else ''
        raise RuntimeError(f'{pathlib.Path(args[0]).name} {args[1:3]} exit {result.returncode}, expected {expected}; {safe}')
    return result.stdout + (result.stderr if expected == 1 else b'')


def kubectl(*args, input=None, expected=0):
    return execute(['kubectl', '--kubeconfig', KUBECONFIG, *args], input=input, expected=expected)


def apply(value):
    kubectl('apply', '-f', '-', input=json.dumps(value).encode())


def read(plural, name):
    return json.loads(kubectl('get', plural, name, '-n', NS, '-o', 'json'))


def wait(predicate, label, timeout=150):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(2)
    raise RuntimeError('bounded convergence deadline exceeded: ' + label)


def check(label):
    CHECKS.append(label)
    print('PASS ' + label, flush=True)


def ready(plural, name):
    obj = read(plural, name)
    return (bool(obj.get('status', {}).get('remoteId')) and obj.get('status', {}).get('observedGeneration') == obj['metadata']['generation'] and
            any(c['type'] == 'Ready' and c['status'] == 'True' for c in obj.get('status', {}).get('conditions', [])))


class PublicGit(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def serve(self):
        url = urllib.parse.urlsplit(self.path)
        if not url.path.startswith('/repo.git/'):
            self.send_error(404)
            return
        length = int(self.headers.get('Content-Length', '0'))
        if length < 0 or length > 4 * 1024 * 1024:
            self.send_error(413)
            return
        env = dict(os.environ, GIT_PROJECT_ROOT=str(RUN / 'git-public'), GIT_HTTP_EXPORT_ALL='1',
                   PATH_INFO=url.path, QUERY_STRING=url.query, REQUEST_METHOD=self.command,
                   CONTENT_TYPE=self.headers.get('Content-Type', ''), CONTENT_LENGTH=str(length),
                   REMOTE_ADDR=self.client_address[0])
        result = subprocess.run(['git', 'http-backend'], input=self.rfile.read(length), env=env,
                                capture_output=True, timeout=20)
        header, body = result.stdout.split(b'\r\n\r\n', 1)
        headers = [line.decode().split(':', 1) for line in header.split(b'\r\n')]
        status = next((int(value.split()[0]) for key, value in headers if key.lower() == 'status'), 200)
        self.send_response(status)
        for key, value in headers:
            if key.lower() != 'status':
                self.send_header(key, value.strip())
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = serve
    do_POST = serve


def main():
    # Build real plugins, no Rust build; container context contains no credentials.
    module = ROOT / 'providers/terraform'
    execute(['go', 'build', '-o', str(RUN / 'terraform-provider-asterius'), '.'], cwd=module)
    execute(['go', 'build', '-o', str(RUN / 'asterius-operator'), './cmd/asterius-operator'], cwd=module,
            env=dict(os.environ, CGO_ENABLED='0'))
    source = json.loads(execute(['node', '--input-type=module', '-e',
        "import{crds,examples}from'./tools/identity-operator/schema.mjs';console.log(JSON.stringify({crds,examples}));"], cwd=ROOT))
    apply({'apiVersion': 'v1', 'kind': 'List', 'items': source['crds']})
    kubectl('wait', '--for=condition=Established', 'crd/resources.identity.asterius.io', '--timeout=30s')
    apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NS}})
    binding = source['examples'][1]
    binding['metadata']['namespace'] = NS
    binding['spec'].update(tenantId='e2e', issuer=ISSUER, clientId='operator-controller', clusterId='gitops-controlled')
    apply(binding)
    binding_uid = read('asteriustenantbindings', 'default')['metadata']['uid']
    for name, key, file in [('asterius-auth-key', 'key.pem', 'controller.pem'), ('asterius-dpop-key', 'key.pem', 'dpop.pem'),
                            ('asterius-ca', 'ca.pem', 'ca.pem'), ('application-public-jwks', 'jwks.json', 'public-jwks.json')]:
        apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': NS},
               'data': {key: base64.b64encode((RUN / file).read_bytes()).decode()}})
    image_context = RUN / 'image-public'
    image_context.mkdir()
    (image_context / 'asterius-operator').write_bytes((RUN / 'asterius-operator').read_bytes())
    (image_context / 'asterius-operator').chmod(0o755)
    image_refs = []
    for revision in ('one', 'two'):
        tag = f'asterius-operator-gitops-{os.getpid()}:{revision}'
        # Two compatible packaging revisions of the actual binary. Not a claim
        # that arbitrary future CRD conversions or incompatible upgrades work.
        (image_context / 'Dockerfile').write_text(f'FROM scratch\nCOPY asterius-operator /asterius-operator\nLABEL acceptance.revision={revision}\nUSER 65532:65532\nENTRYPOINT ["/asterius-operator"]\n')
        execute(['docker', 'build', '-t', tag, str(image_context)])
        IMAGES.append(tag)
        execute(['kind', 'load', 'docker-image', '--name', CLUSTER, tag], timeout=180)
        entries = execute(['docker', 'exec', CLUSTER + '-control-plane', 'ctr', '-n', 'k8s.io', 'images', 'ls', '-q']).decode().splitlines()
        container_ref = next(ref for ref in entries if ref.endswith(tag))
        detailed = execute(['docker', 'exec', CLUSTER + '-control-plane', 'ctr', '-n', 'k8s.io', 'images', 'ls']).decode().splitlines()
        digest = next(line.split()[2] for line in detailed if line.split()[0] == container_ref)
        immutable = tag.split(':')[0] + '@' + digest
        execute(['docker', 'exec', CLUSTER + '-control-plane', 'ctr', '-n', 'k8s.io', 'images', 'tag', container_ref, 'docker.io/library/' + immutable])
        image_refs.append((tag.split(':')[0], digest))
    values = RUN / 'values-public.json'
    def install(image, upgrade=False):
        values.write_text(json.dumps({'replicas': 2, 'tenant': 'e2e', 'issuer': ISSUER, 'clientID': 'operator-controller',
            'keyID': 'operator-1', 'bindingUID': binding_uid, 'clusterID': 'gitops-controlled',
            'image': {'repository': image[0], 'digest': image[1]}}))
        execute(['helm', '--kubeconfig', KUBECONFIG, 'upgrade', '--install', 'identity', str(ROOT / 'charts/asterius-operator'),
                 '-n', NS, '-f', str(values), '--skip-crds', '--wait', '--timeout', '150s'], timeout=180)
    install(image_refs[0])
    check('real Helm chart Pods use immutable images and projected Kubernetes credentials')
    # Download one release with a checked, recorded digest. No unpinned curl|sh.
    archive = RUN / 'flux.tar.gz'
    urllib.request.urlretrieve(f'https://github.com/fluxcd/flux2/releases/download/v{FLUX_VERSION}/flux_{FLUX_VERSION}_linux_amd64.tar.gz', archive)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == FLUX_SHA256
    execute(['tar', '-xzf', str(archive), '-C', str(RUN), 'flux'])
    flux = str(RUN / 'flux')
    raw = execute([flux, 'install', '--export', '--version', 'v'+FLUX_VERSION, '--components=source-controller,kustomize-controller', '--network-policy=false', '--watch-all-namespaces=true'])
    kubectl('apply', '-f', '-', input=raw)
    kubectl('rollout', 'status', 'deployment/source-controller', '-n', 'flux-system', '--timeout=180s')
    kubectl('rollout', 'status', 'deployment/kustomize-controller', '-n', 'flux-system', '--timeout=180s')
    apply({'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'identity-gitops', 'namespace': NS}})
    apply({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': {'name': 'identity-gitops', 'namespace': NS},
        'rules': [{'apiGroups':['identity.asterius.io'], 'resources':['applications','resources','policies'],
                   'verbs':['get','list','watch','create','patch','update','delete']},
                  {'apiGroups':['identity.asterius.io'],'resources':['asteriustenantbindings'],'resourceNames':['default'],'verbs':['get']}]})
    apply({'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': {'name':'identity-gitops','namespace':NS},
        'subjects':[{'kind':'ServiceAccount','name':'identity-gitops','namespace':NS}],
        'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':'identity-gitops'}})
    for verb, resource, extra in [('get','secrets',[]),('update','asteriustenantbindings.identity.asterius.io',[]),('patch','resources.identity.asterius.io',['--subresource=status'])]:
        assert kubectl('auth','can-i',verb,resource,'-n',NS,'--as=system:serviceaccount:'+NS+':identity-gitops',*extra,expected=(0,1)).strip() == b'no'
    check('Flux delivery ServiceAccount cannot read credentials, change binding or write status')
    public_git = RUN / 'git-public'
    public_git.mkdir()
    working = RUN / 'git-work-public'
    execute(['git', 'init', '-b', 'main', str(working)])
    execute(['git', 'init', '--bare', str(public_git / 'repo.git')])
    execute(['git', 'remote', 'add', 'origin', str(public_git / 'repo.git')], cwd=working)
    (working/'kustomization.yaml').write_text('apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [resources.json]\n')
    desired = source['examples'][2:]
    for obj in desired:
        obj['metadata']['namespace'] = NS
        if obj['kind'] == 'Application':
            del obj['spec']['jwksUri']
            obj['spec']['publicJwksSecretRef'] = {'name':'application-public-jwks','key':'jwks.json'}
    def commit(label):
        (working / 'resources.json').write_text(json.dumps({'apiVersion':'v1','kind':'List','items':desired}))
        execute(['git','add','resources.json','kustomization.yaml'],cwd=working)
        execute(['git','-c','user.name=Disposable acceptance','-c','user.email=acceptance@example.test','commit','-m',label],cwd=working)
        execute(['git','push','origin','main'],cwd=working)
        execute(['git','--git-dir',str(public_git/'repo.git'),'symbolic-ref','HEAD','refs/heads/main'])
        return execute(['git','rev-parse','HEAD'],cwd=working).decode().strip()
    commit('initial public resources')
    server = http.server.ThreadingHTTPServer((HOST, 9462), PublicGit)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    apply({'apiVersion':'source.toolkit.fluxcd.io/v1','kind':'GitRepository','metadata':{'name':'identity','namespace':NS},
        'spec':{'interval':'5s','url':f'http://{HOST}:9462/repo.git','ref':{'branch':'main'},'timeout':'20s'}})
    apply({'apiVersion':'kustomize.toolkit.fluxcd.io/v1','kind':'Kustomization','metadata':{'name':'identity','namespace':NS},
        'spec':{'interval':'5s','retryInterval':'5s','timeout':'30s','path':'./','prune':True,'targetNamespace':NS,
                'serviceAccountName':'identity-gitops','sourceRef':{'kind':'GitRepository','name':'identity'},
                'wait':False}})
    kinds = [('applications','billing'),('resources','billing'),('policies','tenant')]
    def all_ready():
        # The GitOps delivery can still be creating CRDs on the first polls.
        result = kubectl('get','applications,resources,policies','-n',NS,'-o','json')
        objects = json.loads(result)['items']
        return len(objects)==3 and all(ready(*item) for item in kinds)
    wait(all_ready,'Flux public delivery and controller convergence')
    ids = {plural: read(plural,name)['status']['remoteId'] for plural,name in kinds}
    check('real Flux GitRepository and Kustomization deliver all three identity kinds')
    # Public Terraform config; credentials remain external files/environment.
    tfdir = RUN / 'terraform-private'
    tfdir.mkdir()
    rc = RUN / 'terraform.rc'
    rc.write_text('provider_installation {\n dev_overrides {\n  "registry.terraform.io/asterius/asterius" = '+json.dumps(str(RUN))+'\n }\n direct {}\n}\n')
    scopes = 'admin.session:read admin.resource_servers:read admin.resource_servers:write'
    env = {k:v for k,v in os.environ.items() if not k.startswith('TF_LOG') and not k.startswith('ASTERIUS_TARGET_')}
    env.update(TF_CLI_CONFIG_FILE=str(rc),TF_IN_AUTOMATION='1',CHECKPOINT_DISABLE='1',ASTERIUS_ISSUER=ISSUER,
        ASTERIUS_CLIENT_ID='terraform-other-controller',ASTERIUS_SIGNING_KEY_FILE=str(RUN/'controller.pem'),
        ASTERIUS_SIGNING_KEY_ID='operator-1',ASTERIUS_CA_FILE=str(RUN/'ca.pem'),
        ASTERIUS_TOKEN_RESOURCE=ISSUER+'/admin/api/v1',ASTERIUS_SCOPES=scopes)
    tf_spec={'identifier':'https://billing-api.example/','scopes':['read','write'],'default_token_lifetime_seconds':300,'introspection_clients':[]}
    def tfconfig(spec, retain=False, adopt=False):
        (tfdir/'main.tf').write_text('terraform {\n required_providers {\n  asterius = { source = "asterius/asterius" }\n }\n}\nprovider "asterius" {}\nresource "asterius_resource" "imported" {\n spec_json = '+json.dumps(json.dumps(spec,sort_keys=True,separators=(',',':')))+'\n retain_on_delete = '+str(retain).lower()+'\n adopt = '+str(adopt).lower()+'\n}\n')
    def tf(expected,*args):
        return execute(['terraform',*args],cwd=tfdir,env=env,expected=expected)
    tfconfig(tf_spec)
    tf(0,'import','-input=false','asterius_resource.imported',ids['resources'])
    imported=json.loads(tf(0,'show','-json'))['values']['root_module']['resources'][0]['values']
    tf_spec=json.loads(imported['observed_spec_json'])
    tfconfig(tf_spec)
    tf(0,'plan','-input=false','-detailed-exitcode')
    check('real Terraform imports the operator-owned immutable ID and produces an empty read plan')
    tf_spec['default_token_lifetime_seconds']=301
    tfconfig(tf_spec)
    refused=tf(1,'apply','-auto-approve','-input=false')
    assert b'Controller ownership conflict' in refused
    check('real Terraform apply visibly rejects a different controller owner')
    tf_spec['default_token_lifetime_seconds']=300
    tfconfig(tf_spec)
    def reviewed_generation(lifetime):
        resource=next(o for o in desired if o['kind']=='Resource')
        resource['spec']['defaultTokenLifetimeSeconds']=lifetime
        commit('reviewed convergence proof '+str(lifetime))
        wait(lambda:read('resources','billing')['spec']['defaultTokenLifetimeSeconds']==lifetime and all_ready(),'fresh observed generation')
        tf_spec['default_token_lifetime_seconds']=lifetime
        tfconfig(tf_spec)
    kubectl('rollout','restart','deployment/asterius-controller','-n',NS)
    kubectl('rollout','status','deployment/asterius-controller','-n',NS,'--timeout=150s')
    reviewed_generation(301)
    assert ids=={p:read(p,n)['status']['remoteId'] for p,n in kinds}
    tf(0,'plan','-input=false','-detailed-exitcode')
    check('controller restart preserves all remote identity references and empty Terraform plans')
    install(image_refs[1],True)
    reviewed_generation(302)
    assert ids=={p:read(p,n)['status']['remoteId'] for p,n in kinds}
    tf(0,'plan','-input=false','-detailed-exitcode')
    execute(['helm','--kubeconfig',KUBECONFIG,'rollback','identity','1','-n',NS,'--wait','--timeout','150s'])
    reviewed_generation(303)
    assert ids=={p:read(p,n)['status']['remoteId'] for p,n in kinds}
    tf(0,'plan','-input=false','-detailed-exitcode')
    check('compatible image upgrade and Helm rollback preserve IDs and empty plans')
    # Recover a lost status remoteId by exact external_key; original UID survives.
    old=read('resources','billing');uid=old['metadata']['uid']
    kubectl('patch','resources','billing','-n',NS,'--subresource=status','--type=merge','-p','{"status":{"remoteId":null,"remoteRevision":null}}')
    wait(lambda:ready('resources','billing') and read('resources','billing').get('status',{}).get('remoteId')==ids['resources'],'lost status recovery')
    assert read('resources','billing')['metadata']['uid']==uid
    check('lost remoteId status recovers the existing logical-key identity without recreation')
    # Flux pruning a Delete object whose protection is still enabled must wait.
    resource=next(o for o in desired if o['kind']=='Resource')
    resource['spec']['deletionPolicy']='Delete'
    commit('explicit delete policy, keep protection')
    wait(lambda:read('resources','billing')['spec']['deletionPolicy']=='Delete' and ready('resources','billing'),'protected delete intent')
    desired.remove(resource)
    commit('prune protected resource')
    wait(lambda:bool(read('resources','billing')['metadata'].get('deletionTimestamp')),'Flux requested delete')
    wait(lambda:any(c['type']=='Deleting' and c['reason']=='DeleteProtectionRequiresPriorGeneration' for c in read('resources','billing').get('status',{}).get('conditions',[])),'protected deletion denial')
    assert read('resources','billing').get('status',{}).get('remoteId')==ids['resources']
    tf(0,'plan','-input=false','-detailed-exitcode')
    check('Flux pruning cannot remove a protected remote object or its finalizer')
    # Restore the public manifest: the Kubernetes incarnation is deleting and
    # cannot be revived. Stop reconciliation, explicitly retain and complete
    # release; re-create with importId and reviewed adoption to preserve ID.
    kubectl('patch','kustomizations.kustomize.toolkit.fluxcd.io','identity','-n',NS,'--type=merge','-p','{"spec":{"suspend":true}}')
    resource['spec']['deletionPolicy']='Retain'
    desired.append(resource)
    kubectl('patch','resources','billing','-n',NS,'--type=merge','-p','{"spec":{"deletionPolicy":"Retain"}}')
    wait(lambda:not json.loads(kubectl('get','resources','-n',NS,'-o','json'))['items'],'retained deletion completes')
    resource['spec']['importId']=ids['resources']
    resource['spec']['adoptionPolicy']='AdoptUnowned'
    commit('explicitly adopt retained resource into new Kubernetes incarnation')
    kubectl('patch','kustomizations.kustomize.toolkit.fluxcd.io','identity','-n',NS,'--type=merge','-p','{"spec":{"suspend":false}}')
    wait(lambda:len(json.loads(kubectl('get','resources','-n',NS,'-o','json'))['items'])==1 and ready('resources','billing'),'retained recovery re-adoption')
    assert read('resources','billing').get('status',{}).get('remoteId')==ids['resources']
    assert read('resources','billing')['metadata']['uid']!=uid
    tf(0,'plan','-input=false','-detailed-exitcode')
    check('reviewed Retain and explicit import adoption recover a new Kubernetes incarnation with the original remote ID')
    evidence={'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'ticket':'ast-dd1y.3.6',
        'target':{'kubernetes':'1.35.0','flux':FLUX_VERSION,'terraform':json.loads(execute(['terraform','version','-json']))['terraform_version'],
                  'helm':execute(['helm','version','--short']).decode().strip(),'operator_chart':'0.1.0','management_api':1,'crd_api':'identity.asterius.io/v1alpha1'},
        'asterius_binary_sha256':os.environ['ASTERIUS_OPERATOR_BINARY_SHA256'],'checks':CHECKS,
        'limits':['compatible packaging upgrade of the same controller binary; no incompatible CRD conversion claim',
                  'local public Git HTTP fixture; production Git authentication/TLS remain infrastructure configuration']}
    (RUN/'public-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
    server.shutdown()


if __name__ == '__main__':
    try:
        main()
    finally:
        for image in IMAGES:
            subprocess.run(['docker','image','rm',image],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
