#!/usr/bin/env python3
"""Real native Kubernetes temporary RBAC and signed code/refresh fixture using seeded PG proofs.
The fixture does not claim a fresh WebAuthn ceremony: proof provenance is seeded
explicitly, while auth-code/PAR/PKCE/private_key_jwt/DPoP and lifecycle are real.
Only aggregate control names are emitted, never sessions, tokens or reasons.
"""
import base64
import hashlib
import ipaddress
import http.cookiejar
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scim'))
from dpop_fixture import FixtureClient, b64, sign
root, database, issuer = sys.argv[1:]
root = Path(root)
owned_database = urllib.parse.urlsplit(database)
assert owned_database.hostname == '127.0.0.1' and owned_database.path.startswith('/ast_jit_rbac_'), 'only owned fixture database allowed'
tenant = 'temporary'
api = issuer + '/admin/api/v1'
resource = 'https://api.example/temporary'
foreign_resource = 'https://api.example/ordinary'
pdp = issuer + '/access/v1/evaluation'
acr = 'urn:asterius:acr:passkey-uv'
origin = issuer.split('/t/')[0]
callback = 'https://client.example/callback'
quote = lambda value: "'" + str(value).replace("'", "''") + "'"
ids = {name: str(uuid.uuid4()) for name in ['owner', 'requester', 'approver', 'stranger']}
raw = {name: secrets.token_urlsafe(32) for name in ids}
key = ec.generate_private_key(ec.SECP256R1())
numbers = key.public_key().public_numbers()
jwk = {'kty':'EC','crv':'P-256','x':b64(numbers.x.to_bytes(32,'big')),'y':b64(numbers.y.to_bytes(32,'big')),'kid':'temporary-fixture','alg':'ES256','use':'sig'}
(root / 'client.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
def sql(statement):
    return subprocess.run(['psql', database, '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', statement], check=True, capture_output=True, text=True).stdout.strip()
sql(f"""insert into resource_servers(tenant_id,identifier,scopes) values
('temporary',{quote(resource)},array['openid','offline_access','read','write']),('temporary',{quote(foreign_resource)},array['openid','offline_access','read']),('temporary',{quote(api)},null),('temporary',{quote(pdp)},array['openid','authzen.evaluate','write']);
insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks,roles_in_id_token,id_token_signed_response_alg) values
('temporary','app','Temporary application','private_key_jwt',array['authorization_code','refresh_token','client_credentials'],array['code'],array[{quote(callback)}],array['openid','offline_access','read','write','authzen.evaluate'],array[{quote(resource)},{quote(foreign_resource)},{quote(pdp)}],{quote(json.dumps({'keys':[jwk]}))}::jsonb,true,'ES256');
insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks) values
('temporary','controller','Controlled administration','private_key_jwt',array['client_credentials'],array[]::text[],array[]::text[],array['admin.app_roles:read','admin.app_roles:write'],array[{quote(api)}],{quote(json.dumps({'keys':[jwk]}))}::jsonb);
insert into client_roles(tenant_id,client_id,name) values('temporary','app','incident-responder'),('temporary','app','pdp-check');""")
for name, user in ids.items():
    digest = hashlib.sha256(raw[name].encode()).hexdigest()
    sql(f"""insert into users(tenant_id,user_id,username,status) values('temporary',{quote(user)},{quote(name+'@fixture.example')},'active');
insert into sessions(tenant_id,session_id,public_sid,user_id,authenticated_at,expires_at,idle_expires_at,acr,amr) values('temporary',{quote(digest)},{quote(str(uuid.uuid4()))},{quote(user)},clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '1 hour',{quote(acr)},array['pop','user']);""")
sql(f"insert into user_roles(tenant_id,user_id,role,tenant_is_reserved) values('temporary',{quote(ids['owner'])},'tenant_admin',false);")
sql(f"insert into user_roles(tenant_id,user_id,role,tenant_is_reserved) values('temporary',{quote(ids['stranger'])},'security_auditor',false);")
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        return None
class Browser:
    def __init__(self, name):
        self.name = name
        self.jar = http.cookiejar.CookieJar()
        self.jar.set_cookie(http.cookiejar.Cookie(0, '__Host-asterius_session', raw[name], None, False, 'localhost.local', False, False, '/', True, True, None, True, None, None, {}, False))
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=root / 'cert.pem')))
        self.csrf = None
    def request(self, method, url, body=None, headers=None):
        if isinstance(body, dict): body = json.dumps(body).encode()
        try:
            response = self.opener.open(urllib.request.Request(url, body, headers or {}, method=method), timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        data = response.read(131073)
        assert len(data) <= 131072, 'bounded fixture response'
        kind = response.headers.get('Content-Type', '')
        return response.status, response.headers, json.loads(data) if 'json' in kind and data else data.decode()
    def admin(self, method, path, body=None, csrf=True, key=None):
        headers = {'Content-Type':'application/json','Origin':origin,'Sec-Fetch-Site':'same-origin','Idempotency-Key':key or str(uuid.uuid4())}
        if csrf and self.csrf: headers['X-CSRF-Token'] = self.csrf
        return self.request(method, api+path, body, headers)
    def forms(self, path='/account/entitlements'):
        status, _, html = self.request('GET', issuer+path)
        assert status == 200, 'ordinary account page'
        parser = Forms(); parser.feed(html)
        return parser.forms
    def command(self, action, fields, csrf=None):
        if csrf is None:
            forms = self.forms()
            tokens = [form['values']['csrf'] for form in forms if 'csrf' in form['values']]
            if tokens:
                csrf = tokens[0]
            else:
                # Controlled adversarial caller owns this seeded credential:
                # still probe server independence when the UI hides the action.
                cookie = next(item.value for item in self.jar if item.name == '__Host-asterius_session')
                digest = hashlib.sha256(cookie.encode()).hexdigest()
                csrf = hashlib.sha256((digest+':temporary-entitlement-account-csrf').encode()).hexdigest()
        body = urllib.parse.urlencode({'csrf':csrf, **fields}).encode()
        return self.request('POST', issuer+'/account/entitlements/'+action, body, {'Content-Type':'application/x-www-form-urlencoded','Origin':origin,'Sec-Fetch-Site':'same-origin'})
class Forms(HTMLParser):
    def __init__(self): super().__init__(); self.forms=[]; self.current=None
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form': self.current={'action':attrs.get('action',''),'values':{},'all':[]}; self.forms.append(self.current)
        if tag == 'input' and self.current is not None and 'name' in attrs:
            name, value = attrs['name'], attrs.get('value','')
            self.current['values'][name]=value; self.current['all'].append((name,value))
    def handle_endtag(self, tag):
        if tag == 'form': self.current=None
browsers = {name:Browser(name) for name in ids}
owner, requester, approver, stranger = [browsers[name] for name in ids]
status, _, session = owner.admin('GET', '/session')
assert status == 200, 'verified console session'
owner.csrf = session['csrf_token']
status, _, settings = owner.admin('GET', '/tenants/temporary/settings')
assert status == 200, 'current tenant assurance policy'
revision = hashlib.sha256(json.dumps(settings['acr_policy'], sort_keys=True, separators=(',',':'), ensure_ascii=False).encode()).hexdigest()
for name in ids:
    digest = hashlib.sha256(raw[name].encode()).hexdigest()
    sql(f"insert into session_assurance_proofs(tenant_id,session_id,acr,assurance_authenticated_at,assurance_policy_revision,assurance_methods) select 'temporary',{quote(digest)},{quote(acr)},authenticated_at,{quote(revision)},array['pop','user'] from sessions where tenant_id='temporary' and session_id={quote(digest)};")
configuration = {'owner_user_id':ids['owner'],'client_id':'app','resource':resource,'role_name':'incident-responder','permissions':['read'],'approver_user_ids':[ids['owner'],ids['requester'],ids['approver']],'requester_acr':acr,'approver_acr':acr,'max_duration_seconds':60,'max_eligibility_seconds':86400,'enabled':True}
assert owner.admin('POST','/temporary-entitlements',configuration,csrf=False)[0] == 403, 'console CSRF required'
status, _, entitlement = owner.admin('POST','/temporary-entitlements',configuration)
assert status == 201, 'owner configuration'
entitlement_id = entitlement['entitlement_id']
path = '/temporary-entitlements/'+entitlement_id
now = int(time.time())
status, _, eligibility = owner.admin('POST',path+'/eligibilities',{'user_id':ids['requester'],'not_before':now-1,'expires_at':now+600,'expected_revision':None})
assert status == 200, 'bounded eligibility'
assert requester.admin('GET',path)[0] == 403, 'ordinary subject has no console authority'
assert owner.admin('PUT',path,{**configuration,'expected_revision':str(uuid.uuid4())})[0] == 409, 'stale owner CAS'
assert owner.admin('GET',path)[2]['revision'] == entitlement['revision']
checks=['console_owner_csrf_cas_and_ordinary_boundary']
def requests():
    result=owner.admin('GET',path+'/requests'); assert result[0] == 200; return result[2]['items']
def activations():
    result=owner.admin('GET',path+'/activations'); assert result[0] == 200; return result[2]['items']
def submit(duration=30):
    command={'entitlement_id':entitlement_id,'duration_seconds':duration,'reason':'<script>incident</script> '+secrets.token_hex(4),'idempotency_key':str(uuid.uuid4())}
    status, _, result=requester.command('request',command)
    assert status == 303, f'ordinary request status={status} freshness_prompt={isinstance(result,str) and "Sign in again with" in result}'
    request_id=next(item['request_id'] for item in requests() if item['status']=='pending' and item['reason']==command['reason'])
    assert requester.command('request',command)[0] == 303, 'same body replay'
    assert requester.command('request',{**command,'duration_seconds':duration+1})[0] == 404, 'changed replay payload refused'
    return request_id

sql("update tenants set settings=jsonb_set(coalesce(settings,'{}'::jsonb),'{options}','{\"allow_non_fapi_clients\":true}'::jsonb) where tenant_id='temporary';")
sql("update clients set compliance_profile='oidc',application_type='web',managed_groups_claim=true,roles_in_id_token=true,dpop_bound_access_tokens=true where tenant_id='temporary' and client_id='app';")
class Client(FixtureClient):
    def authenticate(self): pass
    def authenticated(self, endpoint, form):
        now=int(time.time())
        assertion=sign({'alg':'ES256','typ':'JWT','kid':self.key_id},{'iss':self.client_id,'sub':self.client_id,'aud':issuer,'iat':now,'exp':now+60,'jti':secrets.token_urlsafe(24)},self.key)
        values={'client_id':self.client_id,'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','client_assertion':assertion,**form}
        return self.request('POST',issuer+endpoint,urllib.parse.urlencode(values).encode(),{'Content-Type':'application/x-www-form-urlencoded'})
client=Client(issuer,'app',root/'client.pem','temporary-fixture',root/'cert.pem')
automation=Client(issuer,'controller',root/'client.pem','temporary-fixture',root/'cert.pem')
status, _, automation_issued=automation.authenticated('/token',{'grant_type':'client_credentials','scope':'admin.app_roles:read admin.app_roles:write','resource':api})
assert status==200, 'real administrative DPoP automation credential'
automation.token=automation_issued['access_token']
assert automation.request('GET',api+path)[0]==403, 'automation cannot become resource owner'
assert automation.request('POST',api+'/temporary-entitlements',configuration,{'Content-Type':'application/json','Idempotency-Key':str(uuid.uuid4())})[0]==403, 'automation cannot create entitlement eligibility authority'
checks.append('administrative_dpop_automation_is_not_console_owner')
status, _, keys=requester.request('GET',issuer+'/jwks'); assert status == 200
def userinfo(token):
    previous=client.token
    client.token=token
    try:
        status, _, result=client.request('GET',issuer+'/userinfo')
        assert status==200, 'real proof-bound current UserInfo'
        return result
    finally:
        client.token=previous

def claims(token, audience, algorithm="EdDSA"):
    header, payload, signature=token.split('.')
    decode=lambda value:base64.urlsafe_b64decode(value+'='*(-len(value)%4))
    protected=json.loads(decode(header)); result=json.loads(decode(payload))
    assert protected['alg']==algorithm, 'pinned signature algorithm'
    public=next(item for item in keys['keys'] if item['kid']==protected['kid'])
    signed=(header+'.'+payload).encode()
    raw_signature=decode(signature)
    if algorithm=='ES256':
        assert public['kty']=='EC' and public['crv']=='P-256'
        point=ec.EllipticCurvePublicNumbers(int.from_bytes(decode(public['x']),'big'),int.from_bytes(decode(public['y']),'big'),ec.SECP256R1()).public_key()
        point.verify(utils.encode_dss_signature(int.from_bytes(raw_signature[:32],'big'),int.from_bytes(raw_signature[32:],'big')),signed,ec.ECDSA(hashes.SHA256()))
    else:
        assert algorithm=='EdDSA' and public['kty']=='OKP' and public['crv']=='Ed25519'
        ed25519.Ed25519PublicKey.from_public_bytes(decode(public['x'])).verify(raw_signature,signed)
    assert result['iss']==issuer and audience in ([result['aud']] if isinstance(result['aud'],str) else result['aud'])
    assert result['exp']>time.time(), 'valid signed expiry'
    return result

def code_tokens(selected_resource=resource, scopes='openid offline_access read', browser=requester):
    verifier=secrets.token_urlsafe(32); state=secrets.token_urlsafe(24); nonce=secrets.token_urlsafe(24)
    status, _, pushed=client.authenticated('/par',{'response_type':'code','redirect_uri':callback,'scope':scopes,'resource':selected_resource,'state':state,'nonce':nonce,'code_challenge_method':'S256','code_challenge':b64(hashlib.sha256(verifier.encode()).digest())})
    assert status==201, 'real authenticated PAR'
    url=issuer+'/authorize?'+urllib.parse.urlencode({'client_id':'app','request_uri':pushed['request_uri']})
    for _ in range(8):
        status, headers, body=browser.request('GET',url)
        if status in (302,303):
            location=urllib.parse.urljoin(url,headers['Location'])
            if location.startswith(callback): break
            assert location.startswith(issuer+'/'), 'bounded authorization redirect'; url=location; continue
        assert status==200, 'strong seeded session reaches consent'
        forms=Forms(); forms.feed(body)
        consent=next(form for form in forms.forms if 'csrf' in form['values'] and any(name=='scope' for name,_ in form['all']))
        status, headers, _=browser.request('POST',urllib.parse.urljoin(url,consent['action']),urllib.parse.urlencode(consent['all']+[('decision','allow')]).encode(),{'Content-Type':'application/x-www-form-urlencoded','Origin':origin})
        assert status in (302,303), 'consent advances'
        location=urllib.parse.urljoin(url,headers['Location'])
        if location.startswith(callback): break
        assert location.startswith(issuer+'/'); url=location
    else: raise AssertionError('authorization redirect bound')
    parameters=urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    assert parameters.get('state')==[state] and 'code' in parameters, 'authorization callback state'
    status, _, issued=client.authenticated('/token',{'grant_type':'authorization_code','code':parameters['code'][0],'redirect_uri':callback,'code_verifier':verifier})
    assert status==200 and issued['token_type'].lower()=='dpop', 'real proof-bound code issuance'
    identity=claims(issued['id_token'],'app','ES256'); assert identity['nonce']==nonce
    return issued, claims(issued['access_token'],selected_resource), identity


# All Kubernetes operations below use only this fixture's explicit kubeconfig,
# endpoint and credentials. Ambient current-context and deployment resources are ignored.
repo = Path(__file__).resolve().parents[2]
cluster_name = 'asterius-dd1y53'
issuer_container = cluster_name+'-issuer'
namespace = 'incident'
profile = {'cluster_id':'incident','namespace':namespace,'group_ids':[],'revision':0}
status, _, saved_profile = owner.admin('PUT','/clients/app/kubernetes',profile)
assert status == 200, 'real owner profile configuration'
status, _, mapping = owner.admin('PUT',path+'/kubernetes-binding',{'controller_client_id':'controller','expected_revision':None,'enabled':True})
assert status == 200, f'real owner controller mapping CAS status={status} error={mapping}'
assert owner.admin('PUT',path+'/kubernetes-binding',{'controller_client_id':'controller','expected_revision':None,'enabled':True})[0] == 409, 'mapping creation replay is stale CAS'
assert automation.request('PUT',api+path+'/kubernetes-binding',{'controller_client_id':'controller','expected_revision':mapping['revision'],'enabled':False},{'Content-Type':'application/json'})[0] == 403, 'controller cannot mutate mapping'
status, _, document = owner.admin('GET',path+'/kubernetes-binding')
assert status == 200 and document['binding']['revision']==mapping['revision']
authentication = document['authentication_configuration']
authentication['jwt'][0]['issuer']['certificateAuthority']=(root/'cert.pem').read_text()
(root/'authentication.json').write_text(json.dumps(authentication))
patch = {'kind':'ClusterConfiguration','apiServer':{
    'extraArgs':{'authentication-config':'/etc/kubernetes/asterius-authentication.json'},
    'extraVolumes':[{'name':'asterius-authentication','hostPath':'/etc/kubernetes/asterius-authentication.json','mountPath':'/etc/kubernetes/asterius-authentication.json','readOnly':True,'pathType':'File'}],
}}
kind_config = {'kind':'Cluster','apiVersion':'kind.x-k8s.io/v1alpha4','nodes':[{
    'role':'control-plane','extraMounts':[{'hostPath':str(root/'authentication.json'),'containerPath':'/etc/kubernetes/asterius-authentication.json','readOnly':True}],
    'kubeadmConfigPatches':[json.dumps(patch)],
}]}
(root/'kind.json').write_text(json.dumps(kind_config))
(root/'cluster-created').touch()
kind_log=(root/'kind.log').open('w')
create = subprocess.Popen(['kind','create','cluster','--name',cluster_name,'--image','kindest/node:v1.35.0','--config',str(root/'kind.json'),'--kubeconfig',str(root/'admin-kubeconfig'),'--wait','120s'],stdout=kind_log,stderr=kind_log)
try:
    deadline=time.monotonic()+90
    while subprocess.run(['docker','inspect',cluster_name+'-control-plane'],capture_output=True).returncode:
        assert create.poll() is None and time.monotonic()<deadline, 'own kind container creation'
        time.sleep(.25)
    gateway=str(ipaddress.IPv4Address(json.loads(subprocess.check_output(['docker','inspect',cluster_name+'-control-plane']))[0]['NetworkSettings']['Networks']['kind']['Gateway']))
    subprocess.run(['docker','run','-d','--name',issuer_container,'--network','container:'+cluster_name+'-control-plane','alpine/socat@sha256:5ffbd6ae916cbad86a58fabe0d6d5a6fd5c2b47ddf031e82996baac9300e732f','TCP-LISTEN:9469,bind=127.0.0.1,fork,reuseaddr','TCP:'+gateway+':9469'],check=True,capture_output=True)
    assert create.wait(timeout=150)==0, 'own kind structured authentication readiness'
finally:
    if create.poll() is None: create.terminate(); create.wait(timeout=20)
    kind_log.close()

def kube_admin(*args, data=None):
    return subprocess.run(['kubectl','--kubeconfig',str(root/'admin-kubeconfig'),*args],input=data,check=True,capture_output=True,text=True).stdout
kube_admin('create','namespace',namespace)
kube_admin('apply','-f',str(repo/'deploy/kubernetes-temporary-rbac/rbac.example.yaml'))
kube_admin('-n',namespace,'create','secret','generic','incident-context','--from-literal=purpose=controlled-proof')
kube_admin('-n',namespace,'create','configmap','baseline','--from-literal=purpose=baseline')
config=json.loads(kube_admin('config','view','--raw','-o','json'))
cluster=config['clusters'][0]['cluster']; kube_origin=cluster['server']
(root/'kube-ca.pem').write_bytes(base64.b64decode(cluster['certificate-authority-data']))
kube_context=ssl.create_default_context(cafile=root/'kube-ca.pem')
sa=kube_admin('-n',namespace,'create','token','asterius-temporary-rbac','--duration=10m').strip()
(root/'kube-token').write_text(sa); (root/'kube-token').chmod(0o600)

def kube_http(token, method, path, body=None, content_type='application/json'):
    if body is not None: body=json.dumps(body).encode()
    headers={'Authorization':'Bearer '+token,'Content-Type':content_type}
    try:
        response=urllib.request.urlopen(urllib.request.Request(kube_origin+path,body,headers,method=method),context=kube_context,timeout=5)
    except urllib.error.HTTPError as error: response=error
    data=response.read(65537); assert len(data)<=65536, 'bounded Kubernetes response'
    return response.status, json.loads(data) if data else None

binding_path='/apis/rbac.authorization.k8s.io/v1/namespaces/'+namespace+'/rolebindings/asterius-temporary-secret-read'
status, binding=kube_http(sa,'GET',binding_path); assert status==200
controller_config={'Controller':{
    'Tenant':tenant,'ControllerClient':'controller','ClusterClient':'app','Cluster':'incident','Namespace':namespace,
    'EntitlementID':entitlement_id,'BindingRevision':mapping['revision'],'RoleBindingName':binding['metadata']['name'],
    'RoleBindingUID':binding['metadata']['uid'],'RoleName':'approved-secret-read','ProfileRevision':mapping['profile_revision'],'Interval':400_000_000,
},'Issuer':issuer,'KeyFile':str(root/'client.pem'),'KeyID':'temporary-fixture','CAFile':str(root/'cert.pem'),
'KubernetesURL':kube_origin,'KubernetesTokenFile':str(root/'kube-token'),'KubernetesCAFile':str(root/'kube-ca.pem')}
(root/'controller.json').write_text(json.dumps(controller_config)); (root/'controller.json').chmod(0o600)
controller=None; controller_log=(root/'controller.log').open('w')
def start_controller():
    return subprocess.Popen([str(root/'asterius-jit-rbac'),str(root/'controller.json')],stdout=controller_log,stderr=controller_log)
def wait_subjects(expected, timeout=8):
    started=time.monotonic()
    while True:
        status, current=kube_http(sa,'GET',binding_path); assert status==200
        subjects=current.get('subjects') or []
        if (len(subjects)==expected if type(expected) is int else bool(subjects)==expected): return time.monotonic()-started
        if time.monotonic()-started>=timeout:
            status, _, snapshot=automation.request('GET',api+'/kubernetes/temporary-access/'+entitlement_id)
            print(json.dumps({'projection_status':status,'projection_enabled':snapshot.get('binding',{}).get('enabled'),'projection_subject_count':len(snapshot.get('subjects',[])),'native_subject_count':len(subjects)}),flush=True)
            print((root/'controller.log').read_text()[-2000:],flush=True)
            raise AssertionError('bounded real reconciliation window')
        assert controller is not None and controller.poll() is None, 'controller remains running'
        time.sleep(.1)

# A fixture-only frozen proof reset occurs before any human grant is created;
# no runtime endpoint is claimed to supply a new authenticator ceremony.
for name in ids:
    cookie=next(item.value for item in browsers[name].jar if item.name=='__Host-asterius_session')
    digest=hashlib.sha256(cookie.encode()).hexdigest()
    sql(f"update sessions set authenticated_at=clock_timestamp() where tenant_id='temporary' and session_id={quote(digest)};update session_assurance_proofs p set assurance_authenticated_at=s.authenticated_at from sessions s where p.tenant_id=s.tenant_id and p.session_id=s.session_id and s.tenant_id='temporary' and s.session_id={quote(digest)};")
baseline_issued, _, baseline=code_tokens()
assert 'asterius_jit' not in baseline, 'ordinary baseline ID has no private authority'
baseline_username='asterius:temporary:incident:'+baseline['sub']
kube_admin('-n',namespace,'create','role','baseline','--verb=get','--resource=configmaps','--resource-name=baseline')
kube_admin('-n',namespace,'create','rolebinding','baseline','--role=baseline','--user='+baseline_username)
baseline_binding=json.loads(kube_admin('-n',namespace,'get','rolebinding','baseline','-o','json'))
secret_path='/api/v1/namespaces/'+namespace+'/secrets/incident-context'
configmap_path='/api/v1/namespaces/'+namespace+'/configmaps/baseline'
assert kube_http(baseline_issued['id_token'],'GET',configmap_path)[0]==200
assert kube_http(baseline_issued['id_token'],'GET',secret_path)[0]==403
checks.append('real_baseline_oidc_identity_and_independent_binding')

def approve(duration):
    request_id=submit(duration)
    assert approver.command('decide',{'request_id':request_id,'decision':'approve','idempotency_key':str(uuid.uuid4())})[0]==303
    return next(item for item in activations() if item['status']=='active' and item['request_id']==request_id)
try:
    controller=start_controller()
    active=approve(45)
    overlapping_request=submit(50)
    assert approver.command('decide',{'request_id':overlapping_request,'decision':'approve','idempotency_key':str(uuid.uuid4())})[0]==404, 'existing active approval cannot be silently replaced'
    assert owner.admin('POST',path+'/eligibilities',{'user_id':ids['stranger'],'not_before':int(time.time())-1,'expires_at':int(time.time())+600,'expected_revision':None})[0]==200
    other_reason='Second independent actor '+secrets.token_hex(8)
    assert stranger.command('request',{'entitlement_id':entitlement_id,'duration_seconds':50,'reason':other_reason,'idempotency_key':str(uuid.uuid4())})[0]==303
    other_request=next(item['request_id'] for item in requests() if item['reason']==other_reason)
    assert approver.command('decide',{'request_id':other_request,'decision':'approve','idempotency_key':str(uuid.uuid4())})[0]==303
    other_active=next(item for item in activations() if item['request_id']==other_request)
    issued, _, identity=code_tokens()
    assert identity['asterius_jit']['binding_revision']==mapping['revision']
    assert identity['exp']<=active['expires_at'] and identity['exp']<=identity['asterius_jit']['expires_at']
    other_issued, _, other_identity=code_tokens(browser=stranger)
    enabled_seconds=wait_subjects(2)
    status, _, projection=automation.request('GET',api+'/kubernetes/temporary-access/'+entitlement_id)
    assert status==200 and len(projection['subjects'])==2, 'complete projection retains both independently approved native subjects'
    assert len({item['username'] for item in projection['subjects']})==2
    assert active['activation_id'] in [item['activation_id'] for item in projection['subjects']], 'refused overlap preserves the current valid approval'
    assert kube_http(other_issued['id_token'],'GET',secret_path)[0]==200, 'refused overlap never clears another legitimate subject'
    assert kube_http(issued['id_token'],'GET',secret_path)[0]==200, 'real signed JIT token reaches fixed Role'
    assert kube_http(issued['id_token'],'GET','/api/v1/namespaces/'+namespace+'/secrets')[0]==403, 'get does not grant list'
    assert kube_http(baseline_issued['id_token'],'GET',secret_path)[0]==403, 'ordinary username cannot borrow active JIT binding'
    assert kube_http(baseline_issued['id_token'],'GET',configmap_path)[0]==200
    status, _, refreshed=client.authenticated('/token',{'grant_type':'refresh_token','refresh_token':issued['refresh_token']})
    assert status==200 and claims(refreshed['id_token'],'app','ES256')['asterius_jit']['binding_revision']==mapping['revision']
    assert kube_http(refreshed['id_token'],'GET',secret_path)[0]==200
    for selected, scopes in [(foreign_resource,'openid read'),(resource,'openid'),(resource,'openid read write')]:
        other, _, identity=code_tokens(selected,scopes)
        assert 'asterius_jit' not in identity
        assert kube_http(other['id_token'],'GET',secret_path)[0]==403
    checks.append('actual_code_refresh_jit_fixed_resource_permission_and_verb_ceiling')
    # Negative verifier fixtures are signed only with this disposable realm's
    # known zero development KEK. They are not claims of API-issued authority.
    # Key material stays in process memory and is never logged or persisted.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    identity=claims(issued['id_token'],'app','ES256')
    header=json.loads(base64.urlsafe_b64decode(issued['id_token'].split('.')[0]+'=='))
    row=json.loads(sql("select json_build_object('kid',kid,'purpose',purpose,'alg',alg,'nonce',encode(private_key_nonce,'hex'),'ciphertext',encode(private_key_ciphertext,'hex')) from signing_keys where tenant_id='temporary' and kid="+quote(header['kid'])))
    fields=[tenant.encode(),row['kid'].encode(),row['purpose'].encode(),row['alg'].encode()]
    aad=b'asterius.kek.v1'+b''.join(len(field).to_bytes(4,'big')+field for field in fields)
    der=AESGCM(bytes(32)).decrypt(bytes.fromhex(row['nonce']),bytes.fromhex(row['ciphertext']),aad)
    fixture_signer=serialization.load_der_private_key(der,password=None); del der
    for mutation, expected_status in [
        (lambda claim: claim['asterius_jit'].update({'username':'system:admin'}),401),
        (lambda claim: claim['asterius_jit'].update({'namespace':3}),401),
        (lambda claim: claim['asterius_jit'].update({'expires_at':claim['exp']-1}),401),
        (lambda claim: claim['asterius_jit'].update({'role':'different-role'}),403),
        (lambda claim: claim['asterius_jit'].update({'namespace':'different'}),403),
    ]:
        malformed=json.loads(json.dumps(identity)); mutation(malformed)
        signed=sign(header,malformed,fixture_signer)
        assert kube_http(signed,'GET',secret_path)[0]==expected_status, 'closed signed provenance/tuple guard'
    del fixture_signer
    checks.append('controlled_signed_malformed_provenance_and_foreign_tuple_verifier_negatives')

    status, _, revoked=owner.admin('POST',path+'/activations/'+active['activation_id']+'/revoke',{'activation_id':active['activation_id'],'reason':'Native RBAC proof','idempotency_key':str(uuid.uuid4())})
    assert status==200
    revoked_seconds=wait_subjects(1)
    assert kube_http(other_issued['id_token'],'GET',secret_path)[0]==200, 'another actor survives independent revocation'
    assert kube_http(issued['id_token'],'GET',secret_path)[0]==403
    assert owner.admin('POST',path+'/activations/'+other_active['activation_id']+'/revoke',{'activation_id':other_active['activation_id'],'reason':'Other actor complete','idempotency_key':str(uuid.uuid4())})[0]==200
    wait_subjects(False)
    assert claims(issued['id_token'],'app','ES256')['exp']>time.time(), 'revoked token remains cryptographically valid'
    assert kube_http(issued['id_token'],'GET',secret_path)[0]==403, 'healthy revocation denies old valid ID'
    checks.append('healthy_revocation_old_valid_token_access_loss')

    active=approve(8)
    outage_issued, _, outage_identity=code_tokens()
    wait_subjects(True)
    assert kube_http(outage_issued['id_token'],'GET',secret_path)[0]==200
    # SIGKILL deliberately bypasses graceful cleanup and leaves a real stale binding.
    controller.kill(); controller.wait(timeout=10); controller=None
    time.sleep(max(0,outage_identity['exp']-time.time()+.5))
    status, stale=kube_http(sa,'GET',binding_path)
    assert status==200 and stale.get('subjects'), 'outage leaves stale native binding'
    expiry_probe_started=time.monotonic()
    while True:
        expiry_status=kube_http(outage_issued['id_token'],'GET',secret_path)[0]
        if expiry_status==401:break
        assert expiry_status==200 and time.time()<=outage_identity['exp']+12, 'bounded Kubernetes successful-authentication cache residual'
        time.sleep(.1)
    expiry_residual_seconds=max(0,time.time()-outage_identity['exp'])
    ordinary, _, ordinary_identity=code_tokens()
    assert 'asterius_jit' not in ordinary_identity
    assert kube_http(ordinary['id_token'],'GET',secret_path)[0]==403, 'new ordinary token cannot reuse stale JIT username'
    assert kube_http(ordinary['id_token'],'GET',configmap_path)[0]==200
    checks.append('controller_outage_old_jwt_expiry_and_new_ordinary_token_denial')
    active=approve(30)
    sql("insert into user_client_roles(tenant_id,client_id,user_id,name,granted_at) values('temporary','app',"+quote(ids['requester'])+",'incident-responder',clock_timestamp());")
    standing, _, standing_identity=code_tokens()
    assert 'incident-responder' in standing_identity.get('resource_access',{}).get('app',{}).get('roles',[])
    assert 'asterius_jit' not in standing_identity, 'independent standing role is never temporary-only provenance'
    assert kube_http(standing['id_token'],'GET',secret_path)[0]==403
    sql("delete from user_client_roles where tenant_id='temporary' and client_id='app' and user_id="+quote(ids['requester'])+" and name='incident-responder';")
    status, _, disabled=owner.admin('PUT',path+'/kubernetes-binding',{'controller_client_id':'controller','expected_revision':mapping['revision'],'enabled':False})
    assert status==200 and disabled['revision']!=mapping['revision']
    status, _, changed=owner.admin('PUT',path+'/kubernetes-binding',{'controller_client_id':'controller','expected_revision':disabled['revision'],'enabled':True})
    assert status==200 and changed['revision'] not in [mapping['revision'],disabled['revision']]
    revised, _, revised_identity=code_tokens()
    assert revised_identity['asterius_jit']['binding_revision']==changed['revision']
    assert kube_http(revised['id_token'],'GET',secret_path)[0]==403, 'new generation cannot match stale pinned configuration/binding'
    assert kube_http(revised['id_token'],'GET',configmap_path)[0]==200
    checks.append('standing_role_overlap_and_revision_generation_aba_denial')


    # Real SA authorization, with no inherited admin certificate, enforces ceiling.
    for target, method, body in [
        ('/apis/rbac.authorization.k8s.io/v1/namespaces/'+namespace+'/rolebindings','POST',{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'name':'other'},'roleRef':binding['roleRef'],'subjects':[]}),
        ('/apis/rbac.authorization.k8s.io/v1/namespaces/'+namespace+'/roles/approved-secret-read','PATCH',{'rules':[]}),
        ('/apis/rbac.authorization.k8s.io/v1/namespaces/'+namespace+'/rolebindings/baseline','PATCH',{'subjects':[]}),
        ('/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings/asterius-temporary-secret-read','PATCH',{'subjects':[]}),
        ('/apis/rbac.authorization.k8s.io/v1/clusterrolebindings','POST',{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRoleBinding','metadata':{'name':'escape'},'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':'cluster-admin'},'subjects':[]}),
    ]:
        content='application/merge-patch+json' if method=='PATCH' else 'application/json'
        assert kube_http(sa,method,target,body,content)[0]==403, 'actual controller RBAC ceiling'
    assert kube_http(sa,'PATCH',binding_path,{'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':'cluster-admin'}},'application/merge-patch+json')[0] in (403,422)
    assert json.loads(kube_admin('-n',namespace,'get','rolebinding','baseline','-o','json'))==baseline_binding
    assert kube_http(baseline_issued['id_token'],'GET',configmap_path)[0]==200
    checks.append('actual_controller_ceiling_and_baseline_binding_preservation')
finally:
    if controller is not None: controller.terminate(); controller.wait(timeout=10)
    controller_log.close()
print(json.dumps({'status':'pass','controls':checks,'measured_enable_seconds':round(enabled_seconds,3),'measured_revoke_seconds':round(revoked_seconds,3),'measured_expiry_residual_seconds':round(expiry_residual_seconds,3),'kubernetes_success_authentication_cache_ceiling_seconds':10}))
