#!/usr/bin/env python3
"""Real native Kubernetes temporary RBAC and signed code/refresh fixture using seeded PG proofs.
The fixture does not claim a fresh WebAuthn ceremony: proof provenance is seeded
explicitly, while auth-code/PAR/PKCE/private_key_jwt/DPoP and lifecycle are real.
Only aggregate control names are emitted, never sessions, tokens or reasons.
"""
import base64
import hashlib
import http.cookiejar
import http.server
import threading
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
import concurrent.futures
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
repo = Path(os.environ['ASTERIUS_FIXTURE_REPO'])
sys.path.insert(0, str(repo / 'scripts/scim'))
from dpop_fixture import FixtureClient, b64, sign
root, database, issuer = sys.argv[1:]
root = Path(root)
from tls_transport import OpaqueTlsTransport
owned_database = urllib.parse.urlsplit(database)
assert owned_database.hostname == '127.0.0.1' and owned_database.path.startswith('/ast_online_'), 'only owned fixture database allowed'
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
('temporary','app','Online human public subject','private_key_jwt',array['authorization_code','refresh_token'],array['code'],array[{quote(callback)}],array['openid','offline_access','read','write','authzen.evaluate'],array[{quote(resource)},{quote(foreign_resource)},{quote(pdp)}],{quote(json.dumps({'keys':[jwk]}))}::jsonb,true,'ES256');
insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks) values
('temporary','controller','Controlled administration','private_key_jwt',array['client_credentials'],array[]::text[],array[]::text[],array['admin.kubernetes_reviews:read'],array[{quote(api)}],{quote(json.dumps({'keys':[jwk]}))}::jsonb);
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
class Client(FixtureClient):
    def authenticate(self): pass
    def authenticated(self, endpoint, form):
        now=int(time.time())
        assertion=sign({'alg':'ES256','typ':'JWT','kid':self.key_id},{'iss':self.client_id,'sub':self.client_id,'aud':issuer,'iat':now,'exp':now+60,'jti':secrets.token_urlsafe(24)},self.key)
        values={'client_id':self.client_id,'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','client_assertion':assertion,**form}
        # Client authentication is private_key_jwt only. A resource credential
        # belongs on the review API, never alongside it at the token endpoint.
        previous=self.token;self.token=''
        try:
            return self.request('POST',issuer+endpoint,urllib.parse.urlencode(values).encode(),{'Content-Type':'application/x-www-form-urlencoded'})
        finally:self.token=previous

# Controlled session/proof seed is explicit, not a new WebAuthn ceremony.
sql("update tenants set settings=jsonb_set(coalesce(settings,'{}'::jsonb),'{options}','{\"allow_non_fapi_clients\":true}'::jsonb) where tenant_id='temporary';")
sql("update clients set compliance_profile='oidc',application_type='web',managed_groups_claim=true,dpop_bound_access_tokens=true where tenant_id='temporary' and client_id='app';")
sql("update clients set dpop_bound_access_tokens=true where tenant_id='temporary' and client_id='controller';")
client=Client(issuer,'app',root/'client.pem','temporary-fixture',root/'cert.pem')
reviewer=Client(issuer,'controller',root/'client.pem','temporary-fixture',root/'cert.pem')
status,_,issued_reviewer=reviewer.authenticated('/token',{'grant_type':'client_credentials','scope':'admin.kubernetes_reviews:read','resource':api})
assert status==200 and issued_reviewer['token_type'].lower()=='dpop','real exclusive CC reviewer'
reviewer.token=issued_reviewer['access_token']
status,_,keys=requester.request('GET',issuer+'/jwks'); assert status==200
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

def code_tokens(selected_resource=resource, scopes='openid offline_access read', browser=requester, force_login=False):
    verifier=secrets.token_urlsafe(32); state=secrets.token_urlsafe(24); nonce=secrets.token_urlsafe(24)
    status, _, pushed=client.authenticated('/par',{'response_type':'code','redirect_uri':callback,'scope':scopes,'resource':selected_resource,'state':state,'nonce':nonce,'code_challenge_method':'S256','code_challenge':b64(hashlib.sha256(verifier.encode()).digest()),**({'claims':json.dumps({'id_token':{'acr':{'essential':True,'value':acr}}})} if force_login else {})})
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
        login=next((form for form in forms.forms if 'password' in form['values']),None)
        if login:
            submitted=[(name,value) for name,value in login['all'] if name not in ('username','password')]+[('username',browser.name+'@fixture.example'),('password','correct horse battery staple')]
            target=login['action']
        else:
            consent=next(form for form in forms.forms if 'csrf' in form['values'] and any(name=='scope' for name,_ in form['all']))
            submitted=consent['all']+[('decision','allow')];target=consent['action']
        status, headers, _=browser.request('POST',urllib.parse.urljoin(url,target),urllib.parse.urlencode(submitted).encode(),{'Content-Type':'application/x-www-form-urlencoded','Origin':origin})
        assert status in (302,303), 'consent advances'
        location=urllib.parse.urljoin(url,headers['Location'])
        if location.startswith(callback): break
        assert location.startswith(issuer+'/'); url=location
    else: raise AssertionError('authorization redirect bound')
    parameters=urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    assert parameters.get('state')==[state] and 'code' in parameters, 'authorization callback state'
    status, _, issued=client.authenticated('/token',{'grant_type':'authorization_code','code':parameters['code'][0],'redirect_uri':callback,'code_verifier':verifier})
    assert status==200 and issued.get('token_type','').lower()=='dpop', 'real proof-bound code issuance status='+str(status)+' error='+str(issued.get('error','none'))
    identity=claims(issued['id_token'],'app','ES256'); assert identity['nonce']==nonce
    return issued, claims(issued['access_token'],selected_resource), identity


# Candidate fixture: all runtime assertions below are NOT RUN during preparation.
checks=[]
def record_check(name):
    checks.append(name)
    print(json.dumps({'control':name,'status':'pass'}),flush=True)
group=str(uuid.uuid4()); additional_group=str(uuid.uuid4())
sql(f"insert into managed_groups(tenant_id,group_id,name,display_name,created_at,updated_at) values('temporary',{quote(group)},'online-read','Online read',clock_timestamp(),clock_timestamp()); insert into group_memberships(tenant_id,group_id,user_id,created_at) values('temporary',{quote(group)},{quote(ids['requester'])},clock_timestamp());")
sql(f"insert into managed_groups(tenant_id,group_id,name,display_name,created_at,updated_at) values('temporary',{quote(additional_group)},'online-later','Online later',clock_timestamp(),clock_timestamp());")
status,_,profile=owner.admin('PUT','/clients/app/kubernetes',{'cluster_id':'online','namespace':'online','group_ids':[group,additional_group],'revision':0})
assert status==200,'owned native human profile'
profile_path='/clients/app/kubernetes/online'
unbound,_,_=code_tokens()
assert sql("select count(*) from kubernetes_online_tokens where tenant_id='temporary' and token_digest=decode("+quote(hashlib.sha256(unbound['id_token'].encode()).hexdigest())+",'hex')")=='0','offline token predates online enablement'
configuration={'reviewer_client_id':'controller','expected_revision':None,'enabled':True}
assert owner.admin('PUT',profile_path,configuration,csrf=False)[0]==403,'online config requires CSRF'
status,_,online=owner.admin('PUT',profile_path,configuration)
assert status==200,'explicit online profile enabled in owned fixture only'
assert owner.admin('PUT',profile_path,configuration)[0]==409,'CAS prevents lost update'
assert reviewer.request('PUT',api+profile_path,{**configuration,'expected_revision':online['revision']},{'Content-Type':'application/json'})[0]==403,'reviewer cannot configure human profile'
record_check('owner_csrf_cas_and_reviewer_read_only')
def review(token,audiences=None,route='app',service=reviewer,extra=None):
    body={'apiVersion':'authentication.k8s.io/v1','kind':'TokenReview','spec':{'token':token,'audiences':audiences or ['app']}}
    if extra: body.update(extra)
    status,_,result=service.request('POST',api+'/clients/'+route+'/kubernetes/reviews',body,{'Content-Type':'application/json'})
    return status,result

def authenticated(token):
    status,result=review(token)
    assert status==200,'review response boundary'
    return result.get('status',{}).get('authenticated',False)
assert not authenticated(unbound['id_token']),'review cannot enroll old offline token'
assert sql("select count(*) from kubernetes_online_tokens where tenant_id='temporary' and token_digest=decode("+quote(hashlib.sha256(unbound['id_token'].encode()).hexdigest())+",'hex')")=='0','review never writes missing binding'
first,first_access,first_identity=code_tokens()
assert authenticated(first['id_token']),'actual code token is registered at signing boundary'
digest=lambda token:hashlib.sha256(token.encode()).hexdigest()
def binding(token):
    result=sql("select json_build_object('grant',grant_id,'sid',public_sid,'subject',subject)::text from kubernetes_online_tokens where tenant_id='temporary' and token_digest=decode("+quote(digest(token))+",'hex')")
    assert result,'complete signed-token digest persisted'; return json.loads(result)
first_binding=binding(first['id_token'])
assert first_binding['subject']==first_identity['sub'] and first_binding['sid']==first_identity['sid'],'exact signed grant public sid'
assert sql("select count(*) from kubernetes_online_tokens where tenant_id='temporary' and token_digest=decode("+quote(digest(first['id_token']))+",'hex')")=='1','one exact digest'
status,_,refreshed=client.authenticated('/token',{'grant_type':'refresh_token','refresh_token':first['refresh_token'],'resource':resource})
assert status==200 and authenticated(refreshed['id_token']),'actual refresh ID token bound'
refresh_identity=claims(refreshed['id_token'],'app','ES256')
assert binding(refreshed['id_token'])==first_binding,'refresh preserves original exact grant/session binding'
record_check('real_par_pkce_code_and_refresh_digest_registration')
# A separately minted authorization for the same human must survive exact first-grant revocation.
second,_,second_identity=code_tokens()
second_binding=binding(second['id_token'])
assert second_binding['grant']!=first_binding['grant'],'independent same-user grant'
# A real password reauthentication drives the existing-session rotation handler.
# This is a real credential check, not a claim of fresh passkey assurance.
sql(f"insert into credentials(tenant_id,credential_id,user_id,kind,password_hash,label) values('temporary',{quote(str(uuid.uuid4()))},{quote(ids['requester'])},'password','$argon2id$v=19$m=19456,t=2,p=1$YnJvd3Nlci1zd2VlcC1zYWx0$E8awnsfATh5sLXjht+SvAdX9BEFVTWfDYThAb/+KOfs','owned rotation fixture')")
# Seeded legacy-session precondition: methods are historical, assigned class
# absent. Essential ACR then chooses StepUp rather than a new Login session.
# The real new proof below is password only; no fresh passkey claim is made.
sql("update sessions set acr=null where tenant_id='temporary' and public_sid="+quote(first_binding['sid']))
old_cookie=next(cookie.value for cookie in requester.jar if cookie.name=='__Host-asterius_session')
rotated,_,rotated_identity=code_tokens(force_login=True)
new_cookie=next(cookie.value for cookie in requester.jar if cookie.name=='__Host-asterius_session')
assert new_cookie!=old_cookie,'actual password reauthentication rotates lookup credential'
assert rotated_identity['sid']==first_identity['sid'],'rotation preserves public SID'
assert authenticated(first['id_token']) and authenticated(second['id_token']),'held exact-grant digests remain live across rotation'
status,_,after_rotation_refresh=client.authenticated('/token',{'grant_type':'refresh_token','refresh_token':refreshed.get('refresh_token',first['refresh_token']),'resource':resource})
assert status==200,'actual original-grant refresh after cookie rotation'
assert authenticated(after_rotation_refresh['id_token']),'new ID token after rotation registers exact original grant'
after_rotation_identity=claims(after_rotation_refresh['id_token'],'app','ES256')
assert after_rotation_identity['sid']==first_identity['sid'] and binding(after_rotation_refresh['id_token'])==first_binding,'original exact grant/publicSID survives rotated refresh'
record_check('real_password_session_rotation_preserves_public_sid')
assert authenticated(second['id_token'])
status,result=review(first['id_token'],['foreign']); assert status==200 and not result['status']['authenticated'],'requested audience cannot select different authority'
status,result=review(first['id_token'],route='controller'); assert status==200 and not result['status']['authenticated'],'wrong human route denied'
assert owner.admin('POST','/clients/app/kubernetes/reviews',{'apiVersion':'authentication.k8s.io/v1','kind':'TokenReview','spec':{'token':first['id_token'],'audiences':['app']}})[0]==403,'Console cannot impersonate service reviewer'
assert reviewer.request('POST',api+'/clients/app/kubernetes/reviews',{'apiVersion':'authentication.k8s.io/v1','kind':'TokenReview','spec':{'token':first['id_token'],'audiences':['app']}},{'Content-Type':'application/json'},bearer=True)[0]==401,'reviewer requires proof-bound transport'
for extra in [{'status':{'authenticated':True}}, {'unexpected':True}]:
    status,result=review(first['id_token'],extra=extra); assert status==200 and not result['status']['authenticated'],'caller response scaffolding cannot create authority'
sql(f"insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks,dpop_bound_access_tokens) values('temporary','wrong-reviewer','Wrong reviewer','private_key_jwt',array['client_credentials'],array[]::text[],array[]::text[],array['admin.kubernetes_reviews:read'],array[{quote(api)}],{quote(json.dumps({'keys':[jwk]}))}::jsonb,true)")
wrong_reviewer=Client(issuer,'wrong-reviewer',root/'client.pem','temporary-fixture',root/'cert.pem')
status,_,wrong_issue=wrong_reviewer.authenticated('/token',{'grant_type':'client_credentials','scope':'admin.kubernetes_reviews:read','resource':api});assert status==200
wrong_reviewer.token=wrong_issue['access_token']
status,result=review(first['id_token'],service=wrong_reviewer);assert status==200 and not result['status']['authenticated'],'same-scope unselected reviewer cannot become pinned reviewer'
status,_,_=reviewer.request('POST',origin+'/t/temporary-foreign/admin/api/v1/clients/app/kubernetes/reviews',{'apiVersion':'authentication.k8s.io/v1','kind':'TokenReview','spec':{'token':first['id_token'],'audiences':['app']}},{'Content-Type':'application/json'})
assert status in (401,403),'cross-tenant reviewer credential refused'
pieces=first['id_token'].split('.');payload=json.loads(base64.urlsafe_b64decode(pieces[1]+'='*(-len(pieces[1])%4)));payload['iss']=origin+'/t/temporary-foreign';pieces[1]=b64(json.dumps(payload).encode())
assert not authenticated('.'.join(pieces)),'changed issuer cannot reuse original signature or binding'
record_check('route_audience_service_only_dpop_selected_reviewer_tenant_and_wire_authority')
# Two successful CC mints create independent issuance-established receipts.
# Revoking one must not let another live CC grant repair that receipt.
old_reviewer_token=reviewer.token
status,_,new_reviewer_issue=reviewer.authenticated('/token',{'grant_type':'client_credentials','scope':'admin.kubernetes_reviews:read','resource':api})
assert status==200,'independent selected reviewer CC grant'
status,_,_=reviewer.authenticated('/revoke',{'token':old_reviewer_token,'token_type_hint':'access_token'})
assert status==200,'real selected reviewer access-token revocation'
status,result=review(first['id_token']);assert status in (401,403),'old CC receipt cannot borrow independent live CC grant'
reviewer.token=new_reviewer_issue['access_token']
assert authenticated(first['id_token']),'independent legitimate CC receipt remains accepted'
record_check('reviewer_exact_cc_receipt_revocation_and_independent_grant')

# Read side effects checked against the exact session row, not another account/session.
activity=sql("select row_to_json(s)::text from sessions s where tenant_id='temporary' and public_sid="+quote(first_binding['sid']))
for _ in range(3): assert authenticated(first['id_token'])
assert sql("select row_to_json(s)::text from sessions s where tenant_id='temporary' and public_sid="+quote(first_binding['sid']))==activity,'reviews never touch browser activity or expiry'
record_check('review_is_read_only')
# Dedicated mTLS CA, API-server leaf and an independently trusted but unpinned leaf.
def openssl(*args):
    subprocess.run(['openssl',*args],check=True,capture_output=True)
openssl('req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(root/'api-ca.key'),'-out',str(root/'api-ca.pem'),'-days','1','-subj','/CN=Owned API client CA','-addext','basicConstraints=critical,CA:TRUE')
for name in ['api-client','wrong-client']:
    openssl('req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(root/(name+'.key')),'-out',str(root/(name+'.csr')),'-subj','/CN='+name)
    (root/'client-ext.cnf').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n')
    openssl('x509','-req','-in',str(root/(name+'.csr')),'-CA',str(root/'api-ca.pem'),'-CAkey',str(root/'api-ca.key'),'-CAcreateserial','-out',str(root/(name+'.pem')),'-days','1','-extfile',str(root/'client-ext.cnf'))
leaf=serialization.load_pem_public_key(subprocess.check_output(['openssl','x509','-in',str(root/'api-client.pem'),'-pubkey','-noout']))
pin=hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
adapter_log=(root/'adapter.log').open('w')
adapter_command=[str(root/'asterius-token-review'),'--listen','0.0.0.0:9470','--issuer',issuer,'--human-client','app','--reviewer-client','controller','--reviewer-key',str(root/'client.pem'),'--reviewer-kid','temporary-fixture','--issuer-ca',str(root/'cert.pem'),'--server-cert',str(root/'cert.pem'),'--server-key',str(root/'key.pem'),'--apiserver-ca',str(root/'api-ca.pem'),'--apiserver-spki-sha256',pin,'--identity-prefix','asterius:temporary:online:']
adapter=subprocess.Popen(adapter_command,stdout=adapter_log,stderr=adapter_log)
secondary_log=(root/'adapter-secondary.log').open('w')
secondary_command=list(adapter_command);secondary_command[secondary_command.index('--listen')+1]='0.0.0.0:9471'
secondary=subprocess.Popen(secondary_command,stdout=secondary_log,stderr=secondary_log)
(root/'adapter-secondary.pid').write_text(str(secondary.pid))
transport=OpaqueTlsTransport()
(root/'adapter.pid').write_text(str(adapter.pid))

try:
    context=ssl.create_default_context(cafile=root/'cert.pem'); context.load_cert_chain(root/'api-client.pem',root/'api-client.key')
    wrong_context=ssl.create_default_context(cafile=root/'cert.pem'); wrong_context.load_cert_chain(root/'wrong-client.pem',root/'wrong-client.key')
    def adapter_review(token,ctx=context):
        body=json.dumps({'apiVersion':'authentication.k8s.io/v1','kind':'TokenReview','metadata':{'creationTimestamp':None},'spec':{'token':token,'audiences':['app']},'status':{'user':{}}}).encode()
        try: response=urllib.request.urlopen(urllib.request.Request('https://localhost:'+str(9470 if adapter.poll() is None else 9471)+'/review',body,{'Content-Type':'application/json'}),context=ctx,timeout=5)
        except urllib.error.HTTPError as error: response=error
        raw_response=response.read(65537)
        return response.status,json.loads(raw_response) if raw_response else {}
    deadline=time.monotonic()+10
    while True:
        try:
            assert adapter_review(first['id_token'])[1]['status']['authenticated']; break
        except urllib.error.URLError:
            assert adapter.poll() is None and time.monotonic()<deadline,'owned adapter startup';time.sleep(.1)
    try:
        assert adapter_review(first['id_token'],wrong_context)[0]==403,'trusted CA leaf without exact SPKI denied'
    except (http.client.RemoteDisconnected,ssl.SSLError,urllib.error.URLError):
        # Closed connection is also refusal, and a following pinned positive
        # distinguishes it from outage of the adapter itself.
        assert adapter_review(first['id_token'])[1]['status']['authenticated'],'pinned positive survives refused wrong certificate'
    no_client=ssl.create_default_context(cafile=root/'cert.pem')
    try: adapter_review(first['id_token'],no_client); raise AssertionError('mTLS client certificate mandatory')
    except (urllib.error.URLError,ssl.SSLError): pass
    record_check('real_mtls_and_exact_spki')
    # Webhook-only kind configuration: no native OIDC or structured JWT fallback.
    webhook={'apiVersion':'v1','kind':'Config','clusters':[{'name':'review','cluster':{'server':'https://localhost:9472/review','certificate-authority':'/etc/kubernetes/online/cert.pem'}}],'users':[{'name':'api','user':{'client-certificate':'/etc/kubernetes/online/api-client.pem','client-key':'/etc/kubernetes/online/api-client.key'}}],'contexts':[{'name':'review','context':{'cluster':'review','user':'api'}}],'current-context':'review'}
    (root/'webhook.json').write_text(json.dumps(webhook))
    patch={'kind':'ClusterConfiguration','apiServer':{'extraArgs':{'authentication-token-webhook-config-file':'/etc/kubernetes/online/webhook.json','authentication-token-webhook-version':'v1','authentication-token-webhook-cache-ttl':'0s','api-audiences':'app'},'extraVolumes':[{'name':'online','hostPath':'/etc/kubernetes/online','mountPath':'/etc/kubernetes/online','readOnly':True,'pathType':'Directory'}]}}
    kind_config={'kind':'Cluster','apiVersion':'kind.x-k8s.io/v1alpha4','nodes':[{'role':'control-plane','extraMounts':[{'hostPath':str(root),'containerPath':'/etc/kubernetes/online','readOnly':True}],'kubeadmConfigPatches':[json.dumps(patch)]}]}
    (root/'kind.json').write_text(json.dumps(kind_config));(root/'cluster-created').touch()
    cluster='asterius-dd1y15'; kind_log=(root/'kind.log').open('w')
    create=subprocess.Popen(['kind','create','cluster','--name',cluster,'--image','kindest/node:v1.35.0','--config',str(root/'kind.json'),'--kubeconfig',str(root/'admin-kubeconfig'),'--wait','120s'],stdout=kind_log,stderr=kind_log)
    try:
        deadline=time.monotonic()+90
        while subprocess.run(['docker','inspect',cluster+'-control-plane'],capture_output=True).returncode:
            assert create.poll() is None and time.monotonic()<deadline;time.sleep(.25)
        gateway=next(x['Gateway'] for x in json.loads(subprocess.check_output(['docker','network','inspect','kind']))[0]['IPAM']['Config'] if ':' not in x['Gateway'])
        subprocess.run(['docker','run','-d','--name',cluster+'-issuer','--network','container:'+cluster+'-control-plane','alpine/socat@sha256:5ffbd6ae916cbad86a58fabe0d6d5a6fd5c2b47ddf031e82996baac9300e732f','TCP-LISTEN:9472,bind=127.0.0.1,fork,reuseaddr','TCP:'+gateway+':9472'],check=True,capture_output=True)
        assert create.wait(timeout=150)==0,'owned webhook-only Kubernetes startup'
    finally:
        if create.poll() is None:create.terminate();create.wait(timeout=20)
        kind_log.close()
    def kube_admin(*args,data=None):
        return subprocess.run(['kubectl','--kubeconfig',str(root/'admin-kubeconfig'),*args],input=data,check=True,capture_output=True,text=True).stdout
    kube_admin('create','namespace','online');kube_admin('-n','online','create','configmap','proof','--from-literal=purpose=owned-online-review')
    kube_admin('apply','-f','-',data=json.dumps({'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'name':'online-view','namespace':'online'},'subjects':[{'kind':'Group','apiGroup':'rbac.authorization.k8s.io','name':'asterius:temporary:online:group:group:'+group}],'roleRef':{'kind':'ClusterRole','apiGroup':'rbac.authorization.k8s.io','name':'view'}}))
    cluster_config=json.loads(kube_admin('config','view','--raw','-o','json'))['clusters'][0]['cluster']
    (root/'kube-ca.pem').write_bytes(base64.b64decode(cluster_config['certificate-authority-data']))
    kube_context=ssl.create_default_context(cafile=root/'kube-ca.pem')
    def kube_get(token,timeout=5):
        # Bearer only: never accidentally attach the kind admin client certificate.
        try: response=urllib.request.urlopen(urllib.request.Request(cluster_config['server']+'/api/v1/namespaces/online/configmaps/proof',headers={'Authorization':'Bearer '+token}),context=kube_context,timeout=timeout)
        except urllib.error.HTTPError as error:response=error
        response.read(65537);return response.status
    native_status=kube_get(first['id_token'])
    assert native_status==200,'real Kube webhook authenticates held code token status='+str(native_status)+' source_group_match='+str('asterius:temporary:online:group:group:'+group in adapter_review(first['id_token'])[1].get('status',{}).get('user',{}).get('groups',[]))
    assert kube_get(second['id_token'])==200,'second independent grant works'
    # Two production replicas behind an opaque TLS connection selector. Kill
    # the first replica, then require an uncached human token via the second.
    failover_token,_,_=code_tokens()
    adapter.terminate();adapter.wait(timeout=10)
    assert secondary.poll() is None,'independent adapter replica remains alive'
    deadline=time.monotonic()+10
    while kube_get(failover_token['id_token'])!=200:
        assert time.monotonic()<deadline,'uncached native credential survives single-replica loss';time.sleep(.25)
    record_check('two_production_adapters_opaque_tls_failover_uncached_native_identity')
    # Warm the existing mTLS connection using a different token. The next token
    # has never been observed by Kubernetes' outer authentication cache.
    delayed,_,_=code_tokens();delayed_binding=binding(delayed['id_token'])
    assert authenticated(delayed['id_token']),'delayed credential initially has exact current source authority'
    transport.hold()
    wire_started=time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        # The production route still has its unmodified3-second deadline. This
        # caller allows the pinned upstream30-second timeout to be exercised.
        pending=executor.submit(kube_get,delayed['id_token'],35)
        try:
            assert transport.buffered.wait(5),'opaque server ciphertext withheld on warmed mTLS connection'
            # Await production handler completion before changing authority.
            # Its local deadline is3 seconds; ciphertext has already left it.
            time.sleep(3.5)
            assert not pending.done(),'encrypted response is withheld outside completed adapter route'
            revoked_at=time.monotonic()
            assert owner.admin('DELETE','/users/'+ids['requester']+'/grants/'+delayed_binding['grant'])[0] in (200,204),'revoke exact grant while completed response is held in transport'
            assert not authenticated(delayed['id_token']),'current primary authority denies held response token'
            target_release=wire_started+25
            while time.monotonic()<target_release:time.sleep(min(.25,target_release-time.monotonic()))
            transport.release()
            assert pending.result(timeout=8)==200,'previously completed positive can arrive after revocation'
            stale_arrival=time.monotonic()-wire_started
            last_positive=stale_arrival
            deadline=wire_started+45
            while kube_get(delayed['id_token'])==200:
                last_positive=time.monotonic()-wire_started
                assert time.monotonic()<deadline,'source-derived40s bound plus scheduling margin';time.sleep(.25)
            delayed_denial=time.monotonic()-wire_started
            assert 23<=stale_arrival<=30 and delayed_denial>=stale_arrival+8,'delayed response starts outer success cache after completed lookup'
            print(json.dumps({'measurement':'delayed_wire_and_outer_cache','stale_arrival_seconds':round(stale_arrival,3),'last_native_positive_seconds':round(last_positive,3),'native_denial_seconds':round(delayed_denial,3),'revocation_seconds':round(revoked_at-wire_started,3),'revocation_to_denial_seconds':round(time.monotonic()-revoked_at,3)}),flush=True)
        finally:transport.release()
    record_check('opaque_delayed_completed_response_and_outer_cache_bound')
    # A held completed positive which crosses the upstream30-second deadline
    # must never enter the outer cache after its abandoned lookup has finished.
    assert kube_get(failover_token['id_token'])==200,'warm current replica TLS before timeout trial'
    abandoned,_,_=code_tokens()
    status,_,abandoned_refresh=client.authenticated('/token',{'grant_type':'refresh_token','refresh_token':abandoned['refresh_token'],'resource':resource})
    assert status==200,'fresh original-grant renewal before timeout trial'
    abandoned_token=abandoned_refresh['id_token'];abandoned_binding=binding(abandoned_token)
    assert authenticated(abandoned_token),'timeout-trial grant initially current'
    transport.hold();abandoned_started=time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        pending=executor.submit(kube_get,abandoned_token,42)
        try:
            assert transport.buffered.wait(5),'timeout-trial server ciphertext withheld'
            time.sleep(3.5)
            assert owner.admin('DELETE','/users/'+ids['requester']+'/grants/'+abandoned_binding['grant'])[0] in (200,204),'timeout-trial exact grant revoke'
            assert not authenticated(abandoned_token)
            # The response remains withheld while the pinned30-second native
            # lookup times out. A caller timeout shorter than this is not used.
            outcome=pending.result(timeout=30)
            abandoned_timeout=time.monotonic()-abandoned_started
            assert outcome in (401,500) and 28<=abandoned_timeout<=34,'native upstream lookup deadline refuses unavailable response'
            while time.monotonic()<abandoned_started+35:time.sleep(.25)
            transport.release()
            assert kube_get(abandoned_token) in (401,500),'releasing late ciphertext cannot populate a successful cache entry'
            time.sleep(1)
            assert kube_get(abandoned_token) in (401,500),'abandoned positive remains denied after late-release scheduling'
            print(json.dumps({'measurement':'late_completed_response_after_native_timeout','timeout_seconds':round(abandoned_timeout,3),'late_release_seconds':35,'late_positive_cached':False}),flush=True)
        finally:transport.release()
    record_check('past_native_lookup_timeout_never_late_caches_completed_positive')


    assert kube_get(first['id_token'])==200,'refresh warm outer-cache positive immediately before revoke'
    started=time.monotonic()
    assert owner.admin('DELETE','/users/'+ids['requester']+'/grants/'+first_binding['grant'])[0] in (200,204),'exact real grant revoke'
    assert not authenticated(first['id_token']) and authenticated(second['id_token']),'other same-user grant cannot repair revoked digest binding'
    deadline=time.monotonic()+45
    while kube_get(first['id_token'])==200:
        assert time.monotonic()<deadline,'documented 40s+margin revoke bound';time.sleep(.25)
    revoke_seconds=time.monotonic()-started
    print(json.dumps({'measurement':'native_warm_revoke_seconds','seconds':round(revoke_seconds,3)}),flush=True)
    assert kube_get(second['id_token'])==200,'independent same-user grant remains valid in actual Kubernetes'
    record_check('actual_kube_exact_grant_revocation_and_other_grant_survival')
    # Current group removal narrows old signed release; addition cannot add unsigned groups.
    sql(f"delete from group_memberships where tenant_id='temporary' and group_id={quote(group)} and user_id={quote(ids['requester'])}")
    assert review(second['id_token'])[1]['status']['user']['groups']==[],'current group removed immediately at uncached review'
    deadline=time.monotonic()+45
    while kube_get(second['id_token'])==200:
        assert time.monotonic()<deadline;time.sleep(.25)
    assert kube_get(second['id_token'])==403,'live removal preserves identity but removes native RBAC'
    sql(f"insert into group_memberships(tenant_id,group_id,user_id,created_at) values('temporary',{quote(additional_group)},{quote(ids['requester'])},clock_timestamp())")
    assert review(second['id_token'])[1]['status']['user']['groups']==[],'later directory addition cannot widen old signed release'
    record_check('signed_groups_intersect_current_membership_and_addition_cannot_widen')
    assert owner.admin('PUT','/users/'+ids['requester']+'/status',{'enabled':False})[0]==200,'real ordinary user disable'
    assert not authenticated(second['id_token']),'disabled human denies while signed JWT remains valid'
    record_check('real_user_disable_live_review')
    logout_tokens,_,_=code_tokens(browser=stranger)
    assert authenticated(logout_tokens['id_token'])
    status,_,page=stranger.request('GET',issuer+'/logout'); assert status==200
    forms=Forms();forms.feed(page)
    form=next(form for form in forms.forms if 'csrf' in form['values'])
    status,_,_=stranger.request('POST',urllib.parse.urljoin(issuer+'/logout',form['action']),urllib.parse.urlencode(form['all']+[('decision','logout')]).encode(),{'Content-Type':'application/x-www-form-urlencoded','Origin':origin})
    assert status in (200,302,303),'real RP logout form'
    assert not authenticated(logout_tokens['id_token']),'logout denies exact held public SID'
    record_check('real_browser_logout_live_review')
    # Terminate adapter; this fresh, previously unobserved token cannot hit the outer cache.
    third,_,_=code_tokens(browser=approver)
    assert authenticated(third['id_token']),'live exact grant before availability controls'
    # A complete-route timeout includes authenticated source lookup and waiting
    # for authoritative table access, rather than only timing the SQL statement.
    lock_application='ast-dd1y15-lock-'+secrets.token_hex(6)
    lock_env={**os.environ,'PGAPPNAME':lock_application}
    locker=subprocess.Popen(['psql',database,'-X','-q','-v','ON_ERROR_STOP=1','-c',"begin;lock table kubernetes_online_tokens in access exclusive mode;select pg_sleep(60);rollback;"],env=lock_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        deadline=time.monotonic()+5
        while sql("select count(*) from pg_locks l join pg_stat_activity a on a.pid=l.pid where a.datname=current_database() and a.application_name="+quote(lock_application)+" and l.relation='kubernetes_online_tokens'::regclass and l.mode='AccessExclusiveLock' and l.granted")!='1':
            assert locker.poll() is None and time.monotonic()<deadline,'own lock transaction established';time.sleep(.05)
        started=time.monotonic();status,result=review(third['id_token']);elapsed=time.monotonic()-started
        assert status==200 and not result['status']['authenticated'],'entire route deadline refuses held token during primary-state contention'
        assert 2.5<=elapsed<=4.5,'three-second complete-route lock timeout with bounded local scheduling margin'
    finally:
        # This application name exists only on this explicitly owned nonce DB.
        sql("select pg_terminate_backend(pid) from pg_stat_activity where datname=current_database() and application_name="+quote(lock_application)+" and pid<>pg_backend_pid()")
        if locker.poll() is None:locker.terminate()
        locker.wait(timeout=10)
    assert authenticated(third['id_token']),'released own lock restores current source authentication'
    record_check('complete_three_second_route_timeout_under_owned_table_lock')
    # Disable connection admission and terminate only this nonce database's
    # existing connections. The pinned admin connection stays on /postgres.
    database_name=owned_database.path[1:]
    assert database_name.startswith('ast_online_') and all(c.isalnum() or c=='_' for c in database_name),'owned database identifier only'
    database_admin=urllib.parse.urlunsplit(owned_database._replace(path='/postgres'))
    def admin_sql(statement):
        return subprocess.run(['psql',database_admin,'-X','-q','-At','-v','ON_ERROR_STOP=1','-c',statement],check=True,capture_output=True,text=True).stdout.strip()
    never_cached,_,_=code_tokens(browser=approver)
    # Do not review this digest before outage: the native outer token cache
    # therefore cannot conceal loss of primary database authority.
    try:
        admin_sql('alter database "'+database_name+'" allow_connections false')
        admin_sql("select pg_terminate_backend(pid) from pg_stat_activity where datname="+quote(database_name)+" and pid<>pg_backend_pid()")
        status,result=adapter_review(never_cached['id_token'])
        assert status==200 and not result['status']['authenticated'],'adapter refuses identity without primary database'
        assert kube_get(never_cached['id_token']) in (401,500),'actual uncached Kubernetes credential denied during primary database outage'
    finally:
        admin_sql('alter database "'+database_name+'" allow_connections true')
    deadline=time.monotonic()+20
    while True:
        try:
            if authenticated(third['id_token']):break
        except (urllib.error.URLError,ValueError):pass
        assert time.monotonic()<deadline,'own primary database restoration';time.sleep(.25)
    record_check('owned_primary_database_outage_uncached_native_fail_closed_and_recovery')
    # A different fresh token is used for total adapter outage, after primary
    # recovery, so no preceding rejection/cache observation is being reused.
    adapter_outage_token,_,_=code_tokens(browser=approver)
    secondary.terminate();secondary.wait(timeout=10)
    assert kube_get(adapter_outage_token['id_token']) in (401,500),'all-adapter outage refuses fresh uncached identity'
    record_check('all_adapter_outage_no_native_oidc_fallback')
    assert authenticated(third['id_token']),'direct source review still healthy during isolated adapter outage'
    sql("update clients set managed_groups_claim=false where tenant_id='temporary' and client_id='app'")
    assert not authenticated(third['id_token']),'human metadata change terminally disables online mode'
    sql("update clients set managed_groups_claim=true where tenant_id='temporary' and client_id='app'")
    assert not authenticated(third['id_token']),'metadata restoration cannot revive old digest'
    status,_,disabled=owner.admin('GET',profile_path);assert status==200 and not disabled['enabled']
    status,_,renewed=owner.admin('PUT',profile_path,{'reviewer_client_id':'controller','enabled':True,'expected_revision':disabled['revision']});assert status==200
    assert not authenticated(third['id_token']),'explicit re-enable UUID generation does not resurrect prior binding'
    fresh,_,_=code_tokens(browser=approver);assert authenticated(fresh['id_token']),'fresh login after reviewed profile generation regains valid identity'
    record_check('terminal_metadata_restore_and_revision_aba_denial')
    print(json.dumps({'status':'pass','controls':checks,'measured_revoke_seconds':round(revoke_seconds,3),'limits':['seeded browser/session proofs; no new WebAuthn ceremony','opaque25s completed-response hold plus outer cache measured; entire40s worst-case boundary not saturated','two adapter replicas tested; primary-database replication and signature/storage races not tested']}))
finally:
    transport.close()
    if secondary.poll() is None:secondary.terminate();secondary.wait(timeout=10)
    secondary_log.close()
    if adapter.poll() is None:adapter.terminate();adapter.wait(timeout=10)
    adapter_log.close()
