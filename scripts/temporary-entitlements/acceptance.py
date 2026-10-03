#!/usr/bin/env python3
"""Real HTTPS lifecycle and signed code/refresh fixture using seeded PG proofs.
The fixture does not claim a fresh WebAuthn ceremony: proof provenance is seeded
explicitly, while auth-code/PAR/PKCE/private_key_jwt/DPoP and lifecycle are real.
Only aggregate control names are emitted, never sessions, tokens or reasons.
"""
import base64
import hashlib
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
if os.environ.get('ASTERIUS_TEMPORARY_BROWSER_SCRIPT'):
    browser_input = root / 'temporary-browser.json'
    browser_input.write_text(json.dumps({'issuer':issuer,'origin':origin,'owner_session':raw['owner'],'owner_user_id':ids['owner'],'requester_cookie':raw['requester'],'reader_session':raw['stranger'],'client_id':'app','resource':resource,'role_name':'incident-responder','permissions':['read'],'entitlement_id':entitlement_id,'screenshot_path':os.environ.get('ASTERIUS_TEMPORARY_SCREENSHOT_PATH')}))
    browser_input.chmod(0o600)
    try:
        result = subprocess.run(['node',os.environ['ASTERIUS_TEMPORARY_BROWSER_SCRIPT'],str(browser_input)],capture_output=True,text=True,timeout=120)
        assert result.returncode==0, 'real Chromium temporary owner/read-only UI acceptance: '+result.stderr.strip()[:512]
        browser_result = json.loads(result.stdout.strip())
        assert browser_result['status']=='pass'
        checks.append('real_chromium_owner_and_read_only_ui')
    finally:
        browser_input.unlink(missing_ok=True)
def requests():
    result=owner.admin('GET',path+'/requests'); assert result[0] == 200; return result[2]['items']
def activations():
    result=owner.admin('GET',path+'/activations'); assert result[0] == 200; return result[2]['items']
def submit(duration=30):
    command={'entitlement_id':entitlement_id,'duration_seconds':duration,'reason':'<script>incident</script> '+secrets.token_hex(4),'idempotency_key':str(uuid.uuid4())}
    assert requester.command('request',command)[0] == 303, 'ordinary request'
    request_id=next(item['request_id'] for item in requests() if item['status']=='pending' and item['reason']==command['reason'])
    assert requester.command('request',command)[0] == 303, 'same body replay'
    assert requester.command('request',{**command,'duration_seconds':duration+1})[0] == 404, 'changed replay payload refused'
    return request_id
# A historical session label is insufficient when its frozen proof is weak.
requester_digest=hashlib.sha256(raw['requester'].encode()).hexdigest()
sql(f"update session_assurance_proofs set assurance_methods=array['pwd'] where tenant_id='temporary' and session_id={quote(requester_digest)};")
probe={'entitlement_id':entitlement_id,'duration_seconds':30,'reason':'Weak proof refused','idempotency_key':str(uuid.uuid4())}
assert requester.command('request',probe)[0]==200 and not requests(), 'weak proof shows remedy without authority'
sql(f"update session_assurance_proofs set assurance_methods=array['pop','user'] where tenant_id='temporary' and session_id={quote(requester_digest)};")
assert requester.command('request',{**probe,'duration_seconds':61})[0]==400, 'owner duration ceiling'
checks.append('frozen_methods_and_duration_fail_closed')
request_id=submit()
assert requester.command('decide',{'request_id':request_id,'decision':'approve','idempotency_key':str(uuid.uuid4())})[0] == 404, 'self-approval refused'
assert owner.command('decide',{'request_id':request_id,'decision':'approve','idempotency_key':str(uuid.uuid4())})[0] == 404, 'configuration editor refused'
assert stranger.command('decide',{'request_id':request_id,'decision':'approve','idempotency_key':str(uuid.uuid4())},csrf='posted-no-authority')[0] == 403, 'forged ordinary CSRF refused'
decision={'request_id':request_id,'decision':'approve','idempotency_key':str(uuid.uuid4())}
assert approver.command('decide',decision)[0] == 303, 'independent approval'
assert approver.command('decide',decision)[0] == 303, 'approval replay'
active=next(item for item in activations() if item['status']=='active')
assert len(activations()) == 1, 'one immutable activation'
status, _, html=requester.request('GET',issuer+'/account/entitlements')
assert status == 200 and '<script>incident</script>' not in html and ids['requester'] in html, 'escaped immutable decision details'
checks.append('independent_scope_immutable_approval_and_command_replay')
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

def code_tokens(selected_resource=resource, scopes='openid offline_access read'):
    verifier=secrets.token_urlsafe(32); state=secrets.token_urlsafe(24); nonce=secrets.token_urlsafe(24)
    status, _, pushed=client.authenticated('/par',{'response_type':'code','redirect_uri':callback,'scope':scopes,'resource':selected_resource,'state':state,'nonce':nonce,'code_challenge_method':'S256','code_challenge':b64(hashlib.sha256(verifier.encode()).digest())})
    assert status==201, 'real authenticated PAR'
    url=issuer+'/authorize?'+urllib.parse.urlencode({'client_id':'app','request_uri':pushed['request_uri']})
    for _ in range(8):
        status, headers, body=requester.request('GET',url)
        if status in (302,303):
            location=urllib.parse.urljoin(url,headers['Location'])
            if location.startswith(callback): break
            assert location.startswith(issuer+'/'), 'bounded authorization redirect'; url=location; continue
        assert status==200, 'strong seeded session reaches consent'
        forms=Forms(); forms.feed(body)
        consent=next(form for form in forms.forms if 'csrf' in form['values'] and any(name=='scope' for name,_ in form['all']))
        status, headers, _=requester.request('POST',urllib.parse.urljoin(url,consent['action']),urllib.parse.urlencode(consent['all']+[('decision','allow')]).encode(),{'Content-Type':'application/x-www-form-urlencoded','Origin':origin})
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

def privileged(claim): return 'incident-responder' in claim.get('resource_access',{}).get('app',{}).get('roles',[])
issued, access, identity=code_tokens()
assert privileged(access) and privileged(identity), 'temporary role in both signed tokens'
assert privileged(userinfo(issued['access_token'])), 'current active UserInfo role'
assert access['exp']<=active['expires_at'] and identity['exp']<=active['expires_at'], 'access and ID expiry capped'
status, _, refreshed=client.authenticated('/token',{'grant_type':'refresh_token','refresh_token':issued['refresh_token']})
assert status==200 and privileged(claims(refreshed['access_token'],resource)), 'real refresh retains currently authorized role'
assert claims(refreshed['access_token'],resource)['exp']<=active['expires_at'], 'refresh expiry remains capped'
foreign_issued, access, identity=code_tokens(foreign_resource)
assert not privileged(access) and not privileged(identity), 'different resource never receives temporary role'
assert not privileged(userinfo(foreign_issued['access_token'])), 'UserInfo cannot recover original-resource authority'
narrow_issued, access, identity=code_tokens(resource,'openid')
assert not privileged(access) and not privileged(identity), 'insufficient actual scope never receives role'
assert not privileged(userinfo(narrow_issued['access_token'])), 'UserInfo respects actual narrow token scope'
status, _, machine=client.authenticated('/token',{'grant_type':'client_credentials','scope':'read','resource':resource})
assert status==200 and not privileged(claims(machine['access_token'],resource)), 'nonhuman grant never receives temporary role'
extra_issued, access, identity=code_tokens(resource,'openid read write')
assert not privileged(access) and not privileged(identity), 'extra resource permission cannot broaden immutable role approval'
assert not privileged(userinfo(extra_issued['access_token'])), 'UserInfo cannot combine read approval with write permission'
checks.append('real_signed_code_refresh_exact_resource_scopes_human_and_deadline')
revoke={'activation_id':active['activation_id'],'reason':'Incident ended','idempotency_key':str(uuid.uuid4())}
status, _, revoked=owner.admin('POST',path+'/activations/'+active['activation_id']+'/revoke',revoke)
assert status==200 and revoked['status']=='revoked', 'owner revocation'
assert owner.admin('POST',path+'/activations/'+active['activation_id']+'/revoke',revoke)[2]==revoked, 'owner response-loss replay'
assert not privileged(userinfo(issued['access_token'])), 'live UserInfo removes revoked role from still-valid offline credential'
status, _, after=client.authenticated('/token',{'grant_type':'refresh_token','refresh_token':refreshed.get('refresh_token',issued['refresh_token'])})
assert status in (200,400), 'revoked activation issuance result'
if status==200: assert not privileged(claims(after['access_token'],resource)), 'revocation removes privileged issuance'
_, access, identity=code_tokens()
assert not privileged(access) and not privileged(identity), 'new code cannot resurrect activation'
checks.append('revocation_current_recheck_and_bounded_residual_tokens')
request_id=submit(1)
assert approver.command('decide',{'request_id':request_id,'decision':'approve','idempotency_key':str(uuid.uuid4())})[0]==303
# Actual time elapses; neither fixture nor runtime edits an immutable deadline.
time.sleep(1.2)
_, access, identity=code_tokens()
assert not privileged(access) and not privileged(identity), 'expiry denies without reconciliation'
assert any(item['status']=='expired' for item in activations())
checks.append('database_clock_expiry_without_background_cleanup')
assert owner.request('GET',origin+'/t/temporary-foreign/admin/api/v1/temporary-entitlements/'+entitlement_id)[0]==401, 'foreign tenant session is anonymous and ownership not exposed'
# The online PDP has its own explicitly approved resource/permission tuple.
# A business-resource activation cannot be borrowed as PDP authority.
pdp_configuration={**configuration,'resource':pdp,'role_name':'pdp-check','permissions':['authzen.evaluate']}
status, _, pdp_entitlement=owner.admin('POST','/temporary-entitlements',pdp_configuration)
assert status==201, 'current PDP fixture configuration'
pdp_path='/temporary-entitlements/'+pdp_entitlement['entitlement_id']
now=int(time.time())
assert owner.admin('POST',pdp_path+'/eligibilities',{'user_id':ids['requester'],'not_before':now-1,'expires_at':now+600,'expected_revision':None})[0]==200
policy={'version':1,'rules':[{'id':'base','effect':'permit'}],'conditional_scopes':[{'id':'current-pdp-role','mode':'active','clients':['app'],'actions':['access_evaluation'],'rules':[{'id':'independent-live-pdp-role','effect':'permit','when':{'role':{'name':'pdp-check','owner':'app'}}}]}]}
assert owner.admin('PUT','/policies',policy,key=str(uuid.uuid4()))[0]==409, 'unguarded conditional policy refused'
status, _, prior_policy=owner.admin('GET','/policies'); assert status==200
headers={'Content-Type':'application/json','Origin':origin,'Sec-Fetch-Site':'same-origin','X-CSRF-Token':owner.csrf}
headers.update({'If-None-Match':'*'} if prior_policy['revision'] is None else {'If-Match':'"'+prior_policy['revision']+'"'})
assert owner.request('PUT',api+'/policies',policy,headers)[0]==200, 'guarded active PDP role boundary'
question={'subject':{'type':'user','id':ids['requester']},'action':{'name':'read'},'resource':{'type':'application','id':'app'}}
def evaluate(token):
    previous=client.token; client.token=token
    try:
        actual_question={**question,'subject':{'type':'user','id':claims(token,pdp)['sub']}}
        status, _, result=client.request('POST',pdp,actual_question,{'Content-Type':'application/json'})
        assert status==200, 'real online current-role PDP evaluation'
        return result['decision']
    finally: client.token=previous
pdp_issued, _, _=code_tokens(pdp,'openid authzen.evaluate')
assert evaluate(pdp_issued['access_token']) is False, 'eligibility alone never supplies current PDP role'
command={'entitlement_id':pdp_entitlement['entitlement_id'],'duration_seconds':30,'reason':'Controlled current PDP evaluation','idempotency_key':str(uuid.uuid4())}
assert requester.command('request',command)[0]==303
pdp_requests=owner.admin('GET',pdp_path+'/requests')[2]['items']
pdp_request=next(item for item in pdp_requests if item['status']=='pending')
assert approver.command('decide',{'request_id':pdp_request['request_id'],'decision':'approve','idempotency_key':str(uuid.uuid4())})[0]==303
pdp_issued, _, _=code_tokens(pdp,'openid authzen.evaluate')
assert evaluate(pdp_issued['access_token']) is True, 'live exact-PDP activation supplies role online'
wider_pdp, _, _=code_tokens(pdp,'openid authzen.evaluate write')
assert evaluate(wider_pdp['access_token']) is False, 'PDP cannot borrow role from wider verified scope'
pdp_activation=next(item for item in owner.admin('GET',pdp_path+'/activations')[2]['items'] if item['status']=='active')
assert owner.admin('POST',pdp_path+'/activations/'+pdp_activation['activation_id']+'/revoke',{'activation_id':pdp_activation['activation_id'],'reason':'PDP control complete','idempotency_key':str(uuid.uuid4())})[0]==200
assert evaluate(pdp_issued['access_token']) is False, 'same credential observes committed PDP revocation'
checks.append('real_active_pdp_exact_permission_current_role_and_revocation')
# Marking the exact client as an agent invalidates its policy; restoring the
# flag cannot restore an old activation or approval revision.
request_id=submit(30)
sql("update clients set is_agent=true where tenant_id='temporary' and client_id='app';")
sql("update clients set is_agent=false where tenant_id='temporary' and client_id='app';")
assert owner.admin('GET',path)[2]['enabled'] is False, 'agent catalogue ABA terminal'
assert approver.command('decide',{'request_id':request_id,'decision':'approve','idempotency_key':str(uuid.uuid4())})[0]==404
checks.append('foreign_tenant_and_agent_catalogue_aba_refusals')
print(json.dumps({'fixture':'real_https_seeded_frozen_proof_code_refresh_lifecycle','status':'pass','checks':checks},sort_keys=True))
