#!/usr/bin/env python3
"""Controlled owner-session fixtures against real HTTPS/FAPI handlers.
The seeded grant/session are test inputs, not evidence of a real human login.
No tokens, assertions, session cookies or CSRF values are printed.
"""
import base64
import hashlib
import json
import pathlib
import os
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding, utils
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scim"))
from dpop_fixture import FixtureClient, sign, b64
run,database,issuer=sys.argv[1:]
root=pathlib.Path(run)
resource=issuer+"/admin/api/v1"
owner=str(uuid.uuid4());other=str(uuid.uuid4());root_grant=str(uuid.uuid4())
cookie=secrets.token_urlsafe(32);other_cookie=secrets.token_urlsafe(32);stale_cookie=secrets.token_urlsafe(32)
key=ec.generate_private_key(ec.SECP256R1());number=key.public_key().public_numbers()
jwk={"kty":"EC","crv":"P-256","x":b64(number.x.to_bytes(32,"big")),"y":b64(number.y.to_bytes(32,"big")),"kid":"task-agent","alg":"ES256","use":"sig"}
(root/"agent.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
literal=lambda value:"'"+str(value).replace("'","''")+"'"
def sql(statement,output=False):
    result=subprocess.run(["psql",database,"-X","-At","-v","ON_ERROR_STOP=1","-c",statement],check=True,capture_output=True,text=True)
    return result.stdout.strip() if output else None
ceiling={"scopes":["admin.scim:read"],"resources":[resource],"authorization_details":[{"type":"urn:asterius:workload-actions","actions":["read"],"locations":[resource]}],"max_delegation_depth":2}
full_detail=[{"type":"urn:asterius:workload-actions","actions":["read","write"],"locations":[resource]}]
schema=json.loads((pathlib.Path(__file__).resolve().parents[2]/"examples/kubernetes/workload-exchange/actions-schema.json").read_text())
policy={"grant_types":["client_credentials","urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:device_code"],"max_delegation_depth":2,"scopes":["admin.scim:read","admin.scim:write"],"audiences":[resource],"access_token_ttl_seconds":120}
sql(f"""insert into users(tenant_id,user_id,username,status) values('tasks',{literal(owner)},'controlled-owner','active'),('tasks',{literal(other)},'foreign-owner','active');
insert into resource_servers(tenant_id,identifier,scopes) values('tasks',{literal(resource)},array['admin.scim:read','admin.scim:write','admin.grants:write','admin.audit:read']);
insert into authorization_details_types(tenant_id,type_name,schema) values('tasks','urn:asterius:workload-actions',{literal(json.dumps(schema))}::jsonb);
insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks,is_agent,agent_owner_user_id,agent_policy,authorization_details_types) values('tasks','task-agent','Controlled agent','private_key_jwt',array['client_credentials','urn:ietf:params:oauth:grant-type:token-exchange','urn:ietf:params:oauth:grant-type:device_code'],array[]::text[],array['admin.scim:read','admin.scim:write'],array[{literal(resource)}],{literal(json.dumps({'keys':[jwk]}))}::jsonb,true,{literal(owner)},{literal(json.dumps(policy))}::jsonb,array['urn:asterius:workload-actions']);
insert into grants(tenant_id,grant_id,client_id,user_id,subject,scopes,resources,authorization_details,claimed_at,expires_at) values('tasks',{literal(root_grant)},'task-agent',{literal(owner)},'controlled-owner-subject',array['admin.scim:read','admin.scim:write'],array[{literal(resource)}],{literal(json.dumps(full_detail))}::jsonb,now(),now()+interval '30 minutes');""")
for presented,user,age in [(cookie,owner,0),(other_cookie,other,0),(stale_cookie,owner,180)]:
    digest=hashlib.sha256(presented.encode()).hexdigest()
    sql(f"insert into sessions(tenant_id,session_id,public_sid,user_id,authenticated_at,expires_at,idle_expires_at,amr) values('tasks',{literal(digest)},{literal(str(uuid.uuid4()))},{literal(user)},now()-interval '{age} seconds',now()+interval '1 hour',now()+interval '1 hour',array['pop','user']);")
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args): return None
context=ssl.create_default_context(cafile=root/"cert.pem")
opener=urllib.request.build_opener(NoRedirect(),urllib.request.HTTPSHandler(context=context))
def owner_request(method,path,form=None,session=cookie):
    body=urllib.parse.urlencode(form).encode() if form is not None else None
    request=urllib.request.Request(issuer+path,body,{"Cookie":"__Host-asterius_session="+session,"Content-Type":"application/x-www-form-urlencoded"},method=method)
    try: response=opener.open(request,timeout=20)
    except urllib.error.HTTPError as error: response=error
    raw=response.read(65537);assert len(raw)<=65536,"response bound"
    parsed=json.loads(raw) if response.headers.get("Content-Type","").startswith("application/json") else None
    return response.status,response.headers,parsed
status,_,preview=owner_request("GET","/account/agent-tasks/approval?root_grant_id="+root_grant)
assert status==200 and preview["client_id"]=="task-agent","fresh owner preview"
assert owner_request("GET","/account/agent-tasks/approval?root_grant_id="+root_grant,session=other_cookie)[0]==404,"owner boundary"
assert owner_request("GET","/account/agent-tasks/approval?root_grant_id="+root_grant,session=stale_cookie)[0]==303,"fresh authentication requirement"
form={"root_grant_id":root_grant,"csrf":preview["csrf"],"confirm":"approve","label":"controlled run","expires_in":"600","permissions":json.dumps(ceiling)}
assert owner_request("POST","/account/agent-tasks/approve",{**form,"csrf":"forged"})[0]==403,"CSRF refusal"
expanded=json.loads(json.dumps(ceiling));expanded["scopes"]=["admin.fake:error"]
assert owner_request("POST","/account/agent-tasks/approve",{**form,"permissions":json.dumps(expanded)})[0]==409,"approval expansion refusal"
status,headers,binding=owner_request("POST","/account/agent-tasks/approve",form)
assert status==201 and "no-store" in headers["Cache-Control"],"committed explicit owner approval"
assert owner_request("POST","/account/agent-tasks/approve",form)[0]==409,"approval replay cannot create or revise run"
class Agent(FixtureClient):
    def authenticate(self): pass
    def mint(self,params):
        self.token=""
        now=int(time.time())
        assertion=sign({"alg":"ES256","typ":"JWT","kid":"task-agent"},{"iss":self.client_id,"sub":self.client_id,"aud":self.issuer,"iat":now,"exp":now+60,"jti":secrets.token_urlsafe(24)},self.key)
        form={"client_id":self.client_id,"client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":assertion,"scope":"admin.scim:read","resource":resource,**params}
        return self.request("POST",self.issuer+"/token",urllib.parse.urlencode(form).encode(),{"Content-Type":"application/x-www-form-urlencoded"})
agent=Agent(issuer,"task-agent",root/"agent.pem","task-agent",root/"cert.pem")
assert agent.mint({"grant_type":"client_credentials"})[0]==400,"task obligation cannot be discarded"
params={"grant_type":"client_credentials","task_id":binding["task_id"]}
status,_,issued=agent.mint(params)
assert status==200 and issued["token_type"]=="DPoP" and 0<issued["expires_in"]<=120,"current agent and task TTL"
token=issued["access_token"]
def verified(token):
    header,payload,signature=token.split('.')
    decode=lambda value:base64.urlsafe_b64decode(value+"="*((-len(value))%4))
    metadata=json.loads(decode(header));assert metadata["typ"]=="at+jwt"
    with urllib.request.urlopen(issuer+"/jwks",context=context,timeout=20) as response: keys=json.load(response)["keys"]
    jwk=next(key for key in keys if key["kid"]==metadata["kid"])
    message=(header+"."+payload).encode();signature=decode(signature)
    if metadata["alg"]=="EdDSA": ed25519.Ed25519PublicKey.from_public_bytes(decode(jwk["x"])).verify(signature,message)
    elif metadata["alg"]=="ES256":
        public=ec.EllipticCurvePublicNumbers(int.from_bytes(decode(jwk["x"]),"big"),int.from_bytes(decode(jwk["y"]),"big"),ec.SECP256R1()).public_key()
        public.verify(utils.encode_dss_signature(int.from_bytes(signature[:32],"big"),int.from_bytes(signature[32:],"big")),message,ec.ECDSA(hashes.SHA256()))
    elif metadata["alg"]=="PS256":
        public=rsa.RSAPublicNumbers(int.from_bytes(decode(jwk["e"]),"big"),int.from_bytes(decode(jwk["n"]),"big")).public_key()
        public.verify(signature,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
    else: raise AssertionError("unapproved local signing algorithm")
    claims=json.loads(decode(payload));assert claims["iss"]==issuer and claims["exp"]>time.time()
    thumbprint=b64(hashlib.sha256(json.dumps(agent.jwk,sort_keys=True,separators=(",",":")).encode()).digest())
    assert claims["cnf"]["jkt"]==thumbprint,"actual sender binding"
    return claims
claims=verified(token)
assert claims["task_id"]==binding["task_id"] and claims["task_approval_revision"]==binding["approval_revision"],"signed correlators"
assert claims["authorization_details"]==ceiling["authorization_details"] and "roles" not in claims and "resource_access" not in claims,"exact actions and no owner role inheritance"
assert agent.mint({**params,"scope":"admin.scim:write"})[0]==400,"scope expansion refusal"
assert agent.mint({**params,"resource":"https://unapproved.example/"})[0]==400,"audience expansion refusal"
bad_detail=[{"type":"urn:asterius:workload-actions","actions":["write"],"locations":[resource]}]
action_status,_,action_response=agent.mint({**params,"authorization_details":json.dumps(bad_detail)})
assert action_status==400,f"action expansion refusal status={action_status}, error={action_response.get('error','none')}"
status,_,exchanged=agent.mint({"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token_type":"urn:ietf:params:oauth:token-type:access_token","subject_token":token})
assert status==200 and 0<exchanged["expires_in"]<=issued["expires_in"],"ordinary delegated task exchange"
child=verified(exchanged["access_token"])
assert child["task_id"]==binding["task_id"] and child["task_approval_revision"]==binding["approval_revision"],"descendant binding"
# A normal recipient's existing refresh path inherits durable task lineage;
# the fixture seeds a previously issued sender-constrained refresh credential.
consumer=Agent(issuer,"refresh-consumer",root/"agent.pem","task-agent",root/"cert.pem")
consumer_jkt=b64(hashlib.sha256(json.dumps(consumer.jwk,sort_keys=True,separators=(",",":")).encode()).digest())
owner_session=hashlib.sha256(cookie.encode()).hexdigest()
refresh_grant=str(uuid.uuid4());refresh_token=secrets.token_urlsafe(32)
sql(f"""insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks,authorization_details_types) values('tasks','refresh-consumer','Controlled recipient','private_key_jwt',array['authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:token-exchange'],array['code'],array['https://consumer.example/callback'],array['admin.scim:read'],array[{literal(resource)}],{literal(json.dumps({'keys':[jwk]}))}::jsonb,array['urn:asterius:workload-actions']);
insert into grants(tenant_id,grant_id,client_id,user_id,subject,scopes,resources,authorization_details,parent_grant_id,session_id,authenticated_at,amr,claimed_at,expires_at) values('tasks',{literal(refresh_grant)},'refresh-consumer',{literal(owner)},'controlled-owner-subject',array['admin.scim:read'],array[{literal(resource)}],{literal(json.dumps(ceiling['authorization_details']))}::jsonb,{literal(root_grant)},{literal(owner_session)},now(),array['pop','user'],now(),now()+interval '10 minutes');
insert into refresh_tokens(tenant_id,token_hash,grant_id,client_id,scopes,dpop_jkt,absolute_expires_at) values('tasks',decode({literal(hashlib.sha256(refresh_token.encode()).hexdigest())},'hex'),{literal(refresh_grant)},'refresh-consumer',array['admin.scim:read'],{literal(consumer_jkt)},now()+interval '1 day');""")
status,_,refreshed=consumer.mint({"grant_type":"refresh_token","refresh_token":refresh_token})
assert status==200 and 0<refreshed['expires_in']<=120,f"ordinary descendant refresh status={status}, error={refreshed.get('error','none')}, task_boundary={'task authority' in refreshed.get('error_description','')}"
# Signature verifies against the recipient's own DPoP key, not the root agent.
previous_agent=agent;agent=consumer
refresh_claims=verified(refreshed['access_token']);agent=previous_agent
assert refresh_claims['task_id']==binding['task_id'],"refresh cannot discard lineage"

# Separate authenticated management identity. Task approval never grants its
# initiating agent permission to withdraw other users' grants.
sql(f"insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks) values('tasks','controlled-admin','Controlled management','private_key_jwt',array['client_credentials'],array[]::text[],array['admin.grants:write','admin.audit:read'],array[{literal(resource)}],{literal(json.dumps({'keys':[jwk]}))}::jsonb);")
admin=Agent(issuer,'controlled-admin',root/'agent.pem','task-agent',root/'cert.pem')
status,_,admin_issued=admin.mint({'grant_type':'client_credentials','scope':'admin.grants:write admin.audit:read'})
assert status==200,f"independent management authentication status={status} error={admin_issued.get('error','none')}"
admin.token=admin_issued['access_token']
def protected(client,presented):
    client.token=presented
    return client.request('GET',issuer+'/admin/api/v1/scim/v2/Users')[0]
def introspect(client,presented):
    client.token=''
    now=int(time.time())
    assertion=sign({'alg':'ES256','typ':'JWT','kid':'task-agent'}, {'iss':client.client_id,'sub':client.client_id,'aud':issuer,'iat':now,'exp':now+60,'jti':secrets.token_urlsafe(24)},client.key)
    fields={'client_id':client.client_id,'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','client_assertion':assertion,'token':presented}
    status,_,response=client.request('POST',issuer+'/introspect',urllib.parse.urlencode(fields).encode(),{'Content-Type':'application/x-www-form-urlencoded'})
    assert status==200,'authenticated introspection'
    return response['active']
assert protected(agent,token)==200,'actual protected initial token'
assert protected(agent,exchanged['access_token'])==200,'actual protected original descendant'
status,_,withdrawn_descendant=consumer.mint({'grant_type':'urn:ietf:params:oauth:grant-type:token-exchange','subject_token_type':'urn:ietf:params:oauth:token-type:access_token','subject_token':refreshed['access_token']});assert status==200,'ordinary recipient descendant exchange'
assert introspect(consumer,withdrawn_descendant['access_token']),'actual active intermediate descendant'
status,_,sibling=agent.mint(params);assert status==200
# Another immutable task sharing the same owner and agent remains independent.
independent_root=str(uuid.uuid4())
sql(f"insert into grants(tenant_id,grant_id,client_id,user_id,scopes,resources,authorization_details,claimed_at,expires_at) values('tasks',{literal(independent_root)},'task-agent',{literal(owner)},array['admin.scim:read'],array[{literal(resource)}],{literal(json.dumps(ceiling['authorization_details']))}::jsonb,now(),now()+interval '30 minutes');")
status,_,independent_preview=owner_request('GET','/account/agent-tasks/approval?root_grant_id='+independent_root);assert status==200
status,_,independent_binding=owner_request('POST','/account/agent-tasks/approve',{**form,'root_grant_id':independent_root,'csrf':independent_preview['csrf'],'label':'independent run'});assert status==201
status,_,independent=agent.mint({'grant_type':'client_credentials','task_id':independent_binding['task_id']});assert status==200
viewer=None
if os.environ.get('ASTERIUS_TASK_VIEWER_ACCEPTANCE')=='1':
    from viewer_fixture import ViewerFixture
    viewer=ViewerFixture(admin,issuer,sql,literal,binding,owner,agent,token)
    viewer.before()
first_grant=refresh_grant
admin.token=admin_issued['access_token']
# Wrong path user must not authorize a same-tenant grant owned by someone else.
wrong=admin.request('DELETE',issuer+'/admin/api/v1/users/'+other+'/grants/'+root_grant)[0]
assert wrong==404,f'exact admin grant ownership boundary: expected404 actual{wrong}'
status,_,_=admin.request('DELETE',issuer+'/admin/api/v1/users/'+owner+'/grants/'+first_grant)
assert status==200,'real intermediate grant withdrawal'
if viewer: viewer.after_intermediate(first_grant)
assert not introspect(consumer,refreshed['access_token']),'intermediate token immediately inactive'
assert not introspect(consumer,withdrawn_descendant['access_token']),'descendant immediately inactive'
# User-delegated recipient credentials are intentionally not service authority
# for SCIM. Their current online authority is tested through introspection.
assert introspect(agent,sibling['access_token']),'same task sibling remains live'
assert protected(agent,independent['access_token'])==200,'independent task remains live'
assert consumer.mint({'grant_type':'urn:ietf:params:oauth:grant-type:token-exchange','subject_token_type':'urn:ietf:params:oauth:token-type:access_token','subject_token':withdrawn_descendant['access_token']})[0]==400,'withdrawn descendant cannot exchange'
withdraw={'task_id':binding['task_id'],'csrf':preview['csrf'],'confirm':'revoke'}
assert owner_request('POST','/account/agent-tasks/revoke',withdraw,session=other_cookie)[0]==403,'foreign session cannot use owner CSRF'
foreign_csrf=hashlib.sha256((hashlib.sha256(other_cookie.encode()).hexdigest()+':agent-task-approval-csrf').encode()).hexdigest()
assert owner_request('POST','/account/agent-tasks/revoke',{**withdraw,'csrf':foreign_csrf},session=other_cookie)[0]==404,'foreign owner cannot withdraw guessed task with valid own CSRF'
assert owner_request('POST','/account/agent-tasks/revoke',withdraw,session=stale_cookie)[0]==303,'fresh revocation authentication'
assert owner_request('POST','/account/agent-tasks/revoke',{**withdraw,'csrf':'forged'})[0]==403,'withdrawal CSRF'
assert owner_request('POST','/account/agent-tasks/revoke',withdraw)[0]==204,'owner task withdrawal'
assert owner_request('POST','/account/agent-tasks/revoke',withdraw)[0]==204,'idempotent terminal withdrawal'
assert not introspect(agent,sibling['access_token']),'root withdrawal reaches all task runs'
assert protected(agent,sibling['access_token'])==401,'root protected access refused'
assert protected(agent,independent['access_token'])==200,'unrelated task unaffected by root withdrawal'
assert consumer.mint({'grant_type':'refresh_token','refresh_token':refreshed['refresh_token']})[0]==400,'stored recipient refresh refuses root withdrawal'
# Local signature remains cryptographically valid: offline expiry is the
# declared residual window, whereas online private-JTI state denies immediately.
verified(sibling['access_token'])
withdrawals=int(sql("select count(*) from agent_task_withdrawals where tenant_id='tasks'",True))
assert withdrawals==2,'durable intermediate and root cleanup ledger'
audit_count=int(sql("select count(*) from audit_events where tenant_id='tasks' and event_type='agent.task.withdrawn'",True))
assert audit_count==2,'transactional withdrawal events and idempotence'
browser_controls=[]
if viewer:
    viewer.after_root()
    if os.environ.get('ASTERIUS_TASK_VIEWER_BROWSER')=='1':
        sql(f"insert into user_roles(tenant_id,user_id,role,tenant_is_reserved) values('tasks',{literal(owner)},'tenant_admin',false);")
        browser_input=root/'viewer-browser.json'
        browser_input.write_text(json.dumps({'issuer':issuer,'cookie':cookie,'task':independent_binding['task_id']}))
        browser_run=subprocess.run(['node',str(pathlib.Path(__file__).with_name('viewer_browser.mjs')),str(browser_input)],check=True,capture_output=True,text=True)
        browser_report=json.loads(browser_run.stdout)
        assert browser_report['status']=='pass','actual browser control result'
        browser_controls=browser_report['checks']

with pathlib.Path(os.environ['ASTERIUS_BIN']).open('rb') as binary:
    binary_digest=hashlib.file_digest(binary,'sha256').hexdigest()
evidence={'binary_sha256':binary_digest,'ticket':'ast-dd1y.8.3','controlled_fixture':True,'live_human_login':False,'timestamp_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'checks':['real HTTPS private_key_jwt + DPoP issuance','local signature and exact private JTI linkage','intermediate descendant introspection refusal before cleanup','same-task sibling survives intermediate withdrawal','exact administrative grant owner boundary','fresh owner and CSRF task withdrawal','terminal idempotence without duplicate audit','root withdrawal denies ordinary recipient refresh','independent task remains usable','offline signature residual explicitly observed','durable cleanup ledger and transactional audits'],'limits':['human root grants and owner sessions are controlled seeded inputs','opaque recipient refresh input seeded; rotation response used for withdrawal test','ignored PostgreSQL tests reserved to CI; no full local suite','no external introspection cache or SSF delivery deadline asserted']}
if viewer:
    evidence['ticket']='ast-dd1y.8.4'
    evidence['live_browser_controls']=os.environ.get('ASTERIUS_TASK_VIEWER_BROWSER')=='1'
    evidence['checks'] += ['read scope separate from task approval','bounded UUID keyset task/lineage pagination','cross-tenant task metadata refusal','public identifiers and private JTI exclusion','current scope/resource/TTL ceilings and not-evaluated conditional status','intermediate/root current snapshot versus exact recorded timeline','current client narrowing preserves recorded approval'] + browser_controls
    evidence['limits'] += ['console administrator role is a controlled seed; browser exercises real controls but no live human login ceremony']
print(json.dumps(evidence,sort_keys=True))
