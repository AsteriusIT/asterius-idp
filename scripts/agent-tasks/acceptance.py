#!/usr/bin/env python3
"""Controlled owner-session fixtures against real HTTPS/FAPI handlers.
The seeded grant/session are test inputs, not evidence of a real human login.
No tokens, assertions, session cookies or CSRF values are printed.
"""
import base64
import hashlib
import json
import pathlib
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
resource="https://api.example/tasks"
owner=str(uuid.uuid4());other=str(uuid.uuid4());root_grant=str(uuid.uuid4())
cookie=secrets.token_urlsafe(32);other_cookie=secrets.token_urlsafe(32);stale_cookie=secrets.token_urlsafe(32)
key=ec.generate_private_key(ec.SECP256R1());number=key.public_key().public_numbers()
jwk={"kty":"EC","crv":"P-256","x":b64(number.x.to_bytes(32,"big")),"y":b64(number.y.to_bytes(32,"big")),"kid":"task-agent","alg":"ES256","use":"sig"}
(root/"agent.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
literal=lambda value:"'"+str(value).replace("'","''")+"'"
def sql(statement,output=False):
    result=subprocess.run(["psql",database,"-X","-At","-v","ON_ERROR_STOP=1","-c",statement],check=True,capture_output=True,text=True)
    return result.stdout.strip() if output else None
ceiling={"scopes":["task.read"],"resources":[resource],"authorization_details":[{"type":"urn:asterius:workload-actions","actions":["read"],"locations":[resource]}],"max_delegation_depth":2}
full_detail=[{"type":"urn:asterius:workload-actions","actions":["read","write"],"locations":[resource]}]
schema=json.loads((pathlib.Path(__file__).resolve().parents[2]/"examples/kubernetes/workload-exchange/actions-schema.json").read_text())
policy={"grant_types":["client_credentials","urn:ietf:params:oauth:grant-type:token-exchange","urn:ietf:params:oauth:grant-type:device_code"],"max_delegation_depth":2,"scopes":["task.read","task.write"],"audiences":[resource],"access_token_ttl_seconds":120}
sql(f"""insert into users(tenant_id,user_id,username,status) values('tasks',{literal(owner)},'controlled-owner','active'),('tasks',{literal(other)},'foreign-owner','active');
insert into resource_servers(tenant_id,identifier,scopes) values('tasks',{literal(resource)},array['task.read','task.write']);
insert into authorization_details_types(tenant_id,type_name,schema) values('tasks','urn:asterius:workload-actions',{literal(json.dumps(schema))}::jsonb);
insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,scopes,resources,jwks,is_agent,agent_owner_user_id,agent_policy,authorization_details_types) values('tasks','task-agent','Controlled agent','private_key_jwt',array['client_credentials','urn:ietf:params:oauth:grant-type:token-exchange','urn:ietf:params:oauth:grant-type:device_code'],array[]::text[],array['task.read','task.write'],array[{literal(resource)}],{literal(json.dumps({'keys':[jwk]}))}::jsonb,true,{literal(owner)},{literal(json.dumps(policy))}::jsonb,array['urn:asterius:workload-actions']);
insert into grants(tenant_id,grant_id,client_id,user_id,subject,scopes,resources,authorization_details,claimed_at,expires_at) values('tasks',{literal(root_grant)},'task-agent',{literal(owner)},'controlled-owner-subject',array['task.read','task.write'],array[{literal(resource)}],{literal(json.dumps(full_detail))}::jsonb,now(),now()+interval '30 minutes');""")
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
expanded=json.loads(json.dumps(ceiling));expanded["scopes"]=["task.admin"]
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
        form={"client_id":self.client_id,"client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":assertion,"scope":"task.read","resource":resource,**params}
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
assert agent.mint({**params,"scope":"task.write"})[0]==400,"scope expansion refusal"
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
sql(f"""insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks,authorization_details_types) values('tasks','refresh-consumer','Controlled recipient','private_key_jwt',array['authorization_code','refresh_token'],array['code'],array['https://consumer.example/callback'],array['task.read'],array[{literal(resource)}],{literal(json.dumps({'keys':[jwk]}))}::jsonb,array['urn:asterius:workload-actions']);
insert into grants(tenant_id,grant_id,client_id,user_id,subject,scopes,resources,authorization_details,parent_grant_id,session_id,authenticated_at,amr,claimed_at,expires_at) values('tasks',{literal(refresh_grant)},'refresh-consumer',{literal(owner)},'controlled-owner-subject',array['task.read'],array[{literal(resource)}],{literal(json.dumps(ceiling['authorization_details']))}::jsonb,{literal(root_grant)},{literal(owner_session)},now(),array['pop','user'],now(),now()+interval '10 minutes');
insert into refresh_tokens(tenant_id,token_hash,grant_id,client_id,scopes,dpop_jkt,absolute_expires_at) values('tasks',decode({literal(hashlib.sha256(refresh_token.encode()).hexdigest())},'hex'),{literal(refresh_grant)},'refresh-consumer',array['task.read'],{literal(consumer_jkt)},now()+interval '1 day');""")
status,_,refreshed=consumer.mint({"grant_type":"refresh_token","refresh_token":refresh_token})
assert status==200 and 0<refreshed['expires_in']<=120,f"ordinary descendant refresh status={status}, error={refreshed.get('error','none')}, task_boundary={'task authority' in refreshed.get('error_description','')}"
# Signature verifies against the recipient's own DPoP key, not the root agent.
previous_agent=agent;agent=consumer
refresh_claims=verified(refreshed['access_token']);agent=previous_agent
assert refresh_claims['task_id']==binding['task_id'],"refresh cannot discard lineage"
# Expiry is an actual elapsed server deadline, not an edited approval row.
short_root=str(uuid.uuid4())
sql(f"insert into grants(tenant_id,grant_id,client_id,user_id,scopes,resources,authorization_details,claimed_at,expires_at) values('tasks',{literal(short_root)},'task-agent',{literal(owner)},array['task.read'],array[{literal(resource)}],{literal(json.dumps(ceiling['authorization_details']))}::jsonb,now(),now()+interval '10 minutes');")
status,_,short_preview=owner_request('GET','/account/agent-tasks/approval?root_grant_id='+short_root)
assert status==200
short_form={**form,'root_grant_id':short_root,'csrf':short_preview['csrf'],'expires_in':'2'}
status,_,short_binding=owner_request('POST','/account/agent-tasks/approve',short_form);assert status==201
short_refresh_grant=str(uuid.uuid4());short_refresh_token=secrets.token_urlsafe(32)
sql(f"""insert into grants(tenant_id,grant_id,client_id,user_id,scopes,resources,authorization_details,parent_grant_id,claimed_at,expires_at) values('tasks',{literal(short_refresh_grant)},'refresh-consumer',{literal(owner)},array['task.read'],array[{literal(resource)}],{literal(json.dumps(ceiling['authorization_details']))}::jsonb,{literal(short_root)},now(),now()+interval '1 minute');
insert into refresh_tokens(tenant_id,token_hash,grant_id,client_id,scopes,dpop_jkt,absolute_expires_at) values('tasks',decode({literal(hashlib.sha256(short_refresh_token.encode()).hexdigest())},'hex'),{literal(short_refresh_grant)},'refresh-consumer',array['task.read'],{literal(consumer_jkt)},now()+interval '1 day');""")
time.sleep(2.1)
assert agent.mint({'grant_type':'client_credentials','task_id':short_binding['task_id']})[0]==400,"task expiry terminates new issuance"
assert consumer.mint({'grant_type':'refresh_token','refresh_token':short_refresh_token})[0]==400,"refresh after task expiry refused"

# Hold an actual root writer before a concurrent real token request. The
# request may read a pre-commit snapshot, but its signing fence must wait and
# then refuse the committed revocation. Synchronize with psql output, not sleep.
race_root=str(uuid.uuid4())
sql(f"insert into grants(tenant_id,grant_id,client_id,user_id,scopes,resources,authorization_details,claimed_at,expires_at) values('tasks',{literal(race_root)},'task-agent',{literal(owner)},array['task.read'],array[{literal(resource)}],{literal(json.dumps(ceiling['authorization_details']))}::jsonb,now(),now()+interval '10 minutes');")
status,_,race_preview=owner_request('GET','/account/agent-tasks/approval?root_grant_id='+race_root);assert status==200
status,_,race_binding=owner_request('POST','/account/agent-tasks/approve',{**form,'root_grant_id':race_root,'csrf':race_preview['csrf'],'expires_in':'300'});assert status==201
writer=subprocess.Popen(['psql',database,'-X','-At','-v','ON_ERROR_STOP=1','-c',f"begin; update grants set revoked_at=clock_timestamp(),revocation_reason='user_revoked' where tenant_id='tasks' and grant_id={literal(race_root)}; select 'fence-ready'; select pg_sleep(2); commit;"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
while True:
    line=writer.stdout.readline()
    assert line,'root fence writer failed before synchronization'
    if line.strip()=='fence-ready': break
status,_,_=agent.mint({'grant_type':'client_credentials','task_id':race_binding['task_id']})
assert status==400,'revocation committed before mint cannot leak a signature'
writer.communicate(timeout=10);assert writer.returncode==0,'root fence committed'

# The controlled disable uses the actual persistent principal lifecycle and
# checks both retained task identifiers and a subsequent HTTP mint.
sql(f"update users set status='disabled' where tenant_id='tasks' and user_id={literal(owner)}")
assert agent.mint(params)[0]==400,"owner disable terminates authority"
sql(f"update users set status='active' where tenant_id='tasks' and user_id={literal(owner)}")
assert agent.mint(params)[0]==400,"account reactivation cannot revive old task"
assert int(sql("select count(*) from agent_task_tokens where tenant_id='tasks'",True))==3,"private lineage for issuance, delegation and refresh"
assert int(sql("select count(*) from audit_events where tenant_id='tasks' and event_type='agent.task.approved'",True))==3,"three explicit immutable run approval audits"
assert int(sql("select count(*) from audit_events where tenant_id='tasks' and event_type='agent.task.issued' and outcome='success'",True))==3,"committed task issuance audits"
print("Controlled real HTTPS task acceptance PASS: fresh owner/CSRF, replay, ceilings, FAPI+DPoP issuance, delegation, refresh, elapsed expiry, root race fence, TTL, terminal owner disable and atomic lineage/audits; session/root seeded, not a live human login")
