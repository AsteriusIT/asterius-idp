#!/usr/bin/env python3
"""Administrative inspection against a real server, never mocked authorization.
Only check names and aggregate counts are printed, never tokens/directory values.
"""
import hashlib
import json
import pathlib
import secrets
import subprocess
import sys
import time
import urllib.parse
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scim'))
from dpop_fixture import FixtureClient, b64, sign
run, database, issuer = sys.argv[1:]
root = pathlib.Path(run)
tenant = 'conditional-simulation'
api = issuer + '/admin/api/v1'
resource = 'https://api.example/simulation'
key = ec.generate_private_key(ec.SECP256R1())
numbers = key.public_key().public_numbers()
jwk = {'kty':'EC','crv':'P-256','x':b64(numbers.x.to_bytes(32,'big')),'y':b64(numbers.y.to_bytes(32,'big')),'kid':'simulation-fixture','alg':'ES256','use':'sig'}
(root/'client.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
quote = lambda value: "'"+str(value).replace("'","''")+"'"
scopes = 'admin.session:read admin.policies:read admin.policies:write admin.users:read admin.clients:read admin.clients:write admin.resource_servers:read'
user = str(uuid.uuid4())
foreign_user = str(uuid.uuid4())
def sql(statement):
    subprocess.run(['psql',database,'-X','-At','-v','ON_ERROR_STOP=1','-c',statement],check=True,capture_output=True,text=True)
sql(f"""insert into resource_servers(tenant_id,identifier,scopes) values({quote(tenant)},{quote(api)},null),({quote(tenant)},{quote(resource)},array['read']);
insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks) values
({quote(tenant)},'controller','Controller','private_key_jwt',array['client_credentials'],array[]::text[],array[]::text[],array[{','.join(quote(x) for x in scopes.split())}],array[{quote(api)}],{quote(json.dumps({'keys':[jwk]}))}::jsonb),
({quote(tenant)},'app','Private directory application','private_key_jwt',array['authorization_code','refresh_token'],array['code'],array['https://client.example/callback'],array['read'],array[{quote(resource)}],{quote(json.dumps({'keys':[jwk]}))}::jsonb);
insert into users(tenant_id,user_id,username,status) values({quote(tenant)},{quote(user)},'private-directory-canary','active'),('conditional-simulation-foreign',{quote(foreign_user)},'foreign-private-canary','active');""")
class Client(FixtureClient):
    def authenticate(self): pass
    def mint(self, requested_scopes):
        self.token = ''
        now = int(time.time())
        assertion = sign({'alg':'ES256','typ':'JWT','kid':self.key_id},{'iss':self.client_id,'sub':self.client_id,'aud':issuer,'iat':now,'exp':now+60,'jti':secrets.token_urlsafe(24)},self.key)
        form = {'grant_type':'client_credentials','scope':requested_scopes,'resource':api,'client_id':self.client_id,'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','client_assertion':assertion}
        status,_,result=self.request('POST',issuer+'/token',urllib.parse.urlencode(form).encode(),{'Content-Type':'application/x-www-form-urlencoded'})
        assert status==200,'real administrative FAPI credential'
        self.token=result['access_token']
admin=Client(issuer,'controller',root/'client.pem','simulation-fixture',root/'cert.pem')
admin.mint(scopes)
reader=Client(issuer,'controller',root/'client.pem','simulation-fixture',root/'cert.pem')
reader.mint('admin.policies:read')
def call(method,path,body=None,headers=None,client=admin):
    return client.request(method,api+path,body,{'Content-Type':'application/json',**(headers or {})})
controls=[]
def passed(name): controls.append(name)
status,_,saved=call('GET','/policies')
assert status==200 and saved['revision'] is None
revision=None
def publish(document):
    global revision
    headers={'If-None-Match':'*'} if revision is None else {'If-Match':'"'+revision+'"'}
    assert call('PUT','/policies',document,headers)[0]==200,'reviewed policy publication'
    status,_,saved=call('GET','/policies')
    assert status==200
    revision=saved['revision']
def document(condition, mode='active', base='permit', actions=None):
    return {'version':1,'rules':[{'id':'base','effect':base}],'conditional_scopes':[{'id':'selected','mode':mode,'clients':['app'],'actions':actions or ['refresh_token'],'rules':[{'id':'guard','effect':'permit','when':condition}]}]}
def simulate(examples=None, **override):
    body={'user_id':user,'client_id':'app','resource_id':resource,'resource_type':'api','action':'read','enforcement_action':'refresh_token','expected_policy_revision':revision}
    if examples is not None: body['hypothetical_trusted_context']=examples
    body.update(override)
    return call('POST','/policies/simulate',body)
def fact(result,name):
    return next(value for value in result['simulation']['conditional']['facts'] if value['name']==name)
def private_absent(result):
    assert 'foreign-private-canary' not in json.dumps(result)
    assert 'private-directory-canary' not in json.dumps(result),'directory values not exposed'
    assert 'Private directory application' not in json.dumps(result),'directory values not exposed'
    for value in result['simulation']['conditional']['facts']:
        assert 'value' not in value,'fact values not returned'
missing=document({'device_compliance':'compliant'})
assert call('PUT','/policies',missing)[0]==409,'unguarded first activation refused'
publish(missing)
status,_,result=simulate()
assert status==200 and not result['decision'] and result['simulation']['enforced'] is False
assert result['simulation']['conditional']['evaluated_policy_revision']==revision
assert fact(result,'assurance')['availability']=='absent'
assert fact(result,'authentication_age')['availability']=='absent'
assert fact(result,'network_zone')['availability']=='absent'
assert fact(result,'device_compliance')['availability']=='unavailable'
assert fact(result,'application_sensitivity')['availability']=='absent'
assert fact(result,'groups')['source']=='current_tenant_directory'
private_absent(result)
passed('absent_transaction_and_current_directory_sources')
assert call('PUT','/policies',missing)[0]==409,'unguarded existing activation refused'
assert call('PUT','/policies',missing,{'If-Match':'"sha256:'+'0'*64+'"'})[0]==409,'stale activation refused'
assert call('PUT','/policies',missing,{'If-Match':'"'+revision+'"'},client=reader)[0]==403,'publication RBAC'
body={'user_id':foreign_user,'client_id':'app','resource_id':resource,'resource_type':'api','action':'read','expected_policy_revision':revision}
assert call('POST','/policies/simulate',body,client=reader)[0]==403,'all read authorities precede lookup'
assert call('POST','/policies/simulate',body)[0]==404,'foreign or absent user is not resolved'
passed('activation_and_inspection_rbac_revision_tenant_guards')
for state in ['absent','stale','invalid','unavailable']:
    status,_,result=simulate({'device_compliance':{'availability':state}})
    assert status==200 and not result['decision']
    assert fact(result,'device_compliance')['availability']==state
    assert fact(result,'device_compliance')['hypothetical'] is True
    private_absent(result)
status,_,result=simulate({'device_compliance':{'availability':'known','value':'compliant'}})
assert status==200 and result['decision']
assert fact(result,'device_compliance')['source']=='hypothetical_operator_example'
passed('bounded_hypothetical_sources_and_missing_states')
for examples in [{'groups':{'availability':'known','value':['private-canary']}},{'device_compliance':{'availability':'stale','value':'private-canary'}},{'device_compliance':{'availability':'known','value':'compliant','source':'verified'}}]:
    status,_,result=simulate(examples)
    assert status==400 and 'private-canary' not in json.dumps(result),'closed non-value-bearing refusal'
assert simulate(enforcement_action='read')[0]==400,'resource operation is not enforcement boundary'
status,_,result=simulate({'assurance':{'availability':'known','value':'private-unsupported-level'}})
assert status==200 and fact(result,'assurance')['availability']=='invalid'
assert 'private-unsupported-level' not in json.dumps(result)
passed('closed_authority_and_boundary_dialect')
for condition in [{'not':{'device_compliance':'compliant'}},{'any':[{'device_compliance':'compliant'},{'all':[]}]}]:
    publish(document(condition))
    status,_,result=simulate()
    assert status==200 and not result['decision']
    assert result['simulation']['conditional']['scopes'][0]['missing_required_evidence'] is True
passed('not_any_missing_evidence_guards')
publish(document({'authentication_age_at_most':60}))
for age,permit in [(0,True),(61,False)]:
    status,_,result=simulate({'authentication_age':{'availability':'known','value':age}})
    assert status==200 and result['decision'] is permit
status,_,result=simulate(enforcement_action='authorization_code')
assert status==200 and result['decision'] and result['simulation']['conditional']['scopes']==[]
passed('relative_age_and_exact_enforcement_boundary')
publish(document({'device_compliance':'compliant'},mode='report_only',base='deny'))
status,_,result=simulate({'device_compliance':{'availability':'known','value':'compliant'}})
assert status==200 and not result['decision']
scope=result['simulation']['conditional']['scopes'][0]
assert scope['mode']=='report_only' and scope['would_decision'] is True
assert result['simulation']['conditional']['active_would_permit'] is False
private_absent(result)
passed('report_only_never_grants_base_denial')
status,_,classification=call('PUT','/clients/app/conditional-access',{'sensitivity':'critical','expected_revision':None})
assert status==200 and classification['revision']
assert call('PUT','/clients/app/conditional-access',{'sensitivity':'standard','expected_revision':None})[0]==409
publish(document({'application_sensitivity':'critical'}))
status,_,result=simulate()
assert status==200 and result['decision']
assert fact(result,'application_sensitivity')['source']=='administrative_client_settings'
assert fact(result,'application_sensitivity')['hypothetical'] is False
status,_,result=simulate({'application_sensitivity':{'availability':'known','value':'standard'}})
assert status==200 and not result['decision']
assert call('GET','/clients/app/conditional-access')[2]==classification,'simulation does not mutate classification'
passed('classification_cas_and_hypothetical_isolation')
status,_,result=simulate(expected_policy_revision='sha256:'+'0'*64)
assert status==409
before=call('GET','/policies')[2]
draft=document({'device_compliance':'compliant'},mode='report_only')
status,_,result=simulate(hypothetical_policy=draft)
assert status==200 and result['simulation']['provenance']['policy']=='hypothetical'
assert result['simulation']['conditional']['evaluated_policy_revision']!=revision
assert call('GET','/policies')[2]==before,'preview is not publication'
passed('policy_snapshot_and_unpublished_draft')
print(json.dumps({'fixture':'real_https_fapi_dpop_administrative_simulation','controls':controls,'status':'pass'},sort_keys=True))
