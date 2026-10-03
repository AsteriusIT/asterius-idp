#!/usr/bin/env python3
"""Real FAPI/DPoP checks; seeded refresh authentication is a controlled input.
Never print credentials, tokens, user attributes or policy literals.
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
resource = 'https://api.example/conditional'
admin_api = issuer + '/admin/api/v1'
pdp = issuer + '/access/v1/evaluation'
key = ec.generate_private_key(ec.SECP256R1())
numbers = key.public_key().public_numbers()
jwk = {'kty':'EC','crv':'P-256','x':b64(numbers.x.to_bytes(32,'big')),'y':b64(numbers.y.to_bytes(32,'big')),'kid':'conditional-fixture','alg':'ES256','use':'sig'}
(root / 'client.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
quote = lambda value: "'" + str(value).replace("'", "''") + "'"
def sql(statement, output=False):
    result = subprocess.run(['psql', database, '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', statement], check=True, capture_output=True, text=True)
    return result.stdout.strip() if output else None
admin_scopes = 'admin.session:read admin.clients:read admin.clients:write admin.policies:read admin.policies:write admin.audit:read'
sql(f"""insert into resource_servers(tenant_id,identifier,scopes) values('conditional',{quote(resource)},array['conditional.read']),('conditional',{quote(admin_api)},null),('conditional',{quote(pdp)},null);
insert into clients(tenant_id,client_id,client_name,token_endpoint_auth_method,grant_types,response_types,redirect_uris,scopes,resources,jwks) values
('conditional','controller','Controller','private_key_jwt',array['client_credentials'],array[]::text[],array[]::text[],array[{','.join(quote(x) for x in admin_scopes.split())}],array[{quote(admin_api)}],{quote(json.dumps({'keys':[jwk]}))}::jsonb),
('conditional','app','Application','private_key_jwt',array['client_credentials','authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:token-exchange'],array['code'],array['https://client.example/callback'],array['conditional.read','authzen.evaluate'],array[{quote(resource)},{quote(pdp)}],{quote(json.dumps({'keys':[jwk]}))}::jsonb);""")
class Client(FixtureClient):
    def authenticate(self): pass
    def mint(self, params=None):
        self.token = ''
        now = int(time.time())
        assertion = sign({'alg':'ES256','typ':'JWT','kid':self.key_id}, {'iss':self.client_id,'sub':self.client_id,'aud':issuer,'iat':now,'exp':now+60,'jti':secrets.token_urlsafe(24)}, self.key)
        default = {'grant_type':'client_credentials','scope':'conditional.read','resource':resource}
        form = {**default, **(params or {}), 'client_id':self.client_id,'client_assertion_type':'urn:ietf:params:oauth:client-assertion-type:jwt-bearer','client_assertion':assertion}
        return self.request('POST', issuer+'/token', urllib.parse.urlencode(form).encode(), {'Content-Type':'application/x-www-form-urlencoded'})
admin = Client(issuer, 'controller', root/'client.pem', 'conditional-fixture', root/'cert.pem')
app = Client(issuer, 'app', root/'client.pem', 'conditional-fixture', root/'cert.pem')
status, _, issued = admin.mint({'scope':admin_scopes, 'resource':admin_api})
assert status == 200, 'unscoped administrative FAPI compatibility'
admin.token = issued['access_token']
def request(method, path, body=None, headers=None):
    return admin.request(method, admin_api+path, body, {'Content-Type':'application/json', **(headers or {})})
controls = []
def passed(name): controls.append(name)
assert app.mint()[0] == 200, 'unscoped client credentials compatibility'
passed('unscoped_fapi_compatibility')
status, _, empty = request('GET', '/clients/app/conditional-access')
assert status == 200 and empty == {'sensitivity':None,'revision':None}, 'classification absence is explicit'
status, _, settings = request('PUT','/clients/app/conditional-access', {'sensitivity':'critical','expected_revision':None})
assert status == 200 and settings['revision'], 'administrative classification'
assert request('PUT','/clients/app/conditional-access', {'sensitivity':'standard','expected_revision':None})[0] == 409, 'classification CAS'
passed('classification_incarnation_cas')
def policy(condition=None, mode='active', actions=None):
    rule = {'id':'conditional-permit','effect':'permit'}
    if condition is not None: rule['when'] = condition
    return {'version':1,'rules':[{'id':'baseline','effect':'permit'}], 'conditional_scopes':[{'id':'protected-app','mode':mode,'clients':['app'],'actions':actions or ['client_credentials','refresh_token','token_exchange','access_evaluation'],'rules':[rule]}]}
def revision(document):
    # RuleSet serialization uses recursively sorted object keys; this fixture
    # omits optional/default members except those canonicalized by the parser.
    return 'sha256:'+hashlib.sha256(json.dumps(document,sort_keys=True,separators=(',',':')).encode()).hexdigest()
current_revision = None
def publish(document, expected=None):
    global current_revision
    header = {'If-None-Match':'*'} if current_revision is None else {'If-Match':'"'+current_revision+'"'}
    status, _, _ = request('PUT','/policies',document,header if expected is None else {'If-Match':'"'+expected+'"'})
    if status == 200:
        saved_status, _, saved = request('GET','/policies')
        assert saved_status == 200
        # Read the canonical published document, rather than guessing omitted
        # defaults or relying on PostgreSQL jsonb textual serialization.
        published = saved.get('policy', saved.get('document', saved))
        current_revision = saved['revision']
        assert current_revision == revision(published), 'canonical current policy digest'
    return status
allow = policy({'application_sensitivity':'critical'})
assert request('PUT','/policies',allow)[0] == 409, 'unguarded first conditional publication'
assert publish(allow) == 200, 'explicit first conditional publication'
assert app.mint()[0] == 200, 'current classification permits'
passed('explicit_policy_publication_and_permit')
assert publish(allow, 'sha256:'+'0'*64) == 409, 'stale policy revision'
passed('stale_publication_refused')
for condition in [{'not':{'device_compliance':'compliant'}}, {'any':[{'device_compliance':'compliant'},{'all':[]}]}]:
    assert publish(policy(condition)) == 200, 'conditional publication'
    assert app.mint()[0] == 400, 'missing required device cannot be negated or bypassed'
passed('unknown_device_not_and_any_refused')
assert publish(policy({'device_compliance':'compliant'}, 'report_only')) == 200
status, _, issued = app.mint()
assert status == 200 and issued['token_type'] == 'DPoP', 'report-only leaves existing issuance gates intact'
passed('report_only_issuance')
assert publish(policy({'network_zone':'loopback'})) != 200, 'undefined network zone refused'
network = policy({'network_zone':'loopback'})
network['conditional_scopes'][0]['network_zones'] = {'loopback':['127.0.0.0/8']}
assert publish(network) == 200
assert app.mint()[0] == 200, 'real peer supplies network zone'
passed('current_connection_zone')
# Snapshot before an actual policy writer, followed by issuance waiting on the
# publication fence: no signed result may escape the committed deny.
assert publish(allow) == 200
blocked = policy({'device_compliance':'compliant'})
writer = subprocess.Popen(['psql',database,'-X','-At','-v','ON_ERROR_STOP=1','-c',f"begin; update tenant_policies set document={quote(json.dumps(blocked))}::jsonb,updated_at=clock_timestamp() where tenant_id='conditional'; select 'publication-ready'; select pg_sleep(2); commit;"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
try:
    while True:
        line=writer.stdout.readline()
        assert line, 'publisher failed before synchronization'
        if line.strip() == 'publication-ready': break
    assert app.mint()[0] == 400, 'committed policy deny after lock wait'
finally:
    writer.communicate(timeout=10)
assert writer.returncode == 0
status, _, saved = request('GET','/policies')
assert status == 200
current_revision = saved['revision']
passed('publication_vs_signature_race')
# A previously issued token is evaluated online against the current policy.
assert publish(policy()) == 200
status, _, issued = app.mint({'scope':'authzen.evaluate','resource':pdp})
assert status == 200
app.token = issued['access_token']
question = {'subject':{'type':'client','id':'app'},'action':{'name':'read'},'resource':{'type':'application','id':'app'}}
status, _, result = app.request('POST',pdp,question,{'Content-Type':'application/json'})
assert status == 200 and result['decision'], 'current online permit'
assert publish(blocked) == 200
status, _, result = app.request('POST',pdp,question,{'Content-Type':'application/json'})
assert status == 200 and not result['decision'], 'same token sees current deny'
passed('online_authzen_current_policy')
# The refresh grant's authentication time is seeded, explicitly preserving the
# original time. Refresh iat cannot become a new authentication event.
owner = str(uuid.uuid4());grant = str(uuid.uuid4());refresh = secrets.token_urlsafe(32)
jkt = b64(hashlib.sha256(json.dumps(app.jwk,sort_keys=True,separators=(',',':')).encode()).digest())
sql(f"""insert into users(tenant_id,user_id,username,status) values('conditional',{quote(owner)},'controlled-human','active');
insert into grants(tenant_id,grant_id,client_id,user_id,subject,scopes,resources,authenticated_at,amr,claimed_at,expires_at) values('conditional',{quote(grant)},'app',{quote(owner)},'controlled-human-subject',array['conditional.read'],array[{quote(resource)}],now()-interval '61 seconds',array['pwd'],now(),now()+interval '10 minutes');
insert into refresh_tokens(tenant_id,token_hash,grant_id,client_id,scopes,dpop_jkt,absolute_expires_at) values('conditional',decode({quote(hashlib.sha256(refresh.encode()).hexdigest())},'hex'),{quote(grant)},'app',array['conditional.read'],{quote(jkt)},now()+interval '1 day');""")
assert publish(policy({'authentication_age_at_most':60}, actions=['refresh_token'])) == 200
assert app.mint({'grant_type':'refresh_token','refresh_token':refresh})[0] == 400, 'refresh cannot renew authentication age'
passed('refresh_original_authentication_age')
print(json.dumps({'fixture':'real_https_fapi_dpop','controls':controls,'human_authentication':'seeded_refresh_grant_not_live_login','status':'pass'},sort_keys=True))
