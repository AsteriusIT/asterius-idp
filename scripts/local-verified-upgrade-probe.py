#!/usr/bin/env python3
"""Probe an authorized shared-local upgrade without changing its running image.

This fixture is pinned to the existing local cluster and current private issuer.
It requires an independently verified immutable binary. Snapshots and subprocess
output stay in a private backup directory; stdout contains only public evidence.
"""
import argparse,atexit,subprocess,json,base64,hashlib,os,time,urllib.request,urllib.parse,uuid,re
parser=argparse.ArgumentParser(description="Back up and probe a validated local image; never roll out automatically")
parser.add_argument("--binary", required=True)
parser.add_argument("--sha256", required=True)
parser.add_argument("--source-commit", required=True)
parser.add_argument("--expected-migrations", type=int, default=110)
options=parser.parse_args()
assert re.fullmatch(r"[0-9a-f]{64}", options.sha256)
assert re.fullmatch(r"[0-9a-f]{8,40}", options.source_commit)
from pathlib import Path
os.umask(0o077)
private=Path.home()/('.local/share/asterius/backups/ast-hb5b-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+uuid.uuid4().hex[:8])
private.mkdir(parents=True,exist_ok=True,mode=0o700)
def seal_backup():
 for saved in private.rglob('*'):
  if saved.is_file(): saved.chmod(0o600)
atexit.register(seal_backup)
k=['kubectl','--context','kind-asterius-local','-n','asterius']
def run(args,input=None):
 r=subprocess.run(args,input=input,capture_output=True)
 if r.returncode:
  (private/'failure.log').write_bytes(r.stdout+r.stderr)
  raise RuntimeError('Command failed; private failure.log retained: '+args[0])
 return r.stdout
for name,args in [('deployment',['get','deploy','asterius','-o','json']),('configmap',['get','cm','asterius-config','-o','json']),('secret',['get','secret','asterius-secrets','-o','json']),('ingress',['get','ingress','-o','json'])]:
 (private/(name+'.json')).write_bytes(run(k+args))
(private/'serve.json').write_bytes(run(['tailscale','serve','status','--json']))
pg=k+['exec','asterius-postgresql-1','-c','postgres','--']
for fmt,name in [('custom','asterius.dump'),('plain','asterius.sql')]:
 (private/name).write_bytes(run(pg+['pg_dump','-U','postgres','-d','asterius','--format='+fmt,'--no-owner','--no-privileges']))
q="select 'users',count(*),md5(coalesce(string_agg(to_jsonb(t)::text,',' order by to_jsonb(t)::text),'')) from users t union all select 'credentials',count(*),md5(coalesce(string_agg(to_jsonb(t)::text,',' order by to_jsonb(t)::text),'')) from credentials t union all select 'totp_credentials',count(*),md5(coalesce(string_agg(to_jsonb(t)::text,',' order by to_jsonb(t)::text),'')) from totp_credentials t"
baseline=run(pg+['psql','-U','postgres','-d','asterius','-Atc',q])
(private/'identity-baseline.txt').write_bytes(baseline)
image='asterius-idp:local-ast-hb5b-'+options.sha256[:12]
staging=private/'image'
staging.mkdir(exist_ok=True)
bin=Path(options.binary).read_bytes()
assert hashlib.sha256(bin).hexdigest()==options.sha256
(staging/'asterius').write_bytes(bin)
(staging/'asterius').chmod(0o555)
(staging/'Dockerfile').write_text('FROM gcr.io/distroless/cc-debian13@sha256:54df941ed0d06a1bd95ef5e0ce391fd8d9f94b64782dc9a60062727849ee3f97\nCOPY asterius /usr/local/bin/asterius\nUSER 65532:65532\nENTRYPOINT ["/usr/local/bin/asterius"]\n')
(private/'image-build.log').write_bytes(run(['docker','build','-t',image,str(staging)]))
imageid=run(['docker','image','inspect',image,'--format','{{.Id}}']).decode().strip()
cm=json.loads((private/'configmap.json').read_bytes())
secret=json.loads((private/'secret.json').read_bytes())
for field in ['kek','admin-password']:
 p=private/field
 p.write_bytes(base64.b64decode(secret['data'][field]))
 p.chmod(0o444)
config=cm['data']['asterius.toml'].replace('0.0.0.0:9443','127.0.0.1:9474')
(private/'probe.toml').write_text(config)
(private/'probe.toml').chmod(0o444)
db='ast_hb5b_restore_'+uuid.uuid4().hex[:12]
container='asterius-hb5b-restore-'+db.rsplit('_',1)[-1]
local=['docker','exec','asterius-idp-ast-dd1y71-db-1']
run(local+['createdb','-U','asterius',db])
try:
 sql=(private/'asterius.sql').read_bytes().replace(b'SET transaction_timeout = 0;\n',b'')
 (private/'restore.log').write_bytes(run(['docker','exec','-i','asterius-idp-ast-dd1y71-db-1','psql','-U','asterius','-d',db,'-X','-v','ON_ERROR_STOP=1'],input=sql))
 args=['docker','run','-d','--name',container,'--network','host','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user','65532:65532','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','-v',str(private/'probe.toml')+':/etc/asterius/asterius.toml:ro','-v',str(private/'kek')+':/etc/asterius-secrets/kek:ro','-v',str(private/'admin-password')+':/etc/asterius-secrets/admin-password:ro','-e','ASTERIUS__DATABASE__URL=postgres://asterius:asterius@127.0.0.1:5433/'+db,image,'--config','/etc/asterius/asterius.toml']
 run(args)
 ready=False
 for _ in range(40):
  try:
   with urllib.request.urlopen('http://127.0.0.1:9474/readyz',timeout=2) as r:
    if r.status==200: ready=True; break
  except Exception: time.sleep(0.5)
 (private/'probe.log').write_bytes(run(['docker','logs',container]))
 assert ready,'Restricted image not ready; private probe.log retained'
 after=run(local+['psql','-U','asterius','-d',db,'-Atc',q])
 assert after==baseline,'Identity rows changed on isolated upgrade'
 migrations=run(local+['psql','-U','asterius','-d',db,'-Atc','select count(*) from _sqlx_migrations where success']).decode().strip()
 assert int(migrations)==options.expected_migrations,migrations
 applied=run(local+['psql','-U','asterius','-d',db,'-Atc',"select count(*) from _sqlx_migrations where success and version in (163,165)"]).decode().strip()
 assert applied=='2', 'Required migrations missing'
 for tenant in ['admin','demo']:
  data=json.load(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:9474/t/'+tenant+'/.well-known/openid-configuration',headers={'Host':'desktop-cpbptqn-1.tailacbb15.ts.net'})))
  assert data['issuer']=='https://desktop-cpbptqn-1.tailacbb15.ts.net/t/'+tenant
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self, request, fp, code, msg, headers, newurl): return None
 opener=urllib.request.build_opener(NoRedirect)
 for tenant in ['admin','demo']:
  for suffix in ['account','admin/']:
   try:
    opener.open(urllib.request.Request('http://127.0.0.1:9474/t/'+tenant+'/'+suffix,headers={'Host':'desktop-cpbptqn-1.tailacbb15.ts.net'}),timeout=5)
    raise AssertionError('Protected entrypoint did not redirect')
   except urllib.error.HTTPError as response:
    assert response.code==303, 'Unexpected protected entrypoint status'
    location=response.headers['Location']
    resolved=urllib.parse.urljoin('https://desktop-cpbptqn-1.tailacbb15.ts.net/t/'+tenant+'/'+suffix,location)
    assert resolved.startswith('https://desktop-cpbptqn-1.tailacbb15.ts.net/t/'+tenant+'/'), 'Noncanonical protected redirect'
 evidence={'task':'ast-hb5b','source_commit':options.source_commit,'binary_sha256':hashlib.sha256(bin).hexdigest(),'image':image,'image_id':imageid,'isolated_restore':'pass','restricted_image_readiness':'pass','isolated_canonical_discovery':'pass','isolated_protected_entrypoint_redirects':'pass','exact_account_credential_totp_equality':True,'successful_migrations':int(migrations),'new_migrations':[163,165],'private_backup':'~/.local/share/asterius/backups/'+private.name,'private_backup_mode':'0700/0600'}
 (private/'probe-evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
 print(json.dumps(evidence))
finally:
 subprocess.run(['docker','rm','-f',container],capture_output=True)
 run(local+['dropdb','-U','asterius',db])
 for p in private.iterdir():
  if p.is_file(): p.chmod(0o600)
