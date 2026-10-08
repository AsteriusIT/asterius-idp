#!/usr/bin/env python3
"""Apply the owned playground after normal browser-admin registration.

The PostgreSQL query is read-only ownership verification. Administration writes
happen through setup.js with the human's normal session, never direct SQL.
Private JWK files remain in the operator directory and Kubernetes Secrets.
"""
import argparse, base64, json, subprocess
from pathlib import Path
import yaml

CONTEXT='kind-asterius-local'
NAMESPACE='asterius-playground'
TASK='ast-q66b'

def kubectl(*args, content=None):
 return subprocess.check_output(['kubectl','--context',CONTEXT,*args],input=content,text=True)

def verify(directory):
 plan=json.loads((directory/'plan.json').read_text())
 query="select coalesce(json_agg(t),'[]'::json) from (select client_id,client_name,jwks,grant_types,redirect_uris,resources,token_endpoint_auth_method from clients where tenant_id='demo' and client_name like 'Playground%') t;"
 rows=json.loads(kubectl('-n','asterius','exec','asterius-postgresql-1','-c','postgres','--','psql','-U','postgres','-d','asterius','-At','-c',query))
 ids={}
 for c in plan['clients']:
  expected=c['registration']
  matches=[r for r in rows if r['client_name']==expected['client_name'] and r['jwks']==expected['jwks']]
  if len(matches)!=1: raise ValueError('Complete the normal setup page first: '+c['key'])
  r=matches[0]
  if r['token_endpoint_auth_method']!='private_key_jwt' or set(r['grant_types'])!=set(expected['grant_types']) or set(r['redirect_uris'])!=set(expected['redirect_uris']) or set(r['resources'])!=set(c['resources']): raise ValueError('Registration differs from approved plan: '+c['key'])
  ids[c['key']]=r['client_id']
 return plan,ids

def install(directory, stage=False):
 namespace=kubectl('get','namespace',NAMESPACE,'--ignore-not-found','-o','json').strip()
 if namespace and json.loads(namespace)['metadata'].get('labels',{}).get('asterius.local/task')!=TASK:raise ValueError('Existing namespace is not owned by this setup; refusing to replace resources')
 plan=json.loads((directory/'plan.json').read_text())
 if not stage:
  plan,ids=verify(directory)
  # Check all secrets before any replacement. Rotation is a separate operation.
  manifests=[]
  for name,cid in ids.items():
   raw=(directory/(name+'-private.jwk.json')).read_text();key=json.loads(raw)
   expected=next(c for c in plan['clients'] if c['key']==name)['registration']['jwks']['keys'][0]
   if {k:v for k,v in key.items() if k!='d'}!=expected:raise ValueError('Private key does not match approved public key')
   values={'CLIENT_ID':cid,'CLIENT_KEY_ID':key['kid'],'CLIENT_PRIVATE_KEY_JWK':raw}
   data={k:base64.b64encode(v.encode()).decode() for k,v in values.items()}
   manifest={'apiVersion':'v1','kind':'Secret','metadata':{'name':name+'-oidc','namespace':NAMESPACE,'labels':{'asterius.local/task':TASK}},'type':'Opaque','data':data}
   existing=kubectl('-n',NAMESPACE,'get','secret',name+'-oidc','--ignore-not-found','-o','json').strip()
   if existing:
    held=json.loads(existing)
    if held['metadata'].get('labels',{}).get('asterius.local/task')!=TASK or held['data']!=data:raise ValueError('Existing Secret differs; do not overwrite it: '+name)
   else:manifests.append(manifest)
  for manifest in manifests:kubectl('create','-f','-',content=json.dumps(manifest))
  f=directory/'client-ids.json';f.write_text(json.dumps(ids,indent=2)+'\n');f.chmod(0o600)
 items=list(yaml.safe_load_all(kubectl('kustomize',str(Path(__file__).parent))))
 for item in items:
  item.setdefault('metadata',{}).setdefault('labels',{})['asterius.local/task']=TASK
  if stage and item['kind']=='Deployment' and item['metadata']['name'] not in ['gateway','financial-web']:item['spec']['replicas']=0
 setup=Path(__file__).parent/'setup'
 items.append({'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'playground-setup','namespace':NAMESPACE,'labels':{'asterius.local/task':TASK}},'data':{'index.html':(setup/'index.html').read_text(),'setup.js':(setup/'setup.js').read_text(),'plan.json':json.dumps(plan,indent=2)}})
 kubectl('apply','-f','-',content=json.dumps({'apiVersion':'v1','kind':'List','items':items}))
 return len(items)

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path);parser.add_argument('--stage',action='store_true',help='Deploy setup/portal/web before human registration; other app replicas stay zero');args=parser.parse_args()
 count=install(args.directory,args.stage);print('Applied '+str(count)+' owned resources; private keys were not printed')
