#!/usr/bin/env python3
"""Generate private local keys and a public supported-admin setup plan.

Writes only to an explicitly supplied private operator directory. No database
writes, API calls or cluster mutations. Existing run files are never replaced.
"""
import argparse, base64, json, os, uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec

def b64(n): return base64.urlsafe_b64encode(n.to_bytes(32, 'big')).rstrip(b'=').decode()
def prepare(directory, origin, issuer):
 directory.mkdir(parents=True, exist_ok=True, mode=0o700)
 os.chmod(directory, 0o700)
 if (directory/'plan.json').exists(): raise ValueError('Existing plan retained; select another run directory or reuse it unchanged')
 clients=[]
 for name in ['demo-a','demo-b','financial-api','protocol-lab']:
  key=ec.generate_private_key(ec.SECP256R1()).private_numbers(); pub=key.public_numbers
  public={'kty':'EC','crv':'P-256','x':b64(pub.x),'y':b64(pub.y),'kid':'playground-'+name+'-'+uuid.uuid4().hex[:8],'alg':'ES256','use':'sig'}
  private={**public,'d':b64(key.private_value)}
  target=directory/(name+'-private.jwk.json'); target.write_text(json.dumps(private));target.chmod(0o600)
  scope='openid profile offline_access' if name.startswith('demo-') else 'openid accounts:read accounts:write' if name=='financial-api' else 'openid profile'
  grants=['authorization_code','refresh_token'] if name!='protocol-lab' else ['urn:ietf:params:oauth:grant-type:device_code','urn:openid:params:grant-type:ciba']
  callback=origin+'/'+name+('/auth/callback' if name=='financial-api' else '/callback')
  registration={'client_name':'Playground · '+name,'token_endpoint_auth_method':'private_key_jwt','jwks':{'keys':[public]},'grant_types':grants,'response_types':['code'] if name!='protocol-lab' else [],'scope':scope,'redirect_uris':[callback] if name!='protocol-lab' else [],'dpop_bound_access_tokens':True,'require_pushed_authorization_requests':True,'id_token_signed_response_alg':'EdDSA'}
  if name.startswith('demo-'):registration['post_logout_redirect_uris']=[origin+'/'+name+'/logged-out']
  if name=='protocol-lab':registration['backchannel_token_delivery_mode']='poll'
  clients.append({'key':name,'idempotency_key':str(uuid.uuid4()),'registration':registration,'resources':[origin+'/financial-api'] if name=='financial-api' else [issuer+'/userinfo']})
 plan={'run_id':str(uuid.uuid4()),'tenant':'demo','origin':origin,'issuer':issuer,'clients':clients,'resources':[{'identifier':origin+'/financial-api','scopes':['accounts:read','accounts:write'],'default_token_lifetime_seconds':300,'clients':['financial-api']},{'identifier':issuer+'/userinfo','scopes':['openid','profile','offline_access'],'default_token_lifetime_seconds':300,'clients':['demo-a','demo-b','protocol-lab']}]}
 target=directory/'plan.json';target.write_text(json.dumps(plan,indent=2)+'\n');target.chmod(0o600)
 return plan
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--origin',required=True);p.add_argument('--issuer',required=True);a=p.parse_args();plan=prepare(a.directory,a.origin.rstrip('/'),a.issuer.rstrip('/'));print('Generated four private keys and public setup plan; no cluster changes')
