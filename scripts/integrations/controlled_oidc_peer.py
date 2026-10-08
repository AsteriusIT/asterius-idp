"""Controlled independently signed OIDC faults, backed by real disposable Keycloak login."""
import base64
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import sys
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec,utils

os.umask(0o077)
CONFIG=Path(sys.argv[1])
CONFIGURATION=json.loads(CONFIG.read_text())
if CONFIG.stat().st_mode&0o077:raise ValueError('private fixture configuration required')
KEY_PREFIX='controlled-'+secrets.token_hex(8)
KEYS=[ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
ISSUER=CONFIGURATION['issuer']
NATIVE_ISSUER=CONFIGURATION['keycloak_issuer']


def b64(value):return base64.urlsafe_b64encode(value).decode().rstrip('=')

def public(index):
    numbers=KEYS[index].public_key().public_numbers()
    return {'kty':'EC','crv':'P-256','alg':'ES256','use':'sig','kid':KEY_PREFIX+'-'+str(index),
            'x':b64(numbers.x.to_bytes(32,'big')),'y':b64(numbers.y.to_bytes(32,'big'))}


def signed(claims,index,forged=False):
    encoded=b64(json.dumps({'alg':'ES256','typ':'JWT','kid':KEY_PREFIX+'-'+str(index)}).encode())+'.'+b64(json.dumps(claims).encode())
    r,s=utils.decode_dss_signature(KEYS[2 if forged else index].sign(encoded.encode(),ec.ECDSA(hashes.SHA256())))
    return encoded+'.'+b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))


def native_claims(token):
    parts=token.split('.');header=json.loads(base64.urlsafe_b64decode(parts[0]+'='*(-len(parts[0])%4)))
    conn=http.client.HTTPConnection('127.0.0.1',9488,timeout=10)
    try:
        conn.request('GET','/keycloak/realms/asterius-protocol/protocol/openid-connect/certs')
        response=conn.getresponse();keys=json.loads(response.read(65536))['keys']
    finally:conn.close()
    candidates=[k for k in keys if k.get('kid')==header.get('kid') and k.get('alg')=='ES256' and k.get('use')=='sig']
    if header.get('alg')!='ES256' or len(candidates)!=1:raise ValueError('native signer refused')
    key=candidates[0];decode=lambda value:base64.urlsafe_b64decode(value+'='*(-len(value)%4))
    numbers=ec.EllipticCurvePublicNumbers(int.from_bytes(decode(key['x']),'big'),int.from_bytes(decode(key['y']),'big'),ec.SECP256R1())
    signature=decode(parts[2]);numbers.public_key().verify(utils.encode_dss_signature(int.from_bytes(signature[:32],'big'),int.from_bytes(signature[32:],'big')),('.'.join(parts[:2])).encode(),ec.ECDSA(hashes.SHA256()))
    claims=json.loads(decode(parts[1]))
    if claims.get('iss')!=NATIVE_ISSUER or claims.get('exp',0)<=time.time():raise ValueError('native claims refused')
    return claims


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_):pass

    def respond(self,status,body):
        payload=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)

    def mode(self):
        target=Path(CONFIGURATION['mode_file'])
        if target.stat().st_mode&0o077:raise ValueError('private fault control required')
        mode=json.loads(target.read_text())
        if mode.get('mode') not in ('normal','expired','forged','wrong_issuer','wrong_nonce','wrong_subject','token_outage','jwks_outage'):raise ValueError('unrecognized fault')
        if mode.get('active_key',0) not in (0,1):raise ValueError('unrecognized key')
        return mode

    def do_GET(self):
        try:
            mode=self.mode()
            if self.path=='/controlled-peer/.well-known/openid-configuration':
                self.respond(200,{'issuer':ISSUER,'authorization_endpoint':NATIVE_ISSUER+'/protocol/openid-connect/auth','token_endpoint':ISSUER+'/token','jwks_uri':ISSUER+'/jwks','response_types_supported':['code'],'subject_types_supported':['public'],'id_token_signing_alg_values_supported':['ES256'],'token_endpoint_auth_methods_supported':['client_secret_basic'],'scopes_supported':['openid'],'code_challenge_methods_supported':['S256']})
            elif self.path=='/controlled-peer/jwks':
                if mode['mode']=='jwks_outage':self.respond(503,{'error':'controlled_outage'})
                else:self.respond(200,{'keys':[public(mode.get('active_key',0))]})
            else:self.respond(404,{'error':'unknown_endpoint'})
        except Exception:self.respond(503,{'error':'controlled_peer_unavailable'})

    def do_POST(self):
        connection=None
        try:
            mode=self.mode()
            if self.path!='/controlled-peer/token':self.respond(404,{'error':'unknown_endpoint'});return
            if mode['mode']=='token_outage':self.respond(503,{'error':'controlled_outage'});return
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=8192 or self.headers.get('Transfer-Encoding'):self.respond(400,{'error':'invalid_request'});return
            connection=http.client.HTTPConnection('127.0.0.1',9488,timeout=20)
            connection.request('POST','/keycloak/realms/asterius-protocol/protocol/openid-connect/token',body=self.rfile.read(size),headers={'Content-Type':'application/x-www-form-urlencoded','Authorization':self.headers.get('Authorization',''),'X-Forwarded-Proto':'https','X-Forwarded-Host':CONFIGURATION['public_host'],'X-Forwarded-Port':'10000'})
            response=connection.getresponse();body=response.read(65537)
            if len(body)>65536:raise ValueError('native response exceeds bound')
            document=json.loads(body)
            if response.status!=200:self.respond(response.status,{'error':'native_token_refused'});return
            claims=native_claims(document['id_token']);claims['iss']=ISSUER
            if mode['mode']=='expired':claims.update(iat=int(time.time())-1200,exp=int(time.time())-600)
            if mode['mode']=='wrong_issuer':claims['iss']=ISSUER+'/another-provider'
            if mode['mode']=='wrong_nonce':claims['nonce']=secrets.token_urlsafe(32)
            if mode['mode']=='wrong_subject':claims['sub']='controlled-unmapped-subject'
            document['id_token']=signed(claims,mode.get('active_key',0),mode['mode']=='forged')
            with (CONFIG.parent/'controlled-peer-metrics.jsonl').open('a') as output:output.write(json.dumps({'mode':mode['mode'],'active_key':mode.get('active_key',0),'native_signature_verified':True})+'\n')
            self.respond(200,document)
        except Exception:self.respond(503,{'error':'controlled_peer_unavailable'})
        finally:
            if connection:connection.close()


if __name__=='__main__':
    http.server.ThreadingHTTPServer(('127.0.0.1',9489),Handler).serve_forever()
