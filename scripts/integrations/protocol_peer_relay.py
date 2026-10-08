"""Disposable public peer relay; fixed routes, TLS-verified backend, safe ciphertext metrics."""
import base64
import hashlib
import hmac
import http.client
import http.server
import json
import os
from pathlib import Path
import ssl
import sys
import threading

os.umask(0o077)
CONFIG=Path(sys.argv[1]);LOCK=threading.Lock()


def private_json(path):
    target=Path(path)
    if not target.is_file() or target.stat().st_mode & 0o077:
        raise ValueError('private fixture input required')
    return json.loads(target.read_text())


def envelope(value):
    parts=value.split('.')
    if len(parts) not in (3,5):return {'segments':len(parts),'alg':'invalid','enc':'invalid'}
    header=json.loads(base64.urlsafe_b64decode(parts[0]+'='*(-len(parts[0])%4)))
    return {'segments':len(parts),
            'alg':header.get('alg') if header.get('alg') in ('ES256','EdDSA','RSA-OAEP-256') else 'other',
            'enc':header.get('enc') if header.get('enc')=='A256GCM' else 'other'}


class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_args):pass

    def forward(self):
        connection=None
        try:
            config=private_json(CONFIG);path=self.path.split('?',1)[0]
            forwarded_path=self.path
            if path.startswith('/keycloak/realms/asterius-protocol/') or path.startswith('/keycloak/resources/'):
                connection=http.client.HTTPConnection('127.0.0.1',9488,timeout=20)
            elif path.startswith('/controlled-peer/'):
                connection=http.client.HTTPConnection('127.0.0.1',9489,timeout=20)
            elif path.startswith('/ssf-push-peer/') or path=='/.well-known/ssf-configuration/ssf-push-peer':
                connection=http.client.HTTPConnection('127.0.0.1',19485,timeout=20)
            elif path.startswith('/ssf-peer/') or path=='/.well-known/ssf-configuration/ssf-peer':
                connection=http.client.HTTPConnection('127.0.0.1',9485,timeout=20)
            elif path in ('/asterius-rp/token','/asterius-rp/userinfo','/asterius-rp/jwks'):
                fixture=private_json(config['manifest'])
                if fixture['issuer']!='https://localhost:18444/t/e2e':raise ValueError('exact owned issuer required')
                forwarded_path='/t/e2e/'+path.rsplit('/',1)[1]
                if '?' in self.path:forwarded_path+='?'+self.path.split('?',1)[1]
                connection=http.client.HTTPSConnection('localhost',18444,context=ssl.create_default_context(cafile=fixture['ca_file']),timeout=20)
            elif path in ('/ipsie-rp/token','/ipsie-rp/userinfo','/ipsie-rp/jwks'):
                fixture=private_json(config['ipsie_manifest'])
                if fixture['issuer']!='https://localhost:18447/t/e2e':raise ValueError('exact selected owned issuer required')
                forwarded_path='/t/e2e/'+path.rsplit('/',1)[1]
                connection=http.client.HTTPSConnection('localhost',18447,context=ssl.create_default_context(cafile=fixture['ca_file']),timeout=20)
            elif path=='/asterius-ssf/receiver':
                fixture=private_json(config['manifest'])
                if fixture['issuer']!='https://localhost:18444/t/e2e':raise ValueError('exact owned receiver issuer required')
                forwarded_path='/t/e2e/ssf/receiver'
                connection=http.client.HTTPSConnection('localhost',18444,context=ssl.create_default_context(cafile=fixture['ca_file']),timeout=20)
            else:self.send_error(404);return
            if self.headers.get('Transfer-Encoding'):self.send_error(400);return
            size=int(self.headers.get('Content-Length','0'))
            if not 0<=size<=65536:self.send_error(413);return
            excluded={'host','connection','forwarded','x-forwarded-for','x-forwarded-host','x-forwarded-proto','x-forwarded-port','transfer-encoding'}
            headers={key:value for key,value in self.headers.items() if key.lower() not in excluded}
            headers.update({'Host':config['public_host'],'X-Forwarded-Proto':'https','X-Forwarded-Host':config['public_host'],'X-Forwarded-Port':'10000'})
            if path.startswith('/asterius-rp/') or path=='/asterius-ssf/receiver':
                headers['Host']='localhost:18444';headers['X-Forwarded-Host']='localhost:18444';headers['X-Forwarded-Port']='18444'
            if path.startswith('/ipsie-rp/'):
                headers['Host']='localhost:18447';headers['X-Forwarded-Host']='localhost:18447';headers['X-Forwarded-Port']='18447'
            request_body=self.rfile.read(size) if size else None
            # A private operator arm file injects one authenticated ACK loss
            # before the native transmitter sees it. No public fault endpoint.
            if self.command=='POST' and path.startswith('/ssf-peer/') and request_body and (CONFIG.parent/'ssf-drop-next-ack.flag').exists():
                try:document=json.loads(request_body)
                except ValueError:document=None
                acknowledgments=document.get('ack') if isinstance(document,dict) else None
                if isinstance(acknowledgments,list) and acknowledgments:
                    flag=CONFIG.parent/'ssf-drop-next-ack.flag'
                    with LOCK:
                        if flag.exists():
                            armed=private_json(flag)
                            presented=hashlib.sha256(self.headers.get('Authorization','').encode()).hexdigest()
                            if hmac.compare_digest(presented,armed['authorization_sha256']):
                                flag.unlink()
                                status=CONFIG.parent/'ssf-ack-loss-status.json'
                                status.write_text(json.dumps({'injected':True,'status':503,'forwarded':False}))
                                status.chmod(0o600)
                                self.send_response(503)
                                self.send_header('Content-Length','0')
                                self.send_header('Cache-Control','no-store')
                                self.end_headers()
                                return
            connection.request(self.command,forwarded_path,body=request_body,headers=headers)
            response=connection.getresponse();body=response.read(4194305)
            if len(body)>4194304:self.send_error(502);return
            if path.startswith(('/asterius-rp/','/ipsie-rp/')):
                metric={'path':path,'status':response.status,'backend_tls_verified':True}
                if response.status==200 and not path.endswith('/jwks'):
                    value=json.loads(body)['id_token'] if path.endswith('/token') else body.decode()
                    metric.update(envelope(value))
                with LOCK:
                    with Path(config['metrics']).open('a') as output:output.write(json.dumps(metric)+'\n')
            self.send_response(response.status)
            for key,value in response.getheaders():
                if key.lower() not in {'connection','transfer-encoding','content-length'}:self.send_header(key,value)
            self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        except Exception:self.send_error(502)
        finally:
            if connection:connection.close()

    do_GET=do_POST=do_PUT=do_DELETE=do_PATCH=forward


if __name__=='__main__':
    private_json(CONFIG)
    http.server.ThreadingHTTPServer(('127.0.0.1',9487),Proxy).serve_forever()
