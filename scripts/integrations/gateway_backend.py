#!/usr/bin/env python3
"""Controlled backend: reports identity and credential presence, never tokens."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body=json.dumps({'user':self.headers.get('X-Forwarded-User'),
                         'email':self.headers.get('X-Forwarded-Email'),
                         'groups':self.headers.get('X-Forwarded-Groups'),
                         'auth_request_user':self.headers.get('X-Auth-Request-User'),
                         'authorization_present':bool(self.headers.get('Authorization')),
                         'access_token_present':bool(self.headers.get('X-Forwarded-Access-Token')),
                         'gateway_cookie_present':'__Host-asterius_gateway=' in self.headers.get('Cookie','')}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    do_POST=do_GET
    def log_message(self,*args):
        pass


ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
