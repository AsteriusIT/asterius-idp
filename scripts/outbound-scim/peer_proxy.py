#!/usr/bin/env python3
"""Private fault relay inside the acceptance namespace; never log credentials."""
import argparse
import http.client
import json
from pathlib import Path
import re
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
SCIM = '/t/target/admin/api/v1/scim/v2/'
LIMIT = 65536


def allowed(method, raw):
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        return False
    if parsed.path == '/t/target/token':
        return method == 'POST' and not parsed.query
    if not parsed.path.startswith(SCIM):
        return False
    tail = parsed.path[len(SCIM):]
    if tail in ('ServiceProviderConfig', 'Schemas', 'ResourceTypes'):
        return method == 'GET' and not parsed.query
    if tail in ('Users', 'Groups'):
        if method == 'POST':
            return not parsed.query
        if method != 'GET':
            return False
        query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        return not query or (
            set(query) == {'filter', 'count'} and query['count'] == ['2']
            and len(query['filter']) == 1
            and re.fullmatch(r'(userName|displayName) eq "ast-(user|group)-[0-9a-f]{32}-[0-9a-f]{32}-[0-9a-f]{32}"', query['filter'][0]) is not None
        )
    return re.fullmatch(r'(Users|Groups)/' + UUID, tail) is not None and not parsed.query and method in ('GET', 'PUT', 'DELETE')


class Relay(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.client_tls = ssl.create_default_context()
        super().__init__((config['address'], config['port']), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(config['certificate'], config['private_key'])
        self.socket = context.wrap_socket(self.socket, server_side=True)

    def fault(self, method, path):
        file = Path(self.config['fault_file'])
        with self.lock:
            if not file.exists():
                return None
            pending = json.loads(file.read_text())
            if pending.get('method') != method or pending.get('path') != path:
                return None
            file.unlink()
            return pending.get('action')

    def evidence(self, method, path, status, fault):
        # No headers, body, query, remote resource UUID, URL or token material.
        family = 'token' if path == '/t/target/token' else path[len(SCIM):].split('/')[0]
        record = {'method': method, 'family': family, 'status': status, 'fault': fault}
        with self.lock, Path(self.config['evidence_file']).open('a') as output:
            output.write(json.dumps(record, separators=(',', ':')) + '\n')


class DirectTLS(http.client.HTTPSConnection):
    def __init__(self, server):
        super().__init__(server.config['hostname'], server.config['upstream_port'], timeout=10, context=server.client_tls)
        self.server_config = server.config

    def connect(self):
        # Connect only the fixture upstream in this namespace, preserve strict
        # hostname certificate verification independently of canonical HTTP Host.
        import socket
        plain = socket.create_connection(('127.0.0.1', self.port), self.timeout)
        self.sock = self._context.wrap_socket(plain, server_hostname=self.host)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def reply(self, status, body=b''):
        self.send_response(status)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def route(self):
        try:
            permitted = allowed(self.command, self.path)
        except ValueError:
            permitted = False
        if not permitted or self.headers.get('Transfer-Encoding'):
            return self.reply(404)
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.reply(400)
        if length < 0 or length > LIMIT:
            return self.reply(413)
        self.connection.settimeout(15)
        body = self.rfile.read(length)
        path = urlsplit(self.path).path
        fault = self.server.fault(self.command, path)
        if fault == 'refuse':
            self.server.evidence(self.command, path, 503, fault)
            return self.reply(503)
        headers = {key: value for key, value in self.headers.items()
                   if key.lower() not in ('host', 'connection', 'transfer-encoding', 'content-length')}
        headers['Host'] = self.server.config['hostname'] + ':' + str(self.server.config['port'])
        connection = DirectTLS(self.server)
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(LIMIT + 1)
            if len(data) > LIMIT:
                return self.reply(502)
            self.server.evidence(self.command, path, response.status, fault)
            if fault == 'drop_after_commit' and response.status in (200, 201, 204):
                # Remote request really completed; caller receives no response.
                self.close_connection = True
                self.connection.shutdown(2)
                return
            self.send_response(response.status)
            for key in ('Content-Type', 'ETag', 'DPoP-Nonce', 'Retry-After'):
                if value := response.getheader(key):
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True
        except (OSError, http.client.HTTPException):
            self.server.evidence(self.command, path, 502, fault)
            self.reply(502)
        finally:
            connection.close()

    do_GET = route
    do_POST = route
    do_PUT = route
    do_DELETE = route


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=Path)
    arguments = parser.parse_args()
    with Relay(json.loads(arguments.config.read_text())) as server:
        server.serve_forever(poll_interval=0.1)
