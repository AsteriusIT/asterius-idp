#!/usr/bin/env python3
"""Owned native SPIRE 1.15.3 fixture; no published SPIRE ports or shared DB writes."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.request

SERVER = 'ghcr.io/spiffe/spire-server@sha256:3aa2dce70fc1098d6718a87c629aa8cadb83e4672c71dd63c5575ea5d0603789'
AGENT = 'ghcr.io/spiffe/spire-agent@sha256:0d9c792d7f409b748d3a1fc93fe70b6d1450474c177d2a731ddc36e97a17e9fe'
SOCKET = '/run/spire/server/private/api.sock'
os.umask(0o077)
parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
parser.add_argument('--evidence', required=True)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
nonce = secrets.token_hex(6)
network = 'ast-dd1y-spire-' + nonce
server = network + '-server'
agent = network + '-agent'
database = 'ast_dd1y_spire_' + nonce
base = 'postgres://asterius:asterius@127.0.0.1:5433/postgres'
private = Path(tempfile.mkdtemp(prefix='asterius-spire-'))
process = None
created_database = False
created_network = False
containers = []

def run(command, input=None, check=True, env=None):
    result = subprocess.run(command, input=input, capture_output=True, timeout=60, env=env)
    if check and result.returncode:
        # Keep native SVIDs, join tokens, passwords and SQL out of public errors.
        (private / 'failure.log').write_bytes(result.stdout + result.stderr)
        raise RuntimeError('Owned fixture command failed: ' + command[0])
    return result.stdout

def server_cli(*command):
    return run(['docker', 'exec', server, '/opt/spire/bin/spire-server', *command, '-socketPath', SOCKET])

try:
    for image in (SERVER, AGENT):
        run(['docker', 'image', 'inspect', image])
    server_config = '''server {
 bind_address="0.0.0.0" bind_port="8081"
 socket_path="/run/spire/server/private/api.sock"
 trust_domain="asterius-dd1y.test" jwt_issuer="https://spire-dd1y.example.test"
 default_jwt_svid_ttl="5m" data_dir="/var/lib/spire/server"
}
plugins {
 DataStore "sql" { plugin_data { database_type="sqlite3" connection_string="/var/lib/spire/server/datastore.sqlite3" } }
 NodeAttestor "join_token" { plugin_data {} }
 KeyManager "disk" { plugin_data { keys_path="/var/lib/spire/server/keys.json" } }
}
'''
    (private / 'server.conf').write_text(server_config)
    run(['docker', 'network', 'create', network])
    created_network = True
    run(['docker', 'run', '-d', '--name', server, '--network', network,
         '--network-alias', 'server', '-v', str(private)+':/fixtures:ro',
         '--entrypoint', '/opt/spire/bin/spire-server', SERVER, 'run', '-config', '/fixtures/server.conf'])
    containers.append(server)
    for _ in range(50):
        result = subprocess.run(['docker','exec',server,'/opt/spire/bin/spire-server','healthcheck','-socketPath',SOCKET], capture_output=True)
        if result.returncode == 0:
            break
        time.sleep(0.2)
    else:
        raise RuntimeError('Owned SPIRE server not ready')
    (private / 'server-ca.pem').write_bytes(server_cli('bundle', 'show'))
    join = json.loads(server_cli('token', 'generate', '-spiffeID', 'spiffe://asterius-dd1y.test/agent', '-output', 'json'))
    token = join.get('value') or join.get('token')
    if not isinstance(token, str):
        raise RuntimeError('Unexpected native join-token output shape')
    (private / 'agent.conf').write_text('''agent {
 data_dir="/var/lib/spire/agent" server_address="server" server_port="8081"
 socket_path="/run/spire/agent/public/api.sock" trust_bundle_path="/fixtures/server-ca.pem"
 trust_domain="asterius-dd1y.test"
}
plugins {
 NodeAttestor "join_token" { plugin_data {} }
 KeyManager "disk" { plugin_data { directory="/var/lib/spire/agent/keys" } }
 WorkloadAttestor "unix" { plugin_data {} }
}
''')
    run(['docker','run','-d','--name',agent,'--network',network,'-v',str(private)+':/fixtures:ro',
         '--entrypoint','/opt/spire/bin/spire-agent',AGENT,'run','-config','/fixtures/agent.conf','-joinToken',token])
    containers.append(agent)
    server_cli('entry','create','-parentID','spiffe://asterius-dd1y.test/agent',
               '-spiffeID','spiffe://asterius-dd1y.test/inventory','-selector','unix:uid:1000','-jwtSVIDTTL','300')
    # Attested via the real agent socket, never minted from the privileged server API.
    for _ in range(60):
        ready = subprocess.run(['docker','exec','--user','1000',agent,'/opt/spire/bin/spire-agent',
               'api','fetch','jwt','-socketPath','/run/spire/agent/public/api.sock',
               '-audience','urn:asterius:workload:workload:spire-fixture','-output','json'],capture_output=True)
        if ready.returncode == 0:
            (private/'native-jwt.json').write_bytes(ready.stdout)
            break
        time.sleep(0.5)
    else:
        raise RuntimeError('Owned SPIRE workload attestation not ready')
    run(['psql',base,'-X','-v','ON_ERROR_STOP=1','-c','create database '+database])
    created_database = True
    db = base.removesuffix('/postgres') + '/' + database
    run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
         '-keyout',str(private/'key.pem'),'-out',str(private/'cert.pem'),'-days','1','-nodes',
         '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1'])
    (private/'asterius.toml').write_text(f'''[server]
bind="127.0.0.1:9453"
mode="terminate_tls"
[server.tls]
certificate="{private}/cert.pem"
private_key="{private}/key.pem"
[database]
url="{db}"
max_connections=8
[keys]
kek_env="ASTERIUS_KEK"
[features]
token_exchange=true
[limits]
token_per_address=1000
[[tenant]]
id="workload"
issuer="https://localhost:9453/t/workload"
''')
    environment = dict(os.environ, ASTERIUS_KEK='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
    with (private/'asterius.log').open('wb') as log:
        process = subprocess.Popen([args.binary,'--config',str(private/'asterius.toml')],env=environment,stdout=log,stderr=log)
    import ssl
    context = ssl.create_default_context(cafile=str(private/'cert.pem'))
    for _ in range(60):
        try:
            with urllib.request.urlopen('https://localhost:9453/readyz',context=context,timeout=1) as response:
                if response.status == 200: break
        except (OSError, urllib.error.URLError):
            if process.poll() is not None: raise RuntimeError('Owned Asterius fixture exited')
            time.sleep(0.5)
    else:
        raise RuntimeError('Owned Asterius fixture not ready')
    environment.update(ACCEPTANCE_DATABASE_URL=db, ACCEPTANCE_ISSUER='https://localhost:9453/t/workload',
        ACCEPTANCE_CERTIFICATE=str(private/'cert.pem'), ACCEPTANCE_TLS_KEY=str(private/'key.pem'),
        NODE_EXTRA_CA_CERTS=str(private/'cert.pem'), SPIRE_SERVER=server, SPIRE_AGENT=agent,
        ACCEPTANCE_EVIDENCE=str(Path(args.evidence).resolve()))
    output = run(['node',str(repo/'scripts/spire/acceptance.mjs')],env=environment)
    print(output.decode().strip())
except Exception:
    diagnostics = Path(tempfile.mkdtemp(prefix='asterius-spire-failure-'))
    if (private/'failure.log').is_file():
        shutil.copyfile(private/'failure.log', diagnostics/'failure.log')
    for container in containers:
        result = subprocess.run(['docker','logs',container],capture_output=True)
        (diagnostics/(container+'.log')).write_bytes(result.stdout+result.stderr)
    if (private/'asterius.log').is_file():
        shutil.copyfile(private/'asterius.log', diagnostics/'asterius.log')
    print('Protected failure diagnostics: ' + str(diagnostics))
    raise
finally:
    if process is not None:
        process.terminate()
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
    if created_database:
        run(['psql',base,'-X','-v','ON_ERROR_STOP=1','-c','drop database '+database+' with (force)'])
    for container in reversed(containers):
        run(['docker','rm','-f',container])
    if created_network:
        run(['docker','network','rm',network])
    shutil.rmtree(private)
