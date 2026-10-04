#!/usr/bin/env python3
"""Owned Asterius candidate instance behind the real authenticated TLS edge.

The relay signs real FAPI/DPoP credentials; human refresh authority is seeded
and explicitly labelled. This runner never enables any shared deployment.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'integrations'))
from oidc_product_fixture import command, sql

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
os.umask(0o077)
binary = Path(os.environ['ASTERIUS_BIN']).resolve()
database = 'ast_device_' + uuid.uuid4().hex
edge = server = None
created = False
root = Path(tempfile.mkdtemp(prefix='asterius-managed-device.runtime.'))
root.rmdir()
try:
    command(['bash', str(HERE / 'prepare-pki.sh'), str(root)])
    sql('postgres', f'create database "{database}";')
    created = True
    issuer = 'https://localhost:9525/t/e2e'
    config = (REPO / 'e2e/fixtures/asterius.toml.in').read_text()
    for name, value in {'@PORT@': '9525', '@CERTIFICATE@': str(root / 'backend-cert.pem'),
                        '@PRIVATE_KEY@': str(root / 'backend-key.pem'),
                        '@DATABASE_URL@': f'postgres://asterius:asterius@127.0.0.1:5433/{database}'}.items():
        config = config.replace(name, value)
    config = config.replace('bind = "127.0.0.1:9525"', 'bind = "127.0.0.1:9526"')
    config = config.replace('mode = "terminate_tls"', 'mode = "behind_proxy"')
    config = config.replace('[server.tls]\ncertificate = "' + str(root / 'backend-cert.pem') + '"\nprivate_key = "' + str(root / 'backend-key.pem') + '"',
                            '[server.proxy]\ntrusted_cidrs = ["127.0.0.1/32"]')
    config = config.replace('https://127.0.0.1:9525', 'https://localhost:9525')
    config = config.replace('device_flow = true', 'device_flow = true\ntoken_exchange = true\nauthzen = true')
    # The second browser tenant remains separate; both may trust the same
    # disposable CA but records and policy authority remain tenant scoped.
    config += f'''\n[managed_devices]\ncertificate_header = "x-controlled-device-cert"
[managed_devices.trust_anchors]
e2e = "{root / 'device-ca.pem'}"
[managed_devices.proxy_hop]
certificate = "{root / 'backend-cert.pem'}"
private_key = "{root / 'backend-key.pem'}"
trust_anchors = "{root / 'proxy-ca.pem'}"
client_fingerprints = ["{(root / 'proxy-fingerprint.txt').read_text().strip()}"]
'''
    (root / 'asterius.toml').write_text(config)
    edge_config = {'issuer': 'https://localhost:9525', 'backend': 'https://localhost:9526',
        'device_header': 'x-controlled-device-cert',
        **{name: str(root / file) for name, file in {
            'edge_certificate': 'edge-cert.pem', 'edge_private_key': 'edge-key.pem',
            'device_ca': 'device-ca.pem', 'proxy_certificate': 'proxy-cert.pem',
            'proxy_private_key': 'proxy-key.pem', 'backend_ca': 'backend-ca.pem'}.items()}}
    (root / 'edge.json').write_text(json.dumps(edge_config))
    env = {**os.environ, 'ASTERIUS_KEK': 'YXN0ZXJpdXMtZGV2LWtlay1ub3QtYS1zZWNyZXQhISE=',
           'ASTERIUS_ADMIN_PASSWORD': secrets.token_urlsafe(32)}
    with (root / 'server.log').open('w') as log, (root / 'edge.log').open('w') as edge_log:
        server = subprocess.Popen([str(binary), '--config', str(root / 'asterius.toml')], env=env, stdout=log, stderr=log)
        edge = subprocess.Popen(['node', str(HERE / 'proxy.mjs'), str(root / 'edge.json')], stdout=edge_log, stderr=edge_log)
        context = ssl.create_default_context(cafile=str(root / 'backend-ca.pem'))
        for _ in range(60):
            if server.poll() is not None or edge.poll() is not None:
                log.flush(); edge_log.flush()
                # Emit only known fixed bootstrap classes, never raw logs.
                startup = (root / 'server.log').read_text() + (root / 'edge.log').read_text()
                markers = ['Address already in use', 'configuration', 'migration', 'certificate', 'Connection refused', 'unique constraint', 'issuer']
                raise RuntimeError('DEVICE_RUNTIME_STAGE=bootstrap_exit:server' + str(server.poll()) + ':edge' + str(edge.poll()) + ':' + ','.join(marker for marker in markers if marker in startup))
            try:
                with urllib.request.urlopen('https://localhost:9525/readyz', context=context, timeout=1) as answer:
                    if answer.status == 200:
                        break
            except (urllib.error.URLError, TimeoutError):
                time.sleep(1)
        else:
            raise RuntimeError('DEVICE_RUNTIME_STAGE=bootstrap_timeout')
        # These credentials exist only in this new database. The human input
        # is a controlled refresh grant, never represented as a live login.
        result = subprocess.run([sys.executable, str(HERE / 'runtime_controls.py'), str(root), database, issuer],
                                env=env, capture_output=True, text=True, timeout=180)
        if result.returncode:
            stage = next((line for line in result.stderr.splitlines() if line.startswith('DEVICE_RUNTIME_STAGE=')),
                         'DEVICE_RUNTIME_STAGE=controlled_checks')
            raise RuntimeError(stage)
        evidence = json.loads(result.stdout)
        evidence['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        evidence['migration_count'] = int(sql(database, 'select count(*) from _sqlx_migrations where success;'))
        evidence['observed_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        print(json.dumps(evidence))
finally:
    for process in (edge, server):
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    if created:
        sql('postgres', f'drop database "{database}";')
    import shutil
    shutil.rmtree(root, ignore_errors=True)
