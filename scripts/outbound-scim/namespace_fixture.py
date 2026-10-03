"""Owned namespace for real production-guarded outbound HTTPS acceptance.

The synthetic globally classified address exists only on this namespace's
loopback. This proves classification, pinned dialing and trusted-host TLS;
it deliberately does not assert Internet reachability or expose a public peer.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

HOSTNAME = os.environ['ASTERIUS_OUTBOUND_HOSTNAME']
if not HOSTNAME.endswith('.ts.net') or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in HOSTNAME):
    raise RuntimeError('exact private tailnet DNS hostname required')
ADDRESS = '93.184.215.14'
HELPER = 'python:3.13-alpine3.20'
RUNTIME = 'gcr.io/distroless/cc-debian13:nonroot'


def command(arguments, body=None, timeout=90):
    result = subprocess.run(arguments, input=body, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        # Never print Docker config, runtime logs or child stderr with credentials.
        stage = next((line for line in result.stderr.splitlines() if line.startswith('OUTBOUND_SCIM_STAGE=')), '')
        if not stage:
            stage = ','.join(marker for marker in ('ERR_MODULE_NOT_FOUND', 'SyntaxError', 'ENOENT', 'ENOSPC') if marker in result.stderr)
        raise RuntimeError('owned outbound fixture command refused: ' + Path(arguments[0]).name + (' ' + stage if stage else ''))
    return result.stdout.strip()


@contextlib.contextmanager
def namespace(binary, certificate_directory):
    os.umask(0o077)
    binary = Path(binary).resolve(strict=True)
    certificate_directory = Path(certificate_directory).resolve(strict=True)
    if (certificate_directory / 'hostname').read_text() != HOSTNAME:
        raise RuntimeError('exact authorized TLS hostname required')
    for name in ('cert.pem', 'key.pem'):
        if (certificate_directory / name).stat().st_mode & 0o077:
            raise RuntimeError('private certificate file permissions required')
    nonce = uuid.uuid4().hex[:12]
    helper = 'ast-outbound-net-' + nonce
    containers = []
    with tempfile.TemporaryDirectory(prefix='asterius-outbound-namespace.') as directory:
        root = Path(directory)
        try:
            for name in ('cert.pem', 'key.pem'):
                shutil.copyfile(certificate_directory / name, root / name)
                (root / name).chmod(0o600)
            shutil.copyfile(Path(__file__).with_name('peer_proxy.py'), root / 'peer_proxy.py')
            # No downloads or daemon changes. Cached image requirement is explicit.
            for image in (HELPER, RUNTIME):
                command(['docker', 'image', 'inspect', image])
            command(['docker', 'run', '-d', '--pull=never', '--name', helper,
                     '--cap-drop=ALL', '--cap-add=NET_ADMIN', '--security-opt=no-new-privileges',
                     '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
                     '-v', str(root) + ':/fixture:rw',
                     '-p', '127.0.0.1:9478:9478', '-p', '127.0.0.1:9492:9492',
                     HELPER, 'python', '-c', 'import time;time.sleep(1800)'])
            containers.append(helper)
            command(['docker', 'exec', helper, 'ip', 'address', 'add', ADDRESS + '/32', 'dev', 'lo'])
            gateway = command(['docker', 'inspect', '--format', '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}', helper])
            if not gateway or any(c not in '0123456789.' for c in gateway):
                raise RuntimeError('owned namespace gateway not IPv4')
            db_container = os.environ['ASTERIUS_ACCEPTANCE_DB_CONTAINER']
            networks = json.loads(command(['docker', 'inspect', '--format',
                '{{json .NetworkSettings.Networks}}', db_container]))
            if len(networks) != 1:
                raise RuntimeError('controlled database must have one explicit fixture network')
            db_network, db_details = next(iter(networks.items()))
            database_host = db_details['IPAddress']
            if not database_host or any(c not in '0123456789.' for c in database_host):
                raise RuntimeError('controlled database address must be IPv4')
            command(['docker', 'network', 'connect', db_network, helper])
            (root / 'hosts').write_text('127.0.0.1 localhost\n' + ADDRESS + ' ' + HOSTNAME + '\n')
            relay = {'hostname': HOSTNAME, 'address': ADDRESS, 'port': 9446,
                     'upstream_port': 9492, 'certificate': '/fixture/cert.pem',
                     'private_key': '/fixture/key.pem', 'fault_file': '/fixture/fault.json',
                     'evidence_file': '/fixture/relay.jsonl'}
            (root / 'relay.json').write_text(json.dumps(relay))

            def start_runtime(label, configuration, environment):
                if label not in ('source', 'target'):
                    raise RuntimeError('closed fixture runtime label required')
                config_file = root / (label + '.toml')
                config_file.write_text(configuration)
                env_file = root / (label + '.env')
                if any('\n' in key + value for key, value in environment.items()):
                    raise RuntimeError('fixture environment must be single line')
                env_file.write_text(''.join(key + '=' + value + '\n' for key, value in environment.items()))
                name = 'ast-outbound-' + label + '-' + nonce
                command(['docker', 'run', '-d', '--pull=never', '--name', name,
                         '--network', 'container:' + helper, '--user', str(os.getuid()) + ':' + str(os.getgid()),
                         '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                         '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--env-file', str(env_file),
                         '-v', str(root) + ':/fixture:ro', '-v', str(root / 'hosts') + ':/etc/hosts:ro',
                         '-v', str(binary) + ':/asterius:ro', '--entrypoint', '/asterius',
                         RUNTIME, '--config', '/fixture/' + label + '.toml'])
                containers.append(name)
                return name

            def start_relay():
                command(['docker', 'exec', '-d', '--user', str(os.getuid()) + ':' + str(os.getgid()), helper, 'python', '/fixture/peer_proxy.py', '/fixture/relay.json'])

            yield {'root': root, 'gateway': gateway, 'database_host': database_host, 'helper': helper,
                   'target_issuer': 'https://' + HOSTNAME + ':9446/t/target',
                   'source_issuer': 'https://localhost:9478/t/e2e',
                   'start_runtime': start_runtime, 'start_relay': start_relay,
                   'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                   'certificate_sha256': hashlib.sha256((root / 'cert.pem').read_bytes()).hexdigest()}
        finally:
            cleanup_failed = False
            for name in reversed(containers):
                result = subprocess.run(['docker', 'rm', '-f', name], capture_output=True, text=True, timeout=30)
                cleanup_failed |= result.returncode != 0
            if cleanup_failed:
                raise RuntimeError('owned namespace cleanup refused')
