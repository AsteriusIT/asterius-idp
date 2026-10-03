#!/usr/bin/env python3
"""Owned database/TLS fixture; real password console login and current reports."""
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'integrations'))
from oidc_product_fixture import fixture

os.umask(0o077)
with fixture(9480, 'https://localhost:9481/callback', 'governance-findings', hostname='localhost') as owned:
    payload = owned['root'] / 'findings.json'
    payload.write_text(json.dumps({
        'issuer': owned['issuer'], 'client_id': owned['client_id'], 'database': owned['database'],
        'db_container': os.environ['ASTERIUS_ACCEPTANCE_DB_CONTAINER'],
        'tls_key': str(owned['root'] / 'key.pem'), 'tls_certificate': str(owned['root'] / 'ca.pem'),
    }))
    payload.chmod(0o600)
    result = subprocess.run(['node', str(Path(__file__).with_name('acceptance.mjs')), str(payload)],
                            capture_output=True, text=True, timeout=180)
    if result.returncode:
        stage = next((line for line in result.stderr.splitlines()
                      if line.startswith('GOVERNANCE_FINDINGS_STAGE=')), 'GOVERNANCE_FINDINGS_STAGE=bootstrap')
        raise RuntimeError(stage)
    evidence = json.loads(result.stdout)
    evidence['binary_sha256'] = owned['binary_sha256']
    print(json.dumps(evidence))
