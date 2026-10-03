#!/usr/bin/env python3
"""Own real Chromium/WebAuthn fixture; no credential values in output."""
import json
import os
from pathlib import Path
import sys
import subprocess
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'integrations'))
from oidc_product_fixture import command, fixture
with fixture(9456, 'https://localhost:9457/callback', 'conditional-browser', hostname='localhost') as owned:
    path = owned['root'] / 'browser.json'
    path.write_text(json.dumps({'issuer':owned['issuer'],'client_id':owned['client_id'],
        'secret':owned['secret'],'database':owned['database'],
        'db_container':os.environ['ASTERIUS_ACCEPTANCE_DB_CONTAINER'],'tls_key':str(owned['root']/'key.pem'),'tls_certificate':str(owned['root']/'ca.pem')}))
    result = subprocess.run(['node',str(Path(__file__).with_name('browser_acceptance.mjs')),str(path)],capture_output=True,text=True,timeout=150)
    if result.returncode:
        stage = next((line for line in result.stderr.splitlines() if line.startswith('CONDITIONAL_BROWSER_STAGE=')), 'CONDITIONAL_BROWSER_STAGE=bootstrap')
        raise RuntimeError(stage)
    print(result.stdout.strip())
