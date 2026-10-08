"""Keep one owned protocol fixture alive; publish inputs only in a private file."""
import json
import os
from pathlib import Path
import signal
import threading

from oidc_product_fixture import fixture


def main():
    os.umask(0o077)
    destination=Path(os.environ['ASTERIUS_FIXTURE_MANIFEST']).resolve()
    config_path=os.environ.get('ASTERIUS_FIXTURE_TENANT_CONFIG')
    config_extra=Path(config_path).read_text() if config_path else ''
    stopped=threading.Event()
    for signum in (signal.SIGINT,signal.SIGTERM):
        signal.signal(signum,lambda *_:stopped.set())
    owned=False
    try:
        with fixture(18444,'https://localhost:18445/callback','protocol-rp',hostname='localhost',
                     config_extra=config_extra,
                     automation_scopes=os.environ.get('ASTERIUS_FIXTURE_AUTOMATION_SCOPES','').split(),
                     readonly_paths=filter(None,os.environ.get('ASTERIUS_FIXTURE_READONLY_PATHS','').split(':'))) as source:
            # This file contains ephemeral credentials: never print its content
            # or commit it as evidence. Creation refuses an existing destination.
            document={key:value for key,value in source.items()
                      if key in ('issuer','secret','client_id','database','binary_sha256','runtime_revision')}
            document['ca_file']=str(source['root']/'ca.pem')
            document['config_path']=str(source['config_path'])
            with destination.open('x') as output:
                owned=True
                json.dump(document,output)
            print('PRODUCT_FIXTURE_READY',flush=True)
            stopped.wait()
    finally:
        if owned:destination.unlink(missing_ok=True)


if __name__=='__main__':
    main()
