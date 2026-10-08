"""Privacy of metrics from encrypted/clear JWT wire envelopes."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.argv.append('/unused-private-config')
spec=importlib.util.spec_from_file_location('relay',Path(__file__).with_name('protocol_peer_relay.py'))
relay=importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class Metrics(unittest.TestCase):
    def test_ciphertext_only_header_projection(self):
        header={'alg':'RSA-OAEP-256','enc':'A256GCM','kid':'PRIVATE-CANARY','extra':'PRIVATE-CANARY'}
        encoded=base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        projected=relay.envelope(encoded+'.private-key.private-iv.private-ciphertext.private-tag')
        self.assertEqual(projected,{'segments':5,'alg':'RSA-OAEP-256','enc':'A256GCM'})
        self.assertNotIn('private',json.dumps(projected).lower())
        self.assertNotIn('CANARY',json.dumps(projected))

    def test_untrusted_algorithm_is_not_logged(self):
        encoded=base64.urlsafe_b64encode(json.dumps({'alg':'SECRET-CANARY'}).encode()).decode().rstrip('=')
        self.assertEqual(relay.envelope(encoded+'.payload.signature'),{'segments':3,'alg':'other','enc':'other'})


if __name__=='__main__':
    unittest.main(argv=[sys.argv[0]])
