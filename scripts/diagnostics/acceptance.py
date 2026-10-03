#!/usr/bin/env python3
"""Real isolated HTTP correlation/evidence controls. Never prints credentials."""
import json
import pathlib
import re
import secrets
import subprocess
import sys
import time
import urllib.parse
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scim"))
from dpop_fixture import FixtureClient, sign

run, port, container, database = sys.argv[1:]
root = pathlib.Path(run)
issuer = f"https://127.0.0.1:{port}/t/admin"

class Client(FixtureClient):
    def __init__(self, resource, scopes, tenant_issuer=issuer):
        self.resource, self.scopes = resource, scopes
        super().__init__(tenant_issuer, "terraform-controller", root / "controller.pem", "provider-controller-1", root / "ca.pem")

    def authenticate(self):
        now = int(time.time())
        assertion = sign({"alg": "ES256", "typ": "JWT", "kid": self.key_id}, {"iss": self.client_id, "sub": self.client_id, "aud": self.issuer, "iat": now, "exp": now + 60, "jti": secrets.token_urlsafe(24)}, self.key)
        body = urllib.parse.urlencode({"client_id": self.client_id, "grant_type": "client_credentials", "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": assertion, "scope": self.scopes, "resource": self.resource}).encode()
        status, _, result = self.request("POST", self.issuer + "/token", body, {"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 200 and result.get("token_type", "").lower() == "dpop", "independent DPoP fixture credentials"
        self.token = result["access_token"]

pdp = Client(issuer + "/access/v1/evaluation", "authzen.evaluate")
admin = Client(issuer + "/admin/api/v1", "admin.audit:read")
api = issuer + "/admin/api/v1"
request = {"subject": {"type": "user", "id": "nonexistent-fixture-subject"}, "action": {"name": "read"}, "resource": {"type": "document", "id": "fixture-document"}}
status, headers, decision = pdp.request("POST", pdp.resource, request, {"Content-Type": "application/json", "X-Request-ID": "caller-owned-echo", "X-Asterius-Request-ID": "caller-spoof"})
assert status == 200 and decision["decision"] is False, "real denial"
assert "diagnostics" not in decision and "diagnostic" not in decision, "public wire shape"
assert headers["X-Request-ID"] == "caller-owned-echo", "AuthZEN echo"
reference = headers["X-Asterius-Request-ID"]
assert re.fullmatch("[0-9a-f]{32}", reference) and reference != "caller-spoof", "server support reference"
status, _, page = admin.request("GET", api + "/audit/events?request_id=" + reference)
assert status == 200 and len(page["items"]) == 1, "tenant-scoped correlation"
event_id = page["items"][0]["id"]
assert page["items"][0]["request_id"] == reference
status, _, event = admin.request("GET", api + f"/audit/events/{event_id}")
assert status == 200 and event["diagnostic"]["status"] == "recorded", "historical evidence"
snapshot = event["diagnostic"]["snapshot"]
assert snapshot["enforcement_point"] == "access_evaluation", "actual enforcement-point provenance"
assert snapshot["policy_revision"].startswith("sha256:") and snapshot["rules"][0]["conditions"][0]["missing"], "actual revision and missing-context outcome"
assert "country" not in json.dumps(snapshot) and "nonexistent-fixture-subject" not in json.dumps(snapshot), "no context names/input values"
status, _, empty = admin.request("GET", api + "/audit/events?request_id=" + reference + "&grant=00000000-0000-0000-0000-000000000000&limit=1")
assert status == 200 and empty["items"] == [], "conjunctive paged filters"
status, _, _ = admin.request("GET", api + "/audit/events?request_id=caller-spoof")
assert status == 400, "reference syntax bound"
status, _, _ = pdp.request("GET", api + f"/audit/events/{event_id}")
assert status in (401, 403), "unauthorized evidence refusal"
status, _, _ = admin.request("GET", f"https://127.0.0.1:{port}/t/e2e/admin/api/v1/audit/events/{event_id}")
assert status in (401, 403, 404), f"cross-tenant credential refusal ({status})"
foreign_issuer = f"https://127.0.0.1:{port}/t/e2e"
foreign = Client(foreign_issuer + "/admin/api/v1", "admin.audit:read", foreign_issuer)
status, _, own_page = foreign.request("GET", foreign.resource + "/audit/events?limit=1")
assert status == 200 and "items" in own_page, "foreign credential can read its own audit route"
status, _, _ = foreign.request("GET", foreign.resource + f"/audit/events/{event_id}")
assert status == 404, "authorized foreign tenant cannot probe another tenant's event or evidence"


def sql(statement):
    subprocess.run(["docker", "exec", container, "psql", "-U", "asterius", "-d", database, "-v", "ON_ERROR_STOP=1", "-c", statement], check=True, stdout=subprocess.DEVNULL)

sql("update tenant_policies set document='{\"version\":1,\"rules\":[]}'::jsonb,updated_at=now() where tenant_id='admin';")
status, _, same = admin.request("GET", api + f"/audit/events/{event_id}")
assert status == 200 and same["diagnostic"]["snapshot"] == snapshot, "snapshot cannot be reconstructed from current policy"
sql("update authorization_diagnostics set diagnostics=jsonb_set(diagnostics,'{rules,0,matched}','true'::jsonb) where tenant_id='admin';")
status, _, altered = admin.request("GET", api + f"/audit/events/{event_id}")
assert status == 200 and altered["diagnostic"]["status"] == "unavailable" and altered["diagnostic"]["reason"] == "integrity_mismatch" and "snapshot" not in altered["diagnostic"], "immutable audit digest rejects altered evidence"
sql("update authorization_diagnostics set created_at=now()-interval '8 days',expires_at=now()-interval '1 day' where tenant_id='admin';")
status, _, missing = admin.request("GET", api + f"/audit/events/{event_id}")
assert status == 200 and missing["diagnostic"]["status"] == "unavailable" and "snapshot" not in missing["diagnostic"], "expired stored evidence is unreadable even before sweep"
sql("delete from authorization_diagnostics where expires_at<=now();")
status, _, removed = admin.request("GET", api + f"/audit/events/{event_id}")
assert status == 200 and removed["diagnostic"]["status"] == "unavailable", "event survives evidence retention"
print("Real HTTP diagnostics acceptance PASS: denial, immutable snapshot, missing facts, header anti-spoofing, wire compatibility, paging, expiry and access boundaries")
