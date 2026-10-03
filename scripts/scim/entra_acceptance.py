#!/usr/bin/env python3
"""Native Entra connection probe using explicitly authorized az CLI credentials.

Creates only its nonce-named application/SP and disabled jobs. Deletes them in a
finally block. Never starts a tenant synchronization job or assigns existing users.
"""
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dpop_fixture import FixtureClient

GRAPH = "https://graph.microsoft.com/v1.0"
TEMPLATE = "8adf8e6e-67b2-4cf2-a259-e3dc5476c621"


def run():
    if os.environ.get("ASTERIUS_ENTRA_ACCEPTANCE") != "1":
        raise RuntimeError("set ASTERIUS_ENTRA_ACCEPTANCE=1 only for an authorized cloud fixture")
    tenant = os.environ["ASTERIUS_ENTRA_TENANT"]
    if Path(os.environ["ASTERIUS_ENTRA_MANIFEST"]).exists():
        raise RuntimeError("recovery manifest already exists; resolve prior owned objects before another run")
    account = json.loads(subprocess.run(["az", "account", "show", "-o", "json"], check=True, capture_output=True, text=True).stdout)
    if account["tenantId"] != tenant or account["environmentName"] != "AzureCloud":
        raise RuntimeError("active Azure tenant/cloud differs from explicit fixture")
    issuer = os.environ["ASTERIUS_SCIM_ISSUER"]
    c = FixtureClient(issuer, os.environ["ASTERIUS_SCIM_CLIENT_ID"], os.environ["ASTERIUS_SCIM_SIGNING_KEY_FILE"],
                      os.environ["ASTERIUS_SCIM_SIGNING_KEY_ID"], os.environ["ASTERIUS_SCIM_CA_FILE"])
    prefix = issuer + "/admin/api/v1/scim/v2"
    os.umask(0o077)
    records, processes = [], []
    objects = None
    cleanup = []
    with tempfile.TemporaryDirectory(prefix="ast-entra-probe-") as directory:
        root = Path(directory)
        def graph(method, path, body=None, expected_error=False):
            cmd = ["az", "rest", "--method", method, "--url", GRAPH + path, "-o", "json"]
            if body is not None:
                body_file = root / "body.json"
                body_file.write_text(json.dumps(body))
                cmd += ["--body", "@" + str(body_file)]
            for attempt in range(6):
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
                transient = result.returncode != 0  # Directory replication can initially report several connector-specific errors.
                if not result.returncode or method not in ("GET", "DELETE") or not transient or attempt == 5:
                    break
                time.sleep(min(2 ** attempt, 8))
            # Never print Graph response diagnostics; connectors can echo secrets.
            if result.returncode:
                if expected_error:
                    return {"refused": True, "credential_validation_error": "CredentialValidationUnavailable" in result.stderr,
                            "upstream_401": "Unauthorized (401)" in result.stderr,
                            "upstream_404": "404 Not Found" in result.stderr}
                raise RuntimeError("Microsoft Graph operation failed; private diagnostics retained only until fixture cleanup")
            return json.loads(result.stdout) if result.stdout.strip() else {}
        try:
            port = int(os.environ.get("ASTERIUS_ENTRA_PROXY_PORT", "9481"))
            evidence = root / "requests.jsonl"
            proxy = subprocess.Popen([sys.executable, str(Path(__file__).with_name("entra_proxy.py")), "--upstream", prefix,
                "--ca-file", os.environ["ASTERIUS_SCIM_CA_FILE"], "--port", str(port), "--evidence", str(evidence)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(proxy)
            with open(root / "tunnel.log", "w+") as log:
                tunnel = subprocess.Popen([os.environ["ASTERIUS_CLOUDFLARED"], "tunnel", "--url", "http://127.0.0.1:"+str(port),
                    "--no-autoupdate", "--protocol", "http2"], stdout=log, stderr=log)
                processes.append(tunnel)
                endpoint = None
                for _ in range(60):
                    found = re.search(r"https://[a-z-]+\.trycloudflare\.com", (root / "tunnel.log").read_text())
                    if found:
                        endpoint = found[0] + urllib.parse.urlsplit(prefix).path
                        break
                    if tunnel.poll() is not None or proxy.poll() is not None:
                        raise RuntimeError("SCIM-only tunnel could not start")
                    time.sleep(1)
                if not endpoint:
                    raise RuntimeError("SCIM-only tunnel startup timed out")
                name = "ast-dd1y-6-1-" + secrets.token_hex(6)
                objects = graph("POST", "/applicationTemplates/"+TEMPLATE+"/instantiate", {"displayName": name})
                # Persist only owned IDs for recovery; no authentication material.
                manifest = Path(os.environ["ASTERIUS_ENTRA_MANIFEST"])
                manifest.write_text(json.dumps({k: {x: objects[k][x] for x in ("id", "displayName")} for k in ("application", "servicePrincipal")}, indent=2))
                sp = objects["servicePrincipal"]["id"]
                templates = graph("GET", "/servicePrincipals/"+sp+"/synchronization/templates")
                template_ids = [item["id"] for item in templates["value"]]
                for template in ("customappsso", "scim"):
                    if template not in template_ids:
                        raise RuntimeError("expected native provisioning template absent")
                    job = None
                    jobs_path = "/servicePrincipals/"+sp+"/synchronization/jobs"
                    for attempt in range(6):
                        try:
                            job = graph("POST", jobs_path, {"templateId": template})
                            break
                        except RuntimeError:
                            # Reconcile an uncertain create or asynchronous prior deletion
                            # before retrying this owned, disabled job mutation.
                            current = graph("GET", jobs_path)
                            wanted = "customappssoOutDelta" if template == "customappsso" else template
                            matches = [x for x in current["value"] if x["templateId"] == wanted]
                            if len(matches) == 1:
                                job = matches[0]
                                break
                            if attempt == 5:
                                raise
                            time.sleep(min(2 ** attempt, 8))
                    if job is None:
                        raise RuntimeError("owned disabled provisioning job could not be reconciled")
                    job_path = "/servicePrincipals/"+sp+"/synchronization/jobs/"+job["id"]
                    if job["schedule"]["state"] != "Disabled":
                        raise RuntimeError("disposable provisioning job unexpectedly enabled")
                    outcome = graph("POST", job_path+"/validateCredentials", {"credentials": [
                        {"key": "BaseAddress", "value": endpoint}, {"key": "SecretToken", "value": c.token}]}, expected_error=True)
                    records.append({"requested_template": template, "effective_template": job["templateId"], "job_disabled": True, **outcome})
                    graph("DELETE", job_path)
                requests = [json.loads(line) for line in evidence.read_text().splitlines()]
                native = [r for r in requests if r.get("authorization_scheme") == "Bearer" and not r.get("dpop_present") and r["status"] == 401]
                if not native or not records[-1].get("upstream_401"):
                    raise RuntimeError("native Bearer/DPoP incompatibility was not demonstrated")
        finally:
            for process in reversed(processes):
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            if objects:
                cleanup_failed = False
                for collection, key in (("servicePrincipals", "servicePrincipal"), ("applications", "application")):
                    obj = objects[key]
                    if not obj["displayName"].startswith("ast-dd1y-6-1-"):
                        raise RuntimeError("refusing cleanup of an object outside owned fixture")
                    try:
                        graph("DELETE", "/"+collection+"/"+obj["id"])
                        cleanup.append(collection)
                    except RuntimeError:
                        cleanup_failed = True
                if cleanup_failed:
                    raise RuntimeError("owned cloud cleanup incomplete; recovery IDs remain in ASTERIUS_ENTRA_MANIFEST")
                Path(os.environ["ASTERIUS_ENTRA_MANIFEST"]).unlink()
        print(json.dumps({"graph_version": "v1.0", "application_template": TEMPLATE,
            "available_templates": template_ids, "native_validation": records, "sanitized_requests": requests,
            "cleanup_deleted_owned_objects": cleanup, "lifecycle_after_native_auth_refusal": "not executed"}, indent=2))


if __name__ == "__main__":
    run()
