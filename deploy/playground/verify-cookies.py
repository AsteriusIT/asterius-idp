#!/usr/bin/env python3
"""Exercise the real gateway cookie boundary with owned Docker HTTP fixtures.

Uses dummy credentials only. Requires cached images; never pulls images or
contacts the IdP. The gateway runs its exact supplied config as UID 101 with a
read-only root and /tmp tmpfs. Every owned container/network is removed.
"""
import argparse
import http.cookies
import json
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request
import uuid

NGINX_IMAGE = "nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de"
BACKEND_IMAGE = "python:3.13-alpine3.20"
BACKEND = r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"cookie": self.headers.get("Cookie"), "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
ThreadingHTTPServer(("0.0.0.0", 80), Handler).serve_forever()
'''


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True, stderr=subprocess.PIPE).strip()


def read_response(base, path, cookies=""):
    request = urllib.request.Request(base + path, headers={"Cookie": cookies})
    with urllib.request.urlopen(request, timeout=3) as response:
        if response.status != 200:
            raise AssertionError(f"Unexpected gateway response {response.status}")
        return json.load(response)


def nonempty_cookies(header):
    parsed = http.cookies.SimpleCookie()
    parsed.load(header or "")
    # Nginx emits fixed cookie names with empty values when the app has no
    # cookies. Only nonempty values could forward credential material.
    return {name: value.value for name, value in parsed.items() if value.value}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("nginx.conf"))
    parser.add_argument("--nginx-image", default=NGINX_IMAGE)
    parser.add_argument("--backend-image", default=BACKEND_IMAGE)
    args = parser.parse_args()
    config = args.config.resolve(strict=True)
    if not config.is_file():
        raise ValueError("Gateway config must be a file")
    # Fail before creating resources if required cached images are unavailable.
    docker("image", "inspect", args.nginx_image)
    docker("image", "inspect", args.backend_image)
    suffix = uuid.uuid4().hex[:12]
    network = "asterius-cookie-check-" + suffix
    backend = network + "-backend"
    gateway = network + "-gateway"
    controls = []
    try:
        docker("network", "create", network)
        docker("run", "--detach", "--pull=never", "--name", backend, "--network", network,
               "--network-alias", "demo-a", "--network-alias", "demo-b",
               "--network-alias", "financial-api", "--network-alias", "financial-web",
               "--network-alias", "protocol-lab", "--read-only", "--cap-drop=ALL",
               "--security-opt", "no-new-privileges", args.backend_image, "python", "-c", BACKEND)
        docker("run", "--detach", "--pull=never", "--name", gateway, "--network", network,
               "--user", "101:101", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,mode=1777",
               "--cap-drop=ALL", "--security-opt", "no-new-privileges",
               "--publish", "127.0.0.1::8080", "--mount", f"type=bind,src={config},dst=/etc/nginx/nginx.conf,readonly",
               "--entrypoint", "nginx", args.nginx_image, "-g", "daemon off;")
        port = docker("port", gateway, "8080/tcp").rsplit(":", 1)[1]
        base = "http://127.0.0.1:" + port
        for attempt in range(50):
            try:
                read_response(base, "/demo-a/probe")
                break
            except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                if attempt == 49:
                    raise RuntimeError("Owned gateway/backend HTTP readiness failed") from None
                time.sleep(0.1)
        opener = urllib.request.build_opener(NoRedirect())
        for path in ('/demo-a', '/demo-b', '/financial', '/financial-api', '/protocols', '/playground/setup'):
            request = urllib.request.Request(base + path, headers={
                'Host': 'playground.example:8446', 'X-Forwarded-Proto': 'https',
            })
            try:
                response = opener.open(request, timeout=3)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                if response.code != 308 or response.headers.get('Location') != path + '/':
                    raise AssertionError(f'Gateway exposed internal redirect authority for {path}')
                if response.headers.get('Cache-Control') != 'no-store':
                    raise AssertionError(f'Gateway allows cached slash redirect for {path}')
            controls.append('relative-redirect:' + path)
        app_cookies = {
            "asterius_playground_demo_a": "dummy-demo-a-session",
            "asterius_playground_demo_a_login": "dummy-demo-a-login",
            "asterius_playground_demo_b": "dummy-demo-b-session",
            "asterius_playground_demo_b_login": "dummy-demo-b-login",
            "asterius_playground_financial": "dummy-financial-session",
            "asterius_playground_financial_login": "dummy-financial-login",
            "asterius_protocol_lab": "dummy-protocol-session",
        }
        other_cookies = {
            "__Host-asterius_session": "dummy-idp-admin-session",
            "__Host-asterius_interaction": "dummy-idp-interaction",
            "asterius_session": "dummy-old-general-session",
            "financial_session": "dummy-old-financial-session",
            "asterius_playground_demo_a_other": "dummy-prefix-collision",
        }
        mixed = "; ".join(f"{key}={value}" for key, value in {**other_cookies, **app_cookies}.items())
        idp_only = "; ".join(f"{key}={value}" for key, value in other_cookies.items())
        cases = [
            ("/demo-a/callback?probe=1", "/demo-a/callback?probe=1", ["asterius_playground_demo_a", "asterius_playground_demo_a_login"]),
            ("/demo-b/callback?probe=1", "/demo-b/callback?probe=1", ["asterius_playground_demo_b", "asterius_playground_demo_b_login"]),
            ("/financial-api/auth/callback?probe=1", "/auth/callback?probe=1", ["asterius_playground_financial", "asterius_playground_financial_login"]),
            ("/protocols/status?probe=1", "/status?probe=1", ["asterius_protocol_lab"]),
            ("/financial/index.html?probe=1", "/financial/index.html?probe=1", []),
        ]
        for path, forwarded_path, names in cases:
            result = read_response(base, path, mixed)
            expected = {name: app_cookies[name] for name in names}
            if nonempty_cookies(result["cookie"]) != expected:
                raise AssertionError(f"Mixed cookie boundary failed for {path.split('?')[0]}")
            if result["path"] != forwarded_path:
                raise AssertionError(f"Proxy path contract failed for {path.split('?')[0]}")
            if not names and result["cookie"] is not None:
                raise AssertionError("Static financial backend received a Cookie header")
            controls.append("mixed-cookie-boundary:" + path.split("?")[0])
            result = read_response(base, path, idp_only)
            if nonempty_cookies(result["cookie"]):
                raise AssertionError(f"IdP/legacy cookie leaked to {path.split('?')[0]}")
            if not names and result["cookie"] is not None:
                raise AssertionError("Static financial backend received an IdP-only Cookie header")
            controls.append("idp-legacy-refusal:" + path.split("?")[0])
        print(json.dumps({"passed": len(controls), "controls": controls, "real_http": True,
                          "gateway_uid": 101, "read_only": True, "dummy_cookies_only": True}))
    finally:
        for name in (gateway, backend):
            subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        subprocess.run(["docker", "network", "rm", network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        # Verify cleanup rather than merely assuming removal succeeded.
        for name in (gateway, backend):
            found = docker("container", "ls", "--all", "--filter", "name=^/" + name + "$", "--format", "{{.Names}}")
            if found:
                raise RuntimeError("Owned cookie-check container cleanup failed")
        remaining = docker("network", "ls", "--filter", "name=^" + network + "$", "--format", "{{.Name}}")
        if remaining:
            raise RuntimeError("Owned cookie-check network cleanup failed")


if __name__ == "__main__":
    main()
