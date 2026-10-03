#!/usr/bin/env python3
"""SCIM-only native provisioner probe; forwards authentication unchanged.

The proxy records only scheme/proof presence/status, never header values or bodies.
It cannot make a Bearer request into a DPoP-authenticated request.
"""
import argparse
import http.client
import http.server
import json
import ssl
import urllib.parse


def serve(upstream, ca_file, port, evidence):
    parsed = urllib.parse.urlsplit(upstream)
    if parsed.scheme != "https" or parsed.hostname not in ("127.0.0.1", "localhost"):
        raise ValueError("probe upstream must be a local HTTPS fixture")
    prefix = parsed.path.rstrip("/")
    if not prefix.endswith("/admin/api/v1/scim/v2"):
        raise ValueError("probe upstream must select only the SCIM base")
    context = ssl.create_default_context(cafile=ca_file)

    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(20)

        def log_message(self, *args):
            pass  # HTTP logs can include query attributes; evidence below is bounded.

        def handle_request(self):
            path = urllib.parse.urlsplit(self.path)
            allowed = ("Users", "Groups", "ServiceProviderConfig", "Schemas", "ResourceTypes")
            segments = path.path.split("/")
            if (not path.path.startswith(prefix + "/") or len(segments) < 2
                    or path.path[len(prefix)+1:].split("/")[0] not in allowed
                    or "%" in path.path or ".." in segments or len(self.path) > 4096):
                with open(evidence, "a", encoding="utf-8") as log:
                    log.write(json.dumps({"method": self.command, "boundary": "denied", "path_shape": "/".join(s if s in ("", "t", "e2e", "admin", "api", "v1", "scim", "v2", *allowed, *[x.lower() for x in allowed]) else "[redacted]" for s in segments), "status": 404}) + "\n")
                self.send_error(404)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if not 0 <= size <= 65536 or self.headers.get("Transfer-Encoding"):
                self.send_error(413)
                return
            body = self.rfile.read(size)
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() in ("authorization", "dpop", "content-type", "accept", "if-match")}
            scheme = self.headers.get("Authorization", "").split(" ", 1)[0]
            try:
                conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, context=context, timeout=20)
                conn.request(self.command, self.path, body=body, headers=headers)
                response = conn.getresponse()
                payload = response.read(65537)
                if len(payload) > 65536:
                    raise ValueError("fixture response too large")
                self.send_response(response.status)
                for name in ("Content-Type", "ETag", "WWW-Authenticate", "DPoP-Nonce"):
                    value = response.getheader(name)
                    if value:
                        self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                with open(evidence, "a", encoding="utf-8") as log:
                    log.write(json.dumps({"method": self.command, "resource": path.path[len(prefix)+1:].split("/")[0],
                        "authorization_scheme": scheme if scheme in ("Bearer", "DPoP") else "other",
                        "dpop_present": bool(self.headers.get("DPoP")), "status": response.status}) + "\n")
                conn.close()
            except (OSError, ValueError, http.client.HTTPException):
                self.send_error(502, "isolated fixture unavailable")

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request

    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--port", type=int, default=9481)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    serve(args.upstream, args.ca_file, args.port, args.evidence)
