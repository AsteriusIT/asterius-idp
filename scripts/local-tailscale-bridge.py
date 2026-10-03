#!/usr/bin/env python3
"""Loopback-only development bridge from private Tailscale Serve to verified TLS ingress.

Serve handles public HTTPS. The ingress keeps its existing certificate and TLS
identity; HTTP Host selects the explicitly configured canonical tenant issuer.
No authentication identity is inferred from proxy headers.
"""
import argparse
import http.client
import http.server
import ssl

HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade"}


def upstream_headers(headers, canonical_host):
    connection_tokens = {v.strip().lower() for v in headers.get("Connection", "").split(",")}
    result = {}
    for name, value in headers.items():
        lower = name.lower()
        if lower in HOP_HEADERS | connection_tokens or lower == "host":
            continue
        if (lower == "forwarded" or lower.startswith("x-forwarded-")
                or lower.startswith("tailscale-") or lower.startswith("x-tailscale-")
                or lower in {"x-client-cert", "x-ssl-cert", "x-ssl-client-cert",
                             "ssl-client-cert", "x-real-ip"}):
            continue
        result[name] = value
    result["Host"] = canonical_host
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canonical-host", required=True)
    parser.add_argument("--upstream-tls-host", required=True)
    parser.add_argument("--upstream-port", type=int, default=443)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--port", type=int, default=9475)
    options = parser.parse_args()
    tls = ssl.create_default_context(cafile=options.ca_file)

    class Bridge(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # Request URLs and credentials must never enter local logs.

        def proxy(self):
            if self.headers.get("Host", "").lower() not in {
                    options.canonical_host, options.canonical_host + ":443"}:
                self.send_error(421, "Unexpected canonical host")
                return
            if self.headers.get("Transfer-Encoding"):
                self.send_error(400, "Explicit body length required")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400, "Invalid body length")
                return
            if length < 0 or length > 2 * 1024 * 1024:
                self.send_error(413, "Body exceeds local bridge bound")
                return
            connection = http.client.HTTPSConnection(
                options.upstream_tls_host, options.upstream_port, context=tls, timeout=30)
            try:
                connection.request(self.command, self.path, self.rfile.read(length),
                                   upstream_headers(self.headers, options.canonical_host))
                response = connection.getresponse()
                body = response.read(64 * 1024 * 1024 + 1)
                if len(body) > 64 * 1024 * 1024:
                    raise ValueError("Response exceeds local bridge bound")
                self.send_response(response.status)
                connection_tokens = {v.strip().lower() for v in
                                     (response.getheader("Connection") or "").split(",")}
                for name, value in response.getheaders():
                    if name.lower() not in HOP_HEADERS | connection_tokens | {"content-length"}:
                        self.send_header(name, value)
                declared_length = response.getheader("Content-Length")
                self.send_header("Content-Length", declared_length if
                                 self.command == "HEAD" and declared_length else str(len(body)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (OSError, ValueError, http.client.HTTPException):
                self.send_error(502, "Local verified ingress unavailable")
            finally:
                connection.close()

        do_GET = proxy
        do_HEAD = proxy
        do_POST = proxy
        do_PUT = proxy
        do_PATCH = proxy
        do_DELETE = proxy
        do_OPTIONS = proxy

    http.server.ThreadingHTTPServer(("127.0.0.1", options.port), Bridge).serve_forever()


if __name__ == "__main__":
    main()
