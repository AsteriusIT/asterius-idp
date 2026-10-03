#!/usr/bin/env python3
"""Bounded DPoP control client for an explicitly provisioned disposable fixture."""
import base64
import hashlib
import json
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def sign(header, claims, key):
    unsigned = b64(json.dumps(header, separators=(",", ":")).encode()) + "." + b64(json.dumps(claims, separators=(",", ":")).encode())
    r, s = utils.decode_dss_signature(key.sign(unsigned.encode(), ec.ECDSA(hashes.SHA256())))
    return unsigned + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


class FixtureClient:
    def __init__(self, issuer, client_id, key_file, key_id, ca_file):
        self.issuer, self.client_id = issuer.rstrip("/"), client_id
        self.key = serialization.load_pem_private_key(open(key_file, "rb").read(), None)
        self.key_id = key_id
        self.dpop = ec.generate_private_key(ec.SECP256R1())
        n = self.dpop.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}
        self.context = ssl.create_default_context(cafile=ca_file)
        self.token, self.nonce = "", ""
        self.authenticate()

    def proof(self, method, url):
        claims = {"jti": secrets.token_urlsafe(24), "htm": method, "htu": url.split("?", 1)[0], "iat": int(time.time())}
        if self.token:
            claims["ath"] = b64(hashlib.sha256(self.token.encode()).digest())
        if self.nonce:
            claims["nonce"] = self.nonce
        return sign({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk}, claims, self.dpop)

    def authenticate(self):
        now = int(time.time())
        assertion = sign({"alg": "ES256", "typ": "JWT", "kid": self.key_id}, {"iss": self.client_id, "sub": self.client_id, "aud": self.issuer,
            "iat": now, "exp": now + 60, "jti": secrets.token_urlsafe(24)}, self.key)
        body = urllib.parse.urlencode({"client_id": self.client_id, "grant_type": "client_credentials", "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion, "scope": "admin.scim:read admin.scim:write", "resource": self.issuer + "/admin/api/v1"}).encode()
        status, _, result = self.request("POST", self.issuer + "/token", body, {"Content-Type": "application/x-www-form-urlencoded"})
        if status != 200 or result.get("token_type", "").lower() != "dpop":
            raise RuntimeError("fixture DPoP client credentials refused")
        self.token = result["access_token"]

    def request(self, method, url, body=None, headers=None, bearer=False):
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        for attempt in range(2):
            request_headers = {"Content-Type": "application/scim+json", **(headers or {})}
            if self.token:
                request_headers["Authorization"] = ("Bearer " if bearer else "DPoP ") + self.token
            if not bearer:
                request_headers["DPoP"] = self.proof(method, url)
            req = urllib.request.Request(url, body, request_headers, method=method)
            try:
                response = urllib.request.urlopen(req, context=self.context, timeout=20)
            except urllib.error.HTTPError as error:
                response = error
            data = response.read(65537)
            if len(data) > 65536:
                raise RuntimeError("fixture response bound exceeded")
            result = json.loads(data) if data else {}
            if response.status in (400, 401) and response.headers.get("DPoP-Nonce") and not bearer and attempt == 0:
                self.nonce = response.headers["DPoP-Nonce"]
                continue
            return response.status, response.headers, result
        raise RuntimeError("fixture DPoP nonce negotiation failed")
