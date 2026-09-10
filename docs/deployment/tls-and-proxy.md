# TLS, HSTS and the reverse proxy

FAPI 2.0 Security Profile §5.2 puts TLS on every endpoint, HSTS on every
browser-facing response, and a cipher-suite floor under both. Asterius
implements its half of that; the other half belongs to whatever terminates TLS
in front of it. This document says exactly which half is which, and it is
written for the person holding the proxy configuration.

Every claim below names the file and line that makes it true. Read them rather
than believing this page: a deployment guide that has drifted from the code is
worse than none.

- [1. The two transport modes](#1-the-two-transport-modes)
- [2. TLS versions and cipher suites](#2-tls-versions-and-cipher-suites)
- [3. Host, issuer and tenancy](#3-host-issuer-and-tenancy)
- [4. The client-certificate header](#4-the-client-certificate-header)
- [5. HSTS and the other headers the server emits](#5-hsts-and-the-other-headers-the-server-emits)
- [6. DPoP and the request URI](#6-dpop-and-the-request-uri)
- [7. The `/t/<tenant>` mount prefix](#7-the-ttenant-mount-prefix)
- [8. A complete nginx configuration](#8-a-complete-nginx-configuration)
- [9. The same thing in Caddy](#9-the-same-thing-in-caddy)
- [10. Verifying a deployment](#10-verifying-a-deployment)
- [11. What a proxy must never do](#11-what-a-proxy-must-never-do)

---

## 1. The two transport modes

`server.mode` has two values and there is no third
(`crates/server/src/config.rs:109-118`):

| Mode | What the process does | What must be in front |
| --- | --- | --- |
| `terminate_tls` | Owns the TLS listener: rustls, certificate and key from `[server.tls]` (`crates/server/src/http/server.rs:197-209`). | Nothing, or a TCP-level load balancer that does not terminate TLS. |
| `behind_proxy` | Speaks **cleartext HTTP** on `server.bind` (`crates/server/src/http/server.rs:188-196`). | A terminator you control, reachable only by that terminator. |

`behind_proxy` is the default (`crates/server/src/config.rs:541-547`), and the
comment there says why: `terminate_tls` without usable key material cannot start
at all, whereas a proxy that is not there shows up as a refused connection
rather than as cleartext on the wire.

The two modes are mutually exclusive at configuration time, not by convention:

- `[server.tls]` while `mode = "behind_proxy"` is a startup error
  (`crates/server/src/config.rs:1048-1057`) — that shape is usually a deployment
  that believes it is doing TLS and is not.
- `[server.proxy]` while `mode = "terminate_tls"` is a startup error
  (`crates/server/src/config.rs:1086-1095`): nothing is in front of the process
  to forward anything, so believing a forwarding header would be believing a
  client.
- `server.proxy.trusted_cidrs` may not be empty in `behind_proxy` mode
  (`crates/server/src/config.rs:1105-1113`). It defaults to
  `["127.0.0.0/8", "::1/128"]` (`crates/server/src/config.rs:664`), which is
  right for a proxy on the same host and wrong for everything else.

**`trusted_cidrs` is the single trust switch for this whole document.** The
client's address, the client's host and the client's *certificate* are all read
from headers only when the immediate TCP peer falls inside it
(`crates/server/src/http/forwarded.rs:37-42` and `:78`,
`crates/server/src/mtls.rs:277-279`). There is no second list and no per-header
override; `docs/configuration.md` §`[mtls]` explains why a second spelling would
be a second answer to "who is this server behind".

In `behind_proxy` mode the cleartext port must not be reachable by anyone but
the proxy. Bind it to the loopback (`server.bind = "127.0.0.1:9443"`) or to a
network only the proxy shares. A peer that reaches it *and* is inside
`trusted_cidrs` can assert any client address, any host and any client
certificate it likes.

---

## 2. TLS versions and cipher suites

This section applies to `terminate_tls`. In `behind_proxy` mode nothing here is
enforced by Asterius and the whole of §5.2.1–5.2.3 is the proxy's responsibility.

- **Versions offered: TLS 1.3 and TLS 1.2, nothing else**
  (`crates/server/src/http/tls.rs:17-18`). rustls has no TLS 1.0 or 1.1
  implementation, so the older versions are not a setting anyone can turn back
  on. `crates/server/tests/tls_handshake.rs:196` asserts the refusal on the
  wire, with `openssl s_client` as the client.
- **Cipher suites are written out explicitly** in
  `crates/server/src/http/tls.rs` rather than inherited from a provider default
  that may widen. Three TLS 1.3 suites; for TLS 1.2, exactly the four BCP 195
  recommends — ECDHE with AES-128-GCM or AES-256-GCM, in both the ECDSA and the
  RSA spelling.
- **ALPN offers `h2` then `http/1.1`** (`crates/server/src/http/tls.rs:91`), so
  a client cannot negotiate a protocol the server did not offer.
- There is no configuration key for either list, by design; see
  `docs/configuration.md` §`[server.tls]`.

> **Where the four-suite list comes from.** It is not §5.2.1, which only
> requires TLS 1.2 or later and BCP 195 in general. The binding clause is
> §5.2.2: on endpoints *not* used by web browsers, a server using TLS 1.2
> "shall only permit the cipher suites recommended in [BCP195]", and RFC 9325
> §4.2 recommends exactly `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`,
> `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`,
> `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` and
> `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`. §5.2.3 asks browser-facing endpoints
> for the wider set BCP 195 merely *allows*, and NOTE 1 there states the
> difference outright. Asterius serves the token endpoint and `/authorize` on
> one socket, so the stricter list governs the whole listener.
>
> ChaCha20-Poly1305 falls in the gap: allowed, not recommended. It was offered
> for TLS 1.2 until `ast-i6c`, because the module's tests asserted the BCP 195
> *properties* (AEAD, forward secrecy) rather than the enumeration, and a
> conformance probe asking for a TLS 1.2 ChaCha20 handshake got one. Both
> suites are now out of the TLS 1.2 offer and a test asserts the exact list.
> TLS 1.3 is not covered by either clause and keeps `TLS13_CHACHA20_POLY1305_SHA256`.

What the proxy must do when it terminates TLS:

- TLS 1.2 and 1.3 only. No TLS 1.0, 1.1 or SSLv3, and no renegotiation.
- For TLS 1.2, the four suites above and no others.
- A certificate chain that RFC 9525 name checking accepts for the issuer's host
  — the same host clients read out of the discovery document.

---

## 3. Host, issuer and tenancy

A tenant *is* an issuer, so "which host was this request for?" decides whose
keys sign the result (`crates/server/src/tenancy.rs:1-18`).

The host is resolved in this order
(`crates/server/src/http/forwarded.rs:72-102`, called from
`crates/server/src/tenancy.rs:312-318`):

1. If — and only if — the peer is inside `trusted_cidrs`: `Forwarded: host=…`
   (RFC 7239), preferred because it is the standardised spelling
   (`forwarded.rs:79` and `:105-119`).
2. Still only from a trusted peer: the **first** entry of `X-Forwarded-Host`,
   because a proxy chain appends and the first entry is what the client asked
   for (`forwarded.rs:82-92`).
3. Otherwise the HTTP/2 `:authority` from the request target, then the `Host`
   header (`forwarded.rs:94-101`).

The resolved host is then checked against the tenant
(`crates/server/src/tenancy.rs:404-412` and `:431-442`): it must equal the
authority of the tenant's `issuer`, or the tenant's `custom_host`. Anything else
is a 404 whose body is identical to "no such tenant", so the check cannot be
used to enumerate tenants (`crates/server/src/tenancy.rs:278-292`).

What that means for a proxy:

- **The host the server sees must be the public authority, including a
  non-default port.** `https://as.example:8443/t/demo` compares against
  `as.example:8443`. nginx's `$host` drops the port; `$http_host` keeps it.
  `crates/server/src/http/forwarded.rs:357-370` asserts that a port survives
  `Forwarded: host=`.
- **A proxy that rewrites `Host` to an internal name breaks everything** unless
  it also sends `X-Forwarded-Host` (or `Forwarded: host=`) carrying the public
  one. Symptom: every request is a 404 reading `not found`, and a debug log line
  `host does not belong to the resolved tenant` names both hosts
  (`crates/server/src/tenancy.rs:404-411`).
- **A client-supplied `Forwarded` or `X-Forwarded-Host` that reaches the server
  through a trusted proxy is believed.** The trust check is on the *peer*, not
  on who wrote the header. nginx and Caddy both pass unknown request headers
  through untouched, so the proxy must overwrite or delete both spellings. This
  is the easiest thing on this page to get wrong.
- The client *address* follows the same trust rule and is read right to left,
  skipping hops that are themselves inside `trusted_cidrs`
  (`crates/server/src/http/forwarded.rs:44-58`). It feeds rate limiting, login
  abuse protection and the audit trail, so appending to `X-Forwarded-For` rather
  than replacing it is safe — but only because of that right-to-left walk.

---

## 4. The client-certificate header

Only relevant with `[features] mtls = true`. With the flag off no header is read
and no certificate extension is inserted anywhere
(`crates/server/src/tenancy.rs:231-241` and `:344-353`).

- **Header name:** `x-client-cert` by default, configurable as
  `mtls.certificate_header` (`crates/server/src/mtls.rs:56-61`). The name is a
  deployment fact, not a protocol one.
- **Read only from a peer inside `trusted_cidrs`**, before any parsing happens
  (`crates/server/src/mtls.rs:277-279`). From any other peer the value is
  dropped unexamined; `crates/server/src/mtls.rs:437-451` is the test for that
  exact spoof, and `:469-484` asserts that an empty trust list believes nobody.
- **Encoding: three spellings, all accepted, all the same certificate**
  (`crates/server/src/mtls.rs:294-337`):
  - percent-encoded PEM — nginx's `$ssl_client_escaped_cert`;
  - PEM whose newlines the proxy replaced with a literal `\n` or with spaces;
  - bare base64 DER — HAProxy's `ssl_c_der,base64`, Caddy's
    `…certificate_der_base64` placeholder.

  A raw PEM block with real newlines is *not* among them and cannot be: RFC 9110
  §5.5 forbids a bare newline in a field value, which is why nginx escapes it in
  the first place.
- **Only the leaf travels.** Intermediates are never reconstructed from the
  header (`crates/server/src/mtls.rs:286-291`); a chain the server assembled
  from a string is not a chain the client sent. The leaf must therefore chain
  directly to one of that tenant's anchors — or the client uses the self-signed
  method (RFC 8705 §2.2), which needs no anchors at all.
- **An empty value is harmless**: it decodes to nothing and yields no
  certificate (`crates/server/src/mtls.rs:330-332`). A proxy that always sets
  the header, empty when no certificate was presented, is doing the right thing.
- **Size is bounded before decoding**, at four times the certificate limit
  (`crates/server/src/mtls.rs:63-70`, checked at `:281-283`), so an inflated
  header costs a length comparison and nothing else.
- **Verification is per tenant.** The leaf is checked against
  `mtls.trust_anchors.<tenant>` and nothing else; a tenant with no anchors
  cannot use the PKI method at all (`crates/server/src/mtls.rs:76-86` and
  `:180-201`). The public web CAs are never in scope.

### The one rule that matters

**The proxy must set this header unconditionally — including to an empty value —
so that an inbound copy from the client can never survive.** In `behind_proxy`
mode the proxy already decides which certificate the server sees, and that is a
documented trust root (`crates/server/src/mtls.rs:20-35`, and
`docs/threat-model.md`). What must not additionally be true is that *anyone on
the internet* decides it by sending the header themselves. Neither nginx nor
Caddy strips unknown request headers by default.

Have the proxy *request* but not *require* a client certificate: a client
authenticating with `private_key_jwt`, and every browser reaching `/authorize`,
must still be able to connect. Verification against the tenant's CAs happens
inside Asterius, so the proxy's own client-CA list is a filter for which
certificates get forwarded — not the trust decision.

---

## 5. HSTS and the other headers the server emits

Asterius sets these on **every** response, including JSON and redirects
(`crates/server/src/http/security_headers.rs:51-68`):

| Header | Value | Why |
| --- | --- | --- |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | FAPI 2.0 SP §5.2.3, TLS stripping (`security_headers.rs:21-27`). Asserted exactly by `crates/server/tests/transport.rs:132`. |
| `X-Content-Type-Options` | `nosniff` | An error body a browser decides to treat as script is cross-site scripting delivered by the 400 handler. |
| `X-Frame-Options` | `DENY` | Clickjacking a consent screen is the cheapest way to obtain a grant. |
| `Referrer-Policy` | `no-referrer` | A `Referer` on an authorization request leaks `state`, and on a pushed request a `request_uri`. |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` | Protocol endpoints are not a browsing context. |

Insertion is `entry`-style: a handler that already made a considered choice
keeps it (`security_headers.rs:56-66`). Two more things the server owns:

- **A nonce-based Content-Security-Policy on every HTML document**
  (`crates/web/src/csp.rs:307-330`): `default-src 'none'`, `script-src
  'nonce-…' 'strict-dynamic'`, `frame-ancestors 'none'`, `base-uri 'none'`. The
  nonce is fresh per response (CSP Level 3 §7.1,
  `crates/web/src/csp.rs:32-49`); ADR-0009 is the reasoning.
- **No CORS headers at any endpoint, ever.** There is no CORS layer to
  misconfigure, and `crates/server/tests/transport.rs:92-121` asserts that no
  `Access-Control-*` header appears — on a preflight, on a request carrying
  `Origin`, or on an error. FAPI 2.0 SP §5.2.3 requires that of the
  authorization endpoint; this deployment has no browser-based clients
  (ADR-0002), so it holds everywhere
  (`crates/server/src/http/dpop.rs:19-27`).
- **Every redirect is 303**, hard-coded, with a test that no other status can be
  produced (`crates/server/src/http/redirect.rs:17-19` and `:61-66`) — FAPI 2.0
  SP §5.3.2.2 items 10–11.

The proxy's job for all of this is to *do nothing*:

- Do not add `Strict-Transport-Security`. A proxy that adds its own produces two
  header lines; browsers vary in what they do with that, and a shorter
  `max-age` arriving second is a downgrade nobody intended.
- Do not add or rewrite `Content-Security-Policy`. A policy injected without the
  per-response nonce breaks the console (ADR-0009): page and policy stop
  agreeing and no script runs.
- Do not add `Access-Control-Allow-Origin` to be helpful.
- Do not rewrite 303 into 302 or 307. "Redirect normalisation" is not a feature
  to enable in front of an authorization server.
- Do not buffer or transform in a way that changes status codes. The server's
  own 413 (body over `server.request_body_limit_bytes`, 64 KiB by default) and
  408 (over `server.request_timeout_seconds`, 10 s) are the ones clients are
  meant to see (`crates/server/src/config.rs:549-556`).
- `X-Request-Id` from a client is ignored and replaced
  (`crates/server/src/http/request_id.rs:9`,
  `crates/server/tests/transport.rs:212`). A proxy may log the value the server
  returns; it must not expect the one it sent to come back.

---

## 6. DPoP and the request URI

RFC 9449 §4.3 requires the `htu` of a proof to be the URI of the request. The
usual deployment hazard is a proxy that changes scheme, host or path, so that
"the URI the client used" and "the URI the server saw" differ.

**Asterius does not have that hazard, by construction.** The expected URL is
built from the tenant's `issuer` and the endpoint
(`crates/server/src/http/dpop.rs:403`, `crates/oidc/src/metadata.rs:192`) — the
same string the discovery document publishes — and *never* from `Host`, from
`Forwarded`, or from the request target. The reasoning is written out at
`crates/server/src/http/dpop.rs:322-335`: if the comparison value came from a
header, an attacker who can set that header could make any `htu` match by asking
for it, and the check would compare an attacker's claim against the same
attacker's claim.

For the proxy this reduces to one sentence:

> **The public URL a client reaches must be byte-identical to the tenant's
> configured `issuer`** — scheme, host, port and path prefix.

- `https` only. A client that reached `http://` computed an `htu` that will
  never match, and will be told its proof is invalid rather than that its scheme
  was.
- No port juggling. If the issuer is `https://as.example` the public listener is
  on 443; if it is `https://as.example:8443` it is on 8443 *and* the host seen
  by Asterius carries the port (§3).
- No path rewriting (§7).

Serving the token endpoint on a different public hostname from the one in
`issuer` is not supported: the metadata document is the contract.

### The same rule, from the client's side

The two questions this produces from whoever is integrating a client behind
your proxy have the same answer, and it is the issuer:

- **What goes in the client assertion's `aud`?** The tenant's issuer
  identifier, as a JSON string — `https://localhost/t/demo`, not the token
  endpoint URL and not a one-element array (FAPI 2.0 SP §5.3.2.1 item 8,
  `crates/oidc/src/client_auth.rs`). Behind a proxy that is the *public*
  issuer, which is the whole reason §3 insists the configured issuer be the
  public name.
- **What goes in a DPoP proof's `htu`?** The public endpoint URL, derived from
  that same issuer.

There is one more refusal that looks like a proxy problem and is not: a client
whose registration carries a **`jwks_uri` on a loopback or private address**
can never authenticate, because the outbound guard of ADR-0006 refuses to
dereference it before any connection is attempted. This is common when the
client is a BFF running on the same machine as the stack. The fix is inline
`jwks` in the registration, not a proxy rule — and since `ast-4j1` the server
logs the refusal (`client JWK Set fetch failed`, with the address and the range
it falls in) at `warn` rather than `debug`, so it appears under the default
filter.

The full list of what a confidential client must send, and the `reason` values
this server logs when it refuses one, is
[`../integrating-a-confidential-client.md`](../integrating-a-confidential-client.md).

---

## 7. The `/t/<tenant>` mount prefix

A path-routed tenant is served under `/t/<tenant>`
(`crates/oidc/src/tenancy.rs:26`). The tenancy middleware strips that prefix
before routing, so handlers never learn that tenants exist, and then puts it
back into the request extensions as a `MountPrefix`
(`crates/server/src/tenancy.rs:195-226` and `:360`) so that any URL rendered to
a browser carries it again (`ast-295`).

Two ways a proxy breaks this:

1. **Stripping or rewriting the path.** `proxy_pass http://backend/;` in nginx —
   note the trailing slash — replaces the matched location with `/`, so
   `/t/demo/token` arrives as `/token`. That request is then either a 404, or
   worse resolves to a host-routed tenant with a different issuer. Write
   `proxy_pass http://backend;` with **no** trailing path.
2. **Adding a prefix.** Serving Asterius under `https://as.example/idp/` while
   the issuer says `https://as.example` means every rendered URL, every
   `Location` and every `htu` names a path the proxy does not have. If you want
   a prefix, it belongs in the issuer, not in the proxy.

The console's asset and redirect URLs are relative precisely so that the prefix
survives (`crates/server/src/http/console.rs:73-89` and `:113-131`). A proxy
that rewrites response bodies or `Location` headers undoes that work.

---

## 8. A complete nginx configuration

`mode = "behind_proxy"`, Asterius on the loopback at 9443, tenant `demo` with
`issuer = "https://as.example/t/demo"`, mTLS on. Every line is here for a reason
given above.

```nginx
# The certificate is forwarded only when the client actually presented one that
# nginx could parse; otherwise the variable is empty, which the server decodes
# as "no certificate" (crates/server/src/mtls.rs:330-332).
map $ssl_client_verify $asterius_client_cert {
    SUCCESS  $ssl_client_escaped_cert;
    default  "";
}

upstream asterius {
    server 127.0.0.1:9443;
    keepalive 32;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name as.example;

    ssl_certificate     /etc/asterius/tls/fullchain.pem;
    ssl_certificate_key /etc/asterius/tls/privkey.pem;

    # FAPI 2.0 SP §5.2.1: TLS 1.2 or 1.3 only ...
    ssl_protocols TLSv1.2 TLSv1.3;
    # ... and, for 1.2, only the four suites BCP 195 recommends (SP §5.2.2).
    # ChaCha20-Poly1305 is allowed but not recommended, so it stays out — the
    # same list the in-process listener offers; see §2.
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_tickets off;

    # mTLS: ask, never require. A browser at /authorize and a private_key_jwt
    # client must still connect. `optional_no_ca` forwards what the client sent
    # without nginx deciding whose CA is acceptable — that decision is per
    # tenant and it belongs to Asterius (crates/server/src/mtls.rs:180-201).
    # `ssl_client_certificate` names the CAs whose certificates nginx will
    # ask for by name. With `optional_no_ca` it is optional: a deployment with
    # no client-CA list omits the line, and what the client sent is still
    # forwarded. `deploy/compose/` is that case.
    ssl_client_certificate /etc/asterius/tls/client-cas.pem;
    ssl_verify_client optional_no_ca;
    ssl_verify_depth 3;

    # The server sets HSTS itself (security_headers.rs:27). Do not add one here.

    location / {
        proxy_pass http://asterius;   # no trailing slash: the path passes through
        proxy_http_version 1.1;

        # The public authority, with its port when it is not 443. $http_host
        # keeps the port; $host drops it.
        proxy_set_header Host              $http_host;
        proxy_set_header X-Forwarded-Host  $http_host;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto https;

        # STRIP. nginx passes unknown request headers through untouched, and the
        # server prefers RFC 7239 `Forwarded` over X-Forwarded-* whenever it is
        # present (crates/server/src/http/forwarded.rs:134-155). An empty value
        # means "do not send this header at all".
        proxy_set_header Forwarded "";

        # STRIP AND SET, unconditionally: an inbound X-Client-Cert from the
        # internet must never reach a server that trusts this peer.
        proxy_set_header X-Client-Cert $asterius_client_cert;

        # Optional, and only tidiness: the server generates its own and ignores
        # this one (crates/server/src/http/request_id.rs:9).
        proxy_set_header X-Request-Id "";

        proxy_buffering off;
        proxy_read_timeout 30s;
    }
}

# Port 80 exists only to send browsers to 443. It serves nothing else.
server {
    listen 80;
    listen [::]:80;
    server_name as.example;
    return 308 https://$host$request_uri;
}
```

Read line by line, four lines are load-bearing: `proxy_pass` without a trailing
slash (§7), `Host $http_host` (§3), `proxy_set_header Forwarded ""` (§3), and
`proxy_set_header X-Client-Cert $asterius_client_cert` (§4). Delete any one of
them and the deployment is wrong in a way nothing will tell you.

With this configuration `[server.proxy] trusted_cidrs` is
`["127.0.0.0/8", "::1/128"]` — the default — and Asterius must be bound to the
loopback.

`deploy/nginx/nginx.conf` is this file, running. The example compose stack
([`../../deploy/README.md`](../../deploy/README.md)) puts it in front of the
server with a self-signed certificate, and the only things it changes are
deployment facts: `server_name localhost`, an upstream on the compose network
rather than the loopback — which is why its `trusted_cidrs` is that network's
fixed subnet rather than the loopback — the certificate paths, and the omitted
`ssl_client_certificate` above. If the two ever have to disagree about a
*rule*, this page is what gets corrected first.

---

## 9. The same thing in Caddy

```caddy
as.example {
	tls /etc/asterius/tls/fullchain.pem /etc/asterius/tls/privkey.pem {
		protocols tls1.2 tls1.3
		# The four TLS 1.2 suites BCP 195 recommends (SP §5.2.2). Caddy names TLS 1.3
		# suites separately and offers all three of them by default.
		ciphers TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

		# Ask for a certificate; do not require one.
		client_auth {
			mode request
		}
	}

	reverse_proxy 127.0.0.1:9443 {
		# Caddy preserves the Host header and the full path by default, which
		# is what §3 and §7 need. Named explicitly so that it is a decision.
		header_up Host {http.request.host}
		header_up X-Forwarded-Host {http.request.host}

		# STRIP: Caddy does not touch a client-supplied RFC 7239 header, and
		# the server prefers it when present.
		header_up -Forwarded

		# STRIP AND SET, unconditionally. Empty when no certificate was
		# presented, which the server decodes as "none".
		header_up X-Client-Cert {http.request.tls.client.certificate_der_base64}
	}
}
```

Three notes before copying this:

1. `{http.request.host}` drops the port, as nginx's `$host` does. For a
   deployment whose issuer carries a non-default port use
   `{http.request.hostport}`, and check the result against §3's rule by fetching
   the discovery document (§10, check 3).
2. The certificate placeholder is version-dependent: recent Caddy exposes both
   `{http.request.tls.client.certificate_der_base64}` (bare base64 DER, which
   the server accepts) and `{http.request.tls.client.certificate_pem}` (PEM with
   real newlines, which cannot legally travel in a header). Confirm the name
   against your Caddy version; §10's check 5 is how you tell whether it worked.
3. Caddy sets `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`
   itself and, absent a `trusted_proxies` directive, does not preserve a
   client-supplied `X-Forwarded-For`. That is the behaviour this deployment
   wants. Do not add `trusted_proxies` unless there really is another proxy in
   front of Caddy.

Caddy adds HSTS only to responses it generates itself, not to proxied ones, so
§5's rule holds here without an extra directive.

---

## 10. Verifying a deployment

Run these from outside the deployment, against the public name. The `openssl`
and `curl` invocations were exercised against a local TLS listener while this
page was written; the expected outputs are what a correctly configured
deployment produces.

**1. TLS 1.3 and TLS 1.2 complete a handshake.**

```sh
echo Q | openssl s_client -connect as.example:443 -servername as.example -tls1_3 2>/dev/null | grep -E '^ *(Protocol|Cipher)'
echo Q | openssl s_client -connect as.example:443 -servername as.example -tls1_2 2>/dev/null | grep -E '^ *(Protocol|Cipher)'
```

Expect `Protocol : TLSv1.3` and `TLSv1.2` respectively, with an ECDHE AEAD
suite.

**2. TLS 1.1 is refused.**

```sh
echo Q | openssl s_client -connect as.example:443 -servername as.example -tls1_1 -cipher 'DEFAULT@SECLEVEL=0' 2>&1 | grep -E 'alert|Protocol *:'
```

Expect `tlsv1 alert protocol version` (alert 70). The `-cipher
'DEFAULT@SECLEVEL=0'` is not decoration: with a distribution OpenSSL 3.x a plain
`-tls1_1` fails client-side with `no protocols available` and never reaches the
server, which proves nothing about the server.

**3. HSTS is present and exact, and the issuer is the URL you fetched.**

```sh
curl -sS -D - -o /dev/null https://as.example/t/demo/.well-known/openid-configuration | grep -i '^strict-transport-security'
curl -sS https://as.example/t/demo/.well-known/openid-configuration | jq -r '.issuer, .authorization_endpoint, .token_endpoint'
```

Expect exactly one `strict-transport-security: max-age=31536000;
includeSubDomains; preload` line — two lines means the proxy is adding its own
(§5) — and an `issuer` that is character for character the prefix of the URL you
just fetched. If they differ, §3 and §6 are both broken and DPoP will fail.

**4. No CORS headers anywhere.**

```sh
curl -sS -D - -o /dev/null -X OPTIONS \
     -H 'Origin: https://attacker.example' \
     -H 'Access-Control-Request-Method: POST' \
     https://as.example/t/demo/authorize | grep -i '^access-control-'
```

Expect no output at all.

**5. An injected client-certificate header from outside is ignored.**

Take a certificate one of the tenant's CAs issued for a `tls_client_auth`
client, and try to authenticate with it *without presenting it in the
handshake*:

```sh
CERT=$(openssl x509 -in client.pem -outform DER | base64 -w0)
curl -sS -o /dev/null -w '%{http_code}\n' \
     -X POST https://as.example/t/demo/token \
     -H "X-Client-Cert: $CERT" \
     -d 'grant_type=client_credentials&client_id=demo-client&scope=api'
```

Expect **401** with `invalid_client` (`crates/oidc/src/client_auth.rs:156-164`):
the header travelled from your machine to the proxy, and the proxy overwrote it
with what the TLS handshake actually carried — nothing. A **200** means the
proxy is forwarding an attacker-controlled header, and any client of that tenant
can be impersonated by anyone who has seen their certificate. Stop and fix §4.

Repeat against the discovery document with
`-H 'X-Forwarded-Host: attacker.example'` and then with
`-H 'Forwarded: host=attacker.example'`: both must still return the real
tenant's metadata, and neither a 404 nor another tenant's document.

**6. The cleartext port is not reachable.**

From anywhere that is not the proxy host:

```sh
curl -sS --max-time 3 http://as.example:9443/t/demo/.well-known/openid-configuration
```

Expect a refused connection or a timeout. A JSON document here means the
`behind_proxy` listener is exposed, and every rule above can be bypassed by
talking to it directly (§1).

**7. The in-process listener, when you use `terminate_tls`.**

```sh
cargo nextest run -p asterius-server --test tls_handshake
```

performs checks 1 and 2 against a listener this repository starts itself, with
the same `openssl s_client` invocations. It skips when `openssl` is missing.

---

## 11. What a proxy must never do

- **Never forward a client-supplied `X-Client-Cert`** (or whatever
  `mtls.certificate_header` names). Set it unconditionally, empty when there is
  no certificate.
- **Never forward a client-supplied `Forwarded` or `X-Forwarded-Host`.** Both
  choose the tenant, and both are believed once the peer is trusted.
- **Never rewrite the path.** No trailing slash on nginx's `proxy_pass`, no
  `handle_path`, no prefix stripped or added: `/t/<tenant>` is part of the
  issuer.
- **Never rewrite `Host` to an internal name** without sending the public one in
  `X-Forwarded-Host`.
- **Never drop the port** from the host when the issuer carries one.
- **Never add, replace or duplicate** `Strict-Transport-Security`,
  `Content-Security-Policy`, `X-Frame-Options`, `Referrer-Policy` or any
  `Access-Control-*` header.
- **Never turn a 303 into a 302 or a 307**, and never "normalise" redirects.
- **Never terminate TLS below 1.2**, and never offer a TLS 1.2 suite outside the
  four in §2.
- **Never expose the cleartext `behind_proxy` port** to anything but the proxy.
- **Never list a CIDR in `trusted_cidrs` broader than the proxies you operate.**
  Everything on this page reduces to that one list.
- **Never rewrite response bodies**: the console's URLs and its CSP nonce are
  computed per response and do not survive a rewriting filter.

---

## See also

- [`../configuration.md`](../configuration.md) — `[server]`, `[server.tls]`,
  `[server.proxy]` and `[mtls]`, generated from the schema.
- [`../../deploy/README.md`](../../deploy/README.md) — the image, the example
  stack, upgrades.
- [`../integrating-a-confidential-client.md`](../integrating-a-confidential-client.md)
  — what a BFF or service must send to authenticate: PAR, `private_key_jwt`,
  the `aud` this server accepts, DPoP, inline `jwks` versus `jwks_uri`, and how
  to read a refusal out of the logs.
- [`kubernetes.md`](kubernetes.md) — the Helm chart: which of the rules on this
  page become Ingress annotations, and what the probes and the
  `PodSecurityContext` have to say.
- [`../threat-model.md`](../threat-model.md) — attacker A2 (the network), and
  the trust roots a proxy adds.
- [`../adr/0009-the-admin-console-is-a-first-party-same-origin-app.md`](../adr/0009-the-admin-console-is-a-first-party-same-origin-app.md)
  — why the console's CSP is nonce-based.
