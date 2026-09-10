# Integrating a confidential client (BFF, service, daemon)

This server is FAPI 2.0 only. That is one design decision with a long tail of
consequences for a client, and every one of them shows up as the same four
words if you get it wrong: `401 invalid_client`.

This page is the list of what a confidential client — a back-end-for-frontend,
a service, anything holding a key — has to send. It is written against the code
rather than from memory; the file that decides each rule is named beside it, so
that a disagreement between this page and the server can be settled without
guessing.

## 0. The three things that are not optional

| | Why |
| --- | --- |
| **PAR for every authorization request** | ADR-0002. `/authorize` accepts a `request_uri` and nothing else. `require_pushed_authorization_requests: false` in a registration is *refused*, not downgraded. |
| **`private_key_jwt` or mTLS for client authentication** | FAPI 2.0 SP §5.3.2.1 item 6. There is no `client_secret_basic` and no `client_secret_post`. A client with a shared secret cannot authenticate here at all. |
| **A sender-constrained access token** | FAPI 2.0 SP §5.3.2.1. `dpop_bound_access_tokens` defaults to `true` for a registration that says nothing, so a DPoP proof is required at the token endpoint. |

If your client library was configured for a plain OIDC provider, all three of
these are things it is probably not doing.

## 1. Where the endpoints are, and what `aud` must say

Everything is under the tenant's issuer. Read it, do not construct it:

```
GET https://<host>/t/<tenant>/.well-known/openid-configuration
```

The `issuer` field of that document is the single value your client assertions
must name. For the example compose stack that is `https://localhost/t/demo`
(and `https://localhost/t/admin` for the reserved admin tenant), which is also
what `deploy/compose/asterius.toml` configures — behind nginx the issuer is the
**public** name, not the container's.

> **`aud` is the issuer identifier, as a JSON string.**
>
> Not the token endpoint URL. Not the PAR endpoint URL. Not a one-element
> array containing the issuer.
>
> `crates/oidc/src/client_auth.rs`, `Audiences::issuer_only` and
> `Audiences::accepts`.

Both halves of that are deliberate and both bite real clients:

* **The value.** OIDC Core §9 historically also allowed the token endpoint's
  URL, and a great deal of client software still sends it. FAPI 2.0 SP
  §5.3.2.1 item 8 withdraws that. An assertion is a bearer credential for
  whatever audience it names, so accepting several spellings of "this server"
  would make an assertion minted for one endpoint replayable at another.
* **The form.** `"aud": ["https://localhost/t/demo"]` is refused even though
  its contents are right. An array lets a client mint one assertion naming
  this server *and* somebody else; a hostile audience could then forward it
  here and be authenticated as that client. Refusing the shape removes the
  possibility instead of checking for it.

The one exception is the CIBA backchannel authentication endpoint, which its
own specification (CIBA Core 1.0 §7.1) requires to accept the token endpoint
and backchannel endpoint URLs as well. Nothing else does.

## 2. The client assertion

Two form parameters, on the PAR request and again on the token request:

```
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<the JWT below>
```

Compared byte for byte — `client_assertion_type` is a fixed protocol constant
(RFC 7521 §4.2), not a URL that gets normalised. Sending one of the two without
the other is `invalid_request`, not `invalid_client`: a client that sends half
a credential thinks it authenticated.

### Header

```json
{ "alg": "ES256", "kid": "bff-2026-01", "typ": "client-authentication+jwt" }
```

* `alg` — `EdDSA`, `ES256` or `PS256`. Nothing else, and never `none`.
  (`SigningAlgorithm::ALL`.)
* `kid` — publish one. It is optional in the sense that a set with a single
  key still resolves, but it is what lets you rotate without an outage, and
  its absence is a common cause of "the signature did not verify" on the day
  a second key appears.
* `typ` — optional. Accepted: absent, `JWT`, `client-authentication+jwt`
  (RFC 8725 §3.11), `jwt-bearer`. Anything else is refused, because an access
  token presented as a client assertion is not a spelling difference.

### Claims

```json
{
  "iss": "c.qfxp0uEJeuyW2hD_g-dypQ",
  "sub": "c.qfxp0uEJeuyW2hD_g-dypQ",
  "aud": "https://localhost/t/demo",
  "jti": "01J8Z2N4R5S6T7V8W9X0Y1Z2A3",
  "iat": 1760000000,
  "exp": 1760000180
}
```

* `iss` and `sub` — **both** the `client_id`. They are not redundant: an
  assertion where they differ is one party vouching for another, which is a
  different protocol.
* `aud` — §1 above.
* `jti` — unique, and **single-use within its validity window**. The server
  remembers it until `exp` and refuses the second presentation. Reusing one
  assertion for the PAR call and then the token call fails on the second.
  Maximum 255 characters.
* `exp` — at most 10 minutes out (`DEFAULT_MAX_ASSERTION_LIFETIME`; a tenant
  may shorten it, never lengthen it). A longer one is refused rather than
  clamped, because a year-long assertion is a `jti` this server must remember
  for a year.
* `iat` / `nbf` — may be at most 10 seconds in the future by default, 60 at
  the widest a policy may be set to (FAPI 2.0 SP §5.3.2.1 item 13). **Check
  the clock in your container.** A BFF whose host clock has drifted a minute
  fails here and the failure looks like a key problem.

The `client_id` form parameter is permitted alongside the assertion (RFC 7521
§4.2). If you send it, it must equal `sub`; disagreeing means the request names
two clients and is refused before either is looked up.

## 3. Where the server gets your public key

Your registration carries either inline `jwks` or a `jwks_uri`. This is not a
matter of taste for a locally-hosted client.

> **A `jwks_uri` on a loopback, private or otherwise non-public address is
> refused, always.**
>
> `crates/server/src/outbound/ssrf.rs`, and ADR-0006.

The outbound guard resolves the host and refuses `127.0.0.0/8`, `::1`,
RFC 1918 space, link-local, unique-local, anything outside IPv6 global unicast,
and hosts that are not public DNS names. It runs *before* a connection is
attempted, so there is nothing to whitelist and no timeout to wait out. It is
an SSRF control, not a bug: without it, a client registration would be a way to
make this server issue requests to its own network.

The consequence for a BFF you are developing on your laptop:
`"jwks_uri": "https://localhost:8080/jwks.json"` means **your client can never
authenticate**. The server will refuse to fetch it every time and answer
`invalid_client` every time.

Two ways out, in order of preference:

1. **Inline `jwks`.** Put the public JWK Set in the registration. Nothing is
   fetched, nothing can be refused, and for a client whose keys change on a
   deploy rather than on a schedule this is simply the right shape.

   ```json
   {
     "client_name": "shop BFF",
     "token_endpoint_auth_method": "private_key_jwt",
     "require_pushed_authorization_requests": true,
     "redirect_uris": ["https://localhost:8080/bff/callback"],
     "grant_types": ["authorization_code", "refresh_token"],
     "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "kid": "bff-2026-01", "x": "…", "y": "…" } ] }
   }
   ```

   The set must be public material only — a `d` component anywhere in it and
   the whole set is refused as a disclosure, not as a parse error.

2. **A non-loopback host the server can actually reach.** Inside the compose
   network, a service name resolving to a container address is *still* private
   space and still refused. This route means a genuinely public DNS name.

## 4. DPoP

RFC 9449. One proof per request, signed by the client's *DPoP* key — which is
not the client-assertion key and should not be.

* **Token endpoint: required.** `dpop_bound_access_tokens` defaults to `true`
  here, so a token request without a proof is refused for a client that never
  mentioned the setting (`crates/server/src/http/issuance.rs`,
  `SenderConstraint::confirmation`).
* **PAR: optional but recommended.** RFC 9449 §10.1 — either a proof or the
  `dpop_jkt` form parameter binds the eventual token to your key from the very
  first request. It is checked before the body is read, so a proof that does
  not verify fails the push.
* **Userinfo and any resource server: required**, since the access token is
  DPoP-bound; present it as `Authorization: DPoP <token>` with a matching
  proof, never `Bearer`.

The proof's `htm` and `htu` must be the method and the URL **as the client
called it**, which behind a proxy means the public URL:
`htu: "https://localhost/t/demo/token"`, not the container's address and not
with a query string.

## 5. Which tenant

A client exists in exactly one tenant. A registration in `demo` does not exist
at `https://localhost/t/admin/par`, and the refusal is
`invalid_client`/"unknown client" — identical to a client id that was never
registered anywhere, because telling the two apart would say which client ids
exist.

**Do not put an application client in the `admin` tenant.** ADR-0010 reserves
it for deployment administrators: it is the tenant that cannot be deleted, whose
users hold deployment-scoped roles, and whose whole purpose is that its
population is small and every member of it is an operator. Registering a BFF
there gives that BFF's flows the same neighbourhood as the console's, for no
benefit — the reserved tenant offers an application nothing an ordinary tenant
does not. Use `demo`, or create a tenant for the application.

## 6. Reading the refusal

`invalid_client` is all the client is told (RFC 6749 §5.2), and that will not
change: the reasons are facts about this server's state that an unauthenticated
caller has not earned. The *operator* gets the reason, in the server's log, at
`warn`, which the default filter (`asterius=info`) lets through — so
`docker compose logs asterius` shows it with no `RUST_LOG` set:

```
WARN client authentication failed
     tenant=demo client_id=c.qfxp0uEJeuyW2hD_g-dypQ
     reason=aud_is_not_this_issuer
     detail=expected aud to be the JSON string "https://localhost/t/demo"; the assertion carried "https://localhost/t/demo/token"
     error_code=invalid_client
```

The same fact is written to the audit trail as `client.auth_failed`.

The `reason` values, which are stable identifiers you can alert on:

| `reason` | What to fix |
| --- | --- |
| `no_client_authentication_presented` | The request carried no `client_assertion` and no certificate at all. §2. |
| `assertion_and_type_not_both_present` | One of `client_assertion` / `client_assertion_type` is missing. |
| `unsupported_client_assertion_type` | Not the exact `urn:…:jwt-bearer` string. |
| `more_than_one_method_presented` | An `Authorization` header *and* an assertion, or a certificate and an assertion. RFC 6749 §2.3 forbids picking. |
| `aud_is_not_this_issuer` | §1. The detail names both sides. |
| `assertion_iss_or_sub_is_not_the_client` | `iss` and `sub` must both be the `client_id`. |
| `client_id_does_not_match_assertion_sub` | The form parameter and the assertion disagree. |
| `assertion_signature_or_envelope_rejected` | Signature, `alg`, `typ`, size, `crit`, `exp` in the past, or `iat` beyond the skew window. The detail names which, and how many keys the client publishes. |
| `assertion_claim_missing_or_malformed` | A required claim is absent or the wrong JSON type; the detail names it. |
| `assertion_lifetime_too_long` | `exp - now` over ten minutes. |
| `assertion_jti_replayed` | The same assertion was presented twice. Mint one per request. |
| `unknown_or_disabled_client` | Not registered *in this tenant*, or disabled. §5. |
| `client_registered_for_another_method` | The registration says mTLS and the request sent an assertion, or the reverse. |
| `client_keys_unavailable` | The keys could not be resolved. If the detail names `jwks_uri`, read §3 — the neighbouring `client JWK Set fetch failed` line gives the address and the range it falls in. |

## 7. The shape of a full BFF connection

1. `POST {issuer}/par` — the authorization request parameters, plus
   `client_assertion_type` + `client_assertion`, plus a DPoP proof or
   `dpop_jkt`. Returns `request_uri` and `expires_in`.
2. Redirect the browser to `{issuer}/authorize?client_id=…&request_uri=…`.
3. The person signs in and consents; the browser comes back to your
   `redirect_uri` with `code` and `state`.
4. `POST {issuer}/token` — `grant_type=authorization_code`, the `code`, the
   `code_verifier`, **a fresh** `client_assertion` (new `jti`), and a DPoP
   proof whose `htu` is the token endpoint.
5. `GET {issuer}/userinfo` with `Authorization: DPoP <access_token>` and a
   proof for that URL.

Every step in a code flow here is PKCE-protected: PAR does not replace
`code_challenge`.

## See also

* `docs/deployment/tls-and-proxy.md` — what the issuer must be behind a proxy,
  and which headers have to survive it.
* `deploy/README.md` — the example compose stack.
* `docs/adr/0006-outbound-fetches-of-client-supplied-urls.md` — why a loopback `jwks_uri`
  is refused.
* `docs/adr/0010-deployment-admins-live-in-a-reserved-tenant.md` — why `admin`
  is not a home for an application client.
