# Two SSO browser applications

Run the same image twice with distinct names, external paths and configured
clients. Sessions and pending logins are in memory; restarts sign this demo
application out without deleting IdP users or credentials.

| Environment | Contract |
|---|---|
| `ISSUER` | Exact public tenant issuer. |
| `OIDC_INTERNAL_ISSUER` | Trusted cluster service route to that tenant; public issuer and DPoP targets stay unchanged. |
| `EXTERNAL_URL` | Public application base, e.g. `https://desktop-cpbptqn-1.tailacbb15.ts.net:8446/demo-a`. |
| `CLIENT_ID` | Pre-registered application ID. |
| `CLIENT_PRIVATE_KEY_JWK_FILE` | Mounted private ES256 JWK JSON with matching public key and `kid` registered at the IdP. Inline `CLIENT_PRIVATE_KEY_JWK` is also accepted. |
| `CLIENT_KEY_ID` | Optional override of the JWK `kid`. |
| `RESOURCE` | Registered resource allowlist entry, default `<issuer>/userinfo`. |
| `SCOPES` | Default `openid profile offline_access`. |
| `APP_NAME`, `COOKIE_NAME`, `PORT` | Distinct display name/cookie; port defaults8080. |

Register redirect `<EXTERNAL_URL>/callback`, post-logout redirect
`<EXTERNAL_URL>/logged-out`, code/refresh grants, ES256 private_key_jwt
authentication and DPoP-bound access tokens. Configure the allowed resource and
scopes. Closed dynamic registration is supported: configured clients never
call registration. If no credentials are configured, the original dynamic
registration mode requires an advertised registration endpoint.

The browser can sign in, view actual UserInfo, refresh, check the IdP session,
force reauthentication, request passkey step-up and revoke/log out. Callback
state is bound to a short-lived HttpOnly browser cookie and the exact issuer.
ID-token signature/audience/nonce are verified using JWKS through the same
trusted internal transport. Authenticated requests retry a DPoP nonce challenge
once with a fresh proof and client assertion; nonce state is separated by key
and origin. No tokens or keys appear in the HTML.

Protocol-lab consumers may import `OidcClient`, configure `clientId` and
`clientPrivateJwk`, then call `initialise()`. `oauthPost(endpoint, form, dpopPair)`
handles authenticated nonce negotiation; `dpopRequest(pair, method, url,
{form, accessToken})` returns the HTTP response, and `proof()` uses the retained
nonce. `begin`, `redeem`, `refresh`, `userInfo`, `revoke` remain available.

Run `npm ci && npm test`. These tests cover configured startup with closed
registration, issuer refusal, bounded nonce retry with fresh proofs/assertions,
nonce origin isolation and internal JWKS signature verification. Actual IdP
registration and deployment readiness are verified separately by the playground.
