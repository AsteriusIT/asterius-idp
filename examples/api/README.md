# Financial API

This is an intentionally small in-memory financial resource server and BFF.
It does not use a database: accounts, transfers and sessions live for the
process lifetime and reset on restart.

## Configure

1. Register a confidential client in Asterius with:
   - redirect URI: `https://localhost/financial-api/auth/callback`
   - token endpoint authentication: `private_key_jwt`
   - resource: `https://localhost/financial-api`
2. Mount the registered client's ES256 private JWK JSON with `kid` and set
   `CLIENT_PRIVATE_KEY_JWK_FILE`, or use `CLIENT_PRIVATE_KEY_JWK`.
   The matching public JWK must be registered with the client.
3. Copy `.env.example` to `.env` and set `ISSUER`, `CLIENT_ID`, and the key.

The client must be permitted to request the registered resource and scopes.
The API discovers PAR, authorization, token and JWKS endpoints from the issuer.

## Run

```sh
npm install
npm run dev
```

For standalone development, open the Vite webapp at
`http://localhost:5173/financial/` and select **Sign in with Asterius**. When
using the Compose profile, open `https://localhost/financial/`; the API is
reached through `https://localhost/financial-api`, and port 4000 remains
internal to the Compose network.

The OAuth client uses authorization-code + PKCE S256, pushes the request with
PAR, authenticates PAR and token requests with `private_key_jwt`, and binds
the resulting access token to a generated DPoP key. `/resource/accounts` is a
direct protected-resource example; `/api/accounts` is the browser-facing BFF
route.

## Playground contract and controls

The isolated playground uses `API_URL=<origin>/financial-api`,
`WEBAPP_URL=<origin>/financial/`, `RESOURCE=<origin>/financial-api`, and
`OIDC_INTERNAL_ISSUER=http://asterius.asterius.svc.cluster.local:9443/t/demo`.
The gateway strips only the `/financial-api` prefix; the API listens on 4000.
Set `COOKIE_NAME=asterius_playground_financial` to isolate its browser sessions
from other applications on the same hostname. The default is `financial_sid`;
the login-state cookie uses `<COOKIE_NAME>_login`. Ports do not isolate cookies.
Register the exact public callback and permit the financial resource with
`openid accounts:read accounts:write`. For direct resource calls from a
different registered client, add this API's client ID to the resource's
introspection-client allowlist. Private keys stay in the BFF's mounted Secret.

Protected BFF operations verify the access JWT and obtain a live authenticated
introspection result before returning or modifying the shared in-memory demo
accounts. Reads require `accounts:read`, writes require `accounts:write`.
Transfers and logout require exact browser Origin and `application/json`:
use `credentials: 'include'`, JSON Content-Type and body (`{}` for logout).
Login callback validates its browser state cookie, issuer, PKCE result and
ID-token signature/audience/nonce. OAuth requests handle an IdP DPoP nonce
challenge once with freshly signed assertions/proofs.

The direct `/resource/accounts` route verifies issuer, resource audience,
access-token type, expiry, DPoP algorithm/signature, target/method, token hash,
key binding, freshness and replay before live introspection and scope checks.
Proof history is bounded; it refuses additional requests at saturation rather
than evicting live replay entries. Revoked tokens cannot continue accessing
the financial resource.

Run `npm test` for signed nonce negotiation, actual cryptographic resource
proof/hash/binding/replay checks and browser-origin write refusal controls.
The playground performs actual browser and IdP checks before reporting the
application ready. These in-memory accounts are shared sample data, not
individual banking accounts; they reset on process restart.
