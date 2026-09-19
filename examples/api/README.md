# Financial API

This is an intentionally small in-memory financial resource server and BFF.
It does not use a database: accounts, transfers and sessions live for the
process lifetime and reset on restart.

## Configure

1. Register a confidential client in Asterius with:
   - redirect URI: `https://localhost/financial-api/auth/callback`
   - token endpoint authentication: `private_key_jwt`
   - resource: `https://localhost/financial-api`
2. Put the registered client's private JWK in `CLIENT_PRIVATE_KEY_JWK`.
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
