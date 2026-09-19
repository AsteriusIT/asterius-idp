# Asterius examples

This directory contains a small financial application used to exercise an
Asterius tenant. The API is both:

- a confidential OAuth client/BFF, using PAR, PKCE S256, `private_key_jwt`
  and DPoP; and
- a protected resource server exposing an in-memory accounts API.

The React app never receives the client key or OAuth tokens. It uses the API's
HTTP-only session cookie. The Compose `financial` profile exposes the webapp at
`https://localhost/financial/` and the API at
`https://localhost/financial-api` through the deployment nginx.

See [api/README.md](api/README.md) and [webapp/README.md](webapp/README.md).
