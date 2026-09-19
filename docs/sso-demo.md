# Two-application SSO demonstration

The example Compose deployment includes two minimal confidential BFFs. They
register separate clients through RFC 7591, use `private_key_jwt`, PAR, PKCE
S256 and DPoP, and keep tokens out of the browser. It is a development example:
the stack uses an open registration endpoint and a self-signed certificate.

Start it with one command from the repository root:

```sh
export ASTERIUS_ADMIN_PASSWORD="$(head -c 24 /dev/urandom | base64)"
docker compose -f deploy/compose/docker-compose.yml up --build
```

Open <https://localhost/demo-a> and accept the development certificate. Sign in
with `admin` and the password exported above, then approve application A. Open
<https://localhost/demo-b> in the same browser. Asterius reuses the IdP session,
but application B still receives its own consent screen because it is a distinct
client. Neither application can read the other's cookie or tokens.

Each signed-in application exposes these actions:

- **Refresh tokens** redeems its refresh token with a fresh client assertion and
  a DPoP proof.
- **Force reauthentication** pushes `prompt=login` and `max_age=0`; the existing
  IdP cookie does not bypass the password screen.
- **Require passkey step-up** requests the default tenant's passkey ACR as an
  essential ID-token claim. A password session is sent to the passkey step-up
  ceremony rather than silently treated as strong enough.
- **Check IdP session** uses a silent OIDC authorization. It renews the local
  session while the IdP session exists and clears it on `login_required`.
- **Revoke and log out** revokes the application's refresh and access tokens,
  clears its local session, and starts OIDC RP-Initiated Logout. Open **Check
  IdP session** in the other application afterwards: the silent request proves
  the IdP session is gone and clears that participating local session too.

The applications discover every protocol endpoint. Their private client and
DPoP keys exist only in each BFF process; RFC 7591 receives only the public
client JWK. Removing the Compose volumes removes the registered clients and all
other demonstration state:

```sh
docker compose -f deploy/compose/docker-compose.yml down --volumes
```

For a production integration, keep registration closed or gated by an initial
access token, use a trusted certificate, persist and rotate application keys,
and follow [the confidential-client integration guide](integrating-a-confidential-client.md).
