# Application developer experience — draft

This is a proposed developer journey with implementation outlines. It is not a
claim that framework starters or automatic code generation already exist.
The console **Help & guides** includes the condensed recipes.

## What exists today

The architecture builder creates confidential FAPI web applications, APIs,
groups and roles. Application registrations use `private_key_jwt`, PAR,
DPoP-bound tokens and EdDSA ID-token signing. Supply callbacks and either a
public JWKS URL or inline public JWKS JSON. Keep private keys in the app's
secret store. Applying creates identity configuration, not application code.

The Applications screen additionally supports standard OIDC and public client
profiles when tenant policy permits non-FAPI clients. These profiles are not
created by the builder. Choose an existing reference to represent such an app.
Provider, user and stream nodes currently describe context only.

## Choose the application shape

| Shape | Integration | Where credentials and tokens live |
| --- | --- | --- |
| Server-rendered web app | Confidential authorization-code client with PKCE; implement required PAR and DPoP | Server secret store and server-side session |
| React/Vue/Angular SPA with BFF | Browser calls its same-origin backend; backend performs the confidential flow | Backend; browser receives only a session cookie |
| Standalone SPA | Public client, Authorization Code + S256 PKCE, configured DPoP; verify CORS and discovery | No client secret; browser manages its ephemeral proof keys and session tokens |
| API | Resource server with exact audience and endpoint permissions | API validates access tokens and their sender binding |
| Background service | Separately registered client-credentials application with explicit audience and permissions | Server secret store; no user session |

For the BFF path, use Secure, HttpOnly cookies, an appropriate SameSite policy,
CSRF defenses, and server-side session expiry. Keep the callback URI exact,
including scheme, host, tenant path and trailing slash. Obtain endpoint URLs
from the tenant's discovery document instead of constructing them from the
console's hostname. The configured issuer may differ from the console origin.

## Proposed handoff from a saved architecture

After Apply, an application owner should receive an **Integrate** view for the
selected app and connected API. This view is a design proposal, not an existing
builder feature. It should provide:

- Application shape and language/framework selection.
- Exact issuer, discovery URL, client ID, callback, audience and scopes.
- Authentication method, required PAR/PKCE and token binding, signing algorithms.
- Copyable environment configuration with placeholders for secret-store paths.
- Explicit compatibility results for the chosen library and security profile.
- A login/callback/session/API recipe and negative validation examples.
- Links back to the saved architecture and each created resource.

Example handoff values (illustrative; names are our proposed convention):

```dotenv
OIDC_ISSUER=https://auth.example.test/t/demo
OIDC_CLIENT_ID=<created-application-id>
OIDC_REDIRECT_URI=https://web.example.test/auth/callback
OIDC_RESOURCE=https://api.example.test
OIDC_SCOPES=openid orders.read
OIDC_PRIVATE_KEY_FILE=/run/secrets/oidc-private-key.pem
```

A standalone SPA must not receive `OIDC_PRIVATE_KEY_FILE` or a client secret.
Do not use frontend-public environment variables for confidential credentials.

## Login and API request contract

1. Discover the exact issuer and validate returned metadata against it.
2. Generate state, nonce and an S256 PKCE challenge. Store transaction data in
   the user's server-side session (or the public client's protected transaction
   state), and use it once.
3. For builder applications, authenticate a pushed authorization request with
   the registered method and send the browser to the returned request URI.
4. Validate the callback, then redeem the code using the same redirect URI,
   verifier, registered authentication and required proof binding. Validate the
   ID token's signature, issuer, audience, expiry and nonce through the library.
5. Establish the application session. Request the API's exact `resource` and
   permissions through the authorization/token flow; do not use the ID token
   as an access token.
6. For DPoP access tokens, send the DPoP authorization scheme and a fresh proof
   for the target method and URL, including the access-token hash. Keep the
   bound key available for refresh and requests; handle nonce challenges.
7. The API verifies the access token, exact issuer and audience, expiry and
   required scopes, then checks sender binding and proof freshness/replay.
   A generic JWT bearer middleware alone is insufficient for DPoP.
8. Enforce business authorization on every endpoint. Groups and roles in the
   diagram do not implement authorization in application code.

## Language implementation outlines

### TypeScript / Node.js (web app or BFF)

Use [openid-client](https://github.com/panva/openid-client/blob/main/docs/README.md)
for discovery and protocol processing. Its API exposes private-key JWT client
authentication, PAR and DPoP helpers. Implement `/login`, `/auth/callback`,
`/session` and `/logout` around server-side session storage. Keep separate
client-authentication and DPoP keys. Adapt the official
[DPoP example](https://github.com/panva/openid-client/blob/main/examples/dpop.ts)
to the registration; verify nonce handling and token-bound API calls.

### C# / ASP.NET Core

Use cookie authentication for the local session and an OpenID Connect challenge
for sign-in. Configure Authority, ClientId and callback path from the handoff.
The [official OIDC guide](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-oidc-web-authentication)
is the starting point. Verify PAR, private-key authentication, EdDSA and DPoP
support in the selected versions before promising FAPI compatibility. API
middleware must validate the exact audience and endpoint policy, plus token
binding. Do not silently downgrade a builder-created registration.

### Java / Spring Boot

Use Spring Security `oauth2Login` for the web application and OAuth2 Resource
Server for APIs. Configure provider issuer, client registration and callbacks;
configure the API's exact expected audience and scope authorization.
The [JWT resource server guide](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html)
explains issuer validation and JWT processing. Add verified DPoP handling for
bound tokens and confirm client-side PAR/authentication compatibility.

### Python / Flask or FastAPI

Use an Authlib framework integration, discovered endpoints and a server-side
session. Implement login, callback, session expiry and logout. The
[Flask OIDC guide](https://docs.authlib.org/en/latest/oauth2/client/web/flask.html)
illustrates the client integration. Confirm the chosen framework/version's
PKCE, PAR, private-key authentication, signing algorithms and DPoP capabilities;
the generic sample is not an Asterius FAPI compatibility test.

### Rust / Axum or Actix

Use [openidconnect](https://docs.rs/openidconnect/latest/openidconnect/) for
baseline discovery, PKCE and ID-token validation, with server-side session
middleware. Verify algorithm compatibility and plan explicit PAR, assertion and
DPoP integration where required. No tested Rust application starter is shipped
by this draft.

## Acceptance criteria for future runnable starters

Each starter must demonstrate login, logout, expiry, API access and scope denial.
Reject wrong issuer/audience, invalid signature, expired token, reused state,
wrong PKCE verifier, missing proof, wrong proof key and proof replay. Test the
actual configured tenant profile. Publish exact dependency versions and a
compatibility result before labelling a recipe runnable.

The next design decision is whether the builder should offer explicit Web app,
SPA/BFF and public SPA profiles. Until then, its Web application node keeps its
current confidential FAPI behavior, and the Applications screen handles other
profiles.
