# External identity provider connections

Status: implementation and operator guide for `ast-7vbr`. The existing
Federation signing key and SAML IdP screens are separate features.

## Goal

One Asterius tenant can offer several external OpenID Connect providers, such
as a tenant-specific Microsoft Entra ID issuer and a Keycloak realm. A person
selects a provider on the existing sign-in page. After the provider proves the
person's identity, Asterius binds that identity to a local tenant user and
continues the original authorization or first-party interaction. Applications
continue to trust Asterius as their issuer and never receive an upstream token.

The first release uses generic OpenID Connect Authorization Code Flow. Entra
and Keycloak are interoperability targets, not separate protocol
implementations. Inbound SAML is a later connector using the same local account
binding model. SCIM remains the path for bulk account and group provisioning;
it does not authenticate a browser.

## Provider configuration

Each provider belongs to one tenant and has a stable local identifier, display
name, exact HTTPS issuer, client ID, encrypted client credential, enabled state,
and first-login policy. The console lists providers and gives the operator an
exact redirect URI derived from that tenant's issuer. A credential is accepted
on write and never returned by a read. Configuration changes and provider
disabling are audited. Removing a provider does not silently delete users or
their identity bindings.

### Username claim

The optional **Username claim** setting names one top-level string claim in the
provider's signed ID token, for example `preferred_username` or a custom claim
name. Use the exact claim name; nested paths and expressions are not supported.
Leave it blank to preserve existing usernames and generate names for new accounts.

When configured, the claim sets a new account's username and updates an already
linked account's username on each successful sign-in. The account is first
resolved through its tenant, provider, issuer, and subject binding. A missing,
invalid, or already-used username refuses sign-in and leaves the accounts
unchanged. A username match never creates a binding to another local account.
Changes to linked usernames are audited. Disabling the mapping preserves the
last stored username.

The **External** column in Users lists the names of linked providers. An account
can have external links and local sign-in methods at the same time.

Discovery starts at the operator-pinned issuer. The returned `issuer` must
match exactly; authorization, token, and JWK endpoints must be HTTPS and pass
the existing outbound address and redirect guard. JWKs are fetched on the
callback through that guard; provider configuration stores discovered endpoint
URLs. A provider cannot be chosen merely because an
untrusted page or email domain advertises it. For Entra, use a tenant-specific
issuer, not `common`, so the issuer being validated is fixed.

## Browser transaction

Starting from an existing Asterius interaction, the provider button creates a
short-lived, single-use server-side transaction bound to the tenant,
interaction, provider, browser cookie, random state, nonce, and PKCE verifier.
The browser receives only the authorization redirect. The callback checks the
transaction and consumes it atomically before exchanging the code through the
guarded HTTPS client. It rejects callback errors, repeated parameters, missing
state, expired or replayed transactions, and a provider or tenant mismatch.

The ID token must have a valid signature from that provider's pinned JWK Set;
the exact issuer, configured client ID in `aud`, appropriate `azp`, nonce,
expiration, issuance time, and an acceptable signing algorithm are checked.
The stable `(issuer, sub)` pair identifies the external account. Email,
`preferred_username`, display name, and upstream groups are profile data, not
proof that an existing local user owns the account. Upstream access and refresh
tokens are not sent to applications, placed in a browser cookie, or kept unless
a separately approved feature needs them.

On success, the existing interaction's authentication completion creates or
rotates the local session and resumes its original consent or first-party
destination. The session records an authentication method that identifies the
external proof without asserting that Asterius itself observed a password,
passkey, or MFA. An external `acr` or `amr` is not promoted to a stronger local
assurance rung without an explicit provider-specific policy and evidence.
Deployment administration still requires its existing phishing-resistant
step-up policy.

## Local account binding

The database binds one tenant, provider, exact upstream issuer and subject to
one local user, with uniqueness enforced in both relevant directions. A known
binding signs in only an active local account. A first-time identity follows
the provider's configured policy: either refuse pending operator action, or
create a new local user. An email or username collision never auto-links to an
existing user. Linking an existing local account requires a fresh local sign-in
or an explicit privileged action with audit evidence. Disabling or deleting a
provider stops new sign-ins through it, while the local user and other sign-in
methods remain independent.

Provisioning systems may already have created users through SCIM. They need
an explicit binding workflow to join a provider subject to that user; matching
email is insufficient. Group and role mapping from upstream claims is a
separate policy feature and does not ship as an implicit side effect of
authentication.

## Operational checks

Provider setup displays the expected callback URL, discovery issuer and status;
saving validates metadata. Interoperability checks cover Entra
and Keycloak success, disabled users, first login, link conflicts, key rotation,
expired and forged ID tokens, wrong issuer or audience, replay, mixed-provider
responses, and interrupted browser flows. Existing local password and passkey
login must continue to work when an external provider is unavailable.

Browser sign-in refusals display a tenant-themed error page with a support
reference. A live browser-bound interaction offers **Return to sign-in**;
an expired or missing interaction explains how to restart from the application.
Upstream error descriptions, tokens, and callback state are never rendered.

Sources: [OpenID Connect Core, Authorization Code Flow and ID Token validation](https://openid.net/specs/openid-connect-core-1_0.html),
[Microsoft Entra OpenID Connect endpoints](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc),
[Keycloak identity brokering and account-linking guidance](https://www.keycloak.org/docs/latest/server_admin/).

## Operator setup and interoperability evidence

### Common configuration

1. Give the Asterius tenant a browser-reachable HTTPS issuer. In the tenant
   console, open **Sign-in providers** and choose a stable provider ID (for
   example `keycloak` or `entra`). The exact callback shown by the console is
   `{tenant_issuer}/oidc/upstream/callback/{provider_id}`. Register that full
   URL as a **web/confidential-client** redirect URI at the upstream provider;
   it must match exactly. For a tenant issued at `https://as.example/t/demo`,
   the Keycloak callback is
   `https://as.example/t/demo/oidc/upstream/callback/keycloak`.
2. Enter the upstream discovery document's exact `issuer`, its registered
   client ID and secret, a display name, and the enabled state. Store the secret
   through the console; reads show only whether one is configured. On save,
   Asterius fetches `{issuer}/.well-known/openid-configuration`, requires its
   `issuer` to equal the entered value, and checks the code flow, compatible
   signing algorithm, `client_secret_basic`, and guarded HTTPS endpoints.
3. Keep **Create a new local account on first verified sign-in** off when
   existing accounts must be linked explicitly. When on, an unknown verified
   `(provider, issuer, sub)` gets a new local account; an email match never
   links it to an existing account. Use the user identity-binding controls for
   a pre-existing account. Disable the provider to stop new logins; existing
   Asterius sessions are independent.
4. If a federated-only session must open first-party account pages, add an
   explicit low rung to that tenant's ACR policy with
   `amr: ["federated_oidc"]` (for example
   `urn:asterius:acr:federated`). The default ladder contains password and
   passkey rungs but no federated rung; without one, account-page admission
   starts another sign-in. This local rung records that a verified external
   identity signed in. It does not claim an upstream password, passkey, MFA,
   or higher assurance, and leaves the tenant's privileged-action rules intact.

The connector sends `response_type=code`, `scope=openid`, a random `state` and
`nonce`, and a PKCE S256 challenge. It redeems the code from the server with
`client_secret_basic` and the verifier. It accepts signed RS256, ES256, or
PS256 ID tokens; checks `iss`, `sub`, `aud` (and `azp` when present), `nonce`,
`exp`, `iat`, and optional `nbf`; then uses only the stable issuer/subject pair
for account resolution. It does not copy upstream access or refresh tokens to
the browser or downstream client. Email, username, name, groups, roles,
`acr`, and `amr` are not mapped into an existing account, local roles, or local
assurance. Upstream provider logout and cross-provider single logout are not
implemented: signing out of Asterius ends its local session, not the upstream
session. Keycloak's optional `session_state` callback parameter is accepted;
an `iss` response parameter, if sent, must match the pinned issuer.

### Keycloak 26.7.4

Create an OIDC **confidential** client with **Client authentication** and
**Standard flow** enabled, a client secret, and the exact Asterius callback as
a valid redirect URI. Configure PKCE method S256 if the realm/client policy
exposes that setting. Use the realm issuer
`https://<public-keycloak-host>/realms/<realm>` in Asterius. Keycloak's
published realm discovery path is
`/realms/<realm>/.well-known/openid-configuration`.

For a disposable full-flow deployment, put Keycloak behind a public HTTPS
reverse proxy with a trusted certificate and a DNS name that resolves only to
public addresses from the Asterius server. Set Keycloak's fixed hostname to
that same HTTPS origin, for example:

```sh
docker run --rm --name keycloak-interop \
  -p 127.0.0.1:18080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_TEST_ADMIN_PASSWORD" \
  quay.io/keycloak/keycloak:26.7.4 start-dev \
  --hostname=https://kc.example.org --http-enabled=true \
  --proxy-headers=xforwarded
```

The reverse proxy forwards `https://kc.example.org` to
`http://127.0.0.1:18080` and sets and overwrites `X-Forwarded-Host`,
`X-Forwarded-Proto`, and `X-Forwarded-Port`. For repeatable realm
and client provisioning, mount a realm JSON file at
`/opt/keycloak/data/import/<realm>-realm.json` and add `--import-realm` to the
start command. The disposable `start-dev` mode is for this test only. Check:

```sh
curl -fsS https://kc.example.org/realms/interop/.well-known/openid-configuration \
  | jq '{issuer, authorization_endpoint, token_endpoint, jwks_uri,
         response_types_supported, token_endpoint_auth_methods_supported,
         id_token_signing_alg_values_supported}'
curl -fsS https://kc.example.org/realms/interop/protocol/openid-connect/certs \
  | jq '[.keys[] | {kid,kty,alg,use}]'
```

An HTTP-only container on `127.0.0.1` is useful for inspecting Keycloak but
cannot be registered as an Asterius provider: Asterius refuses non-HTTPS URLs
and private or loopback DNS answers. DNS or `/etc/hosts` aliases that resolve
to loopback do not bypass the address guard. Keycloak's fixed `--hostname`
controls the issuer and URLs it advertises; changing the proxy alone does not
make a mismatched issuer valid.

### Microsoft Entra ID

Register a **single-tenant web application** in the target directory. Add the
exact Asterius callback under the **Web** platform, create a client secret, and
enter the application's client ID and **secret value** in Asterius. Use the
tenant-specific v2 issuer from metadata, for example
`https://login.microsoftonline.com/<directory-id>/v2.0`; avoid `common` and
`organizations` because this connector requires an exact issuer. Inspect the
directory-specific document before saving:

```sh
directory_id='<target-directory-guid>'
curl -fsS "https://login.microsoftonline.com/$directory_id/v2.0/.well-known/openid-configuration" \
  | jq '{issuer, authorization_endpoint, token_endpoint, jwks_uri,
         response_types_supported, token_endpoint_auth_methods_supported,
         id_token_signing_alg_values_supported}'
```

The redirect URI is a server-side Web URI, not an SPA URI. Entra documents
authorization-code redemption by confidential web clients and support for
client credentials in the HTTP Basic header. If an Entra app requires
certificate-based `private_key_jwt` instead of a client secret, this connector
does not support it. Check that the actual ID token's `iss` is the configured
tenant-specific v2 issuer; metadata compatibility alone does not prove this.

### Repeatable browser-flow checks

Use two Asterius tenants and two upstream providers with distinct users. Start
each case from an Asterius sign-in interaction and record the provider, tenant,
callback status, resulting local user/session, and whether any upstream token
appears in browser storage or downstream responses. Never record secrets,
authorization codes, complete tokens, or raw subject values in the evidence.

| Case | Action | Expected result |
| --- | --- | --- |
| Linked login | Sign in at Keycloak, then Entra, with an explicit binding for each subject. | Each resumes the original Asterius interaction as the bound local user. |
| First login | Repeat with an unbound subject, with registration off and then on. | Off refuses; on creates a new local user without matching an existing email. |
| Disabled state | Disable the local user, then disable the provider. | Neither state permits a new login. Existing local sessions follow their own policy. |
| Browser binding | Alter or replay `state`, use another browser cookie, or reuse the callback. | Refused; the consumed state cannot authenticate again. |
| Provider mix-up | Send a valid callback to another provider ID or tenant; change an optional `iss` response parameter. | Refused before local authentication. |
| Token validation | Exchange a code whose ID token has wrong issuer/audience/nonce, bad signature, expired time, or an unsupported algorithm. | Refused; no local session. Use a controlled provider/test harness for forged-token cases. |
| Binding conflict | Try to bind the same provider issuer/subject to another local user; retry with an email collision. | Binding is rejected; email does not transfer ownership. |
| Key rotation | Rotate the upstream signing key and repeat a fresh login. | The new signed token validates from the guarded JWKS; a stale/unknown key is refused. |
| Availability | Interrupt the upstream token or JWKS endpoint; then use a local password or passkey. | Upstream login fails closed; local login still works. |
| Logout | Sign out of Asterius and revisit the upstream login. | Asterius local session ends; an upstream SSO cookie may still allow a new upstream sign-in. |

### Evidence as of 2026-09-28

| Provider/probe | Observed result | Limit |
| --- | --- | --- |
| Disposable Keycloak 26.7.4 `master` realm, HTTP metadata read inside a local Docker test | With fixed hostname `https://kc.example.test:18443`, discovery returned issuer `https://kc.example.test:18443/realms/master`, matching auth/token/JWKS origin; `code`, `client_secret_basic`, and RS256/ES256/PS256 were advertised. JWKS held an RS256 signing key plus an RSA-OAEP encryption key. | No public HTTPS route, registered client/user, browser code exchange, or Asterius session was exercised. Container was removed. |
| Disposable Keycloak 26.7.4 `asterius-interop` realm, local HTTP code flow | A confidential `asterius-local` client and test user completed browser-style authorization code with S256 PKCE and `client_secret_basic`. Callback `state` matched; Keycloak sent `session_state`; token endpoint returned HTTP 200 and an RS256 ID token with matching issuer, audience, and nonce. The Asterius JOSE verifier accepted the live token and rejected wrong nonce, issuer, and audience. Reusing the code returned `invalid_grant`. Keycloak front-channel logout displayed “You are logged out”; using that session's refresh token afterward returned `invalid_grant`. | This local HTTP harness tested the provider and Asterius token verifier, not Asterius's guarded discovery/exchange, binding, browser callback, local session, or Asterius logout. A public HTTPS Keycloak endpoint is still required for a complete Asterius browser flow. The disposable realm and container were removed. |
| Disposable Keycloak 26.7.4 behind Tailscale Funnel HTTPS, Asterius first-party browser flow | Asterius saved the provider from guarded discovery at the exact Funnel issuer. Fresh Chrome sign-in from `/t/demo/account` redirected to Keycloak, returned through the Asterius callback, and opened the account page with a local session and linked Keycloak identity. Replaying the callback returned HTTP 400. Repeated sign-ins left exactly one database binding. Disabling the provider hid it from the chooser and a direct begin request returned HTTP 400; it was then re-enabled. Asterius logout cleared its local session; a new account visit required sign-in. Selecting Keycloak again used its active upstream SSO session and returned the same local user without a password prompt. | A private mount namespace mapped only the Keycloak hostname to a public Funnel relay IP for the Asterius process because host MagicDNS returned a private tailnet address. The production SSRF guard was unchanged. This covers first-party login, binding, replay, provider-disable, and local logout, not the full negative-flow matrix or upstream-initiated logout. Funnel and container were removed after the test. |
| Supplied Microsoft Entra test directory and disposable local Asterius tenant over HTTPS | Live discovery and JWKS matched the exact tenant-specific v2 issuer and advertised `code`, `client_secret_basic`, and RS256. The enabled Asterius provider sent the registered callback, `state`, `nonce`, and S256 PKCE. After the account's mandatory password update and administrator consent, the browser completed Entra authorization and returned through Asterius's guarded code exchange and signed ID-token verification. The disposable database recorded one bound local user and a `federated_oidc` session. An initial callback revealed a relative first-party redirect bug; after changing Asterius to emit a tenant-mount absolute destination and adding an explicit low federated ACR rung to the disposable tenant, the browser landed at `/t/demo/account`, reload returned HTTP 200, and the linked `entra` identity was visible. Repeated sign-ins left exactly one binding. | This tests the target directory and a local self-signed HTTPS Asterius deployment. Negative forged-token, key-rotation, provider-disable, and callback-replay cases have not been fully exercised against Entra. Directory and app identifiers, credentials, codes, tokens, and raw subjects are omitted. |

The Keycloak and Entra first-party browser flows passed. The remaining negative
cases in the matrix require controlled provider or test-harness runs.
See [Keycloak hostname setup](https://www.keycloak.org/server/hostname),
[Keycloak containers and realm import](https://www.keycloak.org/server/containers),
[Keycloak OIDC endpoints](https://www.keycloak.org/securing-apps/oidc-layers),
[Entra OIDC discovery](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc),
and [Entra authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow).
