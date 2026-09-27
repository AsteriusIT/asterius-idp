# External identity provider connections

Status: design for `ast-7vbr`. This document describes an inbound sign-in
feature; the existing Federation signing key and SAML IdP screens do not provide
it.

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

Discovery starts at the operator-pinned issuer. The returned `issuer` must
match exactly; authorization, token, and JWK endpoints must be HTTPS and pass
the existing outbound address and redirect guard. Metadata and JWKs are cached
for bounded lifetimes. A provider cannot be chosen merely because an
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

Provider setup must display the expected callback URL, discovery issuer and
status. The console should offer a connection test that validates metadata and
keys without logging tokens or secrets. Interoperability checks cover Entra
and Keycloak success, disabled users, first login, link conflicts, key rotation,
expired and forged ID tokens, wrong issuer or audience, replay, mixed-provider
responses, and interrupted browser flows. Existing local password and passkey
login must continue to work when an external provider is unavailable.

Sources: [OpenID Connect Core, Authorization Code Flow and ID Token validation](https://openid.net/specs/openid-connect-core-1_0.html),
[Microsoft Entra OpenID Connect endpoints](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc),
[Keycloak identity brokering and account-linking guidance](https://www.keycloak.org/docs/latest/server_admin/).
