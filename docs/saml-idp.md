# SAML IdP deployment boundary

The tenant IdP metadata is at `{issuer}/saml/metadata`. It is signed by the
active tenant SAML key, includes the active certificate and any pending or
retiring rotation certificate, and advertises HTTP-Redirect and HTTP-POST
AuthnRequest bindings at `{issuer}/saml/sso`. Responses are HTTP-POST forms
containing a signed bearer assertion. The metadata route refuses to publish
without a usable active key and live SSO route.

Provision each SP explicitly with an entity ID, exact HTTPS ACS URL and, for
signed requests, its pinned RSA public key. The default policy refuses
unsigned requests. A signed Redirect request is checked against the original
URL-encoded signature input; a signed POST request needs a root-bound XML
Signature. The bounded unsigned POST profile works only when the SP has been
explicitly allowed. `ForceAuthn="false"` and one empty `NameIDPolicy` with
`AllowCreate="true"` and the persistent format are accepted. The issued
assertion declares that same persistent NameID format. `ForceAuthn="true"`,
`IsPassive`, `RequestedAuthnContext` and other NameID policies are refused. The IdP
does not fetch SP metadata or accept an ACS or key from an AuthnRequest.

An already authenticated browser receives the assertion directly. Otherwise
the IdP verifies and replay-reserves the request, opens its existing
first-party authentication flow, and retains only the validated SP/ACS/request
fields in a tenant-scoped one-use pending row. The browser carries an opaque
cookie, not the request XML or an ACS URL. The pending row expires after ten
minutes. Resume requires the exact completed interaction's session and checks
that the SP still has the same ACS and request-signing policy before issuing.
No response is posted to a browser-supplied destination.

## Logout policy

This IdP does not advertise a SAML `SingleLogoutService` and does not accept
SAML `LogoutRequest` or issue SAML `LogoutResponse` messages. The server's
existing local logout ends the IdP browser session. A service provider remains
responsible for ending its own session; IdP local logout does not claim to
terminate sessions at SPs. Operators should not configure SPs to rely on SAML
Single Logout for this deployment.

A local interoperability run with Keycloak 26.7.4 as a SAML SP completed a
signed HTTP-Redirect AuthnRequest, Asterius first-party login, a signed
HTTP-POST assertion accepted by Keycloak's ACS, and a brokered Keycloak
session. This is interoperability evidence for that configuration, not a SAML
conformance result. Operators should verify their SP's request-signing,
metadata and assertion processing against the exact supported profile before
enabling production traffic.
