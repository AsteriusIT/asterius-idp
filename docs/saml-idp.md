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
explicitly allowed. Unknown request controls, including `ForceAuthn`,
`IsPassive`, `RequestedAuthnContext` and `NameIDPolicy`, are refused. The IdP
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

This integration has no recorded third-party SP interoperability run or SAML
conformance result. Operators should verify their SP's request-signing,
metadata and assertion processing against the exact supported profile before
enabling production traffic.
