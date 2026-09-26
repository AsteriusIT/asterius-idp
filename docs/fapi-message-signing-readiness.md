# FAPI 2.0 Message Signing readiness

This is an implementation inventory for the authorization-server role against
[FAPI 2.0 Message Signing Final](https://openid.net/specs/fapi-message-signing-2_0-final.html),
published 25 September 2025. It is not a certification or interoperability
claim. The separate FAPI 2.0 Security Profile baseline is described in
[ADR-0002](adr/0002-fapi-2-0-as-the-only-mode.md) and its certification scope in
[ADR-0015](adr/0015-certify-the-fapi-profile-only.md).

The Message Signing specification §5.1 permits separate conformance options
for signed authorization requests, signed authorization responses, and signed
introspection responses. RFC 9421 HTTP Message Signatures are not among these
requirements. This server's RFC 9421 support for explicitly configured SSF
peers does not establish FAPI Message Signing conformance.

| Server obligation | Current implementation and boundary |
|---|---|
| §5.3.1 signed JAR at PAR | `tenant.fapi_message_signing_client` lists selected client IDs. `http/par.rs` requires a signed request object for those clients; `http/request_object.rs` verifies the registered signing algorithm and key, issuer audience, `nbf` freshness, `exp` lifetime, and request-object type. Startup refuses a nonempty list while the request-object feature is disabled. Unlisted clients retain their ordinary behavior. |
| §5.4.1 signed JARM | The same selected clients must ask for literal `response_mode=jwt` at PAR. `http/interaction.rs`, `http/authorize.rs`, `http/deliver.rs`, and `oidc/jarm.rs` issue signed success and error JWTs as the sole callback `response` parameter. Invalid stored modes fail closed rather than falling back to an unsigned query. |
| §5.5.1 signed JWT introspection response | `http/introspection.rs` signs RFC 9701 responses when the caller explicitly requests `application/token-introspection+jwt` and has a registered `introspection_signed_response_alg`; otherwise the ordinary RFC 7662 JSON response remains available. The server does not assert that every resource server requests or verifies a signed response. |
| §5.6.1 signed ID token | The existing OIDC issuance path signs ID tokens with the tenant key; §5.6.1 adds no further authorization-server requirement. |
| §5.3.3 `response_modes` metadata | This client registration field is optional in the profile and is not implemented as a per-client restriction. Discovery reports server-supported modes; configured Message Signing clients are constrained at PAR. |

The operator must select eligible client IDs, register their signing keys and
algorithms, and configure the request-object feature. A resource server seeking
signed introspection must register its response signing algorithm and request
the RFC 9701 media type. The client and resource server must verify signatures;
the authorization server cannot establish that from its own request path.

No end-to-end interoperability run or OpenID conformance result is recorded for
this profile. Until that evidence exists, support must not be described as
certified or fully interoperable. `ast-s36.30` remains open for that evidence
and any gaps it reveals.
