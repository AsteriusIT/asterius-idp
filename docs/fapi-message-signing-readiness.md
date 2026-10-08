# FAPI 2.0 Message Signing readiness

This records implementation and independently executed evidence for the
authorization-server role against
[FAPI 2.0 Message Signing Final](https://openid.net/specs/fapi-message-signing-2_0-final.html),
published 25 September 2025. It does not claim OIDF certification or coverage of every profile. The separate FAPI 2.0 Security Profile baseline is described in
[ADR-0002](adr/0002-fapi-2-0-as-the-only-mode.md) and its certification scope in
[ADR-0015](adr/0015-certify-the-fapi-profile-only.md).

The Message Signing specification §5.1 permits separate conformance options
for signed authorization requests, signed authorization responses, and signed
introspection responses. RFC 9421 HTTP Message Signatures are not among these
requirements. This server's RFC 9421 support for explicitly configured SSF
peers does not establish FAPI Message Signing conformance.

| Server obligation | Current implementation and boundary |
|---|---|
| §5.3.1 signed JAR at PAR | `tenant.fapi_message_signing_client` lists selected client IDs. `http/par.rs` requires a FAPI client profile and a signed request object for those clients; `http/request_object.rs` verifies the registered signing algorithm and key, issuer audience, `nbf` freshness, `exp` lifetime, and request-object type. Startup refuses a nonempty list while the request-object feature is disabled. Unlisted clients retain their ordinary behavior. |
| §5.4.1 signed JARM | The same selected clients must ask for literal `response_mode=jwt` at PAR. Any client requesting JARM must register an explicit supported `authorization_signed_response_alg`; the RS256 default from generic JARM is excluded by the FAPI algorithm profile. `http/interaction.rs`, `http/authorize.rs`, `http/deliver.rs`, and `oidc/jarm.rs` issue signed success and error JWTs as the sole callback `response` parameter, with the registered algorithm bound at authorization. Invalid stored modes and missing algorithms fail closed. JARM encryption metadata is rejected because this server does not implement encrypted JARM. |
| §5.5.1 signed JWT introspection response | `http/introspection.rs` signs RFC 9701 responses when the caller explicitly requests `application/token-introspection+jwt` and has a registered `introspection_signed_response_alg`; otherwise the ordinary RFC 7662 JSON response remains available. The server does not assert that every resource server requests or verifies a signed response. |
| §5.6.1 signed ID token | The existing OIDC issuance path signs ID tokens with the tenant key; §5.6.1 adds no further authorization-server requirement. |
| §5.3.3 `response_modes` metadata | A client may register a nonempty subset of server-supported response modes. The authorization validator enforces that subset, including when an omitted request mode defaults to `query`. Discovery reports all server-supported modes; configured Message Signing clients must still choose `jwt` at PAR. |

The operator must select eligible client IDs, register their signing keys and
algorithms, and configure the request-object feature. A resource server seeking
signed introspection must register its response signing algorithm and request
the RFC 9701 media type. The client and resource server must verify signatures;
the authorization server cannot establish that from its own request path.

The independent OIDF candidate harness is available through
`./scripts/conformance.sh --message-signing`; see
[the harness instructions](../conformance/README.md#message-signing-candidate-harness).
Its dedicated signed JAR/JARM configuration used an empty waiver list in the
actual 2026-10-08 independent run on source
`0b4c7a4a4486fb981ac18dac39b9a8431065accc`: all 70 Message Signing modules
executed, with 63 PASSED, 4 REVIEW, 1 WARNING, 2 SKIPPED and 0 FAILED. The
separate Security Profile plan executed 56 modules: 50 PASSED, 4 REVIEW,
1 WARNING, 1 SKIPPED and 0 FAILED. Review artifacts were inspected; their
official REVIEW verdicts remain unchanged. The warning concerns the `sid`
extension, and RSA negative modules skipped with the ES256 fixture. See
[recorded suite outcomes](integrations/evidence/oidf-fapi-2026-10-08.json) and
[certification limits](certification.md#current-independently-executed-evidence).

The separate [independent RFC 9701 consumer](integrations/evidence/rfc9701-independent-consumer-2026-10-08.json)
passed thirteen actual controls on source
`97ac7245561064d2f58fbc8c48581f62ee72c451`. It obtains a real DPoP-bound token
for dedicated registered clients/resource, authenticates HTTPS introspection
with private_key_jwt, and independently verifies the Ed25519 signature and
protected header, issuer, audience, issue time and nested active token claims.
Unknown tokens and resource-unauthorized callers receive signed inactive-only
envelopes. The consumer refuses altered signatures, wrong issuer/audience,
unexpected algorithms and JSON downgrade. The server refuses missing signing
registration with 406, and incorrect or missing authentication with 400 for
the signed representation; ordinary RFC 7662 authentication refusal stays 401.
The actual run exposed and corrected the prior signed-authentication 401
mismatch required by RFC 9701 §5. Dedicated fixture registrations were seeded
in the owned database; issuance and introspection were actual HTTPS. All owned
client/resource rows were removed afterward.

These results support the implemented configured-client authorization-server
profile. The official suite and consumer ran different explicitly recorded
source revisions: the 126 suite verdicts are not recertified for the later
consumer source. They do not establish OIDF submission approval, every signing
algorithm, musl packaging, RFC 9421 interoperability or formal CAEP conformance.
