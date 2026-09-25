# ADR-0018: Narrow OID4VP verifier profile

- **Status:** Provisional
- **Date:** 2026-09-25
- **Bead:** ast-s36.22

## Decision

Implement against [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html).
The first verifier profile uses a preregistered Client Identifier, HTTPS
`response_uri`, `direct_post`, one required DCQL `jwt_vc_json` credential query,
and fresh 256-bit `nonce` and `state`. The query selects one configured VC type
and explicit claim paths. The response parser accepts only a matching state
and one JWT VP under the requested DCQL credential ID. It does not treat parsing
as signature or policy verification.

The server must persist transaction state before exposing a request, then
atomically reserve or consume the state when a response arrives. It must
validate the VP holder proof against the request `nonce` and `client_id`, the
credential signature and issuer trust, credential status, type and claims before
using any credential data. Unsupported formats and response modes fail closed.

## Consequences

The pure protocol module can construct and parse a bounded exchange, while
state persistence, wallet transport and complete cryptographic verification
remain separate implementation steps. No production endpoint is enabled by
this first slice.
