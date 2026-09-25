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

The server persists a SHA-256 digest of the transaction state before exposing
an `openid4vp:` request URI, then atomically consumes the state when a
`direct_post` response arrives. Only the configured initiating OAuth client
may start an exchange or retrieve its result; those operations use the normal
client authenticator. The wallet response route has no client authentication,
so its 256-bit state is the one-use transaction secret. The offline
verifier requires separately pinned holder and credential issuer keys, exact
VP `nonce` and `aud`, matching VC subject and holder, an approved VC type, and
all requested claims. Credential status mechanisms have different trust and
freshness rules; a credential with `credentialStatus` is rejected until its
mechanism is implemented. A credential without status is accepted only when
the operator explicitly opts into that policy. Unsupported formats and
response modes fail closed.

## Consequences

The pure protocol module can construct and parse a bounded exchange, while
The verifier reads pinned local JWKS at boot and stops startup if keys are
invalid. It stores only the approved disclosed claims for five minutes and
returns them to the authenticated initiator. This profile serves one configured
holder and one trusted issuer per verifier entry. It does not implement a
general DID resolver, credential status mechanism, or other VC formats.
