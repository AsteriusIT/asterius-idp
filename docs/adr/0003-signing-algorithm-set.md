# ADR-0003: Signing algorithms are EdDSA, ES256 and PS256 — RS256 is not implemented

- **Status:** Accepted
- **Date:** 2026-09-08
- **Bead:** ast-83p.12
- **Deciders:** Quentin RODIC

## Context

FAPI 2.0 SP §5.4.1 is unambiguous:

> Authorization servers, clients, and resource servers when creating or
> processing JWTs shall adhere to [RFC8725]; use PS256, ES256, or EdDSA (using
> Ed25519 variant) algorithms; and not use or accept the `none` algorithm.

RS256 is absent from that list. It is not merely discouraged: RSASSA-PKCS1-v1_5
is the signature scheme behind a long line of implementation defects, and
RFC 8725 §3.1–3.2 tells JWT implementations to fix the permitted algorithms in
advance and to reject anything outside that set rather than trusting the `alg`
header.

The original product note said "RS256 behind a flag". That framing hides the
real shape of the option: a flag that permits RS256 is not a compatibility
setting, it is a switch that makes the deployment non-compliant, and it has to
be defended as a downgrade path for the lifetime of the product.

The question it was meant to answer is interop: some older OIDC client libraries
can only verify RS256 ID Tokens. But an Asterius client must also perform PAR
(RFC 9126), PKCE `S256`, `private_key_jwt` client authentication and DPoP
(RFC 9449) — see ADR-0002. A library old enough to be RS256-only does none of
those. **There is no client that RS256 support would rescue**, so the flag buys
no interop while costing a branch in signing, in verification, in metadata
generation and in every conformance run.

RSA is still worth supporting for deployments whose keys live in an HSM or KMS
that offers RSA and nothing else — but PS256 covers that case and is on the
permitted list.

## Decision

The signing algorithm set is closed:

| Algorithm | Role | Default |
|---|---|---|
| **EdDSA** (Ed25519) | Default for all AS-issued JWTs: ID Tokens, JWT access tokens (`at+jwt`), logout tokens, SETs | ✅ |
| **ES256** | Always enabled, for verifiers without Ed25519 support | ✅ |
| **PS256** | The RSA option, for HSM/KMS estates that only offer RSA | ✅ |

- **RS256 is not implemented.** There is no `compat.rs256` flag, no RS256 branch
  and no configuration that produces or accepts an RS256 signature. The flag is
  *not* reserved: reintroducing it would require a new ADR superseding this one.
- **`none` is never produced and never accepted**, at any layer.
- The allow-list is a **closed Rust enum** in `asterius-jose`, not a string
  compared at runtime. An algorithm that is not a variant cannot be selected,
  which makes the `alg`-confusion class of bug unrepresentable rather than
  merely tested for.
- The same allow-list governs **verification** of client-supplied JWTs —
  `private_key_jwt` assertions, DPoP proofs, request objects — so a client
  cannot pick the algorithm used to check its own credentials.
- Key length floors from SP §5.4.1: RSA ≥ 2048 bits, EC ≥ 224 bits, enforced at
  key import and at generation.

Rejected alternatives: *keep `compat.rs256` behind a warning* (buys no real
client, permanently maintains a downgrade path); *reserve the flag name for
later* (a reserved non-compliant flag still invites the request, and metadata
does not need reserving — adding an algorithm later is an additive change).

## Consequences

**Metadata.** These arrays are derived from the enum, never hand-written
(`ast-o0t.3` owns the parity test):

- `id_token_signing_alg_values_supported`: `["EdDSA", "ES256", "PS256"]`
- `token_endpoint_auth_signing_alg_values_supported`: `["EdDSA", "ES256", "PS256"]`
- `request_object_signing_alg_values_supported`: `["EdDSA", "ES256", "PS256"]`
- `dpop_signing_alg_values_supported`: `["EdDSA", "ES256", "PS256"]`
- `userinfo_signing_alg_values_supported`: `["EdDSA", "ES256", "PS256"]`

`RS256` and `none` appear in none of them, and a client that registers
`id_token_signed_response_alg: "RS256"` is rejected at registration
(`ast-m9c.1`) rather than at first use.

**`/readyz`.** Because no non-compliant mode exists, there is no
`fapi_compliant: false` state to report. `/readyz` reports the enabled feature
flags; every one of them is FAPI-compatible by construction. If that ever stops
being true, this ADR is superseded first.

**Easier.** Conformance runs once, not once per flag combination. Key rotation
(`ast-mxc.3`) has three key types to manage, not four. The JWT verification
service (`ast-mxc.4`) rejects an unknown `alg` before parsing anything else.

**Harder.** A prospective adopter with an RS256-only client is told no, with a
pointer to this record. That is the intended answer.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| FAPI 2.0 SP §5.4.1 | JWTs shall use PS256, ES256 or EdDSA (Ed25519) and shall not use or accept `none` | Closed enum containing exactly those three; `none` is not a variant |
| FAPI 2.0 SP §5.4.1 | RSA keys ≥ 2048 bits; EC keys ≥ 224 bits | Enforced at key generation and at key import |
| RFC 8725 §3.1 | Perform algorithm verification against a fixed set decided in advance | The set is fixed at compile time, per key use |
| RFC 8725 §3.2 | Use appropriate algorithms; do not let the attacker choose | Verification algorithm is chosen from the registered client metadata and the key type, never from the token header alone |
| RFC 9449 §4.2 | DPoP proofs must use an asymmetric algorithm; `none` is prohibited | Same allow-list applies to DPoP proof verification |
