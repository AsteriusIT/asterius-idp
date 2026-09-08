# ADR-0004: JOSE is built on aws-lc-rs, not on a JOSE library

- **Status:** Accepted
- **Date:** 2026-09-08
- **Bead:** ast-mxc.1
- **Deciders:** Quentin RODIC
- **Refines:** [ADR-0003](0003-signing-algorithm-set.md)

## Context

The backlog named `josekit` as the JOSE adapter. It cannot be used:

```
josekit v0.10.3
└── openssl v0.10.81
    └── openssl-sys v0.9.117
```

`deny.toml` bans `openssl` outright — *"use rustls; see ADR-0001"* — and the
README's architecture is rustls with aws-lc-rs. Adopting josekit would mean
either an exception to our own supply-chain rule or a second C crypto library
linked alongside `aws-lc-sys`, with two implementations to track advisories for
and two FIPS stories to explain.

The alternatives considered:

- **`jsonwebtoken`.** Mature and widely used, and it supports the three
  algorithms ADR-0003 permits. But it is a convenience layer over a provider we
  already have, its JWK and custom-header support is thinner than DPoP
  (RFC 9449) and JAR (RFC 9101) will need, and we would still have to constrain
  its algorithm handling ourselves — which is the part that actually matters.
- **RustCrypto (`ed25519-dalek`, `p256`, `rsa`).** No C at all, but three
  crates instead of one provider, and the `rsa` crate has carried a timing
  advisory (RUSTSEC-2023-0071) for exactly the operation we would depend on.
- **josekit with an OpenSSL exception.** Follows the backlog literally, at the
  cost of the rule the backlog itself set.

## Decision

`asterius-jose` implements JOSE directly on **aws-lc-rs**, which is already in
the dependency graph because rustls uses it. One crypto provider serves TLS and
JOSE.

What we own is the *encoding*, not the cryptography:

- JWS compact serialisation — `BASE64URL(header) . BASE64URL(payload) .
  BASE64URL(signature)` — which is three concatenations and two splits.
- JWK serialisation for the public half of each key type.
- The algorithm allow-list, as a closed enum.

What we do not own: key generation, signing, verification, constant-time
comparison, or any arithmetic. All of that is aws-lc-rs.

This refines ADR-0003 on one point of placement. That record says the allow-list
enum lives "in `asterius-jose`". It lives in **`asterius-domain`** instead,
because `asterius-oidc` must name the same algorithms when it generates
discovery metadata, and `asterius-oidc` must not depend on an adapter. The
*implementation* — the mapping from an algorithm to a signing primitive — is in
`asterius-jose` and nowhere else, which is what ADR-0003 was protecting.

Because we own a parser, the project's definition of done applies with full
force: the JWS parser gets a fuzz target, and a human reads RFC 7515 §7.1 and
RFC 8725 §3.1–3.2 before this is called done.

## Consequences

**Easier.** One provider, one set of advisories, one FIPS story. No OpenSSL, so
`deny.toml` stands unamended and `cargo deny` keeps meaning what it says. The
algorithm allow-list is a Rust enum, so an algorithm outside it is not a runtime
rejection but an unrepresentable state — `alg` confusion cannot be expressed.

**Harder.** We maintain the JOSE encoding layer, including its edge cases:
unpadded base64url, the `crit` header, the distinction between a compact JWS and
a JSON one. Roughly two hundred lines, fuzzed, and reviewed against the RFC
rather than against another implementation.

**To maintain.** JWE is not implemented and is not needed: nothing in the FAPI
2.0 profile requires encrypted tokens, and `request_object_encryption` is
out of v1 scope. If that changes, it is a new record, not an extension of this
one.

## Spec clauses

| Clause | What it requires | How this decision satisfies it |
|---|---|---|
| RFC 7515 §3.1, §7.1 | JWS compact serialisation is `BASE64URL(UTF8(header)) \| '.' \| BASE64URL(payload) \| '.' \| BASE64URL(signature)`, base64url without padding | Implemented directly, with a fuzz target over the parser |
| RFC 7517 §4 | JWK members for each key type: `kty`, `crv`, `x`/`y`, `n`/`e` | Serialised per key type from aws-lc-rs public key material |
| RFC 8725 §3.1–3.2 | Verify the algorithm against a set fixed in advance; do not let the token choose | The set is a closed enum resolved from registered metadata, never from the token header alone |
| FAPI 2.0 SP §5.4.1 | PS256, ES256, EdDSA(Ed25519) only; never `none`; RSA ≥ 2048, EC ≥ 224 bits | The enum has exactly three variants; key sizes are checked at generation and import |
