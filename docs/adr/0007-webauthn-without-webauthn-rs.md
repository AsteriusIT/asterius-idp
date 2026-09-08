# ADR-0007: WebAuthn relying-party verification is written here, not taken from webauthn-rs

- **Status:** Accepted
- **Date:** 2026-09-08
- **Bead:** ast-2vk.3
- **Deciders:** Quentin RODIC
- **Refines:** [ADR-0004](0004-jose-on-aws-lc-rs.md)

## Context

The backlog names `webauthn-rs` as the WebAuthn adapter, and the bead title
says so. It cannot be used:

```
webauthn-rs v0.5.5
└── webauthn-rs-core v0.5.5
    └── openssl v0.10
        └── openssl-sys v0.9
```

`deny.toml` bans `openssl` and `openssl-sys` outright — *"use rustls; see
ADR-0001"* — and ADR-0004 already declined `josekit` for exactly this, on the
grounds that a second C crypto library beside `aws-lc-sys` means two
implementations to track advisories for and two FIPS stories to explain.

This is the same decision arriving a second time. Answering it differently now
would not be a WebAuthn decision; it would be the retirement of the rule, taken
sideways.

The alternatives considered:

- **`webauthn-rs` with an openssl exception.** Follows the backlog literally
  and buys a mature, widely deployed library. Costs the rule the project set
  for itself, and the cost is paid by everything else in the tree rather than
  by passkeys.
- **`passkey-rs` (1Password).** No openssl, RustCrypto throughout. But it is an
  *authenticator* implementation — the credential side — and its relying-party
  support is not the part it exists for. Adopting it would mean using a small
  slice of a crate aimed elsewhere.
- **RustCrypto directly (`p256`, `ed25519-dalek`, `rsa`).** Rejected for the
  reason ADR-0004 rejected it: three crates instead of the one provider already
  present, and the `rsa` crate has carried a timing advisory
  (RUSTSEC-2023-0071) for the operation we would depend on.

## Decision

`asterius-webauthn` implements the relying-party side directly, on the crypto
already in the graph. The shape is ADR-0004's: **we own the encoding, not the
cryptography.**

What is owned here:

- `clientDataJSON` — a JSON object, three members read, the original bytes kept
  because §7.1 step 11 hashes what was received rather than a re-serialisation.
- The attestation object — a CBOR map of three members (§6.5).
- Authenticator data — a packed binary header and one length-prefixed field
  (§6.1, §6.5.2).
- `COSE_Key` — a CBOR map keyed by small integers (RFC 9052 §7).
- Every comparison §7.1 calls for.

What is not owned: SHA-256 (`asterius_domain`, which is `sha2`), the
constant-time comparison (`subtle`), and CBOR decoding (`ciborium` — pure Rust,
Apache-2.0, and a byte-string decoder with no cryptography in it).

### Why registration is a small claim to make

With attestation `none` there is **no signature to verify**. §8.7 defines the
`none` statement's verification procedure as returning success. The entire
ceremony is one hash, some length arithmetic, and a set of equality checks —
which is why this ADR is being written for registration rather than argued
about.

Assertion verification (`ast-2vk.4`) is the half with a signature in it, and it
is one call into `aws-lc-rs` against a key this crate has already refused to
store unless it is of a type that call accepts. That refusal, at registration,
is what keeps the verifier's job closed.

### Only `none` attestation

Attestation says which *model* of authenticator made a credential, signed by a
manufacturer key. Verifying it needs a root store; acting on it means deciding
which hardware a person may own. FIDO's own passkey guidance is that a consumer
relying party should not ask.

Refusing every other format also removes `packed`, `tpm`, `android-key`,
`apple` and `fido-u2f` from this crate — between them the majority of the code
and nearly all of the risk in a WebAuthn implementation. A deployment that
genuinely needs enterprise attestation with an AAGUID allow-list is a separate
decision with a separate root store, and it is not this one.

### The COSE algorithm allow-list is not ADR-0003's

ADR-0003 fixes what this server **signs tokens with**: EdDSA, ES256, PS256.
That is a statement about keys we generate and control.

A passkey's algorithm is chosen by somebody else's authenticator and we only
ever verify with it. So the lists differ in both directions:

- `RS256` is accepted here and nowhere near a token. Refusing it would refuse
  Windows Hello and a large share of the security keys already in people's
  pockets — locking users out of an account to make a point about an algorithm
  their hardware chose for them.
- `PS256` is legal for our tokens and absent here, because no authenticator
  offers it.

## Consequences

- One crypto provider still serves TLS, JOSE and WebAuthn.
- We carry a WebAuthn implementation. It is roughly 500 lines, every parser has
  a fuzz target, and the tests are written per numbered step of §7.1 with
  fixtures assembled locally so each check can be shown to refuse when its own
  bit is wrong.
- Enterprise attestation is not available, and adding it means a root store and
  a new decision.
- If `webauthn-rs` ever drops `openssl`, this should be revisited: the argument
  here is entirely about the dependency, not about wanting to own the code.
