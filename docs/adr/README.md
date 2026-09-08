# Architecture decision records

One file per decision, numbered in the order they were taken. A record is
immutable once merged: a decision that is later reversed gets a *new* record
that supersedes the old one, and the old one gains a `Superseded by` line. The
log is the answer to "why is it like this?" six months from now.

Copy [`0000-template.md`](0000-template.md) to start one.

| # | Decision | Status |
|---|---|---|
| [0001](0001-modular-monolith.md) | Modular monolith, single binary, one PostgreSQL | Accepted |
| [0002](0002-fapi-2-0-as-the-only-mode.md) | FAPI 2.0 is the baseline, not a mode | Accepted |
| [0003](0003-signing-algorithm-set.md) | Signing algorithms: EdDSA, ES256, PS256; RS256 is non-FAPI | Accepted |
| [0004](0004-jose-on-aws-lc-rs.md) | JOSE is built on aws-lc-rs, not on a JOSE library | Accepted |
| [0005](0005-exact-redirect-uri-matching.md) | Redirect URIs match exactly against the registered set, including under PAR | Accepted |
| [0006](0006-outbound-fetches-of-client-supplied-urls.md) | How this server dereferences a URL a client chose | Accepted |
| [0007](0007-webauthn-without-webauthn-rs.md) | WebAuthn relying-party verification is written here, not taken from webauthn-rs | Accepted |
