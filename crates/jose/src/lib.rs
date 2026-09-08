//! Key management and JOSE adapter.
//!
//! Implements the domain `KeyStore` and `Signer` ports on top of a JOSE
//! library, behind an algorithm allow-list: EdDSA (Ed25519), ES256 and PS256.
//! `none` is never accepted, and RS256 only under the explicitly non-FAPI
//! `compat.rs256` flag.
#![forbid(unsafe_code)]
