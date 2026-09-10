//! Key management and JOSE.
//!
//! Built directly on aws-lc-rs rather than on a JOSE library: see
//! [ADR-0004](../../../docs/adr/0004-jose-on-aws-lc-rs.md). What this crate
//! owns is the encoding and the algorithm allow-list; the cryptography is the
//! provider's.
//!
//! The allow-list is [`asterius_domain::SigningAlgorithm`] — EdDSA (Ed25519),
//! ES256 and PS256, and nothing else. `none` is not a value that exists.
#![forbid(unsafe_code)]

pub mod client_keys;
pub mod dpop;
pub mod jws;
pub mod kek;
pub mod key;
pub mod store;
pub mod verify;

pub use client_keys::{
    ClientKey, ClientKeyCache, ClientKeyError, ClientKeySet, MAX_JWK_SET_BYTES, MAX_KEYS,
    keys_from_jwk_set, parse_jwk_set,
};
pub use dpop::{DpopError, Expectation, NonceIssuer, NonceRule, NormalisedUri, Proof};
pub use jws::{Header, Unverified};
pub use kek::{
    CompositeKek, KEK_LEN, Kek, KeyBinding, LocalKek, NONCE_LEN, TenantSecret, WrappedKey,
};
pub use key::{MIN_RSA_BITS, SigningKey, VerifyingKey};
pub use store::{LocalKeyStore, thumbprint};
pub use verify::{KeyResolver, Policy, TypRule, VerificationError, Verified, verify};

use asterius_domain::SigningAlgorithm;

/// Why a JOSE operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JoseError {
    /// The provider could not generate a key.
    #[error("cannot generate a {0} key")]
    KeyGeneration(SigningAlgorithm),
    /// The bytes offered are not a key of that algorithm.
    #[error("not a valid {0} private key")]
    KeyRejected(SigningAlgorithm),
    /// An RSA key is below the profile's floor.
    #[error("RSA key is {bits} bits, minimum is {minimum} (FAPI 2.0 SP §5.4.1)")]
    WeakKey {
        /// The offered key's size.
        bits: usize,
        /// The smallest permitted size.
        minimum: usize,
    },
    /// The signing operation failed.
    #[error("signing failed")]
    Signing,
    /// Public key material could not be read or encoded.
    #[error("cannot read the public key")]
    PublicKey,
    /// The token is not a well-formed compact JWS.
    #[error("malformed JWS: {0}")]
    Malformed(&'static str),
    /// The header names an algorithm outside the allow-list.
    #[error("unsupported algorithm {0:?}; permitted: EdDSA, ES256, PS256")]
    UnsupportedAlgorithm(String),
    /// The header carries `crit` parameters, which we never understand.
    #[error("unsupported critical header parameters: {0}")]
    UnsupportedCritical(String),
    /// A header field disagrees with what the verifier requires.
    #[error("{field} is {found:?}, expected {expected:?}")]
    UnexpectedHeader {
        /// Which header field.
        field: &'static str,
        /// What the verifier required.
        expected: String,
        /// What the token claimed.
        found: String,
    },
    /// Claims could not be serialised.
    #[error("cannot serialise claims")]
    Serialisation,
    /// The key-encryption key could not be loaded.
    ///
    /// `reason` is a fixed string, never interpolated from what was read: the
    /// thing that failed to parse may well be the key itself. The field is
    /// `origin` and not `source` because thiserror reads a field of that name
    /// as the underlying error.
    #[error("cannot load the key-encryption key from {origin}: {reason}")]
    KekUnavailable {
        /// Where it was being read from — a variable name or a path.
        origin: String,
        /// Why it was refused.
        reason: &'static str,
    },
    /// Private key material could not be encrypted for storage.
    #[error("cannot wrap the private key")]
    Wrap,
    /// Stored private key material did not authenticate.
    ///
    /// Carries no detail, for the same reason [`JoseError::InvalidSignature`]
    /// does not: "wrong key" and "altered ciphertext" and "wrong tenant" are
    /// three answers an attacker with an `UPDATE` would like to tell apart.
    #[error("cannot unwrap the private key")]
    Unwrap,
    /// The stored material was wrapped under a different key-encryption key.
    ///
    /// Distinct from [`JoseError::Unwrap`] because it is an operations
    /// problem, not an attack: somebody replaced the KEK and left rows behind.
    /// Both identifiers are already stored in the clear.
    #[error("wrapped under key-encryption key {stored}, this process holds {available}")]
    KekMismatch {
        /// The `kek_id` recorded with the ciphertext.
        stored: String,
        /// The `kek_id` of the key this process holds.
        available: String,
    },
    /// A signature did not verify.
    ///
    /// Deliberately carries no detail. Distinguishing "wrong key" from "bad
    /// encoding" from "wrong algorithm" tells an attacker which of their
    /// guesses was closest.
    #[error("signature verification failed")]
    InvalidSignature,
}
