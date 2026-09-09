//! W3C WebAuthn Level 3, relying-party side.
//!
//! Both ceremonies: [`registration::verify`] is §7.1 and
//! [`assertion::verify`] is §7.2. They share the client-data checks, the
//! authenticator-data header, and one rule about what a failure is allowed to
//! tell the browser — nothing.
//!
//! # Why this is written rather than taken from a crate
//!
//! `webauthn-rs` is the obvious library and it cannot be used here.
//! `webauthn-rs-core` depends on `openssl`, which `deny.toml` bans outright,
//! and ADR-0004 already refused `josekit` for exactly that reason: a second C
//! crypto library linked beside `aws-lc-sys` means two implementations to
//! track advisories for and two FIPS stories to explain.
//!
//! So this follows ADR-0004's shape rather than its letter. What is owned here
//! is the *encoding* — CBOR structures, a packed binary header, a JSON object,
//! and the comparisons the specification calls for. What is not owned is any
//! arithmetic: SHA-256 comes from `asterius_domain`, the constant-time
//! comparison from `subtle`, and the CBOR decoding from `ciborium`, which
//! parses a byte string and does no cryptography at all.
//!
//! Registration is the half of WebAuthn where that is a small claim to make.
//! With attestation `none` there is **no signature to verify** (§8.7 defines
//! its verification procedure as returning success), so the whole ceremony is
//! one hash, some length arithmetic, and a set of equality checks.
//!
//! Assertions add exactly one thing to that: a signature, verified by
//! [`signature::verify`], which reshapes a COSE key into what `aws-lc-rs`
//! accepts and then does none of the arithmetic itself. The key it reshapes is
//! one [`cose::parse`] already refused to store unless `aws-lc-rs` could
//! verify with it.
//!
//! # What is deliberately not here
//!
//! * **Every attestation format but `none`.** See [`attestation`].
//! * **Any I/O.** No challenge store, no credential store, no clock. Whether a
//!   challenge is outstanding and whether a credential id is already taken are
//!   queries, and this crate answers no queries.

#![forbid(unsafe_code)]

pub mod assertion;
pub mod attestation;
pub mod authenticator_data;
pub mod client_data;
pub mod cose;
pub mod registration;
pub mod signature;

pub use assertion::{Assertion, AssertionError, AssertionResponse, SignCount, SignCountPolicy};
pub use authenticator_data::{AssertedAuthenticator, AttestedCredential, UserVerification};
pub use cose::{CoseAlgorithm, CredentialPublicKey};
pub use registration::{Registration, RegistrationError};

use asterius_domain::sha256;

/// The smallest challenge this server will issue or accept.
///
/// §13.4.3 requires at least 16 bytes and says a relying party should use at
/// least that "in order to prevent replay attacks". This server issues 32,
/// because there is no reason to issue the minimum, but 16 is what is
/// *accepted* — a challenge that came back shorter than it went out did not
/// come from here.
pub const MIN_CHALLENGE_BYTES: usize = 16;

/// The challenge size this server issues.
pub const CHALLENGE_BYTES: usize = 32;

/// A registration or assertion challenge.
///
/// Owns its bytes and nothing else. Its lifetime, single use, and binding to
/// an interaction are the caller's business — this type exists so those bytes
/// cannot be confused with any other bytes on the way through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge(Vec<u8>);

/// Why a challenge was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a challenge must be at least {MIN_CHALLENGE_BYTES} bytes")]
pub struct ChallengeTooShort;

impl Challenge {
    /// Wraps bytes drawn by the caller.
    ///
    /// The caller draws them because randomness is a port in this codebase and
    /// this crate has none. `asterius_domain::OpaqueToken::generate_bits` is
    /// the generator everything else uses.
    ///
    /// # Errors
    ///
    /// [`ChallengeTooShort`] below [`MIN_CHALLENGE_BYTES`].
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ChallengeTooShort> {
        let bytes = bytes.into();
        if bytes.len() < MIN_CHALLENGE_BYTES {
            return Err(ChallengeTooShort);
        }
        Ok(Self(bytes))
    }

    /// The raw bytes, for the comparison in §7.1 step 8.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Who this server is, as far as an authenticator is concerned (§5.4.2).
///
/// # The RP ID is not the origin
///
/// The RP ID is a *domain*, and a credential is scoped to it: an authenticator
/// will only produce an assertion for a credential whose RP ID is a
/// registrable suffix of the page's origin. The origin list is the separate,
/// stricter check this server makes for itself — a browser will happily allow
/// `https://anything.example.com` to use a credential scoped to
/// `example.com`, and §7.1 step 9 is where a relying party declines to.
///
/// So both are held here and both are checked. A tenant reachable at a
/// path-based issuer *and* a vanity host has two origins and one RP ID, and
/// getting that wrong in either direction is either a lockout or a credential
/// usable from a subdomain nobody meant to trust.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    id: String,
    id_hash: [u8; 32],
    origins: Vec<String>,
    user_verification: UserVerification,
}

/// Why a relying party could not be described.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RelyingPartyError {
    /// The RP ID is empty, or is not a bare domain.
    #[error("an RP ID is a domain: no scheme, no port, no path")]
    NotADomain,
    /// No origin was given, so no ceremony could ever be accepted.
    #[error("a relying party must accept at least one origin")]
    NoOrigins,
    /// An origin is not an absolute `https` origin.
    #[error("an origin must be https with no path")]
    NotAnOrigin,
}

impl RelyingParty {
    /// Describes this server to an authenticator.
    ///
    /// # Errors
    ///
    /// [`RelyingPartyError`] if the RP ID is not a bare domain, or if the
    /// origin list is empty or holds something that is not an https origin.
    pub fn new(
        id: impl Into<String>,
        origins: Vec<String>,
        user_verification: UserVerification,
    ) -> Result<Self, RelyingPartyError> {
        let id = id.into();
        // A domain and nothing else. `https://example.com` as an RP ID is the
        // classic mistake, and it fails at the authenticator with an error
        // nobody can read, so it is refused where the message can say why.
        if id.is_empty()
            || id.contains("://")
            || id.contains('/')
            || id.contains(':')
            || id.contains('@')
        {
            return Err(RelyingPartyError::NotADomain);
        }
        if origins.is_empty() {
            return Err(RelyingPartyError::NoOrigins);
        }
        for origin in &origins {
            // Byte-exact comparison later means the stored form has to be the
            // form a browser produces: scheme, host, optional port, nothing
            // else. A trailing slash is the common way to get this wrong.
            if !origin.starts_with("https://") || origin[8..].contains('/') {
                return Err(RelyingPartyError::NotAnOrigin);
            }
        }

        let id_hash = sha256(id.as_bytes());
        Ok(Self {
            id,
            id_hash,
            origins,
            user_verification,
        })
    }

    /// The RP ID, for `PublicKeyCredentialRpEntity.id`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// `SHA-256(rp_id)`, which is what authenticator data carries.
    #[must_use]
    pub const fn id_hash(&self) -> &[u8; 32] {
        &self.id_hash
    }

    /// The origins a ceremony may have happened at.
    #[must_use]
    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    /// Whether the UV bit is required.
    #[must_use]
    pub const fn user_verification(&self) -> UserVerification {
        self.user_verification
    }
}
