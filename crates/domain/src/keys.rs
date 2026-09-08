//! Signing algorithms, key identifiers, and the ports that reach a key.
//!
//! The algorithm set lives here rather than in the adapter because two crates
//! need to name it: `asterius-oidc` publishes it in discovery metadata, and
//! `asterius-jose` implements it. A protocol crate must not depend on an
//! adapter, so the vocabulary belongs in the middle. See
//! [ADR-0004](../../../docs/adr/0004-jose-on-aws-lc-rs.md).

use crate::TenantId;
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;

/// A signing algorithm this server will use.
///
/// The set is closed, and closed is the point. FAPI 2.0 SP §5.4.1 permits
/// exactly PS256, ES256 and EdDSA(Ed25519); RFC 8725 §3.1–3.2 says to fix the
/// permitted algorithms in advance rather than trusting a token's `alg` header.
/// An enum does both: `none` and `HS256` are not values that exist, so the
/// algorithm-confusion class of attack is unrepresentable rather than rejected
/// at runtime.
///
/// ADR-0003 records why RS256 is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    /// EdDSA over Ed25519. The default for everything this server issues.
    #[serde(rename = "EdDSA")]
    EdDsa,
    /// ECDSA over P-256 with SHA-256.
    #[serde(rename = "ES256")]
    Es256,
    /// RSASSA-PSS with SHA-256. The RSA option, for HSM estates that offer
    /// nothing else.
    #[serde(rename = "PS256")]
    Ps256,
}

impl SigningAlgorithm {
    /// Every permitted algorithm, in the order metadata should advertise them:
    /// the default first.
    pub const ALL: [Self; 3] = [Self::EdDsa, Self::Es256, Self::Ps256];

    /// The default for newly generated keys.
    pub const DEFAULT: Self = Self::EdDsa;

    /// The `alg` value, as it appears in a JOSE header and in metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
            Self::Ps256 => "PS256",
        }
    }

    /// Parses an `alg` value from a token header or from client metadata.
    ///
    /// Returns `None` for anything outside the allow-list — including `none`,
    /// `HS256` and `RS256`, which is the whole job.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.as_str() == value)
    }

    /// The JWK `kty` for keys of this algorithm (RFC 7517 §4.1).
    #[must_use]
    pub const fn key_type(self) -> &'static str {
        match self {
            Self::EdDsa => "OKP",
            Self::Es256 => "EC",
            Self::Ps256 => "RSA",
        }
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A key identifier: the JOSE `kid`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Kid(String);

impl Kid {
    /// Wraps a key identifier.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Kid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a key is in its life.
///
/// Rotation is a sequence of states rather than a swap, because a verifier that
/// cached the JWKS an hour ago must still be able to check a token signed an
/// hour ago. A key is published before it signs and stays published after it
/// stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyState {
    /// In the JWKS, not yet signing. Gives verifiers time to fetch it.
    Pending,
    /// The key new signatures are made with. At most one per algorithm.
    Active,
    /// No longer signing, still in the JWKS so existing tokens verify.
    Retiring,
    /// Gone from the JWKS. Kept only so its `kid` is never reused.
    Retired,
}

impl KeyState {
    /// The storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Retiring => "retiring",
            Self::Retired => "retired",
        }
    }

    /// Whether a key in this state belongs in the published JWKS.
    #[must_use]
    pub const fn is_published(self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::Retiring)
    }
}

/// The public half of a signing key, as published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyRecord {
    /// Which tenant's key this is.
    pub tenant: TenantId,
    /// The key identifier.
    pub kid: Kid,
    /// The algorithm it signs with.
    pub algorithm: SigningAlgorithm,
    /// Where it is in its life.
    pub state: KeyState,
    /// The public key as a JWK, ready to serve in a JWKS.
    pub public_jwk: serde_json::Value,
    /// When it was created.
    pub created_at: OffsetDateTime,
}

/// A JWS in compact serialisation, ready to put on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactJws(String);

impl CompactJws {
    /// Wraps an already-serialised JWS.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The serialisation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CompactJws {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Signs tokens for one tenant.
///
/// The port is deliberately narrow: a caller says what kind of token it is and
/// what is in it, and cannot choose the algorithm, the key or the header
/// beyond that. Every JWT this server issues therefore carries a `kid`, an
/// allow-listed `alg`, and an explicit `typ` (RFC 8725 §3.11) without any call
/// site having to remember.
#[async_trait::async_trait]
pub trait Signer: fmt::Debug + Send + Sync {
    /// Signs `claims` as a JWT of media type `typ`.
    ///
    /// `typ` is the explicit type header — `at+jwt` for an access token
    /// (RFC 9068 §2.1), `logout+jwt`, `dpop+jwt`, `secevent+jwt`. It is
    /// required, not optional, so that a token minted for one purpose cannot be
    /// presented as another.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DomainError`] if no active key exists for the tenant or
    /// if the signing operation fails.
    async fn sign(
        &self,
        tenant: &TenantId,
        typ: &'static str,
        claims: &serde_json::Value,
    ) -> Result<CompactJws, crate::DomainError>;
}

/// Holds a tenant's keys.
#[async_trait::async_trait]
pub trait KeyStore: fmt::Debug + Send + Sync {
    /// The keys a tenant publishes, in JWKS order.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DomainError`] if the keys cannot be read.
    async fn published_keys(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<PublicKeyRecord>, crate::DomainError>;

    /// The key a `kid` refers to, whatever its state.
    ///
    /// Retiring and retired keys must still resolve: a token signed yesterday
    /// is verified today.
    ///
    /// # Errors
    ///
    /// Returns [`crate::DomainError`] if the key cannot be read.
    async fn public_key(
        &self,
        tenant: &TenantId,
        kid: &Kid,
    ) -> Result<Option<PublicKeyRecord>, crate::DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FAPI 2.0 SP §5.4.1 and ADR-0003: exactly three, and not the others.
    #[test]
    fn the_algorithm_set_is_exactly_what_the_profile_permits() {
        let names: Vec<&str> = SigningAlgorithm::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(names, ["EdDSA", "ES256", "PS256"]);
        assert_eq!(SigningAlgorithm::DEFAULT, SigningAlgorithm::EdDsa);
    }

    /// The parser is the allow-list. Everything an attacker would put in an
    /// `alg` header to downgrade a signature must fail to become a value.
    #[test]
    fn no_algorithm_outside_the_allow_list_can_be_named() {
        for rejected in [
            "none", "None", "NONE", // RFC 8725 §3.2
            "HS256", "HS384", "HS512", // symmetric: alg confusion with a public key
            "RS256", "RS384", "RS512", // ADR-0003
            "ES384", "ES512", "PS384", "PS512", // not profiled
            "EdDSA ", " EdDSA", "eddsa", "", "ES25 6",
        ] {
            assert_eq!(
                SigningAlgorithm::parse(rejected),
                None,
                "accepted {rejected:?}"
            );
        }
    }

    #[test]
    fn every_permitted_algorithm_round_trips_through_its_wire_name() {
        for alg in SigningAlgorithm::ALL {
            assert_eq!(SigningAlgorithm::parse(alg.as_str()), Some(alg));
            let json = serde_json::to_string(&alg).expect("serialise");
            assert_eq!(json, format!("\"{}\"", alg.as_str()));
            assert_eq!(
                serde_json::from_str::<SigningAlgorithm>(&json).expect("deserialise"),
                alg
            );
        }
    }

    #[test]
    fn each_algorithm_names_its_jwk_key_type() {
        assert_eq!(SigningAlgorithm::EdDsa.key_type(), "OKP");
        assert_eq!(SigningAlgorithm::Es256.key_type(), "EC");
        assert_eq!(SigningAlgorithm::Ps256.key_type(), "RSA");
    }

    /// A verifier that fetched the JWKS an hour ago must still be able to check
    /// a token signed an hour ago, so a key is published before and after it
    /// signs.
    #[test]
    fn a_key_is_published_before_and_after_it_signs() {
        assert!(KeyState::Pending.is_published());
        assert!(KeyState::Active.is_published());
        assert!(KeyState::Retiring.is_published());
        assert!(!KeyState::Retired.is_published());
    }
}
