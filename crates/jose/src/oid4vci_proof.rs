//! The supported OpenID4VCI 1.0 JWT wallet key proof profile.
//!
//! A verified proof is still not an authorization to issue. Its nonce must be
//! consumed atomically by the issuer for the same tenant and access token.

use crate::{client_keys, jws, store};
use asterius_domain::{Issuer, Kid, SigningAlgorithm};
use serde_json::Value;
use time::OffsetDateTime;

/// Explicit JOSE type required by OpenID4VCI 1.0 Appendix F.1.
pub const TYPE: &str = "openid4vci-proof+jwt";
/// The single wallet proof algorithm currently accepted.
pub const ALGORITHM: SigningAlgorithm = SigningAlgorithm::Es256;
/// The largest accepted compact proof.
pub const MAX_PROOF_BYTES: usize = 8192;
/// Maximum age of a proof independent of nonce expiry.
pub const MAX_AGE_SECONDS: i64 = 300;

/// A checked key proof. Only the nonce repository can make it single use.
#[derive(Debug, Clone)]
pub struct VerifiedKeyProof {
    /// Public key to bind into the credential.
    pub public_jwk: Value,
    /// Stable RFC 7638 public-key thumbprint.
    pub key_thumbprint: Kid,
    /// Server-provided nonce that must be consumed before signing.
    pub nonce: String,
    /// NumericDate after freshness validation.
    pub issued_at: i64,
}

/// A refusal deliberately does not echo proof claims or key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// The compact JWS or claims are not the supported profile.
    #[error("invalid OpenID4VCI key proof")]
    Invalid,
    /// The signature does not verify with the embedded public JWK.
    #[error("OpenID4VCI key proof signature is invalid")]
    Signature,
    /// The proof was signed for another credential issuer.
    #[error("OpenID4VCI key proof audience is invalid")]
    Audience,
    /// The proof did not contain the expected server nonce.
    #[error("OpenID4VCI key proof nonce is invalid")]
    Nonce,
    /// The proof is stale or dated too far in the future.
    #[error("OpenID4VCI key proof is outside the allowed time window")]
    Stale,
}

/// Verifies an ES256 proof with exactly one embedded public JWK.
///
/// `expected_nonce` comes from the nonce repository, and the caller must
/// consume that nonce atomically before signing. `expected_client` is the
/// wallet's OAuth client identifier; a present `iss` must match it.
///
/// # Errors
///
/// Malformed, cross-issuer, stale, forged, or nonce-mismatched proofs fail.
pub fn verify(
    compact: &str,
    issuer: &Issuer,
    expected_client: &str,
    expected_nonce: &str,
    now: OffsetDateTime,
) -> Result<VerifiedKeyProof, ProofError> {
    if compact.len() > MAX_PROOF_BYTES || compact.is_empty() {
        return Err(ProofError::Invalid);
    }
    let unverified = jws::parse(compact).map_err(|_| ProofError::Invalid)?;
    if unverified.claimed_alg() != ALGORITHM.as_str()
        || unverified.claimed_typ() != Some(TYPE)
        || unverified.header().kid.is_some()
    {
        return Err(ProofError::Invalid);
    }
    let header: Value =
        serde_json::from_slice(unverified.raw_header()).map_err(|_| ProofError::Invalid)?;
    if header.get("x5c").is_some() || header.get("key_attestation").is_some() {
        return Err(ProofError::Invalid);
    }
    let jwk = header
        .get("jwk")
        .and_then(Value::as_object)
        .ok_or(ProofError::Invalid)?;
    if client_keys::has_private_members(jwk)
        || jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        || jwk
            .get("alg")
            .is_some_and(|value| value.as_str() != Some(ALGORITHM.as_str()))
    {
        return Err(ProofError::Invalid);
    }
    let public_jwk = Value::Object(jwk.clone());
    let key = client_keys::verifying_key(ALGORITHM, jwk).ok_or(ProofError::Invalid)?;
    let thumbprint = store::thumbprint(&public_jwk).map_err(|_| ProofError::Invalid)?;
    let payload = unverified.verify(&key).map_err(|_| ProofError::Signature)?;
    let claims: Value = serde_json::from_slice(&payload).map_err(|_| ProofError::Invalid)?;
    if claims.get("aud").and_then(Value::as_str) != Some(issuer.as_str()) {
        return Err(ProofError::Audience);
    }
    if claims
        .get("iss")
        .is_some_and(|value| value.as_str() != Some(expected_client))
    {
        return Err(ProofError::Invalid);
    }
    let nonce = claims
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or(ProofError::Nonce)?;
    if nonce != expected_nonce {
        return Err(ProofError::Nonce);
    }
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(ProofError::Invalid)?;
    let age = now.unix_timestamp().saturating_sub(issued_at);
    if !(-60..=MAX_AGE_SECONDS).contains(&age) {
        return Err(ProofError::Stale);
    }
    Ok(VerifiedKeyProof {
        public_jwk,
        key_thumbprint: thumbprint,
        nonce: nonce.to_owned(),
        issued_at,
    })
}
