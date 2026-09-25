//! Verification boundary for a Claims Provider's signed UserInfo response.
//!
//! The provider's issuer and keys come from operator-pinned configuration,
//! never the JWT. This module verifies one collected claim set; the caller is
//! responsible for the user's provider connection and RP-specific consent.

use crate::{ClientKeySet, Policy, TypRule, VerificationError, verify};
use asterius_domain::SigningAlgorithm;
use serde_json::Value;
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};

/// Maximum accepted signed UserInfo size, including JOSE envelope.
pub const MAX_SIGNED_USERINFO_BYTES: usize = 8 * 1024;
/// Maximum number of attributes in one aggregate, excluding JWT protocol claims.
pub const MAX_AGGREGATED_CLAIMS: usize = 16;

/// A provider connection and the exact attributes approved for this retrieval.
#[derive(Debug, Clone)]
pub struct ClaimsProviderPolicy {
    /// Pinned Claims Provider issuer URL.
    pub issuer: String,
    /// Pinned public signing keys for that issuer.
    pub keys: ClientKeySet,
    /// This OP's issuer identifier, the required sole JWT audience.
    pub op_issuer: String,
    /// CP subject tied to the local user's approved provider connection.
    pub provider_subject: String,
    /// Attributes the user approved the OP to retrieve for this RP request.
    pub approved_claims: BTreeSet<String>,
}

/// A signed claim set that survived pinned trust and disclosure checks.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedClaimSet {
    /// Issuer whose pinned key verified this JWT.
    issuer: String,
    /// Subject the configured provider connection named.
    subject: String,
    /// Original compact JWT; the RP must verify this signature itself.
    jwt: String,
    /// Attribute names this exact signed JWT contains.
    names: BTreeSet<String>,
    /// Expiry of the signed claim set.
    expires_at: OffsetDateTime,
}

impl std::fmt::Debug for VerifiedClaimSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedClaimSet")
            .field("issuer", &self.issuer)
            .field("names", &self.names)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl VerifiedClaimSet {
    /// Pinned provider issuer that signed this response.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Provider subject established by the user's connection.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Original signed JWT, to store or release without changing its contents.
    #[must_use]
    pub fn jwt(&self) -> &str {
        &self.jwt
    }

    /// Names actually present in the verified signed JWT.
    #[must_use]
    pub const fn names(&self) -> &BTreeSet<String> {
        &self.names
    }

    /// Signed JWT expiration.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

/// Why a provider claim set cannot be aggregated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AggregationError {
    /// Pinned trust or user approval is incomplete.
    #[error("claims provider policy is incomplete")]
    Policy,
    /// The compact JWS is too large to retain or release.
    #[error("signed UserInfo exceeds the maximum size")]
    TooLarge,
    /// The signature or common JWT claims failed.
    #[error("signed UserInfo verification failed: {0}")]
    Verification(#[from] VerificationError),
    /// Provider subject, audience, expiry or attribute shape failed.
    #[error("signed UserInfo violates the aggregation profile: {0}")]
    Claims(&'static str),
}

/// Verify a signed UserInfo JWT from a configured Claims Provider.
///
/// Every non-protocol claim in the JWT must be in `approved_claims`. Since an
/// aggregated claim source carries the *whole* signed JWT, filtering its JSON
/// after verification would still disclose the original extra attributes.
///
/// # Errors
///
/// Rejects unpinned trust, invalid signatures, wrong issuer/audience/subject,
/// stale or long-lived tokens, excessive claims and any unapproved attribute.
pub fn verify_signed_userinfo(
    compact: &str,
    policy: &ClaimsProviderPolicy,
    now: OffsetDateTime,
) -> Result<VerifiedClaimSet, AggregationError> {
    if policy.issuer.is_empty()
        || policy.op_issuer.is_empty()
        || policy.provider_subject.is_empty()
        || policy.keys.is_empty()
        || policy.approved_claims.is_empty()
        || policy.approved_claims.len() > MAX_AGGREGATED_CLAIMS
    {
        return Err(AggregationError::Policy);
    }
    if compact.len() > MAX_SIGNED_USERINFO_BYTES {
        return Err(AggregationError::TooLarge);
    }
    let mut verification = Policy::new(
        TypRule::OptionalOneOf(&["JWT"]),
        SigningAlgorithm::ALL.to_vec(),
    )
    .issued_by(&policy.issuer)
    .for_audience(&policy.op_issuer);
    verification.max_bytes = MAX_SIGNED_USERINFO_BYTES;
    let verified = verify(compact, &verification, &policy.keys, now)?;
    let claims = verified
        .claims
        .as_object()
        .ok_or(AggregationError::Claims("payload is not an object"))?;
    if claims.get("aud").and_then(Value::as_str) != Some(policy.op_issuer.as_str()) {
        return Err(AggregationError::Claims("audience is not this OP alone"));
    }
    if claims.get("sub").and_then(Value::as_str) != Some(policy.provider_subject.as_str()) {
        return Err(AggregationError::Claims(
            "provider subject does not match connection",
        ));
    }
    let expiry = claims
        .get("exp")
        .and_then(Value::as_i64)
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .ok_or(AggregationError::Claims("expiry is missing"))?;
    if expiry <= now || expiry > now + Duration::hours(1) {
        return Err(AggregationError::Claims(
            "expiry exceeds the accepted window",
        ));
    }
    let mut names = BTreeSet::new();
    for (name, value) in claims {
        if matches!(
            name.as_str(),
            "iss" | "sub" | "aud" | "iat" | "nbf" | "exp" | "jti"
        ) {
            continue;
        }
        if name.len() > 128
            || name.starts_with('_')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || !policy.approved_claims.contains(name)
            || value.is_null()
        {
            return Err(AggregationError::Claims("attribute is not approved"));
        }
        names.insert(name.clone());
    }
    if names.is_empty() || names.len() > MAX_AGGREGATED_CLAIMS {
        return Err(AggregationError::Claims("claim count is outside bounds"));
    }
    Ok(VerifiedClaimSet {
        issuer: policy.issuer.clone(),
        subject: policy.provider_subject.clone(),
        jwt: compact.to_owned(),
        names,
        expires_at: expiry,
    })
}
