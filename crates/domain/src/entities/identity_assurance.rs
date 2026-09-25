//! Explicitly verified identity claims for OpenID Identity Assurance.
//!
//! Ordinary claim provenance or a `verified_at` timestamp alone never turns a
//! claim into an Identity Assurance assertion. A trusted verifier must supply
//! the framework and issuer together with the checked values.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;

use crate::{ClaimName, Issuer, json_sentinel::names_a_serde_json_sentinel};

/// The maximum number of claims in one verification record.
pub const MAX_VERIFIED_CLAIMS: usize = 32;

/// A person attribute eligible for an IDA verified-claims bundle.
///
/// Unlike ordinary [`ClaimName`], this can name `email` and
/// `email_verified`. It cannot be inserted into an ordinary claim bag.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct VerifiedClaimName(String);

impl VerifiedClaimName {
    /// Validate a verified attribute name without accepting token claims.
    ///
    /// # Errors
    /// Returns an error for a server-issued or malformed name.
    pub fn parse(raw: &str) -> Result<Self, VerifiedClaimsError> {
        if !matches!(raw, "email" | "email_verified") {
            ClaimName::parse(raw).map_err(|_| VerifiedClaimsError::ClaimName)?;
        }
        if raw == "verified_claims" {
            return Err(VerifiedClaimsError::ClaimName);
        }
        Ok(Self(raw.to_owned()))
    }

    /// JSON member name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A verified set of identity attributes with its explicit provenance.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerifiedClaims {
    verification: Verification,
    claims: BTreeMap<VerifiedClaimName, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verification {
    trust_framework: String,
    /// Provenance for internal policy. IDA `verification_process` is a
    /// different field: an audit reference, not the verifier's issuer URL.
    #[serde(skip)]
    verifier: String,
    #[serde(with = "time::serde::rfc3339")]
    time: OffsetDateTime,
}

/// Invalid or untrusted verification input.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifiedClaimsError {
    #[error("trust framework must be a bounded ASCII identifier")]
    TrustFramework,
    #[error("verified claims must contain between 1 and 32 entries")]
    ClaimCount,
    #[error("a verified claim value must be non-null and contain no reserved JSON members")]
    ClaimValue,
    #[error("a stored verified claim name is invalid")]
    ClaimName,
    #[error("a verified claim bundle must be at most 64 KiB")]
    Size,
}

impl VerifiedClaims {
    /// Rebuild a stored record through the same validation as a new assertion.
    ///
    /// # Errors
    /// Returns an error for a malformed claim map or invalid verification
    /// metadata. A damaged row is never projected into an OIDC response.
    pub fn from_storage(
        framework: &str,
        verifier: Issuer,
        time: OffsetDateTime,
        claims: Value,
    ) -> Result<Self, VerifiedClaimsError> {
        let object = claims.as_object().ok_or(VerifiedClaimsError::ClaimValue)?;
        let mut validated = BTreeMap::new();
        for (raw, value) in object {
            let name = VerifiedClaimName::parse(raw)?;
            validated.insert(name, value.clone());
        }
        Self::new(framework, verifier, time, validated)
    }

    /// Construct a bundle after a trusted verifier has authenticated its
    /// assertion. Callers must not pass user-supplied verification metadata.
    /// Claim names are already validated by [`VerifiedClaimName`], including refusal
    /// of server-issued names such as `sub`, `iss` and `aud`.
    ///
    /// # Errors
    /// Returns an error for an invalid framework or an empty, oversized or
    /// unsafe claim map.
    pub fn new(
        framework: &str,
        verifier: Issuer,
        time: OffsetDateTime,
        claims: BTreeMap<VerifiedClaimName, Value>,
    ) -> Result<Self, VerifiedClaimsError> {
        if framework.is_empty()
            || framework.len() > 128
            || !framework.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
            })
        {
            return Err(VerifiedClaimsError::TrustFramework);
        }
        if !(1..=MAX_VERIFIED_CLAIMS).contains(&claims.len()) {
            return Err(VerifiedClaimsError::ClaimCount);
        }
        if claims
            .values()
            .any(|value| value.is_null() || names_a_serde_json_sentinel(value))
        {
            return Err(VerifiedClaimsError::ClaimValue);
        }
        if serde_json::to_vec(&claims).map_or(true, |encoded| encoded.len() > 64 * 1024) {
            return Err(VerifiedClaimsError::Size);
        }
        Ok(Self {
            verification: Verification {
                trust_framework: framework.to_owned(),
                verifier: verifier.as_str().to_owned(),
                time,
            },
            claims,
        })
    }

    /// IDA `verified_claims` object, suitable for a consent-filtered OIDC
    /// projection. Release policy must run before calling this method.
    #[must_use]
    pub fn into_json(self) -> Value {
        serde_json::to_value(self).expect("validated verified claims serialize as JSON")
    }

    /// The verification metadata used by release policy.
    #[must_use]
    pub const fn verification(&self) -> &Verification {
        &self.verification
    }

    /// The attributes to be filtered by release policy.
    #[must_use]
    pub const fn claims(&self) -> &BTreeMap<VerifiedClaimName, Value> {
        &self.claims
    }
}

impl Verification {
    /// The registered trust framework identifier.
    #[must_use]
    pub fn trust_framework(&self) -> &str {
        &self.trust_framework
    }

    /// Issuer that asserted the verification.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// Verification time.
    #[must_use]
    pub const fn time(&self) -> OffsetDateTime {
        self.time
    }
}
