//! Offline validation of a pinned ID-JAG before a downstream policy decision.
//!
//! This module cannot authorize redemption. The ID-JAG draft -04 leaves actor
//! token validation and actor-chain meaning to a future profile. This local
//! profile accepts only one operator-pinned actor identity, with no nested
//! chain or `may_act`; the caller must still make every stateful decision.

use crate::{ClientKeySet, Policy, TypRule, VerificationError, verify};
use asterius_domain::SigningAlgorithm;
use serde_json::Value;
use std::collections::BTreeSet;
use time::OffsetDateTime;

/// Local upper bound for the life of a delegated identity assertion.
pub const MAX_LIFETIME_SECONDS: i64 = 300;

/// An operator-approved trust and authorization boundary for one downstream
/// client. The signing keys must come from a trusted, pinned issuer record;
/// never from the token's header or unverified claims.
#[derive(Debug, Clone)]
pub struct IdJagPolicy {
    /// Trusted issuer identifier.
    pub issuer: String,
    /// Authorization server issuer expected as the sole audience.
    pub audience: String,
    /// Authenticated downstream client ID.
    pub client_id: String,
    /// Operator-pinned upstream actor client ID. This is independent of the
    /// authenticated downstream client and is never inferred from `act`.
    pub actor_client_id: String,
    /// Thumbprint of the authenticated client's DPoP proof key.
    pub dpop_jkt: String,
    /// Operator-approved resource identifiers.
    pub resources: BTreeSet<String>,
    /// Operator-approved scopes.
    pub scopes: BTreeSet<String>,
    /// Verifying keys pinned to `issuer` by the caller.
    pub issuer_keys: ClientKeySet,
}

/// Cryptographically verified claims with only the supported subset exposed.
/// This type is a preflight result, not a grant of access or replay decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIdJag {
    /// Configured issuer whose pinned key verified the assertion.
    pub issuer: String,
    /// User subject asserted by the trusted issuer.
    pub subject: String,
    /// Verified actor identity matching the operator's explicit pin.
    pub actor_client_id: String,
    /// JTI to reserve atomically before any future token issuance.
    pub jti: String,
    /// Approved target resource.
    pub resource: String,
    /// Approved scope set.
    pub scopes: BTreeSet<String>,
    /// Expiry of the assertion in Unix seconds.
    pub expires_at: i64,
}

/// Reasons an ID-JAG cannot cross this preflight boundary.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdJagError {
    /// Local policy has not been bound to all required trusted inputs.
    #[error("ID-JAG trust policy is incomplete")]
    IncompletePolicy,
    /// JOSE or common JWT validation failed.
    #[error("ID-JAG signature or common claims are invalid: {0}")]
    Verification(#[from] VerificationError),
    /// A required ID-JAG claim is missing, malformed, or unauthorized.
    #[error("ID-JAG is invalid: {0}")]
    Invalid(&'static str),
    /// Actor differs from the configured single-hop local profile.
    #[error("ID-JAG actor does not match the configured single-hop profile")]
    UnsupportedActor,
}

/// Verifies an ID-JAG against one explicit issuer, client and resource policy.
///
/// The caller must establish how `issuer_keys` were pinned and must perform
/// replay reservation, local subject mapping, consent, and authorization before
/// issuing a token. This validator performs none of those stateful operations.
///
/// # Errors
///
/// Rejects incomplete policy, failed signature/standard claims, unsupported
/// actor chains, or any ID-JAG claim outside the explicit policy.
pub fn validate(
    token: &str,
    policy: &IdJagPolicy,
    now: OffsetDateTime,
) -> Result<ValidatedIdJag, IdJagError> {
    if policy.issuer.is_empty()
        || policy.audience.is_empty()
        || policy.client_id.is_empty()
        || policy.actor_client_id.is_empty()
        || policy.dpop_jkt.is_empty()
        || policy.resources.is_empty()
        || policy.scopes.is_empty()
        || policy.issuer_keys.is_empty()
    {
        return Err(IdJagError::IncompletePolicy);
    }
    let jwt_policy = Policy::new(
        TypRule::Exactly("oauth-id-jag+jwt"),
        SigningAlgorithm::ALL.to_vec(),
    )
    .issued_by(&policy.issuer)
    .for_audience(&policy.audience);
    let verified = verify(token, &jwt_policy, &policy.issuer_keys, now)?;
    let claims = &verified.claims;

    if claims.get("may_act").is_some() {
        return Err(IdJagError::UnsupportedActor);
    }
    // Draft -04 §4.4.1 says client_id continuity does not authenticate act.
    // The verified signature establishes the configured issuer; this exact
    // actor pin is a separate operator decision. Nested chains and extra actor
    // attributes have no authorization semantics in this local profile.
    let actor = claims
        .get("act")
        .and_then(Value::as_object)
        .filter(|value| value.len() == 1)
        .and_then(|value| value.get("client_id"))
        .and_then(Value::as_str)
        .filter(|value| *value == policy.actor_client_id.as_str())
        .ok_or(IdJagError::UnsupportedActor)?;
    if claims.get("authorization_details").is_some() {
        return Err(IdJagError::Invalid("authorization_details is unsupported"));
    }
    if claims.get("sub_id").is_some() {
        return Err(IdJagError::Invalid("sub_id subject mapping is unsupported"));
    }
    let sole_audience = match claims.get("aud") {
        Some(Value::String(value)) => value == &policy.audience,
        Some(Value::Array(values)) => {
            values.len() == 1 && values[0].as_str() == Some(policy.audience.as_str())
        }
        _ => false,
    };
    if !sole_audience {
        return Err(IdJagError::Invalid(
            "aud must name only this authorization server",
        ));
    }
    if claims.get("client_id").and_then(Value::as_str) != Some(policy.client_id.as_str()) {
        return Err(IdJagError::Invalid(
            "client_id does not match authenticated client",
        ));
    }
    let subject = nonempty_string(claims, "sub")?;
    let jti = nonempty_string(claims, "jti")?;
    if jti.len() > 255 {
        return Err(IdJagError::Invalid("jti exceeds replay-key bound"));
    }
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or(IdJagError::Invalid("iat must be an integer NumericDate"))?;
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or(IdJagError::Invalid("exp must be an integer NumericDate"))?;
    if expires_at
        .checked_sub(issued_at)
        .is_none_or(|lifetime| lifetime <= 0 || lifetime > MAX_LIFETIME_SECONDS)
    {
        return Err(IdJagError::Invalid("ID-JAG lifetime exceeds five minutes"));
    }

    let resource = nonempty_string(claims, "resource")?;
    if !policy.resources.contains(resource) {
        return Err(IdJagError::Invalid("resource is not approved"));
    }
    let scope = nonempty_string(claims, "scope")?;
    let scopes: BTreeSet<String> = scope.split_whitespace().map(str::to_owned).collect();
    if scopes.is_empty()
        || scopes.len() > 32
        || scopes.len() != scope.split_whitespace().count()
        || !scopes.is_subset(&policy.scopes)
    {
        return Err(IdJagError::Invalid("scope is not approved"));
    }
    let cnf = claims
        .get("cnf")
        .and_then(Value::as_object)
        .ok_or(IdJagError::Invalid("cnf must contain a DPoP thumbprint"))?;
    if cnf.len() != 1 || cnf.get("jkt").and_then(Value::as_str) != Some(policy.dpop_jkt.as_str()) {
        return Err(IdJagError::Invalid(
            "cnf.jkt does not match authenticated DPoP key",
        ));
    }

    Ok(ValidatedIdJag {
        issuer: policy.issuer.clone(),
        subject: subject.to_owned(),
        actor_client_id: actor.to_owned(),
        jti: jti.to_owned(),
        resource: resource.to_owned(),
        scopes,
        expires_at,
    })
}

fn nonempty_string<'a>(claims: &'a Value, name: &'static str) -> Result<&'a str, IdJagError> {
    claims
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(IdJagError::Invalid(name))
}
