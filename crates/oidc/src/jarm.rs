//! Signed authorization response documents (JARM §2.1).
//!
//! The authorization endpoint only issues codes, so the response document
//! contains either a code or an OAuth error and the request's optional state.
//! The client audience and expiration are added here, before the tenant signer
//! signs the complete document. Callers must deliver the resulting compact JWS
//! as the sole `response` parameter.

use crate::code::AuthorizationResponse;
use asterius_domain::{ClientId, CompactJws, DomainError, Signer, SigningAlgorithm, TenantId};
use serde_json::{Map, Value};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// JARM does not register a dedicated JWT type. The shared signer requires an
/// explicit type, and `JWT` is the interoperable RFC 7519 value.
pub const JARM_TYP: &str = "JWT";

/// The upper bound recommended by JARM §2.1.
pub const MAX_LIFETIME: Duration = Duration::minutes(10);

/// Why an authorization response could not be signed.
#[derive(Debug, Error)]
pub enum JarmError {
    /// The response has no usable issuer or audience.
    #[error("JARM issuer and audience must be nonempty")]
    Identity,
    /// Time cannot be represented or the configured lifetime is invalid.
    #[error("JARM lifetime must be positive and at most ten minutes")]
    Lifetime,
    /// The tenant signing key is unavailable or could not sign.
    #[error("JARM signing failed: {0}")]
    Signing(#[from] DomainError),
}

/// Builds a JARM document with protocol parameters inside the signed payload.
///
/// # Errors
///
/// Returns [`JarmError`] for missing identity or an invalid lifetime.
pub fn claims(
    response: &AuthorizationResponse,
    client: &ClientId,
    now: OffsetDateTime,
    lifetime: Duration,
) -> Result<Value, JarmError> {
    if client.as_str().is_empty() {
        return Err(JarmError::Identity);
    }
    if lifetime <= Duration::ZERO || lifetime > MAX_LIFETIME {
        return Err(JarmError::Lifetime);
    }
    let expires = now.checked_add(lifetime).ok_or(JarmError::Lifetime)?;
    let mut document = Map::new();
    for (name, value) in response.query() {
        if name == "iss" && value.is_empty() {
            return Err(JarmError::Identity);
        }
        document.insert(name.to_owned(), Value::String(value));
    }
    document.insert("aud".to_owned(), Value::String(client.as_str().to_owned()));
    document.insert("exp".to_owned(), Value::from(expires.unix_timestamp()));
    Ok(Value::Object(document))
}

/// Signs a JARM document with the tenant's active, published signing key.
///
/// # Errors
///
/// Returns [`JarmError`] when document construction or signing fails.
pub async fn sign(
    signer: &dyn Signer,
    tenant: &TenantId,
    response: &AuthorizationResponse,
    client: &ClientId,
    algorithm: SigningAlgorithm,
    now: OffsetDateTime,
    lifetime: Duration,
) -> Result<CompactJws, JarmError> {
    let document = claims(response, client, now, lifetime)?;
    signer
        .sign(tenant, Some(algorithm), JARM_TYP, &document)
        .await
        .map_err(JarmError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_and_error_keep_their_parameters_inside_the_document() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("valid timestamp");
        let client = ClientId::new("c.example");
        let code = AuthorizationResponse::Code {
            code: "secret-code".to_owned(),
            state: Some("request-state".to_owned()),
            issuer: "https://issuer.example".to_owned(),
        };
        let signed = claims(&code, &client, now, Duration::minutes(5)).expect("valid response");
        assert_eq!(signed["iss"], "https://issuer.example");
        assert_eq!(signed["aud"], "c.example");
        assert_eq!(signed["exp"], 1_700_000_300);
        assert_eq!(signed["code"], "secret-code");
        assert_eq!(signed["state"], "request-state");
        assert!(signed.get("error").is_none());

        let denied = AuthorizationResponse::Error {
            error: "access_denied",
            state: None,
            issuer: "https://issuer.example".to_owned(),
        };
        let signed = claims(&denied, &client, now, Duration::minutes(5)).expect("valid error");
        assert_eq!(signed["error"], "access_denied");
        assert!(signed.get("code").is_none());
        assert!(signed.get("state").is_none());
    }

    #[test]
    fn invalid_lifetimes_and_missing_identity_are_refused() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let response = AuthorizationResponse::Error {
            error: "access_denied",
            state: None,
            issuer: "https://issuer.example".to_owned(),
        };
        let client = ClientId::new("c.example");
        assert!(claims(&response, &client, now, Duration::ZERO).is_err());
        assert!(claims(&response, &client, now, Duration::minutes(11)).is_err());
        assert!(claims(&response, &ClientId::new(""), now, Duration::minutes(5)).is_err());
        let bad_issuer = AuthorizationResponse::Error {
            error: "access_denied",
            state: None,
            issuer: String::new(),
        };
        assert!(claims(&bad_issuer, &client, now, Duration::minutes(5)).is_err());
    }
}
