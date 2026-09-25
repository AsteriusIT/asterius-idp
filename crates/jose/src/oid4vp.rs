//! Offline verification for the narrow OID4VP `jwt_vc_json` profile.
//!
//! Both trust anchors are explicit inputs. Neither a JWT header nor a VC's
//! issuer claim may supply keys to this verifier. Transaction replay is a
//! separate atomic storage operation and must precede relying on the result.

use crate::{ClientKeySet, Policy, TypRule, VerificationError, verify};
use asterius_domain::SigningAlgorithm;
use serde_json::Value;
use time::OffsetDateTime;

/// Pinned trust and disclosure policy for one verifier transaction.
#[derive(Debug, Clone)]
pub struct PresentationPolicy {
    /// Preregistered client ID from the request and expected VP audience.
    pub client_id: String,
    /// Transaction nonce from the saved request.
    pub nonce: String,
    /// Holder identifier whose keys were pinned by trusted registration.
    pub holder: String,
    /// Keys pinned to that holder, never taken from the VP JWT.
    pub holder_keys: ClientKeySet,
    /// Approved credential issuer.
    pub credential_issuer: String,
    /// Keys pinned to that issuer, never taken from the VC JWT.
    pub credential_issuer_keys: ClientKeySet,
    /// Required VC type besides `VerifiableCredential`.
    pub credential_type: String,
    /// Required claim paths relative to the VC root.
    pub required_claim_paths: Vec<Vec<String>>,
    /// Explicit operator acceptance of credentials with no revocation status.
    pub accept_without_status: bool,
}

/// Verified holder and claims. A caller still needs transaction replay control
/// and business authorization before using these values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPresentation {
    /// Holder bound to both the VP signature and VC subject.
    pub holder: String,
    /// Credential issuer that signed the VC.
    pub credential_issuer: String,
    /// Values of required claim paths, in policy order.
    pub disclosed_claims: Vec<Value>,
}

/// Failure to validate a VP and its contained credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PresentationError {
    /// The caller has not supplied all required pinned trust and policy data.
    #[error("OID4VP trust policy is incomplete")]
    IncompletePolicy,
    /// Holder or credential signature and common JWT claims failed.
    #[error("OID4VP JWT validation failed: {0}")]
    Verification(#[from] VerificationError),
    /// VP structure or binding failed.
    #[error("invalid OID4VP presentation: {0}")]
    Presentation(&'static str),
    /// Embedded VC structure or business policy failed.
    #[error("invalid OID4VP credential: {0}")]
    Credential(&'static str),
}

/// Verify one holder-bound JWT VP containing one pinned-issuer JWT VC.
///
/// # Errors
///
/// Rejects missing policy, signatures, nonce and audience mismatches,
/// unexpected credential structure, issuer, subject, type, status or claims.
pub fn verify_jwt_vc_json(
    vp_jwt: &str,
    policy: &PresentationPolicy,
    now: OffsetDateTime,
) -> Result<VerifiedPresentation, PresentationError> {
    validate_policy(policy)?;
    let holder_policy = Policy::new(TypRule::Exactly("JWT"), SigningAlgorithm::ALL.to_vec())
        .issued_by(&policy.holder)
        .for_audience(&policy.client_id);
    let vp = verify(vp_jwt, &holder_policy, &policy.holder_keys, now)?;
    if vp.claim_str("nonce") != Some(policy.nonce.as_str()) {
        return Err(PresentationError::Presentation(
            "nonce does not match request",
        ));
    }
    if !sole_audience(&vp.claims, &policy.client_id) {
        return Err(PresentationError::Presentation(
            "audience is not sole client ID",
        ));
    }
    if vp.claim_str("sub").is_some_and(|sub| sub != policy.holder) {
        return Err(PresentationError::Presentation(
            "VP subject differs from holder",
        ));
    }
    let presentation = vp
        .claims
        .get("vp")
        .and_then(Value::as_object)
        .ok_or(PresentationError::Presentation("vp claim is missing"))?;
    if !has_type(presentation.get("type"), "VerifiablePresentation") {
        return Err(PresentationError::Presentation("VP type is invalid"));
    }
    if presentation.contains_key("proof") {
        return Err(PresentationError::Presentation(
            "embedded proof is unsupported",
        ));
    }
    let credentials = presentation
        .get("verifiableCredential")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .ok_or(PresentationError::Presentation(
            "exactly one JWT VC is required",
        ))?;
    let vc_jwt = credentials[0]
        .as_str()
        .ok_or(PresentationError::Presentation("VC is not a JWT"))?;
    verify_credential(vc_jwt, policy, now)
}

fn verify_credential(
    vc_jwt: &str,
    policy: &PresentationPolicy,
    now: OffsetDateTime,
) -> Result<VerifiedPresentation, PresentationError> {
    let issuer_policy = Policy::new(TypRule::Exactly("JWT"), SigningAlgorithm::ALL.to_vec())
        .issued_by(&policy.credential_issuer);
    let credential = verify(vc_jwt, &issuer_policy, &policy.credential_issuer_keys, now)?;
    if credential.claim_str("sub") != Some(policy.holder.as_str()) {
        return Err(PresentationError::Credential(
            "VC subject differs from holder",
        ));
    }
    let vc = credential
        .claims
        .get("vc")
        .and_then(Value::as_object)
        .ok_or(PresentationError::Credential("vc claim is missing"))?;
    if !has_type(vc.get("type"), "VerifiableCredential")
        || !has_type(vc.get("type"), &policy.credential_type)
    {
        return Err(PresentationError::Credential("VC type is not approved"));
    }
    if let Some(issuer) = vc.get("issuer")
        && issuer.as_str() != Some(policy.credential_issuer.as_str())
        && issuer.get("id").and_then(Value::as_str) != Some(policy.credential_issuer.as_str())
    {
        return Err(PresentationError::Credential(
            "VC issuer differs from signed issuer",
        ));
    }
    if vc.contains_key("credentialStatus") {
        return Err(PresentationError::Credential(
            "credential status is unsupported",
        ));
    }
    if !policy.accept_without_status {
        return Err(PresentationError::Credential(
            "statusless credentials are not approved",
        ));
    }
    if vc.contains_key("proof") {
        return Err(PresentationError::Credential(
            "embedded proof is unsupported",
        ));
    }
    let credential_subject = vc
        .get("credentialSubject")
        .and_then(Value::as_object)
        .ok_or(PresentationError::Credential(
            "credentialSubject is missing",
        ))?;
    if credential_subject.get("id").and_then(Value::as_str) != Some(policy.holder.as_str()) {
        return Err(PresentationError::Credential(
            "credentialSubject.id differs from holder",
        ));
    }
    let mut disclosed_claims = Vec::with_capacity(policy.required_claim_paths.len());
    for path in &policy.required_claim_paths {
        let mut value = vc.get(&path[0]);
        for segment in path.iter().skip(1) {
            value = value.and_then(|current| current.get(segment));
        }
        let value = value
            .filter(|value| !value.is_null())
            .ok_or(PresentationError::Credential("required claim is absent"))?;
        disclosed_claims.push(value.clone());
    }
    Ok(VerifiedPresentation {
        holder: policy.holder.clone(),
        credential_issuer: policy.credential_issuer.clone(),
        disclosed_claims,
    })
}

fn validate_policy(policy: &PresentationPolicy) -> Result<(), PresentationError> {
    if policy.client_id.is_empty()
        || policy.nonce.is_empty()
        || policy.holder.is_empty()
        || policy.holder_keys.is_empty()
        || policy.credential_issuer.is_empty()
        || policy.credential_issuer_keys.is_empty()
        || policy.credential_type.is_empty()
        || policy.required_claim_paths.is_empty()
        || policy
            .required_claim_paths
            .iter()
            .any(|path| path.is_empty())
    {
        return Err(PresentationError::IncompletePolicy);
    }
    Ok(())
}

fn sole_audience(claims: &Value, expected: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.len() == 1 && values[0].as_str() == Some(expected),
        _ => false,
    }
}

fn has_type(value: Option<&Value>, expected: &str) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|types| types.iter().any(|value| value.as_str() == Some(expected)))
}
