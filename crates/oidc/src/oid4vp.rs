//! Narrow OID4VP 1.0 request and response-envelope processing.
//!
//! Only the `jwt_vc_json` format with one required credential query and
//! `direct_post` is constructed here. This module does not trust or inspect a
//! VP Token. The adapter must atomically consume the pending transaction and
//! verify the holder proof, credential issuer and policy before using it.

use crate::form::{Duplicated, Parameters};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use url::Url;

/// Maximum accepted VP Token envelope size before parsing JSON.
pub const MAX_VP_TOKEN_BYTES: usize = 65_536;
const RANDOM_BYTES: usize = 32;

/// A configured, preregistered verifier and a single credential query.
#[derive(Debug, Clone)]
pub struct VerifierQuery {
    /// Client ID preregistered with the Wallet, without a client ID prefix.
    pub client_id: String,
    /// HTTPS endpoint controlled by this verifier.
    pub response_uri: String,
    /// DCQL credential identifier, unique within this one-query request.
    pub credential_id: String,
    /// VC `type` value, in addition to `VerifiableCredential`.
    pub credential_type: String,
    /// Required paths relative to the root of the VC, each as path segments.
    pub claim_paths: Vec<Vec<String>>,
}

/// A pending verifier transaction to persist before presenting the request.
#[derive(Debug, Clone)]
pub struct PendingPresentation {
    /// Fresh 256-bit nonce to bind a holder proof to this request.
    pub nonce: String,
    /// Fresh 256-bit state to map the response to one stored transaction.
    pub state: String,
    /// Exact client identifier expected in the VP's `aud` claim.
    pub client_id: String,
    /// The sole DCQL credential ID expected in `vp_token`.
    pub credential_id: String,
}

/// An authorization request and its state. Persist `pending` before exposing
/// `parameters` to a wallet; both must be handled as one operation.
#[derive(Debug, Clone)]
pub struct PreparedRequest {
    /// Authorization request parameters to encode into the wallet URL.
    pub parameters: Value,
    /// Transaction data to save and later consume atomically.
    pub pending: PendingPresentation,
}

/// An untrusted VP Token extracted from a correctly shaped response envelope.
#[derive(Debug, Clone)]
pub struct OfferedPresentation {
    /// Compact JWT still requiring complete VP and VC verification.
    pub vp_jwt: String,
}

/// Invalid local configuration or response envelope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Oid4vpError {
    /// A configured verifier query is unusable.
    #[error("invalid OID4VP verifier query: {0}")]
    Configuration(&'static str),
    /// The operating system could not provide random bytes.
    #[error("cannot generate OID4VP transaction secret")]
    Random,
    /// A response parameter was repeated.
    #[error(transparent)]
    Duplicate(#[from] Duplicated),
    /// The response does not match the saved transaction's envelope.
    #[error("invalid OID4VP response envelope: {0}")]
    Response(&'static str),
}

/// Constructs a fresh `direct_post` request for one `jwt_vc_json` credential.
///
/// # Errors
///
/// Rejects invalid preregistration, URL or query configuration and CSPRNG
/// failures. The caller must persist `pending` before sending `parameters`.
pub fn prepare(query: &VerifierQuery) -> Result<PreparedRequest, Oid4vpError> {
    validate_query(query)?;
    let nonce = random_secret()?;
    let state = random_secret()?;
    let claim_queries: Vec<Value> = query
        .claim_paths
        .iter()
        .map(|path| json!({"path": path}))
        .collect();
    let parameters = json!({
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "client_id": query.client_id,
        "response_uri": query.response_uri,
        "nonce": nonce,
        "state": state,
        "client_metadata": {
            "vp_formats_supported": {
                "jwt_vc_json": {"alg_values": ["EdDSA", "ES256", "PS256"]}
            }
        },
        "dcql_query": {"credentials": [{
            "id": query.credential_id,
            "format": "jwt_vc_json",
            "meta": {"type_values": [[query.credential_type]]},
            "claims": claim_queries
        }]}
    });
    Ok(PreparedRequest {
        parameters,
        pending: PendingPresentation {
            nonce,
            state,
            client_id: query.client_id.clone(),
            credential_id: query.credential_id.clone(),
        },
    })
}

/// Extracts a single JWT VP from `direct_post` after the caller has loaded and
/// atomically consumed the pending transaction associated with `state`.
///
/// # Errors
///
/// Rejects duplicate, missing, unexpected or oversized response parameters,
/// mismatched state, and any VP Token other than one JWT under the expected
/// DCQL credential ID. It does not validate the JWT itself.
pub fn extract_direct_post(
    pending: &PendingPresentation,
    form: &Parameters,
) -> Result<OfferedPresentation, Oid4vpError> {
    if form.present("error") || form.present("response") || form.present("id_token") {
        return Err(Oid4vpError::Response("unexpected response parameter"));
    }
    if form.get("state")? != Some(pending.state.as_str()) {
        return Err(Oid4vpError::Response("state does not match transaction"));
    }
    let encoded = form
        .get("vp_token")?
        .ok_or(Oid4vpError::Response("vp_token is missing"))?;
    if encoded.len() > MAX_VP_TOKEN_BYTES {
        return Err(Oid4vpError::Response("vp_token exceeds size limit"));
    }
    let value: Value =
        serde_json::from_str(encoded).map_err(|_| Oid4vpError::Response("vp_token is not JSON"))?;
    let object =
        value
            .as_object()
            .filter(|object| object.len() == 1)
            .ok_or(Oid4vpError::Response(
                "vp_token must contain one credential",
            ))?;
    let presentations = object
        .get(&pending.credential_id)
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .ok_or(Oid4vpError::Response(
            "credential response is missing or ambiguous",
        ))?;
    let jwt = presentations[0]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or(Oid4vpError::Response("credential response is not a JWT"))?;
    // Return an owned token because the JWT is held in the decoded JSON value.
    Ok(OfferedPresentation {
        vp_jwt: jwt.to_owned(),
    })
}

fn validate_query(query: &VerifierQuery) -> Result<(), Oid4vpError> {
    if query.client_id.is_empty() || query.client_id.contains(':') {
        return Err(Oid4vpError::Configuration(
            "client_id must be preregistered",
        ));
    }
    let uri = Url::parse(&query.response_uri)
        .map_err(|_| Oid4vpError::Configuration("response_uri must be HTTPS"))?;
    if uri.scheme() != "https"
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.fragment().is_some()
    {
        return Err(Oid4vpError::Configuration("response_uri must be HTTPS"));
    }
    if query.credential_id.is_empty()
        || !query
            .credential_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Oid4vpError::Configuration("invalid DCQL credential ID"));
    }
    if query.credential_type.is_empty() || query.claim_paths.is_empty() {
        return Err(Oid4vpError::Configuration(
            "credential type and claims are required",
        ));
    }
    if query.claim_paths.len() > 32
        || query
            .claim_paths
            .iter()
            .any(|path| path.is_empty() || path.len() > 8 || path.iter().any(String::is_empty))
    {
        return Err(Oid4vpError::Configuration("invalid claim paths"));
    }
    Ok(())
}

fn random_secret() -> Result<String, Oid4vpError> {
    let mut bytes = [0_u8; RANDOM_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| Oid4vpError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
