//! Operator-only, tenant-scoped SAML SP trust provisioning.
//!
//! These operations do not expose browser SSO. Exact entity IDs and ACS URLs
//! are stored for a later SSO implementation; no submitted XML is trusted.
//! `allow_unsigned_requests` must be supplied explicitly. It defaults to
//! false in storage. HTTP-Redirect signatures require a separate pinned key;
//! XML Signature verification remains unavailable.

use asterius_domain::{DomainError, TenantId};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

/// Maximum request body for an SP trust mutation.
pub const MAX_BODY_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSp {
    entity_id: String,
    acs_url: String,
    allow_unsigned_requests: bool,
    redirect_signing_public_key_der_base64: Option<String>,
}

/// Validated, exact SP trust values from an administrator.
#[derive(Debug, Clone)]
pub struct NewSp {
    pub entity_id: String,
    pub acs_url: String,
    /// Explicit exception to the default refusal of unsigned requests.
    pub allow_unsigned_requests: bool,
    /// Operator-pinned RSA public key DER, never fetched from request XML.
    pub redirect_signing_public_key_der: Option<Vec<u8>>,
}

/// One SP visible to this tenant's administrator.
#[derive(Debug, Clone, Serialize)]
pub struct SpSummary {
    pub entity_id: String,
    pub acs_url: String,
    /// Whether the unsigned-only internal validator may use this row.
    pub allow_unsigned_requests: bool,
    /// SHA-256 fingerprint of the pinned key, without exposing raw bytes.
    pub redirect_signing_key_sha256: Option<String>,
    pub created_at: OffsetDateTime,
}

/// Parses a bounded trust write with no implicit URL normalization.
pub fn parse_sp(body: &[u8]) -> Result<NewSp, crate::error::AdminError> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(crate::error::AdminError::Invalid(
            "invalid SAML SP trust".to_owned(),
        ));
    }
    let raw: RawSp = serde_json::from_slice(body)
        .map_err(|_| crate::error::AdminError::Invalid("invalid SAML SP trust".to_owned()))?;
    if raw.entity_id.is_empty()
        || raw.entity_id.len() > 1024
        || raw.entity_id.chars().any(char::is_control)
        || raw.acs_url.len() > 2048
        || raw.acs_url.chars().any(char::is_control)
    {
        return Err(crate::error::AdminError::Invalid(
            "invalid SAML SP trust".to_owned(),
        ));
    }
    let url = Url::parse(&raw.acs_url)
        .map_err(|_| crate::error::AdminError::Invalid("invalid SAML SP trust".to_owned()))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(crate::error::AdminError::Invalid(
            "invalid SAML SP trust".to_owned(),
        ));
    }
    let key = raw
        .redirect_signing_public_key_der_base64
        .as_deref()
        .map(|encoded| {
            STANDARD.decode(encoded).map_err(|_| {
                crate::error::AdminError::Invalid("invalid SAML signing key".to_owned())
            })
        })
        .transpose()?;
    if key
        .as_ref()
        .is_some_and(|key| !(256..=4096).contains(&key.len()))
        || (!raw.allow_unsigned_requests && key.is_none())
    {
        return Err(crate::error::AdminError::Invalid(
            "invalid SAML signing key".to_owned(),
        ));
    }
    Ok(NewSp {
        entity_id: raw.entity_id,
        acs_url: raw.acs_url,
        allow_unsigned_requests: raw.allow_unsigned_requests,
        redirect_signing_public_key_der: key,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntity {
    entity_id: String,
}

/// Parses an exact entity ID for removal.
pub fn parse_entity(body: &[u8]) -> Result<String, crate::error::AdminError> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(crate::error::AdminError::Invalid(
            "invalid SAML SP entity ID".to_owned(),
        ));
    }
    let raw: RawEntity = serde_json::from_slice(body)
        .map_err(|_| crate::error::AdminError::Invalid("invalid SAML SP entity ID".to_owned()))?;
    if raw.entity_id.is_empty()
        || raw.entity_id.len() > 1024
        || raw.entity_id.chars().any(char::is_control)
    {
        return Err(crate::error::AdminError::Invalid(
            "invalid SAML SP entity ID".to_owned(),
        ));
    }
    Ok(raw.entity_id)
}

/// A deliberately narrow administration port. No replay reservation or SSO
/// issuance method is reachable through the operator API.
#[async_trait::async_trait]
pub trait SpAdministration: Send + Sync {
    async fn list(&self, tenant: &TenantId) -> Result<Vec<SpSummary>, DomainError>;
    async fn provision(&self, tenant: &TenantId, sp: &NewSp) -> Result<bool, DomainError>;
    async fn remove(&self, tenant: &TenantId, entity_id: &str) -> Result<bool, DomainError>;
}
