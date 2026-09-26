//! Operator-only, tenant-scoped SAML SP trust provisioning.
//!
//! These operations do not expose browser SSO. Exact entity IDs and ACS URLs
//! are stored for a later SSO implementation; no submitted XML is trusted.
//! `allow_unsigned_requests` must be supplied explicitly. It defaults to
//! false in storage. HTTP-Redirect signatures require a separate pinned key;
//! XML Signature verification is handled by the server's strict POST profile.

use asterius_domain::{DomainError, TenantId};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;
use zeroize::{Zeroize as _, Zeroizing};

/// Maximum request body for an SP trust mutation.
pub const MAX_BODY_BYTES: usize = 4 * 1024;
/// A certificate and RSA PKCS#8 key can each be 16 KiB before base64.
pub const MAX_IDP_KEY_BODY_BYTES: usize = 48 * 1024;
/// A SHA-256 fingerprint in a small JSON management action.
pub const MAX_IDP_KEY_ACTION_BYTES: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdpKey {
    certificate_der_base64: String,
    private_key_pkcs8_der_base64: String,
}

impl Drop for RawIdpKey {
    fn drop(&mut self) {
        self.private_key_pkcs8_der_base64.zeroize();
    }
}

/// Secret input. Debug output and admin responses never contain private DER.
pub struct NewIdpKey {
    pub certificate_der: Vec<u8>,
    pub private_key_pkcs8: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for NewIdpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewIdpKey")
            .field("certificate_len", &self.certificate_der.len())
            .finish_non_exhaustive()
    }
}

/// Only public material is returned by the administration port.
#[derive(Debug, Clone, Serialize)]
pub struct IdpKeySummary {
    /// `pending`, `active`, or `retiring`; none enables browser SSO.
    pub state: String,
    pub certificate_sha256: String,
    pub certificate_der_base64: String,
    pub created_at: OffsetDateTime,
}

/// Parses one bounded operator key import; cryptographic validation is done
/// by the deployment before any material is sealed or stored.
pub fn parse_idp_key(body: &[u8]) -> Result<NewIdpKey, crate::error::AdminError> {
    if body.is_empty() || body.len() > MAX_IDP_KEY_BODY_BYTES {
        return Err(crate::error::AdminError::Invalid(
            "invalid SAML IdP key".to_owned(),
        ));
    }
    let raw: RawIdpKey = serde_json::from_slice(body)
        .map_err(|_| crate::error::AdminError::Invalid("invalid SAML IdP key".to_owned()))?;
    let certificate_der = STANDARD
        .decode(&raw.certificate_der_base64)
        .map_err(|_| crate::error::AdminError::Invalid("invalid SAML IdP key".to_owned()))?;
    let private_key_pkcs8 = Zeroizing::new(
        STANDARD
            .decode(&raw.private_key_pkcs8_der_base64)
            .map_err(|_| crate::error::AdminError::Invalid("invalid SAML IdP key".to_owned()))?,
    );
    if !(256..=16_384).contains(&certificate_der.len())
        || !(256..=16_384).contains(&private_key_pkcs8.len())
    {
        return Err(crate::error::AdminError::Invalid(
            "invalid SAML IdP key".to_owned(),
        ));
    }
    Ok(NewIdpKey {
        certificate_der,
        private_key_pkcs8,
    })
}

#[async_trait::async_trait]
pub trait IdpKeyAdministration: Send + Sync {
    async fn inspect(&self, tenant: &TenantId) -> Result<Vec<IdpKeySummary>, DomainError>;
    async fn provision(&self, tenant: &TenantId, key: &NewIdpKey) -> Result<bool, DomainError>;
    async fn activate(
        &self,
        tenant: &TenantId,
        certificate_sha256: &str,
    ) -> Result<bool, DomainError>;
    async fn retire(
        &self,
        tenant: &TenantId,
        certificate_sha256: &str,
    ) -> Result<bool, DomainError>;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeyAction {
    certificate_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRetirementAction {
    certificate_sha256: String,
    rollover_confirmed: bool,
}

/// One canonical lowercase SHA-256 certificate fingerprint.
pub fn parse_key_action(body: &[u8]) -> Result<String, crate::error::AdminError> {
    if body.is_empty() || body.len() > MAX_IDP_KEY_ACTION_BYTES {
        return Err(crate::error::AdminError::Invalid(
            "invalid SAML key action".to_owned(),
        ));
    }
    let raw: RawKeyAction = serde_json::from_slice(body)
        .map_err(|_| crate::error::AdminError::Invalid("invalid SAML key action".to_owned()))?;
    valid_fingerprint(raw.certificate_sha256)
}

/// Requires an affirmative operator statement that SP rollover is complete.
pub fn parse_retirement_action(body: &[u8]) -> Result<String, crate::error::AdminError> {
    if body.is_empty() || body.len() > MAX_IDP_KEY_ACTION_BYTES {
        return Err(crate::error::AdminError::Invalid(
            "invalid SAML key retirement".to_owned(),
        ));
    }
    let raw: RawRetirementAction = serde_json::from_slice(body)
        .map_err(|_| crate::error::AdminError::Invalid("invalid SAML key retirement".to_owned()))?;
    if !raw.rollover_confirmed {
        return Err(crate::error::AdminError::Invalid(
            "SP rollover must be confirmed".to_owned(),
        ));
    }
    valid_fingerprint(raw.certificate_sha256)
}

fn valid_fingerprint(value: String) -> Result<String, crate::error::AdminError> {
    if value.len() != 64
        || hex::decode(&value).is_err()
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(crate::error::AdminError::Invalid(
            "invalid SAML key action".to_owned(),
        ));
    }
    Ok(value)
}

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
