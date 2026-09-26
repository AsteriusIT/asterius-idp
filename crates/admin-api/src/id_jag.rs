//! Operator-owned ID-JAG issuer/subject to local-account bindings.
//!
//! A binding resolves identity only. It cannot create owner consent or approve
//! scopes, and its upstream subject is never put into audit detail.

use asterius_domain::{DomainError, Issuer, TenantId};
use serde::Deserialize;
use uuid::Uuid;

/// Maximum operator mapping request body.
pub const MAX_BODY_BYTES: usize = 8 * 1024;

/// Exact external identity and local account named by an operator.
#[derive(Debug, Clone)]
pub struct SubjectBinding {
    pub issuer: Issuer,
    pub subject: String,
    pub user: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBinding {
    issuer: String,
    subject: String,
    user_id: Uuid,
}

/// Parses one bounded mapping request without accepting implicit identities.
pub fn parse_binding(body: &[u8]) -> Result<SubjectBinding, crate::error::AdminError> {
    let raw: RawBinding = serde_json::from_slice(body).map_err(|_| {
        crate::error::AdminError::Invalid("invalid ID-JAG subject binding".to_owned())
    })?;
    let issuer = Issuer::parse(&raw.issuer).map_err(|_| {
        crate::error::AdminError::Invalid("issuer must be a canonical HTTPS URL".to_owned())
    })?;
    if issuer.as_str() != raw.issuer
        || raw.subject.is_empty()
        || raw.subject.len() > 512
        || raw.subject.chars().any(char::is_control)
    {
        return Err(crate::error::AdminError::Invalid(
            "issuer or subject is invalid".to_owned(),
        ));
    }
    Ok(SubjectBinding {
        issuer,
        subject: raw.subject,
        user: raw.user_id,
    })
}

/// Tenant-scoped mutations backed by the deployment's pinned issuer trust.
#[async_trait::async_trait]
pub trait IdJagBindings: Send + Sync {
    async fn bind(&self, tenant: &TenantId, binding: &SubjectBinding) -> Result<(), DomainError>;
    async fn remove(
        &self,
        tenant: &TenantId,
        binding: &SubjectBinding,
    ) -> Result<bool, DomainError>;
}
