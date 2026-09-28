//! Administration of tenant-scoped upstream OpenID Connect registrations.

use asterius_domain::audit::Actor;
use asterius_domain::{DomainError, TenantId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;
use zeroize::Zeroize;

pub const MAX_BODY_BYTES: usize = 8 * 1024;
pub const CALLBACK_PATH: &str = "/oidc/upstream/callback/";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProvider {
    id: String,
    name: String,
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
    enabled: bool,
    #[serde(default)]
    allow_registration: bool,
}

impl Drop for RawProvider {
    fn drop(&mut self) {
        if let Some(secret) = &mut self.client_secret {
            secret.zeroize();
        }
    }
}

pub struct ProviderInput {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<zeroize::Zeroizing<String>>,
    pub enabled: bool,
    pub allow_registration: bool,
}

impl std::fmt::Debug for ProviderInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderInput")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderSummary {
    pub id: String,
    pub name: String,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    pub enabled: bool,
    pub allow_registration: bool,
    pub secret_configured: bool,
    pub callback_url: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityBinding {
    pub provider_id: String,
    pub issuer: String,
    pub upstream_subject: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityInput {
    pub provider_id: String,
    pub issuer: String,
    pub upstream_subject: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawId {
    id: String,
}

#[must_use]
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 63
        && id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && (byte == b'_' || byte == b'-'))
        })
}

pub fn parse_provider(body: &[u8]) -> Result<ProviderInput, crate::error::AdminError> {
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return Err(invalid());
    }
    let mut raw: RawProvider = serde_json::from_slice(body).map_err(|_| invalid())?;
    if !valid_id(&raw.id)
        || raw.name.is_empty()
        || raw.name.len() > 120
        || raw.name.trim() != raw.name
        || raw.name.chars().any(char::is_control)
        || raw.client_id.is_empty()
        || raw.client_id.len() > 512
        || raw.client_id.chars().any(char::is_control)
        || raw.client_secret.as_ref().is_some_and(|secret| {
            secret.is_empty() || secret.len() > 4096 || secret.chars().any(char::is_control)
        })
        || validate_https_url(&raw.issuer).is_err()
    {
        return Err(invalid());
    }
    let issuer = Url::parse(&raw.issuer).map_err(|_| invalid())?;
    if issuer.query().is_some()
        || issuer.fragment().is_some()
        || issuer.as_str().trim_end_matches('/') != raw.issuer.trim_end_matches('/')
    {
        return Err(invalid());
    }
    Ok(ProviderInput {
        id: std::mem::take(&mut raw.id),
        name: std::mem::take(&mut raw.name),
        issuer: std::mem::take(&mut raw.issuer),
        client_id: std::mem::take(&mut raw.client_id),
        client_secret: raw.client_secret.take().map(zeroize::Zeroizing::new),
        enabled: raw.enabled,
        allow_registration: raw.allow_registration,
    })
}

pub fn parse_id(body: &[u8]) -> Result<String, crate::error::AdminError> {
    if body.is_empty() || body.len() > 128 {
        return Err(invalid());
    }
    let raw: RawId = serde_json::from_slice(body).map_err(|_| invalid())?;
    if !valid_id(&raw.id) {
        return Err(invalid());
    }
    Ok(raw.id)
}

/// Exact callback value to register with the upstream provider.
#[must_use]
pub fn callback_url(tenant_issuer: &str, id: &str) -> String {
    format!("{}{CALLBACK_PATH}{id}", tenant_issuer.trim_end_matches('/'))
}

/// Discovery URL per OIDC Discovery §4: well-known path appended to issuer.
#[must_use]
pub fn discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

pub fn validate_https_url(raw: &str) -> Result<(), DomainError> {
    if raw.len() > 2048 {
        return Err(DomainError::invalid("oidc_provider", "URL too long"));
    }
    let url = Url::parse(raw).map_err(|_| DomainError::invalid("oidc_provider", "invalid URL"))?;
    if url.scheme() != "https"
        || !url
            .host_str()
            .is_some_and(|host| host.contains('.') && !host.ends_with('.'))
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || url.as_str().trim_end_matches('/') != raw.trim_end_matches('/')
    {
        return Err(DomainError::invalid("oidc_provider", "invalid HTTPS URL"));
    }
    Ok(())
}

#[async_trait::async_trait]
pub trait ProviderAdministration: Send + Sync {
    async fn list_bindings(
        &self,
        _tenant: &TenantId,
        _user: UserId,
    ) -> Result<Vec<IdentityBinding>, DomainError> {
        Err(DomainError::NotFound)
    }
    async fn link_identity(
        &self,
        _tenant: &TenantId,
        _user: UserId,
        _identity: IdentityInput,
        _actor: Actor,
    ) -> Result<(), DomainError> {
        Err(DomainError::NotFound)
    }
    async fn unlink_identity(
        &self,
        _tenant: &TenantId,
        _user: UserId,
        _identity: IdentityInput,
        _actor: Actor,
    ) -> Result<bool, DomainError> {
        Err(DomainError::NotFound)
    }
    async fn list(
        &self,
        tenant: &TenantId,
        tenant_issuer: &str,
    ) -> Result<Vec<ProviderSummary>, DomainError>;
    async fn put(
        &self,
        tenant: &TenantId,
        tenant_issuer: &str,
        input: ProviderInput,
    ) -> Result<ProviderSummary, DomainError>;
    async fn delete(&self, tenant: &TenantId, id: &str) -> Result<bool, DomainError>;
}

fn invalid() -> crate::error::AdminError {
    crate::error::AdminError::Invalid("invalid OIDC identity provider".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_input_rejects_unsafe_and_ambiguous_urls() {
        for issuer in [
            "http://idp.example",
            "https://localhost/",
            "https://user@idp.example/",
            "https://idp.example/?x=1",
            "https://idp.example/#x",
        ] {
            let input = serde_json::json!({"id":"corp", "name":"Corporate", "issuer":issuer,
                "client_id":"client", "client_secret":"secret", "enabled":false});
            assert!(
                parse_provider(input.to_string().as_bytes()).is_err(),
                "{issuer}"
            );
        }
    }

    #[test]
    fn input_debug_and_summary_never_expose_secret() {
        let body = br#"{"id":"corp","name":"Corporate","issuer":"https://idp.example","client_id":"client","client_secret":"top-secret","enabled":true}"#;
        let input = parse_provider(body).expect("valid input");
        assert!(!format!("{input:?}").contains("top-secret"));
        assert_eq!(
            callback_url("https://as.example/t/acme", "corp"),
            "https://as.example/t/acme/oidc/upstream/callback/corp"
        );
    }
}
