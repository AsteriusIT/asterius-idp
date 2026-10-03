//! Tenant-bound commands carry no credential bytes or posted actor authority.

use super::{Assignment, Connector, CredentialBinding, Projection, ResourceKind, canonical_issuer};
use crate::{ClientId, DomainError, TenantId, UserId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize)]
pub struct CredentialDescriptor {
    pub reference: String,
    pub generation: Uuid,
    pub target_issuer: String,
    pub target_client: String,
}
impl std::fmt::Debug for CredentialDescriptor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialDescriptor")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize)]
pub struct ConnectorPreview {
    pub connector: Uuid,
    pub revision: Uuid,
    pub filter_supported: bool,
    pub etag_supported: bool,
}

#[async_trait::async_trait]
pub trait OutboundScimInspection: std::fmt::Debug + Send + Sync {
    /// Token authentication and SCIM GET only; no target mapping is accepted.
    async fn preview(
        &self,
        tenant: &TenantId,
        actor: UserId,
        connector: Uuid,
        expected_revision: Uuid,
    ) -> Result<ConnectorPreview, DomainError>;
}

/// Immutable deployment catalogue; no path/key material crosses this boundary.
pub trait OutboundScimCredentialCatalogue: std::fmt::Debug + Send + Sync {
    fn available(&self, binding: &CredentialBinding) -> bool;
    fn descriptors(&self, tenant: &TenantId) -> Vec<CredentialDescriptor>;
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureConnector {
    pub id: Uuid,
    pub expected_revision: Option<Uuid>,
    pub target_issuer: String,
    pub target_client: String,
    pub credential_ref: String,
    pub credential_generation: Uuid,
    pub enabled: bool,
    pub allow_reviewed_delete: bool,
}
impl std::fmt::Debug for ConfigureConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfigureConnector")
            .field("id", &self.id)
            .field("expected_revision", &self.expected_revision)
            .finish_non_exhaustive()
    }
}
impl ConfigureConnector {
    pub fn binding(&self, tenant: &TenantId) -> Result<CredentialBinding, DomainError> {
        let issuer = canonical_issuer(&self.target_issuer)?;
        if self.id.is_nil()
            || self.credential_generation.is_nil()
            || self
                .expected_revision
                .is_some_and(|revision| revision.is_nil())
            || self.target_client.is_empty()
            || self.target_client.len() > 2048
            || self.credential_ref.is_empty()
            || self.credential_ref.len() > 64
            || !self
                .credential_ref
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !self
                .credential_ref
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(DomainError::invalid(
                "connector",
                "invalid bounded connector configuration",
            ));
        }
        Ok(CredentialBinding {
            reference: self.credential_ref.clone(),
            generation: self.credential_generation,
            source_tenant: tenant.clone(),
            target_admin_resource: format!("{}/admin/api/v1", self.target_issuer),
            scim_origin: issuer.origin().ascii_serialization(),
            target_issuer: self.target_issuer.clone(),
            target_client: ClientId::new(&self.target_client),
        })
    }
}

#[derive(Clone, Serialize)]
pub struct ConnectorView {
    pub id: Uuid,
    pub revision: Uuid,
    pub target_issuer: String,
    pub target_client: String,
    pub credential_ref: String,
    pub credential_generation: Uuid,
    pub enabled: bool,
    pub allow_reviewed_delete: bool,
}
impl std::fmt::Debug for ConnectorView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectorView")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}
impl From<Connector> for ConnectorView {
    fn from(connector: Connector) -> Self {
        Self {
            id: connector.id,
            revision: connector.revision,
            target_issuer: connector.target_issuer,
            target_client: connector.target_client.as_str().to_owned(),
            credential_ref: connector.credential.reference,
            credential_generation: connector.credential.generation,
            enabled: connector.enabled,
            allow_reviewed_delete: connector.allow_reviewed_delete,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AssignmentView {
    pub id: Uuid,
    pub kind: String,
    pub source: Uuid,
    pub generation: Uuid,
    pub selected: bool,
    pub target: Option<Uuid>,
    pub state: String,
    pub failure_code: Option<String>,
    pub dirty: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectSources {
    pub expected_revision: Uuid,
    pub kind: String,
    pub sources: Vec<Uuid>,
}
impl SelectSources {
    pub fn kind(&self) -> Result<ResourceKind, DomainError> {
        let unique: std::collections::BTreeSet<_> = self.sources.iter().copied().collect();
        if self.expected_revision.is_nil()
            || self.sources.is_empty()
            || self.sources.len() > 100
            || unique.len() != self.sources.len()
            || unique.contains(&Uuid::nil())
        {
            return Err(DomainError::invalid(
                "sources",
                "one to one hundred distinct local sources are required",
            ));
        }
        match self.kind.as_str() {
            "user" => Ok(ResourceKind::User),
            "group" => Ok(ResourceKind::Group),
            _ => Err(DomainError::invalid("kind", "user or group is required")),
        }
    }
}

/// Strict parsing also refuses posted scopes, private keys, actors or snapshots.
// fuzz-target: outbound_scim_commands
pub fn parse_configure(bytes: &[u8]) -> Result<ConfigureConnector, DomainError> {
    if bytes.len() > 8192 {
        return Err(DomainError::invalid(
            "connector",
            "request exceeds the bounded size",
        ));
    }
    let command: ConfigureConnector = serde_json::from_slice(bytes)
        .map_err(|_| DomainError::invalid("connector", "malformed connector command"))?;
    command.binding(&TenantId::new("validation"))?;
    Ok(command)
}
// fuzz-target: outbound_scim_commands
pub fn parse_selection(bytes: &[u8]) -> Result<SelectSources, DomainError> {
    if bytes.len() > 8192 {
        return Err(DomainError::invalid(
            "sources",
            "request exceeds the bounded size",
        ));
    }
    let command: SelectSources = serde_json::from_slice(bytes)
        .map_err(|_| DomainError::invalid("sources", "malformed selection command"))?;
    command.kind()?;
    Ok(command)
}

/// A read-only source projection for peer preview; no delivery lease or mutation.
#[derive(Debug, Clone)]
pub struct PreviewSelection {
    pub connector: Connector,
    pub assignment: Assignment,
    pub projection: Projection,
}

#[async_trait::async_trait]
pub trait OutboundScimAdministration: std::fmt::Debug + Send + Sync {
    async fn preview_connector(
        &self,
        tenant: &TenantId,
        connector: Uuid,
        expected_revision: Uuid,
    ) -> Result<Connector, DomainError>;
    async fn preview_selection(
        &self,
        tenant: &TenantId,
        connector: Uuid,
        assignment: Uuid,
        expected_revision: Uuid,
    ) -> Result<PreviewSelection, DomainError>;
    async fn record_preview(
        &self,
        tenant: &TenantId,
        actor: UserId,
        connector: Uuid,
        expected_revision: Uuid,
    ) -> Result<(), DomainError>;
    async fn read(&self, tenant: &TenantId, connector: Uuid) -> Result<ConnectorView, DomainError>;
    async fn list(
        &self,
        tenant: &TenantId,
        after: Option<Uuid>,
        limit: u16,
    ) -> Result<Vec<ConnectorView>, DomainError>;
    async fn configure(
        &self,
        tenant: &TenantId,
        actor: UserId,
        command: ConfigureConnector,
    ) -> Result<ConnectorView, DomainError>;
    async fn assignments(
        &self,
        tenant: &TenantId,
        connector: Uuid,
        after: Option<Uuid>,
        limit: u16,
    ) -> Result<Vec<AssignmentView>, DomainError>;
    async fn select(
        &self,
        tenant: &TenantId,
        actor: UserId,
        connector: Uuid,
        command: SelectSources,
    ) -> Result<Vec<AssignmentView>, DomainError>;
    async fn unselect(
        &self,
        tenant: &TenantId,
        actor: UserId,
        connector: Uuid,
        assignment: Uuid,
        expected_revision: Uuid,
    ) -> Result<(), DomainError>;
    async fn reconcile(
        &self,
        tenant: &TenantId,
        actor: UserId,
        connector: Uuid,
        expected_revision: Uuid,
        after: Option<Uuid>,
    ) -> Result<Option<Uuid>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selection_refuses_duplicates_and_posted_privileged_context() {
        let id = Uuid::from_u128(1);
        let revision = Uuid::from_u128(2);
        let duplicate =
            serde_json::json!({"kind":"user","expected_revision":revision,"sources":[id,id]});
        assert!(parse_selection(&serde_json::to_vec(&duplicate).expect("JSON")).is_err());
        let posted = serde_json::json!({"kind":"user","expected_revision":revision,"sources":[id],"actor":"admin"});
        assert!(parse_selection(&serde_json::to_vec(&posted).expect("JSON")).is_err());
    }
}
