//! Exact owner-approved controller mappings and minimal live RBAC projections.
use crate::{ClientId, DomainError, TenantId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// A controller receives no lifecycle/configuration authority from this binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesBindingChange {
    pub controller_client_id: String,
    pub expected_revision: Option<Uuid>,
    pub enabled: bool,
}
impl KubernetesBindingChange {
    /// Parses a complete CAS command, including an explicit null on creation.
    // fuzz-target: temporary_entitlement_configuration
    pub fn parse(value: serde_json::Value) -> Result<Self, DomainError> {
        if !value
            .as_object()
            .is_some_and(|object| object.contains_key("expected_revision"))
        {
            return Err(DomainError::invalid(
                "expected_revision",
                "explicit null or UUID required",
            ));
        }
        let command: Self = serde_json::from_value(value).map_err(|_| {
            DomainError::invalid(
                "kubernetes_binding",
                "closed controller/revision/enabled command required",
            )
        })?;
        command.validate()?;
        Ok(command)
    }
    // fuzz-target: temporary_entitlement_configuration
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.controller_client_id.is_empty()
            || self.controller_client_id.len() > 200
            || self.controller_client_id.chars().any(char::is_control)
        {
            return Err(DomainError::invalid(
                "controller_client_id",
                "one exact registered client is required",
            ));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesEntitlementBinding {
    pub entitlement_id: Uuid,
    pub revision: Uuid,
    pub controller_client_id: String,
    pub cluster_client_id: String,
    pub cluster: String,
    pub namespace: String,
    pub profile_revision: i64,
    pub enabled: bool,
}
/// Private signed ID-token provenance; never an independently accepted credential.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KubernetesJitIdentity {
    pub binding_revision: Uuid,
    pub entitlement_id: Uuid,
    pub client_id: String,
    pub resource: String,
    pub permissions: Vec<String>,
    pub role: String,
    pub cluster: String,
    pub namespace: String,
    pub profile_revision: i64,
    /// Exclusive Unix-seconds deadline, also bounding the signed ID-token exp.
    pub expires_at: i64,
}

/// This generation-scoped JIT username comes only from the exact public subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesActiveSubject {
    pub activation_id: Uuid,
    pub username: String,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}
/// Complete bounded read, with no reason, assurance, user attributes or credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesAccessProjection {
    pub binding: KubernetesEntitlementBinding,
    pub entitlement_revision: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    pub subjects: Vec<KubernetesActiveSubject>,
}
#[async_trait::async_trait]
pub trait TemporaryKubernetes: std::fmt::Debug + Send + Sync {
    async fn binding(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        entitlement: Uuid,
    ) -> Result<Option<KubernetesEntitlementBinding>, DomainError>;
    async fn replace_binding(
        &self,
        tenant: &TenantId,
        owner: &UserId,
        entitlement: Uuid,
        change: KubernetesBindingChange,
    ) -> Result<KubernetesEntitlementBinding, DomainError>;
    async fn project(
        &self,
        tenant: &TenantId,
        controller: &ClientId,
        entitlement: Uuid,
    ) -> Result<KubernetesAccessProjection, DomainError>;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn temporary_kubernetes_controller_reference_is_exact_and_bounded() {
        for value in ["", "x\nadmin"] {
            assert!(
                KubernetesBindingChange {
                    controller_client_id: value.into(),
                    expected_revision: None,
                    enabled: true
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            KubernetesBindingChange {
                controller_client_id: "controller".into(),
                expected_revision: None,
                enabled: true
            }
            .validate()
            .is_ok()
        );
        assert!(serde_json::from_value::<KubernetesBindingChange>(serde_json::json!({"controller_client_id":"controller","expected_revision":null,"enabled":true,"username":"system:masters"})).is_err());
    }
}
