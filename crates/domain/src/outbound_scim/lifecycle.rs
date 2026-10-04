//! Explicit, bounded human approvals; authority is recovered from stored context.

use super::{DeliveryFence, FailureCode, PreparedDelivery, target_etag};
use crate::{DomainError, TenantId, UserId};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleKind {
    Archive,
    Delete,
    Recreate,
}
impl LifecycleKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Delete => "delete",
            Self::Recreate => "recreate",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleCommand {
    pub expected_revision: Uuid,
    pub expected_generation: Uuid,
    pub kind: LifecycleKind,
    #[serde(deserialize_with = "Option::deserialize")]
    pub target: Option<Uuid>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub etag: Option<String>,
    pub confirmed: bool,
}
impl LifecycleCommand {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !self.confirmed
            || self.expected_revision.is_nil()
            || self.expected_generation.is_nil()
            || self.target.is_some_and(|id| id.is_nil())
            || self.target.is_some() != self.etag.is_some()
            || (self.kind == LifecycleKind::Delete && self.target.is_none())
        {
            return Err(DomainError::invalid(
                "lifecycle",
                "explicit confirmation and exact incarnation/version are required",
            ));
        }
        if let Some(etag) = &self.etag {
            target_etag(etag)?;
        }
        Ok(())
    }
}
// fuzz-target: outbound_scim_commands
pub fn parse_lifecycle(bytes: &[u8]) -> Result<LifecycleCommand, DomainError> {
    if bytes.len() > 2048 {
        return Err(DomainError::invalid(
            "lifecycle",
            "request exceeds the bounded size",
        ));
    }
    let command: LifecycleCommand = serde_json::from_slice(bytes)
        .map_err(|_| DomainError::invalid("lifecycle", "malformed lifecycle command"))?;
    command.validate()?;
    Ok(command)
}

#[derive(Debug, Clone)]
pub struct LifecycleRequest {
    pub id: Uuid,
    pub kind: LifecycleKind,
    pub reviewer: UserId,
    pub target: Option<Uuid>,
    pub etag: Option<String>,
    pub expires_at: OffsetDateTime,
    pub delete_admitted: bool,
}
#[derive(Debug, Clone)]
pub struct PreparedLifecycle {
    pub delivery: PreparedDelivery,
    pub request: LifecycleRequest,
}
/// A completed receipt may be acknowledged again without another remote request.
#[derive(Debug)]
pub enum LifecyclePreparation {
    Pending(Box<PreparedLifecycle>),
    Completed,
}
#[derive(Debug, Serialize)]
pub struct LifecycleView {
    pub id: Uuid,
    pub kind: LifecycleKind,
    pub completed: bool,
    pub replacement: Option<Uuid>,
    pub failure_code: Option<String>,
    pub cancelled: bool,
}
/// Receipts carry no arbitrary mapping: a saved target remains fixed throughout.
#[derive(Debug)]
pub struct LifecycleReceipt {
    pub absent: bool,
    pub etag: Option<String>,
}
#[async_trait::async_trait]
pub trait OutboundScimLifecycle: std::fmt::Debug + Send + Sync {
    async fn recent(
        &self,
        tenant: &TenantId,
        connector: Uuid,
        assignment: Uuid,
    ) -> Result<Vec<LifecycleView>, DomainError>;
    async fn enqueue(
        &self,
        tenant: &TenantId,
        actor: UserId,
        connector: Uuid,
        assignment: Uuid,
        command: LifecycleCommand,
    ) -> Result<LifecycleView, DomainError>;
    async fn prepare(
        &self,
        tenant: &TenantId,
        outbox_id: i64,
        attempt: u32,
        request: Uuid,
    ) -> Result<LifecyclePreparation, DomainError>;
    async fn admit(
        &self,
        tenant: &TenantId,
        request: Uuid,
        fence: &DeliveryFence,
        mutating: bool,
        deleting: bool,
    ) -> Result<(), DomainError>;
    async fn complete(
        &self,
        tenant: &TenantId,
        request: Uuid,
        fence: &DeliveryFence,
        receipt: &LifecycleReceipt,
    ) -> Result<(), DomainError>;
    async fn fail(
        &self,
        tenant: &TenantId,
        request: Uuid,
        fence: &DeliveryFence,
        code: FailureCode,
    ) -> Result<(), DomainError>;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_requires_explicit_exact_context_and_refuses_posted_actor() {
        let mut value = serde_json::json!({"expected_revision":Uuid::from_u128(1), "expected_generation":Uuid::from_u128(2), "kind":"delete", "target":Uuid::from_u128(3), "etag":"W/\"4\"", "confirmed":true});
        assert!(parse_lifecycle(&serde_json::to_vec(&value).expect("JSON")).is_ok());
        value["confirmed"] = serde_json::json!(false);
        assert!(parse_lifecycle(&serde_json::to_vec(&value).expect("JSON")).is_err());
        value["confirmed"] = serde_json::json!(true);
        value["actor"] = serde_json::json!("tenant_admin");
        assert!(parse_lifecycle(&serde_json::to_vec(&value).expect("JSON")).is_err());
    }
    #[test]
    fn absent_target_approval_requires_explicit_null_context() {
        let mut value = serde_json::json!({"expected_revision":Uuid::from_u128(1),"expected_generation":Uuid::from_u128(2),"kind":"archive","confirmed":true});
        assert!(parse_lifecycle(&serde_json::to_vec(&value).expect("JSON")).is_err());
        value["target"] = serde_json::Value::Null;
        value["etag"] = serde_json::Value::Null;
        assert!(parse_lifecycle(&serde_json::to_vec(&value).expect("JSON")).is_ok());
    }
    #[test]
    fn deletion_cannot_be_approved_without_a_saved_target_and_version() {
        let command = LifecycleCommand {
            expected_revision: Uuid::from_u128(1),
            expected_generation: Uuid::from_u128(2),
            kind: LifecycleKind::Delete,
            target: None,
            etag: None,
            confirmed: true,
        };
        assert!(command.validate().is_err());
    }
}
