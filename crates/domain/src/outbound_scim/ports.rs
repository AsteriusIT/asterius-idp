//! Candidate worker boundary; contract review gates delivery and deployment.

use super::model::{
    CredentialBinding, DeliveryFence, FailureCode, MappingReceipt, PreparedDelivery,
};
use crate::{DomainError, Secret, TenantId};
use uuid::Uuid;

/// Loading never holds a database transaction while a remote request is in flight.
#[async_trait::async_trait]
pub trait OutboundScimJobs: std::fmt::Debug + Send + Sync {
    async fn prepare(
        &self,
        tenant: &TenantId,
        outbox_id: i64,
        attempt: u32,
        assignment: Uuid,
    ) -> Result<PreparedDelivery, DomainError>;

    /// Authorize one new network dispatch against the current source revision.
    /// Already admitted remote effects cannot be cancelled by a later pause.
    async fn admit(
        &self,
        tenant: &TenantId,
        assignment: Uuid,
        fence: &DeliveryFence,
        creating: bool,
    ) -> Result<(), DomainError>;

    /// Compare every context pin and current lease before advancing a receipt.
    /// A different existing target UUID is always an ownership conflict.
    async fn complete(
        &self,
        tenant: &TenantId,
        assignment: Uuid,
        fence: &DeliveryFence,
        receipt: &MappingReceipt,
    ) -> Result<(), DomainError>;

    /// Only fixed codes cross into persisted worker diagnostics.
    async fn fail(
        &self,
        tenant: &TenantId,
        assignment: Uuid,
        fence: &DeliveryFence,
        code: FailureCode,
    ) -> Result<(), DomainError>;
}

/// A scoped signing operation, not an arbitrary secret/key/path resolver.
#[async_trait::async_trait]
pub trait OutboundScimCredentials: std::fmt::Debug + Send + Sync {
    /// Resolve every source/target context pin in the deployment registry, then
    /// mint a fresh bounded assertion using the adapter's trusted clock/jti.
    /// The tenant caller cannot provide arbitrary claims or select a raw key.
    async fn assertion(&self, binding: &CredentialBinding) -> Result<Secret<String>, DomainError>;
}
