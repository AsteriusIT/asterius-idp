//! Prepared worker boundary; no runtime registration until contract acceptance.

use super::model::{Assignment, Connector, DeliveryFence, FailureCode, MappingReceipt};
use crate::{DomainError, TenantId};
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
    ) -> Result<(Connector, Assignment, DeliveryFence), DomainError>;

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
