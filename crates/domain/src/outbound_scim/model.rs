//! Prepared outbound lifecycle model; not exported or enabled before ADR review.

use crate::{ClientId, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

/// Every reference is resolved through a deployment allow-list, never a client path.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialBinding {
    pub reference: String,
    pub generation: Uuid,
    pub source_tenant: TenantId,
    pub target_admin_resource: String,
    pub scim_origin: String,
    pub target_issuer: String,
    pub target_client: ClientId,
}

impl std::fmt::Debug for CredentialBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialBinding")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// Immutable principal pins survive rotations of the same client's credential.
#[derive(Clone, PartialEq, Eq)]
pub struct Connector {
    pub tenant: TenantId,
    pub id: Uuid,
    pub revision: Uuid,
    pub target_issuer: String,
    pub target_client: ClientId,
    pub credential: CredentialBinding,
    pub enabled: bool,
    pub allow_reviewed_delete: bool,
}

impl std::fmt::Debug for Connector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Connector")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    User,
    Group,
}

/// Recreated assignments retain their predecessors as historical tombstones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    pub id: Uuid,
    pub connector: Uuid,
    pub kind: ResourceKind,
    pub source: Uuid,
    pub generation: Uuid,
    pub desired_revision: Uuid,
    pub selected: bool,
    pub target: Option<Uuid>,
    pub observed_etag: Option<String>,
    pub retired_at: Option<OffsetDateTime>,
}

/// The worker may complete only the still-current claimed attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryFence {
    pub outbox_id: i64,
    pub attempt: u32,
    pub connector_revision: Uuid,
    pub credential_generation: Uuid,
    pub assignment_generation: Uuid,
    pub desired_revision: Uuid,
    pub deadline: OffsetDateTime,
}

/// IDs and fixed codes are safe for API, audit and dead-letter evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCode {
    Paused,
    CredentialUnavailable,
    CredentialBindingMismatch,
    AuthenticationRefused,
    TargetUnavailable,
    OwnershipMismatch,
    TargetAbsent,
    TargetVersionChanged,
    SourceProtected,
    SourceProjectionInvalid,
    UserDependenciesPending,
    SnapshotBoundExceeded,
    LeaseSuperseded,
}

/// Personal source attributes are read just before delivery and never queued.
#[derive(Clone, PartialEq, Eq)]
pub struct UserProjection {
    pub immutable_alias: String,
    pub external_id: String,
    pub work_email: Option<String>,
    pub active: bool,
}

impl std::fmt::Debug for UserProjection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UserProjection")
            .field("email_present", &self.work_email.is_some())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

/// Complete direct member projections contain only previously verified UUIDs.
#[derive(Clone, PartialEq, Eq)]
pub struct GroupProjection {
    pub immutable_alias: String,
    pub external_id: String,
    pub target_members: Vec<Uuid>,
}

impl std::fmt::Debug for GroupProjection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GroupProjection")
            .field("member_count", &self.target_members.len())
            .finish_non_exhaustive()
    }
}

/// A mapping receipt follows ownership verification, never an arbitrary Location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingReceipt {
    pub target: Uuid,
    pub etag: String,
    pub observed_at: OffsetDateTime,
}

/// Reviewed deletion is a separate command, tied to one retained UUID and owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedDelete {
    pub id: Uuid,
    pub assignment: Uuid,
    pub assignment_generation: Uuid,
    pub target: Uuid,
    pub connector_revision: Uuid,
    pub reviewed_by: Uuid,
    pub reviewed_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
}
