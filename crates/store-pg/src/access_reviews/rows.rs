//! Stored logical keys are reparsed through the closed review target vocabulary.

use asterius_domain::DomainError;
use asterius_domain::access_reviews::{ApplyStatus, Decision, Item, Ownership, Review, Target};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

pub(super) fn target(kind: &str, keys: Value) -> Result<Target, DomainError> {
    let keys: Vec<String> = serde_json::from_value(keys)
        .map_err(|_| DomainError::invalid("target", "stored logical keys are malformed"))?;
    let uuid = |index: usize| -> Result<Uuid, DomainError> {
        Uuid::parse_str(
            keys.get(index)
                .ok_or_else(|| DomainError::invalid("target", "missing logical key"))?,
        )
        .map_err(|_| DomainError::invalid("target", "stored principal is malformed"))
    };
    let key = |index: usize| -> Result<String, DomainError> {
        keys.get(index)
            .cloned()
            .ok_or_else(|| DomainError::invalid("target", "missing logical key"))
    };
    let value = match (kind, keys.len()) {
        ("membership", 2) => Target::Membership {
            group_id: uuid(0)?,
            user_id: uuid(1)?,
        },
        ("user_tenant_role", 2) => Target::UserTenantRole {
            user_id: uuid(0)?,
            name: key(1)?,
        },
        ("user_client_role", 3) => Target::UserClientRole {
            user_id: uuid(0)?,
            client_id: key(1)?,
            name: key(2)?,
        },
        ("group_tenant_role", 2) => Target::GroupTenantRole {
            group_id: uuid(0)?,
            name: key(1)?,
        },
        ("group_client_role", 3) => Target::GroupClientRole {
            group_id: uuid(0)?,
            client_id: key(1)?,
            name: key(2)?,
        },
        _ => {
            return Err(DomainError::invalid(
                "target",
                "stored target kind or key cardinality is invalid",
            ));
        }
    };
    value.validate()?;
    Ok(value)
}

#[derive(sqlx::FromRow)]
pub(super) struct OwnershipRow {
    pub ownership_id: Uuid,
    pub target_kind: String,
    pub target_keys: Value,
    pub owner_user_id: Option<Uuid>,
    pub reviewers: Vec<Uuid>,
    pub revision: Uuid,
    pub enabled: bool,
}
impl TryFrom<OwnershipRow> for Ownership {
    type Error = DomainError;
    fn try_from(row: OwnershipRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.ownership_id,
            target: target(&row.target_kind, row.target_keys)?,
            owner: row.owner_user_id,
            reviewers: row.reviewers,
            revision: row.revision,
            enabled: row.enabled,
        })
    }
}

#[derive(sqlx::FromRow)]
pub(super) struct ReviewRow {
    pub review_id: Uuid,
    pub created_by: Uuid,
    pub created_at: OffsetDateTime,
    pub due_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    pub cancelled_at: Option<OffsetDateTime>,
}
impl From<ReviewRow> for Review {
    fn from(row: ReviewRow) -> Self {
        Self {
            id: row.review_id,
            created_by: row.created_by,
            created_at: row.created_at,
            due_at: row.due_at,
            completed_at: row.completed_at,
            cancelled_at: row.cancelled_at,
        }
    }
}

#[derive(sqlx::FromRow)]
pub(super) struct ItemRow {
    pub item_id: Uuid,
    pub ownership_id: Uuid,
    pub ownership_revision: Uuid,
    pub target_kind: String,
    pub target_keys: Value,
    pub assignment_generation: Uuid,
    pub assigned_reviewer: Uuid,
    pub snapshot: Value,
    pub decision: Option<String>,
    pub decided_by: Option<Uuid>,
    pub decided_at: Option<OffsetDateTime>,
    pub reason: Option<String>,
    pub apply_status: String,
    pub applied_by: Option<Uuid>,
    pub applied_at: Option<OffsetDateTime>,
}
impl TryFrom<ItemRow> for Item {
    type Error = DomainError;
    fn try_from(row: ItemRow) -> Result<Self, Self::Error> {
        let decision = row
            .decision
            .map(|value| match value.as_str() {
                "retain" => Ok(Decision::Retain),
                "remove" => Ok(Decision::Remove),
                _ => Err(DomainError::invalid("decision", "invalid stored decision")),
            })
            .transpose()?;
        let apply_status = match row.apply_status.as_str() {
            "pending" => ApplyStatus::Pending,
            "retained" => ApplyStatus::Retained,
            "removed" => ApplyStatus::Removed,
            "absent" => ApplyStatus::Absent,
            "conflict" => ApplyStatus::Conflict,
            "protected" => ApplyStatus::Protected,
            _ => {
                return Err(DomainError::invalid(
                    "apply_status",
                    "invalid stored application result",
                ));
            }
        };
        Ok(Self {
            id: row.item_id,
            ownership_id: row.ownership_id,
            ownership_revision: row.ownership_revision,
            target: target(&row.target_kind, row.target_keys)?,
            assignment_generation: row.assignment_generation,
            assigned_reviewer: row.assigned_reviewer,
            snapshot: row.snapshot,
            decision,
            decided_by: row.decided_by,
            decided_at: row.decided_at,
            reason: row.reason,
            apply_status,
            applied_by: row.applied_by,
            applied_at: row.applied_at,
        })
    }
}
