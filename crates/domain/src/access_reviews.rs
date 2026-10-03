//! Tenant-scoped reviews of standing access; decisions never grant authority.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{DomainError, RoleName, TenantId, UserId};

/// A single provenance source, rather than a user's union of effective roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Membership { group_id: Uuid, user_id: Uuid },
    UserTenantRole { user_id: Uuid, name: String },
    UserClientRole { user_id: Uuid, client_id: String, name: String },
    GroupTenantRole { group_id: Uuid, name: String },
    GroupClientRole { group_id: Uuid, client_id: String, name: String },
}

impl Target {
    /// Reuses the role catalogue parser and bounds exact opaque client identity.
    pub fn validate(&self) -> Result<(), DomainError> {
        let principal = match self {
            Self::Membership { group_id, user_id } => {
                if user_id.is_nil() { return Err(DomainError::invalid("user_id", "must not be nil")); }
                group_id
            }
            Self::UserTenantRole { user_id, .. } | Self::UserClientRole { user_id, .. } => user_id,
            Self::GroupTenantRole { group_id, .. } | Self::GroupClientRole { group_id, .. } => group_id,
        };
        if principal.is_nil() { return Err(DomainError::invalid("target", "principal must not be nil")); }
        let (name, client) = match self {
            Self::Membership { .. } => return Ok(()),
            Self::UserTenantRole { name, .. } | Self::GroupTenantRole { name, .. } => (name, None),
            Self::UserClientRole { name, client_id, .. } | Self::GroupClientRole { name, client_id, .. } => (name, Some(client_id)),
        };
        RoleName::parse(name).map_err(|error| DomainError::invalid("name", error.to_string()))?;
        if let Some(client) = client
            && (client.is_empty() || client.len()>2048 || client.chars().any(|character|character.is_control()||character.is_whitespace())) {
            return Err(DomainError::invalid("client_id","an exact bounded client identifier is required"));
        }
        Ok(())
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Membership { .. } => "membership",
            Self::UserTenantRole { .. } => "user_tenant_role",
            Self::UserClientRole { .. } => "user_client_role",
            Self::GroupTenantRole { .. } => "group_tenant_role",
            Self::GroupClientRole { .. } => "group_client_role",
        }
    }

    /// Canonical logical key; generation is deliberately a separate value.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        match self {
            Self::Membership { group_id, user_id } => vec![group_id.to_string(), user_id.to_string()],
            Self::UserTenantRole { user_id, name } => vec![user_id.to_string(), name.clone()],
            Self::UserClientRole { user_id, client_id, name } => vec![user_id.to_string(), client_id.clone(), name.clone()],
            Self::GroupTenantRole { group_id, name } => vec![group_id.to_string(), name.clone()],
            Self::GroupClientRole { group_id, client_id, name } => vec![group_id.to_string(), client_id.clone(), name.clone()],
        }
    }
}

/// Current eligible human reviewer; naming one never grants a role.
#[derive(Debug, Clone, Serialize)]
pub struct Reviewer { pub user_id:Uuid,pub username:String }

/// Current explicit ownership; a deleted owner invalidates it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ownership {
    pub id: Uuid,
    pub target: Target,
    pub owner: Option<Uuid>,
    pub reviewers: Vec<Uuid>,
    pub revision: Uuid,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision { Retain, Remove }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStatus { Pending, Retained, Removed, Absent, Conflict, Protected }

/// An immutable assignment/provenance snapshot plus independent decision/application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    pub ownership_id: Uuid,
    pub ownership_revision: Uuid,
    pub target: Target,
    pub assignment_generation: Uuid,
    pub assigned_reviewer: Uuid,
    pub snapshot: Value,
    pub decision: Option<Decision>,
    pub decided_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub decided_at: Option<OffsetDateTime>,
    pub reason: Option<String>,
    pub apply_status: ApplyStatus,
    pub applied_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub applied_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    pub id: Uuid,
    pub created_by: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub due_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub completed_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub cancelled_at: Option<OffsetDateTime>,
}

/// Explicit assignment; reviewers never gain authority merely from configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureOwnership {
    pub target: Target,
    pub owner_user_id: Uuid,
    pub reviewers: Vec<Uuid>,
    pub enabled: bool,
    pub expected_revision: Option<Uuid>,
}

/// Bounded server-selected snapshot request, never a client-supplied access snapshot.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartReview {
    pub ownership_ids: Vec<Uuid>,
    pub reviewer_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub due_at: OffsetDateTime,
}

impl ConfigureOwnership {
    pub fn validate(&self) -> Result<(), DomainError> {
        self.target.validate()?;
        let distinct: BTreeSet<_> = self.reviewers.iter().copied().collect();
        if self.owner_user_id.is_nil() || self.reviewers.is_empty() || self.reviewers.len() > 20
            || distinct.len() != self.reviewers.len() || distinct.contains(&Uuid::nil()) {
            return Err(DomainError::invalid("ownership", "one active owner and one to twenty distinct reviewers are required"));
        }
        Ok(())
    }
}

impl StartReview {
    pub fn validate(&self, now: OffsetDateTime) -> Result<(), DomainError> {
        let distinct: BTreeSet<_> = self.ownership_ids.iter().copied().collect();
        if self.ownership_ids.is_empty() || self.ownership_ids.len() > 200
            || distinct.len() != self.ownership_ids.len() || distinct.contains(&Uuid::nil())
            || self.reviewer_id.is_nil() || self.due_at <= now || self.due_at > now + Duration::days(90) {
            return Err(DomainError::invalid("review", "one to two hundred distinct assignments and a future deadline within ninety days are required"));
        }
        Ok(())
    }
}

/// Existing administrative authority is required at composition; actor is trusted context.
#[async_trait::async_trait]
pub trait AccessReviews: Send + Sync {
    async fn reviewers(&self, tenant: &TenantId, after: Option<Uuid>, limit: u16) -> Result<Vec<Reviewer>, DomainError>;
    async fn ownerships(&self, tenant: &TenantId, after: Option<Uuid>, limit: u16) -> Result<Vec<Ownership>, DomainError>;
    async fn configure(&self, tenant: &TenantId, actor: UserId, request: ConfigureOwnership) -> Result<Ownership, DomainError>;
    async fn start(&self, tenant: &TenantId, actor: UserId, request: StartReview) -> Result<Review, DomainError>;
    async fn review(&self, tenant: &TenantId, actor: UserId, administrative: bool, id: Uuid) -> Result<Review, DomainError>;
    async fn reviews(&self, tenant: &TenantId, actor: UserId, administrative: bool, after: Option<Uuid>, limit: u16) -> Result<Vec<Review>, DomainError>;
    async fn items(&self, tenant: &TenantId, actor: UserId, administrative: bool, review: Uuid, after: Option<Uuid>, limit: u16) -> Result<Vec<Item>, DomainError>;
    async fn decide(&self, tenant: &TenantId, actor: UserId, review: Uuid, item: Uuid, decision: Decision, reason: String) -> Result<Item, DomainError>;
    async fn apply(&self, tenant: &TenantId, actor: UserId, review: Uuid, item: Uuid) -> Result<Item, DomainError>;
    async fn cancel(&self, tenant: &TenantId, actor: UserId, review: Uuid) -> Result<Review, DomainError>;
}

/// Shared JSON boundary for ownership API and fuzzing; unknown fields fail closed.
// fuzz-target: access_review_requests
pub fn parse_ownership(bytes: &[u8]) -> Result<ConfigureOwnership,DomainError> {
    if bytes.len()>65_536 { return Err(DomainError::invalid("ownership","request exceeds the bounded size")); }
    let request:ConfigureOwnership=serde_json::from_slice(bytes)
        .map_err(|_|DomainError::invalid("ownership","malformed ownership request"))?;
    request.validate()?;
    Ok(request)
}

/// Parses selection only; the deadline is checked against locked database time.
// fuzz-target: access_review_requests
pub fn parse_review(bytes: &[u8]) -> Result<StartReview,DomainError> {
    if bytes.len()>65_536 { return Err(DomainError::invalid("review","request exceeds the bounded size")); }
    let request:StartReview=serde_json::from_slice(bytes)
        .map_err(|_|DomainError::invalid("review","malformed review request"))?;
    let distinct:BTreeSet<_>=request.ownership_ids.iter().copied().collect();
    if request.ownership_ids.is_empty() || request.ownership_ids.len()>200
        || distinct.len()!=request.ownership_ids.len() || distinct.contains(&Uuid::nil()) || request.reviewer_id.is_nil() {
        return Err(DomainError::invalid("review","one to two hundred distinct assignments and a non-nil reviewer are required"));
    }
    Ok(request)
}

#[derive(Debug,Clone,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedDecision { pub decision:Decision,pub reason:String }

// fuzz-target: access_review_requests
pub fn parse_decision(bytes:&[u8])->Result<RecordedDecision,DomainError>{
    if bytes.len()>8192 { return Err(DomainError::invalid("decision","request exceeds the bounded size")); }
    let request:RecordedDecision=serde_json::from_slice(bytes)
        .map_err(|_|DomainError::invalid("decision","malformed decision request"))?;
    if request.reason.trim().is_empty() || request.reason.chars().count()>1000 || request.reason.chars().any(char::is_control) {
        return Err(DomainError::invalid("reason","one to one thousand printable characters are required"));
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn review_cannot_use_posted_access_or_duplicate_targets(){
        let id=Uuid::new_v4();let reviewer=Uuid::new_v4();
        let posted=serde_json::json!({"ownership_ids":[id],"reviewer_id":reviewer,"due_at":"2026-10-04T00:00:00Z","snapshot":{"roles":["admin"]}});
        assert!(parse_review(&serde_json::to_vec(&posted).unwrap()).is_err());
        let duplicates=serde_json::json!({"ownership_ids":[id,id],"reviewer_id":reviewer,"due_at":"2026-10-04T00:00:00Z"});
        assert!(parse_review(&serde_json::to_vec(&duplicates).unwrap()).is_err());
    }
    #[test]
    fn reviewer_assignment_does_not_accept_nil_or_duplicate_principals(){
        let reviewer=Uuid::new_v4();
        let request=ConfigureOwnership {target:Target::Membership {group_id:Uuid::new_v4(),user_id:Uuid::new_v4()},owner_user_id:reviewer,reviewers:vec![reviewer,reviewer],enabled:true,expected_revision:None};
        assert!(request.validate().is_err());
        assert!(Target::Membership {group_id:Uuid::nil(),user_id:reviewer}.validate().is_err());
    }
    #[test]
    fn deadline_is_validated_against_the_supplied_database_instant(){
        let now=OffsetDateTime::UNIX_EPOCH;
        let mut request=StartReview {ownership_ids:vec![Uuid::new_v4()],reviewer_id:Uuid::new_v4(),due_at:now+Duration::days(90)};
        assert!(request.validate(now).is_ok());
        assert!(request.validate(request.due_at).is_err());
        request.due_at+=Duration::seconds(1);assert!(request.validate(now).is_err());
    }
    #[test]
    fn decision_never_accepts_control_characters_or_a_silent_empty_reason(){
        assert!(parse_decision(br#"{"decision":"remove","reason":" "}"#).is_err());
        assert!(parse_decision(br#"{"decision":"remove","reason":"line\nline"}"#).is_err());
        assert!(parse_decision(br#"{"decision":"remove","reason":"Departed project"}"#).is_ok());
    }
}
