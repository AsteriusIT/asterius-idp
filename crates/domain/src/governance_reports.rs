//! Read-only governance evidence. Findings propose review, never withdrawal.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{DomainError, TenantId, UserId};

pub const MAX_QUERY_BYTES: usize = 16_384;
pub const MAX_CURSOR_BYTES: usize = 12_288;
pub const MAX_CURSOR_KEY_BYTES: usize = 8192;
pub const MAX_PAGE: u16 = 50;
pub const SCAN_BOUND: usize = 100;
pub const INACTIVITY_DAYS: i64 = 90;
pub const MEMBERSHIP_REVIEW_DAYS: i64 = 365;
pub const PRIVILEGE_REVIEW_DAYS: i64 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    Accounts,
    Ownership,
    Assignments,
    TemporaryEntitlements,
    AdministrativeRoles,
}
impl Section {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accounts => "accounts",
            Self::Ownership => "ownership",
            Self::Assignments => "assignments",
            Self::TemporaryEntitlements => "temporary_entitlements",
            Self::AdministrativeRoles => "administrative_roles",
        }
    }
    fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "accounts" => Ok(Self::Accounts),
            "ownership" => Ok(Self::Ownership),
            "assignments" => Ok(Self::Assignments),
            "temporary_entitlements" => Ok(Self::TemporaryEntitlements),
            "administrative_roles" => Ok(Self::AdministrativeRoles),
            _ => Err(invalid()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    version: u8,
    tenant: String,
    section: Section,
    key: String,
}
impl Cursor {
    pub fn new(tenant: &TenantId, section: Section, key: String) -> Result<Self, DomainError> {
        if key.is_empty() || key.len() > MAX_CURSOR_KEY_BYTES || key.chars().any(char::is_control) {
            return Err(invalid());
        }
        Ok(Self {
            version: 1,
            tenant: tenant.as_str().to_owned(),
            section,
            key,
        })
    }
    pub fn encode(&self) -> Result<String, DomainError> {
        let bytes = serde_json::to_vec(self).map_err(|_| invalid())?;
        if bytes.len() > MAX_CURSOR_BYTES {
            return Err(invalid());
        }
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }
    fn decode(value: &str) -> Result<Self, DomainError> {
        if value.len() > MAX_QUERY_BYTES {
            return Err(invalid());
        }
        let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| invalid())?;
        if bytes.len() > MAX_CURSOR_BYTES {
            return Err(invalid());
        }
        let cursor: Self = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if cursor.version != 1
            || cursor.tenant.is_empty()
            || cursor.tenant.len() > 256
            || cursor.key.is_empty()
            || cursor.key.len() > MAX_CURSOR_KEY_BYTES
            || cursor.key.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        Ok(cursor)
    }
    pub fn key_for(&self, tenant: &TenantId, section: Section) -> Result<&str, DomainError> {
        if self.tenant != tenant.as_str() || self.section != section {
            return Err(invalid());
        }
        Ok(&self.key)
    }
}

#[derive(Debug, Clone)]
pub struct Query {
    pub section: Section,
    pub limit: u16,
    pub after: Option<Cursor>,
}
impl Query {
    // fuzz-target: governance_report_query
    pub fn parse(query: &str) -> Result<Self, DomainError> {
        if query.len() > MAX_QUERY_BYTES {
            return Err(invalid());
        }
        let mut section = None;
        let mut limit = None;
        let mut after = None;
        for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match name.as_ref() {
                "section" if section.is_none() => section = Some(Section::parse(&value)?),
                "limit" if limit.is_none() => {
                    let value: u16 = value.parse().map_err(|_| invalid())?;
                    if !(1..=MAX_PAGE).contains(&value) {
                        return Err(invalid());
                    }
                    limit = Some(value);
                }
                "after" if after.is_none() => after = Some(Cursor::decode(&value)?),
                _ => return Err(invalid()),
            }
        }
        let section = section.unwrap_or(Section::Accounts);
        if after
            .as_ref()
            .is_some_and(|cursor| cursor.section != section)
        {
            return Err(invalid());
        }
        Ok(Self {
            section,
            limit: limit.unwrap_or(25),
            after,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    MissingOwner,
    InactiveOwner,
    OwnerAuthorityUnavailable,
    ReviewerUnavailable,
    MissingOwnership,
    DisconnectedSource,
    UpstreamDeleted,
    UpstreamAbsent,
    InactiveAccount,
    NoRecentObservedActivity,
    UnknownActivity,
    StaleMembership,
    UnreviewedPrivilege,
    StaleReview,
    OverdueReview,
    UnappliedDecision,
    ProtectedRecoveryAccount,
    SourceHealthUnknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Proposal {
    InspectProvisioningSource,
    AssignCurrentOwner,
    ReviewAccountLifecycle,
    ReviewMembershipSource,
    StartIndependentReview,
    InspectReviewApplication,
    PreserveRecoveryAccess,
}
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub key: String,
    pub reasons: Vec<Reason>,
    /// Server-selected provenance only; never parsed as a cleanup command.
    pub evidence: Value,
    pub proposals: Vec<Proposal>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Thresholds {
    pub inactivity_days: i64,
    pub membership_review_days: i64,
    pub privilege_review_days: i64,
}
impl Default for Thresholds {
    fn default() -> Self {
        Self {
            inactivity_days: INACTIVITY_DAYS,
            membership_review_days: MEMBERSHIP_REVIEW_DAYS,
            privilege_review_days: PRIVILEGE_REVIEW_DAYS,
        }
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct Page {
    pub section: Section,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    pub thresholds: Thresholds,
    pub items: Vec<Finding>,
    pub next: Option<String>,
    /// Empty findings with a cursor still require continuation; scans are bounded.
    pub scanned: usize,
    pub read_only: bool,
}
#[async_trait::async_trait]
pub trait GovernanceReports: std::fmt::Debug + Send + Sync {
    async fn findings(
        &self,
        tenant: &TenantId,
        actor: UserId,
        query: &Query,
    ) -> Result<Page, DomainError>;
}
fn invalid() -> DomainError {
    DomainError::invalid(
        "report_query",
        "invalid bounded governance report query or cursor",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_query_rejects_duplicates_unknown_fields_and_bounds() {
        for query in [
            "section=accounts&section=accounts",
            "limit=0",
            "limit=51",
            "limit=2&limit=3",
            "tenant=other",
            "after=",
        ] {
            assert!(Query::parse(query).is_err(), "{query}");
        }
        assert!(Query::parse(&"x".repeat(MAX_QUERY_BYTES + 1)).is_err());
        assert_eq!(Query::parse("").expect("default").limit, 25);
    }
    #[test]
    fn report_cursor_cannot_cross_tenant_section_or_carry_unbounded_key() {
        let tenant = TenantId::new("one");
        let cursor =
            Cursor::new(&tenant, Section::Accounts, "opaque-user-id".into()).expect("cursor");
        let encoded = cursor.encode().expect("encoded");
        let parsed = Query::parse(&format!("after={encoded}")).expect("query");
        let cursor = parsed.after.expect("after");
        assert!(
            cursor
                .key_for(&TenantId::new("two"), Section::Accounts)
                .is_err()
        );
        assert!(cursor.key_for(&tenant, Section::Ownership).is_err());
        assert!(Query::parse(&format!("section=ownership&after={encoded}")).is_err());
        assert!(
            Cursor::new(
                &tenant,
                Section::Accounts,
                "x".repeat(MAX_CURSOR_KEY_BYTES + 1)
            )
            .is_err()
        );
    }
}
