//! Flat managed groups, deliberately separate from legacy `groups` claims.
//! Persistence alone grants no policy or token authority. See
//! `docs/groups-migration.md` for the staged compatibility contract.

use std::fmt::Debug;

use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{DomainError, RoleName, RoleNameError, TenantId, UserId};

/// Stable identity; renaming a group never changes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(Uuid);

impl GroupId {
    /// Wraps a stored UUID.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Mints a new, unguessable identity.
    #[must_use]
    pub fn mint() -> Self {
        Self(Uuid::new_v4())
    }

    /// The storage representation.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Exact lowercase ASCII name, with the same safe alphabet as role names.
/// Its distinct type prevents accidentally assigning a role by a group name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupName(RoleName);

impl GroupName {
    /// Maximum name size in bytes.
    pub const MAX_LEN: usize = RoleName::MAX_LEN;

    /// Accepts 1–64 ASCII bytes, initial alphanumeric, then `a-z0-9._:-`.
    /// Never normalizes or merges names.
    // fuzz-target: group_metadata
    pub fn parse(raw: &str) -> Result<Self, RoleNameError> {
        RoleName::parse(raw).map(Self)
    }

    /// Exact stored spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Invalid group metadata.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GroupMetadataError {
    /// Invalid machine name.
    #[error(transparent)]
    Name(#[from] RoleNameError),
    /// Empty, excessive or misleading display text.
    #[error(
        "display name must contain 1–200 UTF-8 bytes without control or bidi formatting characters or surrounding whitespace"
    )]
    DisplayName,
}

/// Validated metadata, with private fields so adapters cannot store unchecked text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMetadata {
    name: GroupName,
    display_name: String,
}

impl GroupMetadata {
    /// Maximum UTF-8 display size, enforced in PostgreSQL as well.
    pub const MAX_DISPLAY_BYTES: usize = 200;

    /// Validates both fields without trimming, case folding or truncating.
    // fuzz-target: group_metadata
    pub fn parse(name: &str, display_name: &str) -> Result<Self, GroupMetadataError> {
        let name = GroupName::parse(name)?;
        if display_name.is_empty()
            || display_name.len() > Self::MAX_DISPLAY_BYTES
            || display_name.trim() != display_name
            || display_name.chars().any(|c| {
                c.is_control()
                    || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            })
        {
            return Err(GroupMetadataError::DisplayName);
        }
        Ok(Self {
            name,
            display_name: display_name.to_owned(),
        })
    }

    /// Machine name, unique inside one tenant.
    #[must_use]
    pub const fn name(&self) -> &GroupName {
        &self.name
    }

    /// Human-facing label, never used for authorization.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// Persisted group and its optimistic concurrency token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    /// Owning tenant.
    pub tenant: TenantId,
    /// Stable identity.
    pub id: GroupId,
    /// Validated metadata.
    pub metadata: GroupMetadata,
    /// Starts at one; increments on metadata and explicit membership changes.
    pub revision: i64,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Latest explicit change timestamp.
    pub updated_at: OffsetDateTime,
}

/// Tenant-scoped catalogue and direct memberships. No nested/dynamic groups.
/// Every write is atomic. Listing limits must be 1–200; cursors are exclusive.
/// Implementations reject stale revisions with `DomainError::Conflict` and
/// missing groups on writes with `DomainError::NotFound`. Deleting a user or group
/// cascades memberships; deleting a user leaves the group itself intact.
#[async_trait::async_trait]
pub trait GroupDirectory: Debug + Send + Sync {
    /// Creates a distinct group; duplicate names conflict rather than overwrite.
    async fn create(
        &self,
        tenant: &TenantId,
        metadata: &GroupMetadata,
        now: OffsetDateTime,
    ) -> Result<Group, DomainError>;
    /// Fetches only inside the named tenant.
    async fn get(&self, tenant: &TenantId, id: GroupId) -> Result<Option<Group>, DomainError>;
    /// Lists by stable identity with bounded keyset pagination.
    async fn list(
        &self,
        tenant: &TenantId,
        after: Option<GroupId>,
        limit: u16,
    ) -> Result<Vec<Group>, DomainError>;
    /// Changes metadata only if the current revision matches.
    async fn update(
        &self,
        tenant: &TenantId,
        id: GroupId,
        expected_revision: i64,
        metadata: &GroupMetadata,
        now: OffsetDateTime,
    ) -> Result<Group, DomainError>;
    /// Deletes the matching revision and its memberships in one transaction.
    async fn delete(
        &self,
        tenant: &TenantId,
        id: GroupId,
        expected_revision: i64,
    ) -> Result<(), DomainError>;
    /// Idempotently adds a same-tenant user; returns whether membership changed.
    async fn add_member(
        &self,
        tenant: &TenantId,
        id: GroupId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;
    /// Idempotently removes membership; returns whether membership changed.
    async fn remove_member(
        &self,
        tenant: &TenantId,
        id: GroupId,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;
    /// Lists direct users with bounded keyset pagination; missing groups return an empty page.
    async fn members(
        &self,
        tenant: &TenantId,
        id: GroupId,
        after: Option<UserId>,
        limit: u16,
    ) -> Result<Vec<UserId>, DomainError>;
    /// Lists one user's managed groups. Does not inspect stored claims.
    async fn groups_for_user(
        &self,
        tenant: &TenantId,
        user: UserId,
        after: Option<GroupId>,
        limit: u16,
    ) -> Result<Vec<Group>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_names_preserve_exact_safe_spelling() {
        for name in ["a", "team.engineering:read-only", &"a".repeat(64)] {
            assert_eq!(GroupName::parse(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn groups_names_reject_aliases_and_oversize_values() {
        for name in [
            "",
            "Admins",
            " admins",
            "a/b",
            "-admin",
            "équipe",
            &"a".repeat(65),
        ] {
            assert!(GroupName::parse(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn groups_display_metadata_rejects_controls_bidi_and_whitespace() {
        for display in [
            "",
            " Engineering",
            "Engineering ",
            "a\nb",
            "a\u{0085}b",
            "a\u{202e}b",
            "a\u{200f}b",
            &"a".repeat(201),
        ] {
            assert!(
                GroupMetadata::parse("engineering", display).is_err(),
                "{display:?}"
            );
        }
    }

    #[test]
    fn groups_display_limit_counts_utf8_bytes_without_normalization() {
        let display = "é".repeat(100);
        let parsed = GroupMetadata::parse("engineering", &display).unwrap();
        assert_eq!(parsed.display_name(), display);
        assert!(GroupMetadata::parse("engineering", &"é".repeat(101)).is_err());
    }

    #[test]
    fn groups_identity_is_independent_of_metadata() {
        assert_ne!(GroupId::mint(), GroupId::mint());
        let uuid = Uuid::new_v4();
        assert_eq!(GroupId::from_uuid(uuid).as_uuid(), uuid);
    }
}
