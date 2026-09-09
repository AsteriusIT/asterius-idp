//! Administrative authority: what a user is allowed to administer.
//!
//! ADR-0010 decides the shape. A deployment admin is not a principal type of
//! its own and not an OAuth client: it is a *user*, of a reserved tenant,
//! carrying a role whose scope is the deployment rather than one tenant. That
//! keeps [`Session::tenant`] non-optional — every session still belongs to a
//! tenant, and every tenant-scoped query keeps its invariant.
//!
//! **A scope is not stored, it is derived.** [`Role::scope`] is a `match`, so
//! "which roles reach across tenants" has one answer in one place; a scope
//! column would be a second answer, and an admin API writing the wrong value
//! into it would silently widen somebody's authority. The database agrees by
//! reasoning about the role name directly: `user_roles` refuses
//! `deployment_admin` outside the reserved tenant.
//!
//! [`Session::tenant`]: crate::Session

use crate::{TenantId, UserId};
use time::OffsetDateTime;

/// What a role reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleScope {
    /// The tenant the user belongs to, and nothing outside it.
    Tenant,
    /// The whole deployment: every tenant, including the ones not created yet.
    ///
    /// Only grantable to a user of the reserved tenant, and the schema — not
    /// this type — is what makes that true of the stored data.
    Deployment,
}

/// An administrative role held by a user.
///
/// The set is closed and small on purpose. A role is authority over other
/// people's accounts and credentials, so every value here is a decision, not a
/// configuration item; finer-grained permissions belong to a policy model
/// (`ast-f7m`), not to a string somebody can invent at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Administers the tenant the user belongs to.
    TenantAdmin,
    /// Administers the deployment: creates tenants, and sees across them.
    DeploymentAdmin,
}

impl Role {
    /// Every role, so a caller cannot iterate a list that has gone stale.
    pub const ALL: [Self; 2] = [Self::TenantAdmin, Self::DeploymentAdmin];

    /// The value as stored in `user_roles.role`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TenantAdmin => "tenant_admin",
            Self::DeploymentAdmin => "deployment_admin",
        }
    }

    /// Parses a stored value, returning `None` for anything else.
    ///
    /// `None` rather than a default: a row holding a role this build does not
    /// know is a row from a newer schema, and treating it as the weakest role
    /// would be a guess about somebody's authority.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.as_str() == value)
    }

    /// How far this role reaches.
    #[must_use]
    pub const fn scope(self) -> RoleScope {
        match self {
            Self::TenantAdmin => RoleScope::Tenant,
            Self::DeploymentAdmin => RoleScope::Deployment,
        }
    }

    /// Whether this role may only be held inside the reserved tenant.
    ///
    /// The predicate the schema enforces, spelled here so the two can be read
    /// against each other.
    #[must_use]
    pub const fn needs_the_reserved_tenant(self) -> bool {
        matches!(self.scope(), RoleScope::Deployment)
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One granted role: which user, in which tenant, holds what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRole {
    /// The tenant the user belongs to. For a deployment-scoped role this is
    /// the reserved tenant, and the schema will not store anything else.
    pub tenant: TenantId,
    /// The user who holds the role.
    pub user: UserId,
    /// What they hold.
    pub role: Role,
    /// When it was granted. Part of the answer to "who made this person an
    /// admin, and when", which the audit trail carries the rest of.
    pub granted_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deployment_admin_reaches_past_its_own_tenant() {
        assert_eq!(Role::DeploymentAdmin.scope(), RoleScope::Deployment);
        assert!(Role::DeploymentAdmin.needs_the_reserved_tenant());
    }

    #[test]
    fn a_tenant_admin_reaches_only_its_own_tenant() {
        assert_eq!(Role::TenantAdmin.scope(), RoleScope::Tenant);
        assert!(!Role::TenantAdmin.needs_the_reserved_tenant());
    }

    #[test]
    fn every_role_round_trips_through_its_stored_spelling() {
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
    }

    /// A role this build has never heard of is not quietly downgraded to the
    /// weakest one it knows.
    #[test]
    fn an_unknown_stored_role_does_not_parse() {
        assert_eq!(Role::parse("superuser"), None);
        assert_eq!(Role::parse(""), None);
    }
}
