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
/// configuration item; per-tenant application roles are a different model
/// (`ast-095`) and not a string somebody can invent at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Administers the tenant the user belongs to.
    TenantAdmin,
    /// Administers the deployment: creates tenants, and sees across them.
    DeploymentAdmin,
    /// Helps the people of one tenant: reads accounts, and acts on their
    /// sessions and grants.
    ///
    /// Deliberately cannot write to the account itself. "End the session this
    /// person is stuck in, and withdraw the authorization they no longer want"
    /// is support work; editing the claims that describe somebody — their
    /// email, their status — changes who they are to every relying party, and
    /// is not.
    UserSupport,
    /// Reads one tenant, and writes nothing anywhere.
    ///
    /// The role an audit or a compliance review is given, so that reviewing a
    /// deployment does not require holding the authority to change it.
    SecurityAuditor,
}

impl Role {
    /// Every role, so a caller cannot iterate a list that has gone stale.
    pub const ALL: [Self; 4] = [
        Self::TenantAdmin,
        Self::DeploymentAdmin,
        Self::UserSupport,
        Self::SecurityAuditor,
    ];

    /// The prefix every scope of the admin surface carries.
    ///
    /// The mapping below reasons about the scope *grammar*
    /// — `admin.<resource>:<action>` — rather than about a list of scope
    /// strings copied out of the admin API's registry. A copy would rot: a
    /// scope added there and forgotten here would be refused to everybody
    /// including a tenant admin, and one removed here and kept there would be
    /// granted to nobody's knowledge. Reasoning about the grammar fails
    /// closed instead: anything that is not spelled like an admin scope is
    /// granted to no role at all.
    const ADMIN_PREFIX: &'static str = "admin.";

    /// The value as stored in `user_roles.role`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TenantAdmin => "tenant_admin",
            Self::DeploymentAdmin => "deployment_admin",
            Self::UserSupport => "user_support",
            Self::SecurityAuditor => "security_auditor",
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
            Self::TenantAdmin | Self::UserSupport | Self::SecurityAuditor => RoleScope::Tenant,
            Self::DeploymentAdmin => RoleScope::Deployment,
        }
    }

    /// Whether this role holds `scope`, one of the admin surface's
    /// `admin.<resource>:<action>` values.
    ///
    /// This is the whole authority map, and it is *here* rather than in the
    /// admin API because it is a statement about what a role means and not
    /// about how a request is routed. [`Self::scope`] answers how far a role
    /// reaches; this answers what it may do once it is there, and a caller is
    /// admitted only when both say yes.
    ///
    /// Two rules are worth reading twice.
    ///
    /// * **Every role may read and end its own session.** Otherwise a
    ///   restricted role signs in to a console that cannot draw its own header
    ///   or sign out, which is not a restriction anybody asked for.
    /// * **`SecurityAuditor` holds every read action and no write action**,
    ///   including reads that do not exist yet. That is the definition of the
    ///   role rather than an oversight: a review that had to be re-granted
    ///   every time a screen was added would be a review nobody kept current.
    ///   A future scope whose action is `write` is still refused, so the
    ///   direction the mapping widens in is the harmless one.
    #[must_use]
    pub fn grants(self, scope: &str) -> bool {
        let Some(action) = Self::admin_action(scope) else {
            return false;
        };

        // The caller's own session: never authority over anybody else.
        if matches!(scope, "admin.session:read" | "admin.session:write")
            || scope == "admin.openapi:read"
        {
            return true;
        }

        match self {
            Self::TenantAdmin | Self::DeploymentAdmin => true,
            Self::UserSupport => matches!(
                scope,
                "admin.users:read"
                    | "admin.sessions:read"
                    | "admin.sessions:write"
                    | "admin.grants:read"
                    | "admin.grants:write"
            ),
            Self::SecurityAuditor => action == "read",
        }
    }

    /// The action of an admin scope, or `None` for anything that is not one.
    fn admin_action(scope: &str) -> Option<&str> {
        let resource_and_action = scope.strip_prefix(Self::ADMIN_PREFIX)?;
        let (resource, action) = resource_and_action.split_once(':')?;
        // A scope with an empty half is not a scope: refusing it here keeps
        // `admin.:read` and `admin.users:` out of every branch below.
        (!resource.is_empty() && !action.is_empty()).then_some(action)
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

    /// A support agent may read an account and act on its sessions and
    /// grants, and may not write to the account itself: editing the claims
    /// that describe somebody is not support work.
    #[test]
    fn a_support_agent_reads_accounts_and_acts_on_their_sessions() {
        // Arrange
        let role = Role::UserSupport;

        // Act / Assert
        assert!(role.grants("admin.users:read"));
        assert!(role.grants("admin.sessions:read"));
        assert!(role.grants("admin.sessions:write"));
        assert!(role.grants("admin.grants:read"));
        assert!(role.grants("admin.grants:write"));
        assert!(!role.grants("admin.users:write"));
        assert!(!role.grants("admin.clients:read"));
        assert!(!role.grants("admin.keys:write"));
    }

    /// The one refusal an auditor is defined by: it writes nothing, anywhere.
    #[test]
    fn a_security_auditor_writes_nothing() {
        // Arrange
        let role = Role::SecurityAuditor;

        // Act / Assert
        assert!(role.grants("admin.users:read"));
        assert!(role.grants("admin.clients:read"));
        assert!(role.grants("admin.keys:read"));
        assert!(!role.grants("admin.users:write"));
        assert!(!role.grants("admin.keys:write"));
        assert!(!role.grants("admin.sessions:write"));
        assert!(!role.grants("admin.tenants:write"));
    }

    /// A scope that does not spell an admin action grants nothing, whichever
    /// role reads it: the mapping fails closed rather than guessing.
    #[test]
    fn a_scope_outside_the_admin_grammar_is_granted_to_nobody() {
        for role in Role::ALL {
            assert!(!role.grants("openid"), "{role} granted `openid`");
            assert!(!role.grants(""), "{role} granted the empty scope");
            assert!(!role.grants("read"), "{role} granted a bare action");
        }
    }

    /// Every role can find out who it is and can sign itself out, or the
    /// console it signs in to has no way to draw its own header.
    #[test]
    fn every_role_may_read_and_end_its_own_session() {
        for role in Role::ALL {
            assert!(
                role.grants("admin.session:read"),
                "{role} cannot read itself"
            );
            assert!(role.grants("admin.session:write"), "{role} cannot sign out");
        }
    }

    /// The two full-authority roles hold every scope the admin surface
    /// declares, restricted only by how far they reach.
    #[test]
    fn an_administrator_holds_every_admin_scope() {
        for role in [Role::TenantAdmin, Role::DeploymentAdmin] {
            assert!(role.grants("admin.users:write"));
            assert!(role.grants("admin.tenants:write"));
            assert!(role.grants("admin.keys:write"));
            assert!(role.grants("admin.outbox:read"));
        }
    }

    /// A restricted role is an ordinary tenant role: it reaches one tenant and
    /// has no business inside the reserved one.
    #[test]
    fn a_restricted_role_reaches_only_its_own_tenant() {
        for role in [Role::UserSupport, Role::SecurityAuditor] {
            assert_eq!(role.scope(), RoleScope::Tenant);
            assert!(!role.needs_the_reserved_tenant());
        }
    }

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
