//! What a caller must hold, and how the two authentication modes satisfy it.
//!
//! ADR-0010 decides where authority lives: a deployment admin is a *user* of a
//! reserved tenant holding a *role*, and a role's reach — one tenant or the
//! whole deployment — is derived from the role name by
//! [`asterius_domain::Role::scope`] rather than stored. Nothing here re-decides
//! that. This module answers one narrower question: given the authority a
//! caller was found to hold, and the authority an operation declares, may this
//! request proceed?
//!
//! # Two modes, one requirement
//!
//! An [`Authority`] is a pair: how far the operation reaches, and the scope
//! string that names it.
//!
//! * The **console** presents a session cookie, and its roles come from
//!   `user_roles`. A role satisfies a reach; the scope string is unused, since
//!   a role is not a scope and pretending otherwise would invent authority
//!   values nobody granted.
//! * **Automation** presents a DPoP-bound access token, and its scopes come
//!   from the grant. A scope satisfies the scope string; the reach is
//!   satisfied by the token's own tenant, or by a deployment-wide token.
//!
//! Keeping both on one [`Authority`] is what lets the table-driven test
//! enumerate every route once and check both modes against it. A route that
//! declared only a role would be unreachable by automation and a route that
//! declared only a scope would be unreachable by the console, and either gap
//! is the kind of thing that is discovered by an operator rather than by a
//! test.
//!
//! # Why the role set is the one the schema knows
//!
//! `security-auditor` and `user-support` are named in this bead's description
//! and are **not** implemented here. [`asterius_domain::Role`] is a closed set
//! of two, and `user_roles.role` carries a check constraint listing exactly
//! those two: adding a role is a schema change and a decision about somebody's
//! authority, not a string this crate may invent at runtime — which is what
//! `role.rs` says in as many words. The shape below takes them without a
//! signature change when that decision is made.

use asterius_domain::{Role, RoleScope, TenantId};

/// How far an operation reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// One tenant: the one the request was routed to. A caller holding
    /// authority over that tenant, or over the deployment, is admitted.
    Tenant,
    /// The deployment: every tenant, including ones that do not exist yet.
    /// Creating a tenant is the archetype.
    Deployment,
    /// Nothing beyond being an authenticated administrator of some kind.
    ///
    /// For the two routes whose whole content is about the caller: the `OpenAPI`
    /// document and "who am I". Still 401 without a credential — the
    /// table-driven test asserts it — because an unauthenticated reader of the
    /// admin surface's own description is a reconnaissance aid.
    Authenticated,
}

/// What one operation requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authority {
    reach: Reach,
    scope: &'static str,
}

impl Authority {
    /// Declares a requirement.
    #[must_use]
    pub const fn new(reach: Reach, scope: &'static str) -> Self {
        Self { reach, scope }
    }

    /// How far it reaches.
    #[must_use]
    pub const fn reach(&self) -> Reach {
        self.reach
    }

    /// The scope an automation token must carry.
    #[must_use]
    pub const fn scope(&self) -> &'static str {
        self.scope
    }
}

/// The authority a caller was found to hold, whichever mode they used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// Roles read from `user_roles` for the session's user, in the session's
    /// tenant.
    Roles {
        /// The tenant the session belongs to.
        tenant: TenantId,
        /// Every role the user holds there.
        roles: Vec<Role>,
    },
    /// Scopes carried by a DPoP-bound access token.
    Scopes {
        /// The tenant the token was issued by, or `None` for a token whose
        /// grant reaches the deployment.
        tenant: Option<TenantId>,
        /// The scope values, exactly as granted.
        scopes: Vec<String>,
    },
}

impl Held {
    /// Whether this authority satisfies `required` for a request routed to
    /// `tenant`.
    ///
    /// `tenant` is the tenant the *request* was routed to, which for the
    /// console is always the session's own tenant and for automation may not
    /// be. Passing it explicitly rather than reading it off `self` is what
    /// makes "a tenant admin of A may not administer B" a check rather than an
    /// assumption.
    #[must_use]
    pub fn satisfies(&self, required: Authority, tenant: &TenantId) -> bool {
        match self {
            Self::Roles {
                tenant: held_in,
                roles,
            } => Self::roles_satisfy(roles, held_in, required.reach(), tenant),
            Self::Scopes {
                tenant: held_in,
                scopes,
            } => Self::scopes_satisfy(scopes, held_in.as_ref(), required, tenant),
        }
    }

    fn roles_satisfy(roles: &[Role], held_in: &TenantId, reach: Reach, tenant: &TenantId) -> bool {
        // Deployment scope reaches everywhere, and the schema guarantees it is
        // only ever held inside the reserved tenant (ADR-0010), so it needs no
        // tenant comparison here.
        let deployment_wide = roles
            .iter()
            .any(|role| role.scope() == RoleScope::Deployment);

        match reach {
            Reach::Authenticated => !roles.is_empty(),
            Reach::Deployment => deployment_wide,
            // A tenant-scoped role only reaches the tenant it was granted in.
            // Comparing the *session's* tenant with the *request's* is the
            // whole check, and it is why `held_in` is carried rather than
            // assumed equal to the route's tenant.
            Reach::Tenant => deployment_wide || (held_in == tenant && !roles.is_empty()),
        }
    }

    fn scopes_satisfy(
        scopes: &[String],
        held_in: Option<&TenantId>,
        required: Authority,
        tenant: &TenantId,
    ) -> bool {
        let in_reach = match required.reach() {
            // A token bound to one tenant cannot administer the deployment.
            Reach::Deployment => held_in.is_none(),
            Reach::Tenant | Reach::Authenticated => {
                held_in.is_none_or(|issued_for| issued_for == tenant)
            }
        };

        // `Authenticated` still demands a scope, so a token minted for some
        // unrelated purpose is not a pass to the admin surface: every route
        // this API serves is an admin route.
        in_reach && scopes.iter().any(|held| held == required.scope())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant(id: &str) -> TenantId {
        TenantId::parse(id).expect("a valid tenant id")
    }

    fn console(in_tenant: &str, roles: &[Role]) -> Held {
        Held::Roles {
            tenant: tenant(in_tenant),
            roles: roles.to_vec(),
        }
    }

    const READ_TENANT: Authority = Authority::new(Reach::Tenant, "admin.tenants:read");
    const WRITE_DEPLOYMENT: Authority = Authority::new(Reach::Deployment, "admin.tenants:write");
    const ANY: Authority = Authority::new(Reach::Authenticated, "admin.session:read");

    #[test]
    fn a_tenant_admin_administers_its_own_tenant() {
        // Arrange
        let held = console("acme", &[Role::TenantAdmin]);

        // Act / Assert
        assert!(held.satisfies(READ_TENANT, &tenant("acme")));
    }

    /// The check the whole multi-tenant model rests on.
    #[test]
    fn a_tenant_admin_does_not_administer_another_tenant() {
        // Arrange
        let held = console("acme", &[Role::TenantAdmin]);

        // Act / Assert
        assert!(!held.satisfies(READ_TENANT, &tenant("other")));
    }

    #[test]
    fn a_tenant_admin_does_not_reach_the_deployment() {
        assert!(
            !console("acme", &[Role::TenantAdmin]).satisfies(WRITE_DEPLOYMENT, &tenant("acme"))
        );
    }

    /// ADR-0010: a deployment-scoped role reaches every tenant, including the
    /// ones that do not exist yet.
    #[test]
    fn a_deployment_admin_reaches_a_tenant_it_is_not_a_user_of() {
        // Arrange
        let held = console("asterius-admin", &[Role::DeploymentAdmin]);

        // Act / Assert
        assert!(held.satisfies(READ_TENANT, &tenant("acme")));
        assert!(held.satisfies(WRITE_DEPLOYMENT, &tenant("acme")));
    }

    /// A signed-in user holding no role at all is authenticated and nothing
    /// more: `Authenticated` is not "anybody with a session".
    #[test]
    fn a_user_with_no_role_holds_no_authority_at_all() {
        // Arrange
        let held = console("acme", &[]);

        // Act / Assert
        assert!(!held.satisfies(ANY, &tenant("acme")));
        assert!(!held.satisfies(READ_TENANT, &tenant("acme")));
    }

    #[test]
    fn an_administrator_of_any_kind_satisfies_authenticated() {
        assert!(console("acme", &[Role::TenantAdmin]).satisfies(ANY, &tenant("acme")));
    }

    #[test]
    fn a_token_needs_the_declared_scope() {
        // Arrange
        let held = Held::Scopes {
            tenant: Some(tenant("acme")),
            scopes: vec!["admin.tenants:read".to_owned()],
        };

        // Act / Assert
        assert!(held.satisfies(READ_TENANT, &tenant("acme")));
        assert!(!held.satisfies(WRITE_DEPLOYMENT, &tenant("acme")));
    }

    #[test]
    fn a_tenant_bound_token_does_not_reach_another_tenant() {
        // Arrange
        let held = Held::Scopes {
            tenant: Some(tenant("acme")),
            scopes: vec!["admin.tenants:read".to_owned()],
        };

        // Act / Assert
        assert!(!held.satisfies(READ_TENANT, &tenant("other")));
    }

    /// Even a deployment-wide token is refused a scope it was not granted.
    #[test]
    fn a_deployment_token_still_needs_the_scope() {
        // Arrange
        let held = Held::Scopes {
            tenant: None,
            scopes: vec!["admin.tenants:read".to_owned()],
        };

        // Act / Assert
        assert!(held.satisfies(READ_TENANT, &tenant("acme")));
        assert!(!held.satisfies(WRITE_DEPLOYMENT, &tenant("acme")));
    }

    /// A token minted for something else entirely is not admitted by
    /// `Authenticated`, which is a reach and not a waiver.
    #[test]
    fn a_token_without_an_admin_scope_is_not_merely_authenticated() {
        // Arrange
        let held = Held::Scopes {
            tenant: None,
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
        };

        // Act / Assert
        assert!(!held.satisfies(ANY, &tenant("acme")));
    }
}
