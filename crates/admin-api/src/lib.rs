//! Admin API.
//!
//! A first-party, same-origin API for the React console. It is deliberately
//! *not* an OAuth public client: the console authenticates with the same
//! session cookie as the rest of the first-party surface.
//!
//! **Who an admin is lives elsewhere, on purpose.** ADR-0010 makes a deployment
//! admin a user of a reserved tenant holding a deployment-scoped role, so the
//! model is [`asterius_domain::Role`] and its store is
//! `asterius_store_pg::PgRoleRepository`; the reserved tenant and the first
//! admin are seeded at startup by `asterius_store_pg::PgAdminSeed`. The two
//! rules that matter — the reserved tenant cannot be deleted, and a
//! deployment-scoped role cannot be granted outside it — are constraints in the
//! schema, not checks this crate performs.
//!
//! # The registry is the single source
//!
//! [`registry`] is the one list of routes. The axum router
//! ([`router::AdminApi`]), the `OpenAPI` document ([`openapi`]) and the
//! table-driven authorization test all read it, so there is no second list to
//! keep in step and no route that can exist without declaring the authority it
//! requires. `ast-k2o` — four fuzz targets that sat uncompiled because a
//! second list had to be remembered — is the reason there is only one here.
//!
//! # What a route cannot be
//!
//! A route that changes state **cannot be mounted on `GET`**, and that is a
//! property of the types rather than of review: [`operations::Mutating`] has no
//! `Get` variant, and [`operations::Operation`]'s fields are private so the two
//! constructors are the only way to build one. ADR-0009 requires exactly this,
//! because `SameSite=Lax` — deliberately not `Strict`, since a top-level
//! navigation back from a relying party is how a user arrives — does not
//! protect a top-level `GET`.
//!
//! # What this crate does not do
//!
//! The screens and their business resources are `ast-f7m.3` to `.7`. What is
//! here is the foundation they stand on: authentication in two modes, RBAC,
//! audit, the generated `OpenAPI` document, cursor pagination, idempotency keys,
//! one error envelope and rate limits. The routes that exist exist to make that
//! foundation exercisable — enough surface to prove the gate works, not a CRUD
//! API.
#![forbid(unsafe_code)]

pub mod auth;
pub mod backend;
pub mod console;
pub mod csrf;
pub mod error;
pub mod idempotency;
pub mod openapi;
pub mod operations;
pub mod pagination;
pub mod rbac;
pub mod router;
pub mod throttle;

pub use backend::{AdminBackend, AdminTokens, PresentedToken, TokenPrincipal};
pub use console::{Asset, Bundle};
pub use error::AdminError;
pub use operations::{Effect, Method, Mutating, Operation, Safe};
pub use rbac::{Authority, Held, Reach};
pub use router::{AdminApi, AdminState, ClientAddress};

use operations::{Mutating as M, Safe as S};
use rbac::{Authority as A, Reach as R};

/// Where the API is mounted, beneath the tenant prefix the tenancy middleware
/// has already stripped.
///
/// Versioned in the path rather than in a header: an admin console is pinned to
/// a release of this server, and a version a person can read in a URL is one
/// they can also curl.
pub const BASE_PATH: &str = "/admin/api/v1";

/// The `operationId` of `GET /session`.
pub const SESSION_READ_ID: &str = "session.read";
/// The `operationId` of `GET /openapi.json`.
pub const OPENAPI_READ_ID: &str = "openapi.read";
/// The `operationId` of `GET /tenants`.
pub const TENANTS_LIST_ID: &str = "tenants.list";
/// The `operationId` of `GET /tenants/{tenant_id}`.
pub const TENANT_READ_ID: &str = "tenants.read";
/// The `operationId` of `POST /tenants`.
pub const TENANT_CREATE_ID: &str = "tenants.create";

/// Who the caller is, and the CSRF token the console must send back.
///
/// [`Reach::Authenticated`], because its entire content is about the caller —
/// but still authenticated, so an anonymous request is a 401 rather than a
/// document describing a session that does not exist.
pub const SESSION_READ: Operation = Operation::read(
    SESSION_READ_ID,
    "/session",
    S::Get,
    A::new(R::Authenticated, "admin.session:read"),
    "The signed-in administrator, their roles, and this session's CSRF token",
);

/// The `OpenAPI` 3.1 document, generated from this registry.
///
/// Authenticated, because the description of an administration surface is a
/// reconnaissance aid: it names every path and the authority each one needs.
pub const OPENAPI_READ: Operation = Operation::read(
    OPENAPI_READ_ID,
    openapi::PATH,
    S::Get,
    A::new(R::Authenticated, "admin.openapi:read"),
    "This API's OpenAPI 3.1 description",
);

/// Every tenant in the deployment, one cursor page at a time.
pub const TENANTS_LIST: Operation = Operation::read(
    TENANTS_LIST_ID,
    "/tenants",
    S::Get,
    A::new(R::Deployment, "admin.tenants:read"),
    "Lists the deployment's tenants",
)
.paginated();

/// One tenant, named in the path.
///
/// [`Reach::Tenant`] and *not* the tenant the request was routed to: the
/// handler re-checks the caller against the tenant its path names, which is
/// what stops a tenant admin from reading a sibling's row through their own
/// console.
pub const TENANT_READ: Operation = Operation::read(
    TENANT_READ_ID,
    "/tenants/{tenant_id}",
    S::Get,
    A::new(R::Tenant, "admin.tenants:read"),
    "Reads one tenant",
);

/// Creates a tenant, with its signing keys.
pub const TENANT_CREATE: Operation = Operation::mutation(
    TENANT_CREATE_ID,
    "/tenants",
    M::Post,
    A::new(R::Deployment, "admin.tenants:write"),
    "Creates a tenant",
);

/// Every route this API serves.
///
/// A `static` rather than a function building a `Vec`, so that the router, the
/// document and the tests are looking at one object and cannot be handed
/// different copies of it.
static REGISTRY: [Operation; 5] = [
    SESSION_READ,
    OPENAPI_READ,
    TENANTS_LIST,
    TENANT_READ,
    TENANT_CREATE,
];

/// The registry.
#[must_use]
pub fn registry() -> &'static [Operation] {
    &REGISTRY
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_operation_id_is_unique() {
        // Arrange / Act
        let ids: BTreeSet<_> = registry().iter().map(Operation::id).collect();

        // Assert
        assert_eq!(ids.len(), registry().len());
    }

    /// Two routes at one path and one verb would make the second unreachable,
    /// and axum would merge them without saying so.
    #[test]
    fn no_two_operations_share_a_path_and_a_verb() {
        // Arrange / Act
        let mounted: BTreeSet<_> = registry()
            .iter()
            .map(|op| (op.path(), op.method()))
            .collect();

        // Assert
        assert_eq!(mounted.len(), registry().len());
    }

    /// The scope strings are the vocabulary an automation client is granted,
    /// so they are a namespace and not free text.
    #[test]
    fn every_declared_scope_is_in_the_admin_namespace() {
        for operation in registry() {
            let scope = operation.authority().scope();
            assert!(
                scope.starts_with("admin.") && scope.contains(':'),
                "{} declares {scope}, which is not admin.<resource>:<action>",
                operation.id()
            );
        }
    }

    #[test]
    fn every_path_is_rooted_and_carries_no_version_of_its_own() {
        for operation in registry() {
            assert!(operation.path().starts_with('/'), "{}", operation.id());
            assert!(
                operation.full_path().starts_with(BASE_PATH),
                "{}",
                operation.id()
            );
        }
    }
}
