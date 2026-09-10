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
pub mod clients;
pub mod console;
pub mod csrf;
pub mod error;
pub mod idempotency;
pub mod initial_access_tokens;
pub mod keys;
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
/// The `operationId` of `DELETE /session`.
pub const SESSION_END_ID: &str = "session.end";
/// The `operationId` of `GET /openapi.json`.
pub const OPENAPI_READ_ID: &str = "openapi.read";
/// The `operationId` of `GET /tenants`.
pub const TENANTS_LIST_ID: &str = "tenants.list";
/// The `operationId` of `GET /tenants/{tenant_id}`.
pub const TENANT_READ_ID: &str = "tenants.read";
/// The `operationId` of `POST /tenants`.
pub const TENANT_CREATE_ID: &str = "tenants.create";
/// The `operationId` of `GET /tenants/{tenant_id}/settings`.
pub const TENANT_SETTINGS_READ_ID: &str = "tenants.settings.read";
/// The `operationId` of `PUT /tenants/{tenant_id}/settings`.
pub const TENANT_SETTINGS_UPDATE_ID: &str = "tenants.settings.update";
/// The `operationId` of `GET /clients`.
pub const CLIENTS_LIST_ID: &str = "clients.list";
/// The `operationId` of `GET /clients/{client_id}`.
pub const CLIENT_READ_ID: &str = "clients.read";
/// The `operationId` of `POST /clients`.
pub const CLIENT_CREATE_ID: &str = "clients.create";
/// The `operationId` of `PUT /clients/{client_id}`.
pub const CLIENT_UPDATE_ID: &str = "clients.update";
/// The `operationId` of `GET /registration`.
pub const REGISTRATION_READ_ID: &str = "registration.read";
/// The `operationId` of `GET /initial-access-tokens`.
pub const INITIAL_ACCESS_TOKENS_LIST_ID: &str = "initial_access_tokens.list";
/// The `operationId` of `POST /initial-access-tokens`.
pub const INITIAL_ACCESS_TOKEN_CREATE_ID: &str = "initial_access_tokens.create";
/// The `operationId` of `GET /keys`.
pub const KEYS_LIST_ID: &str = "keys.list";
/// The `operationId` of `GET /keys/jwks`.
pub const KEYS_JWKS_ID: &str = "keys.jwks";
/// The `operationId` of `POST /keys/rotate`.
pub const KEYS_ROTATE_ID: &str = "keys.rotate";
/// The `operationId` of `POST /keys/{kid}/retire`.
pub const KEYS_RETIRE_ID: &str = "keys.retire";
/// The `operationId` of `POST /keys/{kid}/purge`.
pub const KEYS_PURGE_ID: &str = "keys.purge";
/// The `operationId` of `PUT /keys/schedule`.
pub const KEYS_SCHEDULE_ID: &str = "keys.schedule";
/// The `operationId` of `POST /keys/schedule/apply`.
pub const KEYS_SCHEDULE_APPLY_ID: &str = "keys.schedule.apply";

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

/// Ends the caller's own session: the console's "Sign out".
///
/// [`Reach::Authenticated`], for the same reason [`SESSION_READ`] is: the
/// operation is about the caller and reaches nothing else. There is no session
/// id in the path and none in a body — the *only* session this route can end
/// is the one the request authenticated with, so there is no identifier a
/// caller could aim at somebody else's session. Ending another person's
/// session is an administrative act on a user and belongs to a route about
/// users, not to this one.
///
/// A mutation, so the console's synchroniser token is required: a cross-site
/// page that could sign an administrator out at will is a nuisance attack, and
/// the CSRF check that already covers every other state change covers this one
/// by declaring it here.
pub const SESSION_END: Operation = Operation::mutation(
    SESSION_END_ID,
    "/session",
    M::Delete,
    A::new(R::Authenticated, "admin.session:write"),
    "Ends the session this request was made with",
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

/// One tenant's settings: its feature flags and its lifetimes.
///
/// Split from [`TENANT_READ`] rather than folded into the tenant document,
/// because the two answer different questions and are read at different rates
/// — a console lists tenants far more often than it opens one's settings — and
/// because a settings screen that PUTs back what it GOT is the shape that does
/// not lose a member somebody else added.
pub const TENANT_SETTINGS_READ: Operation = Operation::read(
    TENANT_SETTINGS_READ_ID,
    "/tenants/{tenant_id}/settings",
    S::Get,
    A::new(R::Tenant, "admin.tenants:read"),
    "Reads one tenant's feature flags and lifetimes",
);

/// Replaces one tenant's settings.
///
/// `PUT` and not `PATCH`: the document is small, the console holds all of it,
/// and a whole-document replacement is the one shape where "what I saw is what
/// I saved" is true. The lifetimes in the body are checked against the
/// profile's ceilings *here*, below the console — see
/// [`asterius_domain::TenantSettings`].
pub const TENANT_SETTINGS_UPDATE: Operation = Operation::mutation(
    TENANT_SETTINGS_UPDATE_ID,
    "/tenants/{tenant_id}/settings",
    M::Put,
    A::new(R::Tenant, "admin.tenants:write"),
    "Replaces one tenant's feature flags and lifetimes",
);

/// This tenant's clients, one cursor page at a time, optionally filtered.
///
/// [`Reach::Tenant`] and no `{tenant_id}` in the path, for the reason
/// [`KEYS_LIST`] gives: the tenant is the issuer the request arrived at, not a
/// parameter a caller chooses.
pub const CLIENTS_LIST: Operation = Operation::read(
    CLIENTS_LIST_ID,
    "/clients",
    S::Get,
    A::new(R::Tenant, "admin.clients:read"),
    "Lists this tenant's clients, filtered by an optional q parameter",
)
.paginated();

/// One client's whole registration document.
pub const CLIENT_READ: Operation = Operation::read(
    CLIENT_READ_ID,
    "/clients/{client_id}",
    S::Get,
    A::new(R::Tenant, "admin.clients:read"),
    "Reads one client's registration",
);

/// Registers a client from the console, through the RFC 7591 validator.
///
/// The body is a registration document — the same document `POST /register`
/// takes — and it is handed to the same validator. See [`clients`] for why the
/// console has no rules of its own.
pub const CLIENT_CREATE: Operation = Operation::mutation(
    CLIENT_CREATE_ID,
    "/clients",
    M::Post,
    A::new(R::Tenant, "admin.clients:write"),
    "Registers a client, validated exactly as dynamic registration validates one",
);

/// Replaces one client's registration.
///
/// `PUT` and not `PATCH`, for the reason RFC 7592 §2.2 gives: "Valid values of
/// client metadata fields in this request MUST replace, not augment, the values
/// previously associated with this client." A merge would leave a client on a
/// redirect URI an administrator has just deleted.
pub const CLIENT_UPDATE: Operation = Operation::mutation(
    CLIENT_UPDATE_ID,
    "/clients/{client_id}",
    M::Put,
    A::new(R::Tenant, "admin.clients:write"),
    "Replaces one client's registration",
);

/// Whether dynamic client registration admits anybody, and on how many
/// credentials.
///
/// [`Reach::Deployment`]: the registration policy is one process-wide setting
/// read from the configuration file, not a tenant's property, and a tenant
/// administrator learning how many initial access tokens the deployment holds
/// learns something about a neighbour's arrangements.
pub const REGISTRATION_READ: Operation = Operation::read(
    REGISTRATION_READ_ID,
    "/registration",
    S::Get,
    A::new(R::Deployment, "admin.clients:read"),
    "Reports the dynamic client registration gate this deployment is running",
);

/// The initial access tokens this tenant has issued (`ast-cu3`).
///
/// [`Reach::Tenant`], unlike [`REGISTRATION_READ`] beside it: these are the
/// tenant's own credentials rather than the deployment's configuration, and the
/// request is already routed to the tenant that owns them. No digest and no
/// plaintext is rendered — see [`initial_access_tokens::summarise`] — so what
/// this returns is a quota, an expiry and a label.
pub const INITIAL_ACCESS_TOKENS_LIST: Operation = Operation::read(
    INITIAL_ACCESS_TOKENS_LIST_ID,
    "/initial-access-tokens",
    S::Get,
    A::new(R::Tenant, "admin.clients:read"),
    "Lists the initial access tokens this tenant has issued",
);

/// Mints one initial access token for this tenant, shown once.
///
/// `admin.clients:write` and not a scope of its own: the credential's entire
/// authority is to create clients at this tenant, which is what that scope
/// already grants directly. A separate scope would suggest a separate
/// privilege and would let a deployment grant one without the other, which is
/// a distinction with no security content.
///
/// The quota is **not** a parameter. It is stamped from the tenant's
/// `max_clients_per_initial_access_token`, so that the policy an operator
/// stored is the policy that binds; see [`initial_access_tokens`].
pub const INITIAL_ACCESS_TOKEN_CREATE: Operation = Operation::mutation(
    INITIAL_ACCESS_TOKEN_CREATE_ID,
    "/initial-access-tokens",
    M::Post,
    A::new(R::Tenant, "admin.clients:write"),
    "Issues an initial access token for this tenant, shown once",
);

/// Every signing key this tenant holds, with each algorithm's rotation policy.
///
/// [`Reach::Tenant`]: a tenant administrator manages their own tenant's keys,
/// and the request is already routed to that tenant. There is no `{tenant_id}`
/// in the path for the same reason the interaction endpoints have none — the
/// tenant is the issuer the request arrived at, not a parameter a caller
/// chooses.
pub const KEYS_LIST: Operation = Operation::read(
    KEYS_LIST_ID,
    "/keys",
    S::Get,
    A::new(R::Tenant, "admin.keys:read"),
    "Lists this tenant's signing keys and their rotation schedules",
);

/// The JWK Set this tenant publishes right now.
///
/// Rendered from the same records `GET /jwks` serves, so an operator reading
/// the preview before a rotation is reading the bytes a relying party fetches
/// after it.
pub const KEYS_JWKS: Operation = Operation::read(
    KEYS_JWKS_ID,
    "/keys/jwks",
    S::Get,
    A::new(R::Tenant, "admin.keys:read"),
    "Previews the JWK Set this tenant publishes",
);

/// Stages a new signing key, and optionally promotes it in the same call.
pub const KEYS_ROTATE: Operation = Operation::mutation(
    KEYS_ROTATE_ID,
    "/keys/rotate",
    M::Post,
    A::new(R::Tenant, "admin.keys:write"),
    "Rotates a signing key now",
);

/// Takes one key out of the published set.
///
/// `POST` rather than `DELETE`: the row is not deleted. A retired key's `kid`
/// must never be reused and an incident review has to be able to see that the
/// key existed, so this is a state change on a resource that stays.
pub const KEYS_RETIRE: Operation = Operation::mutation(
    KEYS_RETIRE_ID,
    "/keys/{kid}/retire",
    M::Post,
    A::new(R::Tenant, "admin.keys:write"),
    "Retires one signing key, removing it from the published JWK Set",
);

/// Destroys one key's private material after a compromise.
///
/// A second, harder button beside [`KEYS_RETIRE`], and a separate operation
/// rather than a flag on that one. Retiring stops a key being used; purging
/// stops it being usable, by erasing the sealed private half so that a database
/// dump taken afterwards carries nothing to forge with. Two different decisions
/// with two different consequences should not share an `operationId`, because
/// an audit trail and an RBAC policy both read that id as the name of what was
/// done.
///
/// `POST` and not `DELETE` for the reason [`KEYS_RETIRE`] gives: the row stays.
/// The `kid` is never reused and an incident review must be able to see that
/// the key existed and when it was destroyed.
pub const KEYS_PURGE: Operation = Operation::mutation(
    KEYS_PURGE_ID,
    "/keys/{kid}/purge",
    M::Post,
    A::new(R::Tenant, "admin.keys:write"),
    "Destroys one signing key's private material after a compromise",
);

/// Replaces one algorithm's rotation policy.
pub const KEYS_SCHEDULE: Operation = Operation::mutation(
    KEYS_SCHEDULE_ID,
    "/keys/schedule",
    M::Put,
    A::new(R::Tenant, "admin.keys:write"),
    "Sets the rotation schedule for one algorithm",
);

/// Runs the rotation sweep now, instead of waiting for the next pass.
///
/// The other half of [`KEYS_SCHEDULE`]: setting a policy states what should
/// happen, and this makes it happen at a moment somebody is watching. Without
/// it, an operator who has just shortened a rotation period learns whether the
/// policy does what they meant whenever the background sweep next runs, which
/// is the wrong time to find out.
///
/// Deliberately not [`KEYS_ROTATE`]. Rotate forces a new key whatever the
/// schedule says; this runs the schedule, so it stages nothing that was not
/// due, promotes nothing whose propagation period has not elapsed and retires
/// nothing still inside its grace. Pressing it twice is safe, and the second
/// press reports that it did nothing — the property that makes it a button at
/// all rather than a runbook step with a warning attached.
///
/// A mutation on `POST`, and under `/keys/schedule/` so that the two operations
/// on a schedule read as one pair in the path as well as in this file.
pub const KEYS_SCHEDULE_APPLY: Operation = Operation::mutation(
    KEYS_SCHEDULE_APPLY_ID,
    "/keys/schedule/apply",
    M::Post,
    A::new(R::Tenant, "admin.keys:write"),
    "Runs this tenant's rotation schedule now",
);

/// Every route this API serves.
///
/// A `static` rather than a function building a `Vec`, so that the router, the
/// document and the tests are looking at one object and cannot be handed
/// different copies of it.
static REGISTRY: [Operation; 22] = [
    SESSION_READ,
    SESSION_END,
    OPENAPI_READ,
    TENANTS_LIST,
    TENANT_READ,
    TENANT_CREATE,
    TENANT_SETTINGS_READ,
    TENANT_SETTINGS_UPDATE,
    CLIENTS_LIST,
    CLIENT_READ,
    CLIENT_CREATE,
    CLIENT_UPDATE,
    REGISTRATION_READ,
    INITIAL_ACCESS_TOKENS_LIST,
    INITIAL_ACCESS_TOKEN_CREATE,
    KEYS_LIST,
    KEYS_JWKS,
    KEYS_ROTATE,
    KEYS_RETIRE,
    KEYS_PURGE,
    KEYS_SCHEDULE,
    KEYS_SCHEDULE_APPLY,
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
