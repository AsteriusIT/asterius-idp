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

pub mod audit;
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
pub mod outbox;
pub mod pagination;
pub mod policies;
pub mod rbac;
pub mod roles;
pub mod router;
pub mod ssf;
pub mod theme_image;
pub mod throttle;
pub mod users;

pub use backend::{AdminBackend, AdminTokens, PresentedToken, TokenPrincipal};
pub use console::{Asset, Bundle};
pub use error::AdminError;
pub use operations::{Effect, Method, Mutating, Operation, Safe};
pub use rbac::{Authority, Held, Reach};
pub use router::{AdminApi, AdminState, ClientAddress};
pub use theme_image::{ImageError, ReEncodedImage};

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
/// The `operationId` of `PUT /tenants/{tenant_id}/status`.
pub const TENANT_STATUS_UPDATE_ID: &str = "tenants.status.update";
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
/// The `operationId` of `GET /outbox/dead-letters`.
pub const OUTBOX_DEAD_LETTERS_ID: &str = "outbox.dead_letters";
/// The `operationId` of [`OUTBOX_DEAD_LETTER_RETRY`].
pub const OUTBOX_DEAD_LETTER_RETRY_ID: &str = "outbox.dead_letters.retry";
/// The `operationId` of [`OUTBOX_DEAD_LETTER_DROP`].
pub const OUTBOX_DEAD_LETTER_DROP_ID: &str = "outbox.dead_letters.drop";
/// The `operationId` of [`SSF_STREAMS_LIST`].
pub const SSF_STREAMS_LIST_ID: &str = "ssf.streams.list";
/// The `operationId` of [`SSF_STREAM_STATUS_UPDATE`].
pub const SSF_STREAM_STATUS_UPDATE_ID: &str = "ssf.streams.status.update";
/// The `operationId` of [`SSF_STREAM_VERIFY`].
pub const SSF_STREAM_VERIFY_ID: &str = "ssf.streams.verify";
/// The `operationId` of `GET /audit/events`.
pub const AUDIT_EVENTS_LIST_ID: &str = "audit.events.list";
/// The `operationId` of `GET /audit/events/export`.
pub const AUDIT_EVENTS_EXPORT_ID: &str = "audit.events.export";
/// The `operationId` of `GET /users`.
pub const USERS_LIST_ID: &str = "users.list";
/// The `operationId` of `POST /users`.
pub const USER_CREATE_ID: &str = "users.create";
/// The `operationId` of `GET /users/{user_id}`.
pub const USER_READ_ID: &str = "users.read";
/// The `operationId` of `PUT /users/{user_id}/claims`.
pub const USER_CLAIMS_UPDATE_ID: &str = "users.claims.update";
/// The `operationId` of `PUT /users/{user_id}/status`.
pub const USER_STATUS_UPDATE_ID: &str = "users.status.update";
/// The `operationId` of `GET /users/{user_id}/credentials`.
pub const USER_CREDENTIALS_READ_ID: &str = "users.credentials.read";
/// The `operationId` of `DELETE /users/{user_id}/credentials/passkeys/{credential_id}`.
pub const USER_PASSKEY_REMOVE_ID: &str = "users.credentials.passkey.remove";
/// The `operationId` of `POST /users/{user_id}/credentials/password/reset`.
pub const USER_PASSWORD_RESET_ID: &str = "users.credentials.password.reset";
/// The `operationId` of `GET /users/{user_id}/sessions`.
pub const USER_SESSIONS_LIST_ID: &str = "users.sessions.list";
/// The `operationId` of `DELETE /users/{user_id}/sessions/{sid}`.
pub const USER_SESSION_REVOKE_ID: &str = "users.sessions.revoke";
/// The `operationId` of `GET /users/{user_id}/grants`.
pub const USER_GRANTS_LIST_ID: &str = "users.grants.list";
/// The `operationId` of `DELETE /users/{user_id}/grants/{grant_id}`.
pub const USER_GRANT_REVOKE_ID: &str = "users.grants.revoke";
/// The `operationId` of `GET /users/{user_id}/roles`.
pub const USER_ROLES_READ_ID: &str = "users.roles.read";
/// The `operationId` of `PUT /users/{user_id}/roles`.
pub const USER_ROLES_UPDATE_ID: &str = "users.roles.update";

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

/// Switches a tenant on or off (`ast-l5bl`).
///
/// [`Reach::Deployment`], and that is the decision this route embodies. A
/// disabled tenant's endpoints behave as if it is not there
/// ([`asterius_domain::TenantStatus::Disabled`]), so the act cuts off every
/// client and every user of that tenant at once — including the administrators
/// who would switch it back on. Giving it [`Reach::Tenant`] would let a tenant
/// admin lock their own tenant out of this API with one request, and the only
/// way back would be a hand-written `update` against the database. Suspending
/// a tenant is something the deployment does *to* a tenant.
///
/// A route of its own and not a member of the settings document, for the
/// reason [`USER_STATUS_UPDATE`] gives: an audit trail and an RBAC policy both
/// read the `operationId` as the name of what was done, and "suspended a
/// tenant" must not be spelled "replaced some lifetimes".
///
/// `PUT` and not `POST`: the request states the state the tenant should be in,
/// so sending it twice is the same as sending it once (RFC 9110 §9.2.2).
pub const TENANT_STATUS_UPDATE: Operation = Operation::mutation(
    TENANT_STATUS_UPDATE_ID,
    "/tenants/{tenant_id}/status",
    M::Put,
    A::new(R::Deployment, "admin.tenants:write"),
    "Suspends or restores a tenant, across every endpoint it serves",
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

/// Deliveries this deployment has given up on (`ast-0ju.9`).
///
/// [`Reach::Tenant`]: an outbox row belongs to the tenant whose change
/// produced it, and the request is already routed to that tenant.
///
/// A scope of its own rather than `admin.clients:read`, because the two
/// answer different questions and a deployment should be able to grant the
/// second without the first: "which of my relying parties are we failing to
/// reach" is an operations concern, and whoever holds it does not thereby need
/// to read client registrations.
///
/// What it renders is deliberately less than the row holds: no payload, no
/// destination, no ordering key. See [`outbox`].
pub const OUTBOX_DEAD_LETTERS: Operation = Operation::read(
    OUTBOX_DEAD_LETTERS_ID,
    "/outbox/dead-letters",
    S::Get,
    A::new(R::Tenant, "admin.outbox:read"),
    "Lists deliveries this tenant's outbox has abandoned",
);

/// Puts one abandoned SSF delivery back on the schedule (`ast-f7m.8`).
///
/// `admin.outbox:write`, a scope of its own beside the read: the screen
/// that shows a delivery failing is granted more widely than the button
/// that makes this server post to a receiver again. Only `ssf.*` rows are
/// accepted — see [`crate::router`]'s handler — because an SSF receiver
/// deduplicates on `jti` and orders on `event_timestamp`, and whether a
/// late `notification.account_recovery` is a message somebody wants is a
/// question nobody has answered. The row's ordering key is not consulted:
/// an abandoned row stopped blocking its key when it was abandoned, so the
/// rows behind it have gone, and this one goes out after them.
///
/// A `POST` and not a `PUT`, because two of them are two deliveries'
/// worth of attempts and the `Idempotency-Key` is what makes a retried
/// click one.
pub const OUTBOX_DEAD_LETTER_RETRY: Operation = Operation::mutation(
    OUTBOX_DEAD_LETTER_RETRY_ID,
    "/outbox/dead-letters/{outbox_id}/retry",
    M::Post,
    A::new(R::Tenant, "admin.outbox:write"),
    "Requeues an abandoned SSF delivery with a fresh attempt budget",
);

/// Removes one abandoned delivery for good (`ast-f7m.8`).
///
/// What the retention sweep would do a week later, done now and recorded
/// with the operator's name on it. A `DELETE` on the resource it removes;
/// the same family rule as the retry, for the same reason.
pub const OUTBOX_DEAD_LETTER_DROP: Operation = Operation::mutation(
    OUTBOX_DEAD_LETTER_DROP_ID,
    "/outbox/dead-letters/{outbox_id}",
    M::Delete,
    A::new(R::Tenant, "admin.outbox:write"),
    "Drops an abandoned SSF delivery, recording it in the audit trail",
);

/// Every SSF stream of the tenant with its state and delivery figures
/// (`ast-f7m.8`).
///
/// Its own scope, `admin.ssf:read`, and not `admin.outbox:read` beside it:
/// the dead-letter screen says *that* deliveries fail, and this one says
/// which receiver has arranged to hear about the tenant's users and which
/// events. Neither the push endpoint nor the credential is rendered; see
/// [`ssf::StreamSummary`].
pub const SSF_STREAMS_LIST: Operation = Operation::read(
    SSF_STREAMS_LIST_ID,
    "/ssf/streams",
    S::Get,
    A::new(R::Tenant, "admin.ssf:read"),
    "Lists this tenant's SSF streams with status, reason, counters and queue depth",
);

/// Pauses or re-enables a stream (SSF 1.0 §8.1.2, `ast-f7m.8`).
///
/// A `PUT` of the whole status: `enabled` or `paused`, with an optional
/// reason. Idempotent by its own definition, so no `Idempotency-Key`.
/// Recorded as `ssf.stream_updated`, the same type the receiver's own
/// edits leave, with the operator as the actor.
pub const SSF_STREAM_STATUS_UPDATE: Operation = Operation::mutation(
    SSF_STREAM_STATUS_UPDATE_ID,
    "/ssf/streams/{stream_id}/status",
    M::Put,
    A::new(R::Tenant, "admin.ssf:write"),
    "Pauses or re-enables an SSF stream, with an optional reason",
);

/// Sends a stream §8.1.4's verification event (`ast-f7m.8`).
///
/// A `POST`, because each one is a SET on the wire and a retried click
/// must be one SET. The body may carry a `state`, placed in the event
/// verbatim as §8.1.4 requires.
pub const SSF_STREAM_VERIFY: Operation = Operation::mutation(
    SSF_STREAM_VERIFY_ID,
    "/ssf/streams/{stream_id}/verification",
    M::Post,
    A::new(R::Tenant, "admin.ssf:write"),
    "Queues an SSF verification event on the stream, with an optional state",
);

/// This tenant's audit trail, filtered, one cursor page at a time
/// (`ast-lh3.9`).
///
/// Its own scope, `admin.audit:read`, and not `admin.outbox:read` or
/// `admin.users:read` beside it: the trail is the one artefact that
/// describes the tenant's *people* — who signed in, which agent acted for
/// whom, from which fingerprinted address — and "may see that delivery is
/// failing" or "may look up an account" must not thereby be "may read
/// everything everyone did". The auditor role holds it by definition
/// (`asterius_domain::Role::grants`); user support does not.
///
/// The filters are [`audit::PARAMETERS`]; the cursor is the record's
/// position in the tenant's chain. Introspection (RFC 7662) is not mounted in
/// this build (`ast-1sk.1`), so the trail holds issuance and exchange and the
/// query will hold introspection the day it is recorded.
pub const AUDIT_EVENTS_LIST: Operation = Operation::read(
    AUDIT_EVENTS_LIST_ID,
    "/audit/events",
    S::Get,
    A::new(R::Tenant, "admin.audit:read"),
    "Lists this tenant's audit records, filtered by agent, owner, user, grant, type and time window",
)
.paginated();

/// The same records as NDJSON, streamed, newest first, at most
/// [`asterius_domain::audit::query::EXPORT_MAX_RECORDS`] lines.
///
/// A second operation rather than a `format=` parameter on the listing, so
/// that the two are two `operationId`s in the trail's own rate-limit bucket
/// and in a token's scope grant — an export is mass exfiltration with a
/// purpose, and a policy must be able to say "list, but do not export"
/// without parsing a query string. See [`audit`] for what the export does
/// and does not add on the way out.
pub const AUDIT_EVENTS_EXPORT: Operation = Operation::read(
    AUDIT_EVENTS_EXPORT_ID,
    "/audit/events/export",
    S::Get,
    A::new(R::Tenant, "admin.audit:read"),
    "Streams this tenant's audit records as NDJSON, with the same filters as the listing",
);

/// This tenant's accounts, one cursor page at a time, optionally filtered
/// (`ast-f7m.6`).
///
/// [`Reach::Tenant`] and no `{tenant_id}` in the path, for the reason
/// [`KEYS_LIST`] gives: the tenant is the issuer the request arrived at, not a
/// parameter a caller chooses. The cursor is the username, which is unique
/// within a tenant and is what the listing is ordered by.
pub const USERS_LIST: Operation = Operation::read(
    USERS_LIST_ID,
    "/users",
    S::Get,
    A::new(R::Tenant, "admin.users:read"),
    "Lists this tenant's accounts, filtered by an optional q parameter",
)
.paginated();

/// One account, with its claims and their provenance.
pub const USER_READ: Operation = Operation::read(
    USER_READ_ID,
    "/users/{user_id}",
    S::Get,
    A::new(R::Tenant, "admin.users:read"),
    "Reads one account and its claims",
);

/// Creates an account, with a password that passed policy or with none.
///
/// The password in the body goes through
/// [`asterius_domain::AcceptedPassword`] — the deny list included (`ast-895`)
/// — so the console is not a way around the policy the login form enforces.
pub const USER_CREATE: Operation = Operation::mutation(
    USER_CREATE_ID,
    "/users",
    M::Post,
    A::new(R::Tenant, "admin.users:write"),
    "Creates an account, with a password that passed policy or with none",
);

/// Replaces one account's claims and its verification flags (OIDC Core §5.1).
///
/// `PUT` and not `PATCH`, for the reason [`CLIENT_UPDATE`] gives: a merge
/// would leave a claim an administrator has just deleted in place, and the
/// claim being deleted is usually the one that was wrong.
pub const USER_CLAIMS_UPDATE: Operation = Operation::mutation(
    USER_CLAIMS_UPDATE_ID,
    "/users/{user_id}/claims",
    M::Put,
    A::new(R::Tenant, "admin.users:write"),
    "Replaces one account's claims and its verification flags",
);

/// Switches an account on or off.
///
/// A route of its own and not a member of the claims document, because
/// disabling an account is not an edit: it revokes every live session and
/// queues a back-channel logout token for each participating relying party
/// (OIDC Back-Channel Logout 1.0 §2.5). An operation with those effects needs
/// its own `operationId` — an audit trail and an RBAC policy both read that id
/// as the name of what was done.
///
/// `PUT` and not `POST`: the request states the state the account should be
/// in, so sending it twice is the same as sending it once, and RFC 9110 §9.2.2
/// makes that idempotence the verb's own rather than a key the caller must
/// remember.
pub const USER_STATUS_UPDATE: Operation = Operation::mutation(
    USER_STATUS_UPDATE_ID,
    "/users/{user_id}/status",
    M::Put,
    A::new(R::Tenant, "admin.users:write"),
    "Enables or disables an account, revoking its sessions when it is disabled",
);

/// What one account can sign in with.
///
/// No material is rendered: the port answers with
/// [`asterius_domain::CredentialSummary`], which carries no password hash, no
/// public key and no signature counter. See [`users`].
pub const USER_CREDENTIALS_READ: Operation = Operation::read(
    USER_CREDENTIALS_READ_ID,
    "/users/{user_id}/credentials",
    S::Get,
    A::new(R::Tenant, "admin.users:read"),
    "Lists what one account can sign in with",
);

/// Blocks one passkey.
///
/// `DELETE` on the credential, and the row stays: it is stamped rather than
/// removed, for the reason [`KEYS_RETIRE`] gives about a retired key's row —
/// an incident review has to be able to see that the credential existed and
/// when it stopped being usable.
pub const USER_PASSKEY_REMOVE: Operation = Operation::mutation(
    USER_PASSKEY_REMOVE_ID,
    "/users/{user_id}/credentials/passkeys/{credential_id}",
    M::Delete,
    A::new(R::Tenant, "admin.users:write"),
    "Blocks one passkey of an account",
);

/// Forces a password reset (`ast-2vk.10`).
///
/// Invalidates the password, ends the account's sessions and mails a recovery
/// link — it does **not** set a password an administrator chose. A password
/// two people know is a shared secret, and the recovery path already binds to
/// a mailbox and already forces a new credential in the same request.
///
/// `POST` and therefore an `Idempotency-Key`: pressing it twice must not send
/// two links and invalidate a credential the person has just re-established.
pub const USER_PASSWORD_RESET: Operation = Operation::mutation(
    USER_PASSWORD_RESET_ID,
    "/users/{user_id}/credentials/password/reset",
    M::Post,
    A::new(R::Tenant, "admin.users:write"),
    "Invalidates an account's password and mails it a recovery link",
);

/// One account's browser sessions.
///
/// A scope of its own — `admin.sessions:read` rather than `admin.users:read` —
/// for the reason [`OUTBOX_DEAD_LETTERS`] gives: the two answer different
/// questions and a deployment should be able to grant the second without the
/// first. "Which sessions does this person have open, and end that one" is
/// support work; reading and editing the claims that describe them is not, and
/// the `user_support` role (`ast-3t8`) is the shape that distinction is for.
pub const USER_SESSIONS_LIST: Operation = Operation::read(
    USER_SESSIONS_LIST_ID,
    "/users/{user_id}/sessions",
    S::Get,
    A::new(R::Tenant, "admin.sessions:read"),
    "Lists one account's browser sessions",
);

/// Ends one session, by the `sid` the deployment already publishes.
///
/// The path names the `sid` of OIDC Back-Channel Logout 1.0 §2.4 and never the
/// session's lookup digest — the port this route reaches through carries no
/// digest at all, so there is no identifier here that names a row.
///
/// Revoking notifies the participating relying parties (§2.5) through the same
/// seam RP-initiated logout uses, so a session ended from the console and one
/// ended by the person are indistinguishable to a relying party.
pub const USER_SESSION_REVOKE: Operation = Operation::mutation(
    USER_SESSION_REVOKE_ID,
    "/users/{user_id}/sessions/{sid}",
    M::Delete,
    A::new(R::Tenant, "admin.sessions:write"),
    "Ends one session and notifies the relying parties that took part",
);

/// The authorizations one account has granted.
///
/// Its own scope, for the reason [`USER_SESSIONS_LIST`] gives.
pub const USER_GRANTS_LIST: Operation = Operation::read(
    USER_GRANTS_LIST_ID,
    "/users/{user_id}/grants",
    S::Get,
    A::new(R::Tenant, "admin.grants:read"),
    "Lists the authorizations one account has granted",
);

/// Withdraws one authorization, with Grant Management ID1 §6.5's semantics.
///
/// The same call the client-facing `DELETE /grants/{grant_id}` makes, through
/// the same transaction: the refresh tokens are marked, the access-token
/// cutoff is written (`ast-m9c.13`) and the grant is stamped last. Two entry
/// points, one meaning of "revoked".
pub const USER_GRANT_REVOKE: Operation = Operation::mutation(
    USER_GRANT_REVOKE_ID,
    "/users/{user_id}/grants/{grant_id}",
    M::Delete,
    A::new(R::Tenant, "admin.grants:write"),
    "Withdraws one authorization and the credentials issued under it",
);

/// Who administers this account, and what they hold (`ast-3t8`).
///
/// Its own scope — `admin.roles:read` — and not `admin.users:read`, for the
/// reason [`USER_SESSIONS_LIST`] gives about sessions: "who may administer
/// this tenant" is a different question from "who has an account here", and a
/// deployment must be able to grant the second without the first. A support
/// agent reads accounts and is deliberately not told who the administrators
/// are; an auditor is told, and may change nothing.
pub const USER_ROLES_READ: Operation = Operation::read(
    USER_ROLES_READ_ID,
    "/users/{user_id}/roles",
    S::Get,
    A::new(R::Tenant, "admin.roles:read"),
    "Lists the administrative roles one account holds",
);

/// Replaces the administrative roles one account holds.
///
/// A replacement rather than a grant and a revoke, because the console shows a
/// set of checkboxes and "what this account should hold" is what an
/// administrator decides: two routes would let a form be applied halfway.
///
/// `admin.roles:write` is authority over *authority*, which is why it is
/// separate from `admin.users:write`. An operator who has delegated account
/// administration has not thereby delegated the power to appoint
/// administrators, and the threat model calls that boundary out.
pub const USER_ROLES_UPDATE: Operation = Operation::mutation(
    USER_ROLES_UPDATE_ID,
    "/users/{user_id}/roles",
    M::Put,
    A::new(R::Tenant, "admin.roles:write"),
    "Replaces the administrative roles one account holds",
);

// ---------------------------------------------------------------------------
// Application roles (`ast-095`)
// ---------------------------------------------------------------------------

/// The `operationId` of [`APP_ROLES_LIST`].
pub const APP_ROLES_LIST_ID: &str = "app_roles.tenant.list";
/// The `operationId` of [`APP_ROLE_CREATE`].
pub const APP_ROLE_CREATE_ID: &str = "app_roles.tenant.create";
/// The `operationId` of [`APP_ROLE_DELETE`].
pub const APP_ROLE_DELETE_ID: &str = "app_roles.tenant.delete";
/// The `operationId` of [`CLIENT_APP_ROLES_LIST`].
pub const CLIENT_APP_ROLES_LIST_ID: &str = "app_roles.client.list";
/// The `operationId` of [`CLIENT_APP_ROLE_CREATE`].
pub const CLIENT_APP_ROLE_CREATE_ID: &str = "app_roles.client.create";
/// The `operationId` of [`CLIENT_APP_ROLE_DELETE`].
pub const CLIENT_APP_ROLE_DELETE_ID: &str = "app_roles.client.delete";
/// The `operationId` of [`USER_APP_ROLES_LIST`].
pub const USER_APP_ROLES_LIST_ID: &str = "users.app_roles.list";
/// The `operationId` of [`USER_APP_ROLE_ASSIGN`].
pub const USER_APP_ROLE_ASSIGN_ID: &str = "users.app_roles.assign";
/// The `operationId` of [`USER_APP_ROLE_WITHDRAW`].
pub const USER_APP_ROLE_WITHDRAW_ID: &str = "users.app_roles.tenant.withdraw";
/// The `operationId` of [`USER_CLIENT_APP_ROLE_WITHDRAW`].
pub const USER_CLIENT_APP_ROLE_WITHDRAW_ID: &str = "users.app_roles.client.withdraw";
/// The `operationId` of [`POLICY_READ`].
pub const POLICY_READ_ID: &str = "policies.read";
/// The `operationId` of [`POLICY_UPDATE`].
pub const POLICY_UPDATE_ID: &str = "policies.update";
/// The `operationId` of [`POLICY_DELETE`].
pub const POLICY_DELETE_ID: &str = "policies.delete";
/// The `operationId` of [`POLICY_TRY`].
pub const POLICY_TRY_ID: &str = "policies.try";

/// The tenant's shared role catalogue (`ast-095`).
///
/// These are the names that reach every application of the tenant, under the
/// access token's `roles` claim. Its own scope — `admin.app_roles:read` — and
/// deliberately not `admin.roles:read`, which `ast-3t8` gave to the
/// *administrative* roles of this server: delegating the power to invent a
/// role an application authorises against is not the power to appoint an
/// administrator, and one scope covering both would make it so.
pub const APP_ROLES_LIST: Operation = Operation::read(
    APP_ROLES_LIST_ID,
    "/app-roles",
    S::Get,
    A::new(R::Tenant, "admin.app_roles:read"),
    "Lists the tenant's shared application roles",
);

/// Adds a role to the tenant's catalogue.
///
/// The only way a role name enters this system. Dynamic client registration
/// cannot declare one — there is no field for it in a registration document —
/// so a client cannot arrive with authority it named for itself.
pub const APP_ROLE_CREATE: Operation = Operation::mutation(
    APP_ROLE_CREATE_ID,
    "/app-roles",
    M::Post,
    A::new(R::Tenant, "admin.app_roles:write"),
    "Creates a tenant application role",
);

/// Removes a role from the tenant's catalogue.
///
/// **Refused with 409 while any account still holds it.** The alternative —
/// cascading the deletion onto every assignment — would be one request that
/// withdraws authority from an unbounded number of people, recorded as a
/// single audit event naming none of them. See
/// `0023_application_roles.sql`.
pub const APP_ROLE_DELETE: Operation = Operation::mutation(
    APP_ROLE_DELETE_ID,
    "/app-roles/{role_name}",
    M::Delete,
    A::new(R::Tenant, "admin.app_roles:write"),
    "Deletes a tenant application role; 409 while any account still holds it",
);

/// One client's own role catalogue.
///
/// Issued under `resource_access.{client_id}.roles`, and visible only to
/// tokens issued to that client.
pub const CLIENT_APP_ROLES_LIST: Operation = Operation::read(
    CLIENT_APP_ROLES_LIST_ID,
    "/clients/{client_id}/app-roles",
    S::Get,
    A::new(R::Tenant, "admin.app_roles:read"),
    "Lists one client's application roles",
);

/// Adds a role to one client's catalogue.
pub const CLIENT_APP_ROLE_CREATE: Operation = Operation::mutation(
    CLIENT_APP_ROLE_CREATE_ID,
    "/clients/{client_id}/app-roles",
    M::Post,
    A::new(R::Tenant, "admin.app_roles:write"),
    "Creates an application role belonging to one client",
);

/// Removes a role from one client's catalogue.
///
/// Refused with 409 while any account still holds it, for the reason
/// [`APP_ROLE_DELETE`] gives.
pub const CLIENT_APP_ROLE_DELETE: Operation = Operation::mutation(
    CLIENT_APP_ROLE_DELETE_ID,
    "/clients/{client_id}/app-roles/{role_name}",
    M::Delete,
    A::new(R::Tenant, "admin.app_roles:write"),
    "Deletes one client's application role; 409 while any account still holds it",
);

/// What one account holds, in both catalogues.
pub const USER_APP_ROLES_LIST: Operation = Operation::read(
    USER_APP_ROLES_LIST_ID,
    "/users/{user_id}/app-roles",
    S::Get,
    A::new(R::Tenant, "admin.app_roles:read"),
    "Lists the application roles one account holds",
);

/// Gives one account a role from either catalogue.
///
/// `POST` with a body naming the role and, for a client role, the client — one
/// route rather than two, because the two differ only in which catalogue the
/// name is looked up in and a caller assigning the wrong kind would otherwise
/// get a 404 from the wrong path.
///
/// A role that is not in the catalogue is a 409 and never a silent creation:
/// assignment must not be a way to invent a name that ends up in a token.
pub const USER_APP_ROLE_ASSIGN: Operation = Operation::mutation(
    USER_APP_ROLE_ASSIGN_ID,
    "/users/{user_id}/app-roles",
    M::Post,
    A::new(R::Tenant, "admin.app_roles:write"),
    "Gives one account an application role",
);

/// Takes a tenant role away from one account.
pub const USER_APP_ROLE_WITHDRAW: Operation = Operation::mutation(
    USER_APP_ROLE_WITHDRAW_ID,
    "/users/{user_id}/app-roles/{role_name}",
    M::Delete,
    A::new(R::Tenant, "admin.app_roles:write"),
    "Takes a tenant application role away from one account",
);

/// Takes a client role away from one account.
///
/// A path of its own rather than a `client_id` query parameter on the route
/// above: the thing being deleted is identified by the pair, and a deletion
/// whose target depends on an optional parameter is one a proxy that drops
/// query strings would aim at the wrong role.
pub const USER_CLIENT_APP_ROLE_WITHDRAW: Operation = Operation::mutation(
    USER_CLIENT_APP_ROLE_WITHDRAW_ID,
    "/users/{user_id}/clients/{client_id}/app-roles/{role_name}",
    M::Delete,
    A::new(R::Tenant, "admin.app_roles:write"),
    "Takes one client's application role away from one account",
);

/// Every route this API serves.
///
/// A `static` rather than a function building a `Vec`, so that the router, the
/// document and the tests are looking at one object and cannot be handed
/// different copies of it.
static REGISTRY: [Operation; 59] = [
    SESSION_READ,
    SESSION_END,
    OPENAPI_READ,
    TENANTS_LIST,
    TENANT_READ,
    TENANT_CREATE,
    TENANT_STATUS_UPDATE,
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
    OUTBOX_DEAD_LETTERS,
    OUTBOX_DEAD_LETTER_RETRY,
    OUTBOX_DEAD_LETTER_DROP,
    SSF_STREAMS_LIST,
    SSF_STREAM_STATUS_UPDATE,
    SSF_STREAM_VERIFY,
    AUDIT_EVENTS_LIST,
    AUDIT_EVENTS_EXPORT,
    USERS_LIST,
    USER_READ,
    USER_CREATE,
    USER_CLAIMS_UPDATE,
    USER_STATUS_UPDATE,
    USER_CREDENTIALS_READ,
    USER_PASSKEY_REMOVE,
    USER_PASSWORD_RESET,
    USER_SESSIONS_LIST,
    USER_SESSION_REVOKE,
    USER_GRANTS_LIST,
    USER_GRANT_REVOKE,
    USER_ROLES_READ,
    USER_ROLES_UPDATE,
    APP_ROLES_LIST,
    APP_ROLE_CREATE,
    APP_ROLE_DELETE,
    CLIENT_APP_ROLES_LIST,
    CLIENT_APP_ROLE_CREATE,
    CLIENT_APP_ROLE_DELETE,
    USER_APP_ROLES_LIST,
    USER_APP_ROLE_ASSIGN,
    USER_APP_ROLE_WITHDRAW,
    USER_CLIENT_APP_ROLE_WITHDRAW,
    POLICY_READ,
    POLICY_UPDATE,
    POLICY_DELETE,
    POLICY_TRY,
];

/// The tenant's authorization policy, as the PDP evaluates it (`ast-pj0.4`).
///
/// Its own scope, `admin.policies:read`, and not `admin.tenants:read` beside
/// the settings document: a rule catalogue says which of this tenant's people
/// may reach which of its applications' resources, and "may read the tenant's
/// lifetimes" must not thereby be "may read the authorization model". The
/// auditor role holds it by definition
/// (`asterius_domain::Role::grants` gives every read to `security_auditor`),
/// which is the right answer for a document a compliance review exists to
/// read.
pub const POLICY_READ: Operation = Operation::read(
    POLICY_READ_ID,
    "/policies",
    S::Get,
    A::new(R::Tenant, "admin.policies:read"),
    "The tenant's AuthZEN policy document, with the count of rules and when it last changed",
);

/// Replaces the tenant's policy, whole (ADR-0011).
///
/// A `PUT` and not a `PATCH`: deny precedence is a property of the rule *set*,
/// so a partial write would leave a tenant authorised by half of two policies.
/// Idempotent by its own definition — the same document twice is the same
/// policy — so no `Idempotency-Key`.
///
/// The body is the document `GET` returns under `document`, which is what lets
/// the console (`ast-f7m.9`) fetch, edit and put it back. Everything in it is
/// data: there is no member of the language that names code, and one this
/// build does not know is a 400 naming the path rather than a value stored for
/// a later build to interpret.
pub const POLICY_UPDATE: Operation = Operation::mutation(
    POLICY_UPDATE_ID,
    "/policies",
    M::Put,
    A::new(R::Tenant, "admin.policies:write"),
    "Replaces the tenant's AuthZEN policy document after validating it",
);

/// Removes the tenant's policy.
///
/// The tenant goes back to denying every evaluation, which is why an
/// administrator may reach it: it is the one edit to this document that cannot
/// widen anybody's authority. Recorded as `policy.updated` with a `cleared`
/// flag, so a reader of the trail filtering on the type sees every change to
/// the tenant's authorization, whichever direction it went.
pub const POLICY_DELETE: Operation = Operation::mutation(
    POLICY_DELETE_ID,
    "/policies",
    M::Delete,
    A::new(R::Tenant, "admin.policies:write"),
    "Removes the tenant's AuthZEN policy document, which denies every evaluation",
);

/// Decides one evaluation against the tenant's stored policy, without being a
/// policy enforcement point (`ast-f7m.9`).
///
/// The console's test bench. An administrator writes a rule catalogue and has
/// no way to know what it *does* until a relying party asks; this answers the
/// question they would otherwise answer by deploying.
///
/// # Why it is not `POST /access/v1/evaluation`
///
/// That endpoint authenticates a PEP: a DPoP-bound access token whose audience
/// is the PDP and which carries `authzen.evaluate`. The console holds a session
/// cookie and no such token, and giving it one would mean minting a PEP
/// credential for a browser. So the same question is asked over the credential
/// the console already has, and the two endpoints stay apart in every way that
/// matters: this one is on the admin API's rate limiter rather than the PDP's,
/// so a bench that is being hammered cannot spend a PEP's budget; and it writes
/// no `access.evaluated` record, because nothing enforced its answer.
///
/// # Why read and not write authority
///
/// It computes a function of the document a caller may already `GET` in full,
/// over facts that caller may already read. `admin.policies:read` is therefore
/// the authority it needs — asking for `:write` would mean an auditor could
/// read a catalogue and not ask what it decides, which is the question an
/// auditor is there to ask.
///
/// The facts are this server's: `groups`, `roles`, `grants` and `acr` are
/// resolved from the store exactly as the PDP resolves them, and the body's
/// `properties` are the only thing a caller supplies. A bench that let an
/// administrator state "this subject is in group admins" would answer a
/// question about a fiction.
pub const POLICY_TRY: Operation = Operation::probe(
    POLICY_TRY_ID,
    "/policies/try",
    M::Post,
    A::new(R::Tenant, "admin.policies:read"),
    "Decides one Authorization API evaluation against the tenant's stored policy, without enforcing it",
);

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
