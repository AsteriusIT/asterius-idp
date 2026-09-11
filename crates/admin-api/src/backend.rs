//! The one port this crate reaches the outside world through.
//!
//! `asterius-admin-api` may not depend on `sqlx` — `scripts/check-layering.sh`
//! fails the build if it does — so everything below the API is a trait
//! implemented in the composition root. One trait rather than six, because the
//! thing a handler needs is "the deployment", and six handles would be six
//! chances to obtain a tenant-scoped repository for the wrong tenant.
//!
//! # The tenant repository is a handle, not a method
//!
//! [`AdminBackend::tenants`] hands back the `dyn TenantRepository` **the
//! composition root holds**, which is `ProvisionedTenants` — the decorator
//! `ast-qa3` added so that writing a tenant and giving it signing keys are one
//! step. Reaching for `PgTenantRepository` here instead would create tenants
//! with no active key, which refuse every client registration afterwards, and
//! the failure would surface days later at somebody else's endpoint. The port
//! type is what makes the right thing the only thing available.

use asterius_domain::entities::session::SessionRevocation;
use asterius_domain::keys::KeyAdministration;
use asterius_domain::ports::{
    ClientAdministration, InitialAccessTokenStore, TenantRepository, TenantSettingsRepository,
};
use asterius_domain::{
    AuditSink, Capabilities, DomainError, PasskeyEnrolment, RateLimitStore, ReplayGuard, Role,
    Session, TenantId, UserId,
};
use std::sync::Arc;

use crate::clients::RegistrationGate;

/// What an admin API request needs from below the API.
#[async_trait::async_trait]
pub trait AdminBackend: std::fmt::Debug + Send + Sync {
    /// The session behind a cookie, whatever state it is in.
    ///
    /// Returns the row rather than a verdict, because deciding whether an
    /// expired session is a 401 belongs to the API and
    /// [`asterius_domain::Session::status`] is where the states are named.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn session(
        &self,
        tenant: &TenantId,
        id_digest: &str,
    ) -> Result<Option<Session>, DomainError>;

    /// Ends one session, by the digest of the id it was presented with.
    ///
    /// Takes a digest and not a [`Session`], so that the only thing a caller
    /// can end is a session it has already resolved a cookie to. Revoking an
    /// already-revoked session keeps the first reason
    /// (`asterius_domain::ports::SessionRepository::revoke`), so a repeated
    /// call is harmless rather than a rewrite of the trail.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn end_session(
        &self,
        tenant: &TenantId,
        id_digest: &str,
        reason: SessionRevocation,
        now: time::OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Every role `user` holds in `tenant`.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] for a stored role this build does not know —
    /// which must never be read as a weaker authority than it is — or a
    /// storage failure.
    async fn roles(&self, tenant: &TenantId, user: UserId) -> Result<Vec<Role>, DomainError>;

    /// Gives `role` to `user` in `tenant`, or does nothing if they hold it
    /// already (`ast-3t8`).
    ///
    /// Idempotent, because the console sends the set it wants and not a diff:
    /// a re-sent form must not be a failure.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] when the schema refuses the grant — no such
    /// account or tenant, or a deployment-scoped role outside the reserved
    /// tenant, which is a rule of the database and not of this API — or a
    /// storage failure.
    async fn grant_role(
        &self,
        tenant: &TenantId,
        user: UserId,
        role: Role,
    ) -> Result<(), DomainError>;

    /// Takes `role` away from `user` in `tenant`.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if they did not hold it, or a storage
    /// failure.
    async fn revoke_role(
        &self,
        tenant: &TenantId,
        user: UserId,
        role: Role,
    ) -> Result<(), DomainError>;

    /// Whether `user` has a passkey it could have signed in with (`ast-895`).
    ///
    /// Asked only when the answer decides something — a deployment-scoped role
    /// on a session that is not phishing-resistant
    /// (`asterius_domain::admin_access_policy::enrolment_decides`) — because
    /// it is a credential read on the authentication path, and the common case
    /// must not pay for it.
    ///
    /// Disabled credentials do not count: a passkey blocked for a signature
    /// counter regression cannot be presented, so demanding it would lock the
    /// account out rather than raise its assurance.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. A caller
    /// must not read a failure here as "no passkey": that would turn an
    /// unreachable database into a way in on a password.
    async fn passkey_enrolment(
        &self,
        tenant: &TenantId,
        user: UserId,
    ) -> Result<PasskeyEnrolment, DomainError>;

    /// The deployment's tenant repository: `ProvisionedTenants`, never the
    /// bare adapter. See the module documentation.
    fn tenants(&self) -> Arc<dyn TenantRepository>;

    /// The per-tenant settings document: feature flags and lifetimes.
    ///
    /// A second handle rather than two methods on the tenant repository,
    /// because the write side of it only accepts a
    /// [`asterius_domain::TenantSettings`], which cannot be built without
    /// having passed the profile's ceilings.
    fn tenant_settings(&self) -> Arc<dyn TenantSettingsRepository>;

    /// The deployment's signing keys, for the console's key screen.
    ///
    /// A handle for the same reason [`Self::tenants`] is one: the object behind
    /// it is the process's `TenantKeyStore`, holding the key-encryption key and
    /// the audit sink a rotation must be recorded through. A repository built
    /// here instead would be one holding a different KEK, and a key sealed
    /// under it would not decrypt on the next boot.
    ///
    /// The port is [`KeyAdministration`] and not the read-side `KeyStore`,
    /// which is what stops a handler from reaching a signing key: there is no
    /// method on it that returns one.
    fn keys(&self) -> Arc<dyn KeyAdministration>;

    /// The deployment's accounts, for the console's user screen (`ast-f7m.6`).
    ///
    /// A handle for the same reason [`Self::tenants`] is one, and with a
    /// sharper consequence: the object behind it is the composition root's,
    /// which is where the back-channel logout notification lives. Disabling an
    /// account has to revoke its sessions *and* tell the relying parties that
    /// took part (OIDC Back-Channel Logout 1.0 §2.5), and a repository
    /// assembled here would do the first and silently skip the second — the
    /// failure being a relying party that keeps a person signed in after an
    /// administrator switched their account off.
    ///
    /// The port carries no session digest, no password hash and no public key;
    /// see [`asterius_domain::administration`] for why that is structural
    /// rather than a rule about what handlers render.
    fn users(&self) -> Arc<dyn asterius_domain::UserAdministration>;

    /// The application-role catalogues and their assignments (`ast-095`).
    ///
    /// A handle for the same reason [`Self::tenants`] is one: the object
    /// behind it is the composition root's, over the same pool the token
    /// endpoint reads roles from at issuance. A second one built here would be
    /// a catalogue nothing mints tokens against.
    ///
    /// The port carries [`asterius_domain::RoleName`] and nothing else, which
    /// is what stops this API from being a way to grant
    /// [`asterius_domain::Role`]: there is no method on it that takes one.
    fn application_roles(&self) -> Arc<dyn asterius_domain::ApplicationRoleDirectory>;

    /// The deployment's clients, for the console's client screen.
    ///
    /// A handle for the same reason [`Self::tenants`] is one, and with the same
    /// consequence: the object behind it is the composition root's, so the
    /// `sector_identifier_uri` check on this port goes through the process's
    /// one outbound adapter (ADR-0006) rather than through a second HTTP client
    /// built for the console.
    fn clients(&self) -> Arc<dyn ClientAdministration>;

    /// The deployment's outbox, for the dead-letter screen (`ast-0ju.9`).
    ///
    /// A handle for the same reason [`Self::tenants`] is one: the object
    /// behind it is the composition root's `PgOutbox`, over the pool the
    /// delivery worker claims from. A second one built here would read a
    /// different schedule and report a backlog nothing is working through.
    ///
    /// The port is the read-only
    /// [`asterius_domain::outbox::DeadLetterQuery`] and not the adapter: there
    /// is no method on it that queues a delivery, so no admin route can be
    /// written that makes this server post to a URL of the caller's choosing.
    fn outbox(&self) -> Arc<dyn asterius_domain::outbox::DeadLetterQuery>;

    /// The operator's two mutations on a dead letter (`ast-f7m.8`).
    ///
    /// A second handle beside [`Self::outbox`] rather than a wider port, for
    /// the reason the trail has a sink and a query: the listing is reached
    /// with `admin.outbox:read`, and the object it reads through must not
    /// be one that can requeue. The object behind this one is the same
    /// `PgOutbox` the worker claims from, so a requeued row is claimed by
    /// the schedule the screen reports.
    fn dead_letter_operations(&self) -> Arc<dyn asterius_domain::outbox::DeadLetterOperations>;

    /// The deployment's SSF streams as an operator sees them, and the
    /// transmitter that signs a verification event (`ast-f7m.8`).
    ///
    /// A handle for the reason [`Self::keys`] is one: the verification SET is
    /// signed with the tenant's active key through the process's signer, and
    /// queued on the same outbox or poll table the emitters use. A second
    /// transmitter built here would sign with whatever key this crate could
    /// reach and queue where nothing delivers from.
    fn ssf(&self) -> Arc<dyn crate::ssf::SsfAdministration>;

    /// The audit trail, for the query API and the export (`ast-lh3.9`).
    ///
    /// The port is the read-only [`asterius_domain::audit::AuditQuery`] and
    /// not the sink beside it: there is no method on it that appends, so no
    /// admin route built on this handle can be one that writes to the one
    /// table nothing may rewrite. It is a second handle rather than a method
    /// on [`Self::audit`] for the same reason the outbox's queue and its
    /// dead-letter view are two: one object that could both read the trail
    /// and append to it would give the export the authority to write.
    fn audit_trail(&self) -> Arc<dyn asterius_domain::audit::AuditQuery>;

    /// This tenant's initial access tokens (`ast-cu3`).
    ///
    /// A handle for the same reason [`Self::tenants`] is one: the object
    /// behind it is the composition root's, over the same pool `POST
    /// /register` spends from. A second one built here would issue credentials
    /// into a store the endpoint does not read.
    fn initial_access_tokens(&self) -> Arc<dyn InitialAccessTokenStore>;

    /// What this deployment offers, for validating a registration document.
    ///
    /// The same value `POST /register` validates against
    /// (`asterius_server::http::protocol`'s `capabilities`), and it has to be:
    /// a console validating against a wider set could create a client for a
    /// grant this build does not implement, and one validating against a
    /// narrower set would refuse a client dynamic registration accepts. Not
    /// `async`, because it is configuration read at startup and not a row.
    fn capabilities(&self) -> Capabilities;

    /// Who dynamic client registration admits, as the console reports it.
    ///
    /// A summary rather than the policy itself: the policy holds the digests of
    /// the initial access tokens, and this crate has no business being able to
    /// name one. See [`crate::clients::RegistrationGate`] for why the console
    /// reports this gate rather than offering to mint a credential for it.
    fn registration_gate(&self) -> RegistrationGate;

    /// Where an administrative change is recorded.
    fn audit(&self) -> Arc<dyn AuditSink>;

    /// The shared fixed-window counters (`ast-2vk.9`).
    fn rate_limits(&self) -> Arc<dyn RateLimitStore>;

    /// The atomic single-use store the `Idempotency-Key` is claimed in.
    fn replay(&self) -> Arc<dyn ReplayGuard>;

    /// Drops whatever caches the deployment keeps of the tenant directory and
    /// of the tenants' settings.
    ///
    /// Called after a tenant is written, because the routing snapshot is
    /// otherwise up to thirty seconds stale and an operator who has just
    /// created a tenant will try it immediately — and after its settings are
    /// written, because a feature flag is *published* in the discovery
    /// document and an administrator who has just switched one off will look
    /// at that document to check. One hook and not two: a caller who has to
    /// remember which of two caches a change touches is a caller who will
    /// eventually pick the wrong one, and dropping both costs one query.
    fn tenant_directory_changed(&self);
}

/// A DPoP-bound access token, resolved to what it authorises.
///
/// Separate from [`AdminBackend`] because the thing that implements it does
/// not exist yet. `ast-a05.8` has since made the `client_credentials` grant
/// real, so a service token can now be *minted*; what is still missing is the
/// resolver that turns one back into what it authorises here. Wiring `None`
/// therefore means the
/// automation mode answers 401 rather than pretending — see
/// [`crate::auth::authenticate`] — while every decision the mode makes is
/// implemented, exercised and tested here against a fake.
#[async_trait::async_trait]
pub trait AdminTokens: std::fmt::Debug + Send + Sync {
    /// Resolves a presented token.
    ///
    /// The implementation is responsible for the whole of RFC 9449: the proof
    /// must be present, valid, bound to this token's confirmation claim and
    /// bound to this request's method and URL. `None` means "not a token this
    /// server will act on", with no further detail — a token endpoint that
    /// explains *why* a token was refused is an oracle.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if a store could not be reached, which is not
    /// the same as a refusal and must not be reported as one.
    async fn resolve(
        &self,
        presented: &PresentedToken<'_>,
    ) -> Result<Option<TokenPrincipal>, DomainError>;
}

/// What was presented at the API by an automation caller.
#[derive(Debug, Clone, Copy)]
pub struct PresentedToken<'a> {
    /// The value after the `DPoP` scheme in `Authorization`.
    pub token: &'a str,
    /// The `DPoP` header, which RFC 9449 §7.1 requires alongside it.
    pub proof: &'a str,
    /// The request's method, which the proof's `htm` must match.
    pub method: &'a str,
    /// The request's URL, which the proof's `htu` must match.
    pub url: &'a str,
}

/// A resolved automation caller.
#[derive(Debug, Clone)]
pub struct TokenPrincipal {
    /// The subject the audit trail records, which under ADR-0009 is a user
    /// identifier when a human's authority is behind the token.
    pub subject: String,
    /// The tenant the token was issued by, or `None` for a deployment-wide
    /// one.
    pub tenant: Option<TenantId>,
    /// The granted scopes.
    pub scopes: Vec<String>,
}
