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

use asterius_domain::ports::TenantRepository;
use asterius_domain::{
    AuditSink, DomainError, RateLimitStore, ReplayGuard, Role, Session, TenantId, UserId,
};
use std::sync::Arc;

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

    /// Every role `user` holds in `tenant`.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] for a stored role this build does not know —
    /// which must never be read as a weaker authority than it is — or a
    /// storage failure.
    async fn roles(&self, tenant: &TenantId, user: UserId) -> Result<Vec<Role>, DomainError>;

    /// The deployment's tenant repository: `ProvisionedTenants`, never the
    /// bare adapter. See the module documentation.
    fn tenants(&self) -> Arc<dyn TenantRepository>;

    /// Where an administrative change is recorded.
    fn audit(&self) -> Arc<dyn AuditSink>;

    /// The shared fixed-window counters (`ast-2vk.9`).
    fn rate_limits(&self) -> Arc<dyn RateLimitStore>;

    /// The atomic single-use store the `Idempotency-Key` is claimed in.
    fn replay(&self) -> Arc<dyn ReplayGuard>;

    /// Drops whatever caches the deployment keeps of the tenant directory.
    ///
    /// Called after a tenant is written, because the routing snapshot is
    /// otherwise up to thirty seconds stale and an operator who has just
    /// created a tenant will try it immediately.
    fn tenant_directory_changed(&self);
}

/// A DPoP-bound access token, resolved to what it authorises.
///
/// Separate from [`AdminBackend`] because the thing that implements it does
/// not exist yet: `ast-a05.8` (`client_credentials` for service tokens) is not
/// merged, so no admin token can be minted. Wiring `None` therefore means the
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
