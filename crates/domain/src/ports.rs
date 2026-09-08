//! Ports: the traits through which protocol code reaches the outside world.
//!
//! Adapters live in `asterius-store-pg`, `asterius-jose` and the server crate.
//! Protocol crates depend on these traits and never on an implementation.

use crate::{DomainError, Issuer, Tenant, TenantId};
use std::fmt::Debug;
use time::OffsetDateTime;

/// Source of the current time.
///
/// Every expiry, `iat`/`exp` and lifetime check goes through a clock so that
/// tests can pin time instead of sleeping.
pub trait Clock: Debug + Send + Sync + 'static {
    /// The current instant, in UTC.
    fn now(&self) -> OffsetDateTime;
}

/// The real clock, backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

// ---------------------------------------------------------------------------
// Repositories
// ---------------------------------------------------------------------------

/// Looks tenants up. The one repository that is not itself tenant-scoped —
/// something has to resolve a host or a path to a tenant before scoping is
/// possible.
#[async_trait::async_trait]
pub trait TenantRepository: Debug + Send + Sync {
    /// Finds a tenant by id.
    async fn find_by_id(&self, id: &TenantId) -> Result<Option<Tenant>, DomainError>;

    /// Finds a tenant by its canonical issuer.
    async fn find_by_issuer(&self, issuer: &Issuer) -> Result<Option<Tenant>, DomainError>;

    /// Finds a tenant by its vanity host.
    async fn find_by_host(&self, host: &str) -> Result<Option<Tenant>, DomainError>;

    /// Lists every tenant, ordered by id.
    async fn list(&self) -> Result<Vec<Tenant>, DomainError>;

    /// Creates or replaces a tenant.
    async fn upsert(&self, tenant: &Tenant) -> Result<(), DomainError>;

    /// Deletes a tenant and, by cascade, everything that belongs to it.
    async fn delete(&self, id: &TenantId) -> Result<(), DomainError>;
}

/// Something that can only be reached through a tenant.
///
/// Every repository except [`TenantRepository`] is obtained from a scope rather
/// than constructed directly, so there is no way to phrase a query that has not
/// already chosen a tenant. The tenant is not a parameter the caller might
/// forget; it is a precondition of holding the handle at all.
///
/// This is as close to a compile-time guarantee as Rust gets without
/// type-level tenants: it does not stop code from opening the *wrong* scope,
/// but it does stop code from opening *no* scope, which is the mistake that
/// actually happens — a `WHERE` clause missing a predicate in a hand-written
/// query.
pub trait TenantScoped {
    /// The tenant every operation on this handle is confined to.
    fn tenant(&self) -> &TenantId;
}

// ---------------------------------------------------------------------------
// Outbound fetches
// ---------------------------------------------------------------------------

/// Dereferences a URL that a *client* chose.
///
/// The only port whose input is attacker-controlled end to end: a `jwks_uri` is
/// a string a client wrote into its own registration, and an implementation of
/// this trait is the server going and fetching it. RFC 7591 §5 raises the
/// general shape of the problem — an authorization server that dereferences a
/// URL from a registration document is doing work an attacker asked for, at an
/// address an attacker chose.
///
/// An implementation is therefore not merely an HTTP client. It is the boundary
/// that decides which addresses this process will ever connect to, how long it
/// will wait, and how many bytes it will read. `asterius_server::outbound` has
/// the one that ships, and states precisely what its guard does and does not
/// stop.
///
/// The port hands back a body and nothing else. Status codes, media types,
/// redirects and the size cap are HTTP's vocabulary and stay in the adapter:
/// protocol code above this line has no use for them, and a port that leaked
/// them would invite a second implementation to interpret them differently.
#[async_trait::async_trait]
pub trait JwksFetcher: Debug + Send + Sync {
    /// Fetches the JWK Set document at `url`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invalid`] when the URL is one this server refuses
    /// to dereference at all, and [`DomainError::Storage`] when the fetch was
    /// attempted and failed. A caller should treat both the same way — as "no
    /// keys, and do not ask again immediately" — because the difference is
    /// useful to an operator reading a log and to nobody else.
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_moves_forward() {
        let clock = SystemClock;
        assert!(clock.now() <= clock.now());
    }
}
