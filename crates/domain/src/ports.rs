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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_moves_forward() {
        let clock = SystemClock;
        assert!(clock.now() <= clock.now());
    }
}
