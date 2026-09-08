//! The tenant scope: the handle every tenant-scoped repository hangs off.

use crate::auth_requests::PgAuthRequestRepository;
use crate::clients::PgClientRepository;
use crate::grants::PgGrantRepository;
use crate::sessions::PgSessionRepository;
use crate::users::PgUserRepository;
use asterius_domain::ports::TenantScoped;
use asterius_domain::{Capabilities, TenantId};
use asterius_jose::Kek;
use sqlx::postgres::PgPool;
use std::sync::Arc;

/// Database access confined to one tenant.
///
/// Repositories for clients, users, sessions, grants and tokens are implemented
/// as methods on this type (each by its own story), and every one of them binds
/// [`TenantScope::tenant`] into its `WHERE` clause. The tenant is therefore not
/// an argument a caller can omit — it is a precondition of having the handle.
#[derive(Debug, Clone)]
pub struct TenantScope<'a> {
    pool: &'a PgPool,
    tenant: TenantId,
}

impl<'a> TenantScope<'a> {
    pub(crate) const fn new(pool: &'a PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// The client repository for this tenant.
    ///
    /// `capabilities` is what a stored client is re-validated against on the
    /// way out; see [`PgClientRepository::new`].
    #[must_use]
    pub fn clients(&self, capabilities: Capabilities) -> PgClientRepository {
        PgClientRepository::new(self.pool.clone(), self.tenant.clone(), capabilities)
    }

    /// The user repository for this tenant.
    ///
    /// `kek` is what opens the tenant's pairwise salt; see
    /// [`PgUserRepository::new`]. A user repository that could not reach the
    /// salt would be a user repository that cannot mint a `sub`, and minting
    /// one is not an optional part of having a user.
    #[must_use]
    pub fn users(&self, kek: Arc<dyn Kek>) -> PgUserRepository {
        PgUserRepository::new(self.pool.clone(), self.tenant.clone(), kek)
    }

    /// The session repository for this tenant.
    #[must_use]
    pub fn sessions(&self) -> PgSessionRepository {
        PgSessionRepository::new(self.pool.clone(), self.tenant.clone())
    }

    /// The pushed-authorization-request repository for this tenant.
    #[must_use]
    pub fn auth_requests(&self) -> PgAuthRequestRepository {
        PgAuthRequestRepository::new(self.pool.clone(), self.tenant.clone())
    }

    /// The grant repository for this tenant.
    #[must_use]
    pub fn grants(&self) -> PgGrantRepository {
        PgGrantRepository::new(self.pool.clone(), self.tenant.clone())
    }
}

impl TenantScoped for TenantScope<'_> {
    fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}
