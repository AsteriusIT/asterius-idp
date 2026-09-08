//! The tenant scope: the handle every tenant-scoped repository hangs off.

use crate::clients::PgClientRepository;
use crate::grants::PgGrantRepository;
use crate::users::PgUserRepository;
use asterius_domain::ports::TenantScoped;
use asterius_domain::{Capabilities, TenantId};
use sqlx::postgres::PgPool;

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
    #[must_use]
    pub fn users(&self) -> PgUserRepository {
        PgUserRepository::new(self.pool.clone(), self.tenant.clone())
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
