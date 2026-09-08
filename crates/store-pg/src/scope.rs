//! The tenant scope: the handle every tenant-scoped repository hangs off.

use asterius_domain::TenantId;
use asterius_domain::ports::TenantScoped;
use sqlx::postgres::PgPool;

/// Database access confined to one tenant.
///
/// Repositories for clients, users, sessions, grants and tokens are implemented
/// as methods on this type (each by its own story), and every one of them binds
/// [`TenantScope::tenant`] into its `WHERE` clause. The tenant is therefore not
/// an argument a caller can omit — it is a precondition of having the handle.
#[derive(Debug, Clone)]
pub struct TenantScope<'a> {
    #[expect(
        dead_code,
        reason = "the seam is deliberately empty: each repository is added by \
                  its own story (clients ast-m9c.1, sessions ast-2vk.2, grants \
                  ast-uwv.2), and every one of them reaches the database through \
                  this field so that the tenant is already chosen"
    )]
    pool: &'a PgPool,
    tenant: TenantId,
}

impl<'a> TenantScope<'a> {
    pub(crate) const fn new(pool: &'a PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }
}

impl TenantScoped for TenantScope<'_> {
    fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}
