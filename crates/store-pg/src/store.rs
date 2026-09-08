//! The connection pool and the migrator.

use sqlx::migrate::Migrator;
use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::scope::TenantScope;
use asterius_domain::TenantId;

/// The baseline schema and every migration after it.
///
/// Embedded in the binary rather than shipped alongside it: an operator can
/// then upgrade by replacing one file, and the binary can never be paired with
/// migrations from a different version.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// A handle on the database.
#[derive(Debug, Clone)]
pub struct Store {
    pool: PgPool,
}

impl Store {
    /// Connects, without running migrations.
    ///
    /// # Errors
    ///
    /// Returns the `sqlx` error if the pool cannot be created.
    pub async fn connect(url: &str, max_connections: u32) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    /// Wraps an existing pool.
    #[must_use]
    pub const fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Applies any migrations the database has not seen.
    ///
    /// # Errors
    ///
    /// Returns a migration error if a migration fails or if an already-applied
    /// migration's checksum has changed.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }

    /// The underlying pool, for adapters in this crate.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Confines every subsequent operation to one tenant.
    ///
    /// This is the only way to reach a tenant-scoped repository, so a query
    /// that forgot its tenant is not something a caller can express.
    #[must_use]
    pub fn scope(&self, tenant: TenantId) -> TenantScope<'_> {
        TenantScope::new(&self.pool, tenant)
    }
}
