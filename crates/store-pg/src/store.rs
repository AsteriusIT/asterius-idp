//! The connection pool and the migrator.

use sqlx::migrate::Migrator;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

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

    /// How long a readiness probe waits before deciding the answer is "no".
    ///
    /// Short on purpose. `sqlx` will happily wait out its acquire timeout for a
    /// connection, which for a readiness probe is the wrong answer delivered
    /// slowly: a load balancer that gets no response at all keeps sending
    /// traffic to a replica that cannot serve it. Failing in two seconds is
    /// more useful than being right in thirty.
    const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

    /// Whether the database answers, within [`Store::PROBE_TIMEOUT`].
    ///
    /// Deliberately the cheapest possible query: the question is "is the
    /// connection usable", not "is the schema correct".
    pub async fn ping(&self) -> bool {
        let query = sqlx::query("select 1").fetch_optional(&self.pool);
        matches!(
            tokio::time::timeout(Self::PROBE_TIMEOUT, query).await,
            Ok(Ok(_))
        )
    }

    /// Whether every migration compiled into this binary is recorded applied.
    ///
    /// A binary running against a schema older than itself fails in ways that
    /// look like data corruption rather than a deployment mistake, so it should
    /// refuse traffic instead.
    pub async fn migrations_applied(&self) -> bool {
        let expected = MIGRATOR.iter().count();
        let query =
            sqlx::query_scalar::<_, i64>("select count(*) from _sqlx_migrations where success")
                .fetch_one(&self.pool);
        // No table means no migration has ever run; a timeout means we cannot
        // tell, which for readiness is the same answer.
        match tokio::time::timeout(Self::PROBE_TIMEOUT, query).await {
            Ok(Ok(count)) => usize::try_from(count).is_ok_and(|count| count >= expected),
            _ => false,
        }
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
