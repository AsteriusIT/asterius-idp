//! Fixed-cost tenant aggregates for the administration overview.
//!
//! Every aggregate is a scalar count over an indexed tenant predicate. The
//! boolean guards are bound parameters chosen after authorization; PostgreSQL
//! therefore never evaluates a subquery for a metric the caller may not read.

use asterius_domain::{DomainError, TenantId};
use sqlx::PgPool;
use time::OffsetDateTime;

/// The one aggregate an already-authorized route requested.
#[derive(Debug, Clone, Copy)]
pub enum Metric {
    Users,
    Sessions,
    Applications,
    Authentication,
    Keys,
    Delivery,
}

/// Reads the overview from the process's shared pool.
#[derive(Debug, Clone)]
pub struct PgOverview {
    pool: PgPool,
}

impl PgOverview {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Runs the one bounded scalar statement selected by the authorized route.
    pub async fn read(
        &self,
        tenant: &TenantId,
        metric: Metric,
        now: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let statement = match metric {
            Metric::Users => {
                "select count(*) from users where tenant_id = $1 and status = 'active'"
            }
            Metric::Sessions => {
                "select count(*) from sessions where tenant_id = $1 and revoked_at is null and expires_at > $2 and idle_expires_at > $2"
            }
            Metric::Applications => "select count(*) from clients where tenant_id = $1",
            Metric::Authentication => {
                "select count(*) from audit_events where tenant_id = $1 and event_type = 'auth.failed' and occurred_at >= $2 - interval '24 hours'"
            }
            Metric::Keys => {
                "select count(*) from signing_keys where tenant_id = $1 and purpose = 'sig' and state = 'active'"
            }
            Metric::Delivery => {
                "select count(*) from outbox_attempts where tenant_id = $1 and outcome in ('retry', 'abandoned') and attempted_at >= $2 - interval '24 hours'"
            }
        };
        let mut query = sqlx::query_scalar::<_, i64>(statement).bind(tenant.as_str());
        if matches!(
            metric,
            Metric::Sessions | Metric::Authentication | Metric::Delivery
        ) {
            query = query.bind(now);
        }
        let value = query
            .fetch_one(&self.pool)
            .await
            .map_err(crate::to_domain_error)?;
        u64::try_from(value)
            .map_err(|_| DomainError::invalid("overview.count", "a count was negative"))
    }
}
