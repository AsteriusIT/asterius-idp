//! Fixed-window counters over PostgreSQL.
//!
//! The increment is a single `insert … on conflict do update … returning`, so
//! two replicas racing on the same bucket serialise on the row rather than on
//! anybody's opinion. That is the whole reason the state is here and not in a
//! process: a counter per replica is a limit multiplied by the replica count
//! (`asterius_domain::rate_limit` says why at length).
//!
//! Nothing here is tenant-agnostic. A bucket is scoped by `tenant_id` like
//! every other row in the schema, so one tenant's failures cannot lock another
//! tenant's users out.

use crate::error::to_domain_error;
use asterius_domain::rate_limit::{Bucket, RateLimitStore};
use asterius_domain::{DomainError, TenantId};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// [`RateLimitStore`] over PostgreSQL.
#[derive(Debug, Clone)]
pub struct PgRateLimitStore {
    pool: PgPool,
}

impl PgRateLimitStore {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Narrows a stored counter to the domain's type.
///
/// The column is `integer` and the counter only ever grows by one, so a
/// negative or oversized value is not reachable — but saturating is still the
/// right answer if it ever were: a counter that wrapped to zero would open the
/// limit, and a limiter that fails open is not a limiter.
fn saturate(counter: i32) -> u32 {
    u32::try_from(counter).unwrap_or(u32::MAX)
}

#[async_trait::async_trait]
impl RateLimitStore for PgRateLimitStore {
    async fn count(
        &self,
        tenant: &TenantId,
        bucket: &Bucket,
        window_start: OffsetDateTime,
    ) -> Result<u32, DomainError> {
        let row = sqlx::query!(
            "select counter from rate_limits
              where tenant_id = $1 and bucket = $2 and window_start = $3",
            tenant.as_str(),
            bucket.as_str(),
            window_start,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(row.map_or(0, |row| saturate(row.counter)))
    }

    async fn record(
        &self,
        tenant: &TenantId,
        bucket: &Bucket,
        window_start: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<u32, DomainError> {
        // `greatest` on the expiry rather than `excluded.expires_at`: a row
        // must never have its life shortened by a later write, or a sweep
        // would remove a window that is still counting.
        let row = sqlx::query!(
            "insert into rate_limits (tenant_id, bucket, window_start, counter, expires_at)
                  values ($1, $2, $3, 1, $4)
             on conflict (tenant_id, bucket, window_start) do update
                     set counter = rate_limits.counter + 1,
                         expires_at = greatest(rate_limits.expires_at, excluded.expires_at)
               returning counter",
            tenant.as_str(),
            bucket.as_str(),
            window_start,
            expires_at,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(saturate(row.counter))
    }

    async fn clear(&self, tenant: &TenantId, bucket: &Bucket) -> Result<(), DomainError> {
        // Every window of the bucket, not only the current one: the boundary is
        // aligned to the epoch, so a proof made a second before a rollover would
        // otherwise leave the next window a counter it never earned. The rows
        // are keyed by `(tenant_id, bucket, window_start)` and a bucket holds at
        // most a handful of live windows, so the delete is bounded by the index.
        sqlx::query!(
            "delete from rate_limits where tenant_id = $1 and bucket = $2",
            tenant.as_str(),
            bucket.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::saturate;

    #[test]
    fn a_counter_that_could_not_be_read_as_a_count_saturates_rather_than_wrapping() {
        assert_eq!(saturate(-1), u32::MAX);
        assert_eq!(saturate(7), 7);
    }
}
