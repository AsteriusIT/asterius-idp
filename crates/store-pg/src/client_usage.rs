//! When a client last authenticated (`ast-cu3`).
//!
//! # Why this is a write on the authentication path, and why it is cheap
//!
//! `unused_client_expiry_seconds` is a per-tenant policy that has been stored,
//! validated and unread since `ast-m9c.6`, because nothing in the schema could
//! say when a client was last used. The only place that can answer is the
//! place where a client authenticates, which is
//! `asterius_server::client_auth::ClientAuthenticator` — one function, reached
//! by both the token endpoint and PAR, so there is one definition of "used"
//! rather than two that drift.
//!
//! That is also the hottest path in the server, and a write per token request
//! would be a row lock per token request on a table every endpoint reads. So
//! the statement carries its own predicate: it only writes when the recorded
//! instant is more than [`GRANULARITY`] old. A busy client costs one update an
//! hour instead of one per request, and the value the sweep reads is accurate
//! to the hour — against a policy whose unit is days.
//!
//! # It only ever moves forward
//!
//! The predicate is `last_used_at < now - granularity`, so a replica whose
//! clock is behind cannot move the instant backwards past the granularity
//! window, and a client that authenticates at two replicas at once produces
//! one write. Moving it backwards is the one thing that would matter: it is
//! what would let a *used* client be swept.
//!
//! # A runtime query, not `query!`
//!
//! The trade [`crate::tenant_settings`] states. One single-column update on a
//! table this crate already reads with `query!`; the database tests exercise
//! it against the real schema, and `crate::sql_audit` enforces the tenant
//! predicate on the literal.

use crate::error::to_domain_error;
use asterius_domain::ports::ClientUsageRecorder;
use asterius_domain::{ClientId, DomainError, TenantId};
use sqlx::postgres::PgPool;
use time::{Duration, OffsetDateTime};

/// How coarse the recorded instant is.
///
/// One hour. The only reader is a retention sweep whose window is a number of
/// days an operator chose, so an hour of imprecision cannot change its answer
/// unless the operator set an expiry shorter than an hour — which
/// `RegistrationPolicy` accepts and which would be a decision to delete
/// clients hourly, not a case this granularity breaks.
pub const GRANULARITY: Duration = Duration::hours(1);

/// `ClientUsageRecorder` over `PostgreSQL`.
#[derive(Debug, Clone)]
pub struct PgClientUsage {
    pool: PgPool,
}

impl PgClientUsage {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ClientUsageRecorder for PgClientUsage {
    async fn record_use(
        &self,
        tenant: &TenantId,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "update clients
                set last_used_at = $3
              where tenant_id = $1
                and client_id = $2
                and (last_used_at is null or last_used_at < $4)",
        )
        .bind(tenant.as_str())
        .bind(client_id.as_str())
        .bind(now)
        .bind(now - GRANULARITY)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The granularity is what keeps this off the hot path, and it is only
    /// safe while it is far below the shortest expiry an operator would set.
    #[test]
    fn the_granularity_is_far_below_any_plausible_expiry() {
        // Arrange / Act / Assert
        assert!(GRANULARITY < Duration::days(1));
        assert!(GRANULARITY > Duration::ZERO);
    }
}
