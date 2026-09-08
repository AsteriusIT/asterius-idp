//! Single-use enforcement for `jti` values, over PostgreSQL.
//!
//! The whole adapter is one `insert ... on conflict do nothing`, and that is
//! the point: the check and the record are the same statement, so there is no
//! window between "have I seen this?" and "now I have" for a replayed
//! assertion to fit through.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, ReplayCheck, ReplayGuard, ReplayPurpose, TenantId, sha256};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// [`ReplayGuard`] over PostgreSQL.
#[derive(Debug, Clone)]
pub struct PgReplayGuard {
    pool: PgPool,
}

impl PgReplayGuard {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Drops one tenant's entries whose tokens have expired.
    ///
    /// An expired entry protects nothing: the token it describes now fails on
    /// `exp` before the replay check is ever reached. Retention here is
    /// therefore bounded by the *longest permitted assertion lifetime* rather
    /// than by policy — ten minutes, not ninety days — which is why this table
    /// stays small without anybody tuning it.
    ///
    /// Per tenant, though a single unqualified `delete` would be cheaper. The
    /// `sql_audit` invariant is that *every* statement over a tenant-scoped
    /// table names `tenant_id`, and an invariant with one maintenance-shaped
    /// exception is one an ordinary query can later be written to look like.
    /// The caller iterates tenants; the loop costs less than the exception
    /// would.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Storage`] if the delete fails.
    pub async fn purge_expired(
        &self,
        tenant: &TenantId,
        now: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let result = sqlx::query!(
            "delete from jti_replay where tenant_id = $1 and expires_at <= $2",
            tenant.as_str(),
            now
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected())
    }
}

#[async_trait::async_trait]
impl ReplayGuard for PgReplayGuard {
    async fn claim(
        &self,
        tenant: &TenantId,
        purpose: ReplayPurpose,
        subject: &str,
        jti: &str,
        expires_at: OffsetDateTime,
    ) -> Result<ReplayCheck, DomainError> {
        // Hashed because the `jti` is chosen by the client: it is only ever
        // compared for equality, so storing the bytes themselves would put an
        // attacker-controlled string in the database to no purpose. A digest
        // is also fixed-width, which keeps the primary key's size independent
        // of what a client sends.
        let jti_hash = sha256(jti.as_bytes());

        // One statement. `on conflict do nothing` makes the insert the test:
        // a row appears only if this `jti` was not already recorded, and the
        // database resolves the race between two concurrent replays rather
        // than this process trying to.
        let inserted = sqlx::query!(
            "insert into jti_replay (tenant_id, purpose, subject, jti_hash, expires_at)
             values ($1, $2, $3, $4, $5)
             on conflict (tenant_id, purpose, subject, jti_hash) do nothing",
            tenant.as_str(),
            purpose.as_str(),
            subject,
            &jti_hash[..],
            expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        // Exactly one row means this insert won. Zero means an earlier one did.
        if inserted.rows_affected() == 1 {
            Ok(ReplayCheck::FirstUse)
        } else {
            Ok(ReplayCheck::Replay)
        }
    }
}
