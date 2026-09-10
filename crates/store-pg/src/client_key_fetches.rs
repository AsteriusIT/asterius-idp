//! The shared negative cache for client JWK Set fetches, over PostgreSQL.
//!
//! One row per `(tenant, client, jwks_uri)` that failed, holding the instant
//! before which no replica fetches it again. See
//! [`asterius_domain::ports::ClientKeyFetchBackoff`] for why the in-memory
//! cache in `asterius-jose` is not enough on its own, and
//! `0006_client_key_fetches.sql` for why the URL is stored as a digest.

use crate::error::to_domain_error;
use asterius_domain::ports::ClientKeyFetchBackoff;
use asterius_domain::{ClientId, DomainError, TenantId, sha256};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// The most characters of a failure reason kept.
///
/// The database enforces the same bound; this is where a long reason is cut
/// rather than turned into a write error, because a fetch that failed *and*
/// whose failure could not be recorded is the worst of both.
const MAX_ERROR_CHARS: usize = 200;

/// [`ClientKeyFetchBackoff`] over PostgreSQL.
#[derive(Debug, Clone)]
pub struct PgClientKeyFetches {
    pool: PgPool,
}

impl PgClientKeyFetches {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// The first [`MAX_ERROR_CHARS`] characters of `reason`.
///
/// On a character boundary, so a multi-byte reason is shortened rather than
/// made invalid, and the truncation is marked so that nobody reads a cut
/// sentence as the whole one.
fn bounded(reason: &str) -> String {
    match reason.char_indices().nth(MAX_ERROR_CHARS - 1) {
        Some((cut, _)) => format!("{}…", &reason[..cut]),
        None => reason.to_owned(),
    }
}

#[async_trait::async_trait]
impl ClientKeyFetchBackoff for PgClientKeyFetches {
    async fn next_attempt_at(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        jwks_uri: &str,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        let uri_hash = sha256(jwks_uri.as_bytes());
        let row = sqlx::query!(
            "select next_attempt_at from client_key_fetches
              where tenant_id = $1 and client_id = $2 and jwks_uri_hash = $3",
            tenant.as_str(),
            client.as_str(),
            &uri_hash[..],
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(row.map(|row| row.next_attempt_at))
    }

    async fn record_failure(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        jwks_uri: &str,
        error: &str,
        attempted_at: OffsetDateTime,
        next_attempt_at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let uri_hash = sha256(jwks_uri.as_bytes());
        // Last writer wins, and that is the right rule: whichever replica
        // attempted most recently knows the most about this URL. The `where`
        // keeps a slow replica's stale report from moving the deadline
        // backwards — the row is a deadline every replica reads, so it must
        // only ever be pushed forward by a *later* attempt.
        sqlx::query!(
            "insert into client_key_fetches
                 (tenant_id, client_id, jwks_uri_hash,
                  last_attempt_at, last_error, next_attempt_at)
             values ($1, $2, $3, $4, $5, $6)
             on conflict (tenant_id, client_id, jwks_uri_hash) do update
                set last_attempt_at = excluded.last_attempt_at,
                    last_error      = excluded.last_error,
                    next_attempt_at = excluded.next_attempt_at
              where client_key_fetches.last_attempt_at < excluded.last_attempt_at",
            tenant.as_str(),
            client.as_str(),
            &uri_hash[..],
            attempted_at,
            bounded(error),
            next_attempt_at,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    async fn clear(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        jwks_uri: &str,
    ) -> Result<(), DomainError> {
        let uri_hash = sha256(jwks_uri.as_bytes());
        sqlx::query!(
            "delete from client_key_fetches
              where tenant_id = $1 and client_id = $2 and jwks_uri_hash = $3",
            tenant.as_str(),
            client.as_str(),
            &uri_hash[..],
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The column is bounded in the schema; cutting here is what keeps a long
    /// reason from turning a recorded failure into an unrecorded one.
    #[test]
    fn a_long_reason_is_cut_to_the_column_bound() {
        let long = "é".repeat(1_000);
        let bounded = bounded(&long);
        assert_eq!(bounded.chars().count(), MAX_ERROR_CHARS);
        assert!(bounded.ends_with('…'));
    }

    /// A reason that fits is stored as it is, ellipsis included or not.
    #[test]
    fn a_short_reason_is_left_alone() {
        assert_eq!(
            bounded("cannot connect to client.example"),
            "cannot connect to client.example"
        );
    }
}
