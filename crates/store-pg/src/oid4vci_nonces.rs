//! Shared, single-use OpenID4VCI credential proof challenges.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId, sha256};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};

/// How long a wallet may retain a `c_nonce` before requesting another.
pub const NONCE_LIFETIME: Duration = Duration::minutes(5);

/// The nonce database adapter; every statement is tenant-bound.
#[derive(Debug, Clone)]
pub struct PgOid4vciNonces {
    pool: PgPool,
    tenant: TenantId,
}

impl PgOid4vciNonces {
    /// Binds the adapter to one tenant.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Issues a random, one-time nonce and stores only its digest.
    ///
    /// # Errors
    ///
    /// A database failure prevents issuance.
    pub async fn issue(&self, now: OffsetDateTime) -> Result<String, DomainError> {
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let digest = sha256(nonce.as_bytes());
        sqlx::query(
            "insert into oid4vci_nonces (tenant_id, nonce_digest, expires_at)
             values ($1, $2, $3)",
        )
        .bind(self.tenant.as_str())
        .bind(digest.as_slice())
        .bind(now + NONCE_LIFETIME)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(nonce)
    }

    /// Atomically consumes a previously issued nonce for this tenant.
    ///
    /// A caller must first verify the wallet's JWT proof and authorization;
    /// the nonce itself is public and is never an access credential.
    ///
    /// # Errors
    ///
    /// Database failure is not treated as a first use.
    pub async fn consume(&self, nonce: &str, now: OffsetDateTime) -> Result<bool, DomainError> {
        if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(false);
        }
        let digest = sha256(nonce.as_bytes());
        let result = sqlx::query(
            "update oid4vci_nonces set consumed_at = $3
             where tenant_id = $1 and nonce_digest = $2
               and consumed_at is null and expires_at > $3",
        )
        .bind(self.tenant.as_str())
        .bind(digest.as_slice())
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Removes expired rows for this tenant.
    ///
    /// # Errors
    ///
    /// A database failure is returned for the caller to log.
    pub async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64, DomainError> {
        let result =
            sqlx::query("delete from oid4vci_nonces where tenant_id = $1 and expires_at <= $2")
                .bind(self.tenant.as_str())
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(to_domain_error)?;
        Ok(result.rows_affected())
    }
}
