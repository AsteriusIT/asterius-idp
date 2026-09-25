//! Tenant-scoped Native SSO device credentials and derived grant links.

use crate::error::to_domain_error;
use asterius_domain::{ClientId, DomainError, GrantId, TenantId, UserId};
use sqlx::{PgPool, Row as _};
use time::OffsetDateTime;

/// A validated device credential, never containing its bearer value.
#[derive(Debug, Clone)]
pub struct NativeSsoBinding {
    pub source_client: ClientId,
    pub source_grant: GrantId,
    pub user: UserId,
    pub public_sid: String,
    pub session_digest: String,
}

/// Native SSO's stored credentials, scoped to a single tenant.
#[derive(Debug, Clone)]
pub struct PgNativeSso {
    pool: PgPool,
    tenant: TenantId,
}

impl PgNativeSso {
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Stores a digest only when the source grant and browser session are live.
    pub async fn issue(
        &self,
        digest: &[u8],
        source: &ClientId,
        grant: &GrantId,
        user: &UserId,
        sid: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let grant_id = uuid::Uuid::parse_str(grant.as_str())
            .map_err(|_| DomainError::invalid("grant_id", "invalid UUID"))?;
        let result = sqlx::query(
            "insert into native_sso_secrets
                (tenant_id, secret_digest, source_client_id, source_grant_id,
                 user_id, public_sid, expires_at)
             select $1, $2, g.client_id, g.grant_id, s.user_id, s.public_sid, s.expires_at
               from grants g
               join sessions s on s.tenant_id = g.tenant_id
              where g.tenant_id = $1 and g.grant_id = $4 and g.client_id = $3
                and g.user_id = $5 and s.public_sid = $6 and s.user_id = g.user_id
                and g.revoked_at is null and (g.expires_at is null or g.expires_at > $7)
                and s.revoked_at is null and s.expires_at > $7
                and s.idle_expires_at > $7
              for share of g, s",
        )
        .bind(self.tenant.as_str())
        .bind(digest)
        .bind(source.as_str())
        .bind(grant_id)
        .bind(user.as_uuid())
        .bind(sid)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Resolves only a live secret under a live session and source grant.
    pub async fn binding(
        &self,
        digest: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<NativeSsoBinding>, DomainError> {
        let row = sqlx::query(
            "select n.source_client_id, n.source_grant_id, n.user_id, n.public_sid, s.session_id
               from native_sso_secrets n
               join sessions s on s.tenant_id = n.tenant_id and s.public_sid = n.public_sid
               join grants g on g.tenant_id = n.tenant_id and g.grant_id = n.source_grant_id
              where n.tenant_id = $1 and n.secret_digest = $2
                and n.revoked_at is null and n.expires_at > $3
                and s.revoked_at is null and s.expires_at > $3 and s.idle_expires_at > $3
                and g.revoked_at is null and (g.expires_at is null or g.expires_at > $3)
                and g.client_id = n.source_client_id and g.user_id = n.user_id",
        )
        .bind(self.tenant.as_str())
        .bind(digest)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(|row| {
            let grant: uuid::Uuid = row.try_get("source_grant_id").map_err(to_domain_error)?;
            let user: uuid::Uuid = row.try_get("user_id").map_err(to_domain_error)?;
            Ok(NativeSsoBinding {
                source_client: ClientId::new(
                    row.try_get::<String, _>("source_client_id")
                        .map_err(to_domain_error)?,
                ),
                source_grant: GrantId::new(grant.to_string()),
                user: UserId::new(user),
                public_sid: row.try_get("public_sid").map_err(to_domain_error)?,
                session_digest: row.try_get("session_id").map_err(to_domain_error)?,
            })
        })
        .transpose()
    }

    /// Links a derived grant to its source session, or refuses a closed session.
    pub async fn link_derivation(
        &self,
        secret_digest: &[u8],
        grant: &GrantId,
        source_grant: &GrantId,
        sid: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let grant_id = uuid::Uuid::parse_str(grant.as_str())
            .map_err(|_| DomainError::invalid("grant_id", "invalid UUID"))?;
        let source_id = uuid::Uuid::parse_str(source_grant.as_str())
            .map_err(|_| DomainError::invalid("source_grant_id", "invalid UUID"))?;
        let result = sqlx::query(
            "insert into native_sso_derivations (tenant_id, grant_id, public_sid, source_grant_id)
             select $1, $2, s.public_sid, g.grant_id
               from sessions s
               join native_sso_secrets n on n.tenant_id = s.tenant_id and n.public_sid = s.public_sid
               join grants g on g.tenant_id = n.tenant_id and g.grant_id = n.source_grant_id
              where s.tenant_id = $1 and s.public_sid = $4
                and n.secret_digest = $6 and n.source_grant_id = $3
                and n.revoked_at is null and n.expires_at > $5
                and g.revoked_at is null and (g.expires_at is null or g.expires_at > $5)
                and s.revoked_at is null and s.expires_at > $5 and s.idle_expires_at > $5
              for share of s, n, g",
        )
        .bind(self.tenant.as_str())
        .bind(grant_id)
        .bind(source_id)
        .bind(sid)
        .bind(now)
        .bind(secret_digest)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }
}
