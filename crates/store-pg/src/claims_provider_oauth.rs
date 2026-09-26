//! Single-use, session-bound Claims Provider OAuth setup transactions.

use crate::error::to_domain_error;
use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::{DomainError, TenantId, UserId};
use asterius_jose::{Kek, KeyBinding, RowSecret, WrappedKey};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroize;

/// Locally held CP tokens. Debug output deliberately omits both credentials.
pub struct CpConnection {
    pub provider_issuer: String,
    pub provider_subject: String,
    pub granted_scope: String,
    pub access_token: String,
    pub access_expires_at: OffsetDateTime,
    pub refresh_token: Option<String>,
    pub refresh_expires_at: Option<OffsetDateTime>,
    pub revision: i64,
}

impl Drop for CpConnection {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(token) = &mut self.refresh_token {
            token.zeroize();
        }
    }
}

impl std::fmt::Debug for CpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CpConnection")
            .field("provider_issuer", &self.provider_issuer)
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .finish_non_exhaustive()
    }
}

/// Metadata safe for the account page.
#[derive(Debug)]
pub struct CpConnectionSummary {
    pub provider_issuer: String,
    pub access_expires_at: OffsetDateTime,
    pub refresh_expires_at: Option<OffsetDateTime>,
}

/// A consumed setup request. The verifier is held only long enough to redeem
/// the authorization code and is never returned to the browser.
pub struct CpPending {
    pub user_id: Uuid,
    pub provider_issuer: String,
    pub provider_nonce: String,
    pub code_verifier: String,
    pub created_at: OffsetDateTime,
}

impl Drop for CpPending {
    fn drop(&mut self) {
        self.code_verifier.zeroize();
    }
}

impl std::fmt::Debug for CpPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CpPending")
            .field("user_id", &self.user_id)
            .field("provider_issuer", &self.provider_issuer)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct PgCpOAuth {
    pool: PgPool,
    tenant: TenantId,
    kek: Arc<dyn Kek>,
}

impl std::fmt::Debug for PgCpOAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PgCpOAuth")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgCpOAuth {
    #[must_use]
    pub fn new(pool: PgPool, tenant: TenantId, kek: Arc<dyn Kek>) -> Self {
        Self { pool, tenant, kek }
    }

    fn binding(user: UserId, issuer: &str) -> String {
        format!("{}:{issuer}", user.as_uuid())
    }

    async fn seal(
        &self,
        user: UserId,
        issuer: &str,
        kind: RowSecret,
        token: &str,
    ) -> Result<WrappedKey, DomainError> {
        self.kek
            .wrap(
                KeyBinding::row_secret(&self.tenant, kind, &Self::binding(user, issuer)),
                token.as_bytes(),
            )
            .await
            .map_err(|error| DomainError::Storage(Box::new(error)))
    }

    async fn open(
        &self,
        user: UserId,
        issuer: &str,
        kind: RowSecret,
        kek_id: String,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<String, DomainError> {
        let wrapped = WrappedKey::from_parts(kek_id, nonce, ciphertext)
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let plain = self
            .kek
            .unwrap(
                KeyBinding::row_secret(&self.tenant, kind, &Self::binding(user, issuer)),
                &wrapped,
            )
            .await
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
        String::from_utf8(plain.to_vec()).map_err(|_| {
            DomainError::invalid("claims_provider.oauth", "stored credential is invalid")
        })
    }

    /// Store the verified initial grant. An existing provider subject cannot change silently.
    pub async fn save(
        &self,
        user: UserId,
        connection: &CpConnection,
        started_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<i64, DomainError> {
        self.validate(connection, now)?;
        let access = self
            .seal(
                user,
                &connection.provider_issuer,
                RowSecret::ClaimsProviderAccessToken,
                &connection.access_token,
            )
            .await?;
        let refresh = match &connection.refresh_token {
            Some(token) => Some(
                self.seal(
                    user,
                    &connection.provider_issuer,
                    RowSecret::ClaimsProviderRefreshToken,
                    token,
                )
                .await?,
            ),
            None => None,
        };
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let present: Option<Uuid> = sqlx::query_scalar(
            "select user_id from users where tenant_id=$1 and user_id=$2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if present.is_none() {
            return Err(DomainError::NotFound);
        }
        let db_now: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        if started_at > db_now || started_at < db_now - time::Duration::minutes(15) {
            return Err(DomainError::invalid(
                "claims_provider.oauth",
                "setup window expired",
            ));
        }
        let revoked_at: Option<OffsetDateTime> = sqlx::query_scalar(
            "select revoked_at from claims_provider_oauth_revocations
            where tenant_id=$1 and user_id=$2 and provider_issuer=$3",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .bind(&connection.provider_issuer)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if revoked_at.is_some_and(|revoked| revoked >= started_at) {
            return Err(DomainError::invalid(
                "claims_provider.oauth",
                "setup was revoked",
            ));
        }
        let result = sqlx::query("insert into claims_provider_oauth_connections
            (tenant_id,user_id,provider_issuer,provider_subject,granted_scope,access_ciphertext,access_nonce,access_kek_id,access_expires_at,
             refresh_ciphertext,refresh_nonce,refresh_kek_id,refresh_expires_at,updated_at)
            values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
            on conflict (tenant_id,user_id,provider_issuer) do update set
              granted_scope=excluded.granted_scope, access_ciphertext=excluded.access_ciphertext, access_nonce=excluded.access_nonce,
              access_kek_id=excluded.access_kek_id, access_expires_at=excluded.access_expires_at,
              refresh_ciphertext=excluded.refresh_ciphertext,refresh_nonce=excluded.refresh_nonce,
              refresh_kek_id=excluded.refresh_kek_id,refresh_expires_at=excluded.refresh_expires_at,
              revision=claims_provider_oauth_connections.revision+1,updated_at=excluded.updated_at
            where claims_provider_oauth_connections.provider_subject=excluded.provider_subject
            returning revision")
            .bind(self.tenant.as_str()).bind(user.as_uuid()).bind(&connection.provider_issuer)
            .bind(&connection.provider_subject).bind(&connection.granted_scope)
            .bind(access.ciphertext()).bind(access.nonce()).bind(access.kek_id()).bind(connection.access_expires_at)
            .bind(refresh.as_ref().map(WrappedKey::ciphertext)).bind(refresh.as_ref().map(WrappedKey::nonce))
            .bind(refresh.as_ref().map(WrappedKey::kek_id)).bind(connection.refresh_expires_at).bind(now)
            .fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        let Some(result) = result else {
            return Err(DomainError::invalid(
                "claims_provider.oauth",
                "provider subject changed",
            ));
        };
        let revision = result.try_get("revision").map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(revision)
    }

    fn validate(&self, connection: &CpConnection, now: OffsetDateTime) -> Result<(), DomainError> {
        if connection.provider_issuer.is_empty()
            || connection.provider_issuer.len() > 2048
            || connection.provider_subject.is_empty()
            || connection.provider_subject.len() > 256
            || connection.granted_scope.is_empty()
            || connection.granted_scope.len() > 512
            || connection.access_token.is_empty()
            || connection.access_token.len() > 4096
            || connection.access_expires_at <= now
            || connection.access_expires_at > now + time::Duration::hours(1)
            || connection
                .refresh_token
                .as_ref()
                .is_some_and(|token| token.is_empty() || token.len() > 4096)
            || connection.refresh_token.is_some() != connection.refresh_expires_at.is_some()
            || connection
                .refresh_expires_at
                .is_some_and(|expiry| expiry <= now || expiry > now + time::Duration::days(30))
        {
            return Err(DomainError::invalid(
                "claims_provider.oauth",
                "credential bounds are invalid",
            ));
        }
        Ok(())
    }

    pub async fn by_user(
        &self,
        user: UserId,
        now: OffsetDateTime,
    ) -> Result<Vec<CpConnectionSummary>, DomainError> {
        let rows = sqlx::query("select provider_issuer,access_expires_at,refresh_expires_at from claims_provider_oauth_connections
            where tenant_id=$1 and user_id=$2 and (access_expires_at>$3 or refresh_expires_at>$3) order by provider_issuer")
            .bind(self.tenant.as_str()).bind(user.as_uuid()).bind(now).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        rows.into_iter()
            .map(|row| {
                Ok(CpConnectionSummary {
                    provider_issuer: row.try_get("provider_issuer").map_err(to_domain_error)?,
                    access_expires_at: row.try_get("access_expires_at").map_err(to_domain_error)?,
                    refresh_expires_at: row
                        .try_get("refresh_expires_at")
                        .map_err(to_domain_error)?,
                })
            })
            .collect()
    }

    pub async fn load(
        &self,
        user: UserId,
        issuer: &str,
        now: OffsetDateTime,
    ) -> Result<Option<CpConnection>, DomainError> {
        let row = sqlx::query("select provider_subject,granted_scope,access_ciphertext,access_nonce,access_kek_id,access_expires_at,
            refresh_ciphertext,refresh_nonce,refresh_kek_id,refresh_expires_at,revision
            from claims_provider_oauth_connections where tenant_id=$1 and user_id=$2 and provider_issuer=$3
              and (access_expires_at>$4 or refresh_expires_at>$4)")
            .bind(self.tenant.as_str()).bind(user.as_uuid()).bind(issuer).bind(now)
            .fetch_optional(&self.pool).await.map_err(to_domain_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let access_token = self
            .open(
                user,
                issuer,
                RowSecret::ClaimsProviderAccessToken,
                row.try_get("access_kek_id").map_err(to_domain_error)?,
                row.try_get("access_nonce").map_err(to_domain_error)?,
                row.try_get("access_ciphertext").map_err(to_domain_error)?,
            )
            .await?;
        let refresh_token = match (
            row.try_get::<Option<String>, _>("refresh_kek_id")
                .map_err(to_domain_error)?,
            row.try_get::<Option<Vec<u8>>, _>("refresh_nonce")
                .map_err(to_domain_error)?,
            row.try_get::<Option<Vec<u8>>, _>("refresh_ciphertext")
                .map_err(to_domain_error)?,
        ) {
            (Some(kek), Some(nonce), Some(ciphertext)) => Some(
                self.open(
                    user,
                    issuer,
                    RowSecret::ClaimsProviderRefreshToken,
                    kek,
                    nonce,
                    ciphertext,
                )
                .await?,
            ),
            (None, None, None) => None,
            _ => {
                return Err(DomainError::invalid(
                    "claims_provider.oauth",
                    "stored refresh envelope is incomplete",
                ));
            }
        };
        Ok(Some(CpConnection {
            provider_issuer: issuer.to_owned(),
            provider_subject: row.try_get("provider_subject").map_err(to_domain_error)?,
            granted_scope: row.try_get("granted_scope").map_err(to_domain_error)?,
            access_token,
            access_expires_at: row.try_get("access_expires_at").map_err(to_domain_error)?,
            refresh_token,
            refresh_expires_at: row.try_get("refresh_expires_at").map_err(to_domain_error)?,
            revision: row.try_get("revision").map_err(to_domain_error)?,
        }))
    }

    /// Compare-and-swap the rotated token; a concurrent refresh cannot overwrite newer credentials.
    pub async fn rotate(
        &self,
        user: UserId,
        connection: &CpConnection,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        self.validate(connection, now)?;
        let access = self
            .seal(
                user,
                &connection.provider_issuer,
                RowSecret::ClaimsProviderAccessToken,
                &connection.access_token,
            )
            .await?;
        let refresh = match &connection.refresh_token {
            Some(token) => Some(
                self.seal(
                    user,
                    &connection.provider_issuer,
                    RowSecret::ClaimsProviderRefreshToken,
                    token,
                )
                .await?,
            ),
            None => None,
        };
        let changed=sqlx::query("update claims_provider_oauth_connections set access_ciphertext=$1,access_nonce=$2,access_kek_id=$3,
            access_expires_at=$4,refresh_ciphertext=$5,refresh_nonce=$6,refresh_kek_id=$7,refresh_expires_at=$8,
            revision=revision+1,updated_at=$9 where tenant_id=$10 and user_id=$11 and provider_issuer=$12
            and provider_subject=$13 and granted_scope=$14 and revision=$15")
            .bind(access.ciphertext()).bind(access.nonce()).bind(access.kek_id()).bind(connection.access_expires_at)
            .bind(refresh.as_ref().map(WrappedKey::ciphertext)).bind(refresh.as_ref().map(WrappedKey::nonce))
            .bind(refresh.as_ref().map(WrappedKey::kek_id)).bind(connection.refresh_expires_at).bind(now)
            .bind(self.tenant.as_str()).bind(user.as_uuid()).bind(&connection.provider_issuer)
            .bind(&connection.provider_subject).bind(&connection.granted_scope).bind(connection.revision)
            .execute(&self.pool).await.map_err(to_domain_error)?;
        Ok(changed.rows_affected() == 1)
    }

    /// Erase locally held tokens and revoke the signed source in one transaction.
    pub async fn revoke(
        &self,
        user: UserId,
        issuer: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let present: Option<Uuid> = sqlx::query_scalar(
            "select user_id from users where tenant_id=$1 and user_id=$2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if present.is_none() {
            return Err(DomainError::NotFound);
        }
        let revoked_at: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        sqlx::query("insert into claims_provider_oauth_revocations (tenant_id,user_id,provider_issuer,revoked_at)
            values ($1,$2,$3,$4) on conflict (tenant_id,user_id,provider_issuer)
            do update set revoked_at=greatest(claims_provider_oauth_revocations.revoked_at,excluded.revoked_at)")
            .bind(self.tenant.as_str()).bind(user.as_uuid()).bind(issuer).bind(revoked_at)
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        sqlx::query("delete from claims_provider_oauth_pending where tenant_id=$1 and user_id=$2 and provider_issuer=$3")
            .bind(self.tenant.as_str()).bind(user.as_uuid()).bind(issuer)
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        let deleted=sqlx::query("delete from claims_provider_oauth_connections where tenant_id=$1 and user_id=$2 and provider_issuer=$3")
            .bind(self.tenant.as_str()).bind(user.as_uuid()).bind(issuer).execute(&mut *tx).await.map_err(to_domain_error)?;
        let revoked=sqlx::query("update aggregated_claim_sources set revoked_at=$4 where tenant_id=$1 and user_id=$2 and provider_issuer=$3 and revoked_at is null")
            .bind(self.tenant.as_str()).bind(user.as_uuid()).bind(issuer).bind(now).execute(&mut *tx).await.map_err(to_domain_error)?;
        if deleted.rows_affected() > 0 || revoked.rows_affected() > 0 {
            crate::audit::append(
                &mut tx,
                AuditEvent::new(
                    self.tenant.clone(),
                    EventType::USER_CLAIMS_CHANGED,
                    Outcome::Success,
                    Actor::User(user.to_string()),
                    now,
                )
                .subject(user.to_string())
                .detail(
                    Detail::new()
                        .label("operation", "claims_provider.revoke")
                        .text("provider_issuer", issuer),
                ),
            )
            .await?;
        }
        tx.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    /// Remove only the grant written by a failed callback; never remove a
    /// concurrent reconnect or refresh that has since advanced its revision.
    pub async fn discard_if_revision(
        &self,
        user: UserId,
        issuer: &str,
        revision: i64,
    ) -> Result<(), DomainError> {
        sqlx::query("delete from claims_provider_oauth_connections where tenant_id=$1 and user_id=$2 and provider_issuer=$3 and revision=$4")
            .bind(self.tenant.as_str()).bind(user.as_uuid()).bind(issuer).bind(revision)
            .execute(&self.pool).await.map_err(to_domain_error)?;
        Ok(())
    }

    /// Persist a ten-minute setup attempt before sending the browser to CP.
    pub async fn begin(
        &self,
        state_hash: &str,
        user_id: Uuid,
        session_digest: &str,
        provider_issuer: &str,
        provider_nonce: &str,
        code_verifier: &str,
    ) -> Result<(), DomainError> {
        if state_hash.len() != 64
            || session_digest.len() != 64
            || provider_issuer.len() > 2048
            || provider_issuer.is_empty()
            || !(32..=128).contains(&provider_nonce.len())
            || !(43..=128).contains(&code_verifier.len())
        {
            return Err(DomainError::invalid(
                "claims_provider.oauth",
                "pending request is invalid",
            ));
        }
        let wrapped = self
            .kek
            .wrap(
                KeyBinding::row_secret(&self.tenant, RowSecret::ClaimsProviderPkce, state_hash),
                code_verifier.as_bytes(),
            )
            .await
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let present: Option<Uuid> = sqlx::query_scalar(
            "select user_id from users where tenant_id=$1 and user_id=$2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if present.is_none() {
            return Err(DomainError::NotFound);
        }
        let created_at: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        let expires_at = created_at + time::Duration::minutes(10);
        sqlx::query(
            "delete from claims_provider_oauth_pending
             where tenant_id = $1 and (expires_at <= now() or (user_id = $2 and provider_issuer = $3))",
        )
        .bind(self.tenant.as_str()).bind(user_id).bind(provider_issuer)
        .execute(&mut *tx).await.map_err(to_domain_error)?;
        sqlx::query(
            "insert into claims_provider_oauth_pending
             (tenant_id, state_hash, user_id, session_digest, provider_issuer,
              provider_nonce, verifier_ciphertext, verifier_nonce, verifier_kek_id, created_at, expires_at)
             values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        )
        .bind(self.tenant.as_str())
        .bind(state_hash)
        .bind(user_id)
        .bind(session_digest)
        .bind(provider_issuer)
        .bind(provider_nonce)
        .bind(wrapped.ciphertext())
        .bind(wrapped.nonce())
        .bind(wrapped.kek_id())
        .bind(created_at)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    /// Consume one state token only for the browser session that began it.
    /// Failed token exchange cannot replay the code against this transaction.
    pub async fn consume(
        &self,
        state_hash: &str,
        session_digest: &str,
    ) -> Result<Option<CpPending>, DomainError> {
        let row = sqlx::query(
            "delete from claims_provider_oauth_pending
             where tenant_id = $1 and state_hash = $2 and session_digest = $3 and expires_at > clock_timestamp()
             returning user_id, provider_issuer, provider_nonce,
                       verifier_ciphertext, verifier_nonce, verifier_kek_id, created_at",
        )
        .bind(self.tenant.as_str())
        .bind(state_hash)
        .bind(session_digest)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let wrapped = WrappedKey::from_parts(
            row.try_get::<String, _>("verifier_kek_id")
                .map_err(to_domain_error)?,
            row.try_get("verifier_nonce").map_err(to_domain_error)?,
            row.try_get("verifier_ciphertext")
                .map_err(to_domain_error)?,
        )
        .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let plaintext = self
            .kek
            .unwrap(
                KeyBinding::row_secret(&self.tenant, RowSecret::ClaimsProviderPkce, state_hash),
                &wrapped,
            )
            .await
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let code_verifier = String::from_utf8(plaintext.to_vec()).map_err(|_| {
            DomainError::invalid("claims_provider.oauth", "stored verifier is invalid")
        })?;
        Ok(Some(CpPending {
            user_id: row.try_get("user_id").map_err(to_domain_error)?,
            provider_issuer: row.try_get("provider_issuer").map_err(to_domain_error)?,
            provider_nonce: row.try_get("provider_nonce").map_err(to_domain_error)?,
            code_verifier,
            created_at: row.try_get("created_at").map_err(to_domain_error)?,
        }))
    }
}
