//! Tenant-scoped TOTP enrollment with KEK-wrapped seeds (`ast-s36.15.2`).

use asterius_domain::{
    DomainError, TenantId, ct_eq,
    totp::{SECRET_LENGTH, TotpSecret},
};
use asterius_jose::{Kek, KeyBinding, RowSecret, WrappedKey};
use sqlx::PgPool;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

const ENROLLMENT_LIFETIME_SECONDS: i64 = 600;
const MAX_CONFIRMATION_ATTEMPTS: i16 = 5;
const TOTP_STEP_SECONDS: u64 = 30;

/// Whether a user has an authenticator configured. No secret material is
/// exposed by this status type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpStatus {
    /// No TOTP credential exists.
    Unenrolled,
    /// Enrollment is awaiting proof of possession.
    Pending,
    /// The credential has been activated.
    Active,
}

/// TOTP credential storage restricted to one tenant.
#[derive(Clone)]
pub struct PgTotpCredentials {
    pool: PgPool,
    tenant: TenantId,
    kek: Arc<dyn Kek>,
}

impl std::fmt::Debug for PgTotpCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgTotpCredentials")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgTotpCredentials {
    /// Creates a credential repository confined to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId, kek: Arc<dyn Kek>) -> Self {
        Self { pool, tenant, kek }
    }

    /// Starts or rotates a pending enrollment. Existing active credentials
    /// cannot be overwritten through enrollment.
    ///
    /// # Errors
    /// Returns a conflict if the user already has an active authenticator,
    /// and a storage error if encryption or persistence fails.
    pub async fn begin(
        &self,
        user_id: Uuid,
        secret: &TotpSecret,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let binding_row = user_id.to_string();
        let binding = KeyBinding::row_secret(&self.tenant, RowSecret::TotpSeed, &binding_row);
        let wrapped = self
            .kek
            .wrap(binding, secret.expose())
            .await
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let expires_at = now + time::Duration::seconds(ENROLLMENT_LIFETIME_SECONDS);
        let result = sqlx::query(
            "insert into totp_credentials
                (tenant_id, user_id, ciphertext, nonce, kek_id, state, created_at, expires_at,
                 activated_at, failed_attempts)
             values ($1, $2, $3, $4, $5, 'pending', $6, $7, null, 0)
             on conflict (tenant_id, user_id) do update
                 set ciphertext = excluded.ciphertext, nonce = excluded.nonce,
                     kek_id = excluded.kek_id, state = 'pending', created_at = excluded.created_at,
                     expires_at = excluded.expires_at, activated_at = null, failed_attempts = 0
               where totp_credentials.state = 'pending'
             returning user_id",
        )
        .bind(self.tenant.as_str())
        .bind(user_id)
        .bind(wrapped.ciphertext())
        .bind(wrapped.nonce())
        .bind(wrapped.kek_id())
        .bind(now)
        .bind(expires_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(crate::to_domain_error)?;
        if result.is_none() {
            return Err(DomainError::Conflict(
                "TOTP authenticator is already active".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reads lifecycle state without decrypting the seed. Expired pending
    /// enrollments are reported as absent and removed.
    pub async fn status(
        &self,
        user_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<TotpStatus, DomainError> {
        let row = sqlx::query_scalar::<_, String>(
            "select state from totp_credentials
              where tenant_id = $1 and user_id = $2
                and (state = 'active' or expires_at > $3)",
        )
        .bind(self.tenant.as_str())
        .bind(user_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(crate::to_domain_error)?;
        if row.is_none() {
            sqlx::query("delete from totp_credentials where tenant_id = $1 and user_id = $2 and state = 'pending' and expires_at <= $3")
                .bind(self.tenant.as_str()).bind(user_id).bind(now).execute(&self.pool).await
                .map_err(crate::to_domain_error)?;
        }
        Ok(match row.as_deref() {
            Some("pending") => TotpStatus::Pending,
            Some("active") => TotpStatus::Active,
            _ => TotpStatus::Unenrolled,
        })
    }

    /// Removes the tenant-bound authenticator after the caller has established
    /// the account's required step-up assurance. Returns whether a row existed.
    pub async fn remove(&self, user_id: Uuid) -> Result<bool, DomainError> {
        let result =
            sqlx::query("delete from totp_credentials where tenant_id = $1 and user_id = $2")
                .bind(self.tenant.as_str())
                .bind(user_id)
                .execute(&self.pool)
                .await
                .map_err(crate::to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Confirms an unexpired pending credential. A malformed or incorrect
    /// code consumes one of five attempts; successful activation never
    /// returns the seed.
    pub async fn confirm(
        &self,
        user_id: Uuid,
        code: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            self.failed_attempt(user_id).await?;
            return Ok(false);
        }
        let mut tx = self.pool.begin().await.map_err(crate::to_domain_error)?;
        let row = sqlx::query(
            "select ciphertext, nonce, kek_id, expires_at, failed_attempts
               from totp_credentials
              where tenant_id = $1 and user_id = $2 and state = 'pending'
              for update",
        )
        .bind(self.tenant.as_str())
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(crate::to_domain_error)?;
        let Some(row) = row else {
            tx.rollback().await.map_err(crate::to_domain_error)?;
            return Ok(false);
        };
        let expires_at: OffsetDateTime =
            row.try_get("expires_at").map_err(crate::to_domain_error)?;
        let attempts: i16 = row
            .try_get("failed_attempts")
            .map_err(crate::to_domain_error)?;
        if expires_at <= now || attempts >= MAX_CONFIRMATION_ATTEMPTS {
            sqlx::query("delete from totp_credentials where tenant_id = $1 and user_id = $2 and state = 'pending'")
                .bind(self.tenant.as_str()).bind(user_id).execute(&mut *tx).await.map_err(crate::to_domain_error)?;
            tx.commit().await.map_err(crate::to_domain_error)?;
            return Ok(false);
        }
        let ciphertext: Vec<u8> = row.try_get("ciphertext").map_err(crate::to_domain_error)?;
        let nonce: Vec<u8> = row.try_get("nonce").map_err(crate::to_domain_error)?;
        let kek_id: String = row.try_get("kek_id").map_err(crate::to_domain_error)?;
        let wrapped = WrappedKey::from_parts(kek_id, nonce, ciphertext)
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let binding_row = user_id.to_string();
        let binding = KeyBinding::row_secret(&self.tenant, RowSecret::TotpSeed, &binding_row);
        let plaintext = self
            .kek
            .unwrap(binding, &wrapped)
            .await
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let bytes: [u8; SECRET_LENGTH] = plaintext.as_slice().try_into().map_err(|_| {
            DomainError::invalid(
                "totp_credentials.ciphertext",
                "stored seed has an invalid length",
            )
        })?;
        let secret = TotpSecret::from_bytes(bytes);
        let timestamp = u64::try_from(now.unix_timestamp())
            .map_err(|_| DomainError::invalid("now", "must be after the Unix epoch"))?;
        let expected = secret
            .code_at(timestamp)
            .map_err(|error| DomainError::invalid("totp", error.to_string()))?;
        if !ct_eq(expected.as_bytes(), code.as_bytes()) {
            sqlx::query("update totp_credentials set failed_attempts = failed_attempts + 1 where tenant_id = $1 and user_id = $2")
                .bind(self.tenant.as_str()).bind(user_id).execute(&mut *tx).await.map_err(crate::to_domain_error)?;
            tx.commit().await.map_err(crate::to_domain_error)?;
            return Ok(false);
        }
        let confirmed_step = i64::try_from(timestamp / TOTP_STEP_SECONDS)
            .map_err(|_| DomainError::invalid("now", "TOTP step is too large"))?;
        sqlx::query("update totp_credentials set state = 'active', activated_at = $3, failed_attempts = 0, last_used_step = $4 where tenant_id = $1 and user_id = $2")
            .bind(self.tenant.as_str()).bind(user_id).bind(now).bind(confirmed_step)
            .execute(&mut *tx).await.map_err(crate::to_domain_error)?;
        tx.commit().await.map_err(crate::to_domain_error)?;
        Ok(true)
    }

    /// Verifies an active credential and atomically consumes its matching
    /// time step. A step may be accepted only once across all replicas.
    ///
    /// The one-step clock window accommodates ordinary clock drift. A code
    /// matching only a step at or below `last_used_step` is a replay and is
    /// refused exactly like an incorrect code.
    pub async fn verify(
        &self,
        user_id: Uuid,
        code: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        if code.len() != 6 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return Ok(false);
        }
        let timestamp = u64::try_from(now.unix_timestamp())
            .map_err(|_| DomainError::invalid("now", "must be after the Unix epoch"))?;
        let current_step = timestamp / TOTP_STEP_SECONDS;
        let mut tx = self.pool.begin().await.map_err(crate::to_domain_error)?;
        let row = sqlx::query(
            "select ciphertext, nonce, kek_id, last_used_step
               from totp_credentials
              where tenant_id = $1 and user_id = $2 and state = 'active'
              for update",
        )
        .bind(self.tenant.as_str())
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(crate::to_domain_error)?;
        let Some(row) = row else {
            tx.rollback().await.map_err(crate::to_domain_error)?;
            return Ok(false);
        };
        let ciphertext: Vec<u8> = row.try_get("ciphertext").map_err(crate::to_domain_error)?;
        let nonce: Vec<u8> = row.try_get("nonce").map_err(crate::to_domain_error)?;
        let kek_id: String = row.try_get("kek_id").map_err(crate::to_domain_error)?;
        let last_used_step: i64 = row
            .try_get("last_used_step")
            .map_err(crate::to_domain_error)?;
        let wrapped = WrappedKey::from_parts(kek_id, nonce, ciphertext)
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let binding_row = user_id.to_string();
        let binding = KeyBinding::row_secret(&self.tenant, RowSecret::TotpSeed, &binding_row);
        let plaintext = self
            .kek
            .unwrap(binding, &wrapped)
            .await
            .map_err(|error| DomainError::Storage(Box::new(error)))?;
        let bytes: [u8; SECRET_LENGTH] = plaintext.as_slice().try_into().map_err(|_| {
            DomainError::invalid(
                "totp_credentials.ciphertext",
                "stored seed has an invalid length",
            )
        })?;
        let secret = TotpSecret::from_bytes(bytes);
        let mut matched_step = None;
        for step in [
            current_step.checked_sub(1),
            Some(current_step),
            current_step.checked_add(1),
        ]
        .into_iter()
        .flatten()
        {
            let seconds = step
                .checked_mul(TOTP_STEP_SECONDS)
                .ok_or_else(|| DomainError::invalid("now", "TOTP step overflowed"))?;
            let expected = secret
                .code_at(seconds)
                .map_err(|error| DomainError::invalid("totp", error.to_string()))?;
            if ct_eq(expected.as_bytes(), code.as_bytes())
                && i128::from(step) > i128::from(last_used_step)
            {
                matched_step = Some(matched_step.map_or(step, |matched: u64| matched.max(step)));
            }
        }
        let Some(step) = matched_step else {
            tx.commit().await.map_err(crate::to_domain_error)?;
            return Ok(false);
        };
        sqlx::query("update totp_credentials set last_used_step = $3 where tenant_id = $1 and user_id = $2 and state = 'active'")
            .bind(self.tenant.as_str()).bind(user_id)
            .bind(i64::try_from(step).map_err(|_| DomainError::invalid("now", "TOTP step is too large"))?)
            .execute(&mut *tx).await.map_err(crate::to_domain_error)?;
        tx.commit().await.map_err(crate::to_domain_error)?;
        Ok(true)
    }

    async fn failed_attempt(&self, user_id: Uuid) -> Result<(), DomainError> {
        sqlx::query("update totp_credentials set failed_attempts = least(failed_attempts + 1, $3) where tenant_id = $1 and user_id = $2 and state = 'pending'")
            .bind(self.tenant.as_str()).bind(user_id).bind(MAX_CONFIRMATION_ATTEMPTS)
            .execute(&self.pool).await.map_err(crate::to_domain_error)?;
        Ok(())
    }
}

use sqlx::Row;
