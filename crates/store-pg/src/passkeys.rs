//! Passkey enrolments and the credentials they produce, over PostgreSQL.
//!
//! Two statements carry the security properties, and both are single
//! statements for the same reason.
//!
//! [`PgPasskeyRepository::spend_challenge`] is one `update ... returning` that
//! reads the challenge and nulls it in the same round trip, so two finishes
//! racing on one challenge cannot both come back with bytes. A read followed by
//! a delete would be exactly the replay window WebAuthn L3 §13.4.3 asks for a
//! challenge in order to close.
//!
//! [`PgPasskeyRepository::register`] leans on `credentials_by_passkey_id`, the
//! unique index over `(tenant_id, passkey_credential_id)`, rather than checking
//! first. A prior `select` is a check with a gap after it; the index is the
//! tenant-wide uniqueness §7.1 step 22 wants, and a violation comes back as
//! [`DomainError::Conflict`].

use crate::error::to_domain_error;
use asterius_domain::{DomainError, Enrolment, NewPasskey, PasskeyRepository, TenantId, UserId};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// [`PasskeyRepository`] over PostgreSQL, scoped to one tenant.
#[derive(Debug, Clone)]
pub struct PgPasskeyRepository {
    pool: PgPool,
    tenant: TenantId,
}

impl PgPasskeyRepository {
    /// Scopes a repository to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }
}

#[async_trait::async_trait]
impl PasskeyRepository for PgPasskeyRepository {
    async fn open_enrolment(
        &self,
        session_digest: &str,
        csrf_digest: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        // The upsert clears `challenge`: rendering the page again starts the
        // ceremony over, and a challenge left attached to a superseded token
        // would be one the previous page could still spend.
        sqlx::query!(
            "insert into passkey_enrolments
                 (tenant_id, session_id, csrf_digest, challenge, expires_at)
             values ($1, $2, $3, null, $4)
             on conflict (tenant_id, session_id) do update
                set csrf_digest = excluded.csrf_digest,
                    challenge   = null,
                    expires_at  = excluded.expires_at",
            self.tenant.as_str(),
            session_digest,
            csrf_digest,
            expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    async fn issue_challenge(
        &self,
        session_digest: &str,
        challenge: &[u8],
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let result = sqlx::query!(
            "update passkey_enrolments
                set challenge = $3, expires_at = $4
              where tenant_id = $1 and session_id = $2 and expires_at > $5",
            self.tenant.as_str(),
            session_digest,
            challenge,
            expires_at,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn enrolment(
        &self,
        session_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Enrolment>, DomainError> {
        let row = sqlx::query!(
            "select csrf_digest, challenge, expires_at
               from passkey_enrolments
              where tenant_id = $1 and session_id = $2 and expires_at > $3",
            self.tenant.as_str(),
            session_digest,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(row.map(|row| Enrolment {
            csrf_digest: row.csrf_digest,
            challenge: row.challenge,
            expires_at: row.expires_at,
        }))
    }

    async fn spend_challenge(
        &self,
        session_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, DomainError> {
        // `returning` alone would give the *new* value, which this statement
        // has just set to null. So the old row is joined in from a subquery,
        // which reads the pre-update snapshot: `returning old.challenge` is
        // then the value that was outstanding.
        //
        // The race is settled by the row lock. A second spend blocks on the
        // update, then re-checks `challenge is not null` against the committed
        // row, finds it null, and updates nothing — so it returns nothing,
        // however far its own snapshot had got.
        let row = sqlx::query!(
            "update passkey_enrolments as current
                set challenge = null
               from (select tenant_id, session_id, challenge
                       from passkey_enrolments
                      where tenant_id = $1 and session_id = $2) as previous
              where current.tenant_id = previous.tenant_id
                and current.session_id = previous.session_id
                and current.expires_at > $3
                and current.challenge is not null
             returning previous.challenge",
            self.tenant.as_str(),
            session_digest,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(row.and_then(|row| row.challenge))
    }

    async fn register(&self, passkey: &NewPasskey) -> Result<uuid::Uuid, DomainError> {
        let credential_id = uuid::Uuid::new_v4();
        // A `u32` counter in a `bigint`: the column is signed, and the
        // authenticator's counter is not.
        let sign_count = i64::from(passkey.sign_count);
        sqlx::query!(
            "insert into credentials
                 (tenant_id, credential_id, user_id, kind,
                  passkey_credential_id, passkey_public_key, passkey_sign_count,
                  passkey_aaguid, passkey_backup_eligible, passkey_backup_state,
                  passkey_rp_id, passkey_user_verified, label)
             values ($1, $2, $3, 'passkey', $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            self.tenant.as_str(),
            credential_id,
            passkey.user.as_uuid(),
            passkey.credential_id,
            passkey.public_key,
            sign_count,
            passkey.aaguid,
            passkey.backup_eligible,
            passkey.backup_state,
            passkey.rp_id,
            passkey.user_verified,
            passkey.label.as_deref(),
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(credential_id)
    }

    async fn credential_ids(&self, user: &UserId) -> Result<Vec<Vec<u8>>, DomainError> {
        let rows = sqlx::query_scalar!(
            "select passkey_credential_id
               from credentials
              where tenant_id = $1 and user_id = $2 and kind = 'passkey'
                and disabled_at is null
                and passkey_credential_id is not null",
            self.tenant.as_str(),
            user.as_uuid(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(rows.into_iter().flatten().collect())
    }
}
