//! Backchannel authentication requests (CIBA Core 1.0), over PostgreSQL.
//!
//! `ast-lh3.4` records the request and nothing else: this is the half of the
//! flow that runs while the client is still on the connection. The approval
//! (`ast-lh3.6`) and the redemption (`ast-lh3.5`) are the other two actors on
//! the same row, and the statements they need are theirs to add — with the
//! same rule the device flow's store follows, that a check and the write it
//! authorises are one statement.
//!
//! # Nothing here appears in the clear
//!
//! The `auth_req_id` arrives as a digest, and so does the
//! `client_notification_token`. The first is what the token endpoint answers
//! to; the second is what a §10.2 notification will carry in an
//! `Authorization` header. Both are bearer values, and a copy of this table is
//! a list of digests rather than a list of credentials.
//!
//! The `binding_message` is the exception and is stored in the clear, because
//! it exists to be *rendered*: §7.1 puts the same string on the consumption
//! device and on the authentication device so that a person can see the two
//! are one transaction. A digest could not be shown to anybody.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId, UserId};
use sqlx::postgres::PgPool;
use time::{Duration, OffsetDateTime};

/// A backchannel authentication request to record (§7.1, §7.2).
///
/// Every field is post-validation: the scopes are narrowed to the client's
/// registration, the user is what the hint resolved to, and the lifetime is
/// already clamped to the tenant's maximum. Nothing here is re-decided.
#[derive(Debug, Clone)]
pub struct NewCibaRequest {
    /// The authenticated client that asked.
    pub client_id: String,
    /// Who the hint named (§7.2 step 2).
    pub user_id: UserId,
    /// What it asked for, already narrowed to its registration.
    pub scopes: Vec<String>,
    /// RFC 9396 §3's rich authorization, as the parser accepted it.
    pub authorization_details: serde_json::Value,
    /// §7.1's `acr_values`, most preferred first.
    pub acr_values: Vec<String>,
    /// §7.1's `binding_message`, in the clear because it is displayed.
    pub binding_message: Option<String>,
    /// §4's delivery mode, copied onto the row: a registration that changes
    /// after the request must not change how the request is answered.
    pub delivery_mode: String,
    /// The SHA-256 of §7.1's `client_notification_token`, hex, in ping mode.
    pub client_notification_token_digest: Option<String>,
    /// §7.3's `expires_in`, as an instant.
    pub expires_at: OffsetDateTime,
    /// §7.3's `interval`, as this request starts out.
    pub interval: Duration,
}

/// Backchannel authentication requests for one tenant.
#[derive(Debug, Clone)]
pub struct PgCibaRequestRepository {
    pool: PgPool,
    tenant: TenantId,
}

impl PgCibaRequestRepository {
    /// Scopes a repository to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Records a backchannel authentication request (§7.1, §7.3).
    ///
    /// The `auth_req_id` is handed in as a digest and never as itself, so this
    /// crate never holds the value the acknowledgement carries.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] when the digest is not hexadecimal or the
    /// interval is not a number of seconds — both of which are bugs in the
    /// caller rather than anything a client sent. [`DomainError::Conflict`]
    /// when the digest is already in this tenant, which for a 256-bit value
    /// means a broken generator. [`DomainError::Storage`] otherwise.
    pub async fn issue(
        &self,
        auth_req_id_digest: &str,
        request: &NewCibaRequest,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let auth_req_id = hex::decode(auth_req_id_digest)
            .map_err(|error| DomainError::invalid("auth_req_id", error.to_string()))?;
        let notification = request
            .client_notification_token_digest
            .as_deref()
            .map(|digest| {
                hex::decode(digest).map_err(|error| {
                    DomainError::invalid("client_notification_token", error.to_string())
                })
            })
            .transpose()?;
        let interval = i32::try_from(request.interval.whole_seconds())
            .map_err(|_| DomainError::invalid("interval", "is not a number of seconds"))?;

        sqlx::query!(
            "insert into ciba_requests
                 (tenant_id, auth_req_id_hash, client_id, user_id, scopes,
                  authorization_details, acr_values, binding_message, delivery_mode,
                  client_notification_token_hash, issued_at, expires_at,
                  poll_interval_seconds)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            self.tenant.as_str(),
            auth_req_id,
            request.client_id,
            request.user_id.as_uuid(),
            &request.scopes,
            request.authorization_details,
            &request.acr_values,
            request.binding_message.as_deref(),
            request.delivery_mode,
            notification.as_deref(),
            now,
            request.expires_at,
            interval,
        )
        .execute(&self.pool)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(db) if db.is_unique_violation() => DomainError::Conflict(
                "backchannel authentication request already exists".to_owned(),
            ),
            _ => to_domain_error(error),
        })?;
        Ok(())
    }
}
