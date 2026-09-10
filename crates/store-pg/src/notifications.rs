//! The journal mail sender: the one [`MailSender`] this repository ships.
//!
//! # It delivers nothing, and says so
//!
//! Every message becomes a row in the transactional `outbox` and a log line.
//! Nothing leaves the process. That is a deliberate shape rather than a stub:
//! a deployment gets a complete, queryable record of what recovery links were
//! produced and for whom, tests get a way to read the link a browser would
//! have been mailed, and nobody is misled into thinking mail is configured.
//! `delivered_at` stays null, because it was not delivered.
//!
//! An operator wires their own sender — SMTP, a provider API, a queue — and
//! this stays as the audit trail beside it or is replaced. See
//! `docs/configuration.md`.
//!
//! # Why the payload is JSON and not a rendered body
//!
//! `asterius_domain::notification` explains it: wording, locale and brand
//! belong to whatever sends. What this records is the *values* — the link, the
//! validity — so that a real sender reading this table later can render the
//! same message.
//!
//! # Retention
//!
//! An `account_recovery` row contains a live reset link until the token behind
//! it expires, fifteen minutes later, and a dead one after that. The row is
//! still worth treating as a credential: `docs/configuration.md` says to keep
//! outbox retention short, and the existing retention sweep already ages this
//! table.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, MailSender, Notification, NotificationKind, TenantId};
use serde_json::json;
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// The `outbox.kind` prefix every notification row carries.
///
/// Prefixed rather than bare, because that table also holds back-channel
/// logout tokens and, one day, SSF events: a worker that dispatches by kind
/// must be able to tell a message meant for a person from one meant for a
/// client.
const KIND_PREFIX: &str = "notification.";

/// A [`MailSender`] that writes to the outbox and logs.
#[derive(Clone)]
pub struct PgOutboxMailSender {
    pool: PgPool,
    tenant: TenantId,
}

impl std::fmt::Debug for PgOutboxMailSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgOutboxMailSender")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgOutboxMailSender {
    /// Binds a pool to one tenant.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// What this tenant has queued and nothing has taken, oldest first.
    ///
    /// A journal that cannot be read is a hole rather than a record. This is
    /// how an operator sees what *would* have been sent while no real sender
    /// is wired, how the console will show it, and how the recovery tests read
    /// the link a mailbox would have received — which is the only place that
    /// link exists, the token being stored as a digest.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails.
    pub async fn queued(&self) -> Result<Vec<QueuedNotification>, DomainError> {
        let rows = sqlx::query!(
            "select kind, destination, payload, created_at
               from outbox
              where tenant_id = $1 and kind like 'notification.%' and delivered_at is null
              order by outbox_id asc",
            self.tenant.as_str(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(rows
            .into_iter()
            .map(|row| QueuedNotification {
                kind: row
                    .kind
                    .strip_prefix(KIND_PREFIX)
                    .unwrap_or(&row.kind)
                    .to_owned(),
                recipient: row.destination,
                payload: row.payload,
                created_at: row.created_at,
            })
            .collect())
    }
}

/// One message this server wanted sent and nothing has taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedNotification {
    /// [`NotificationKind::as_str`], with the outbox prefix removed.
    pub kind: String,
    /// The address it was addressed to.
    pub recipient: String,
    /// The kind's values. For a recovery message this contains the link, and
    /// therefore the token: treat it as a credential.
    pub payload: serde_json::Value,
    /// When it was queued.
    pub created_at: time::OffsetDateTime,
}

/// The values a kind carries, as the row stores them.
fn payload(kind: &NotificationKind) -> serde_json::Value {
    match kind {
        NotificationKind::AccountRecovery {
            link,
            valid_for_minutes,
        } => json!({ "link": link, "valid_for_minutes": valid_for_minutes }),
        NotificationKind::CredentialChanged => json!({}),
    }
}

#[async_trait::async_trait]
impl MailSender for PgOutboxMailSender {
    async fn send(&self, message: &Notification) -> Result<(), DomainError> {
        let kind = format!("{KIND_PREFIX}{}", message.kind.as_str());
        sqlx::query!(
            "insert into outbox (tenant_id, kind, destination, payload, created_at)
             values ($1, $2, $3, $4, $5)",
            self.tenant.as_str(),
            kind,
            message.to,
            payload(&message.kind),
            OffsetDateTime::now_utc(),
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        // The recipient is not logged and neither is the link. The first is
        // personal data on a path an unauthenticated visitor chooses, the
        // second is the credential itself — a log aggregator is not where a
        // reset link should end up. The row has both; that table is access
        // controlled and this stream is not.
        tracing::info!(
            tenant = %self.tenant,
            kind = message.kind.as_str(),
            "queued a notification in the outbox; no sender is wired, nothing was delivered"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The link and the validity are what a real sender needs to render the
    /// same message. Losing either would make the row unrenderable.
    #[test]
    fn a_recovery_payload_carries_the_link_and_its_validity() {
        // Arrange
        let kind = NotificationKind::AccountRecovery {
            link: "https://as.example/t/a/recovery/new?token=x".to_owned(),
            valid_for_minutes: 15,
        };

        // Act
        let stored = payload(&kind);

        // Assert
        assert_eq!(
            stored,
            json!({
                "link": "https://as.example/t/a/recovery/new?token=x",
                "valid_for_minutes": 15,
            })
        );
    }

    /// A credential-change notice has nothing to carry, and must not acquire a
    /// link by accident.
    #[test]
    fn a_credential_change_payload_is_empty() {
        // Arrange
        let kind = NotificationKind::CredentialChanged;

        // Act
        let stored = payload(&kind);

        // Assert
        assert_eq!(stored, json!({}));
    }
}
