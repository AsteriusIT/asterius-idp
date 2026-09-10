//! The notification deliverer: `ast-2vk.10`'s journal, wired to the worker.
//!
//! `asterius_store_pg::PgOutboxMailSender` writes a row for every message this
//! server wanted sent and logs that it did. Until this ticket nothing read
//! those rows back, so the "queue" half of the transactional outbox was a
//! table with no consumer: rows accumulated as `pending` forever, and the
//! retention sweep — which deliberately keeps `pending` rows however old they
//! look, because a pending row is work still owed — kept every one of them.
//!
//! This is the consumer. It is the whole of what the ticket that added the
//! journal said it did: it records that the message was produced, and it sends
//! nothing.
//!
//! # It reports [`Delivered::Journalled`], not [`Delivered::Sent`]
//!
//! That distinction is the point of the type. A journalled row is finished —
//! the worker stops claiming it, the retention sweep can age it — but its
//! `delivered_at` stays null, because nothing left the process. So
//! `PgOutboxMailSender::queued`, which is how an operator with no mail sender
//! wired sees what *would* have been sent, and how the recovery tests read the
//! link a mailbox would have received, keeps returning exactly what it did
//! before. A deliverer that claimed `Sent` here would empty that view and tell
//! an operator their reset e-mails had gone out.
//!
//! # Wiring a real sender
//!
//! An operator who wants mail to actually leave replaces this in the
//! composition root with a deliverer that speaks to their provider, and gets
//! the retries, the backoff, the ordering and the dead-letter screen for free.
//! That is what the outbox is for: the `notification` family becomes deliver
//! shaped like everything else, rather than a second mechanism with its own
//! idea of what a failure is.

use crate::outbox::{Delivered, Deliverer, Undelivered};
use asterius_domain::outbox::OutboxEvent;

/// The `outbox.kind` family this deliverer answers for.
///
/// Matches the prefix `PgOutboxMailSender` writes, minus the dot.
pub const FAMILY: &str = "notification";

/// Records notifications and sends nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct JournalDeliverer;

#[async_trait::async_trait]
impl Deliverer for JournalDeliverer {
    fn family(&self) -> &'static str {
        FAMILY
    }

    async fn deliver(&self, event: &OutboxEvent) -> Result<Delivered, Undelivered> {
        // The kind and the row, and nothing else. The recipient is personal
        // data on a path an unauthenticated visitor chooses and the payload is
        // the reset link itself — a log aggregator is not where either should
        // end up. `PgOutboxMailSender::send` says the same thing at the other
        // end of the same row.
        tracing::info!(
            tenant = %event.tenant,
            row = event.id,
            kind = %event.kind,
            "journalled a notification; no mail sender is wired, nothing was delivered"
        );
        Ok(Delivered::Journalled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::TenantId;
    use time::OffsetDateTime;

    fn recovery_message() -> OutboxEvent {
        OutboxEvent {
            tenant: TenantId::new("acme"),
            id: 12,
            kind: "notification.account_recovery".to_owned(),
            destination: "someone@example.test".to_owned(),
            payload: serde_json::json!({"link": "https://as.example/r?token=secret"}),
            attempt: 1,
            max_attempts: 10,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// The family has to be exactly the prefix `PgOutboxMailSender` writes, or
    /// every notification row dead-letters as "no deliverer registered".
    #[test]
    fn the_family_matches_the_prefix_the_mail_sender_writes() {
        // Arrange / Act
        let family = JournalDeliverer.family();

        // Assert
        assert_eq!(format!("{family}."), "notification.");
    }

    /// Journalled and not sent. A deliverer that claimed `Sent` would stamp
    /// `delivered_at` and empty the operator's view of what was never mailed.
    #[tokio::test]
    async fn a_notification_is_journalled_and_never_claimed_as_sent() {
        // Arrange
        let event = recovery_message();

        // Act
        let outcome = JournalDeliverer.deliver(&event).await;

        // Assert
        assert_eq!(outcome, Ok(Delivered::Journalled));
    }

    /// It never fails, which is what makes it safe as the default: a
    /// deployment with no mail configured does not accumulate dead letters for
    /// every password reset anybody asked for.
    #[tokio::test]
    async fn journalling_cannot_fail() {
        // Arrange
        let mut event = recovery_message();
        event.attempt = event.max_attempts;

        // Act
        let outcome = JournalDeliverer.deliver(&event).await;

        // Assert
        assert!(outcome.is_ok());
    }
}
