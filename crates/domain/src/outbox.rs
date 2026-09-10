//! The transactional outbox, as everything above the adapter sees it.
//!
//! The outbox itself is SQL and lives in `asterius_store_pg::outbox`: a row is
//! written in the same transaction as the change it describes, and a worker
//! claims, delivers and acks it. None of that belongs here. What belongs here
//! is the part other crates need a *name* for and must not reach `sqlx` to
//! get:
//!
//! * [`OutboxEvent`] — the row as a deliverer sees it, with nothing in it that
//!   only makes sense to the claim query.
//! * [`DeadLetter`] — what an operator is shown about a row that will not be
//!   retried again, which is deliberately less than the row contains.
//! * [`DeadLetterQuery`] — the port the admin API reads them through, because
//!   `scripts/check-layering.sh` will not let that crate depend on `sqlx`.
//!
//! # Why a dead letter is not the row
//!
//! [`DeadLetter`] has no payload and no destination, and that is the whole
//! design of the type rather than an omission to be fixed later. An abandoned
//! `notification.account_recovery` row's payload is a live password-reset link
//! (`ast-2vk.10`), its destination is the address of the person it was for,
//! and an ordering key is built from a subject or a session id. All three are
//! either a credential or personal data, and the screen that lists dead
//! letters is reached with `admin.*:read` — an authority granted so that
//! somebody can see *that* delivery is failing, not so they can read the
//! messages.
//!
//! So what crosses this boundary is: which row, what kind of thing it was, how
//! many times it was tried, when, and the deliverer's own description of the
//! failure. That is enough to answer "is this one broken receiver or all of
//! them" and to decide whether to retry, which is what the screen is for.

use crate::error::DomainError;
use crate::ids::TenantId;
use std::fmt::Debug;
use time::OffsetDateTime;

/// One row, as the worker hands it to a deliverer.
///
/// Owned rather than borrowed: a deliverer is `async` and may hold this across
/// an await point while the connection it was read on has gone back to the
/// pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEvent {
    /// The tenant the row belongs to. Every delivery is one tenant's.
    pub tenant: TenantId,
    /// The row's identity within the tenant, stable across retries.
    ///
    /// This is the "same identifier" an at-least-once receiver deduplicates
    /// on: a row delivered twice because a worker died before it acked is
    /// delivered twice under this id, never under two.
    pub id: i64,
    /// What kind of thing this is, e.g. `notification.account_recovery`.
    ///
    /// Dispatch is by the prefix before the first `.`, so a new event family
    /// is a new prefix rather than a change to the worker.
    pub kind: String,
    /// Where it goes, in whatever spelling the kind uses: a URL for an HTTP
    /// delivery, an address for a notification.
    pub destination: String,
    /// The kind's values. Treated as a credential wherever it is logged.
    pub payload: serde_json::Value,
    /// Which attempt this is, counting from 1.
    pub attempt: u32,
    /// The most attempts this row gets before it is dead-lettered.
    pub max_attempts: u32,
    /// When the row was written, which is when the change it describes
    /// committed.
    pub created_at: OffsetDateTime,
}

impl OutboxEvent {
    /// The dispatch prefix: everything before the first `.`, or the whole kind.
    #[must_use]
    pub fn family(&self) -> &str {
        self.kind
            .split_once('.')
            .map_or(&*self.kind, |(head, _)| head)
    }

    /// Whether this attempt is the last one the row will get.
    #[must_use]
    pub const fn is_final_attempt(&self) -> bool {
        self.attempt >= self.max_attempts
    }
}

/// A row that has exhausted its attempts, as an operator is shown it.
///
/// See the module documentation for what is deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadLetter {
    /// The row's identity within the tenant. Enough to find it in the
    /// database, which is where anybody entitled to the payload looks.
    pub id: i64,
    /// What kind of thing failed to be delivered.
    pub kind: String,
    /// How many times it was tried.
    pub attempts: u32,
    /// When it was queued.
    pub created_at: OffsetDateTime,
    /// When the last attempt was made, if any was recorded.
    pub last_attempt_at: Option<OffsetDateTime>,
    /// The deliverer's description of the last failure.
    ///
    /// Written by a deliverer that knows what it may say: a host and a status
    /// code, never a response body and never the URL. A receiver's error page
    /// is a string an outsider chose, and this one is rendered to an operator.
    pub last_error: Option<String>,
}

/// Reading the dead-letter queue.
///
/// A read-only port with one method. There is no "retry this row" here on
/// purpose: re-queueing is a mutation that has to decide what happens to the
/// ordering key's other rows, and a button that quietly reorders a session's
/// events is worse than no button. An operator who has fixed the receiver
/// resets the row in SQL, which is a deliberate act with a record.
#[async_trait::async_trait]
pub trait DeadLetterQuery: Debug + Send + Sync {
    /// The tenant's abandoned rows, newest first, at most `limit` of them.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn dead_letters(
        &self,
        tenant: &TenantId,
        limit: u32,
    ) -> Result<Vec<DeadLetter>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(kind: &str, attempt: u32, max_attempts: u32) -> OutboxEvent {
        OutboxEvent {
            tenant: TenantId::new("acme"),
            id: 1,
            kind: kind.to_owned(),
            destination: "https://rp.example/backchannel".to_owned(),
            payload: json!({}),
            attempt,
            max_attempts,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// Dispatch is by family, so the split has to stop at the *first* dot: a
    /// kind like `ssf.caep.session-revoked` belongs to `ssf`.
    #[test]
    fn a_family_is_everything_before_the_first_dot() {
        // Arrange
        let subject = event("ssf.caep.session-revoked", 1, 10);

        // Act
        let family = subject.family().to_owned();

        // Assert
        assert_eq!(family, "ssf");
    }

    /// A kind with no dot is its own family rather than an empty one, so a
    /// registry lookup for it fails loudly instead of matching a `""` entry.
    #[test]
    fn a_kind_without_a_dot_is_its_own_family() {
        // Arrange
        let subject = event("heartbeat", 1, 10);

        // Act
        let family = subject.family().to_owned();

        // Assert
        assert_eq!(family, "heartbeat");
    }

    /// The last attempt is the one *equal* to the maximum, not the one after
    /// it: an off-by-one here would dead-letter a row that still had a try
    /// left, or log "final" on an attempt that was not.
    #[test]
    fn the_final_attempt_is_the_one_that_reaches_the_maximum() {
        // Arrange / Act / Assert
        assert!(!event("notification.x", 2, 3).is_final_attempt());
        assert!(event("notification.x", 3, 3).is_final_attempt());
    }
}
