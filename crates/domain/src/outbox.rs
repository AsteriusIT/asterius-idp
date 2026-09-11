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
//! * [`DeadLetterOperations`] — the two things an operator may do to one
//!   (`ast-f7m.8`): put it back on the schedule, or remove it for good.
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

/// A row to be written, as everything above the adapter states it.
///
/// The mirror of [`OutboxEvent`] on the write side, and deliberately not the
/// same type: a row being queued has no id, no attempt count and no claim, and
/// a caller that could set those could queue a row already three attempts into
/// its budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedEvent {
    /// What kind of thing this is, e.g. `logout.backchannel`. The part before
    /// the first `.` chooses the deliverer.
    pub kind: String,
    /// Where it goes, in the kind's own spelling.
    pub destination: String,
    /// The kind's values, in the shape its deliverer reads. Treated as a
    /// credential wherever it is logged: a `logout.backchannel` payload holds
    /// a signed logout token.
    pub payload: serde_json::Value,
    /// The group this row must stay in order within, or `None` for one that
    /// may be delivered concurrently with any other.
    pub ordering_key: Option<String>,
}

/// Queueing outbox rows from above the adapter.
///
/// A port because the callers are protocol handlers — back-channel logout
/// today, the SSF transmitter next — and `scripts/check-layering.sh` will not
/// let those name `sqlx`. It is also what lets the notifying step be tested
/// without a database: what a logout queues is a property of the
/// specification, and a test that needed Postgres to assert it would not be
/// written.
#[async_trait::async_trait]
pub trait OutboxQueue: Debug + Send + Sync {
    /// Writes every row, or none of them.
    ///
    /// All-or-nothing on purpose: the rows of one cause — the logout tokens of
    /// one ended session — are one statement about the world, and half of them
    /// is a session some relying parties believe is live and others do not.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the rows could not be written. Nothing was.
    async fn queue(
        &self,
        tenant: &TenantId,
        events: &[QueuedEvent],
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;
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
/// A read-only port. The mutations live on [`DeadLetterOperations`], a
/// second port rather than two more methods here, for the reason the audit
/// trail has a sink and a query: the screen that lists dead letters is
/// reached with `admin.outbox:read`, and a handle that could also requeue
/// would give a read scope's route the means to write.
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

    /// One abandoned row of the tenant, or `None` if `id` names no such row
    /// — including a row that exists and is not abandoned, which an operator
    /// has no business acting on.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn dead_letter(
        &self,
        tenant: &TenantId,
        id: i64,
    ) -> Result<Option<DeadLetter>, DomainError>;
}

/// What an operator may do to a dead letter (`ast-f7m.8`).
///
/// Until `ast-f7m.8` this crate said, in as many words, that there would be
/// no retry button: re-queueing has to decide what happens to the ordering
/// key's other rows. The decision is now made and written down rather than
/// avoided. A row that was abandoned stopped blocking its key the moment it
/// was abandoned, so the rows behind it have gone out already; putting it
/// back therefore delivers it *after* them, not before. For the one family
/// the admin API lets an operator requeue — SSF SETs, whose receivers
/// deduplicate on `jti` and order on `event_timestamp` (RFC 8417 §1.2, CAEP
/// §2) — a late signal is strictly better than a lost one. Whether that
/// holds for another family is that family's question, which is why the
/// policy of *which kinds* may be requeued belongs to the caller and not to
/// this port.
///
/// Both operations are recorded by the admin API that offers them: the row
/// says nothing about who pressed the button, and the trail must.
#[async_trait::async_trait]
pub trait DeadLetterOperations: Debug + Send + Sync {
    /// Puts an abandoned row back on the schedule with a fresh attempt
    /// budget, to be claimed at `now`.
    ///
    /// `false` means the row was not abandoned — gone, or already picked up
    /// — and nothing changed.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn requeue(
        &self,
        tenant: &TenantId,
        id: i64,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Removes an abandoned row and its attempt trail for good, which is
    /// what the retention sweep would have done a week later.
    ///
    /// `false` means the row was not abandoned and nothing was removed: a
    /// row still owed is not a row an operator may delete from a screen.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    async fn drop_letter(&self, tenant: &TenantId, id: i64) -> Result<bool, DomainError>;
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
