//! The transactional outbox: writing rows, claiming them, and acking them.
//!
//! `0001_baseline.sql` created the table and stated the property it exists for
//! — a notification is written in the same transaction as the change it
//! describes, so there is no window in which a session is revoked and the
//! logout token that says so was lost. `0017_outbox_delivery.sql` and this
//! module are the other half: the part that takes those rows and hands them to
//! something that delivers.
//!
//! # The three statements
//!
//! **[`enqueue`]** takes a `&mut` transaction rather than the pool. That is
//! the whole design: a caller cannot write an outbox row *except* inside a
//! transaction it already has, so "the row and the change commit together" is
//! not a convention to remember. A rollback takes the row with it, which is
//! what `a_rolled_back_change_takes_its_outbox_row_with_it` asserts.
//!
//! **[`PgOutbox::claim`]** is one statement: `select … for update skip locked`
//! inside a CTE, feeding an `update` that marks the rows claimed. Two workers
//! racing therefore take disjoint sets rather than one waiting for the other,
//! and neither takes a row a third worker is already delivering.
//!
//! **[`PgOutbox::ack`]** records the attempt and moves the row on: delivered,
//! backed off, or abandoned.
//!
//! # At-least-once, and why it is not at-most-once
//!
//! The claim commits *before* the delivery is attempted, and the row is only
//! finished after the deliverer returns. A worker killed between the two
//! leaves a `claimed` row whose `claim_expires_at` lapses; the next worker
//! reclaims it and delivers it again, under the same `outbox_id`. So a
//! receiver can see one event twice and must deduplicate on the id — which is
//! exactly what every specification that will ride this expects: an SSF
//! receiver deduplicates on `jti`, a back-channel logout receiver on the
//! logout token's `jti`.
//!
//! The alternative — delete the row, then deliver — turns every eviction into
//! a lost logout, and a logout that never arrives is a session that stays live
//! at a relying party after the authorization server revoked it. Duplicate
//! delivery is a receiver's problem; lost delivery is a security failure.
//!
//! # Ordering by key
//!
//! Some events only mean anything in order. Two CAEP events about one
//! `(stream, subject)`, two back-channel logouts about one `(client,
//! session)`: delivered out of order they say the opposite of what happened.
//! [`NewOutboxEntry::ordering_key`] names that group, and the claim refuses a
//! row while an earlier row with the same key is still owed — pending, backed
//! off, or in another worker's hands. Rows with no key are unordered and go
//! out concurrently.
//!
//! The cost is stated rather than hidden: one stuck key blocks its own later
//! rows until the stuck row is delivered or abandoned. That is the point. A
//! key whose head is wedged behind an unreachable receiver holds *that key's*
//! queue and nothing else's.
//!
//! # Retention
//!
//! `crate::retention::POLICY` already sweeps `delivered` and `abandoned` rows
//! after a week and deliberately keeps `pending` and `failed` ones however old
//! they look. `claimed` was added to the in-flight set by this ticket, and is
//! not swept for the same reason: a claimed row is work still owed.
//! `outbox_attempts` cascades from its parent, so the trail is aged by the
//! same cutoff and there is no second schedule to keep in step.

use crate::error::to_domain_error;
use asterius_domain::outbox::{DeadLetter, DeadLetterQuery, OutboxEvent};
use asterius_domain::{DomainError, TenantId};
use sqlx::postgres::PgPool;
use time::{Duration, OffsetDateTime};

/// The transaction type [`enqueue`] borrows.
pub type PgTransaction<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// A row about to be written, before it has an id.
#[derive(Debug, Clone)]
pub struct NewOutboxEntry<'a> {
    /// The dispatch kind, e.g. `notification.account_recovery`. The part
    /// before the first `.` chooses the deliverer.
    pub kind: &'a str,
    /// Where it goes, in the kind's own spelling.
    pub destination: &'a str,
    /// The values the deliverer renders from.
    pub payload: serde_json::Value,
    /// The group this row must stay in order within, or `None` for a row that
    /// may be delivered concurrently with any other.
    pub ordering_key: Option<&'a str>,
    /// How many attempts this row gets before it is dead-lettered. `None`
    /// takes the column default.
    pub max_attempts: Option<u32>,
}

impl<'a> NewOutboxEntry<'a> {
    /// An unordered row with the default attempt budget.
    #[must_use]
    pub const fn new(kind: &'a str, destination: &'a str, payload: serde_json::Value) -> Self {
        Self {
            kind,
            destination,
            payload,
            ordering_key: None,
            max_attempts: None,
        }
    }

    /// Puts the row in an ordering group.
    #[must_use]
    pub const fn ordered_by(mut self, key: &'a str) -> Self {
        self.ordering_key = Some(key);
        self
    }
}

/// Writes one row inside the caller's transaction.
///
/// The transaction is a `&mut` borrow and not a pool, so this cannot be called
/// anywhere the caller does not already have one. See the module
/// documentation.
///
/// # Errors
///
/// [`DomainError::Storage`] if the insert fails. The caller's transaction is
/// left for the caller to roll back — which it must, because a change whose
/// notification could not be queued is a change nobody will be told about.
pub async fn enqueue(
    transaction: &mut PgTransaction<'_>,
    tenant: &TenantId,
    entry: &NewOutboxEntry<'_>,
    now: OffsetDateTime,
) -> Result<i64, DomainError> {
    let max_attempts = entry
        .max_attempts
        .map(|attempts| i32::try_from(attempts).unwrap_or(i32::MAX));

    let id = sqlx::query_scalar!(
        "insert into outbox
             (tenant_id, kind, destination, payload, ordering_key, created_at, available_at,
              max_attempts)
         values ($1, $2, $3, $4, $5, $6, $6, coalesce($7, 10))
         returning outbox_id",
        tenant.as_str(),
        entry.kind,
        entry.destination,
        entry.payload,
        entry.ordering_key,
        now,
        max_attempts,
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(to_domain_error)?;

    Ok(id)
}

/// How long a failed row waits before it is tried again.
///
/// Exponential from [`Backoff::base`], doubling per attempt, capped at
/// [`Backoff::cap`]. The cap is what keeps a receiver that has been down for a
/// day from being retried once a week: a row that has waited an hour has
/// waited long enough, and doubling past that only delays the recovery once
/// the receiver comes back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// The wait after the first failure.
    pub base: Duration,
    /// The longest wait between attempts.
    pub cap: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base: Duration::seconds(5),
            cap: Duration::hours(1),
        }
    }
}

impl Backoff {
    /// The most doublings applied before the cap is reached anyway.
    ///
    /// `2^31 * base` overflows nothing this type can hold, but computing it is
    /// pointless once the cap has bitten, and shifting by 64 or more is
    /// undefined in the abstract and a panic in debug builds here. Twenty is
    /// a million times the base, which is past any cap an operator can set.
    const MAX_DOUBLINGS: u32 = 20;

    /// How long to wait after `attempt` has failed, spread by `id`.
    ///
    /// The spread is deterministic and derived from the row id rather than
    /// from a random source: a thousand logout rows queued by one revocation
    /// all fail at the same instant against the same unreachable receiver, and
    /// without it they would all come back at the same instant too. Twelve and
    /// a half percent is enough to smear the retry across seconds without
    /// making the schedule unpredictable to an operator reading it — and being
    /// a pure function of the id, it is a thing a test can assert on.
    #[must_use]
    pub fn delay(&self, attempt: u32, id: i64) -> Duration {
        let doublings = attempt.saturating_sub(1).min(Self::MAX_DOUBLINGS);
        let scaled = self
            .base
            .saturating_mul(i32::try_from(1_u64 << doublings).unwrap_or(i32::MAX));
        let capped = scaled.min(self.cap);

        // `id % 8` eighths of an eighth: zero to 12.5% added, never subtracted,
        // so a spread can only delay a retry and never bring one forward past
        // the schedule an operator configured.
        let eighth = capped / 8;
        let spread = eighth / 8 * i32::try_from(id.rem_euclid(8)).unwrap_or(0);
        capped.saturating_add(spread)
    }
}

/// The outbox, from the worker's side.
#[derive(Clone)]
pub struct PgOutbox {
    pool: PgPool,
    backoff: Backoff,
    lease: Duration,
    max_attempts: u32,
}

impl std::fmt::Debug for PgOutbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgOutbox")
            .field("backoff", &self.backoff)
            .field("lease", &self.lease)
            .field("max_attempts", &self.max_attempts)
            .finish_non_exhaustive()
    }
}

/// How long a claim is held before another worker may take the row.
///
/// It bounds two things at once: how long a crashed worker's rows sit
/// undelivered, and how long a *live* worker has to finish a delivery before a
/// second one starts the same delivery beside it. Sixty seconds is comfortably
/// more than the five-second ceiling `crate`'s outbound fetches run under, so
/// the second case means the worker really is gone.
pub const DEFAULT_LEASE: Duration = Duration::seconds(60);

/// The attempt budget a row gets when nothing says otherwise.
///
/// The same number as the `outbox.max_attempts` column default, so a row
/// written by the free [`enqueue`] and a row written through
/// [`PgOutbox::enqueue`] on a deployment that configured nothing get the same
/// budget. Ten attempts on the default schedule spans a little over two hours,
/// which is long enough to ride out a receiver's deployment and short enough
/// that a genuinely dead endpoint is on the dead-letter screen the same
/// morning.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 10;

impl PgOutbox {
    /// Binds a pool with the default schedule.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            backoff: Backoff::default(),
            lease: DEFAULT_LEASE,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Binds a pool with a chosen schedule, from `[outbox]` or from a test.
    #[must_use]
    pub const fn with_schedule(pool: PgPool, backoff: Backoff, lease: Duration) -> Self {
        Self {
            pool,
            backoff,
            lease,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Sets the attempt budget rows written through [`Self::enqueue`] get.
    #[must_use]
    pub const fn with_max_attempts(mut self, max_attempts: u32) -> Self {
        self.max_attempts = max_attempts;
        self
    }

    /// The retry schedule in force.
    #[must_use]
    pub const fn backoff(&self) -> Backoff {
        self.backoff
    }

    /// The attempt budget in force.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Writes one row inside the caller's transaction, with this deployment's
    /// attempt budget.
    ///
    /// The front door. It differs from the free [`enqueue`] in one way: a row
    /// that does not choose its own `max_attempts` gets the configured one
    /// rather than the column default, which is how `[outbox] max_attempts`
    /// binds. The budget is stamped on the row at write time rather than read
    /// from configuration at delivery time on purpose — a row that has already
    /// failed nine times must not get nine more because somebody edited the
    /// file and restarted, and a row must mean the same thing to every replica
    /// whatever each one's configuration says.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the insert fails.
    pub async fn enqueue(
        &self,
        transaction: &mut PgTransaction<'_>,
        tenant: &TenantId,
        entry: &NewOutboxEntry<'_>,
        now: OffsetDateTime,
    ) -> Result<i64, DomainError> {
        let mut entry = entry.clone();
        entry.max_attempts = entry.max_attempts.or(Some(self.max_attempts));
        enqueue(transaction, tenant, &entry, now).await
    }

    /// Writes several rows in one transaction of this adapter's own.
    ///
    /// The [`asterius_domain::outbox::OutboxQueue`] port's implementation, and the one enqueue path
    /// that does *not* take the caller's transaction — because its callers are
    /// protocol handlers above the adapter layer, which cannot name a
    /// [`PgTransaction`]. The property the `&mut` transaction on
    /// [`Self::enqueue`] buys is not lost so much as narrowed: the rows here
    /// commit together, so a logout that notifies three relying parties queues
    /// three rows or none.
    ///
    /// What it does not buy is the row committing with the change it
    /// describes. For back-channel logout that is the honest shape: the
    /// session is revoked first and the tokens are queued after, so a crash
    /// between the two leaves a session that is *ended* and relying parties
    /// that were not told — which is a logout that under-notifies, not one
    /// that announces a session that is still live. The other order would be
    /// worse, and a single transaction is not available: revoking a session is
    /// the private `sessions` module's statement, not this one's.
    ///
    /// Every row gets this deployment's attempt budget, exactly as
    /// [`Self::enqueue`] gives it.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if any insert or the commit fails. Nothing was
    /// written.
    pub async fn queue_all(
        &self,
        tenant: &TenantId,
        events: &[asterius_domain::outbox::QueuedEvent],
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if events.is_empty() {
            return Ok(());
        }
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        for event in events {
            let entry = NewOutboxEntry {
                kind: &event.kind,
                destination: &event.destination,
                payload: event.payload.clone(),
                ordering_key: event.ordering_key.as_deref(),
                max_attempts: Some(self.max_attempts),
            };
            enqueue(&mut transaction, tenant, &entry, now).await?;
        }
        transaction.commit().await.map_err(to_domain_error)
    }

    /// Takes up to `limit` due rows across every tenant, marking them claimed.
    ///
    /// One statement, so the claim is atomic: the rows this returns are rows
    /// no other worker will be handed until the lease lapses. `skip locked`
    /// rather than a wait, because a worker that waits for another worker's
    /// row has stopped doing the work it could have been doing.
    ///
    /// Across every tenant rather than one: the rows are ordered by
    /// `available_at`, so a busy tenant does not starve a quiet one that has
    /// been waiting longer, and a per-tenant loop would be one statement per
    /// tenant per poll for a deployment where nearly every tenant is idle.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the statement fails.
    pub async fn claim(
        &self,
        worker: &str,
        limit: u32,
        now: OffsetDateTime,
    ) -> Result<Vec<OutboxEvent>, DomainError> {
        let rows = sqlx::query!(
            "with due as (
                 select c.tenant_id, c.outbox_id
                   from outbox c
                  where c.available_at <= $1
                    and (c.status in ('pending', 'failed')
                         or (c.status = 'claimed' and c.claim_expires_at <= $1))
                    and c.attempts < c.max_attempts
                    and (c.ordering_key is null
                         or not exists (
                             select 1
                               from outbox e
                              where e.tenant_id = c.tenant_id
                                and e.ordering_key = c.ordering_key
                                and e.outbox_id < c.outbox_id
                                and e.status in ('pending', 'failed', 'claimed')))
                  order by c.available_at, c.outbox_id
                  limit $2
                    for update skip locked
             )
             update outbox o
                set status = 'claimed',
                    claimed_by = $3,
                    claim_expires_at = $4,
                    attempts = o.attempts + 1
               from due
              where o.tenant_id = due.tenant_id
                and o.outbox_id = due.outbox_id
             returning o.tenant_id, o.outbox_id, o.kind, o.destination, o.payload,
                       o.attempts, o.max_attempts, o.created_at",
            now,
            i64::from(limit),
            worker,
            now + self.lease,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(rows
            .into_iter()
            .map(|row| OutboxEvent {
                tenant: TenantId::new(&row.tenant_id),
                id: row.outbox_id,
                kind: row.kind,
                destination: row.destination,
                payload: row.payload,
                attempt: u32::try_from(row.attempts).unwrap_or(u32::MAX),
                max_attempts: u32::try_from(row.max_attempts).unwrap_or(u32::MAX),
                created_at: row.created_at,
            })
            .collect())
    }

    /// Finishes a row: records the attempt and moves the row on.
    ///
    /// One transaction, so a row can never be marked delivered without the
    /// attempt that delivered it being recorded, nor the reverse.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the statements fail. A failure here leaves
    /// the claim in place, which lapses and is retried — the row is not lost,
    /// it is delivered twice, which is the trade this whole module makes.
    pub async fn ack(&self, event: &OutboxEvent, outcome: &Outcome) -> Result<(), DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        sqlx::query!(
            "insert into outbox_attempts
                 (tenant_id, outbox_id, attempt, attempted_at, outcome, detail)
             values ($1, $2, $3, $4, $5, $6)
             on conflict (tenant_id, outbox_id, attempt) do nothing",
            event.tenant.as_str(),
            event.id,
            i32::try_from(event.attempt).unwrap_or(i32::MAX),
            outcome.at,
            outcome.verdict.as_str(),
            outcome.detail.as_deref(),
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        match outcome.verdict {
            Verdict::Delivered | Verdict::Journalled => {
                // `delivered_at` is stamped only when something left the
                // process. A journal deliverer records the event here and
                // sends nothing, and `PgOutboxMailSender::queued` reads
                // exactly that distinction: an operator with no mail sender
                // wired still sees every message that was produced.
                let sent = matches!(outcome.verdict, Verdict::Delivered).then_some(outcome.at);
                sqlx::query!(
                    "update outbox
                        set status = 'delivered', delivered_at = $3, last_error = null,
                            claimed_by = null, claim_expires_at = null
                      where tenant_id = $1 and outbox_id = $2",
                    event.tenant.as_str(),
                    event.id,
                    sent,
                )
                .execute(&mut *transaction)
                .await
                .map_err(to_domain_error)?;
            }
            Verdict::Retry | Verdict::Abandoned => {
                let abandoned = matches!(outcome.verdict, Verdict::Abandoned);
                let available_at = outcome.at + self.backoff.delay(event.attempt, event.id);
                sqlx::query!(
                    "update outbox
                        set status = case when $3 then 'abandoned' else 'failed' end,
                            available_at = case when $3 then available_at else $4 end,
                            last_error = $5,
                            claimed_by = null, claim_expires_at = null
                      where tenant_id = $1 and outbox_id = $2",
                    event.tenant.as_str(),
                    event.id,
                    abandoned,
                    available_at,
                    outcome.detail.as_deref(),
                )
                .execute(&mut *transaction)
                .await
                .map_err(to_domain_error)?;
            }
        }

        transaction.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    /// How many rows are still owed across every tenant, for a metric.
    ///
    /// Counts `pending`, `failed` and `claimed` — everything that is not in a
    /// terminal state — because "how far behind is delivery" is the question a
    /// gauge answers, and a row backed off for an hour is behind.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the count fails.
    pub async fn backlog(&self) -> Result<i64, DomainError> {
        sqlx::query_scalar!(
            "select count(*) from outbox where status in ('pending', 'failed', 'claimed')"
        )
        .fetch_one(&self.pool)
        .await
        .map(Option::unwrap_or_default)
        .map_err(to_domain_error)
    }
}

/// What a deliverer reported, as the outbox records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// It left the process and the receiver accepted it.
    Delivered,
    /// It was recorded inside this process and sent nowhere. Terminal, and
    /// honest about it: `delivered_at` stays null.
    Journalled,
    /// It failed and the row has attempts left.
    Retry,
    /// It failed and the row has none. Dead-lettered.
    Abandoned,
}

impl Verdict {
    /// The spelling the `outbox_attempts.outcome` check constraint accepts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Journalled => "journalled",
            Self::Retry => "retry",
            Self::Abandoned => "abandoned",
        }
    }
}

/// One finished attempt.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// What happened.
    pub verdict: Verdict,
    /// When, from the caller's clock rather than the database's, so that a
    /// test can decide what "now" is.
    pub at: OffsetDateTime,
    /// The deliverer's description of a failure, already stripped of anything
    /// a payload or a receiver's response body carried. `None` on success.
    pub detail: Option<String>,
}

impl Outcome {
    /// A success that left the process.
    #[must_use]
    pub const fn delivered(at: OffsetDateTime) -> Self {
        Self {
            verdict: Verdict::Delivered,
            at,
            detail: None,
        }
    }

    /// A success that stayed inside it.
    #[must_use]
    pub const fn journalled(at: OffsetDateTime) -> Self {
        Self {
            verdict: Verdict::Journalled,
            at,
            detail: None,
        }
    }

    /// A failure the caller has decided will not become a success.
    ///
    /// Dead-letters the row whatever its attempt budget says. A deliverer
    /// reaches for this when the request itself is wrong — a receiver
    /// answering 400, a family nothing is registered for — because the
    /// alternative is nine more identical failures and an operator who finds
    /// out an hour later.
    #[must_use]
    pub const fn abandoned(at: OffsetDateTime, detail: String) -> Self {
        Self {
            verdict: Verdict::Abandoned,
            at,
            detail: Some(detail),
        }
    }

    /// A failure. Whether it is the last one is the event's to say, not the
    /// caller's, so this takes the event rather than a boolean somebody could
    /// pass the wrong way round.
    #[must_use]
    pub fn failed(event: &OutboxEvent, at: OffsetDateTime, detail: String) -> Self {
        Self {
            verdict: if event.is_final_attempt() {
                Verdict::Abandoned
            } else {
                Verdict::Retry
            },
            at,
            detail: Some(detail),
        }
    }
}

#[async_trait::async_trait]
impl asterius_domain::outbox::OutboxQueue for PgOutbox {
    async fn queue(
        &self,
        tenant: &TenantId,
        events: &[asterius_domain::outbox::QueuedEvent],
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.queue_all(tenant, events, now).await
    }
}

#[async_trait::async_trait]
impl DeadLetterQuery for PgOutbox {
    async fn dead_letters(
        &self,
        tenant: &TenantId,
        limit: u32,
    ) -> Result<Vec<DeadLetter>, DomainError> {
        let rows = sqlx::query!(
            "select o.outbox_id, o.kind, o.attempts, o.created_at, o.last_error,
                    (select max(a.attempted_at)
                       from outbox_attempts a
                      where a.tenant_id = o.tenant_id and a.outbox_id = o.outbox_id)
                        as last_attempt_at
               from outbox o
              where o.tenant_id = $1 and o.status = 'abandoned'
              order by o.outbox_id desc
              limit $2",
            tenant.as_str(),
            i64::from(limit),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(rows
            .into_iter()
            .map(|row| DeadLetter {
                id: row.outbox_id,
                kind: row.kind,
                attempts: u32::try_from(row.attempts).unwrap_or(u32::MAX),
                created_at: row.created_at,
                last_attempt_at: row.last_attempt_at,
                last_error: row.last_error,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(attempt: u32, max_attempts: u32) -> OutboxEvent {
        OutboxEvent {
            tenant: TenantId::new("acme"),
            id: 0,
            kind: "notification.credential_changed".to_owned(),
            destination: "someone@example".to_owned(),
            payload: serde_json::json!({}),
            attempt,
            max_attempts,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// The first retry waits `base`, not `base * 2`: an attempt counter that
    /// starts at one must not double before it has failed twice.
    #[test]
    fn the_first_retry_waits_one_base_period() {
        // Arrange
        let backoff = Backoff {
            base: Duration::seconds(4),
            cap: Duration::hours(1),
        };

        // Act
        let delay = backoff.delay(1, 0);

        // Assert
        assert_eq!(delay, Duration::seconds(4));
    }

    /// Doubling is what makes the schedule back *off*. Without it a receiver
    /// that is down for an hour is hit every four seconds for an hour.
    #[test]
    fn each_further_attempt_doubles_the_wait() {
        // Arrange
        let backoff = Backoff {
            base: Duration::seconds(4),
            cap: Duration::hours(1),
        };

        // Act
        let delays: Vec<_> = (1..=4).map(|attempt| backoff.delay(attempt, 0)).collect();

        // Assert
        assert_eq!(
            delays,
            vec![
                Duration::seconds(4),
                Duration::seconds(8),
                Duration::seconds(16),
                Duration::seconds(32),
            ]
        );
    }

    /// The cap is the operator's ceiling. A schedule that walks past it turns
    /// a configured "retry at least hourly" into "retry next week".
    #[test]
    fn the_wait_never_exceeds_the_cap() {
        // Arrange
        let backoff = Backoff {
            base: Duration::seconds(5),
            cap: Duration::minutes(2),
        };

        // Act
        let delays: Vec<_> = (1..=40).map(|attempt| backoff.delay(attempt, 0)).collect();

        // Assert
        assert!(
            delays.iter().all(|delay| *delay <= Duration::minutes(2)),
            "a delay exceeded the cap: {delays:?}"
        );
        assert_eq!(delays[39], Duration::minutes(2));
    }

    /// The schedule must be monotonic for every attempt and every row id: a
    /// spread that could make attempt four come back sooner than attempt three
    /// would be a way for a wedged row to spin.
    #[test]
    fn the_schedule_never_goes_backwards_for_any_row() {
        // Arrange
        let backoff = Backoff {
            base: Duration::seconds(3),
            cap: Duration::minutes(30),
        };

        // Act / Assert
        for id in 0..64_i64 {
            for attempt in 1..30_u32 {
                let earlier = backoff.delay(attempt, id);
                let later = backoff.delay(attempt + 1, id);
                assert!(
                    later >= earlier,
                    "attempt {attempt} on row {id}: {later:?} < {earlier:?}"
                );
            }
        }
    }

    /// The spread only ever delays. A negative one would fire a retry before
    /// the schedule the operator configured.
    #[test]
    fn the_spread_only_ever_adds_time() {
        // Arrange
        let backoff = Backoff {
            base: Duration::seconds(8),
            cap: Duration::hours(1),
        };
        let unspread = backoff.delay(3, 0);

        // Act
        let spread: Vec<_> = (0..16_i64).map(|id| backoff.delay(3, id)).collect();

        // Assert
        assert!(spread.iter().all(|delay| *delay >= unspread));
        assert!(
            spread.iter().any(|delay| *delay > unspread),
            "no row id produced any spread at all"
        );
    }

    /// A failure on the last attempt is a dead letter and a failure before it
    /// is a retry. Getting this backwards either loses the row silently or
    /// retries it forever.
    #[test]
    fn a_failure_on_the_last_attempt_is_abandoned() {
        // Arrange
        let now = OffsetDateTime::UNIX_EPOCH;

        // Act
        let penultimate = Outcome::failed(&event(2, 3), now, "refused".to_owned());
        let last = Outcome::failed(&event(3, 3), now, "refused".to_owned());

        // Assert
        assert_eq!(penultimate.verdict, Verdict::Retry);
        assert_eq!(last.verdict, Verdict::Abandoned);
    }

    /// Every verdict has to spell itself the way the check constraint on
    /// `outbox_attempts.outcome` expects, or the ack fails at runtime.
    #[test]
    fn every_verdict_spells_itself_as_the_constraint_expects() {
        // Arrange
        let accepted = ["delivered", "journalled", "retry", "abandoned"];

        // Act
        let spelt = [
            Verdict::Delivered.as_str(),
            Verdict::Journalled.as_str(),
            Verdict::Retry.as_str(),
            Verdict::Abandoned.as_str(),
        ];

        // Assert
        assert_eq!(spelt, accepted);
    }
}
