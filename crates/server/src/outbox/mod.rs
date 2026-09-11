//! The delivery worker: what turns outbox rows into things that happened.
//!
//! `asterius_store_pg::outbox` owns the table, the claim and the ack — the
//! part that has to be SQL. This is the part that has to be a process: a loop
//! that claims a batch, hands each row to the [`Deliverer`] registered for its
//! family, and acks what each one reported. It is the same shape as
//! [`crate::retention`] and [`crate::rotation`], for the same reason: the work
//! is owed by the deployment rather than by any request, so it belongs to a
//! task with the lifetime of the process.
//!
//! # One deliverer per family
//!
//! An outbox row's `kind` is `family.name` — `notification.account_recovery`,
//! `logout.backchannel`, one day `ssf.caep.session-revoked` — and the family
//! chooses the deliverer. That is what lets back-channel logout, SSF push,
//! CIBA ping and notifications share one worker, one claim query, one backoff
//! schedule and one dead-letter screen while each decides for itself what
//! "deliver" means.
//!
//! Two are registered here today:
//!
//! * [`journal::JournalDeliverer`] for `notification.*`, which is `ast-2vk.10`'s
//!   mail journal becoming a consumer of this worker rather than a table that
//!   nothing reads.
//! * [`http::HttpDeliverer`] for everything that is a `POST` to a URL a client
//!   registered, through [`crate::outbound::post`] and therefore through
//!   ADR-0006's one outbound path.
//!
//! There is deliberately no SSF or CIBA deliverer here. Those are their own
//! tickets and their own payload formats; what this ticket owes them is the
//! machinery, and machinery with a speculative implementation of a
//! specification nobody has written yet is worse than none.
//!
//! # A row nobody can deliver is a dead letter immediately
//!
//! An unregistered family is not a transient failure and retrying it ten times
//! over an hour would only delay the moment an operator finds out. It is
//! abandoned on the first attempt, with a reason that names the family.
//!
//! # What a worker may log
//!
//! The tenant, the row id, the family, the attempt, and the deliverer's own
//! description of a failure. Never the payload — an
//! `notification.account_recovery` payload is a live reset link — never the
//! destination, and never the ordering key, which is built from a subject or a
//! session id. `crates/server/tests/log_redaction.rs` holds the worker case.

pub mod ciba;
pub mod http;
pub mod journal;
pub mod ssf;

use asterius_domain::DomainError;
use asterius_domain::outbox::OutboxEvent;
use asterius_domain::ports::Clock;
use asterius_store_pg::{Outcome, PgOutbox, Verdict};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use time::Duration;

pub use ciba::{CibaPingDeliverer, PgPingRequests, PingRequests};
pub use http::HttpDeliverer;
pub use journal::JournalDeliverer;
pub use ssf::{PgPushStreams, PgSsfQueues, PushStreams, SetPoster, SsfPushDeliverer, push_event};

/// What a deliverer did with an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    /// It left the process and the receiver accepted it.
    Sent,
    /// It was recorded inside this process and sent nowhere.
    ///
    /// Terminal, and honest about it: the row is finished but its
    /// `delivered_at` stays null, so `PgOutboxMailSender::queued` — an
    /// operator's view of what *would* have been sent while no mail sender is
    /// wired — still shows it.
    Journalled,
}

/// Why a delivery did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undelivered {
    /// What to record, already stripped of anything a payload or a receiver's
    /// response body carried. It ends up in `outbox.last_error` and on an
    /// operator's screen.
    pub detail: String,
    /// Whether trying again could plausibly work.
    ///
    /// `true` spends the whole attempt budget at once and dead-letters now. A
    /// deliverer says so when the request itself is wrong — an unparseable
    /// destination, a receiver answering 400 — because nine more identical
    /// requests will be just as wrong and the operator finds out an hour later.
    pub permanent: bool,
}

impl Undelivered {
    /// A failure worth retrying.
    #[must_use]
    pub const fn transient(detail: String) -> Self {
        Self {
            detail,
            permanent: false,
        }
    }

    /// A failure that will not become a success.
    #[must_use]
    pub const fn permanent(detail: String) -> Self {
        Self {
            detail,
            permanent: true,
        }
    }
}

/// Something that delivers one family of outbox events.
#[async_trait::async_trait]
pub trait Deliverer: std::fmt::Debug + Send + Sync {
    /// The `kind` prefix this deliverer answers for, e.g. `notification`.
    ///
    /// A `&'static str` because it is also a metric label: see
    /// [`crate::observability::metrics::OUTBOX_DELIVERIES`].
    fn family(&self) -> &'static str;

    /// Delivers one event.
    ///
    /// # Errors
    ///
    /// [`Undelivered`] with a description an operator can act on. A deliverer
    /// returns rather than panics: one broken receiver must not stop the
    /// worker.
    async fn deliver(&self, event: &OutboxEvent) -> Result<Delivered, Undelivered>;
}

/// The deliverers a worker can reach, keyed by family.
///
/// A type of its own rather than a field, so that "which family goes where"
/// can be built and asserted on without a database — this crate cannot even
/// name `sqlx`, and a registry that could only be tested through a pool would
/// not be tested.
#[derive(Debug, Default, Clone)]
pub struct Deliverers(BTreeMap<&'static str, Arc<dyn Deliverer>>);

impl Deliverers {
    /// An empty registry. A worker with one delivers nothing and dead-letters
    /// everything, which is the correct behaviour for a misconfiguration and a
    /// bad thing to leave in place.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a deliverer under its own family, replacing any already there.
    #[must_use]
    pub fn with(mut self, deliverer: Arc<dyn Deliverer>) -> Self {
        self.0.insert(deliverer.family(), deliverer);
        self
    }

    /// The families this registry answers for, in order.
    #[must_use]
    pub fn families(&self) -> Vec<&'static str> {
        self.0.keys().copied().collect()
    }

    /// The deliverer for `event`, if one is registered.
    #[must_use]
    pub fn for_event(&self, event: &OutboxEvent) -> Option<Arc<dyn Deliverer>> {
        self.0.get(event.family()).map(Arc::clone)
    }
}

/// What one pass did, for the caller that wants to assert on it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryReport {
    /// Rows claimed this pass.
    pub claimed: usize,
    /// Rows a deliverer accepted, sent or journalled.
    pub delivered: usize,
    /// Rows that failed and will be tried again.
    pub retrying: usize,
    /// Rows that failed for the last time and are now dead letters.
    pub abandoned: usize,
}

/// Claims outbox rows and hands them to deliverers.
pub struct OutboxWorker {
    outbox: PgOutbox,
    deliverers: Deliverers,
    clock: Arc<dyn Clock>,
    name: String,
    batch: u32,
    interval: Duration,
}

impl std::fmt::Debug for OutboxWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxWorker")
            .field("name", &self.name)
            .field("families", &self.deliverers.families())
            .field("batch", &self.batch)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl OutboxWorker {
    /// How often a worker with nothing to do looks again.
    ///
    /// One second. Polling rather than `LISTEN`/`NOTIFY` for the reason
    /// ADR-0001 gives about not adding a second mechanism: a notification is
    /// lost if no replica is listening at the moment it fires, so a poll would
    /// be needed as a backstop anyway, and then there are two things to reason
    /// about during an incident instead of one. A second of latency on a
    /// back-channel logout is not what anybody notices.
    pub const DEFAULT_INTERVAL: Duration = Duration::seconds(1);

    /// How many rows one claim takes.
    ///
    /// Bounded because the batch is claimed under one lease: a worker that
    /// took a thousand rows and then delivered them one at a time would hold
    /// the last of them past its lease and have it delivered twice beside it.
    pub const DEFAULT_BATCH: u32 = 32;

    /// Builds a worker over `outbox`, with no deliverers registered yet.
    #[must_use]
    pub fn new(outbox: PgOutbox, clock: Arc<dyn Clock>, name: String) -> Self {
        Self {
            outbox,
            deliverers: Deliverers::new(),
            clock,
            name,
            batch: Self::DEFAULT_BATCH,
            interval: Self::DEFAULT_INTERVAL,
        }
    }

    /// Registers a deliverer for its family, replacing any already there.
    #[must_use]
    pub fn with(mut self, deliverer: Arc<dyn Deliverer>) -> Self {
        self.deliverers = self.deliverers.with(deliverer);
        self
    }

    /// Chooses the poll interval and the batch size.
    #[must_use]
    pub const fn with_pace(mut self, interval: Duration, batch: u32) -> Self {
        self.interval = interval;
        self.batch = batch;
        self
    }

    /// The families this worker can deliver, in order.
    #[must_use]
    pub fn families(&self) -> Vec<&'static str> {
        self.deliverers.families()
    }

    /// Claims one batch, delivers it, and acks every row.
    ///
    /// Deliveries within a batch run concurrently. They are independent by
    /// construction — the claim query already refused to hand out two rows
    /// that share an ordering key — so serialising them would only mean a
    /// batch of thirty-two costs thirty-two round trips to thirty-two
    /// different receivers, one after another.
    ///
    /// # Errors
    ///
    /// [`DomainError`] only if the *claim* failed, which is the one failure
    /// that is not about a particular row. A row whose delivery or ack failed
    /// is counted and left for the lease to reclaim.
    pub async fn deliver_once(&self) -> Result<DeliveryReport, DomainError> {
        let claimed = self
            .outbox
            .claim(&self.name, self.batch, self.clock.now())
            .await?;

        let mut report = DeliveryReport {
            claimed: claimed.len(),
            ..DeliveryReport::default()
        };
        if claimed.is_empty() {
            return Ok(report);
        }

        let mut deliveries = tokio::task::JoinSet::new();
        for event in claimed {
            let deliverer = self.deliverers.for_event(&event);
            let outbox = self.outbox.clone();
            let now = self.clock.now();
            deliveries
                .spawn(async move { finish(&outbox, deliverer.as_deref(), event, now).await });
        }

        while let Some(joined) = deliveries.join_next().await {
            match joined {
                Ok(Verdict::Delivered | Verdict::Journalled) => report.delivered += 1,
                Ok(Verdict::Retry) => report.retrying += 1,
                Ok(Verdict::Abandoned) => report.abandoned += 1,
                Err(error) => {
                    // A deliverer that panicked leaves its row claimed; the
                    // lease reclaims it. Logged at error because a panic in a
                    // background task is otherwise completely silent.
                    tracing::error!(%error, "an outbox delivery task panicked");
                    report.retrying += 1;
                }
            }
        }
        Ok(report)
    }

    /// Delivers every interval until `shutdown` resolves.
    ///
    /// Never returns an error, for the reason [`crate::retention`] gives:
    /// there is nobody above this to handle one, and a database that is
    /// briefly unreachable is not a reason to stop delivering for the life of
    /// the process.
    ///
    /// A pass that had a full batch does not wait: a backlog is cleared as
    /// fast as the database will hand rows over, and the interval is what an
    /// *idle* worker waits.
    pub async fn run(self, shutdown: impl Future<Output = ()> + Send) {
        let period = std::time::Duration::try_from(self.interval)
            .unwrap_or_else(|_| std::time::Duration::from_secs(1));
        let mut shutdown = std::pin::pin!(shutdown);

        tracing::info!(
            worker = %self.name,
            families = ?self.families(),
            "outbox delivery started"
        );

        loop {
            let busy = match self.deliver_once().await {
                Ok(report) => {
                    if report.abandoned > 0 {
                        // Warn rather than debug: a dead letter is a delivery
                        // this deployment has given up on, and nothing else
                        // will mention it until somebody opens the screen.
                        tracing::warn!(
                            claimed = report.claimed,
                            delivered = report.delivered,
                            abandoned = report.abandoned,
                            "the outbox abandoned deliveries"
                        );
                    } else if report.claimed > 0 {
                        tracing::debug!(
                            claimed = report.claimed,
                            delivered = report.delivered,
                            retrying = report.retrying,
                            "the outbox delivered a batch"
                        );
                    }
                    report.claimed >= self.batch as usize
                }
                Err(error) => {
                    tracing::error!(%error, "could not claim outbox rows");
                    false
                }
            };

            match self.outbox.backlog().await {
                Ok(rows) => crate::observability::metrics::outbox_backlog(rows),
                Err(error) => tracing::debug!(%error, "could not measure the outbox backlog"),
            }

            if busy {
                // A full batch means there is more waiting. Yield rather than
                // sleep, so a backlog drains at the database's pace, but still
                // check for shutdown between passes.
                if futures_lite_ready(&mut shutdown).await {
                    break;
                }
                continue;
            }
            tokio::select! {
                () = tokio::time::sleep(period) => {}
                () = &mut shutdown => break,
            }
        }
        tracing::info!(worker = %self.name, "outbox delivery stopped");
    }
}

/// Whether the shutdown future has already resolved, without waiting for it.
///
/// The busy path must not sleep and must not ignore a stop signal, and
/// `select!` with a zero sleep would be a busy loop with extra steps.
async fn futures_lite_ready(shutdown: &mut std::pin::Pin<&mut impl Future<Output = ()>>) -> bool {
    tokio::select! {
        biased;
        () = &mut *shutdown => true,
        () = tokio::task::yield_now() => false,
    }
}

/// Delivers one event and acks it, returning what was recorded.
async fn finish(
    outbox: &PgOutbox,
    deliverer: Option<&dyn Deliverer>,
    event: OutboxEvent,
    now: time::OffsetDateTime,
) -> Verdict {
    let (outcome, family) = match deliverer {
        Some(deliverer) => match deliverer.deliver(&event).await {
            Ok(Delivered::Sent) => (Outcome::delivered(now), deliverer.family()),
            Ok(Delivered::Journalled) => (Outcome::journalled(now), deliverer.family()),
            Err(failure) => {
                let outcome = if failure.permanent {
                    Outcome::abandoned(now, failure.detail)
                } else {
                    Outcome::failed(&event, now, failure.detail)
                };
                (outcome, deliverer.family())
            }
        },
        // Named rather than described: the family is a prefix this server
        // wrote into the row, so it is safe to log and it is the one thing an
        // operator needs to know to fix the wiring.
        None => (
            Outcome::abandoned(
                now,
                format!(
                    "no deliverer is registered for the {} family",
                    event.family()
                ),
            ),
            "unregistered",
        ),
    };

    let verdict = outcome.verdict;
    crate::observability::metrics::outbox_delivery(family, verdict.as_str());

    if let Err(error) = outbox.ack(&event, &outcome).await {
        // The row stays claimed and its lease reclaims it, so the event is
        // delivered again rather than lost. That is the trade this whole
        // design makes; it is logged so that a receiver reporting duplicates
        // has something to correlate against.
        tracing::error!(
            %error,
            tenant = %event.tenant,
            row = event.id,
            "could not record an outbox delivery; it will be attempted again"
        );
    }
    if matches!(verdict, Verdict::Abandoned) {
        tracing::warn!(
            tenant = %event.tenant,
            row = event.id,
            family = family,
            attempts = event.attempt,
            "an outbox row was abandoned"
        );
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::TenantId;
    use std::sync::Mutex;
    use time::OffsetDateTime;

    /// A deliverer that answers however the test says and remembers what it
    /// was asked for.
    #[derive(Debug)]
    struct Scripted {
        family: &'static str,
        answer: Result<Delivered, Undelivered>,
        seen: Mutex<Vec<i64>>,
    }

    #[async_trait::async_trait]
    impl Deliverer for Scripted {
        fn family(&self) -> &'static str {
            self.family
        }

        async fn deliver(&self, event: &OutboxEvent) -> Result<Delivered, Undelivered> {
            self.seen
                .lock()
                .expect("the lock is never poisoned")
                .push(event.id);
            self.answer.clone()
        }
    }

    fn scripted(
        family: &'static str,
        answer: Result<Delivered, Undelivered>,
    ) -> Arc<dyn Deliverer> {
        Arc::new(Scripted {
            family,
            answer,
            seen: Mutex::new(Vec::new()),
        })
    }

    fn event(kind: &str) -> OutboxEvent {
        OutboxEvent {
            tenant: TenantId::new("acme"),
            id: 7,
            kind: kind.to_owned(),
            destination: "https://rp.example/hook".to_owned(),
            payload: serde_json::json!({}),
            attempt: 1,
            max_attempts: 5,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// A registry keyed by family is what lets one worker serve back-channel
    /// logout, SSF and notifications. Registering two deliverers must leave
    /// both reachable.
    #[test]
    fn a_registry_reports_the_families_it_can_deliver() {
        // Arrange
        let registry = Deliverers::new()
            .with(scripted("notification", Ok(Delivered::Journalled)))
            .with(scripted("logout", Ok(Delivered::Sent)));

        // Act
        let families = registry.families();

        // Assert
        assert_eq!(families, vec!["logout", "notification"]);
    }

    /// Dispatch is by family, so a `logout.backchannel` row reaches the
    /// deliverer registered as `logout` and an `ssf.*` row reaches nothing —
    /// which is what dead-letters it with a reason rather than dropping it.
    #[test]
    fn a_row_reaches_the_deliverer_registered_for_its_family() {
        // Arrange
        let registry = Deliverers::new().with(scripted("logout", Ok(Delivered::Sent)));

        // Act
        let known = registry.for_event(&event("logout.backchannel"));
        let unknown = registry.for_event(&event("ssf.caep.session-revoked"));

        // Assert
        assert_eq!(
            known.expect("a logout deliverer is registered").family(),
            "logout"
        );
        assert!(unknown.is_none());
    }

    /// A deliverer really is asked, and asked about the row it was handed.
    /// Without this the registry tests above would pass on a `deliver` that
    /// was never called.
    #[tokio::test]
    async fn a_registered_deliverer_is_handed_the_row() {
        // Arrange
        let deliverer = Arc::new(Scripted {
            family: "logout",
            answer: Ok(Delivered::Sent),
            seen: Mutex::new(Vec::new()),
        });
        let registry = Deliverers::new().with(Arc::clone(&deliverer) as Arc<dyn Deliverer>);
        let row = event("logout.backchannel");

        // Act
        let outcome = registry
            .for_event(&row)
            .expect("a deliverer is registered")
            .deliver(&row)
            .await;

        // Assert
        assert_eq!(outcome, Ok(Delivered::Sent));
        assert_eq!(
            *deliverer.seen.lock().expect("the lock is never poisoned"),
            vec![row.id]
        );
    }

    /// Dispatch is by family and not by the whole kind, so a family that
    /// grows a new event name does not need the worker changed.
    #[test]
    fn dispatch_uses_the_family_and_not_the_whole_kind() {
        // Arrange
        let subject = event("ssf.caep.session-revoked");

        // Act
        let family = subject.family().to_owned();

        // Assert
        assert_eq!(family, "ssf");
    }

    /// A permanent failure spends the whole budget at once. Retrying a request
    /// the receiver has already called malformed only delays the dead letter.
    #[test]
    fn a_permanent_failure_is_abandoned_on_the_first_attempt() {
        // Arrange
        let subject = event("logout.backchannel");
        let failure = Undelivered::permanent("rp.example answered 400".to_owned());

        // Act
        let outcome = if failure.permanent {
            Outcome::abandoned(OffsetDateTime::UNIX_EPOCH, failure.detail)
        } else {
            Outcome::failed(&subject, OffsetDateTime::UNIX_EPOCH, failure.detail)
        };

        // Assert
        assert_eq!(outcome.verdict, Verdict::Abandoned);
        assert_eq!(subject.attempt, 1, "the budget was not what abandoned it");
    }

    /// A transient failure on a row with attempts left is retried, which is
    /// the other half of the decision above.
    #[test]
    fn a_transient_failure_with_budget_left_is_retried() {
        // Arrange
        let subject = event("logout.backchannel");

        // Act
        let outcome = Outcome::failed(
            &subject,
            OffsetDateTime::UNIX_EPOCH,
            "rp.example answered 503".to_owned(),
        );

        // Assert
        assert_eq!(outcome.verdict, Verdict::Retry);
    }
}
