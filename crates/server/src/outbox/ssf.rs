//! Push delivery of Security Event Tokens (RFC 8935, `ast-0ju.6`).
//!
//! The `ssf` family's deliverer. One outbox row is one SET, addressed to one
//! stream, and delivering it is one `POST` to the receiver's endpoint — §2.2:
//! "SETs MUST be transmitted one at a time". There is no batch here and no
//! place to add one.
//!
//! # Why this is not [`super::http::HttpDeliverer`]
//!
//! The generic deliverer posts a body to `event.destination` and reads a
//! status. Push delivery needs four things it cannot do, and each of them is a
//! decision a receiver's answer steers:
//!
//! * the destination is a **stream identifier, not a URL**. The receiver's
//!   endpoint is configuration, read at delivery time, so a receiver that
//!   changed it is not still being posted to the old one — and a stream that
//!   was deleted (SSF 1.0 §8.1.1.5) is not posted to at all;
//! * the request carries the receiver's **`authorization_header`** (SSF 1.0
//!   §6.1.1: the transmitter MUST send it on every request), which is sealed
//!   in that same row;
//! * a refusal carries **§2.3's error object**, and which code it holds
//!   decides whether anybody is told to look at this server's published keys;
//! * a stream whose deliveries have run out of retries is **paused** (§8.1.2),
//!   which is the thing that stops the next hundred SETs from becoming dead
//!   letters too.
//!
//! # Ordering
//!
//! Not enforced here, and deliberately so: it is the claim query's, which
//! refuses to hand out a row whose `ordering_key` has an older row still owed
//! (`0017_outbox_delivery.sql`). This module's contribution is
//! [`push_event`], which builds that key from the stream and the subject — so
//! two events about one person reach the receiver in the order they happened
//! even when the first is retried, and two events about different people are
//! not serialised behind each other.
//!
//! # What may be logged
//!
//! The tenant, the row, the stream identifier, the §2.3 code and a status.
//! Never the endpoint URL — it may carry a token in a query parameter — never
//! the `authorization_header`, and never the SET, which carries a subject
//! identifier.

use crate::outbound::{PostError, PostRequest};
use crate::outbox::{Delivered, Deliverer, Undelivered};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::outbox::{OutboxEvent, QueuedEvent};
use asterius_domain::ports::Clock;
use asterius_domain::{DomainError, TenantId};
use asterius_jose::Kek;
use asterius_ssf::push::{self, Disposition, PUSH_ACCEPT, PUSH_CONTENT_TYPE};
use asterius_ssf::stream::StreamId;
use asterius_store_pg::{PushTarget, SET_OUTBOX_KIND, Store};
use std::sync::Arc;

/// The outbox family this deliverer answers for.
pub const FAMILY: &str = "ssf";

/// One SET on its way to one stream.
///
/// The `ordering_key` is `(stream, subject)` and not `(stream)`: SSF 1.0 makes
/// order matter *per subject* — a "session revoked" must not overtake the
/// "session established" it invalidates — and a key of the whole stream would
/// put a busy tenant's every signal behind whichever receiver is slowest to
/// answer.
///
/// `subject` is whatever names the person the SET is about, in the spelling
/// the emitter uses. It is not rendered anywhere: the key reaches
/// `outbox.ordering_key`, which `crates/server/src/observability/redact.rs`
/// keeps out of logs for exactly this reason.
#[must_use]
pub fn push_event(stream: &StreamId, subject: &str, jws: &str) -> QueuedEvent {
    QueuedEvent {
        kind: format!("{FAMILY}.set"),
        destination: stream.as_str().to_owned(),
        payload: serde_json::json!({ "body": jws }),
        ordering_key: Some(format!("{}\u{1f}{subject}", stream.as_str())),
    }
}

/// Posting one SET, as this deliverer needs it.
///
/// A port rather than [`crate::outbound::HttpsPoster`] itself, so that the
/// decisions in this module — which answers are retried, which pause a stream,
/// which ask for a key refresh — are testable against a receiver that says
/// what a test needs it to say. They cannot be tested against a real socket:
/// the outbound path refuses every address a test could bind
/// ([`crate::outbound::ssrf`]), which is the correct behaviour and makes a
/// loopback receiver impossible by construction. What that guard, the TLS
/// configuration and the timeout do is covered where they live.
#[async_trait::async_trait]
pub trait SetPoster: std::fmt::Debug + Send + Sync {
    /// Delivers one SET and returns the status it was accepted with.
    ///
    /// # Errors
    ///
    /// [`PostError`], including the receiver's refusal body where there was
    /// one.
    async fn post(
        &self,
        url: &str,
        request: PostRequest<'_>,
        body: &[u8],
    ) -> Result<u16, PostError>;
}

#[async_trait::async_trait]
impl SetPoster for crate::outbound::HttpsPoster {
    async fn post(
        &self,
        url: &str,
        request: PostRequest<'_>,
        body: &[u8],
    ) -> Result<u16, PostError> {
        self.post_with(url, request, body).await
    }
}

/// The stream state one delivery reads and writes.
///
/// A port for the same reason as [`SetPoster`]: what this module does with a
/// receiver's answer is a property of RFC 8935, and a test that needed
/// Postgres to assert it would be a test nobody writes.
#[async_trait::async_trait]
pub trait PushStreams: std::fmt::Debug + Send + Sync {
    /// Where to deliver, with what credential, and whether the stream is
    /// delivering at all.
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the store could not be reached or the credential did
    /// not open.
    async fn target(
        &self,
        tenant: &TenantId,
        stream: &StreamId,
    ) -> Result<Option<PushTarget>, DomainError>;

    /// Tells the receiver that its stream is about to stop (SSF 1.0 §8.1.5).
    ///
    /// Called immediately *before* [`Self::pause`], because §8.1.5 requires
    /// the stream-updated event to be sent "before the stream is paused or
    /// disabled". Queued while the stream is still enabled, it is a SET the
    /// queue accepts; announced after the pause, it would be one the pause
    /// itself holds back.
    ///
    /// The SET bypasses `events_requested` and the stream's subject
    /// membership, as §8.1.4's verification event does — see
    /// [`crate::ssf::StreamSignals`].
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the stream cannot be read, or the SET cannot be
    /// built, signed or queued. The caller logs it and pauses the stream
    /// anyway: a receiver that cannot be told is usually the reason the
    /// stream is being paused.
    async fn announce_pause(
        &self,
        tenant: &TenantId,
        stream: &StreamId,
        reason: &str,
        now: time::OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Stops delivery on the stream, recording why (SSF 1.0 §8.1.2).
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the write failed.
    async fn pause(
        &self,
        tenant: &TenantId,
        stream: &StreamId,
        reason: &str,
        now: time::OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Counts one attempt against the stream's own totals.
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the write failed.
    async fn count_attempt(
        &self,
        tenant: &TenantId,
        stream: &StreamId,
        delivered: bool,
    ) -> Result<(), DomainError>;
}

/// [`PushStreams`] over `PostgreSQL`.
///
/// It holds a signer and the tenant directory as well as the rows, because
/// §8.1.5's announcement is a *signed* SET: the worker that pauses a stream
/// has to be able to tell the receiver so, and the key that signs that SET is
/// the tenant's own — the same one the emitters and the console sign with.
#[derive(Clone)]
pub struct PgPushStreams {
    store: Store,
    kek: Arc<dyn Kek>,
    signer: Arc<dyn asterius_domain::keys::Signer>,
    tenants: Arc<dyn asterius_domain::ports::TenantRepository>,
}

impl std::fmt::Debug for PgPushStreams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PgPushStreams")
    }
}

impl PgPushStreams {
    /// Builds the adapter over the process's store, key-encryption key,
    /// signer and tenant directory.
    #[must_use]
    pub const fn new(
        store: Store,
        kek: Arc<dyn Kek>,
        signer: Arc<dyn asterius_domain::keys::Signer>,
        tenants: Arc<dyn asterius_domain::ports::TenantRepository>,
    ) -> Self {
        Self {
            store,
            kek,
            signer,
            tenants,
        }
    }

    fn streams(&self, tenant: &TenantId) -> asterius_store_pg::PgSsfStreams {
        self.store
            .scope(tenant.clone())
            .ssf_streams(Arc::clone(&self.kek))
    }
}

#[async_trait::async_trait]
impl PushStreams for PgPushStreams {
    async fn target(
        &self,
        tenant: &TenantId,
        stream: &StreamId,
    ) -> Result<Option<PushTarget>, DomainError> {
        self.streams(tenant).for_delivery(stream).await
    }

    async fn announce_pause(
        &self,
        tenant: &TenantId,
        stream: &StreamId,
        reason: &str,
        now: time::OffsetDateTime,
    ) -> Result<(), DomainError> {
        let Some(subscription) = self.streams(tenant).subscription(stream).await? else {
            // The stream was deleted under the delivery (§8.1.1.5). There is
            // nobody to announce a pause to, and `pause` will report the same.
            return Ok(());
        };
        let tenant_entity = self
            .tenants
            .find_by_id(tenant)
            .await?
            .ok_or(DomainError::NotFound)?;
        let queues = crate::outbox::PgSsfQueues::new(
            self.store.clone(),
            tenant.clone(),
            Arc::clone(&self.kek),
        );
        crate::ssf::StreamSignals {
            tenant,
            issuer: &tenant_entity.issuer,
            queues: &queues,
            signer: self.signer.as_ref(),
        }
        .announce_status(
            &subscription,
            asterius_ssf::stream::StreamStatus::Paused,
            Some(reason),
            now,
        )
        .await
    }

    async fn pause(
        &self,
        tenant: &TenantId,
        stream: &StreamId,
        reason: &str,
        now: time::OffsetDateTime,
    ) -> Result<bool, DomainError> {
        self.streams(tenant).pause(stream, reason, now).await
    }

    async fn count_attempt(
        &self,
        tenant: &TenantId,
        stream: &StreamId,
        delivered: bool,
    ) -> Result<(), DomainError> {
        self.streams(tenant).count_attempt(stream, delivered).await
    }
}

/// Delivers `ssf.*` outbox rows by pushing them (RFC 8935 §2).
pub struct SsfPushDeliverer {
    streams: Arc<dyn PushStreams>,
    poster: Arc<dyn SetPoster>,
    audit: Arc<dyn AuditSink>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SsfPushDeliverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsfPushDeliverer")
            .field("streams", &self.streams)
            .finish_non_exhaustive()
    }
}

impl SsfPushDeliverer {
    /// Assembles a deliverer.
    #[must_use]
    pub const fn new(
        streams: Arc<dyn PushStreams>,
        poster: Arc<dyn SetPoster>,
        audit: Arc<dyn AuditSink>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            streams,
            poster,
            audit,
            clock,
        }
    }

    /// Writes one entry, and never fails the delivery over it.
    ///
    /// A delivery that succeeded and could not be audited is still a delivery
    /// that happened; re-posting the SET to make the trail tidy would send a
    /// receiver a duplicate. The failure is logged instead, which is the same
    /// trade [`super::finish`] makes for an ack it could not write.
    async fn record(
        &self,
        tenant: &TenantId,
        stream: &StreamId,
        event_type: EventType,
        outcome: Outcome,
        detail: Detail,
    ) {
        let event = AuditEvent::new(
            tenant.clone(),
            event_type,
            outcome,
            // The server pushed this, not the receiver: nobody asked, which is
            // what push delivery is.
            Actor::System,
            self.clock.now(),
        )
        .detail(detail);
        if let Err(error) = self.audit.record(event).await {
            tracing::error!(
                %error,
                tenant = %tenant,
                "an SSF push delivery was not written to the audit trail"
            );
        }
        let _ = stream;
    }

    /// Pauses the stream and says so in the trail (SSF 1.0 §8.1.2), having
    /// first told the receiver (§8.1.5).
    ///
    /// Called when a SET has spent RFC 8935 §2.4's retries. The dead letter
    /// records the one SET; this is what records that the rest are not being
    /// attempted either.
    ///
    /// The stream-updated event is queued **before** the status is written,
    /// which is the order §8.1.5 requires: while the stream is still enabled
    /// the queue takes the SET, and a paused stream then holds it (§8.1.2)
    /// until somebody re-enables the stream — at which point the receiver
    /// learns both that it was paused and that it is back. Announcing after
    /// the write would queue the same SET into a stream that is already
    /// holding everything, with nothing to distinguish it from the backlog.
    ///
    /// An announcement that cannot be made does not stop the pause: the
    /// receiver has just failed every retry, so being unable to tell it
    /// anything is the expected case here, not a reason to keep delivering.
    async fn pause(&self, tenant: &TenantId, stream: &StreamId, reason: &str) {
        if let Err(error) = self
            .streams
            .announce_pause(tenant, stream, reason, self.clock.now())
            .await
        {
            tracing::warn!(
                %error,
                tenant = %tenant,
                stream = %stream.as_str(),
                "an SSF stream was paused without the receiver being told",
            );
        }
        match self
            .streams
            .pause(tenant, stream, reason, self.clock.now())
            .await
        {
            // `false` is a stream somebody had already stopped: the reason on
            // the row is the one that stopped it, and this delivery has no
            // better claim to it.
            Ok(false) => {}
            Ok(true) => {
                tracing::warn!(
                    tenant = %tenant,
                    stream = %stream.as_str(),
                    reason,
                    "an SSF stream was paused after a delivery ran out of retries"
                );
                self.record(
                    tenant,
                    stream,
                    EventType::SSF_STREAM_PAUSED,
                    Outcome::Failure,
                    Detail::new()
                        .credential("stream_id", stream.as_str())
                        .text("reason", reason),
                )
                .await;
            }
            Err(error) => tracing::error!(
                %error,
                tenant = %tenant,
                "could not pause an SSF stream whose deliveries are failing"
            ),
        }
    }

    /// Counts the attempt, and never fails the delivery over it.
    async fn count(&self, tenant: &TenantId, stream: &StreamId, delivered: bool) {
        if let Err(error) = self.streams.count_attempt(tenant, stream, delivered).await {
            tracing::debug!(%error, tenant = %tenant, "could not count an SSF delivery");
        }
    }
}

#[async_trait::async_trait]
impl Deliverer for SsfPushDeliverer {
    fn family(&self) -> &'static str {
        FAMILY
    }

    async fn deliver(&self, event: &OutboxEvent) -> Result<Delivered, Undelivered> {
        // The row addresses a stream. A destination that is not one is a
        // programming error at the queueing end and will look the same on the
        // tenth attempt.
        let stream = StreamId::parse(&event.destination).ok_or_else(|| {
            Undelivered::permanent("the row's destination is not a stream identifier".to_owned())
        })?;
        let jws = event
            .payload
            .get("body")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Undelivered::permanent("the row's payload has no signed SET to push".to_owned())
            })?;

        let target = match self.streams.target(&event.tenant, &stream).await {
            Ok(Some(target)) => target,
            // §8.1.1.5: a deleted stream delivers nothing more. `PgSsfStreams::
            // delete` abandons what was queued in the same transaction, so this
            // is the narrow race where a row was already claimed — permanent,
            // because the stream is not coming back.
            Ok(None) => {
                return Err(Undelivered::permanent(
                    "the stream no longer exists, or is not a push stream".to_owned(),
                ));
            }
            // A store that cannot be read is this deployment's problem and not
            // the receiver's; the SET is still owed.
            Err(error) => return Err(Undelivered::transient(error.to_string())),
        };

        if !target.status.delivers() {
            // Queued, not delivered, for as long as the attempt budget lasts.
            // §8.1.2 makes a paused stream one that keeps its events, and this
            // is as close as an outbox with a bounded budget gets: the backlog
            // dead-letters rather than growing without limit, and the dead
            // letters name the pause.
            return Err(Undelivered::transient(format!(
                "the stream is {} and is not delivering",
                target.status.as_str()
            )));
        }

        let request = PostRequest::of(PUSH_CONTENT_TYPE)
            .accepting(PUSH_ACCEPT)
            .authorized_by(
                target
                    .authorization_header
                    .as_ref()
                    .map(asterius_ssf::push::AuthorizationHeader::expose),
            );
        let answer = self
            .poster
            .post(&target.endpoint_url, request, jws.as_bytes())
            .await;

        match answer {
            Ok(status) => {
                self.count(&event.tenant, &stream, true).await;
                self.record(
                    &event.tenant,
                    &stream,
                    EventType::SSF_SET_PUSHED,
                    Outcome::Success,
                    Detail::new()
                        .credential("stream_id", stream.as_str())
                        .number("status", i64::from(status)),
                )
                .await;
                Ok(Delivered::Sent)
            }
            Err(failure) => {
                self.count(&event.tenant, &stream, false).await;
                Err(self.refused(event, &stream, &failure).await)
            }
        }
    }
}

impl SsfPushDeliverer {
    /// What a failed `POST` means, in RFC 8935's terms.
    async fn refused(
        &self,
        event: &OutboxEvent,
        stream: &StreamId,
        failure: &PostError,
    ) -> Undelivered {
        // A failure that never reached the receiver has no status, and §2.4
        // groups it with the timeouts: retry. `PostError::is_permanent` is
        // where a body this server would not send, or a header it cannot
        // carry, becomes permanent instead.
        let Some(status) = failure.status() else {
            let detail = failure.to_string();
            if failure.is_permanent() {
                self.pause(&event.tenant, stream, &detail).await;
                return Undelivered::permanent(detail);
            }
            if event.is_final_attempt() {
                self.pause(&event.tenant, stream, &detail).await;
            }
            return Undelivered::transient(detail);
        };

        match push::disposition(status, failure.body()) {
            // Only reachable if a receiver answered 2xx and the outbound path
            // still reported a failure, which it does not; kept because the
            // alternative is a wildcard that would silently swallow a future
            // status class.
            Disposition::Delivered => Undelivered::transient(failure.to_string()),
            Disposition::Retry { status } => {
                let detail = format!("the receiver answered {status}; the SET is still owed");
                if event.is_final_attempt() {
                    self.pause(&event.tenant, stream, &detail).await;
                }
                Undelivered::transient(detail)
            }
            Disposition::Rejected(error) => {
                let mut detail = Detail::new()
                    .credential("stream_id", stream.as_str())
                    .number("status", i64::from(status))
                    // `label`, not `text`: the code is one of this build's own
                    // constants by the time it gets here, never the receiver's
                    // string.
                    .label("err", error.code.as_str())
                    // The one code that points at this server's published keys
                    // rather than at the SET (§2.3). Nothing is refreshed on a
                    // receiver's say-so — that would be a denial of service by
                    // 400 — but an operator is told where to look.
                    .flag("jwks_refresh_hint", error.code.suggests_key_refresh());
                if let Some(description) = &error.description {
                    detail = detail.text("description", description);
                }
                self.record(
                    &event.tenant,
                    stream,
                    EventType::SSF_PUSH_REFUSED,
                    Outcome::Failure,
                    detail,
                )
                .await;
                if error.code.suggests_key_refresh() {
                    tracing::warn!(
                        tenant = %event.tenant,
                        stream = %stream.as_str(),
                        "a receiver could not use this transmitter's signing key; \
                         check the published JWK set"
                    );
                }
                // §2.4: a 4xx other than 429 and 503 is not retried. The stream
                // is paused with it — a receiver that refuses one SET as
                // malformed, or refuses the credential, will refuse the next
                // one for the same reason, and a hundred dead letters say no
                // more than the first.
                let reason = error.detail();
                self.pause(&event.tenant, stream, &reason).await;
                Undelivered::permanent(reason)
            }
        }
    }
}

/// The outbox `kind` a pushed SET is written under, re-exported for the
/// emitters that will queue them (`ast-0ju.8`).
pub const KIND: &str = SET_OUTBOX_KIND;

/// The queues an SSF emitter puts a signed SET on, over `PostgreSQL`
/// (`ast-0ju.8`).
///
/// The production [`crate::ssf::SsfQueues`]: it reads the subscribed streams
/// through [`asterius_store_pg::PgSsfStreams::subscribed`], holds the poll
/// SETs of one cause in one transaction ([`asterius_store_pg::PgSsfPoll`]),
/// and hands the push SETs to the same outbox the push deliverer above reads.
#[derive(Clone)]
pub struct PgSsfQueues {
    store: Store,
    tenant: TenantId,
    kek: Arc<dyn Kek>,
}

impl std::fmt::Debug for PgSsfQueues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgSsfQueues")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgSsfQueues {
    /// Scopes the queues to one tenant.
    ///
    /// `kek` opens a push stream's sealed credential when the delivery worker
    /// reads it; it is not used on the way *in*, but the streams repository
    /// asks for it, so it is held here rather than reconstructed per call.
    #[must_use]
    pub const fn new(store: Store, tenant: TenantId, kek: Arc<dyn Kek>) -> Self {
        Self { store, tenant, kek }
    }
}

#[async_trait::async_trait]
impl crate::ssf::SsfQueues for PgSsfQueues {
    async fn subscribed(
        &self,
        event: &str,
    ) -> Result<Vec<asterius_store_pg::Subscription>, DomainError> {
        self.store
            .scope(self.tenant.clone())
            .ssf_streams(Arc::clone(&self.kek))
            .subscribed(event)
            .await
    }

    async fn queue_poll(
        &self,
        sets: &[crate::ssf::PolledSet<'_>],
        now: time::OffsetDateTime,
    ) -> Result<(), DomainError> {
        use asterius_store_pg::to_domain_error;
        let poll = self.store.scope(self.tenant.clone()).ssf_poll();
        let mut transaction = self.store.pool().begin().await.map_err(to_domain_error)?;
        for set in sets {
            poll.enqueue(&mut transaction, set.stream, set.jti, set.jws, now)
                .await?;
        }
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(())
    }

    async fn queue_push(
        &self,
        events: &[QueuedEvent],
        now: time::OffsetDateTime,
    ) -> Result<(), DomainError> {
        use asterius_domain::outbox::OutboxQueue as _;
        asterius_store_pg::PgOutbox::new(self.store.pool().clone())
            .queue(&self.tenant, events, now)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_ssf::push::AuthorizationHeader;
    use asterius_ssf::stream::StreamStatus;
    use std::sync::Mutex;
    use time::OffsetDateTime;

    const JWS: &str = "eyJ0eXAiOiJzZWNldmVudCtqd3QifQ.e30.sig";

    /// What a receiver is told to answer: a status, or a status with a body.
    type Answer = Result<u16, (u16, Vec<u8>)>;

    /// One request the fake receiver was sent.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Sent {
        url: String,
        content_type: String,
        accept: Option<String>,
        authorization: Option<String>,
        body: Vec<u8>,
    }

    /// A receiver that answers what the test tells it to, and remembers what
    /// it was asked for.
    #[derive(Debug, Default)]
    struct FakeReceiver {
        answers: Mutex<Vec<Answer>>,
        seen: Mutex<Vec<Sent>>,
    }

    impl FakeReceiver {
        fn answering(answers: Vec<Answer>) -> Arc<Self> {
            Arc::new(Self {
                answers: Mutex::new(answers),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn requests(&self) -> Vec<Sent> {
            self.seen.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait::async_trait]
    impl SetPoster for FakeReceiver {
        async fn post(
            &self,
            url: &str,
            request: PostRequest<'_>,
            body: &[u8],
        ) -> Result<u16, PostError> {
            self.seen.lock().expect("not poisoned").push(Sent {
                url: url.to_owned(),
                content_type: request.content_type.to_owned(),
                accept: request.accept.map(str::to_owned),
                authorization: request.authorization.map(str::to_owned),
                body: body.to_vec(),
            });
            let answer = {
                let mut answers = self.answers.lock().expect("not poisoned");
                if answers.is_empty() {
                    Ok(202)
                } else {
                    answers.remove(0)
                }
            };
            answer.map_err(|(status, body)| PostError::Refused {
                host: "receiver.example".to_owned(),
                status,
                body,
            })
        }
    }

    /// A stream store that starts enabled and records what was done to it.
    #[derive(Debug)]
    struct FakeStreams {
        target: Mutex<Option<PushTarget>>,
        paused: Mutex<Option<String>>,
        counted: Mutex<Vec<bool>>,
        /// What this stream was told and when, in order: `"announced"` for
        /// §8.1.5's stream-updated event and `"paused"` for the write. The
        /// order is the assertion — §8.1.5 requires the first before the
        /// second.
        trail: Mutex<Vec<&'static str>>,
    }

    impl FakeStreams {
        fn holding(target: Option<PushTarget>) -> Arc<Self> {
            Arc::new(Self {
                target: Mutex::new(target),
                paused: Mutex::new(None),
                counted: Mutex::new(Vec::new()),
                trail: Mutex::new(Vec::new()),
            })
        }

        fn pushing(authorization: Option<&str>) -> Arc<Self> {
            Self::holding(Some(PushTarget {
                endpoint_url: "https://receiver.example/events".to_owned(),
                authorization_header: authorization
                    .map(|raw| AuthorizationHeader::parse(raw).expect("a field value")),
                status: StreamStatus::Enabled,
            }))
        }

        fn pause_reason(&self) -> Option<String> {
            self.paused.lock().expect("not poisoned").clone()
        }

        fn counts(&self) -> Vec<bool> {
            self.counted.lock().expect("not poisoned").clone()
        }

        fn trail(&self) -> Vec<&'static str> {
            self.trail.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait::async_trait]
    impl PushStreams for FakeStreams {
        async fn target(
            &self,
            _tenant: &TenantId,
            _stream: &StreamId,
        ) -> Result<Option<PushTarget>, DomainError> {
            Ok(self.target.lock().expect("not poisoned").clone())
        }

        async fn announce_pause(
            &self,
            _tenant: &TenantId,
            _stream: &StreamId,
            _reason: &str,
            _now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            self.trail.lock().expect("not poisoned").push("announced");
            Ok(())
        }

        async fn pause(
            &self,
            _tenant: &TenantId,
            _stream: &StreamId,
            reason: &str,
            _now: OffsetDateTime,
        ) -> Result<bool, DomainError> {
            self.trail.lock().expect("not poisoned").push("paused");
            let mut paused = self.paused.lock().expect("not poisoned");
            if paused.is_some() {
                return Ok(false);
            }
            *paused = Some(reason.to_owned());
            Ok(true)
        }

        async fn count_attempt(
            &self,
            _tenant: &TenantId,
            _stream: &StreamId,
            delivered: bool,
        ) -> Result<(), DomainError> {
            self.counted.lock().expect("not poisoned").push(delivered);
            Ok(())
        }
    }

    /// An audit sink that keeps what it was given.
    #[derive(Debug, Default)]
    struct Trail(Mutex<Vec<AuditEvent>>);

    #[async_trait::async_trait]
    impl AuditSink for Trail {
        async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
            self.0.lock().expect("not poisoned").push(event);
            Ok(())
        }
    }

    impl Trail {
        fn types(&self) -> Vec<EventType> {
            self.0
                .lock()
                .expect("not poisoned")
                .iter()
                .map(|event| event.event_type)
                .collect()
        }

        fn rendered(&self) -> String {
            format!("{:?}", self.0.lock().expect("not poisoned"))
        }
    }

    #[derive(Debug)]
    struct Fixed(OffsetDateTime);

    impl Clock for Fixed {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    fn stream() -> StreamId {
        StreamId::generate()
    }

    fn row(stream: &StreamId, attempt: u32, max_attempts: u32) -> OutboxEvent {
        OutboxEvent {
            tenant: TenantId::new("acme"),
            id: 11,
            kind: "ssf.set".to_owned(),
            destination: stream.as_str().to_owned(),
            payload: serde_json::json!({ "body": JWS }),
            attempt,
            max_attempts,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn deliverer(
        streams: Arc<dyn PushStreams>,
        receiver: Arc<FakeReceiver>,
        trail: Arc<Trail>,
    ) -> SsfPushDeliverer {
        SsfPushDeliverer::new(
            streams,
            receiver,
            trail,
            Arc::new(Fixed(OffsetDateTime::UNIX_EPOCH)),
        )
    }

    /// §2.1: the SET goes out as `application/secevent+jwt`, with an `Accept`
    /// of `application/json`, to the endpoint the stream names; SSF 1.0 §6.1.1:
    /// with the registered credential on it.
    #[tokio::test]
    async fn a_push_carries_the_media_types_the_credential_and_the_set() {
        // Arrange
        let receiver = FakeReceiver::answering(vec![Ok(202)]);
        let streams = FakeStreams::pushing(Some("Bearer receiver-token"));
        let trail = Arc::new(Trail::default());
        let stream = stream();
        let deliverer = deliverer(
            Arc::clone(&streams) as Arc<dyn PushStreams>,
            Arc::clone(&receiver),
            Arc::clone(&trail),
        );

        // Act
        let outcome = deliverer.deliver(&row(&stream, 1, 10)).await;

        // Assert
        assert_eq!(outcome, Ok(Delivered::Sent));
        let requests = receiver.requests();
        assert_eq!(requests.len(), 1, "§2.2: one SET, one request");
        let sent = &requests[0];
        assert_eq!(sent.url, "https://receiver.example/events");
        assert_eq!(sent.content_type, "application/secevent+jwt");
        assert_eq!(sent.accept.as_deref(), Some("application/json"));
        assert_eq!(sent.authorization.as_deref(), Some("Bearer receiver-token"));
        assert_eq!(sent.body, JWS.as_bytes());
        assert_eq!(streams.counts(), vec![true]);
        assert_eq!(trail.types(), vec![EventType::SSF_SET_PUSHED]);
    }

    /// A stream with no credential sends no `Authorization`, rather than an
    /// empty one: §6.1.1 obliges the transmitter to send the value it was
    /// given, and it was given none.
    #[tokio::test]
    async fn a_stream_without_a_credential_sends_no_authorization() {
        // Arrange
        let receiver = FakeReceiver::answering(vec![Ok(202)]);
        let deliverer = deliverer(
            FakeStreams::pushing(None),
            Arc::clone(&receiver),
            Arc::new(Trail::default()),
        );

        // Act
        let _ = deliverer.deliver(&row(&stream(), 1, 10)).await;

        // Assert
        assert_eq!(receiver.requests()[0].authorization, None);
    }

    /// §2.3: a 400 naming a code is recorded and not retried, and the stream
    /// stops — the next SET would be refused for the same reason.
    #[tokio::test]
    async fn a_refusal_is_recorded_not_retried_and_pauses_the_stream() {
        // Arrange
        let receiver = FakeReceiver::answering(vec![Err((
            400,
            br#"{"err":"invalid_audience","description":"not my aud"}"#.to_vec(),
        ))]);
        let streams = FakeStreams::pushing(None);
        let trail = Arc::new(Trail::default());
        let deliverer = deliverer(
            Arc::clone(&streams) as Arc<dyn PushStreams>,
            receiver,
            Arc::clone(&trail),
        );

        // Act
        let refused = deliverer
            .deliver(&row(&stream(), 1, 10))
            .await
            .expect_err("a 400 is not a delivery");

        // Assert
        assert!(
            refused.permanent,
            "§2.4: a 4xx other than 429 is not retried"
        );
        assert!(refused.detail.contains("invalid_audience"), "{refused:?}");
        assert!(
            streams.pause_reason().is_some(),
            "the stream kept delivering"
        );
        assert!(trail.types().contains(&EventType::SSF_PUSH_REFUSED));
        assert_eq!(streams.counts(), vec![false]);
    }

    /// §2.3's `invalid_key` is the one refusal that points at this server's
    /// published keys, and the trail says so. Nothing is refreshed on a
    /// receiver's say-so.
    #[tokio::test]
    async fn an_invalid_key_refusal_records_a_key_refresh_hint() {
        // Arrange
        let receiver =
            FakeReceiver::answering(vec![Err((400, br#"{"err":"invalid_key"}"#.to_vec()))]);
        let trail = Arc::new(Trail::default());
        let deliverer = deliverer(FakeStreams::pushing(None), receiver, Arc::clone(&trail));

        // Act
        let _ = deliverer.deliver(&row(&stream(), 1, 10)).await;

        // Assert
        let rendered = trail.rendered();
        assert!(rendered.contains("jwks_refresh_hint"), "{rendered}");
        assert!(rendered.contains("invalid_key"), "{rendered}");
    }

    /// §2.4: 429, 503 and 5xx are retried, and a retry does not pause the
    /// stream while the row still has attempts left.
    #[tokio::test]
    async fn a_throttled_or_unavailable_receiver_is_retried() {
        for status in [429_u16, 500, 503] {
            // Arrange
            let receiver = FakeReceiver::answering(vec![Err((status, Vec::new()))]);
            let streams = FakeStreams::pushing(None);
            let deliverer = deliverer(
                Arc::clone(&streams) as Arc<dyn PushStreams>,
                receiver,
                Arc::new(Trail::default()),
            );

            // Act
            let failed = deliverer
                .deliver(&row(&stream(), 1, 10))
                .await
                .expect_err("the receiver did not take it");

            // Assert
            assert!(!failed.permanent, "{status} was not retried");
            assert_eq!(
                streams.pause_reason(),
                None,
                "{status} paused a stream that still had attempts left"
            );
        }
    }

    /// The last attempt of a transient failure is where the budget runs out,
    /// and where §8.1.2's pause has to happen: the SET dead-letters either
    /// way, and without this the next hundred would too.
    #[tokio::test]
    async fn the_last_retry_of_a_failing_receiver_pauses_the_stream() {
        // Arrange
        let receiver = FakeReceiver::answering(vec![Err((503, Vec::new()))]);
        let streams = FakeStreams::pushing(None);
        let trail = Arc::new(Trail::default());
        let deliverer = deliverer(
            Arc::clone(&streams) as Arc<dyn PushStreams>,
            receiver,
            Arc::clone(&trail),
        );

        // Act
        let failed = deliverer
            .deliver(&row(&stream(), 10, 10))
            .await
            .expect_err("the receiver did not take it");

        // Assert
        assert!(
            !failed.permanent,
            "the last attempt is still a retry verdict"
        );
        assert!(streams.pause_reason().is_some());
        assert!(trail.types().contains(&EventType::SSF_STREAM_PAUSED));
    }

    /// **SSF 1.0 §8.1.5**: the receiver is told *before* the stream stops.
    ///
    /// > The Transmitter MUST send this event to the Receiver before the
    /// > stream is paused or disabled.
    ///
    /// Announced first, the SET is queued while the stream still takes
    /// events; announced after the write, it would be queued into a stream
    /// that is already holding everything.
    #[tokio::test]
    async fn a_transmitter_initiated_pause_announces_itself_before_it_takes_effect() {
        // Arrange
        let receiver = FakeReceiver::answering(vec![Err((503, Vec::new()))]);
        let streams = FakeStreams::pushing(None);
        let deliverer = deliverer(
            Arc::clone(&streams) as Arc<dyn PushStreams>,
            receiver,
            Arc::new(Trail::default()),
        );

        // Act
        let _ = deliverer.deliver(&row(&stream(), 10, 10)).await;

        // Assert
        assert_eq!(streams.trail(), vec!["announced", "paused"]);
    }

    /// A receiver that cannot be told is usually *why* the stream is being
    /// paused, so a failed announcement must not leave it delivering.
    #[tokio::test]
    async fn a_pause_that_cannot_be_announced_still_pauses_the_stream() {
        // Arrange
        #[derive(Debug)]
        struct Mute(Arc<FakeStreams>);

        #[async_trait::async_trait]
        impl PushStreams for Mute {
            async fn target(
                &self,
                tenant: &TenantId,
                stream: &StreamId,
            ) -> Result<Option<PushTarget>, DomainError> {
                self.0.target(tenant, stream).await
            }

            async fn announce_pause(
                &self,
                _tenant: &TenantId,
                _stream: &StreamId,
                _reason: &str,
                _now: OffsetDateTime,
            ) -> Result<(), DomainError> {
                Err(DomainError::invalid("ssf.set", "the receiver is gone"))
            }

            async fn pause(
                &self,
                tenant: &TenantId,
                stream: &StreamId,
                reason: &str,
                now: OffsetDateTime,
            ) -> Result<bool, DomainError> {
                self.0.pause(tenant, stream, reason, now).await
            }

            async fn count_attempt(
                &self,
                tenant: &TenantId,
                stream: &StreamId,
                delivered: bool,
            ) -> Result<(), DomainError> {
                self.0.count_attempt(tenant, stream, delivered).await
            }
        }

        let inner = FakeStreams::pushing(None);
        let deliverer = deliverer(
            Arc::new(Mute(Arc::clone(&inner))),
            FakeReceiver::answering(vec![Err((503, Vec::new()))]),
            Arc::new(Trail::default()),
        );

        // Act
        let _ = deliverer.deliver(&row(&stream(), 10, 10)).await;

        // Assert
        assert!(inner.pause_reason().is_some());
    }

    /// §8.1.1.5: a stream that is gone is not delivered to, and the SET is not
    /// retried into a stream that is not coming back.
    #[tokio::test]
    async fn a_deleted_stream_is_a_permanent_failure() {
        // Arrange
        let deliverer = deliverer(
            FakeStreams::holding(None) as Arc<dyn PushStreams>,
            FakeReceiver::answering(Vec::new()),
            Arc::new(Trail::default()),
        );

        // Act
        let refused = deliverer
            .deliver(&row(&stream(), 1, 10))
            .await
            .expect_err("a deleted stream takes nothing");

        // Assert
        assert!(refused.permanent);
    }

    /// §8.1.2: a paused stream keeps its events rather than delivering them,
    /// so the row is retried rather than posted anywhere.
    #[tokio::test]
    async fn a_paused_stream_is_not_posted_to() {
        // Arrange
        let receiver = FakeReceiver::answering(Vec::new());
        let streams = FakeStreams::holding(Some(PushTarget {
            endpoint_url: "https://receiver.example/events".to_owned(),
            authorization_header: None,
            status: StreamStatus::Paused,
        }));
        let deliverer = deliverer(streams, Arc::clone(&receiver), Arc::new(Trail::default()));

        // Act
        let held = deliverer
            .deliver(&row(&stream(), 1, 10))
            .await
            .expect_err("a paused stream delivers nothing");

        // Assert
        assert!(!held.permanent);
        assert!(
            receiver.requests().is_empty(),
            "a paused stream was posted to"
        );
    }

    /// A row whose destination is not a stream identifier, or which carries no
    /// SET, cannot be delivered by any number of retries.
    #[tokio::test]
    async fn a_malformed_row_is_a_permanent_failure() {
        // Arrange
        let deliverer = deliverer(
            FakeStreams::pushing(None),
            FakeReceiver::answering(Vec::new()),
            Arc::new(Trail::default()),
        );
        let stream = stream();
        let mut no_body = row(&stream, 1, 10);
        no_body.payload = serde_json::json!({});
        let mut no_stream = row(&stream, 1, 10);
        no_stream.destination = "https://receiver.example/events".to_owned();

        // Act
        let without_body = deliverer.deliver(&no_body).await.expect_err("no SET");
        let without_stream = deliverer.deliver(&no_stream).await.expect_err("no stream");

        // Assert
        assert!(without_body.permanent);
        assert!(without_stream.permanent);
    }

    /// A store that cannot be read is this deployment's problem, not the
    /// receiver's: the SET is still owed and must not dead-letter over it.
    #[tokio::test]
    async fn a_store_failure_is_transient() {
        // Arrange
        #[derive(Debug)]
        struct Broken;

        #[async_trait::async_trait]
        impl PushStreams for Broken {
            async fn target(
                &self,
                _tenant: &TenantId,
                _stream: &StreamId,
            ) -> Result<Option<PushTarget>, DomainError> {
                Err(DomainError::invalid("ssf_streams", "the store is down"))
            }

            async fn announce_pause(
                &self,
                _tenant: &TenantId,
                _stream: &StreamId,
                _reason: &str,
                _now: OffsetDateTime,
            ) -> Result<(), DomainError> {
                Err(DomainError::invalid("ssf_streams", "the store is down"))
            }

            async fn pause(
                &self,
                _tenant: &TenantId,
                _stream: &StreamId,
                _reason: &str,
                _now: OffsetDateTime,
            ) -> Result<bool, DomainError> {
                Ok(false)
            }

            async fn count_attempt(
                &self,
                _tenant: &TenantId,
                _stream: &StreamId,
                _delivered: bool,
            ) -> Result<(), DomainError> {
                Ok(())
            }
        }

        let deliverer = SsfPushDeliverer::new(
            Arc::new(Broken),
            FakeReceiver::answering(Vec::new()),
            Arc::new(Trail::default()),
            Arc::new(Fixed(OffsetDateTime::UNIX_EPOCH)),
        );

        // Act
        let failed = deliverer
            .deliver(&row(&stream(), 1, 10))
            .await
            .expect_err("the store could not be read");

        // Assert
        assert!(!failed.permanent);
    }

    /// Order is kept per subject, not per stream: two events about one person
    /// share an ordering key — which is what the claim query serialises on,
    /// retries included — and two events about different people do not, so one
    /// slow subject does not hold up the rest.
    #[test]
    fn two_events_about_one_subject_share_an_ordering_key() {
        // Arrange
        let stream = stream();

        // Act
        let first = push_event(&stream, "u-1", JWS);
        let second = push_event(&stream, "u-1", "other.set.jws");
        let elsewhere = push_event(&stream, "u-2", JWS);

        // Assert
        assert_eq!(first.ordering_key, second.ordering_key);
        assert_ne!(first.ordering_key, elsewhere.ordering_key);
        assert_eq!(first.kind, "ssf.set");
        assert_eq!(first.destination, stream.as_str());
    }

    /// The family is what the worker dispatches on, and `ssf.set` has to reach
    /// this deliverer rather than dead-lettering as an unregistered family.
    #[test]
    fn the_family_matches_the_kind_a_queued_set_carries() {
        // Arrange
        let queued = push_event(&stream(), "u-1", JWS);
        let row = OutboxEvent {
            tenant: TenantId::new("acme"),
            id: 1,
            kind: queued.kind.clone(),
            destination: queued.destination,
            payload: queued.payload,
            attempt: 1,
            max_attempts: 10,
            created_at: OffsetDateTime::UNIX_EPOCH,
        };

        // Act / Assert
        assert_eq!(row.family(), FAMILY);
        assert_eq!(queued.kind, KIND);
    }

    /// A credential never renders itself, wherever it is written: the
    /// deliverer and its target are both `Debug`.
    #[test]
    fn nothing_here_renders_the_receivers_credential() {
        // Arrange
        let streams = FakeStreams::pushing(Some("Bearer secret-value"));
        let deliverer = deliverer(
            Arc::clone(&streams) as Arc<dyn PushStreams>,
            FakeReceiver::answering(Vec::new()),
            Arc::new(Trail::default()),
        );

        // Act
        let rendered = format!("{deliverer:?} {:?}", streams.target);

        // Assert
        assert!(!rendered.contains("secret-value"), "{rendered}");
    }
}
