//! Emitting CAEP and RISC Security Event Tokens (`ast-0ju.8`).
//!
//! A domain event this server already records in its audit trail — a session
//! revoked, a passkey added, an account disabled — is also, for the receivers
//! that asked, a signal. This module is what turns the first into the second:
//! it reads the streams that subscribed to the event type
//! ([`asterius_store_pg::PgSsfStreams::subscribed`]), builds one SET per
//! stream through [`asterius_ssf`], signs each with the tenant's key, and puts
//! it on the queue the stream's delivery method uses — the poll table
//! (`ast-0ju.7`) or the outbox (`ast-0ju.6`).
//!
//! # What this does *not* filter yet: the stream's subjects (§8.1.3)
//!
//! [`asterius_store_pg::PgSsfStreams::subscribed`] answers "which streams
//! asked for this event *type*", and that is the whole filter today. SSF 1.0
//! §8.1.3 has a second one: a stream carries events about the subjects its
//! receiver added, and this transmitter advertises `default_subjects: NONE`
//! (§7.1), so strictly a stream with no membership should receive nothing.
//! The membership and the matching rules exist — `ssf_stream_subjects` and
//! [`asterius_ssf::Subject::matches`] (`ast-0ju.4`) — and nothing here calls
//! them, so a subscribed stream is over-delivered rather than under-delivered.
//!
//! Joining the two is deliberately not done in passing: the subject a cause
//! renders is *complex* for a session event (`user` and `session`), a receiver
//! that added the plain `iss_sub` would stop matching under §8.1.3.1's literal
//! reading, and "a receiver silently stops being told things" is the failure
//! this whole subsystem exists to avoid. It needs its own story, with tests
//! over the subject shapes a [`Cause`] actually renders.
//!
//! # Why a transmitter and not a call at each site
//!
//! The five effects that map to events happen in five places, and each of
//! them already does the hard part — revoking the session, disabling the
//! account. What they must not each re-derive is the part where a mistake is a
//! security bug: the `sub` a *receiver* knows a user by (OIDC Core §8.1 — a
//! pairwise receiver must never be handed the local id or another sector's
//! subject), the one `txn` shared by every SET of one cause (SSF 1.0 §4.1.9),
//! and the rule that a SET carries `sub_id` whatever its event body says (SSF
//! 1.0 §3.1). [`SsfTransmitter`] is the one place that gets those right, and
//! [`Cause`] is the vocabulary a call site uses to say what happened without
//! knowing any of it.
//!
//! # What is shared and what is not
//!
//! **One `txn` per cause.** [`Txn::generate`] is called once, in
//! [`SsfTransmitter::emit`], and handed to every SET. A receiver correlating
//! this server's signals — or two receivers comparing notes — sees the SETs of
//! one sign-out as one transaction.
//!
//! **One database transaction per cause, per queue.** The poll SETs of one
//! cause are enqueued in a single transaction, so a stream's backlog never
//! gains half a cause; the push SETs go through
//! [`asterius_domain::outbox::OutboxQueue::queue`], which is all-or-nothing by
//! its own contract. The SET is *not* in the same transaction as the effect it
//! reports, for the reason [`crate::backchannel`] gives for a logout token:
//! revoking a session is the session repository's statement, and a crash
//! between the two under-notifies rather than announcing something that did
//! not happen.
//!
//! # What may be logged
//!
//! The tenant, the event type, how many streams were told. Never a `sub_id` —
//! it is a subject identifier and personal data — and never the SET.

use asterius_domain::keys::Signer;
use asterius_domain::outbox::QueuedEvent;
use asterius_domain::ports::SubjectResolver;
use asterius_domain::{
    ClientId, ClientRepository, DomainError, Issuer, SectorIdentifier, TenantId, UserId,
};
use asterius_ssf::caep::{self, EventDetails};
use asterius_ssf::stream_updated::stream_updated_event;
use asterius_ssf::verification::{VerificationState, verification_event};
use asterius_ssf::{
    ComplexSubject, SecurityEvent, Set, SimpleSubject, StreamAudience, Subject, Txn,
};
use asterius_store_pg::{DeliveryMethod, Subscription};
use time::OffsetDateTime;

/// The queues an emitted SET is put on.
///
/// A port so the transmitter's decisions — which stream, which queue, one
/// `txn` — can be tested without a database, the same reason
/// [`asterius_domain::outbox::OutboxQueue`] is one. The production
/// implementation is [`crate::outbox::PgSsfQueues`].
#[async_trait::async_trait]
pub trait SsfQueues: std::fmt::Debug + Send + Sync {
    /// The streams that subscribed to `event`, across every receiver
    /// (`PgSsfStreams::subscribed`).
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the streams cannot be read.
    async fn subscribed(&self, event: &str) -> Result<Vec<Subscription>, DomainError>;

    /// Queues every poll SET of one cause, in one transaction.
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the transaction fails; nothing was queued.
    async fn queue_poll(
        &self,
        sets: &[PolledSet<'_>],
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Queues every push SET of one cause, all or nothing
    /// ([`OutboxQueue::queue`](asterius_domain::outbox::OutboxQueue::queue)).
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the rows cannot be written; none were.
    async fn queue_push(
        &self,
        events: &[QueuedEvent],
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;
}

/// One SET bound for the poll queue.
#[derive(Debug, Clone, Copy)]
pub struct PolledSet<'a> {
    /// The stream that holds it.
    pub stream: &'a asterius_ssf::stream::StreamId,
    /// RFC 8417 §2's `jti`, the poll response's member name.
    pub jti: &'a str,
    /// The compact serialisation.
    pub jws: &'a str,
}

/// What happened, in terms a call site can state without knowing SSF.
///
/// Each variant carries the data the matching CAEP or RISC event needs and
/// nothing the transmitter can derive itself: the transmitter adds the
/// `event_timestamp`, the per-receiver `sub_id` and the shared `txn`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Cause {
    /// CAEP §3.1: a session was revoked. `sid` is the session's public
    /// identifier, the `sid` a receiver saw in its ID token.
    SessionRevoked {
        /// The person whose session ended.
        user: UserId,
        /// The public session identifier.
        sid: String,
        /// Who or what revoked it.
        initiator: caep::InitiatingEntity,
    },
    /// CAEP §3.3: a credential changed.
    CredentialChange {
        /// The person the credential belongs to.
        user: UserId,
        /// The event, already carrying its `credential_type` and
        /// `change_type` — the call site knows which credential moved.
        change: caep::CredentialChange,
        /// Who or what changed it.
        initiator: caep::InitiatingEntity,
    },
    /// CAEP §3.4: a session's assurance level changed.
    AssuranceLevelChange {
        /// The person whose session it is.
        user: UserId,
        /// The session, named by its public identifier.
        sid: String,
        /// The change, with the namespace and the two levels.
        change: caep::AssuranceLevelChange,
        /// Who or what caused it.
        initiator: caep::InitiatingEntity,
    },
    /// RISC `account-disabled`.
    AccountDisabled {
        /// The person whose account was disabled.
        user: UserId,
        /// RISC's `reason`, where there is one.
        reason: Option<caep::DisabledReason>,
        /// Who disabled it.
        initiator: caep::InitiatingEntity,
    },
    /// RISC `account-enabled`.
    AccountEnabled {
        /// The person whose account was enabled.
        user: UserId,
        /// Who enabled it.
        initiator: caep::InitiatingEntity,
    },
}

impl Cause {
    /// The event type URI this cause maps to, which is also what a stream must
    /// have in `events_requested` to hear about it.
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::SessionRevoked { .. } => caep::SESSION_REVOKED,
            Self::CredentialChange { .. } => caep::CREDENTIAL_CHANGE,
            Self::AssuranceLevelChange { .. } => caep::ASSURANCE_LEVEL_CHANGE,
            Self::AccountDisabled { .. } => caep::ACCOUNT_DISABLED,
            Self::AccountEnabled { .. } => caep::ACCOUNT_ENABLED,
        }
    }

    /// The subject of every effect is one person.
    const fn user(&self) -> UserId {
        match self {
            Self::SessionRevoked { user, .. }
            | Self::CredentialChange { user, .. }
            | Self::AssuranceLevelChange { user, .. }
            | Self::AccountDisabled { user, .. }
            | Self::AccountEnabled { user, .. } => *user,
        }
    }

    fn details(&self, now: OffsetDateTime) -> EventDetails {
        let initiator = match self {
            Self::SessionRevoked { initiator, .. }
            | Self::CredentialChange { initiator, .. }
            | Self::AssuranceLevelChange { initiator, .. }
            | Self::AccountDisabled { initiator, .. }
            | Self::AccountEnabled { initiator, .. } => *initiator,
        };
        EventDetails::at(now).initiated_by(initiator)
    }

    /// The event body, and the `sub_id` a receiver at `receiver_sub` is told.
    ///
    /// `receiver_sub` is the `sub` this receiver already knows the user by,
    /// derived under its sector — never the local id and never another
    /// sector's subject (§8.1). The `session` member of a complex subject is
    /// an `opaque` sid, which is what a receiver stores when it learns of a
    /// session; it is not a `sub`, so it is not derived.
    fn render(&self, issuer: &Issuer, receiver_sub: &str, now: OffsetDateTime) -> Rendered {
        let details = self.details(now);
        // Infallible by construction: `receiver_sub` is a subject this server
        // minted (43 base64url characters) and the sid is a stored, non-empty
        // identifier. A malformed one is a bug here, not a receiver's input,
        // so it fails loudly rather than emitting a half subject.
        let user = SimpleSubject::iss_sub(issuer, receiver_sub)
            .expect("a subject this server minted is within the member bound");
        match self {
            Self::SessionRevoked { sid, .. } => {
                let session = SimpleSubject::opaque(sid)
                    .expect("a stored session identifier is non-empty and bounded");
                Rendered {
                    subject: ComplexSubject::of_user(user).with_session(session).into(),
                    event: caep::session_revoked(&details),
                }
            }
            Self::CredentialChange { change, .. } => Rendered {
                subject: user.into(),
                event: change.clone().into_event(&details),
            },
            Self::AssuranceLevelChange { sid, change, .. } => {
                let session = SimpleSubject::opaque(sid)
                    .expect("a stored session identifier is non-empty and bounded");
                Rendered {
                    subject: ComplexSubject::of_user(user).with_session(session).into(),
                    event: change.clone().into_event(&details),
                }
            }
            Self::AccountDisabled { reason, .. } => Rendered {
                subject: user.into(),
                event: caep::account_disabled(&details, *reason),
            },
            Self::AccountEnabled { .. } => Rendered {
                subject: user.into(),
                event: caep::account_enabled(&details),
            },
        }
    }
}

/// A rendered event and the subject it is about.
struct Rendered {
    subject: Subject,
    event: SecurityEvent,
}

/// The transmitter: turns a [`Cause`] into signed SETs on the right queues.
///
/// It reaches no database of its own — the queues and the stream list come
/// through [`SsfQueues`], the subject through [`SubjectResolver`], and the
/// receiver's sector through [`ClientRepository`], exactly the ports
/// [`crate::backchannel::Notifier`] uses. That is what lets its one
/// security-critical decision — the per-receiver `sub` — be tested against a
/// resolver a test controls.
pub struct SsfTransmitter<'a> {
    /// The tenant these signals belong to.
    pub tenant: &'a TenantId,
    /// The tenant's issuer, which SSF 1.0 §4.1.6 makes the SET's `iss`.
    pub issuer: &'a Issuer,
    /// The streams and the queues.
    pub queues: &'a dyn SsfQueues,
    /// The receivers, for each one's sector identifier.
    pub clients: &'a dyn ClientRepository,
    /// The `sub` each receiver knows the user by (§8.1).
    pub subjects: &'a dyn SubjectResolver,
    /// The tenant's active signing key.
    pub signer: &'a dyn Signer,
}

impl std::fmt::Debug for SsfTransmitter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsfTransmitter")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl SsfTransmitter<'_> {
    /// Emits the SETs one cause produces, to every stream that subscribed.
    ///
    /// Best-effort and never fatal to the caller: a signal that could not be
    /// queued is logged, because the effect it reports has already happened
    /// and must not be rolled back for want of a receiver being told. Returns
    /// how many SETs were queued, for the caller's own trail.
    #[allow(clippy::too_many_lines)] // one cause, one linear fan-out; splitting hides the shared `txn`.
    pub async fn emit(&self, cause: &Cause, now: OffsetDateTime) -> usize {
        let event_type = cause.event_type();
        let subscriptions = match self.queues.subscribed(event_type).await {
            Ok(subscriptions) => subscriptions,
            Err(error) => {
                tracing::error!(
                    %error,
                    tenant = %self.tenant,
                    event = event_type,
                    "cannot read the streams subscribed to a security event",
                );
                return 0;
            }
        };
        if subscriptions.is_empty() {
            return 0;
        }

        // One transaction identifier for the whole cause (§4.1.9).
        let txn = Txn::generate();
        let user = cause.user();

        let mut poll = Vec::new();
        let mut push = Vec::new();
        // The compact serialisations are owned here so `PolledSet` can borrow
        // them for the single poll transaction below.
        let mut poll_backing: Vec<(asterius_ssf::stream::StreamId, String, String)> = Vec::new();

        for subscription in &subscriptions {
            let signed = match self.sign_for(cause, subscription, &txn, now).await {
                Ok(Some(signed)) => signed,
                Ok(None) => continue,
                Err(error) => {
                    tracing::error!(
                        %error,
                        tenant = %self.tenant,
                        event = event_type,
                        "cannot build a security event token for a stream",
                    );
                    continue;
                }
            };
            match subscription.delivery {
                DeliveryMethod::Poll => poll_backing.push((
                    subscription.stream_id.clone(),
                    signed.jti().as_str().to_owned(),
                    signed.jws().as_str().to_owned(),
                )),
                DeliveryMethod::Push => push.push(crate::outbox::push_event(
                    &subscription.stream_id,
                    // The ordering key's subject: the person the SET is about,
                    // so two events about one person keep their order. It is
                    // the local id and never leaves the ordering column
                    // (`crates/server/src/observability/redact.rs`).
                    &user.as_uuid().to_string(),
                    signed.jws().as_str(),
                )),
            }
        }

        for (stream, jti, jws) in &poll_backing {
            poll.push(PolledSet { stream, jti, jws });
        }

        let mut queued = 0;
        if !poll.is_empty() {
            match self.queues.queue_poll(&poll, now).await {
                Ok(()) => queued += poll.len(),
                Err(error) => tracing::error!(
                    %error,
                    tenant = %self.tenant,
                    event = event_type,
                    "cannot queue polled security event tokens",
                ),
            }
        }
        if !push.is_empty() {
            match self.queues.queue_push(&push, now).await {
                Ok(()) => queued += push.len(),
                Err(error) => tracing::error!(
                    %error,
                    tenant = %self.tenant,
                    event = event_type,
                    "cannot queue pushed security event tokens",
                ),
            }
        }
        if queued > 0 {
            tracing::info!(
                tenant = %self.tenant,
                event = event_type,
                queued,
                "security event tokens queued",
            );
        }
        queued
    }

    /// Queues SSF 1.0 §8.1.4's verification event on one stream
    /// (`ast-f7m.8`).
    ///
    /// Unlike [`Self::emit`], this is one SET for one stream and it is *not*
    /// best-effort: the operator who asked is standing there, and a
    /// verification that was silently not queued would be read as "the
    /// stream is fine". The `sub_id` is the stream itself as an `opaque`
    /// identifier, which is what §8.1.4's example carries and what makes the
    /// event about no person — no receiver sector is consulted and no
    /// subject is derived. The ordering key of a push SET is therefore the
    /// stream alone: a verification is ordered behind nothing but earlier
    /// verifications of the same stream.
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the SET cannot be built, signed or queued. Nothing
    /// was queued.
    pub async fn verify(
        &self,
        subscription: &Subscription,
        state: Option<&VerificationState>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.about_streams().verify(subscription, state, now).await
    }

    /// Queues SSF 1.0 §8.1.5's stream-updated event on one stream
    /// (`ast-0ju.5`).
    ///
    /// Delegates to [`StreamSignals::announce_status`], which is where the
    /// ordering contract is written down.
    ///
    /// # Errors
    ///
    /// As [`StreamSignals::announce_status`].
    pub async fn announce_status(
        &self,
        subscription: &Subscription,
        status: asterius_ssf::stream::StreamStatus,
        reason: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.about_streams()
            .announce_status(subscription, status, reason, now)
            .await
    }

    /// The half of this transmitter that needs no receiver and no subject.
    const fn about_streams(&self) -> StreamSignals<'_> {
        StreamSignals {
            tenant: self.tenant,
            issuer: self.issuer,
            queues: self.queues,
            signer: self.signer,
        }
    }
}

/// The two SETs that are about a *stream* rather than about a person: SSF 1.0
/// §8.1.4's verification event and §8.1.5's stream-updated event
/// (`ast-0ju.5`).
///
/// Its own type, and not merely two more methods on [`SsfTransmitter`],
/// because of what it does *not* need: no receiver registration, no sector
/// identifier, no subject resolver. Both events carry the stream as an
/// `opaque` `sub_id`, so there is no person to derive an identifier for — and
/// a caller that only has to announce a pause (the delivery worker) should
/// not have to assemble the machinery for deriving pairwise subjects in order
/// to do it.
///
/// Neither event consults `events_requested` or the stream's subject
/// membership. §8.1.4 is the answer to a question the receiver just asked, and
/// §8.1.5 is news about the receiver's own stream; a filter on either would be
/// a receiver that can silently unsubscribe from being told that it is no
/// longer being told anything.
pub struct StreamSignals<'a> {
    /// The tenant these signals belong to.
    pub tenant: &'a TenantId,
    /// The tenant's issuer, which SSF 1.0 §4.1.6 makes the SET's `iss`.
    pub issuer: &'a Issuer,
    /// The queues a SET is put on.
    pub queues: &'a dyn SsfQueues,
    /// The tenant's active signing key.
    pub signer: &'a dyn Signer,
}

impl std::fmt::Debug for StreamSignals<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamSignals")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl StreamSignals<'_> {
    /// Queues SSF 1.0 §8.1.4's verification event on one stream.
    ///
    /// Not best-effort: whoever asked — a receiver at §8.1.4.2's endpoint, or
    /// an operator in the console — is waiting for an answer, and a
    /// verification that was silently not queued would be read as "the stream
    /// is fine".
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the SET cannot be built, signed or queued. Nothing
    /// was queued.
    pub async fn verify(
        &self,
        subscription: &Subscription,
        state: Option<&VerificationState>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.queue_about_the_stream(subscription, verification_event(state), now)
            .await?;
        tracing::info!(
            tenant = %self.tenant,
            stream = subscription.stream_id.as_str(),
            "a verification event was queued",
        );
        Ok(())
    }

    /// Queues SSF 1.0 §8.1.5's stream-updated event on one stream.
    ///
    /// > The Transmitter MUST send this event to the Receiver before the
    /// > stream is paused or disabled, and upon the stream being re-enabled.
    ///
    /// Hence the contract: this is **not** best-effort and the caller is
    /// expected to run it *before* it writes the new status, so that the SET
    /// is enqueued while the stream still accepts events. A transmitter that
    /// paused first and announced afterwards would be announcing a pause over
    /// a stream that, by then, is holding or dropping what it is handed —
    /// which is exactly the order §8.1.5 forbids.
    ///
    /// Like the verification event, it ignores `events_requested` and the
    /// stream's subject membership: the `sub_id` is the stream itself as an
    /// `opaque` identifier, so the event is about no person, and a receiver
    /// cannot subscribe or unsubscribe from news about its own stream.
    ///
    /// # Errors
    ///
    /// [`DomainError`] if the SET cannot be built, signed or queued. Nothing
    /// was queued, and the caller must decide whether the status change is
    /// still worth making — [`crate::admin`] and the delivery worker both do,
    /// because a stream nobody can be told about is still a stream that has
    /// to stop.
    pub async fn announce_status(
        &self,
        subscription: &Subscription,
        status: asterius_ssf::stream::StreamStatus,
        reason: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.queue_about_the_stream(subscription, stream_updated_event(status, reason), now)
            .await?;
        tracing::info!(
            tenant = %self.tenant,
            stream = subscription.stream_id.as_str(),
            status = status.as_str(),
            "a stream-updated event was queued",
        );
        Ok(())
    }

    /// Signs one event *about a stream* and puts it on that stream's queue.
    ///
    /// The two events of §8.1.4 and §8.1.5 share every decision here: one SET
    /// for one stream, no `txn` — there is no wider cause to correlate with —
    /// and a `sub_id` that is the stream as an `opaque` identifier, which is
    /// what both sections' examples carry and what makes the event about no
    /// person. No receiver sector is consulted and no subject is derived. The
    /// ordering key of a push SET is therefore the stream alone: one of these
    /// is ordered behind nothing but earlier events about the same stream.
    async fn queue_about_the_stream(
        &self,
        subscription: &Subscription,
        event: SecurityEvent,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let stream = subscription.stream_id.as_str();
        let subject = SimpleSubject::opaque(stream)
            .map_err(|error| DomainError::invalid("ssf.stream.sub_id", error.to_string()))?;
        let audience = StreamAudience::new(subscription.audience.iter().map(String::as_str))
            .map_err(|_| {
                DomainError::invalid(
                    "ssf_streams.audience",
                    "a stored stream audience is empty or over the bound",
                )
            })?;
        let signed = Set::about(subject)
            .reporting(event)
            .issue(self.issuer, &audience, now)
            .map_err(|error| DomainError::invalid("ssf.set", error.to_string()))?
            .sign(self.signer, self.tenant)
            .await
            .map_err(|error| DomainError::invalid("ssf.set", error.to_string()))?;

        match subscription.delivery {
            DeliveryMethod::Poll => {
                let polled = PolledSet {
                    stream: &subscription.stream_id,
                    jti: signed.jti().as_str(),
                    jws: signed.jws().as_str(),
                };
                self.queues.queue_poll(&[polled], now).await?;
            }
            DeliveryMethod::Push => {
                let event = crate::outbox::push_event(
                    &subscription.stream_id,
                    stream,
                    signed.jws().as_str(),
                );
                self.queues.queue_push(&[event], now).await?;
            }
        }
        Ok(())
    }
}

impl SsfTransmitter<'_> {
    /// Builds and signs the SET for one subscription, or `None` if the
    /// receiver's registration has gone.
    async fn sign_for(
        &self,
        cause: &Cause,
        subscription: &Subscription,
        txn: &Txn,
        now: OffsetDateTime,
    ) -> Result<Option<asterius_ssf::SignedSet>, DomainError> {
        let sector = self.sector(&subscription.receiver).await?;
        let Some(sector) = sector else {
            return Ok(None);
        };
        let sub = self.subjects.subject(cause.user(), &sector).await?;
        let rendered = cause.render(self.issuer, sub.as_str(), now);
        let audience = StreamAudience::new(subscription.audience.iter().map(String::as_str))
            .map_err(|_| {
                DomainError::invalid(
                    "ssf_streams.audience",
                    "a stored stream audience is empty or over the bound",
                )
            })?;
        let unsigned = Set::about(rendered.subject)
            .reporting(rendered.event)
            .caused_by(txn.clone())
            .issue(self.issuer, &audience, now)
            .map_err(|error| DomainError::invalid("ssf.set", error.to_string()))?;
        let signed = unsigned
            .sign(self.signer, self.tenant)
            .await
            .map_err(|error| DomainError::invalid("ssf.set", error.to_string()))?;
        Ok(Some(signed))
    }

    /// The receiver's sector identifier, or `None` if it is no longer
    /// registered.
    async fn sector(&self, receiver: &ClientId) -> Result<Option<SectorIdentifier>, DomainError> {
        let Some(client) = self.clients.find(receiver).await? else {
            // A stream whose receiver has been deleted: nothing to derive a
            // subject under, and the stream's `on delete cascade` will remove
            // it. Skip rather than fail the whole cause.
            return Ok(None);
        };
        SectorIdentifier::of_client(&client).map(Some).map_err(|_| {
            DomainError::invalid(
                "client.sector_identifier",
                "a receiver's sector identifier cannot be derived",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{Client, SubjectId};
    use asterius_jose::LocalKeyStore;
    use serde_json::Value;
    use std::sync::Mutex;

    const ISSUER: &str = "https://as.example/t/demo";
    const POLL_STREAM: &str = "stream-poll-000000000000000000000000";
    const PUSH_STREAM: &str = "stream-push-000000000000000000000000";

    fn tenant() -> TenantId {
        TenantId::new("demo")
    }

    fn issuer() -> Issuer {
        Issuer::parse(ISSUER).expect("an issuer")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("a time")
    }

    fn user() -> UserId {
        UserId::new(uuid::Uuid::from_u128(1))
    }

    fn stream_id(raw: &str) -> asterius_ssf::stream::StreamId {
        asterius_ssf::stream::StreamId::parse(raw).expect("a stream id")
    }

    /// A stream source and a pair of queues that remember what they were
    /// handed.
    #[derive(Debug, Default)]
    struct FakeQueues {
        subscriptions: Vec<Subscription>,
        polled: Mutex<Vec<(String, String, String)>>,
        pushed: Mutex<Vec<QueuedEvent>>,
        /// Every event type the stream list was asked about, so a test can
        /// assert that a SET about a *stream* never asks (§8.1.4, §8.1.5).
        asked: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl SsfQueues for FakeQueues {
        async fn subscribed(&self, event: &str) -> Result<Vec<Subscription>, DomainError> {
            self.asked
                .lock()
                .expect("not poisoned")
                .push(event.to_owned());
            Ok(self.subscriptions.clone())
        }

        async fn queue_poll(
            &self,
            sets: &[PolledSet<'_>],
            _now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            let mut polled = self.polled.lock().expect("not poisoned");
            for set in sets {
                polled.push((
                    set.stream.as_str().to_owned(),
                    set.jti.to_owned(),
                    set.jws.to_owned(),
                ));
            }
            Ok(())
        }

        async fn queue_push(
            &self,
            events: &[QueuedEvent],
            _now: OffsetDateTime,
        ) -> Result<(), DomainError> {
            self.pushed
                .lock()
                .expect("not poisoned")
                .extend_from_slice(events);
            Ok(())
        }
    }

    /// A resolver that hands back a stable, per-sector subject, so a test can
    /// assert that a receiver is told the subject of *its* sector.
    #[derive(Debug)]
    struct FakeSubjects;

    #[async_trait::async_trait]
    impl SubjectResolver for FakeSubjects {
        async fn subject(
            &self,
            _user: UserId,
            sector: &SectorIdentifier,
        ) -> Result<SubjectId, DomainError> {
            Ok(SubjectId::new(format!("sub-for-{}", sector.as_str())))
        }
    }

    /// A client directory with one public receiver.
    #[derive(Debug)]
    struct FakeClients;

    #[async_trait::async_trait]
    impl ClientRepository for FakeClients {
        async fn find(&self, client_id: &ClientId) -> Result<Option<Client>, DomainError> {
            let json = serde_json::json!({
                "client_name": client_id.as_str(),
                "redirect_uris": [],
                "grant_types": ["client_credentials"],
                "response_types": [],
                "token_endpoint_auth_method": "private_key_jwt",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
                "subject_type": "public",
            });
            let registration = asterius_domain::ClientRegistration::from_json(
                &serde_json::to_vec(&json).expect("serialise"),
                asterius_domain::Capabilities::default(),
            )
            .expect("a registration");
            Ok(Some(Client {
                tenant: tenant(),
                id: client_id.clone(),
                registration,
                status: asterius_domain::ClientStatus::Active,
                created_at: now(),
                updated_at: now(),
            }))
        }
    }

    fn subscription(stream: &str, delivery: DeliveryMethod) -> Subscription {
        Subscription {
            stream_id: stream_id(stream),
            receiver: ClientId::new("receiver"),
            audience: vec!["https://receiver.example".to_owned()],
            delivery,
        }
    }

    fn keys() -> LocalKeyStore {
        let keys = LocalKeyStore::new();
        keys.generate(&tenant(), asterius_domain::SigningAlgorithm::DEFAULT)
            .expect("a tenant key");
        keys
    }

    /// The claims of a signed SET, read back off the compact serialisation.
    fn claims_of(jws: &str) -> Value {
        use base64::Engine as _;
        let payload = jws.split('.').nth(1).expect("a JWS payload segment");
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url");
        serde_json::from_slice(&bytes).expect("json claims")
    }

    /// **SSF 1.0 §8.1.4, on a poll stream.** The event type is the
    /// verification URI, the `sub_id` is the stream as an `opaque`
    /// identifier, and the `state` is carried verbatim.
    #[tokio::test]
    async fn a_verification_reaches_a_poll_stream_with_its_state() {
        let keys = keys();
        let queues = FakeQueues::default();
        let transmitter = SsfTransmitter {
            tenant: &tenant(),
            issuer: &issuer(),
            queues: &queues,
            clients: &FakeClients,
            subjects: &FakeSubjects,
            signer: &keys,
        };
        let state = VerificationState::parse("corr-1").expect("a state");

        transmitter
            .verify(
                &subscription(POLL_STREAM, DeliveryMethod::Poll),
                Some(&state),
                now(),
            )
            .await
            .expect("queued");

        let polled = queues.polled.lock().expect("not poisoned");
        assert_eq!(polled.len(), 1);
        assert_eq!(polled[0].0, POLL_STREAM);
        let claims = claims_of(&polled[0].2);
        assert_eq!(claims["iss"], ISSUER);
        assert_eq!(claims["aud"], "https://receiver.example");
        assert_eq!(
            claims["sub_id"],
            serde_json::json!({"format": "opaque", "id": POLL_STREAM})
        );
        assert_eq!(
            claims["events"],
            serde_json::json!({ asterius_ssf::VERIFICATION: {"state": "corr-1"} })
        );
        assert!(queues.pushed.lock().expect("not poisoned").is_empty());
    }

    /// On a push stream the SET goes to the outbox under the stream's own
    /// key, and without a `state` the event payload is empty.
    #[tokio::test]
    async fn a_verification_reaches_a_push_stream_ordered_behind_the_stream_alone() {
        let keys = keys();
        let queues = FakeQueues::default();
        let transmitter = SsfTransmitter {
            tenant: &tenant(),
            issuer: &issuer(),
            queues: &queues,
            clients: &FakeClients,
            subjects: &FakeSubjects,
            signer: &keys,
        };

        transmitter
            .verify(
                &subscription(PUSH_STREAM, DeliveryMethod::Push),
                None,
                now(),
            )
            .await
            .expect("queued");

        let pushed = queues.pushed.lock().expect("not poisoned");
        assert_eq!(pushed.len(), 1);
        assert_eq!(pushed[0].kind, "ssf.set");
        assert_eq!(pushed[0].destination, PUSH_STREAM);
        assert_eq!(
            pushed[0].ordering_key.as_deref(),
            Some(format!("{PUSH_STREAM}\u{1f}{PUSH_STREAM}").as_str())
        );
        let claims = claims_of(pushed[0].payload["body"].as_str().expect("a jws"));
        assert_eq!(
            claims["events"],
            serde_json::json!({ asterius_ssf::VERIFICATION: {} })
        );
        assert!(queues.polled.lock().expect("not poisoned").is_empty());
    }

    /// **SSF 1.0 §8.1.5, on a poll stream.** The event type is the
    /// stream-updated URI, the payload is the new status and the reason, and
    /// the `sub_id` is the stream as an `opaque` identifier — no person is
    /// named by a SET about a stream.
    #[tokio::test]
    async fn a_status_change_is_announced_as_a_stream_updated_set() {
        // Arrange
        let keys = keys();
        let queues = FakeQueues::default();
        let transmitter = SsfTransmitter {
            tenant: &tenant(),
            issuer: &issuer(),
            queues: &queues,
            clients: &FakeClients,
            subjects: &FakeSubjects,
            signer: &keys,
        };

        // Act
        transmitter
            .announce_status(
                &subscription(POLL_STREAM, DeliveryMethod::Poll),
                asterius_ssf::stream::StreamStatus::Paused,
                Some("Disabled by administrator action."),
                now(),
            )
            .await
            .expect("queued");

        // Assert
        let polled = queues.polled.lock().expect("not poisoned");
        assert_eq!(polled.len(), 1);
        let claims = claims_of(&polled[0].2);
        assert_eq!(claims["iss"], ISSUER);
        assert_eq!(claims["aud"], "https://receiver.example");
        assert_eq!(
            claims["sub_id"],
            serde_json::json!({"format": "opaque", "id": POLL_STREAM})
        );
        assert_eq!(
            claims["events"],
            serde_json::json!({
                asterius_ssf::STREAM_UPDATED: {
                    "status": "paused",
                    "reason": "Disabled by administrator action.",
                },
            })
        );
    }

    /// §8.1.5's re-enable: the same event with the new status, and no reason
    /// left over from the pause it ends.
    #[tokio::test]
    async fn re_enabling_a_stream_is_announced_too() {
        // Arrange
        let keys = keys();
        let queues = FakeQueues::default();
        let transmitter = SsfTransmitter {
            tenant: &tenant(),
            issuer: &issuer(),
            queues: &queues,
            clients: &FakeClients,
            subjects: &FakeSubjects,
            signer: &keys,
        };

        // Act
        transmitter
            .announce_status(
                &subscription(PUSH_STREAM, DeliveryMethod::Push),
                asterius_ssf::stream::StreamStatus::Enabled,
                None,
                now(),
            )
            .await
            .expect("queued");

        // Assert
        let pushed = queues.pushed.lock().expect("not poisoned");
        assert_eq!(pushed.len(), 1);
        assert_eq!(pushed[0].destination, PUSH_STREAM);
        // Ordered behind the stream alone, like a verification: there is no
        // subject to order it against.
        assert_eq!(
            pushed[0].ordering_key.as_deref(),
            Some(format!("{PUSH_STREAM}\u{1f}{PUSH_STREAM}").as_str())
        );
        let claims = claims_of(pushed[0].payload["body"].as_str().expect("a jws"));
        assert_eq!(
            claims["events"],
            serde_json::json!({ asterius_ssf::STREAM_UPDATED: {"status": "enabled"} })
        );
    }

    /// Both events about a stream bypass §8.1.1's `events_requested`: the
    /// stream list is never consulted, so a receiver that asked for nothing
    /// still hears that its stream stopped and still gets the verification it
    /// asked for.
    #[tokio::test]
    async fn the_two_stream_events_never_consult_events_requested() {
        // Arrange: a queue whose subscription list is empty, so a call to
        // `subscribed` would yield nothing to queue on.
        let keys = keys();
        let queues = FakeQueues::default();
        let transmitter = SsfTransmitter {
            tenant: &tenant(),
            issuer: &issuer(),
            queues: &queues,
            clients: &FakeClients,
            subjects: &FakeSubjects,
            signer: &keys,
        };
        let stream = subscription(POLL_STREAM, DeliveryMethod::Poll);

        // Act
        transmitter
            .verify(&stream, None, now())
            .await
            .expect("queued");
        transmitter
            .announce_status(
                &stream,
                asterius_ssf::stream::StreamStatus::Disabled,
                None,
                now(),
            )
            .await
            .expect("queued");

        // Assert
        assert_eq!(queues.polled.lock().expect("not poisoned").len(), 2);
        assert!(
            queues.asked.lock().expect("not poisoned").is_empty(),
            "a SET about a stream asked which streams subscribed"
        );
    }

    /// A session revocation reaches a poll stream as a `session-revoked` SET
    /// whose complex `sub_id` names this receiver's subject and the session.
    #[tokio::test]
    async fn a_revocation_queues_a_session_revoked_set_on_a_poll_stream() {
        let keys = keys();
        let queues = FakeQueues {
            subscriptions: vec![subscription(POLL_STREAM, DeliveryMethod::Poll)],
            ..FakeQueues::default()
        };
        let transmitter = SsfTransmitter {
            tenant: &tenant(),
            issuer: &issuer(),
            queues: &queues,
            clients: &FakeClients,
            subjects: &FakeSubjects,
            signer: &keys,
        };

        let queued_count = transmitter
            .emit(
                &Cause::SessionRevoked {
                    user: user(),
                    sid: "sid-1".to_owned(),
                    initiator: caep::InitiatingEntity::User,
                },
                now(),
            )
            .await;

        assert_eq!(queued_count, 1);
        let polled = queues.polled.lock().expect("not poisoned");
        assert_eq!(polled.len(), 1);
        assert_eq!(polled[0].0, POLL_STREAM);
        let claims = claims_of(&polled[0].2);
        assert_eq!(claims["iss"], ISSUER);
        assert_eq!(
            claims["sub_id"],
            serde_json::json!({
                "user": {
                    "format": "iss_sub",
                    "iss": ISSUER,
                    "sub": "sub-for-",
                },
                "session": {"format": "opaque", "id": "sid-1"},
            })
        );
        assert!(claims["events"][caep::SESSION_REVOKED]["event_timestamp"].is_number());
        assert!(queues.pushed.lock().expect("not poisoned").is_empty());
    }

    /// A push stream gets the SET through the outbox, addressed to the stream.
    #[tokio::test]
    async fn a_push_stream_receives_the_set_through_the_outbox() {
        let keys = keys();
        let queues = FakeQueues {
            subscriptions: vec![subscription(PUSH_STREAM, DeliveryMethod::Push)],
            ..FakeQueues::default()
        };
        let transmitter = SsfTransmitter {
            tenant: &tenant(),
            issuer: &issuer(),
            queues: &queues,
            clients: &FakeClients,
            subjects: &FakeSubjects,
            signer: &keys,
        };

        let queued_count = transmitter
            .emit(
                &Cause::AccountDisabled {
                    user: user(),
                    reason: Some(caep::DisabledReason::Hijacking),
                    initiator: caep::InitiatingEntity::Admin,
                },
                now(),
            )
            .await;

        assert_eq!(queued_count, 1);
        assert!(queues.polled.lock().expect("not poisoned").is_empty());
        let pushed = queues.pushed.lock().expect("not poisoned");
        assert_eq!(pushed.len(), 1);
        assert_eq!(pushed[0].destination, PUSH_STREAM);
        assert!(pushed[0].kind.starts_with("ssf."));
    }

    /// Every SET of one cause shares one `txn` (§4.1.9) but has its own `jti`.
    #[tokio::test]
    async fn every_set_of_one_cause_shares_a_txn_and_has_its_own_jti() {
        let keys = keys();
        let queues = FakeQueues {
            subscriptions: vec![
                subscription(POLL_STREAM, DeliveryMethod::Poll),
                Subscription {
                    stream_id: stream_id("stream-two-0000000000000000000000000"),
                    ..subscription(POLL_STREAM, DeliveryMethod::Poll)
                },
            ],
            ..FakeQueues::default()
        };
        let transmitter = SsfTransmitter {
            tenant: &tenant(),
            issuer: &issuer(),
            queues: &queues,
            clients: &FakeClients,
            subjects: &FakeSubjects,
            signer: &keys,
        };

        transmitter
            .emit(
                &Cause::AccountEnabled {
                    user: user(),
                    initiator: caep::InitiatingEntity::Admin,
                },
                now(),
            )
            .await;

        let polled = queues.polled.lock().expect("not poisoned");
        assert_eq!(polled.len(), 2);
        let txns: Vec<Value> = polled
            .iter()
            .map(|(_, _, jws)| claims_of(jws)["txn"].clone())
            .collect();
        assert_eq!(txns[0], txns[1], "one cause, one txn");
        let jtis: Vec<Value> = polled
            .iter()
            .map(|(_, jti, _)| Value::from(jti.clone()))
            .collect();
        assert_ne!(jtis[0], jtis[1], "each SET its own jti");
    }

    /// No subscribed stream: nothing is signed and nothing is queued.
    #[tokio::test]
    async fn no_subscribers_means_no_tokens() {
        let keys = keys();
        let queues = FakeQueues::default();
        let transmitter = SsfTransmitter {
            tenant: &tenant(),
            issuer: &issuer(),
            queues: &queues,
            clients: &FakeClients,
            subjects: &FakeSubjects,
            signer: &keys,
        };

        let queued_count = transmitter
            .emit(
                &Cause::SessionRevoked {
                    user: user(),
                    sid: "sid-1".to_owned(),
                    initiator: caep::InitiatingEntity::User,
                },
                now(),
            )
            .await;

        assert_eq!(queued_count, 0);
        assert!(queues.polled.lock().expect("not poisoned").is_empty());
        assert!(queues.pushed.lock().expect("not poisoned").is_empty());
    }
}
