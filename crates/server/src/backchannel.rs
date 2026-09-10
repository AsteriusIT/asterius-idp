//! Back-channel logout: telling the relying parties that a session ended.
//!
//! **OIDC Back-Channel Logout 1.0 §2.4 and §2.5.** One logout token per
//! participating relying party, signed with the same key and through the same
//! port as every other JWT this deployment issues, queued in the outbox that
//! POSTs it.
//!
//! # Why this is not in the end-session handler any more
//!
//! It was, and RP-initiated logout was its only caller. `ast-f7m.6` added the
//! second: an administrator disabling an account, or ending one of its
//! sessions from the console, reaches exactly the same relying parties with
//! exactly the same statement. Two implementations of §2.4 would be two
//! answers to "what does a logout token say", and they would diverge on the
//! case that is hardest to test — a pairwise client that asked for a session
//! identifier. So the notification lives here, and both callers hold a
//! [`Notifier`].
//!
//! # What the count means
//!
//! The number of logout tokens **queued**, not the number of relying parties
//! that acknowledged one. Delivery is the outbox's, is retried, and may end in
//! a dead letter; nothing in the specification asks a browser to be held while
//! three RPs are posted to. A client with no `backchannel_logout_uri` is not
//! counted, because nothing was sent to it — an audit record saying
//! "notified 3" when one client is not a participant is a control an auditor
//! would believe and should not.
//!
//! # What is still to come
//!
//! The CAEP `session-revoked` signal for the SSF transmitter (`ast-o4u.3`)
//! lands beside the logout tokens, in [`Notifier::notify`], and the RISC
//! `account-disabled` signal beside the audit record in [`crate::admin`]
//! (`ast-0ju`). Both are named rather than built, for the reason
//! `notify_credential_change` is: a hook with a name is one a reviewer can
//! find, and one that does not exist is a signal nobody remembers to send.

use asterius_domain::{ClientId, ClientRepository, Session, Tenant};
use time::OffsetDateTime;

/// The outbox `kind` a queued logout token carries.
///
/// The part before the first `.` is the family, and `logout` is the family the
/// process registers [`crate::outbox::HttpDeliverer`] for. A kind whose family
/// has no deliverer is dead-lettered on its first attempt, so this constant
/// and that registration are one fact spelled in two places — which is why it
/// is a constant and why `the_kind_is_delivered_by_the_http_family` asserts
/// the prefix.
pub const BACKCHANNEL_LOGOUT_KIND: &str = "logout.backchannel";

/// What minting one relying party's logout token needs.
///
/// Five borrows and no more: the tenant it is issued by, the registrations
/// that say who is a participant, the `sub` each client knows the person by,
/// the signer, and the queue. A struct rather than five arguments so that a
/// caller cannot transpose two of the same type, and so that the CAEP
/// transmitter arriving later is a field rather than a signature change at
/// every call site.
pub struct Notifier<'a> {
    /// The tenant whose issuer the tokens carry.
    pub tenant: &'a Tenant,
    /// This tenant's clients: `backchannel_logout_uri`, the algorithm each RP
    /// registered, and whether it is still active.
    pub clients: &'a dyn ClientRepository,
    /// The `sub` each participating client knows this person by (OIDC Core
    /// §8.1).
    pub subjects: &'a dyn asterius_domain::ports::SubjectResolver,
    /// Signs the tokens, with the key the tenant publishes — a second signing
    /// path would produce tokens no relying party can verify.
    pub signer: &'a dyn asterius_domain::keys::Signer,
    /// Where a logout token is queued for delivery (§2.5).
    ///
    /// `None` notifies nobody and says so in the log.
    pub outbox: Option<&'a dyn asterius_domain::outbox::OutboxQueue>,
}

impl std::fmt::Debug for Notifier<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Notifier")
            .field("tenant", &self.tenant.id)
            .field("outbox", &self.outbox.is_some())
            .finish_non_exhaustive()
    }
}

impl Notifier<'_> {
    /// Mints and queues one logout token per participating relying party.
    ///
    /// Returns how many rows were written. Every failure here is logged and
    /// degrades to "this client was not notified": a relying party whose
    /// registration will not load, whose sector cannot be resolved or whose
    /// token will not sign must not stop the session from ending or the other
    /// RPs from being told, and it must not turn a completed logout into an
    /// error page.
    pub async fn notify(
        &self,
        session: &Session,
        participants: &[asterius_domain::Participant],
        now: OffsetDateTime,
    ) -> usize {
        let Some(queue) = self.outbox else {
            if !participants.is_empty() {
                tracing::warn!(
                    tenant = %self.tenant.id,
                    participants = participants.len(),
                    "no outbox is wired; the participating relying parties were not notified"
                );
            }
            return 0;
        };

        let mut rows = Vec::with_capacity(participants.len());
        for participant in participants {
            match self.notice(session, &participant.client, now).await {
                Ok(Some(row)) => rows.push(row),
                // §2.2: a client with no `backchannel_logout_uri` is not a
                // participant of back-channel logout. Nothing to send, nothing
                // to count, nothing to say.
                Ok(None) => {}
                Err(error) => tracing::error!(
                    %error,
                    tenant = %self.tenant.id,
                    client = %participant.client,
                    "cannot build a logout token for a participating client"
                ),
            }
        }

        if rows.is_empty() {
            return 0;
        }
        let queued = rows.len();
        if let Err(error) = queue.queue(&self.tenant.id, &rows, now).await {
            // All-or-nothing: the port writes every row or none, so this is a
            // logout nobody was told about. The session is still ended and the
            // browser still leaves — the audit record carries the zero.
            tracing::error!(
                %error,
                tenant = %self.tenant.id,
                "cannot queue the back-channel logout tokens of an ended session"
            );
            return 0;
        }
        tracing::info!(
            tenant = %self.tenant.id,
            queued,
            "back-channel logout tokens queued"
        );
        queued
    }

    /// One relying party's logout token, as an outbox row (§2.4, §2.5).
    ///
    /// `Ok(None)` is a client that is not a participant of back-channel
    /// logout: it is gone, disabled, or registered no `backchannel_logout_uri`.
    ///
    /// # What goes in the token
    ///
    /// §2.4 requires `sub` and/or `sid` and allows both. Which this server
    /// sends is decided here:
    ///
    /// * **`sid` and `sub`** by default. The RP matches either (§2.6 step 4),
    ///   and a token carrying both is one it can attribute whichever it
    ///   indexed by.
    /// * **`sid` alone** when the client both requires a session identifier
    ///   (`backchannel_logout_session_required`) and is pairwise. It asked to
    ///   be told which session ended; a pairwise `sub` adds nothing it needs
    ///   and puts a subject identifier on the wire, in a token delivered to a
    ///   URL, for a client that said the session was the part it cared about.
    ///   Data minimisation, and §2.4 permits it in as many words.
    ///
    /// The `sub` is never the local user id: it is [`SubjectResolver`]'s
    /// answer for *this client's* sector, which is the identifier the RP was
    /// issued in its ID token (OIDC Core §8.1). A local identifier here would
    /// be a `sub` no RP recognises and a correlator across every RP that
    /// received one.
    ///
    /// [`SubjectResolver`]: asterius_domain::ports::SubjectResolver
    async fn notice(
        &self,
        session: &Session,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Option<asterius_domain::outbox::QueuedEvent>, NoticeError> {
        let Some(registered) = self
            .clients
            .find(client)
            .await
            .map_err(NoticeError::Registration)?
        else {
            return Ok(None);
        };
        if !registered.is_active() {
            // A client an operator has just turned off is not one this server
            // opens a connection to.
            return Ok(None);
        }
        let Some(endpoint) = registered.registration.backchannel_logout_uri.clone() else {
            return Ok(None);
        };

        let sid = asterius_oidc::tokens::Session::new(&asterius_domain::SessionId::new(
            &session.public_sid,
        ))
        .map_err(NoticeError::Session)?;

        let pairwise_and_session_only = registered.registration.backchannel_logout_session_required
            && registered.registration.subject_type == asterius_domain::SubjectType::Pairwise;
        let unsigned = if pairwise_and_session_only {
            asterius_oidc::tokens::LogoutToken::about_session(sid)
        } else {
            let sector = asterius_domain::SectorIdentifier::of_client(&registered)
                .map_err(|_| NoticeError::Sector)?;
            let subject = self
                .subjects
                .subject(asterius_domain::UserId::new(session.user), &sector)
                .await
                .map_err(NoticeError::Subject)?;
            asterius_oidc::tokens::LogoutToken::about_session(sid).and_subject(
                asterius_oidc::tokens::LogoutSubject::new(subject.as_str())
                    .map_err(NoticeError::Claims)?,
            )
        }
        .issue(
            &self.tenant.issuer,
            client,
            // §2.6 step 3: the RP validates the signature "in the same manner
            // as an ID Token", so the algorithm is the one it registered.
            registered.registration.id_token_signed_response_alg,
            now,
            asterius_oidc::tokens::logout_token::MAX_LOGOUT_TOKEN_LIFETIME,
        )
        .map_err(NoticeError::Claims)?;

        let token = self
            .signer
            .sign(
                &self.tenant.id,
                unsigned.required_algorithm(),
                unsigned.typ(),
                unsigned.claims(),
            )
            .await
            .map_err(NoticeError::Signing)?;

        // §2.5: "the Logout Token is sent ... using the HTTP POST method ...
        // with the `logout_token` parameter" in a form-encoded body. The
        // encoding is done properly rather than by concatenation: a JWT needs
        // no escaping today, and a body built by `format!` is one that stops
        // being true the day anything else is added to it.
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("logout_token", token.as_str())
            .finish();

        Ok(Some(asterius_domain::outbox::QueuedEvent {
            kind: BACKCHANNEL_LOGOUT_KIND.to_owned(),
            destination: endpoint.as_str().to_owned(),
            payload: serde_json::json!({
                "body": body,
                "content_type": "application/x-www-form-urlencoded",
            }),
            // One key per (session, client): two statements about one session
            // at one relying party delivered out of order say the opposite of
            // what happened. Different clients are different keys, so a wedged
            // receiver holds its own queue and nobody else's.
            ordering_key: Some(format!("logout:{}:{client}", session.public_sid)),
        }))
    }
}

/// Why one relying party could not be sent a logout token.
///
/// Every variant is a reason to skip that client, never to fail the logout.
/// The `Display` names no URL and no token: it is logged beside a `client_id`.
#[derive(Debug, thiserror::Error)]
enum NoticeError {
    /// The client's registration could not be read.
    #[error("the client's registration could not be read")]
    Registration(#[source] asterius_domain::DomainError),
    /// The session identifier is not one that may appear in a `sid` claim.
    #[error("the session identifier cannot be a sid claim")]
    Session(#[source] asterius_oidc::tokens::IssuanceError),
    /// The `sub` this client knows the person by could not be resolved.
    #[error("the subject this client knows the user by could not be resolved")]
    Subject(#[source] asterius_domain::DomainError),
    /// The client's registration names a sector that will not resolve.
    #[error("the client's sector identifier cannot be derived")]
    Sector,
    /// The claims set was refused by the builder.
    #[error("the logout token claims were refused")]
    Claims(#[source] asterius_oidc::tokens::IssuanceError),
    /// The tenant's signer refused, most often for want of an active key of
    /// the client's `id_token_signed_response_alg`.
    #[error("the logout token could not be signed")]
    Signing(#[source] asterius_domain::DomainError),
}
