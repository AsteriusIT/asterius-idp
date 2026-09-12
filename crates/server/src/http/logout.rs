//! The end-session endpoint: RP-initiated logout, wired up.
//!
//! OIDC RP-Initiated Logout 1.0 (Final, 2022-09) §2–§4. The rules are
//! [`asterius_oidc::logout`], the pages are `asterius_web::pages`; what lives
//! here is the HTTP, the session, and the order the effects happen in.
//!
//! # The order §3 fixes
//!
//! ```text
//!   verify the hint  →  decide  →  [ask the user]  →  end the session
//!                                                  →  notify the RPs
//!                                                  →  redirect
//! ```
//!
//! Two steps of it are load-bearing and neither is left to the order of
//! statements in this file:
//!
//! * **Nothing is ended before the user has answered.** A request this server
//!   could not attribute reaches [`asterius_oidc::logout::Disposition::Confirm`],
//!   and that arm returns a page. An implementation that revoked the session
//!   and *then* asked would violate the §3 MUST while looking, from the
//!   outside, almost the same.
//! * **The relying parties are notified before the browser leaves.** The
//!   `Location` is built from a [`Notified`] receipt, and the only way to
//!   obtain one is [`asterius_oidc::logout::notifying`], which *takes* the
//!   notification and returns the receipt after awaiting it. Redirecting
//!   first therefore does not compile rather than merely being against the
//!   convention (`ast-t9k`).
//!
//! # Back-channel logout
//!
//! `notify_participants` mints one logout token per participating client that
//! registered a `backchannel_logout_uri` and queues it in the outbox, which
//! POSTs it (OIDC Back-Channel Logout 1.0 §2.4, §2.5). The token itself is
//! [`asterius_oidc::tokens::logout_token`]; what lives here is which clients
//! are told, what each one's token says about the person, and the row that
//! carries it.
//!
//! # CAEP `session-revoked`
//!
//! Beside the logout tokens, and in the same function, every stream that
//! subscribed to CAEP `session-revoked` is told this session ended
//! (`ast-o4u.3`): `initiating_entity` `user`, because a relying party that
//! sent the browser here is carrying the person's request. The two
//! notifications reach different audiences — participants of *this session*
//! versus receivers subscribed to *the event type* — and neither is a
//! substitute for the other.
//!
//! # What is not built yet
//!
//! There is still no front-channel logout and no session-management iframe
//! (`ast-o4u.4`).
//!
//! Registered `post_logout_redirect_uris` (§3.1) *are* stored, and
//! `registered_redirect_uris` reads them off the identified client's
//! registration. The comparison stays where it was — [`asterius_oidc::logout`]
//! — and stays byte-exact; what this file decides is only whose set is
//! consulted, and it answers "nobody's" for every case it is not certain
//! about.

use crate::http::redirect::SeeOther;
use crate::tenancy::MountPrefix;
use asterius_domain::entities::session::{COOKIE_NAME, SessionRevocation};
use asterius_domain::{
    Actor, AuditEvent, AuditSink, ClientId, ClientRepository, Detail, EventType, KeyStore, Outcome,
    Session, SessionRepository, Tenant,
};
use asterius_oidc::logout::{
    Disposition, LogoutRequest, LogoutRequestError, Notified, RedirectTarget, client_from_hint,
    confirmation_token, confirmation_token_matches, disposition, identify,
};
use asterius_web::Brand;
use asterius_web::interaction::{self, InteractionError};
use asterius_web::pages::{
    self, ErrorPage, LoggedOutPage, LogoutConfirmationPage, nonce_attribute,
};
use asterius_web::{Document, csp::Nonce};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

/// What the end-session handlers need.
pub struct LogoutContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// The words these pages are rendered with.
    ///
    /// Negotiated by the caller from the request's `ui_locales` (OIDC Core
    /// §3.1.2.1), the browser's `Accept-Language` and the tenant's default —
    /// before the request is validated, so that §4's "did not parse" page is in
    /// the same language as the question it replaces.
    pub text: &'a asterius_web::Catalog,
    /// This tenant's sessions: the thing being ended, and the participant list
    /// back-channel logout will need.
    pub sessions: &'a dyn SessionRepository,
    /// This tenant's clients, for the registered `post_logout_redirect_uris`
    /// of an identified relying party (§3.1).
    pub clients: &'a dyn ClientRepository,
    /// This tenant's published and retired keys, for the `id_token_hint`.
    pub keys: &'a dyn KeyStore,
    /// Where the end of a session is recorded.
    pub audit: &'a dyn AuditSink,
    /// The CSP nonce the document middleware drew for this response.
    pub nonce: &'a Nonce,
    /// The request id, for correlating the audit record with the logs.
    pub request_id: Option<&'a str>,
    /// The prefix routing removed from this request's path, put back on the
    /// URLs this handler names to the browser (`ast-295`, `ast-j3v`).
    pub mount: MountPrefix,
    /// The `sub` each participating client knows this person by, for the
    /// logout token's subject (OIDC Back-Channel Logout 1.0 §2.4, OIDC Core
    /// §8.1).
    pub subjects: &'a dyn asterius_domain::ports::SubjectResolver,
    /// Signs the logout tokens, with the same key and the same port as every
    /// other JWT this deployment issues — a relying party resolves the key
    /// from the tenant's published JWKS, so a second signing path would
    /// produce tokens no RP can verify.
    pub signer: &'a dyn asterius_domain::keys::Signer,
    /// Where a logout token is queued for delivery (§2.5).
    ///
    /// `None` notifies nobody and says so. See
    /// [`crate::http::protocol::ClientEndpoints::outbox`].
    pub outbox: Option<&'a dyn asterius_domain::outbox::OutboxQueue>,
    /// Where the CAEP `session-revoked` Security Event Tokens of this
    /// sign-out are queued (`ast-o4u.3`).
    ///
    /// `None` is a deployment with no stream storage wired: it tells no
    /// receiver and says so in the log, the same degradation `outbox` above
    /// makes — a signal that cannot be queued must not hold up a sign-out that
    /// has already happened.
    pub queues: Option<&'a dyn crate::ssf::SsfQueues>,
    /// The long-lived credentials issued under this session, for the tenant
    /// that has asked a logout to withdraw them.
    ///
    /// `None` is a deployment with no such store wired; with the policy off it
    /// is never reached either way.
    pub credentials: Option<&'a dyn asterius_domain::ports::SessionCredentials>,
    /// This tenant's `revoke_refresh_on_logout` (`ast-o4u.2`).
    ///
    /// Resolved by the caller from the tenant's settings, so the handler
    /// applies a decision rather than reading configuration mid-request. False
    /// for a tenant that has expressed no opinion: a refresh token is offline
    /// access rather than a session — see
    /// [`asterius_domain::TenantSettings::revoke_refresh_on_logout`].
    pub revoke_refresh: bool,
}

impl std::fmt::Debug for LogoutContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogoutContext").finish_non_exhaustive()
    }
}

/// `GET /logout` — §2 permits GET and POST, with the same parameters.
///
/// A GET never ends a session on its own unless the request carried an
/// `id_token_hint` this server verified: a link, an `<img>` or a prefetch is
/// not a decision, and §2's "ask the End-User" is what an unverifiable request
/// gets.
pub async fn show(
    context: LogoutContext<'_>,
    headers: &HeaderMap,
    pairs: &[(String, String)],
    now: OffsetDateTime,
) -> Response {
    handle(&context, headers, pairs, Confirmation::NotOffered, now).await
}

/// `POST /logout` — the same request form-encoded, and the answer to the
/// confirmation page.
pub async fn submit(
    context: LogoutContext<'_>,
    headers: &HeaderMap,
    pairs: &[(String, String)],
    now: OffsetDateTime,
) -> Response {
    let field = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let confirmation = match field("decision") {
        Some("logout") => Confirmation::Answered {
            log_out: true,
            csrf: field("csrf").map(ToOwned::to_owned),
        },
        Some("stay") => Confirmation::Answered {
            log_out: false,
            csrf: field("csrf").map(ToOwned::to_owned),
        },
        // A POST that is an RP-initiated request rather than an answer.
        _ => Confirmation::NotOffered,
    };
    handle(&context, headers, pairs, confirmation, now).await
}

/// Whether this request is an answer to the confirmation page.
enum Confirmation {
    /// It is an ordinary logout request.
    NotOffered,
    /// The user pressed one of the two buttons.
    Answered {
        /// Which one.
        log_out: bool,
        /// The synchroniser token they carried.
        csrf: Option<String>,
    },
}

/// Everything both verbs share.
async fn handle(
    context: &LogoutContext<'_>,
    headers: &HeaderMap,
    pairs: &[(String, String)],
    confirmation: Confirmation,
    now: OffsetDateTime,
) -> Response {
    // §4: a request that is not well formed gets an error page. It never gets
    // a redirect — a malformed request has identified nobody, so there is
    // nowhere it would be safe to send the browser.
    let request = match LogoutRequest::parse(pairs.iter().cloned()) {
        Ok(request) => request,
        Err(error) => return malformed(context, &error),
    };

    // Every `cookie` field, not just the first (ast-bze): a logout that misses
    // the session cookie ends nothing and shows the neutral page, so the user
    // believes they are signed out while they are not.
    let cookies = crate::http::cookies(headers);
    let presented = interaction::cookie_value(&cookies, COOKIE_NAME).map(ToOwned::to_owned);
    let session = match live_session(context, presented.as_deref(), now).await {
        Ok(session) => session,
        Err(response) => return *response,
    };

    // The answer to the confirmation page, when that is what this is. It is
    // handled before the hint is looked at: the user has spoken, and the
    // request that put the page in front of them identified nobody, so there
    // is nothing to redirect to either way.
    if let Confirmation::Answered { log_out, csrf } = confirmation {
        return answered(
            context,
            session.as_ref(),
            presented.as_deref(),
            log_out,
            csrf.as_deref(),
            now,
        )
        .await;
    }

    let rp = identify(
        hinted_client(context, request.id_token_hint.as_deref(), now).await,
        request.client_id.as_ref(),
    );
    let registered = registered_redirect_uris(context, rp.client()).await;

    match disposition(&request, &rp, &registered) {
        // §2's MUST for a request nobody could verify: ask first, change
        // nothing. Reached before any call that writes.
        Disposition::Confirm => match (&session, presented.as_deref()) {
            (Some(_), Some(id)) => confirmation_page(context, id),
            // Nothing to end and nothing to ask. The neutral page is the
            // truthful answer, and it is the same page whether the session
            // expired an hour ago or never existed.
            _ => logged_out_page(context, true),
        },
        Disposition::EndSession => {
            let _notified = end_session(context, session.as_ref(), rp.client(), now).await;
            let mut response = logged_out_page(context, true);
            clear_session_cookie(&mut response);
            response
        }
        Disposition::EndSessionAndRedirect(target) => {
            // The receipt is the argument `location` needs, so the notify step
            // cannot be moved after the redirect without the code failing to
            // compile.
            let notified = end_session(context, session.as_ref(), rp.client(), now).await;
            redirect(context, &target, notified)
        }
    }
}

/// The confirmation page's answer.
async fn answered(
    context: &LogoutContext<'_>,
    session: Option<&Session>,
    presented: Option<&str>,
    log_out: bool,
    csrf: Option<&str>,
    now: OffsetDateTime,
) -> Response {
    let (Some(id), Some(csrf)) = (presented, csrf) else {
        // No cookie, or no token: there is no session this answer could be
        // about. Not an error page — a user who pressed "log out" twice is not
        // owed a failure.
        return logged_out_page(context, true);
    };
    if !confirmation_token_matches(id, csrf) {
        tracing::warn!(
            tenant = %context.tenant.id,
            "a logout confirmation arrived without this session's token"
        );
        return error_page(
            context,
            StatusCode::BAD_REQUEST,
            InteractionError::CsrfFailed,
        );
    }
    if !log_out {
        return logged_out_page(context, false);
    }

    let _notified = end_session(context, session, None, now).await;
    let mut response = logged_out_page(context, true);
    clear_session_cookie(&mut response);
    response
}

/// Ends the session, records it, and notifies the relying parties that took
/// part — in that order, and always through here.
///
/// Returns the [`Notified`] receipt §3's ordering is expressed with.
async fn end_session(
    context: &LogoutContext<'_>,
    session: Option<&Session>,
    requested_by: Option<&ClientId>,
    now: OffsetDateTime,
) -> Notified {
    let Some(session) = session else {
        // Already signed out. There is no session to revoke and no
        // participant list to read, so there is nobody to notify — and the
        // receipt is still earned by running the (empty) notification, which
        // is the only way to hold one.
        return asterius_oidc::logout::notifying(|| async { 0 }).await;
    };

    if let Err(error) = context
        .sessions
        .revoke(&session.id_digest, SessionRevocation::UserLogout, now)
        .await
    {
        // The browser is still sent onward with its cookie cleared: a logout
        // that half worked must not look to the user like one that did not
        // happen. The operator gets the error and the failed audit outcome.
        tracing::error!(%error, tenant = %context.tenant.id, "cannot revoke a session at logout");
        record(context, session, requested_by, Outcome::Failure, 0, now).await;
        // Nothing was revoked, so there is nothing to tell a relying party
        // about: a logout token for a session that is still live would be a
        // statement this server cannot stand behind.
        return asterius_oidc::logout::notifying(|| async { 0 }).await;
    }

    // Before the notification and after the revocation: a relying party told
    // that a session ended, whose refresh token still works, is a client that
    // can mint a fresh access token a second later. The order is the point,
    // and a failure here is logged rather than fatal — the session is already
    // ended and the browser must still be let go.
    revoke_refresh_tokens(context, session, now).await;

    let participants = match context.sessions.participants(&session.id_digest).await {
        Ok(participants) => participants,
        Err(error) => {
            tracing::error!(%error, "cannot read the participants of an ended session");
            Vec::new()
        }
    };
    let notified = notify_participants(context, session, &participants, now).await;
    record(
        context,
        session,
        requested_by,
        Outcome::Success,
        notified.participants(),
        now,
    )
    .await;
    notified
}

/// **Back-channel logout: OIDC Back-Channel Logout 1.0 §2.**
///
/// Every relying party that was issued an ID token in this session is told
/// that it ended: one logout token per participant that registered a
/// `backchannel_logout_uri` (§2.2), queued in the outbox and posted by its
/// HTTP deliverer (§2.5).
///
/// The receipt comes back through [`asterius_oidc::logout::notifying`], which
/// is the only way to obtain one: the [`Notified`] is built from what the
/// queueing returned, so §3's "notify, then redirect" is a property of the
/// types rather than of the order of statements here (`ast-t9k`).
///
/// # What the count means
///
/// The number of logout tokens **queued**, not the number of relying parties
/// that acknowledged one. Delivery is the outbox's, is retried, and may end in
/// a dead letter; a browser cannot be held while three RPs are posted to and
/// nothing in §3 asks for it to be. A client with no `backchannel_logout_uri`
/// is not counted, because nothing was sent to it — an audit record saying
/// "notified 3" when one client is not a participant is a control an auditor
/// would believe and should not.
///
/// # The other notification: CAEP `session-revoked` (`ast-o4u.3`)
///
/// A logout token goes to the relying parties that *took part in this
/// session*; a CAEP `session-revoked` Security Event Token goes to the
/// receivers that *subscribed to the event type*, which is a different set and
/// a different transport (SSF 1.0). Both are sent here, from the one place
/// that knows a session has just ended, and neither is counted by the other:
/// [`Notified`] is a receipt for §3's ordering and says nothing about SETs.
async fn notify_participants(
    context: &LogoutContext<'_>,
    session: &Session,
    participants: &[asterius_domain::Participant],
    now: OffsetDateTime,
) -> Notified {
    let notifier = crate::backchannel::Notifier {
        tenant: context.tenant,
        clients: context.clients,
        subjects: context.subjects,
        signer: context.signer,
        outbox: context.outbox,
    };
    let receipt =
        asterius_oidc::logout::notifying(|| notifier.notify(session, participants, now)).await;
    emit_session_revoked(context, session, now).await;
    receipt
}

/// **CAEP 1.0 §3.1: one `session-revoked` for the session that just ended.**
///
/// The subject is complex — `{user, session}` — so a receiver holding several
/// of this person's sessions drops the one that ended and keeps the others;
/// `initiating_entity` is `user` and the two reasons say "the user signed out"
/// ([`crate::ssf::RevokedBy::EndSession`], CAEP §2).
///
/// Best-effort, after the revocation, and never fatal: the browser is on its
/// way back to the relying party and the session is already gone. A receiver
/// that could not be queued is the transmitter's log line, not this handler's
/// error page.
async fn emit_session_revoked(context: &LogoutContext<'_>, session: &Session, now: OffsetDateTime) {
    let Some(queues) = context.queues else {
        tracing::debug!(
            tenant = %context.tenant.id,
            "no security event queue is wired; no receiver was told a session ended"
        );
        return;
    };
    let transmitter = crate::ssf::SsfTransmitter {
        tenant: &context.tenant.id,
        issuer: &context.tenant.issuer,
        queues,
        clients: context.clients,
        subjects: context.subjects,
        signer: context.signer,
    };
    transmitter
        .emit(
            &crate::ssf::Cause::SessionRevoked {
                user: asterius_domain::UserId::new(session.user),
                // The public `sid`, which is what a receiver stored when it
                // learned of the session — never the digest.
                sid: session.public_sid.clone(),
                by: crate::ssf::RevokedBy::EndSession,
                // The language this logout was conducted in: the person is in
                // front of the browser that asked for it.
                locale: context.text.locale(),
            },
            now,
        )
        .await;
}

/// Withdraws the refresh tokens issued under this session, if the tenant asked
/// for that (`revoke_refresh_on_logout`).
///
/// Nothing happens for a tenant that has expressed no opinion, which is every
/// tenant that has never opened the setting: RP-Initiated Logout §2 asks the
/// OP to end the session, and a refresh token is offline access a person
/// granted a client rather than part of a browser session. A deployment whose
/// clients are all first-party turns it on and gets the other reading.
async fn revoke_refresh_tokens(
    context: &LogoutContext<'_>,
    session: &Session,
    now: OffsetDateTime,
) {
    if !context.revoke_refresh {
        return;
    }
    let Some(credentials) = context.credentials else {
        tracing::warn!(
            tenant = %context.tenant.id,
            "revoke_refresh_on_logout is set but no credential store is wired"
        );
        return;
    };
    match credentials
        .revoke_refresh_for_session(&session.id_digest, now)
        .await
    {
        Ok(revoked) => tracing::info!(
            tenant = %context.tenant.id,
            revoked,
            "refresh tokens revoked with the session"
        ),
        Err(error) => tracing::error!(
            %error,
            tenant = %context.tenant.id,
            "cannot revoke the refresh tokens of an ended session"
        ),
    }
}

/// The registered `post_logout_redirect_uris` of an identified relying party
/// (§3.1).
///
/// Empty whenever anything is less than certain — no identified client, a
/// client that is gone or disabled, a store that could not be read. Each of
/// those returns the same empty set, and an empty set can only produce the
/// neutral logged-out page: a storage error must never widen what counts as
/// registered, and a disabled client must not keep redirecting users at the
/// callbacks of a relying party an operator has just turned off.
async fn registered_redirect_uris(
    context: &LogoutContext<'_>,
    client: Option<&ClientId>,
) -> Vec<String> {
    let Some(client) = client else {
        return Vec::new();
    };
    match context.clients.find(client).await {
        Ok(Some(registered)) => {
            if registered.is_active() {
                registered
                    .registration
                    .registered_post_logout_redirect_uris()
            } else {
                tracing::debug!(
                    tenant = %context.tenant.id,
                    "an id_token_hint named a disabled client"
                );
                Vec::new()
            }
        }
        Ok(None) => {
            tracing::debug!(
                tenant = %context.tenant.id,
                "an id_token_hint named a client that is gone"
            );
            Vec::new()
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a client at logout");
            Vec::new()
        }
    }
}

/// The client an `id_token_hint` names, when the hint is one this server
/// signed (§4).
///
/// * The signature is checked against this tenant's own keys, **including
///   retired ones** — [`KeyStore::public_key`] resolves a `kid` whatever its
///   state, because a hint is by nature an old token.
/// * `iss` must be this tenant's issuer.
/// * `exp` is ignored. §4: the OP should accept an expired ID token here,
///   because the hint's job is to name a relying party and a session, not to
///   authorise anything.
/// * `aud` is not pinned to a client, because the client is what is being
///   *read out* of it; [`client_from_hint`] applies OIDC Core §2's rule that
///   `aud` contains the `client_id`, and refuses to guess when there is more
///   than one and no `azp`.
///
/// Anything that does not verify returns `None`, which makes the relying party
/// [`asterius_oidc::logout::Rp::Unidentified`] and the request one that has to be confirmed. A hint
/// that fails is never an error page: §2 already has an answer for a request
/// that cannot be verified, and it is the question.
async fn hinted_client(
    context: &LogoutContext<'_>,
    hint: Option<&str>,
    now: OffsetDateTime,
) -> Option<ClientId> {
    let claims =
        crate::http::id_token_hint::verified_claims(context.keys, context.tenant, hint?, now)
            .await?;
    client_from_hint(&claims)
}

/// The session behind the cookie, if it is one that may still be used.
///
/// A session that is expired, idle or already revoked is `None`: there is
/// nothing to end, and the cookie is cleared by the caller either way.
async fn live_session(
    context: &LogoutContext<'_>,
    presented: Option<&str>,
    now: OffsetDateTime,
) -> Result<Option<Session>, Box<Response>> {
    let Some(presented) = presented else {
        return Ok(None);
    };
    let digest = asterius_domain::sha256_hex(presented.as_bytes());
    match context.sessions.find(&digest).await {
        Ok(Some(session)) if session.status(now).is_usable() => Ok(Some(session)),
        Ok(_) => Ok(None),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a session at logout");
            Err(Box::new(error_page(
                context,
                StatusCode::SERVICE_UNAVAILABLE,
                InteractionError::NotAvailable,
            )))
        }
    }
}

/// Writes the audit record for an ended session.
async fn record(
    context: &LogoutContext<'_>,
    session: &Session,
    requested_by: Option<&ClientId>,
    outcome: Outcome,
    participants: usize,
    now: OffsetDateTime,
) {
    let detail = Detail::new()
        .label("reason", SessionRevocation::UserLogout.as_str())
        .label("initiator", "rp_initiated_logout")
        // CAEP §2's `initiating_entity`, in the words the SETs of this
        // sign-out carry (`ast-o4u.3`): the trail and the signals must agree
        // about who ended the session.
        .label(
            "initiating_entity",
            crate::ssf::RevokedBy::EndSession
                .initiating_entity()
                .as_str(),
        )
        .number("participants", i64::try_from(participants).unwrap_or(-1));
    let mut event = AuditEvent::new(
        context.tenant.id.clone(),
        EventType::SESSION_REVOKED,
        outcome,
        Actor::User(session.user.to_string()),
        now,
    )
    .subject(session.user.to_string())
    .session(asterius_domain::SessionId::new(&session.public_sid))
    .detail(detail);
    if let Some(client) = requested_by {
        event = event.client(client.clone());
    }
    if let Some(request_id) = context.request_id {
        event = event.request_id(request_id);
    }
    if let Err(error) = context.audit.record(event).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot record a logout");
    }
}

/// The post-logout redirect (§3), built from a receipt and never before one.
fn redirect(context: &LogoutContext<'_>, target: &RedirectTarget, notified: Notified) -> Response {
    let location = match target.location(&notified) {
        Ok(location) => location,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "a registered post_logout_redirect_uri will not parse");
            let mut response = logged_out_page(context, true);
            clear_session_cookie(&mut response);
            return response;
        }
    };
    // Through `SeeOther`, never open-coded: 303 is what the profile leaves
    // available, and the helper is also where response splitting through
    // `Location` is refused.
    let Ok(see_other) = SeeOther::to(&location) else {
        tracing::error!(tenant = %context.tenant.id, "a post-logout location is not a header value");
        let mut response = logged_out_page(context, true);
        clear_session_cookie(&mut response);
        return response;
    };

    let mut response = see_other.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    clear_session_cookie(&mut response);
    response
}

/// The confirmation question (§2), with a token derived from the session id.
fn confirmation_page(context: &LogoutContext<'_>, session_id: &str) -> Response {
    // Where this page fetches its face, under the prefix routing removed (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    Document::render(context.nonce, |nonce| {
        pages::render(&LogoutConfirmationPage {
            text: context.text,
            tenant_name: &context.tenant.display_name,
            // The prefix routing removed, put back: this form is posted by a
            // browser, and `/logout` is mounted under `/t/{tenant}` and
            // nowhere else. Without it the button is a 404 and the session
            // survives a logout the user believes happened (`ast-j3v`).
            action: &context
                .mount
                .absolute(asterius_oidc::metadata::Endpoint::EndSession.path()),
            csrf: &confirmation_token(session_id),
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .into_response()
}

/// The neutral page (§3): no client name, no link anybody else chose.
fn logged_out_page(context: &LogoutContext<'_>, signed_out: bool) -> Response {
    // Where this page fetches its face, under the prefix routing removed (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    Document::render(context.nonce, |nonce| {
        pages::render(&LoggedOutPage {
            text: context.text,
            tenant_name: &context.tenant.display_name,
            signed_out,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .into_response()
}

/// A request that did not parse (§4). Logged with the reason, shown without.
fn malformed(context: &LogoutContext<'_>, error: &LogoutRequestError) -> Response {
    tracing::info!(%error, tenant = %context.tenant.id, "a logout request did not parse");
    error_page(
        context,
        StatusCode::BAD_REQUEST,
        InteractionError::NotAvailable,
    )
}

/// The error page: one generic message, one correlation id.
fn error_page(
    context: &LogoutContext<'_>,
    status: StatusCode,
    reason: InteractionError,
) -> Response {
    // Where this page fetches its face, under the prefix routing removed (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    let correlation = interaction::correlation_id();
    tracing::info!(
        correlation_id = %correlation,
        tenant = %context.tenant.id,
        reason = %reason,
        "logout error page shown"
    );
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            text: context.text,
            tenant_name: &context.tenant.display_name,
            message: context.text.error_cannot_continue(),
            correlation_id: &correlation,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (status, document).into_response()
}

/// Removes the session cookie.
fn clear_session_cookie(response: &mut Response) {
    if let Ok(value) = asterius_web::session::clear_cookie().parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `ast-bze` site: a logout that misses the session cookie ends
    /// nothing and shows the neutral page, so the user believes they are
    /// signed out while they are not. HTTP/2 lets the client send the session
    /// cookie in a second `cookie` field (RFC 9113 §8.2.3), and it does.
    #[test]
    fn the_session_cookie_is_read_from_a_second_cookie_field() {
        // Arrange
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-asterius_ix=an-interaction"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-asterius_session=a-session"),
        );

        // Act
        let cookies = crate::http::cookies(&headers);
        let presented = interaction::cookie_value(&cookies, COOKIE_NAME);

        // Assert
        assert_eq!(presented, Some("a-session"));
    }
}
