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
//!   `Location` is built from a [`Notified`] receipt, and the one place in
//!   this server that mints one is the notifying step itself. That step,
//!   `notify_participants`, stays private so no second path to a receipt can
//!   appear beside it.
//!
//! # What is not built yet
//!
//! `notify_participants` is the named seam for **back-channel logout**
//! (OIDC Back-Channel Logout 1.0 §2, `E10_02`) and for the **CAEP
//! `session-revoked`** signal, which needs the outbox (`ast-0ju.9`). It reads
//! the participant list and records the count today; it does not send
//! anything, and it does not pretend to. Both of those land inside this one
//! function, which is why the redirect is already gated behind its receipt.
//!
//! Registered `post_logout_redirect_uris` (§3.1) *are* stored, and
//! `registered_redirect_uris` reads them off the identified client's
//! registration. The comparison stays where it was — [`asterius_oidc::logout`]
//! — and stays byte-exact; what this file decides is only whose set is
//! consulted, and it answers "nobody's" for every case it is not certain
//! about.

use crate::http::redirect::SeeOther;
use asterius_domain::entities::session::{COOKIE_NAME, SessionRevocation};
use asterius_domain::{
    Actor, AuditEvent, AuditSink, ClientId, ClientRepository, Detail, EventType, KeyStore, Outcome,
    Session, SessionRepository, SigningAlgorithm, Tenant,
};
use asterius_jose::verify::{self, Policy, TypRule};
use asterius_oidc::logout::{
    Disposition, LogoutRequest, LogoutRequestError, Notified, RedirectTarget, client_from_hint,
    confirmation_token, confirmation_token_matches, disposition, identify,
};
use asterius_oidc::tokens::id_token::ID_TOKEN_TYP;
use asterius_web::interaction::{self, InteractionError};
use asterius_web::pages::{
    self, ErrorPage, LoggedOutPage, LogoutConfirmationPage, nonce_attribute,
};
use asterius_web::{Document, csp::Nonce};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use time::OffsetDateTime;

/// What the end-session handlers need.
pub struct LogoutContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
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
        // participant list to read, so there is nobody to notify.
        return Notified::after_notifying(0);
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
        return Notified::after_notifying(0);
    }

    let participants = match context.sessions.participants(&session.id_digest).await {
        Ok(participants) => participants,
        Err(error) => {
            tracing::error!(%error, "cannot read the participants of an ended session");
            Vec::new()
        }
    };
    let notified = notify_participants(context, session, &participants).await;
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

/// **Extension point: back-channel logout and CAEP `session-revoked`.**
///
/// Every relying party that was issued an ID token in this session has to be
/// told that it ended — OIDC Back-Channel Logout 1.0 §2, tracked as `E10_02`
/// — and the same event is a CAEP `session-revoked` subject for the SSF
/// transmitter (`ast-o4u.3`), which needs the outbox in `ast-0ju.9`.
///
/// Neither exists yet, so this function does the part that does: it reads the
/// participant list and returns the receipt. It deliberately does **not**
/// fabricate a notification — a logout that logs "notified 3 clients" while
/// sending nothing is worse than one that is honestly incomplete, because the
/// first is a control an auditor would believe.
///
/// What lands here, and nowhere else, is: mint a logout token per participant,
/// hand it to the outbox, and emit the CAEP event. The signature already
/// returns [`Notified`], which is what [`RedirectTarget::location`] needs, so
/// the §3 ordering does not have to be rediscovered when it does.
#[expect(
    clippy::unused_async,
    reason = "this is the seam back-channel logout (E10_02) plugs into, and sending a               logout token per participant is I/O; making it synchronous now would only               have to be undone, and its caller is already async"
)]
async fn notify_participants(
    context: &LogoutContext<'_>,
    session: &Session,
    participants: &[asterius_domain::Participant],
) -> Notified {
    if !participants.is_empty() {
        tracing::info!(
            tenant = %context.tenant.id,
            sid = %session.public_sid,
            participants = participants.len(),
            "session ended with participating clients; back-channel logout (E10_02) is not built yet"
        );
    }
    // The count is of clients that *should* be notified, and it is used for
    // the audit detail and nothing else until E10_02 lands.
    Notified::after_notifying(participants.len())
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
    let hint = hint?;
    let unverified = asterius_jose::jws::parse(hint).ok()?;
    let kid = unverified.kid();

    // The candidate keys are fetched before verification, because the resolver
    // is synchronous and because a `kid` must narrow an already-trusted set
    // rather than be followed.
    let mut jwks: Vec<Value> = Vec::new();
    if let Some(kid) = &kid {
        match context.keys.public_key(&context.tenant.id, kid).await {
            Ok(Some(record)) => jwks.push(record.public_jwk),
            Ok(None) => {}
            Err(error) => {
                tracing::error!(%error, tenant = %context.tenant.id, "cannot read a key for an id_token_hint");
                return None;
            }
        }
    }
    if jwks.is_empty() {
        match context.keys.published_keys(&context.tenant.id).await {
            Ok(records) => jwks.extend(records.into_iter().map(|record| record.public_jwk)),
            Err(error) => {
                tracing::error!(%error, tenant = %context.tenant.id, "cannot read the key set for an id_token_hint");
                return None;
            }
        }
    }
    let resolver = asterius_jose::keys_from_jwk_set(&json!({"keys": jwks})).ok()?;

    let policy = Policy::new(
        TypRule::Exactly(ID_TOKEN_TYP),
        SigningAlgorithm::ALL.to_vec(),
    )
    .issued_by(context.tenant.issuer.as_str().to_owned())
    .accepting_expired();

    match verify::verify(hint, &policy, &resolver, now) {
        Ok(verified) => client_from_hint(&verified.claims),
        Err(error) => {
            // Debug, not warn: a stale hint from a client that has since been
            // rotated is ordinary, and the user still gets a usable page.
            tracing::debug!(%error, tenant = %context.tenant.id, "an id_token_hint did not verify");
            None
        }
    }
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
    Document::render(context.nonce, |nonce| {
        pages::render(&LogoutConfirmationPage {
            locale: "en",
            tenant_name: &context.tenant.display_name,
            action: asterius_oidc::metadata::Endpoint::EndSession.path(),
            csrf: &confirmation_token(session_id),
            nonce_attribute: nonce_attribute(nonce),
        })
    })
    .into_response()
}

/// The neutral page (§3): no client name, no link anybody else chose.
fn logged_out_page(context: &LogoutContext<'_>, signed_out: bool) -> Response {
    Document::render(context.nonce, |nonce| {
        pages::render(&LoggedOutPage {
            locale: "en",
            tenant_name: &context.tenant.display_name,
            signed_out,
            nonce_attribute: nonce_attribute(nonce),
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
    let correlation = interaction::correlation_id();
    tracing::info!(
        correlation_id = %correlation,
        tenant = %context.tenant.id,
        reason = %reason,
        "logout error page shown"
    );
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            locale: "en",
            tenant_name: &context.tenant.display_name,
            message: "Something went wrong, and this request cannot continue.",
            correlation_id: &correlation,
            nonce_attribute: nonce_attribute(nonce),
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
