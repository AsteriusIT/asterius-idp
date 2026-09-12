//! The sessions open on an account, and the buttons that close them
//! (`ast-1xd`).
//!
//! Three routes, the shape the other account pages use:
//!
//! * `GET /account/sessions` lists this person's live sessions;
//! * `POST /account/sessions` closes one, or every one but this browser;
//! * `GET /account/sessions/sign-in` opens a fresh authentication for a session
//!   too old to close anything with.
//!
//! # What closing a session does, and in what order
//!
//! Three effects, in this order, and the order is the point:
//!
//! 1. the session is revoked — one statement, so two tabs racing on the same
//!    button produce one revocation and one "no longer there";
//! 2. one logout token per relying party that took an ID token in it is queued
//!    (OIDC Back-Channel Logout 1.0 §2.2), through the same
//!    [`crate::backchannel::Notifier`] the end-session endpoint uses;
//! 3. CAEP `session-revoked` is emitted to every stream that subscribed
//!    (`ast-0ju.8`), with [`caep::InitiatingEntity::User`] because the person
//!    themselves pressed it.
//!
//! The notifications come *after* the revocation and never fail it: the
//! session is already over by the time a receiver is told, and a relying party
//! that cannot be reached must not leave a session somebody asked to close
//! still open. That is [`crate::backchannel`]'s reasoning and this page keeps
//! to it.
//!
//! # A session that is not this account's
//!
//! Answered exactly as a session that does not exist, and with the same status:
//! the `sid` is the value a relying party holds, so somebody who has one from
//! another context must not be able to learn from this page whether it names a
//! live session of somebody else's. There is no 403 here, because a 403 is the
//! answer that says "this exists and is not yours".
//!
//! # Why the current session is marked and not hidden
//!
//! "Which of these is me" is the first question anybody asks on this page, and
//! a list that silently omitted the browser being read from would leave a
//! person unable to tell whether the row they are about to close is their own.
//! It is also closable: signing yourself out from here is a reasonable thing to
//! want, and it is what "I am on a shared computer" means.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::{
    FirstPartyDestination, Session, SessionId as DomainSessionId, SessionRepository,
    SessionRevocation, SessionSummary, UserId,
};
use asterius_ssf::caep;
use asterius_store_pg::PgSessionRepository;
use asterius_web::Brand;
use asterius_web::Document;
use asterius_web::pages::{self, AccountSessionsPage, SessionLine, nonce_attribute};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

use crate::http::account::{
    self, AccountContext, MAX_BODY, MAX_CSRF_CHARS, Signals, begin, checked_csrf, csrf_for,
    error_page, fresh, no_store, stamp,
};

/// Where the list lives, and where its submissions post.
pub const PAGE_PATH: &str = "/account/sessions";

/// Where a person goes to authenticate again.
pub const SIGN_IN_PATH: &str = "/account/sessions/sign-in";

/// This page's CSRF separator.
const CSRF_SEPARATOR: &str = "account-sessions-csrf";

/// The longest `sid` this parser will carry.
///
/// This server's own are 43 base64url characters. The bound is not a format
/// check — a `sid` is opaque and this page must not pretend to know its
/// shape — it is the promise that a caller cannot make this function allocate
/// without limit inside a body that is itself bounded.
const MAX_SID_CHARS: usize = 256;

/// What a submission asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Close the one session the body names.
    Revoke,
    /// Close every live session of this account except the one submitting.
    ///
    /// It names no session, deliberately: the server works out which rows
    /// those are from the cookie it is already holding, so a body cannot be
    /// made to close somebody else's.
    Others,
}

/// A submission from this page, after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    /// The synchroniser token the form carried.
    pub csrf: String,
    /// Which verb the pressed button named.
    pub verb: Verb,
    /// Which session, for [`Verb::Revoke`]. `None` for [`Verb::Others`].
    pub session: Option<String>,
}

/// Reads a submission from this page, or refuses it.
///
/// Every refusal is `None`, because the caller answers all of them with one
/// page: a body that is too large, that is not UTF-8, that names a parameter
/// twice (RFC 6749 §3.1's parameter pollution, applied to this server's own
/// forms), that names no verb or one this page does not have, or that asks to
/// close a session without saying which.
///
/// The `sid` is bounded and otherwise untouched. It is opaque — OIDC Session
/// Management §5 says nothing about its shape, and this server's own spelling
/// has changed once already — so what is checked here is that it *could* be a
/// value, and the statement that acts on it is what decides whether it is one
/// of this account's.
// fuzz-target: account_session_revocation
#[must_use]
pub fn revocation(body: &[u8]) -> Option<Revocation> {
    if body.len() > MAX_BODY {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;

    let mut csrf: Option<String> = None;
    let mut session: Option<String> = None;
    let mut verb: Option<Verb> = None;
    for (key, value) in url::form_urlencoded::parse(text.as_bytes()) {
        match key.as_ref() {
            "csrf" if csrf.is_some() => return None,
            "csrf" => csrf = Some(value.into_owned()),
            "session" if session.is_some() => return None,
            "session" => session = Some(value.into_owned()),
            "do" if verb.is_some() => return None,
            "do" => {
                verb = Some(match value.as_ref() {
                    "revoke" => Verb::Revoke,
                    "others" => Verb::Others,
                    _ => return None,
                });
            }
            _ => {}
        }
    }

    let csrf = csrf?;
    if csrf.is_empty() || csrf.chars().count() > MAX_CSRF_CHARS {
        return None;
    }
    let verb = verb?;
    if let Some(session) = session.as_ref()
        && (session.is_empty() || session.chars().count() > MAX_SID_CHARS)
    {
        return None;
    }
    // Closing "this one" without saying which one is not a request this page
    // makes, and guessing — the newest, the current — would be this server
    // choosing a session to end on somebody's behalf.
    if verb == Verb::Revoke && session.is_none() {
        return None;
    }
    Some(Revocation {
        csrf,
        verb,
        session: match verb {
            Verb::Revoke => session,
            // A body that named one anyway is read as the button it pressed:
            // "everything else" takes no argument, and carrying one would
            // invite a reader to think it did.
            Verb::Others => None,
        },
    })
}

/// What this page needs beyond [`AccountContext`].
pub struct SessionsContext<'a> {
    /// Admission, freshness, the sign-in and the chrome.
    pub account: AccountContext<'a>,
    /// This person's sessions, and the writes this page makes.
    ///
    /// The concrete repository rather than the port, because listing an
    /// account's sessions and resolving a `sid` to a digest are
    /// [`PgSessionRepository`]'s own methods — the same ones the admin API
    /// reaches through its port.
    pub store: &'a PgSessionRepository,
    /// The trail. A revocation is recorded whether or not anybody polls it.
    pub audit: &'a dyn AuditSink,
    /// The receivers that asked to be told (`ast-0ju.8`, Back-Channel Logout
    /// 1.0 §2.2).
    pub signals: Signals<'a>,
}

impl std::fmt::Debug for SessionsContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionsContext").finish_non_exhaustive()
    }
}

/// `GET /account/sessions` — where this person is signed in.
pub async fn page(
    context: &SessionsContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(
            &context.account,
            FirstPartyDestination::AccountSessions,
            now,
        )
        .await;
    };
    rendered(context, &session, None, StatusCode::OK, now).await
}

/// `GET /account/sessions/sign-in` — authenticate again, and come back.
pub async fn sign_in(context: &SessionsContext<'_>, now: OffsetDateTime) -> Response {
    begin(
        &context.account,
        FirstPartyDestination::AccountSessions,
        now,
    )
    .await
}

/// `POST /account/sessions` — close one session, or all the others.
pub async fn submit(
    context: &SessionsContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = account::admitted(&context.account, headers, now).await else {
        return begin(
            &context.account,
            FirstPartyDestination::AccountSessions,
            now,
        )
        .await;
    };
    let Some(form) = revocation(body) else {
        return refused(context, &session, now).await;
    };
    if !checked_csrf(&session, CSRF_SEPARATOR, &form.csrf) {
        return refused(context, &session, now).await;
    }
    // Freshness before anything is read, because it is a fact about the
    // person: deciding it first also means a stale session learns nothing
    // about whether the `sid` it submitted names a row.
    if !fresh(&session, now) {
        return begin(
            &context.account,
            FirstPartyDestination::AccountSessions,
            now,
        )
        .await;
    }

    match form.verb {
        Verb::Others => close_the_others(context, &session, now).await,
        Verb::Revoke => {
            let Some(sid) = form.session else {
                // Unreachable: the parser refuses a revocation with no `sid`.
                return refused(context, &session, now).await;
            };
            close_one(context, &session, &sid, now).await
        }
    }
}

/// Closes the session a `sid` names, when it is this account's.
async fn close_one(
    context: &SessionsContext<'_>,
    session: &Session,
    sid: &str,
    now: OffsetDateTime,
) -> Response {
    let digest = match context.store.digest_of_sid(sid).await {
        Ok(Some(digest)) => digest,
        // No such `sid` in this tenant. The same page a `sid` belonging to
        // somebody else gets, below.
        Ok(None) => return gone(context, session, now).await,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot resolve a session id");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let named = match context.store.find(&digest).await {
        Ok(Some(named)) => named,
        Ok(None) => return gone(context, session, now).await,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read a session");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    // Somebody else's session and no such session are one answer. The
    // repository is already scoped to this tenant, so what is left to check
    // here is the account.
    if named.user != session.user {
        tracing::info!(
            tenant = %context.account.tenant.id,
            "a revocation named a session that is not the signed-in account's"
        );
        return gone(context, session, now).await;
    }
    // Already revoked, or expired: there is nothing to close, and saying so is
    // what a second press of the same button gets.
    if !named.status(now).is_usable() {
        return gone(context, session, now).await;
    }

    if !revoke(context, &named, now).await {
        return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
    }
    rendered(
        context,
        session,
        Some(context.account.text.sessions_revoked()),
        StatusCode::OK,
        now,
    )
    .await
}

/// Closes every live session of this account except the one submitting.
///
/// The list comes from the store and the exclusion is by digest, so what is
/// closed is decided here and never by the body: "everywhere else" is the one
/// button on these pages a person presses when they believe somebody else is
/// signed in, and it must not be possible to aim it.
async fn close_the_others(
    context: &SessionsContext<'_>,
    session: &Session,
    now: OffsetDateTime,
) -> Response {
    let digests = match context.store.live_digests_for_user(session.user, now).await {
        Ok(digests) => digests,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot list live sessions");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    for digest in digests {
        if digest == session.id_digest {
            continue;
        }
        let named = match context.store.find(&digest).await {
            Ok(Some(named)) => named,
            Ok(None) => continue,
            Err(error) => {
                tracing::error!(%error, tenant = %context.account.tenant.id, "cannot read a session");
                continue;
            }
        };
        // One failure does not stop the others: a person pressing this has
        // decided every other session should end, and closing three of four is
        // strictly better than closing none.
        revoke(context, &named, now).await;
    }
    rendered(
        context,
        session,
        Some(context.account.text.sessions_others_revoked()),
        StatusCode::OK,
        now,
    )
    .await
}

/// Revokes one session and tells everybody who asked to be told.
///
/// Returns whether the revocation itself happened. The notifications after it
/// are best-effort by design — see this module's documentation.
async fn revoke(context: &SessionsContext<'_>, named: &Session, now: OffsetDateTime) -> bool {
    if let Err(error) = context
        .store
        .revoke(&named.id_digest, SessionRevocation::UserLogout, now)
        .await
    {
        tracing::error!(%error, tenant = %context.account.tenant.id, "cannot revoke a session");
        return false;
    }

    record(context, named, now).await;
    let logout_tokens = notify_participants(context, named, now).await;
    // CAEP §3.1: the session named by its public `sid`, which is what a
    // receiver stored when it learned of the session — never the digest, which
    // is this server's own lookup key.
    account::emit_signal(
        &context.account,
        &context.signals,
        &crate::ssf::Cause::SessionRevoked {
            user: UserId::new(named.user),
            sid: named.public_sid.clone(),
            initiator: caep::InitiatingEntity::User,
        },
        now,
    )
    .await;
    tracing::info!(
        tenant = %context.account.tenant.id,
        logout_tokens,
        "a session was closed from the account pages"
    );
    true
}

/// Queues one logout token per participating relying party (§2.2).
///
/// Returns how many were *queued*, not how many relying parties acknowledged
/// one: delivery is the outbox's, is retried, and may end in a dead letter.
/// The end-session endpoint counts the same thing for the same reason.
async fn notify_participants(
    context: &SessionsContext<'_>,
    named: &Session,
    now: OffsetDateTime,
) -> usize {
    let participants = match context.store.participants(&named.id_digest).await {
        Ok(participants) => participants,
        Err(error) => {
            tracing::error!(%error, "cannot read the participants of an ended session");
            return 0;
        }
    };
    if participants.is_empty() {
        return 0;
    }
    let notifier = crate::backchannel::Notifier {
        tenant: context.account.tenant,
        clients: context.signals.clients,
        subjects: context.signals.subjects,
        signer: context.signals.signer,
        outbox: context.signals.outbox,
    };
    notifier.notify(named, &participants, now).await
}

/// The page, with whatever there is to say on it.
async fn rendered(
    context: &SessionsContext<'_>,
    session: &Session,
    message: Option<&str>,
    status: StatusCode,
    now: OffsetDateTime,
) -> Response {
    let held = match context.store.summaries_for_user(session.user).await {
        Ok(held) => held,
        Err(error) => {
            tracing::error!(%error, tenant = %context.account.tenant.id, "cannot list sessions");
            return error_page(&context.account, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let sessions: Vec<SessionLine> = held
        .iter()
        .filter(|summary| summary.is_live(now))
        .map(|summary| line(summary, &session.public_sid))
        .collect();
    let others = sessions.iter().any(|line| !line.current);

    let message = match message {
        Some(message) => Some(message),
        None if !fresh(session, now) => Some(context.account.text.sessions_stale()),
        None => None,
    };

    let font_url = crate::http::font_url(&context.account.mount);
    let action = context.account.mount.absolute(PAGE_PATH);
    let sign_in_href = context.account.mount.absolute(SIGN_IN_PATH);
    let account_href = context.account.mount.absolute(account::PAGE_PATH);
    let csrf = csrf_for(session, CSRF_SEPARATOR);
    let document = Document::render(context.account.nonce, |nonce| {
        pages::render(&AccountSessionsPage {
            text: context.account.text,
            tenant_name: &context.account.tenant.display_name,
            sessions: sessions.clone(),
            others,
            action: &action,
            sign_in_href: &sign_in_href,
            account_href: &account_href,
            csrf: &csrf,
            message,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (status, no_store(), document).into_response()
}

/// One row of the list.
///
/// No user agent and no address: the `sessions` table records neither, and a
/// page cannot show a fact nobody stored. What it does show is what OIDC Core
/// §2's `amr` recorded — identifiers such as `pwd` and `hwk`, joined and
/// rendered as the identifiers they are rather than dressed up as sentences
/// this server would then have to translate.
fn line(summary: &SessionSummary, current: &str) -> SessionLine {
    SessionLine {
        reference: summary.public_sid.clone(),
        started_at: stamp(summary.created_at),
        last_seen_at: stamp(summary.last_seen_at),
        methods: summary
            .amr
            .iter()
            .map(|method| method.as_str().to_owned())
            .collect::<Vec<_>>()
            .join(", "),
        current: summary.public_sid == current,
    }
}

/// The page a submission this server would not read produces.
async fn refused(
    context: &SessionsContext<'_>,
    session: &Session,
    now: OffsetDateTime,
) -> Response {
    rendered(
        context,
        session,
        Some(context.account.text.sessions_gone()),
        StatusCode::BAD_REQUEST,
        now,
    )
    .await
}

/// The page a revocation of something that is not there produces.
///
/// 404, and it is the same 404 for a session belonging to somebody else: see
/// this module's documentation for why there is no 403 here.
async fn gone(context: &SessionsContext<'_>, session: &Session, now: OffsetDateTime) -> Response {
    rendered(
        context,
        session,
        Some(context.account.text.sessions_gone()),
        StatusCode::NOT_FOUND,
        now,
    )
    .await
}

/// Records a revocation.
///
/// [`EventType::SESSION_REVOKED`], the event the admin API and the end-session
/// endpoint write, because it is the same fact. What differs is the actor —
/// the person themselves — and the `reason` label, which is how a reader tells
/// the doors apart. The session is named by its digest through
/// [`AuditEvent::session`], as everywhere else in this server.
async fn record(context: &SessionsContext<'_>, named: &Session, now: OffsetDateTime) {
    let subject = named.user.to_string();
    let event = AuditEvent::new(
        context.account.tenant.id.clone(),
        EventType::SESSION_REVOKED,
        Outcome::Success,
        Actor::User(subject.clone()),
        now,
    )
    .session(DomainSessionId::new(named.id_digest.clone()))
    .subject(subject)
    .detail(Detail::new().label("reason", "account_sessions_page"));

    if let Err(error) = context.audit.record(event).await {
        tracing::error!(
            %error,
            tenant = %context.account.tenant.id,
            "a session revocation was not written to the audit trail"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ordinary submission: a token, a session and the button pressed.
    #[test]
    fn a_submission_names_one_session() {
        // Arrange
        let body = b"csrf=abc&session=sid-one&do=revoke";

        // Act
        let parsed = revocation(body);

        // Assert
        assert_eq!(
            parsed,
            Some(Revocation {
                csrf: "abc".to_owned(),
                verb: Verb::Revoke,
                session: Some("sid-one".to_owned()),
            })
        );
    }

    /// "Everything else" takes no argument: the server decides which rows
    /// those are from the cookie, so a `sid` in the body changes nothing.
    #[test]
    fn closing_the_others_carries_no_session() {
        // Arrange
        let body = b"csrf=abc&session=sid-one&do=others";

        // Act
        let parsed = revocation(body).expect("a well-formed submission");

        // Assert
        assert_eq!(parsed.verb, Verb::Others);
        assert_eq!(parsed.session, None);
    }

    /// Asking to close "this one" without saying which is refused rather than
    /// resolved: guessing would be this server choosing a session to end.
    #[test]
    fn a_revocation_without_a_session_is_refused() {
        assert_eq!(revocation(b"csrf=abc&do=revoke"), None);
    }

    /// RFC 6749 §3.1's parameter pollution, on the field that decides which
    /// session ends.
    #[test]
    fn a_body_naming_two_sessions_is_refused() {
        assert_eq!(revocation(b"csrf=abc&session=a&session=b&do=revoke"), None);
    }

    /// And on the verb.
    #[test]
    fn a_body_naming_two_verbs_is_refused() {
        assert_eq!(revocation(b"csrf=abc&session=a&do=revoke&do=others"), None);
    }

    /// A verb this page does not have is not a verb.
    #[test]
    fn a_verb_this_page_does_not_have_is_refused() {
        assert_eq!(revocation(b"csrf=abc&session=a&do=delete"), None);
    }

    /// A submission with no token is not one this page posts.
    #[test]
    fn a_submission_without_a_token_is_refused() {
        assert_eq!(revocation(b"session=a&do=revoke"), None);
    }

    /// A body this server will not buffer is refused before it is decoded.
    #[test]
    fn an_over_long_body_is_refused() {
        // Arrange
        let body = format!("csrf={}&session=a&do=revoke", "a".repeat(MAX_BODY));

        // Act & assert
        assert_eq!(revocation(body.as_bytes()), None);
    }

    /// A form body is text; bytes that are not are refused rather than lossily
    /// decoded.
    #[test]
    fn a_body_that_is_not_text_is_refused() {
        assert_eq!(revocation(&[0xff, 0xfe, 0xfd]), None);
    }

    /// An identifier longer than anything this server mints is refused: the
    /// `sid` is opaque, so the bound is what there is to check.
    #[test]
    fn an_over_long_session_identifier_is_refused() {
        // Arrange
        let body = format!("csrf=abc&session={}&do=revoke", "s".repeat(257));

        // Act & assert
        assert_eq!(revocation(body.as_bytes()), None);
    }
}
