//! The approvals inbox: where a person answers something that is not in front
//! of them (`ast-lh3.6`).
//!
//! Two flows arrive at the same question. CIBA Core 1.0 §8 has this server
//! identify the end user, authenticate them *on the authentication device*,
//! and then "obtain an authorization decision as described in Section 3.1.2.4
//! of OpenID Core" — a decision taken on a device the client never touches.
//! RFC 8628 §3.3 has a person type a code into a browser on behalf of a device
//! that has no browser. Both are "something elsewhere wants to act as you";
//! both are answered here.
//!
//! Three routes:
//!
//! * `GET /account/approvals` lists what is waiting, with §7.1's
//!   `binding_message`, what each request asks for, and how long it has left;
//! * `POST /account/approvals/decide` records one answer;
//! * `GET /account/approvals/sign-in` opens a fresh authentication for a
//!   person whose session is too old or too weak to approve with.
//!
//! # Only CIBA is listed, and the device flow is entered
//!
//! A CIBA request names a user before anybody is asked: §7.2 resolves a hint
//! to an account, which is what makes a *list* possible. A device
//! authorization does not — RFC 8628 §3.1 happens before anybody is
//! identified, so there is nothing to attribute to an inbox until a code is
//! typed. So the page lists CIBA requests and carries the device flow's code
//! entry, posting to the same `/device` the printed `verification_uri` leads
//! to. Agent scope elevation is neither: this server has no agent step-up
//! mechanism to list yet (`ast-lh3.6` SUITE).
//!
//! # An approval is a fresh, sufficient authentication, or it is a step-up
//!
//! Two conditions, and they are separate questions.
//!
//! * **Fresh.** The session must have authenticated within [`FRESHNESS`].
//!   OIDC Core §3.1.2.1 gives `max_age` the same shape, and the reason is the
//!   same one: an approval that can be given by a browser somebody left open
//!   in a café this morning is an approval an attacker gets for free. A stale
//!   session is not refused — it is sent to authenticate again and comes back.
//! * **Sufficient.** §7.1's `acr_values` is what the *client* asked the
//!   person's authentication to be worth, and it is honoured here rather than
//!   at the token endpoint, because this is the only moment a person is
//!   present. A session that reaches none of the requested levels is told so
//!   and offered the sign-in again; it is not redirected, because a redirect
//!   that cannot fix the problem is a loop.
//!
//! The criterion this bead was written with says "a fresh **passkey**
//! authentication". What is implemented is the tenant's ladder
//! ([`asterius_domain::AcrPolicy`]) rather than a hard-coded method, for the
//! reason `crate::http::device` gives at its own admission check: a deployment
//! that has configured no passkeys would otherwise have an inbox nobody can
//! ever answer, and the ladder is where this server already writes down what
//! an authentication is worth. On the default ladder a request that asks for
//! `urn:asterius:acr:passkey` is answerable only by a passkey.
//!
//! # Nothing here distinguishes its failures
//!
//! Expired, already decided, somebody else's, never existed: one sentence for
//! all four ([`asterius_web::i18n::MessageKey::ApprovalsGone`]). The person in
//! front of this page cannot act on the difference, and each distinction is an
//! answer to a question about a request they may not hold. The same reasoning
//! the device pages give for their single refusal.
//!
//! # CSRF
//!
//! Both forms carry a synchroniser token derived from the session's *digest*,
//! which the browser does not hold — `crate::http::device::csrf_for`'s
//! argument, under a separator of this page's own. A forged approval would
//! hand an attacker a credential on somebody else's account, which is the
//! highest-value cross-site request this server has.

use asterius_domain::audit::trail::keys;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::rate_limit::{RateLimit, RateLimitStore, approval_decision_bucket};
use asterius_domain::{
    AcrPolicy, ClientRepository, FirstPartyDestination, Grant, GrantRepository,
    InteractionRepository, SectorIdentifier, Session, SessionId as DomainSessionId,
    SessionRepository, SubjectResolver, Tenant, UserId, entities::session,
};
use asterius_store_pg::{PendingApproval, PgCibaRequestRepository};
use asterius_web::Brand;
use asterius_web::i18n::Catalog;
use asterius_web::interaction::{self, InteractionId};
use asterius_web::pages::{
    self, ApprovalLine, ApprovalsPage, ErrorPage, ScopeLine, nonce_attribute,
};
use asterius_web::{Document, csp::Nonce};
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::{Duration, OffsetDateTime};

use crate::http::redirect::SeeOther;
use crate::tenancy::MountPrefix;

/// Where the inbox lives.
pub const PAGE_PATH: &str = "/account/approvals";

/// Where a decision posts.
pub const DECIDE_PATH: &str = "/account/approvals/decide";

/// Where a person goes to authenticate again.
pub const SIGN_IN_PATH: &str = "/account/approvals/sign-in";

/// How recently an approver must have authenticated.
///
/// Two minutes, from this bead's acceptance criterion, and the same order of
/// magnitude as the five-minute ceiling a CIBA request itself lives under
/// (§7.3): long enough to read a page and press a button, short enough that
/// the authentication and the decision are one act rather than two.
pub const FRESHNESS: Duration = Duration::seconds(120);

/// How long a sign-in opened from this page stays open.
///
/// The device page's ten minutes, for its reason: long enough for somebody
/// typing a password, short enough that an abandoned login goes away.
const ENTRY_LIFETIME: Duration = Duration::minutes(10);

/// Decisions one session may post per [`DECISION_WINDOW`] (`ast-5lw`).
///
/// Twenty, which is four times the number of requests one person may have
/// waiting ([`asterius_oidc::ciba::MAX_PENDING_PER_USER`]) and so leaves room for a person
/// clearing a full inbox, changing their mind, and reloading the page. What it
/// refuses is a script: an approval posted in a loop, either by somebody who
/// has stolen a session or by a page that has found a way to post one.
///
/// A constant rather than a configuration key, for the reason
/// [`asterius_domain::admin_api_bucket`] has no key either: this is a
/// first-party form a signed-in person submits, not a protocol surface an
/// operator tunes against traffic they do not control.
pub const DECISIONS_PER_WINDOW: u32 = 20;

/// The window those decisions are counted in.
///
/// The device verification page's ten minutes, so the two pages a person may
/// be moving between behave the same way.
pub const DECISION_WINDOW: Duration = Duration::minutes(10);

/// The largest decision body this page will read.
///
/// A synchroniser token, a digest and a word. Four kilobytes is the device
/// pages' bound and is already generous; a bound is what stops an
/// unauthenticated caller making this server buffer.
pub const MAX_BODY: usize = 4 * 1024;

/// The characters an approval reference is written in.
///
/// Lower-case hex, because the reference is [`asterius_domain::sha256_hex`]'s
/// output and nothing else is ever a valid one. Checked before the store is
/// asked, so a submission that could not name a row costs a comparison rather
/// than a query.
const REFERENCE_CHARS: usize = 64;

/// The longest synchroniser token this parser will carry.
///
/// The real one is 64 hex characters. The bound is not a format check — it is
/// the promise that a caller cannot make this function allocate without limit
/// inside a body that is itself bounded.
const MAX_CSRF_CHARS: usize = 256;

/// What a person decided about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// CIBA Core 1.0 §10.1: the client may redeem.
    Approve,
    /// §11's `access_denied`, and it is a decision rather than a silence: the
    /// client is told rather than left to time out.
    Deny,
}

/// A decision form, after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The synchroniser token the form carried.
    pub csrf: String,
    /// Which request is being answered: the `auth_req_id` digest, hex.
    pub approval: String,
    /// Which answer.
    pub verdict: Verdict,
}

/// Reads a decision form, or refuses it.
///
/// Every refusal is `None`, because the caller answers all of them with one
/// page: a body that is too large, that is not UTF-8, that names a parameter
/// twice (RFC 6749 §3.1's parameter pollution, applied to this server's own
/// forms for the reason the token endpoint applies it to a client's), that
/// carries a reference which is not a digest, or that says something other
/// than approve or deny.
///
/// The reference is checked for *shape* here and for *ownership* in the
/// statement that acts on it: this function cannot know whose request it is,
/// and a validator that pretended to would be the one place somebody later
/// trusted instead of the predicate.
// fuzz-target: approval_decision
#[must_use]
pub fn decision(body: &[u8]) -> Option<Decision> {
    if body.len() > MAX_BODY {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;

    let mut csrf: Option<String> = None;
    let mut approval: Option<String> = None;
    let mut verdict: Option<Verdict> = None;
    for (key, value) in url::form_urlencoded::parse(text.as_bytes()) {
        // A repeated parameter is refused outright rather than resolved to the
        // first or the last. Both resolutions are a choice an attacker can
        // exploit once anything downstream makes the other one.
        match key.as_ref() {
            "csrf" if csrf.is_some() => return None,
            "csrf" => csrf = Some(value.into_owned()),
            "approval" if approval.is_some() => return None,
            "approval" => approval = Some(value.into_owned()),
            "decision" if verdict.is_some() => return None,
            "decision" => {
                verdict = Some(match value.as_ref() {
                    "approve" => Verdict::Approve,
                    "deny" => Verdict::Deny,
                    _ => return None,
                });
            }
            _ => {}
        }
    }

    let csrf = csrf?;
    let approval = approval?;
    if csrf.is_empty() || csrf.chars().count() > MAX_CSRF_CHARS {
        return None;
    }
    if approval.len() != REFERENCE_CHARS
        || !approval
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some(Decision {
        csrf,
        approval,
        verdict: verdict?,
    })
}

/// What the inbox needs.
pub struct ApprovalsContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// The backchannel requests waiting for this person.
    pub ciba_requests: &'a PgCibaRequestRepository,
    /// Where the cookie's session is resolved.
    pub sessions: &'a dyn SessionRepository,
    /// Where a sign-in is opened for a visitor who has none.
    pub interactions: &'a dyn InteractionRepository,
    /// This tenant's clients, for the names the page shows.
    pub clients: &'a dyn ClientRepository,
    /// Where an approval's authorization is recorded.
    pub grants: &'a dyn GrantRepository,
    /// How the `sub` the client will see is resolved (OIDC Core §8.1).
    pub subjects: &'a dyn SubjectResolver,
    /// The authentication contexts this tenant can produce (`ast-2vk.7`).
    pub acr: &'a AcrPolicy,
    /// The words this page is rendered with.
    pub text: &'a Catalog,
    /// The CSP nonce the document middleware drew for this response.
    pub nonce: &'a Nonce,
    /// Where a decision is recorded.
    pub audit: &'a dyn AuditSink,
    /// Where this session's decision budget is counted (`ast-5lw`).
    pub limits: &'a dyn RateLimitStore,
    /// The prefix routing removed from this request's path (`ast-295`).
    pub mount: MountPrefix,
}

impl std::fmt::Debug for ApprovalsContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalsContext").finish_non_exhaustive()
    }
}

/// `GET /account/approvals` — what is waiting.
pub async fn page(
    context: &ApprovalsContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = admitted(context, headers, now).await else {
        return begin(context, now).await;
    };
    rendered(context, &session, None, StatusCode::OK, now).await
}

/// `GET /account/approvals/sign-in` — authenticate again, and come back.
///
/// A route rather than a link into the interaction pages, because the
/// interaction has to be *opened* and its destination is a variant of a closed
/// enumeration rather than a URL anybody can supply (ADR-0009). It is a `GET`
/// that writes a row, which is what every first-party entry point here is; the
/// row is a ten-minute login attempt and nothing about this account changes.
pub async fn sign_in(context: &ApprovalsContext<'_>, now: OffsetDateTime) -> Response {
    begin(context, now).await
}

/// `POST /account/approvals/decide` — one answer.
pub async fn decide(
    context: &ApprovalsContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = admitted(context, headers, now).await else {
        return begin(context, now).await;
    };
    // Before the body is read, so a flood of malformed submissions costs the
    // same budget as a flood of well-formed ones. Keyed by the session rather
    // than by the address: the address is a person's home connection, and a
    // household behind one of them is several approvers.
    if self::throttled(context.limits, &context.tenant.id, &session, now).await {
        return too_many_decisions(context, &session, now).await;
    }
    let Some(form) = decision(body) else {
        return refused(context, &session, now).await;
    };
    if !checked_csrf(&session, &form.csrf) {
        return refused(context, &session, now).await;
    }
    let user = UserId::new(session.user);

    match form.verdict {
        Verdict::Deny => denied(context, &session, &user, &form.approval, now).await,
        Verdict::Approve => approved(context, &session, &user, &form.approval, now).await,
    }
}

/// §11's `access_denied`, recorded.
///
/// No freshness requirement and no `acr` requirement, deliberately: refusing is
/// the safe direction, and a person who has just been shown a request they did
/// not start must be able to stop it with the session they already have.
/// Nothing is granted by saying no.
async fn denied(
    context: &ApprovalsContext<'_>,
    session: &Session,
    user: &UserId,
    reference: &str,
    now: OffsetDateTime,
) -> Response {
    // Read first, so the trail can name the client that was refused. A row
    // that moves between this read and the write below is reported as gone,
    // which is what a second submission of the same form gets.
    let pending = match context
        .ciba_requests
        .pending_for_user_by_id(user, reference, now)
        .await
    {
        Ok(pending) => pending,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a pending approval");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    match context.ciba_requests.deny(reference, user, now).await {
        Ok(true) => {
            record(
                context,
                session,
                EventType::CONSENT_DENIED,
                reference,
                pending.as_ref().map(|pending| pending.client_id.as_str()),
                None,
                now,
            )
            .await;
            rendered(
                context,
                session,
                Some(context.text.approvals_denied()),
                StatusCode::OK,
                now,
            )
            .await
        }
        Ok(false) => gone(context, session, now).await,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot refuse an approval");
            error_page(context, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// §8's authorization decision, with the two conditions in front of it.
async fn approved(
    context: &ApprovalsContext<'_>,
    session: &Session,
    user: &UserId,
    reference: &str,
    now: OffsetDateTime,
) -> Response {
    // Freshness first, because it is about the *approver* and is decided
    // without touching the row: a session too old to approve with is too old
    // to approve anything with, and sending it to authenticate again is the
    // answer to all of them.
    if !fresh(session, now) {
        return begin(context, now).await;
    }

    let pending = match context
        .ciba_requests
        .pending_for_user_by_id(user, reference, now)
        .await
    {
        Ok(Some(pending)) => pending,
        Ok(None) => return gone(context, session, now).await,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a pending approval");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    // §7.1's `acr_values`: what the client asked this person's authentication
    // to be worth. A session that reaches none of them is told so rather than
    // redirected, because a redirect that cannot fix the problem is a loop.
    if !strong_enough(context, session, &pending) {
        tracing::info!(
            tenant = %context.tenant.id,
            "an approval was attempted by a session that reaches none of the requested acr values"
        );
        return rendered(
            context,
            session,
            Some(context.text.approvals_step_up()),
            StatusCode::FORBIDDEN,
            now,
        )
        .await;
    }

    let Some(grant) = authorization(context, session, &pending, now).await else {
        // This server's failure, not a decision: it must not read as one.
        return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
    };

    match context
        .ciba_requests
        .approve(reference, user, &grant, now)
        .await
    {
        // The row moved between the read and this write — a second tab, a
        // double-clicked button, an expiry a moment ago. The grant just
        // created is left `Pending` and unclaimed, which is the state Grant
        // Management ID1 §5.6 has for an authorization no credential was taken
        // from, and retention removes it. This is also the whole of "a request
        // cannot be approved twice": the statement's predicate is `pending`.
        Ok(false) => gone(context, session, now).await,
        Ok(true) => {
            record(
                context,
                session,
                EventType::CONSENT_GRANTED,
                reference,
                Some(pending.client_id.as_str()),
                Some(&grant),
                now,
            )
            .await;
            rendered(
                context,
                session,
                Some(context.text.approvals_approved()),
                StatusCode::OK,
                now,
            )
            .await
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot approve a request");
            error_page(context, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// Whether this authentication happened recently enough to approve with.
fn fresh(session: &Session, now: OffsetDateTime) -> bool {
    now - session.authenticated_at <= FRESHNESS && session.authenticated_at <= now
}

/// Whether this session reaches what the request asked for (§7.1).
///
/// A request that named no `acr_values` has asked for nothing in particular,
/// and the admission check has already refused a session this tenant cannot
/// classify at all.
fn strong_enough(
    context: &ApprovalsContext<'_>,
    session: &Session,
    pending: &PendingApproval,
) -> bool {
    pending.acr_values.is_empty()
        || context
            .acr
            .strongest_met(&pending.acr_values, &session.amr)
            .is_some()
}

/// Creates the grant an approval records.
///
/// The device page's `approval`, with one difference that matters: the
/// authentication recorded on the grant is the *approver's*, which is what the
/// ID token minted from it will carry as `auth_time` and `acr` (CIBA Core 1.0
/// §7.4). A CIBA ID token describes an authentication that happened here, on
/// this page, and nowhere else.
async fn authorization(
    context: &ApprovalsContext<'_>,
    session: &Session,
    pending: &PendingApproval,
    now: OffsetDateTime,
) -> Option<asterius_domain::GrantId> {
    let client_id = asterius_domain::ClientId::new(pending.client_id.clone());
    let client = match context.clients.find(&client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            tracing::error!(
                tenant = %context.tenant.id,
                "a pending approval names a client that no longer exists"
            );
            return None;
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a client");
            return None;
        }
    };
    let Ok(sector) = SectorIdentifier::of_client(&client) else {
        tracing::error!(tenant = %context.tenant.id, "this client has no sector to identify in");
        return None;
    };
    let user = UserId::new(session.user);
    let subject = match context.subjects.subject(user, &sector).await {
        Ok(subject) => subject,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot resolve a subject");
            return None;
        }
    };

    let mut grant = Grant::new(context.tenant.id.clone(), client.id.clone(), now);
    grant.user = Some(user);
    grant.subject = Some(subject);
    grant.scopes = pending.scopes.iter().cloned().collect();
    grant.authorization_details = pending
        .authorization_details
        .as_array()
        .cloned()
        .unwrap_or_default();
    grant.session = Some(DomainSessionId::new(session.id_digest.clone()));
    grant.authentication = Some(asterius_domain::GrantAuthentication {
        authenticated_at: session.authenticated_at,
        acr: session.acr.clone(),
        amr: session.amr.clone(),
    });

    let id = grant.id.clone();
    match context.grants.create(&grant).await {
        Ok(()) => Some(id),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot record an approval's grant");
            None
        }
    }
}

/// The session behind the cookie, when it is one this tenant will let approve.
///
/// The device page's admission, for its reasons: the session must be usable
/// and belong to this tenant, and where the tenant has an authentication
/// ladder the session must reach a rung of it. A tenant that has configured no
/// levels has expressed no requirement, and inventing one here would leave
/// such a deployment with an inbox nobody can answer.
async fn admitted(
    context: &ApprovalsContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Option<Session> {
    let cookies = crate::http::cookies(headers);
    let value = interaction::cookie_value(&cookies, session::COOKIE_NAME)?;
    let digest = asterius_domain::sha256_hex(value.as_bytes());
    let session = match context.sessions.find(&digest).await {
        Ok(session) => session?,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a session");
            return None;
        }
    };
    if session.tenant != context.tenant.id || !session.status(now).is_usable() {
        return None;
    }
    if !context.acr.levels().is_empty() && context.acr.achieved(&session.amr).is_none() {
        tracing::info!(
            tenant = %context.tenant.id,
            "the approvals inbox was asked for by a session this tenant cannot classify"
        );
        return None;
    }
    Some(session)
}

/// The synchroniser token for this session, under this page's separator.
///
/// Derived from the session's *digest*, which the browser does not hold: a
/// page forged on another origin can make the browser send the session cookie,
/// which is the whole of what CSRF is, but it cannot read it and so cannot
/// compute this.
fn csrf_for(session: &Session) -> String {
    asterius_domain::sha256_hex(format!("{}:approvals-csrf", session.id_digest).as_bytes())
}

/// Compares a submitted token against the one this session's pages carry.
fn checked_csrf(session: &Session, presented: &str) -> bool {
    asterius_domain::ct_eq(presented.as_bytes(), csrf_for(session).as_bytes())
}

/// The page, with whatever there is to say on it.
async fn rendered(
    context: &ApprovalsContext<'_>,
    session: &Session,
    message: Option<&str>,
    status: StatusCode,
    now: OffsetDateTime,
) -> Response {
    let pending = match context
        .ciba_requests
        .pending_for_user(&UserId::new(session.user), now)
        .await
    {
        Ok(pending) => pending,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot list pending approvals");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    let mut approvals = Vec::with_capacity(pending.len());
    for request in pending {
        approvals.push(line(context, request, now).await);
    }

    // A stale session is shown the page and told to sign in again rather than
    // being redirected out of it: the redirect belongs to the moment somebody
    // presses Approve, not to the moment they read the list.
    let message = match message {
        Some(message) => Some(message),
        None if !fresh(session, now) && !approvals.is_empty() => {
            Some(context.text.approvals_stale())
        }
        None => None,
    };

    let font_url = crate::http::font_url(&context.mount);
    let action = context.mount.absolute(DECIDE_PATH);
    let device_action = context.mount.absolute(crate::http::device::PAGE_PATH);
    let sign_in_href = context.mount.absolute(SIGN_IN_PATH);
    let csrf = csrf_for(session);
    let device_csrf = crate::http::device::csrf_for(session);
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&ApprovalsPage {
            text: context.text,
            tenant_name: &context.tenant.display_name,
            approvals: approvals.clone(),
            action: &action,
            device_action: &device_action,
            sign_in_href: &sign_in_href,
            csrf: &csrf,
            device_csrf: &device_csrf,
            message,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (status, no_store(), document).into_response()
}

/// One row of the list.
async fn line(
    context: &ApprovalsContext<'_>,
    request: PendingApproval,
    now: OffsetDateTime,
) -> ApprovalLine {
    ApprovalLine {
        client_name: client_name(context, &request.client_id).await,
        scopes: request
            .scopes
            .iter()
            .map(|scope| ScopeLine {
                // No description, for the reason the device confirmation gives:
                // the sentences a tenant writes for its scopes belong to the
                // consent screen, and a half-populated copy of them would show
                // a described scope on one page and a bare token on the other.
                name: scope.clone(),
                description: None,
                required: true,
            })
            .collect(),
        authorization_details: crate::http::device::detail_lines(&request.authorization_details),
        expires_in: remaining(request.expires_at - now),
        expires_at: request
            .expires_at
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        binding_message: request.binding_message,
        reference: request.auth_req_id_digest,
    }
}

/// A duration, as digits and unit symbols.
///
/// Rendered here rather than in the template and without a script, because the
/// page must work with scripting disabled: what a person needs is "is this
/// about to run out", and a number they can read is that. Unit *symbols*
/// rather than words, so the one string is as close to language-neutral as a
/// duration gets — the sentence around it is what the catalogue translates.
///
/// Negative and zero both render `0 s`: a request that ran out between the
/// query and the rendering is gone rather than owed a negative countdown.
fn remaining(left: Duration) -> String {
    let seconds = left.whole_seconds().max(0);
    if seconds < 60 {
        return format!("{seconds} s");
    }
    format!("{} min {} s", seconds / 60, seconds % 60)
}

/// The client's registered name, or a placeholder.
///
/// A name chosen at registration, escaped into the markup like the one on the
/// consent screen and trusted as little.
async fn client_name(context: &ApprovalsContext<'_>, client_id: &str) -> String {
    let client_id = asterius_domain::ClientId::new(client_id.to_owned());
    match context.clients.find(&client_id).await {
        Ok(Some(client)) => client.registration.client_name.clone(),
        Ok(None) => "an unknown application".to_owned(),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a client name");
            "an unknown application".to_owned()
        }
    }
}

/// Whether this session has spent its decision budget (`ast-5lw`).
///
/// Counted on the way in, so a refusal costs the budget as much as an approval
/// does — what is bounded is submissions, not outcomes.
///
/// A counter that cannot be read is reported as spent, the direction
/// `crate::http::device`'s budget fails in: the alternative is a limiter an
/// attacker switches off by loading the database.
async fn throttled(
    limits: &dyn RateLimitStore,
    tenant: &asterius_domain::TenantId,
    session: &Session,
    now: OffsetDateTime,
) -> bool {
    let limit = decision_limit();
    let bucket = approval_decision_bucket(&session.id_digest);
    match limits
        .record(
            tenant,
            &bucket,
            limit.window_start(now),
            limit.window_end(now),
        )
        .await
    {
        Ok(counted) => !limit.admits(counted.saturating_sub(1)),
        Err(error) => {
            tracing::error!(%error, %tenant, "cannot count an approval decision");
            true
        }
    }
}

/// The per-session budget, as the limiter's own type.
const fn decision_limit() -> RateLimit {
    RateLimit {
        max: DECISIONS_PER_WINDOW,
        window: DECISION_WINDOW,
    }
}

/// The page a session that has spent its budget produces.
///
/// 429 with `Retry-After`, like every other throttled surface here, and the
/// inbox itself underneath it: a person who waited out the window presses the
/// button again on a page that is still correct.
///
/// One trail record per window rather than one per submission
/// ([`asterius_domain::audited_once_bucket`]), for the reason
/// `crate::http::limits` keeps to it: a trail that grows with the flood is a
/// place to bury everything else.
async fn too_many_decisions(
    context: &ApprovalsContext<'_>,
    session: &Session,
    now: OffsetDateTime,
) -> Response {
    let limit = decision_limit();
    let retry_after = limit.retry_after(now).whole_seconds().max(1);
    if self::first_refusal_in_window(context, session, now).await {
        let record = AuditEvent::new(
            context.tenant.id.clone(),
            EventType::REQUEST_THROTTLED,
            Outcome::Failure,
            Actor::User(session.user.to_string()),
            now,
        )
        .session(DomainSessionId::new(session.id_digest.clone()))
        .detail(
            Detail::new()
                .label("endpoint", "approval_decision")
                .label("limit", "session")
                .number("retry_after_seconds", retry_after),
        );
        if let Err(error) = context.audit.record(record).await {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot record a throttled approval decision");
        }
    }
    let page = rendered(
        context,
        session,
        Some(context.text.approvals_throttled()),
        StatusCode::TOO_MANY_REQUESTS,
        now,
    )
    .await;
    with_retry_after(page, retry_after)
}

/// Whether this is the first refusal for this session in this window.
///
/// A marker counter beside the one that was full, written once: the first
/// write returns `1`, and a marker that cannot be written is reported as "not
/// the first", which loses a record rather than risking a flood of them.
async fn first_refusal_in_window(
    context: &ApprovalsContext<'_>,
    session: &Session,
    now: OffsetDateTime,
) -> bool {
    let limit = decision_limit();
    let marker =
        asterius_domain::audited_once_bucket(&approval_decision_bucket(&session.id_digest));
    match context
        .limits
        .record(
            &context.tenant.id,
            &marker,
            limit.window_start(now),
            limit.window_end(now),
        )
        .await
    {
        Ok(counted) => counted == 1,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "a throttle marker was not written");
            false
        }
    }
}

/// Adds `Retry-After` to a response that is already rendered.
fn with_retry_after(mut response: Response, seconds: i64) -> Response {
    if let Ok(value) = HeaderValue::from_str(&seconds.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

/// The page a submission this server would not read produces.
async fn refused(
    context: &ApprovalsContext<'_>,
    session: &Session,
    now: OffsetDateTime,
) -> Response {
    rendered(
        context,
        session,
        Some(context.text.approvals_gone()),
        StatusCode::BAD_REQUEST,
        now,
    )
    .await
}

/// The page a decision about a request that is no longer pending produces.
async fn gone(context: &ApprovalsContext<'_>, session: &Session, now: OffsetDateTime) -> Response {
    rendered(
        context,
        session,
        Some(context.text.approvals_gone()),
        StatusCode::CONFLICT,
        now,
    )
    .await
}

/// The page a failure of *this server* produces.
fn error_page(context: &ApprovalsContext<'_>, status: StatusCode) -> Response {
    let font_url = crate::http::font_url(&context.mount);
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            text: context.text,
            tenant_name: &context.tenant.display_name,
            message: "This did not work. Nothing was decided.",
            correlation_id: "",
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (status, no_store(), document).into_response()
}

/// Opens a first-party interaction and sends the browser to its login page.
///
/// The device page's `begin`, with this page's destination: 303 so the browser
/// fetches the next page rather than repeating this request, the id in both the
/// URL and a `__Host-` cookie so a leaked URL is inert without the cookie (FAPI
/// 2.0 SP §6.5), and `no-store` because the response carries a credential.
async fn begin(context: &ApprovalsContext<'_>, now: OffsetDateTime) -> Response {
    let id = InteractionId::generate();
    if let Err(error) = context
        .interactions
        .begin_first_party_interaction(
            &id.digest(),
            FirstPartyDestination::ApprovalsInbox,
            now + ENTRY_LIFETIME,
            now,
        )
        .await
    {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot open a sign-in for the inbox");
        return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
    }

    // Relative, for `console::location_of`'s reason: the tenant prefix is not
    // visible from here, and `interaction/{id}` resolved against
    // `/t/x/account/approvals` is this tenant's interaction page.
    let Ok(redirect) = SeeOther::to(&format!("../interaction/{}", id.expose())) else {
        tracing::error!(tenant = %context.tenant.id, "an interaction id is not a usable Location");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = redirect.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = interaction::set_cookie(&id).parse() {
        headers.insert(header::SET_COOKIE, value);
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Records what a person decided (`ast-lh3.9`'s `approval_id`).
///
/// The approval is named by the fingerprint of its `auth_req_id` — the same
/// value `Detail::credential` would produce from the identifier itself, so the
/// decision here and the issuance at the token endpoint are joinable — and
/// never by the identifier, which is the credential the client polls with.
async fn record(
    context: &ApprovalsContext<'_>,
    session: &Session,
    event: EventType,
    reference: &str,
    client_id: Option<&str>,
    grant: Option<&asterius_domain::GrantId>,
    now: OffsetDateTime,
) {
    let mut record = AuditEvent::new(
        context.tenant.id.clone(),
        event,
        Outcome::Success,
        Actor::User(session.user.to_string()),
        now,
    )
    .session(DomainSessionId::new(session.id_digest.clone()))
    .detail(
        Detail::new()
            .label("flow", "ciba")
            .raw_fingerprint(keys::APPROVAL_ID, reference),
    );
    if let Some(client_id) = client_id {
        record = record.client(asterius_domain::ClientId::new(client_id.to_owned()));
    }
    if let Some(grant) = grant {
        record = record.grant(grant.clone());
    }
    if let Err(error) = context.audit.record(record).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot record an approval decision");
    }
}

/// Every response from this page carries a decision, a credential or a clock.
fn no_store() -> [(header::HeaderName, HeaderValue); 1] {
    [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    const REFERENCE: &str = "0f9d0f9d0f9d0f9d0f9d0f9d0f9d0f9d0f9d0f9d0f9d0f9d0f9d0f9d0f9d0f9d";

    /// The ordinary form: a token, a reference, a verdict.
    #[test]
    fn a_decision_form_names_one_request_and_one_answer() {
        // Arrange
        let form = body(&format!("csrf=abc&approval={REFERENCE}&decision=approve"));

        // Act
        let parsed = decision(&form);

        // Assert
        assert_eq!(
            parsed,
            Some(Decision {
                csrf: "abc".to_owned(),
                approval: REFERENCE.to_owned(),
                verdict: Verdict::Approve,
            })
        );
    }

    /// RFC 6749 §3.1's parameter pollution, applied to this server's own form:
    /// a body naming two verdicts is a body where the answer depends on which
    /// one this parser preferred.
    #[test]
    fn a_form_that_answers_twice_is_refused() {
        // Arrange
        let form = body(&format!(
            "csrf=abc&approval={REFERENCE}&decision=approve&decision=deny"
        ));

        // Act
        let parsed = decision(&form);

        // Assert
        assert_eq!(parsed, None);
    }

    /// Counters in memory. Enough to assert what the decision budget decides;
    /// the server counts in the `rate_limits` table, because a per-process
    /// counter limits nothing across replicas.
    #[derive(Debug, Default)]
    struct Counters(std::sync::Mutex<std::collections::BTreeMap<String, u32>>);

    #[async_trait::async_trait]
    impl RateLimitStore for Counters {
        async fn count(
            &self,
            _tenant: &asterius_domain::TenantId,
            bucket: &asterius_domain::Bucket,
            _window_start: OffsetDateTime,
        ) -> Result<u32, asterius_domain::DomainError> {
            let counters = self.0.lock().expect("the test store is not poisoned");
            Ok(counters.get(bucket.as_str()).copied().unwrap_or(0))
        }

        async fn record(
            &self,
            _tenant: &asterius_domain::TenantId,
            bucket: &asterius_domain::Bucket,
            _window_start: OffsetDateTime,
            _expires_at: OffsetDateTime,
        ) -> Result<u32, asterius_domain::DomainError> {
            let mut counters = self.0.lock().expect("the test store is not poisoned");
            let entry = counters.entry(bucket.as_str().to_owned()).or_default();
            *entry += 1;
            Ok(*entry)
        }

        async fn clear(
            &self,
            _tenant: &asterius_domain::TenantId,
            _bucket: &asterius_domain::Bucket,
        ) -> Result<(), asterius_domain::DomainError> {
            Ok(())
        }
    }

    /// A store that is down. A limiter that cannot be read must not be a
    /// limiter that is off.
    #[derive(Debug)]
    struct Broken;

    #[async_trait::async_trait]
    impl RateLimitStore for Broken {
        async fn count(
            &self,
            _tenant: &asterius_domain::TenantId,
            _bucket: &asterius_domain::Bucket,
            _window_start: OffsetDateTime,
        ) -> Result<u32, asterius_domain::DomainError> {
            Err(asterius_domain::DomainError::Storage("down".into()))
        }

        async fn record(
            &self,
            _tenant: &asterius_domain::TenantId,
            _bucket: &asterius_domain::Bucket,
            _window_start: OffsetDateTime,
            _expires_at: OffsetDateTime,
        ) -> Result<u32, asterius_domain::DomainError> {
            Err(asterius_domain::DomainError::Storage("down".into()))
        }

        async fn clear(
            &self,
            _tenant: &asterius_domain::TenantId,
            _bucket: &asterius_domain::Bucket,
        ) -> Result<(), asterius_domain::DomainError> {
            Err(asterius_domain::DomainError::Storage("down".into()))
        }
    }

    fn tenant_id() -> asterius_domain::TenantId {
        asterius_domain::TenantId::parse("demo").expect("`demo` is a valid tenant id")
    }

    fn a_session() -> Session {
        Session::begin(
            tenant_id(),
            &session::SessionId::generate(),
            uuid::Uuid::from_u128(1),
            vec![],
            OffsetDateTime::UNIX_EPOCH,
            session::Lifetimes::default(),
        )
    }

    /// `ast-5lw`: a person clearing a full inbox is not throttled, and the
    /// submission after the budget is spent is.
    #[tokio::test]
    async fn a_session_may_decide_until_its_budget_is_spent() {
        // Arrange
        let store = Counters::default();
        let session = a_session();
        let now = OffsetDateTime::UNIX_EPOCH;

        // Act
        let mut admitted = 0;
        for _ in 0..DECISIONS_PER_WINDOW {
            if !throttled(&store, &tenant_id(), &session, now).await {
                admitted += 1;
            }
        }
        let refused = throttled(&store, &tenant_id(), &session, now).await;

        // Assert
        assert_eq!(admitted, DECISIONS_PER_WINDOW);
        assert!(refused);
    }

    /// The budget is one session's, not one deployment's: a person who has
    /// spent theirs cannot stop anybody else deciding.
    #[tokio::test]
    async fn one_sessions_budget_is_not_another_sessions() {
        // Arrange
        let store = Counters::default();
        let spent = a_session();
        let other = a_session();
        let now = OffsetDateTime::UNIX_EPOCH;
        for _ in 0..=DECISIONS_PER_WINDOW {
            throttled(&store, &tenant_id(), &spent, now).await;
        }

        // Act
        let elsewhere = throttled(&store, &tenant_id(), &other, now).await;

        // Assert
        assert!(!elsewhere);
    }

    /// A counter that cannot be read is not permission to stop counting.
    #[tokio::test]
    async fn a_limiter_that_cannot_be_read_refuses() {
        // Arrange
        let store = Broken;
        let session = a_session();

        // Act
        let refused = throttled(&store, &tenant_id(), &session, OffsetDateTime::UNIX_EPOCH).await;

        // Assert
        assert!(refused);
    }

    /// The reference is a digest or it is nothing: the store is not asked to
    /// look up a shape that could never be a row.
    #[test]
    fn a_reference_that_is_not_a_digest_is_refused() {
        // Arrange
        let short = body("csrf=abc&approval=0f9d&decision=deny");
        let upper = body(&format!(
            "csrf=abc&approval={}&decision=deny",
            REFERENCE.to_uppercase()
        ));

        // Act & assert
        assert_eq!(decision(&short), None);
        assert_eq!(decision(&upper), None);
    }

    /// A verdict this page does not offer is not a verdict.
    #[test]
    fn a_third_answer_is_refused() {
        // Arrange
        let form = body(&format!("csrf=abc&approval={REFERENCE}&decision=maybe"));

        // Act
        let parsed = decision(&form);

        // Assert
        assert_eq!(parsed, None);
    }

    /// A body this server will not buffer is refused before it is decoded.
    #[test]
    fn an_over_long_body_is_refused() {
        // Arrange
        let form = body(&format!(
            "csrf={}&approval={REFERENCE}&decision=deny",
            "a".repeat(MAX_BODY)
        ));

        // Act
        let parsed = decision(&form);

        // Assert
        assert_eq!(parsed, None);
    }

    /// A form body is text; bytes that are not are refused rather than
    /// lossily decoded into something that parses.
    #[test]
    fn a_body_that_is_not_text_is_refused() {
        // Arrange
        let form = vec![0xff, 0xfe, 0xfd];

        // Act
        let parsed = decision(&form);

        // Assert
        assert_eq!(parsed, None);
    }

    /// The countdown is text, and a request that has run out shows no negative
    /// number.
    #[test]
    fn a_countdown_renders_as_digits_and_unit_symbols() {
        // Arrange & act & assert
        assert_eq!(remaining(Duration::seconds(42)), "42 s");
        assert_eq!(remaining(Duration::seconds(252)), "4 min 12 s");
        assert_eq!(remaining(Duration::seconds(-9)), "0 s");
    }
}
