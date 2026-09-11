//! Email verification: proving that the address on an account can be read.
//!
//! Two routes, neither of which needs a line of JavaScript and neither of
//! which is reached with a credential:
//!
//! * `GET /verify-email?token=…` spends the token the mailed link carries and,
//!   if it still proves the address the account holds, sets OIDC Core §5.1's
//!   `email_verified`;
//! * `POST /verify-email` sends another link, answering the same page whatever
//!   was asked for.
//!
//! The third way in is not a route: [`gate`] is called from the sign-in path,
//! and it is what stops an unverified account completing an OIDC login for a
//! tenant that requires one.
//!
//! # What this token is, and the thing it must never become
//!
//! It is a proof about a *mailbox*, not about a person. Following a link here
//! signs nobody in, sets no credential and starts no session: the response is
//! a page saying the address is confirmed, and the person still has to sign in
//! afterwards with something they know or hold.
//!
//! That restraint is the whole security argument. The moment a confirmation
//! link produced a session it would be a second recovery flow — one with no
//! password step, reachable from a sign-up form — and "prove you can read this
//! mailbox" would have become "take this account". `crates/domain`'s
//! `entities::email_verification` says the same thing from the other end.
//!
//! # A GET that writes
//!
//! `GET /verify-email?token=…` consumes a single-use token, which is a write
//! behind a safe method, and that is deliberate rather than overlooked. A mail
//! client is going to follow this link as a top-level navigation with no form
//! and no script, and the alternative — an interstitial page with a button —
//! is the pattern that trains people to press *Confirm* on a page that arrived
//! from a message.
//!
//! What makes it safe is that the write is idempotent in effect and harmless
//! when unintended: confirming an address the account already holds is what
//! the recipient wanted, and there is no other state it can move. A link
//! prefetched by a mail scanner spends the token and confirms the address —
//! the same outcome as the person clicking, reached slightly earlier — which
//! is why the page the link leads to says "confirmed" rather than offering an
//! action. Nothing about the account can be changed from here, so CSRF has
//! nothing to protect: an attacker who can make a browser issue this request
//! is an attacker who is holding the token, and holding the token is the whole
//! of the authorisation.
//!
//! `POST /verify-email` is the opposite case — it sends mail, which is an
//! effect an attacker would like to fire from an image tag — so it is a POST
//! behind the same `__Host-` double-submit synchroniser the recovery pages
//! use, and behind the same limiter.
//!
//! # The resend tells nobody anything
//!
//! `POST /verify-email` renders one page, byte for byte, whether the address
//! belongs to an account, belongs to a *confirmed* account, belongs to a
//! disabled one, or belongs to nobody. That is the rule
//! `crate::http::recovery` states at length, and it applies here for the same
//! reason (RFC 9700 §4.4.1): an endpoint that answered differently would be an
//! account checker with a Send button.
//!
//! # The address is compared, not assumed
//!
//! [`confirm`] does not write `email_verified` because a token was valid. It
//! writes it because the token was valid *and* the address it was mailed to is
//! still the address the account holds, checked twice: once here, and once as
//! a predicate inside
//! [`asterius_store_pg::PgUserRepository::mark_email_verified`], which is the
//! half that is atomic. Sign up as `attacker@evil.test`, ask for a link,
//! change the address to `victim@bank.test`, follow the link — and the flag
//! does not move.
//!
//! # CAEP
//!
//! A confirmed address emits `email_verification.verified` to the audit trail.
//! It is not a `credential-change`: nothing about how this person authenticates
//! has changed, and emitting one would tell every receiver to end sessions
//! over an event that ended no credential. When `crates/ssf` grows an assurance
//! signal this is where it goes.

use crate::http::cookies;
use crate::http::throttle::LoginThrottle;
use crate::tenancy::MountPrefix;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::{
    EMAIL_VERIFICATION_LIFETIME, EmailVerificationStore, EmailVerificationToken,
    IssuedEmailVerification, MailSender, Notification, Tenant, User, UserStatus,
};
use asterius_web::Brand;
use asterius_web::pages::{self, EmailVerificationPage, ErrorPage, nonce_attribute};
use asterius_web::{Document, csp::Nonce, recovery as csrf};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

/// Where the link leads, and where a resend is posted.
///
/// One path and two verbs, like `/recovery`: the GET is the link in the
/// message and the POST is the button on the page it produced.
pub const PAGE_PATH: &str = "/verify-email";

/// The query parameter the mailed link carries the token in.
pub const TOKEN_PARAMETER: &str = "token";

/// The longest address this endpoint will look at or echo.
///
/// The registration form's own ceiling, read from the domain rather than
/// written here so the two cannot drift. It matters at this endpoint because
/// the address arrives in a hidden field: without a bound, a submission could
/// make this server render a megabyte of somebody's text back at them.
const MAX_ADDRESS_LEN: usize = asterius_domain::MAX_REGISTRATION_EMAIL_LENGTH;

/// What the verification handlers need.
///
/// Holds borrowed handles, like every other per-request context here: built
/// inside a handler from the tenant's scope and dropped with the response.
pub struct VerificationContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// This tenant's accounts, for resolving an address and for the one write.
    pub users: &'a asterius_store_pg::PgUserRepository,
    /// The single-use tokens.
    pub tokens: &'a dyn EmailVerificationStore,
    /// Where a message is handed off. The journal adapter, unless an operator
    /// wired something else.
    pub mail: &'a dyn MailSender,
    /// Where every route here is recorded.
    pub audit: &'a dyn AuditSink,
    /// The limiter of `ast-2vk.9`, with this request's address.
    pub throttle: LoginThrottle<'a>,
    /// The CSP nonce the document middleware drew.
    pub nonce: &'a Nonce,
    /// The prefix routing removed from this request's path (`ast-295`).
    pub mount: MountPrefix,
}

impl std::fmt::Debug for VerificationContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationContext")
            .finish_non_exhaustive()
    }
}

/// Everything the sign-in path needs to stop an unverified account.
///
/// A separate, smaller value than [`VerificationContext`] because the sign-in
/// path has no business holding a limiter or a user repository for this: it
/// has already authenticated somebody and knows who. It is
/// [`Option`]-shaped at the call site — `Some` exactly when the tenant
/// requires a verified address — so a handler cannot be given the store and
/// forget to consult the setting.
pub struct Gate<'a> {
    /// The single-use tokens.
    pub tokens: &'a dyn EmailVerificationStore,
    /// Where the message is handed off.
    pub mail: &'a dyn MailSender,
}

impl std::fmt::Debug for Gate<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate").finish_non_exhaustive()
    }
}

/// Whether this account may finish signing in, and the page to render if not.
///
/// Called after a credential has been accepted and **before** a session is
/// established. That order is the requirement: a session is the thing an
/// unverified account must not get, so the check cannot be one the caller
/// performs afterwards and then decides what to do about.
///
/// The refusal is not a refusal to the person — they proved a credential, and
/// telling them "those details did not match" would be a lie that sends them
/// to the recovery form. It is a page saying a link has been sent, with a
/// button to send another.
///
/// `None` means "carry on": the address is confirmed, or the account has none
/// to confirm. An account with no address at all is *not* blocked, because a
/// tenant that provisions passkey-only accounts with no mailbox would
/// otherwise lock every one of them out on the day this setting is switched
/// on, and the setting is about proving an address rather than about requiring
/// one.
pub async fn gate(
    gate: &Gate<'_>,
    tenant: &Tenant,
    audit: &dyn AuditSink,
    nonce: &Nonce,
    mount: &MountPrefix,
    user: &User,
    now: OffsetDateTime,
) -> Option<Response> {
    if user.email_verified {
        return None;
    }
    let address = user.email.clone()?;

    // Drawn and sent here rather than leaving the person to press the button:
    // they have just proved a credential and been stopped, and a page that
    // said "ask us for a link" without having sent one is a page that looks
    // broken. A failure is logged and swallowed — the page is the same either
    // way, and the button is what a person whose message did not arrive uses.
    issue_and_send(gate.tokens, gate.mail, tenant, audit, user, &address, now).await;

    let (csrf_token, cookie) = csrf::issue();
    let mut response = waiting_page(
        tenant,
        nonce,
        mount,
        &address,
        csrf_token.expose(),
        Some("Confirm your email address to finish signing in."),
    );
    append_cookie(&mut response, &cookie);
    Some(response)
}

// ---------------------------------------------------------------------------
// The link
// ---------------------------------------------------------------------------

/// `GET /verify-email?token=…` — spend the token and confirm the address.
pub async fn confirm(
    context: &VerificationContext<'_>,
    query: Option<&str>,
    now: OffsetDateTime,
) -> Response {
    let Some(token) = query
        .and_then(|query| query_value(query, TOKEN_PARAMETER))
        .and_then(|value| EmailVerificationToken::parse(&value).ok())
    else {
        return refused(context, "a malformed token at the verification link", now).await;
    };

    // The point of no return, and one statement. Whoever wins this gets the
    // confirmation; a second request with the same link finds nothing.
    let proved = match context.tokens.spend(&token.digest(), now).await {
        Ok(Some(proved)) => proved,
        Ok(None) => {
            return refused(context, "an unusable token at the verification link", now).await;
        }
        Err(error) => {
            tracing::error!(
                %error,
                tenant = %context.tenant.id,
                "cannot spend an email verification token"
            );
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    // The check the address column exists for. Performed here so the refusal
    // is legible, and again as a predicate in the statement below so it is
    // atomic: see the module documentation.
    let account = match context.users.find(proved.user).await {
        Ok(account) => account,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read an account");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    if !proved.still_matches(account.as_ref().and_then(|user| user.email.as_deref())) {
        // The one refusal worth an operator's attention: somebody proved one
        // mailbox and presented the proof against another. The token is
        // already spent, which is correct — it proved what it proved, and it
        // does not get a second chance at a different address.
        return refused(
            context,
            "a verification token for an address the account no longer holds",
            now,
        )
        .await;
    }

    match context
        .users
        .mark_email_verified(proved.user, &proved.address)
        .await
    {
        // `false` is an address that moved between the read above and this
        // write, or one that was already confirmed. Neither is an error and
        // neither is distinguishable on the page: the address is confirmed
        // either way, which is what the page says.
        Ok(moved) => {
            if moved {
                record(
                    context,
                    AuditEvent::new(
                        context.tenant.id.clone(),
                        EventType::EMAIL_VERIFIED,
                        Outcome::Success,
                        Actor::User(proved.user.as_uuid().to_string()),
                        now,
                    )
                    .subject(proved.user.as_uuid().to_string()),
                )
                .await;
            }
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot confirm an address");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    confirmed_page(context, &proved.address)
}

// ---------------------------------------------------------------------------
// The resend
// ---------------------------------------------------------------------------

/// `POST /verify-email` — send another link, and say the same thing either way.
///
/// Everything between the limiter and the final page may or may not happen.
/// Nothing after the limiter changes what is rendered.
pub async fn resend(
    context: &VerificationContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let form = form(body);
    let cookies = cookies(headers);

    let address = field(&form, "email")
        .map(str::trim)
        .filter(|address| !address.is_empty() && address.len() <= MAX_ADDRESS_LEN)
        .unwrap_or_default()
        .to_owned();

    if csrf::check(&cookies, field(&form, "csrf")).is_err() {
        // A fresh token, because the one this browser held is either absent or
        // wrong and rendering the old value back would keep it stuck.
        return reissued_waiting_page(
            context,
            &address,
            Some("That form had expired. Please try again."),
        );
    }

    if address.is_empty() {
        return reissued_waiting_page(
            context,
            &address,
            Some("Enter the email address on your account."),
        );
    }

    // The same buckets the login form counts against (`ast-2vk.9`). A resend
    // is counted like a failed sign-in on purpose: without it, this form is an
    // unauthenticated way to make this server send mail to an address an
    // attacker chooses, as many times as they like.
    let attempt = context.throttle.attempt(Some(&address));
    match context
        .throttle
        .check(&context.tenant.id, &attempt, now)
        .await
    {
        Ok(Some(refused)) => {
            record(
                context,
                AuditEvent::new(
                    context.tenant.id.clone(),
                    EventType::AUTH_THROTTLED,
                    Outcome::Failure,
                    Actor::System,
                    now,
                )
                .detail(Detail::new().label("path", "verify_email.resend")),
            )
            .await;
            // The hint is about the requester, not about any account: it says
            // the same thing to somebody sweeping addresses as to somebody who
            // pressed the button three times.
            return reissued_waiting_page(context, &address, Some(&refused.hint()));
        }
        Ok(None) => {}
        Err(error) => {
            // A limiter that cannot be read is not permission. Failing closed
            // costs a person one retry; failing open makes the limit
            // switchable off by loading the database.
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read the login limiter");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    }
    context
        .throttle
        .record_failure(&context.tenant.id, &attempt, now)
        .await;

    if let Some(user) = verifiable(context, &address).await {
        let to = user.email.clone().unwrap_or_default();
        issue_and_send(
            context.tokens,
            context.mail,
            context.tenant,
            context.audit,
            &user,
            &to,
            now,
        )
        .await;
    }

    reissued_waiting_page(context, &address, None)
}

/// The account this address belongs to, if any, and if it has anything to
/// confirm.
///
/// `None` for an address nobody has, for an account that is not active, for
/// one with no address, and for one whose address is already confirmed. Four
/// different facts, one answer, and the caller cannot tell them apart — which
/// is the point: an already-confirmed account that produced a different page
/// would be a way to ask this server which addresses it has proved.
///
/// The lookup is by address only, unlike `crate::http::recovery`'s. There is
/// no courtesy fallback to the login identifier here, because the address is
/// the *subject* of this flow rather than a way of naming a person: confirming
/// "the address on the account whose username happens to be `a@b.test`" would
/// be confirming something nobody asked about.
async fn verifiable(context: &VerificationContext<'_>, address: &str) -> Option<User> {
    let found = match context.users.find_by_email(address).await {
        Ok(found) => found?,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot look up an account");
            return None;
        }
    };
    if found.status != UserStatus::Active || found.email_verified {
        return None;
    }
    found.email.as_ref()?;
    Some(found)
}

/// Draws the token, writes it, and hands the message over.
///
/// Failures are logged and swallowed. Every caller renders the same page
/// regardless, and the reason is in the module documentation.
async fn issue_and_send(
    tokens: &dyn EmailVerificationStore,
    mail: &dyn MailSender,
    tenant: &Tenant,
    audit: &dyn AuditSink,
    user: &User,
    address: &str,
    now: OffsetDateTime,
) {
    if address.is_empty() {
        return;
    }
    let token = EmailVerificationToken::generate();
    let issued = IssuedEmailVerification::new(user.id, address, &token, now);

    if let Err(error) = tokens.issue(&issued).await {
        tracing::error!(%error, tenant = %tenant.id, "cannot store an email verification token");
        return;
    }

    // Absolute, because it is going into a message: a browser opening it has
    // no page to resolve a relative path against. Built from the tenant's
    // issuer, so a path-mounted tenant's link comes back through the prefix it
    // is served under (`ast-295`).
    let link = format!(
        "{}{PAGE_PATH}?{TOKEN_PARAMETER}={}",
        tenant.issuer.as_str().trim_end_matches('/'),
        token.expose()
    );

    let message = Notification::email_verification(
        address.to_owned(),
        link,
        EMAIL_VERIFICATION_LIFETIME.whole_minutes(),
    );
    if let Err(error) = mail.send(&message).await {
        tracing::error!(%error, tenant = %tenant.id, "cannot hand off a verification message");
        return;
    }

    // Only ever emitted for a request that matched an unconfirmed account, so
    // this record *is* account-existence information — which is exactly why it
    // goes here and not into anything a browser sees.
    if let Err(failure) = audit
        .record(
            AuditEvent::new(
                tenant.id.clone(),
                EventType::EMAIL_VERIFICATION_SENT,
                Outcome::Success,
                Actor::System,
                now,
            )
            .subject(user.id.as_uuid().to_string()),
        )
        .await
    {
        tracing::error!(
            %failure,
            tenant = %tenant.id,
            "a verification event was not written to the audit trail"
        );
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The "we sent you a link" page, with its resend form.
fn waiting_page(
    tenant: &Tenant,
    nonce: &Nonce,
    mount: &MountPrefix,
    address: &str,
    csrf_token: &str,
    message: Option<&str>,
) -> Response {
    // Where this page fetches its face, under the prefix routing removed
    // (`ast-vn7`).
    let font_url = crate::http::font_url(mount);
    let action = mount.absolute(PAGE_PATH);
    Document::render(nonce, |nonce| {
        pages::render(&EmailVerificationPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &tenant.display_name,
            email: address,
            verified: false,
            resend_action: &action,
            // Unread in this state — the template only spells it on the
            // confirmed page — and set to the tenant's own entry point rather
            // than to anything from the request. A "where to go next"
            // parameter on a page reached from a message is an open redirect
            // with extra steps.
            continue_href: tenant.issuer.as_str(),
            csrf: csrf_token,
            message,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .into_response()
}

/// The waiting page again, with a new synchroniser token and its cookie.
fn reissued_waiting_page(
    context: &VerificationContext<'_>,
    address: &str,
    message: Option<&str>,
) -> Response {
    let (token, cookie) = csrf::issue();
    let mut response = waiting_page(
        context.tenant,
        context.nonce,
        &context.mount,
        address,
        token.expose(),
        message,
    );
    append_cookie(&mut response, &cookie);
    response
}

/// The page a followed link lands on.
fn confirmed_page(context: &VerificationContext<'_>, address: &str) -> Response {
    // Where this page fetches its face, under the prefix routing removed
    // (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    let action = context.mount.absolute(PAGE_PATH);
    let mut response = Document::render(context.nonce, |nonce| {
        pages::render(&EmailVerificationPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            email: address,
            verified: true,
            resend_action: &action,
            continue_href: context.tenant.issuer.as_str(),
            // No form is rendered in this state, so there is nothing for a
            // synchroniser token to protect and none is drawn: a token on a
            // page with no form is a value in a browser's jar doing nothing.
            csrf: "",
            message: None,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .into_response();
    // Nothing follows this page, so the synchroniser cookie has no next
    // submission to protect.
    append_cookie(&mut response, &csrf::clear_cookie());
    response
}

/// The one answer to every unusable token: unknown, spent, expired,
/// superseded, or proving an address the account no longer holds.
///
/// One page and one status for all five, matching what the audit trail records
/// under one type. `reason` goes to the log beside the correlation id, and the
/// page carries none of it.
async fn refused(context: &VerificationContext<'_>, reason: &str, now: OffsetDateTime) -> Response {
    let font_url = crate::http::font_url(&context.mount);
    tracing::info!(tenant = %context.tenant.id, reason, "an email verification token was refused");
    record(
        context,
        AuditEvent::new(
            context.tenant.id.clone(),
            EventType::EMAIL_VERIFICATION_REFUSED,
            Outcome::Failure,
            Actor::System,
            now,
        ),
    )
    .await;
    let mut response = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            message: "That link is no longer usable. Ask for a new one.",
            correlation_id: &asterius_web::interaction::correlation_id(),
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .into_response();
    *response.status_mut() = StatusCode::BAD_REQUEST;
    append_cookie(&mut response, &csrf::clear_cookie());
    response
}

/// The generic failure page, for a store that cannot be reached.
fn error_page(context: &VerificationContext<'_>, status: StatusCode) -> Response {
    let font_url = crate::http::font_url(&context.mount);
    let mut response = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            message: "Something went wrong. Please try again.",
            correlation_id: &asterius_web::interaction::correlation_id(),
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    })
    .into_response();
    *response.status_mut() = status;
    response
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

/// Appends one event to the trail, logging a sink that refused it.
async fn record(context: &VerificationContext<'_>, event: AuditEvent) {
    if let Err(failure) = context.audit.record(event).await {
        tracing::error!(
            %failure,
            tenant = %context.tenant.id,
            "a verification event was not written to the audit trail"
        );
    }
}

/// Appends a `Set-Cookie`, without replacing any already there.
fn append_cookie(response: &mut Response, value: &str) {
    if let Ok(value) = value.parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// The submitted form, as pairs.
///
/// `application/x-www-form-urlencoded` with no schema, because a repeated
/// field must be visible to [`field`] rather than silently resolved.
fn form(body: &Bytes) -> Vec<(String, String)> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

/// One field, or `None` if it is absent **or repeated**.
fn field<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let mut found = None;
    for (key, value) in form {
        if key != name {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(value.as_str());
    }
    found
}

/// One query parameter, or `None` if it is absent **or repeated**.
fn query_value(query: &str, name: &str) -> Option<String> {
    let mut found = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if key != name {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(value.into_owned());
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The link a message carries must be absolute and must carry the token as
    /// the parameter the handler reads back, or every confirmation fails at
    /// the parser.
    #[test]
    fn the_parameter_the_link_carries_is_the_one_the_handler_reads() {
        // Arrange
        let token = EmailVerificationToken::generate();
        let query = format!("{TOKEN_PARAMETER}={}", token.expose());

        // Act
        let read = query_value(&query, TOKEN_PARAMETER);

        // Assert
        assert_eq!(read.as_deref(), Some(token.expose()));
    }

    /// A repeated parameter is no parameter. Two spellings of "the token" in
    /// one URL is a request two readers could disagree about, and the safe
    /// resolution is to read neither.
    #[test]
    fn a_repeated_token_parameter_is_refused() {
        // Arrange
        let token = EmailVerificationToken::generate();
        let query = format!(
            "{TOKEN_PARAMETER}={}&{TOKEN_PARAMETER}={}",
            token.expose(),
            token.expose()
        );

        // Act
        let read = query_value(&query, TOKEN_PARAMETER);

        // Assert
        assert_eq!(read, None);
    }

    /// The same rule on the form, where it matters for the synchroniser token:
    /// a submission carrying two `csrf` fields must not be resolved in the
    /// submitter's favour.
    #[test]
    fn a_repeated_form_field_is_refused() {
        // Arrange
        let body = Bytes::from_static(b"csrf=a&csrf=b");
        let parsed = form(&body);

        // Act
        let read = field(&parsed, "csrf");

        // Assert
        assert_eq!(read, None);
    }

    /// The path the link is built against is the path the router mounts.
    /// Stated as a test because the two are written in different files and a
    /// message is not something a person can retry.
    #[test]
    fn the_page_lives_where_the_router_puts_it() {
        // Arrange, Act, Assert
        assert_eq!(PAGE_PATH, "/verify-email");
    }

    /// The address ceiling is the registration form's, not a second opinion.
    #[test]
    fn the_address_ceiling_is_the_one_registration_enforces() {
        // Arrange, Act, Assert
        assert_eq!(
            MAX_ADDRESS_LEN,
            asterius_domain::MAX_REGISTRATION_EMAIL_LENGTH
        );
    }
}
