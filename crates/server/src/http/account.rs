//! The account pages: what a person can do to their own account without an
//! administrator (`ast-1xd`).
//!
//! Four pages live under `/account`, and this module holds the home page that
//! links them together plus the three decisions all of them make the same way.
//! The pages themselves are [`crate::http::account_passkeys`],
//! [`crate::http::account_password`] and [`crate::http::account_sessions`];
//! [`crate::http::approvals`] and [`crate::http::account_grants`] arrived
//! earlier and are linked from here.
//!
//! # Why this exists at all
//!
//! An administrator can already remove a credential and end a session from the
//! console (`ast-f7m.6`). Until this bead, the person the credential and the
//! session belong to could not: somebody whose passkey was stolen, or who
//! could see a session they did not start, had to open a support ticket and
//! wait. That is the failure these pages remove, and it is why the acceptance
//! criterion for each of them is an *irreversible* action rather than a list.
//!
//! # The frontier this moves, and the three answers to it
//!
//! Self-service moves a security boundary: before it, a stolen session could
//! read this server's pages and authorise clients; after it, a stolen session
//! is one step away from taking the account — removing the real owner's
//! passkey, setting a password, closing the sessions they are watching from.
//! Three rules answer that, and every page here applies all three.
//!
//! * **A fresh authentication.** Every write needs an authentication from the
//!   last [`FRESHNESS`] — the approvals inbox's two minutes, for the reason it
//!   gives (OIDC Core §3.1.2.1's `max_age` has the same shape): a browser
//!   somebody left open in a café is a browser an attacker gets for free. A
//!   stale session is not refused, it is sent to authenticate again and comes
//!   back to the page it left, through a [`FirstPartyDestination`] rather than
//!   a redirect parameter (ADR-0009).
//! * **The password, for the one step that cannot be undone.** Removing the
//!   *last* passkey asks for it as well; see
//!   [`crate::http::account_passkeys`].
//! * **No enumeration, ever.** A credential that is not this account's, a
//!   session that is not this account's, and one that never existed are one
//!   answer. The person in front of the page cannot act on the difference, and
//!   each distinction answers a question about a row they may not hold.
//!
//! # CSRF
//!
//! Every form here carries a synchroniser token derived from the session's
//! *digest*, which the browser does not hold — `crate::http::device::csrf_for`'s
//! argument — under a separator of its own page, so a token lifted from one
//! account page is not one another accepts. [`csrf_for`] is where that
//! derivation lives, once, for all of them.

use asterius_domain::{
    AcrPolicy, FirstPartyDestination, InteractionRepository, Session, SessionRepository, Tenant,
    entities::session,
};
use asterius_web::Brand;
use asterius_web::i18n::Catalog;
use asterius_web::interaction::{self, InteractionId};
use asterius_web::pages::{self, AccountPage, ErrorPage, nonce_attribute};
use asterius_web::{Document, csp::Nonce};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::{Duration, OffsetDateTime};

use crate::http::redirect::SeeOther;
use crate::tenancy::MountPrefix;

/// Where the home page lives.
pub const PAGE_PATH: &str = "/account";

/// How recently somebody must have authenticated to change anything here.
///
/// The approvals inbox's and the grants dashboard's two minutes, for their
/// reason and with their shape: long enough to read a page and press a button,
/// short enough that the authentication and the change are one act.
pub const FRESHNESS: Duration = Duration::seconds(120);

/// How long a sign-in opened from one of these pages stays open.
///
/// The device page's ten minutes, for its reason: long enough for somebody
/// typing a password, short enough that an abandoned login goes away.
pub const ENTRY_LIFETIME: Duration = Duration::minutes(10);

/// The largest body any of these forms will read.
///
/// A synchroniser token, an identifier, a label and a password. The inbox's
/// four kilobytes, and it is a bound rather than a format check: it is what
/// stops a caller making this server buffer.
pub const MAX_BODY: usize = 4 * 1024;

/// The longest synchroniser token any of these parsers will carry.
///
/// The real one is 64 hex characters. The bound is the promise that a caller
/// cannot make a parser allocate without limit, not a format check.
pub const MAX_CSRF_CHARS: usize = 256;

/// What every page under `/account` needs in order to decide who is asking.
///
/// The pages each add their own repositories; what is here is what all four
/// share, so that admission, freshness and the return-to-sign-in are written
/// once.
pub struct AccountContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// Where the cookie's session is resolved.
    pub sessions: &'a dyn SessionRepository,
    /// Where a sign-in is opened for a session that is missing or too old.
    pub interactions: &'a dyn InteractionRepository,
    /// The authentication contexts this tenant can produce (`ast-2vk.7`).
    pub acr: &'a AcrPolicy,
    /// The words these pages are rendered with.
    pub text: &'a Catalog,
    /// The CSP nonce the document middleware drew for this response.
    pub nonce: &'a Nonce,
    /// The prefix routing removed from this request's path (`ast-295`).
    pub mount: MountPrefix,
}

impl std::fmt::Debug for AccountContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountContext").finish_non_exhaustive()
    }
}

/// The session behind the cookie, when it is one this tenant will let read an
/// account page.
///
/// The inbox's admission, for its reasons: the session must be usable and
/// belong to this tenant, and where the tenant has an authentication ladder the
/// session must reach a rung of it. A tenant that has configured no levels has
/// expressed no requirement, and inventing one here would leave such a
/// deployment with pages nobody can open.
pub async fn admitted(
    context: &AccountContext<'_>,
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
            "an account page was asked for by a session this tenant cannot classify"
        );
        return None;
    }
    Some(session)
}

/// Whether this authentication happened recently enough to change something.
#[must_use]
pub fn fresh(session: &Session, now: OffsetDateTime) -> bool {
    now - session.authenticated_at <= FRESHNESS && session.authenticated_at <= now
}

/// The synchroniser token for this session, under one page's separator.
///
/// Derived from the session's *digest*, which the browser does not hold: a page
/// forged on another origin can make the browser send the session cookie, which
/// is the whole of what CSRF is, but it cannot read it and so cannot compute
/// this. `separator` is the page's own, so a token lifted from one account page
/// is not one another accepts.
#[must_use]
pub fn csrf_for(session: &Session, separator: &str) -> String {
    asterius_domain::sha256_hex(format!("{}:{separator}", session.id_digest).as_bytes())
}

/// Compares a submitted token against the one this session's page carries.
#[must_use]
pub fn checked_csrf(session: &Session, separator: &str, presented: &str) -> bool {
    asterius_domain::ct_eq(
        presented.as_bytes(),
        csrf_for(session, separator).as_bytes(),
    )
}

/// Opens a first-party interaction and sends the browser to its login page.
///
/// The inbox's `begin`, with the caller's destination: 303 so the browser
/// fetches the next page rather than repeating this request, the id in both the
/// URL and a `__Host-` cookie so a leaked URL is inert without the cookie (FAPI
/// 2.0 SP §6.5), and `no-store` because the response carries a credential.
pub async fn begin(
    context: &AccountContext<'_>,
    destination: FirstPartyDestination,
    now: OffsetDateTime,
) -> Response {
    let id = InteractionId::generate();
    if let Err(error) = context
        .interactions
        .begin_first_party_interaction(&id.digest(), destination, now + ENTRY_LIFETIME, now)
        .await
    {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot open a sign-in for an account page");
        return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
    }

    // Relative, for `console::location_of`'s reason: the tenant prefix is not
    // visible from here, and `interaction/{id}` resolved against
    // `/t/x/account/passkeys` is this tenant's interaction page.
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

/// The page a failure of *this server* produces.
///
/// One sentence for all of them, out of the catalogue since `ast-1xd`: it says
/// that nothing changed, which is the fact the person needs and the one this
/// server can always honestly state — every write on these pages is a single
/// statement that either happened or did not.
#[must_use]
pub fn error_page(context: &AccountContext<'_>, status: StatusCode) -> Response {
    let font_url = crate::http::font_url(&context.mount);
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            text: context.text,
            tenant_name: &context.tenant.display_name,
            message: context.text.error_nothing_changed(),
            correlation_id: "",
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (status, no_store(), document).into_response()
}

/// Every response from these pages carries a credential, a list of them, or the
/// fact that one just changed.
#[must_use]
pub fn no_store() -> [(header::HeaderName, HeaderValue); 1] {
    [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))]
}

/// An instant, RFC 3339, or an empty string.
///
/// The grants dashboard's `stamp`, for its reason: the value reaches a
/// `datetime` attribute, and an attribute holding something that is not a
/// timestamp is worse than one holding nothing.
#[must_use]
pub fn stamp(instant: OffsetDateTime) -> String {
    instant
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// The seam between an account page and the receivers that asked to be told.
///
/// Two mechanisms, and they are not alternatives.
///
/// * **Back-channel logout** (OIDC Back-Channel Logout 1.0 §2): one logout
///   token per relying party that took an ID token in a session, so an
///   application a person was signed in to stops treating them as signed in.
///   Only a session revocation produces these.
/// * **CAEP** (`ast-0ju.8`): a `session-revoked` or `credential-change`
///   Security Event Token for every stream that subscribed. A receiver holding
///   a signed access token that still verifies is told here and nowhere else.
///
/// Carried as a struct rather than as six fields on each page's context
/// because every page that changes something needs all of it, and a page that
/// assembled five of the six would emit SETs to the wrong `sub`.
///
/// [`Self::queues`] is `None` in a deployment with no outbox wiring, which
/// notifies nobody and says so in the log — the same degradation
/// [`crate::backchannel::Notifier`] makes for the same reason: a receiver that
/// cannot be told must not stop the revocation that has already happened.
pub struct Signals<'a> {
    /// The receivers, for each one's sector identifier and logout endpoint.
    pub clients: &'a dyn asterius_domain::ClientRepository,
    /// The `sub` each receiver knows the person by (OIDC Core §8.1).
    pub subjects: &'a dyn asterius_domain::ports::SubjectResolver,
    /// The tenant's active signing key: both a logout token and a SET are
    /// signed with the key the tenant publishes.
    pub signer: &'a dyn asterius_domain::keys::Signer,
    /// Where the SETs of one cause are queued.
    pub queues: Option<&'a dyn crate::ssf::SsfQueues>,
    /// Where a logout token is queued for delivery (§2.5).
    pub outbox: Option<&'a dyn asterius_domain::outbox::OutboxQueue>,
}

impl std::fmt::Debug for Signals<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signals")
            .field("queues", &self.queues.is_some())
            .field("outbox", &self.outbox.is_some())
            .finish_non_exhaustive()
    }
}

/// Emits the SETs one effect produces, to every stream that subscribed.
///
/// Best-effort and after the effect, the order `crate::admin`'s emitter keeps
/// to: the credential is already gone, and a receiver that could not be told
/// must not undo that. Returns how many SETs were queued, for the caller's own
/// trail.
pub async fn emit_signal(
    context: &AccountContext<'_>,
    signals: &Signals<'_>,
    cause: &crate::ssf::Cause,
    now: OffsetDateTime,
) -> usize {
    let Some(queues) = signals.queues else {
        tracing::debug!(
            tenant = %context.tenant.id,
            "no security event queue is wired; no receiver was told about an account change"
        );
        return 0;
    };
    let transmitter = crate::ssf::SsfTransmitter {
        tenant: &context.tenant.id,
        issuer: &context.tenant.issuer,
        queues,
        clients: signals.clients,
        subjects: signals.subjects,
        signer: signals.signer,
    };
    transmitter.emit(cause, now).await
}

/// `GET /account` — the four pages, as links.
///
/// A stale session reads this one: there is no form on it and nothing it can
/// change, and sending somebody to authenticate again in order to be shown a
/// list of links would teach them that re-authentication is noise.
pub async fn page(
    context: &AccountContext<'_>,
    users: &dyn asterius_domain::UserDirectory,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = admitted(context, headers, now).await else {
        return begin(context, FirstPartyDestination::AccountHome, now).await;
    };

    // The username rather than the account's UUID: the page says who is signed
    // in so that somebody with two accounts can see which one this is, and a
    // UUID answers that question for nobody. An account that cannot be read
    // renders no name rather than failing the page.
    let username = match users
        .by_id(asterius_domain::UserId::new(session.user))
        .await
    {
        Ok(Some(user)) => user.username,
        Ok(None) => String::new(),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read an account");
            String::new()
        }
    };

    let font_url = crate::http::font_url(&context.mount);
    let passkeys_href = context
        .mount
        .absolute(crate::http::account_passkeys::PAGE_PATH);
    let password_href = context
        .mount
        .absolute(crate::http::account_password::PAGE_PATH);
    let sessions_href = context
        .mount
        .absolute(crate::http::account_sessions::PAGE_PATH);
    let approvals_href = context.mount.absolute(crate::http::approvals::PAGE_PATH);
    let grants_href = context
        .mount
        .absolute(crate::http::account_grants::PAGE_PATH);
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&AccountPage {
            text: context.text,
            tenant_name: &context.tenant.display_name,
            username: &username,
            passkeys_href: &passkeys_href,
            password_href: &password_href,
            sessions_href: &sessions_href,
            approvals_href: &approvals_href,
            grants_href: &grants_href,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (StatusCode::OK, no_store(), document).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::TenantId;

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
    }

    fn session(authenticated_at: OffsetDateTime) -> Session {
        let mut session = Session::begin(
            TenantId::parse("demo").expect("a tenant id"),
            &session::SessionId::generate(),
            uuid::Uuid::nil(),
            vec![asterius_domain::AuthenticationMethod::Password],
            epoch(),
            asterius_domain::Lifetimes {
                idle: Duration::hours(1),
                absolute: Duration::days(1),
            },
        );
        session.authenticated_at = authenticated_at;
        session
    }

    /// The freshness window is the one the inbox and the dashboard use, and it
    /// is a *window*: an authentication two minutes and one second old is not
    /// one somebody may remove a credential with.
    #[test]
    fn an_authentication_older_than_the_window_is_not_fresh() {
        // Arrange
        let now = epoch();
        let recent = session(now - Duration::seconds(119));
        let stale = session(now - FRESHNESS - Duration::seconds(1));

        // Act & assert
        assert!(fresh(&recent, now));
        assert!(!fresh(&stale, now));
    }

    /// A session that claims to have authenticated in the future is not fresh
    /// either: a clock that went backwards must not hand somebody an unbounded
    /// window.
    #[test]
    fn an_authentication_in_the_future_is_not_fresh() {
        // Arrange
        let now = epoch();
        let ahead = session(now + Duration::seconds(1));

        // Act & assert
        assert!(!fresh(&ahead, now));
    }

    /// Each account page derives its token under its own separator, so a token
    /// lifted from one page's form is not one another page accepts.
    #[test]
    fn each_page_has_a_token_of_its_own() {
        // Arrange
        let session = session(epoch());

        // Act
        let passkeys = csrf_for(&session, "account-passkeys-csrf");
        let sessions = csrf_for(&session, "account-sessions-csrf");

        // Assert
        assert_ne!(passkeys, sessions);
        assert!(checked_csrf(&session, "account-passkeys-csrf", &passkeys));
        assert!(!checked_csrf(&session, "account-passkeys-csrf", &sessions));
        assert!(!checked_csrf(&session, "account-passkeys-csrf", ""));
    }
}
