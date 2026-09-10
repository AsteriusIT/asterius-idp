//! The verification pages of the device authorization grant (RFC 8628 §3.3).
//!
//! Three pages and two routes. `GET /device` asks for the code the device is
//! showing; `POST /device` looks it up and shows what approving it would mean;
//! `POST /device/confirm` records the answer. The templates are
//! `asterius_web::pages`' three device pages, unscripted like every other page
//! in that tree.
//!
//! # This is a first-party page, so it needs a session
//!
//! An approval creates a [`Grant`] on somebody's account, so "somebody" has to
//! be a person this server has authenticated. A visitor with no usable session
//! is sent through the ordinary interaction pages exactly as the admin console
//! sends one (`ast-akl`, `crates/server/src/http/console.rs`): a first-party
//! interaction is opened, the browser is 303'd to it, and the destination is a
//! **variant** of [`FirstPartyDestination`] rather than a URL anybody could
//! supply (ADR-0009).
//!
//! The cost is that a `verification_uri_complete` opened by somebody not
//! signed in loses its prefilled code across the sign-in. That is the safe
//! direction: the code is a prefill and never a decision, and the page it
//! returns to asks for it again.
//!
//! # The authentication has to be one this tenant recognises
//!
//! A device approval hands an unattended agent a credential on the approver's
//! account, so it is not a place to accept an authentication this tenant
//! cannot classify. When the tenant has an [`AcrPolicy`] with levels in it,
//! the session's `amr` must reach one of them; a session that reaches none is
//! sent back through the interaction to authenticate again rather than
//! approving anything. A tenant that has configured no levels has expressed no
//! requirement and any usable session approves.
//!
//! # Why a guess costs so much here
//!
//! RFC 8628 §5.1: a user code is ~34.5 bits, which is small enough to be worth
//! searching. Two limits stand in front of it, and they stop different
//! attacks.
//!
//! * **Per address**: [`ATTEMPTS_PER_WINDOW`] failed submissions per
//!   [`ATTEMPT_WINDOW`], counted in the same `rate_limits` table the sign-in
//!   limiter uses, so it survives a restart and is not multiplied by the
//!   replica count. This is what bounds somebody sweeping the space.
//! * **Per authorization**: [`FAILURES_PER_CODE`] failed confirmations against
//!   one row, after which the row is refused outright and the device is told
//!   `access_denied`. This is what bounds somebody who has *found* a live code
//!   and is working at the ceremony in front of it.
//!
//! And every failure says the same thing. "No such code", "expired",
//! "already used" and "already refused" are one sentence, because each
//! distinction is an oracle for whoever is guessing.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::rate_limit::{RateLimit, RateLimitStore, device_verification_bucket};
use asterius_domain::{
    AcrPolicy, ClientRepository, FirstPartyDestination, Grant, GrantRepository,
    InteractionRepository, SectorIdentifier, Session, SessionId as DomainSessionId,
    SessionRepository, SubjectResolver, Tenant, UserId, entities::session,
};
use asterius_oidc::device::UserCode;
use asterius_store_pg::PgDeviceCodeRepository;
use asterius_web::Brand;
use asterius_web::interaction::{self, InteractionId};
use asterius_web::pages::{
    self, DeviceConfirmationPage, DeviceOutcomePage, DevicePage, ErrorPage, ScopeLine,
    nonce_attribute,
};
use asterius_web::{Document, csp::Nonce};
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use std::net::IpAddr;
use time::{Duration, OffsetDateTime};

use crate::http::redirect::SeeOther;
use crate::tenancy::MountPrefix;

/// Where the code-entry page lives.
///
/// Deliberately short: it is printed on a screen and typed by hand, and every
/// character of it is one a person can get wrong (RFC 8628 §3.3.1 makes the
/// same argument about the code).
pub const PAGE_PATH: &str = "/device";

/// Where the confirmation posts.
pub const CONFIRM_PATH: &str = "/device/confirm";

/// How long a first-party sign-in opened from this page stays open.
///
/// The same ten minutes the console's entry uses, and the same reasoning: long
/// enough for somebody typing a password, short enough that an abandoned login
/// goes away by itself.
const ENTRY_LIFETIME: Duration = Duration::minutes(10);

/// Failed submissions permitted from one address per [`ATTEMPT_WINDOW`].
///
/// Five, from the acceptance criterion. It is a *failure* budget: a person who
/// types their code correctly spends none of it, so the number bounds guessing
/// and nothing else.
pub const ATTEMPTS_PER_WINDOW: u32 = 5;

/// The window those five failures are counted in.
pub const ATTEMPT_WINDOW: Duration = Duration::minutes(10);

/// Failed confirmations one authorization survives before it is refused.
///
/// Ten, from the acceptance criterion. Reaching it denies the row, so the
/// device stops polling and the person in front of it sees a refusal rather
/// than a flow that mysteriously never completes.
pub const FAILURES_PER_CODE: i32 = 10;

/// The largest form body either route will read.
///
/// A synchroniser token and a code. Nothing on these pages is large, and a
/// bound is what stops an unauthenticated caller making this server buffer.
const MAX_BODY: usize = 4 * 1024;

/// What every failed submission says.
///
/// One sentence for every reason (§5.1). It names neither the code nor the
/// client, because a page that said "that code has expired" would answer a
/// question somebody was working through the space to ask.
const REFUSED: &str = "That code did not work. Check the code on your device and try again.";

/// What a throttled submission says.
const THROTTLED: &str = "Too many attempts. Wait a few minutes and try again.";

/// What the device pages need.
pub struct DeviceContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// Device authorizations for this tenant.
    pub device_codes: &'a PgDeviceCodeRepository,
    /// Where the cookie's session is resolved.
    pub sessions: &'a dyn SessionRepository,
    /// Where a first-party sign-in is opened for a visitor who has none.
    pub interactions: &'a dyn InteractionRepository,
    /// This tenant's clients, for the name the confirmation page shows.
    pub clients: &'a dyn ClientRepository,
    /// Where the approval is recorded.
    pub grants: &'a dyn GrantRepository,
    /// How the `sub` this client will see is resolved (OIDC Core §8.1).
    pub subjects: &'a dyn SubjectResolver,
    /// The authentication contexts this tenant can produce (`ast-2vk.7`).
    pub acr: &'a AcrPolicy,
    /// Where the per-address attempt budget is counted.
    pub limits: &'a dyn RateLimitStore,
    /// Where this request came from, when the deployment resolved it.
    ///
    /// `None` — a peer the forwarded-header policy would not vouch for — is
    /// *not* a free pass: it shares one bucket, so an unattributable flood is
    /// limited as if it came from one address rather than not at all.
    pub address: Option<IpAddr>,
    /// The CSP nonce the document middleware drew for this response.
    pub nonce: &'a Nonce,
    /// Where an approval or a refusal is recorded.
    pub audit: &'a dyn AuditSink,
    /// The prefix routing removed from this request's path (`ast-295`).
    pub mount: MountPrefix,
}

impl std::fmt::Debug for DeviceContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceContext").finish_non_exhaustive()
    }
}

/// `GET /device` — the code-entry page (RFC 8628 §3.3).
///
/// `user_code` is the prefill a `verification_uri_complete` carries (§3.3.1).
/// It is rendered escaped into an editable field and nothing else: the page
/// decides nothing from it, and the submission that follows is compared
/// server-side like any other.
pub async fn page(
    context: &DeviceContext<'_>,
    headers: &HeaderMap,
    user_code: Option<&str>,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = admitted(context, headers, now).await else {
        return begin(context, now).await;
    };
    entry_page(context, &session, user_code, None, StatusCode::OK)
}

/// `POST /device` — the code a person typed.
///
/// Every refusal renders the same page with the same message and the same
/// status, so the response is not an oracle either.
pub async fn submit(
    context: &DeviceContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = admitted(context, headers, now).await else {
        return begin(context, now).await;
    };
    let Some(form) = form(body) else {
        return entry_page(
            context,
            &session,
            None,
            Some(REFUSED),
            StatusCode::BAD_REQUEST,
        );
    };
    if !checked_csrf(&session, form.get("csrf").map(String::as_str)) {
        return entry_page(
            context,
            &session,
            None,
            Some(REFUSED),
            StatusCode::BAD_REQUEST,
        );
    }

    // §5.1's per-address budget, read before the code is looked at so that a
    // sweep pays for itself rather than for the rows it happens to hit.
    if self::throttled(context, now).await {
        return entry_page(
            context,
            &session,
            None,
            Some(THROTTLED),
            StatusCode::TOO_MANY_REQUESTS,
        );
    }

    let typed = form
        .get("user_code")
        .map(String::as_str)
        .unwrap_or_default();
    // The shape check runs before the database is touched, so a guess costs a
    // comparison. It still costs a *budget*, which is the point: a
    // well-formed guess and a malformed one are the same attempt.
    let Ok(code) = UserCode::parse(typed) else {
        self::record_failure(context, now).await;
        return entry_page(
            context,
            &session,
            None,
            Some(REFUSED),
            StatusCode::BAD_REQUEST,
        );
    };

    let pending = match context.device_codes.pending(&code.digest(), now).await {
        Ok(Some(pending)) => pending,
        Ok(None) => {
            self::record_failure(context, now).await;
            return entry_page(
                context,
                &session,
                None,
                Some(REFUSED),
                StatusCode::BAD_REQUEST,
            );
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a device authorization");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    let client_name = self::client_name(context, &pending.client_id).await;
    let action = format!(
        "{}?user_code={}",
        context.mount.absolute(CONFIRM_PATH),
        url::form_urlencoded::byte_serialize(code.formatted().as_bytes()).collect::<String>()
    );
    // Where this page fetches its face, under the same prefix (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&DeviceConfirmationPage {
            // The device pages still hold their words in their templates:
            // `ast-ndk.5` translated the authorization journey and left these
            // for the bead that wired them. Rendering them under a negotiated
            // locale would put `lang="fr"` over English (WCAG 2.2 SC 3.1.1).
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            client_name: &client_name,
            // The code this server matched, not the string that was typed:
            // §3.3.1 asks the person to compare what the *server* holds
            // against what the device shows, and echoing their own input back
            // would compare it against itself.
            user_code: &code.formatted(),
            scopes: pending
                .scopes
                .iter()
                .map(|scope| ScopeLine {
                    // No description: the sentences a tenant writes for its
                    // scopes are the consent screen's (`ast-uwv`), and a
                    // half-populated copy of them here would show a described
                    // scope on one page and a bare token on the other. The
                    // token renders unexplained, which is what an unexplained
                    // scope should look like.
                    name: scope.clone(),
                    description: None,
                    required: true,
                })
                .collect(),
            authorization_details: detail_lines(&pending.authorization_details),
            action: &action,
            csrf: &csrf_for(&session),
            message: None,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (StatusCode::OK, no_store(), document).into_response()
}

/// `POST /device/confirm` — the answer.
///
/// `user_code` comes from the query of the action this server wrote on the
/// previous page, which makes it exactly as trustworthy as the field it
/// replaced: it is parsed, looked up and compared here like any other input.
pub async fn confirm(
    context: &DeviceContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    user_code: Option<&str>,
    now: OffsetDateTime,
) -> Response {
    let Some(session) = admitted(context, headers, now).await else {
        return begin(context, now).await;
    };
    let Some(form) = form(body) else {
        return outcome(context, false, "");
    };
    if !checked_csrf(&session, form.get("csrf").map(String::as_str)) {
        return outcome(context, false, "");
    }
    let Ok(code) = UserCode::parse(user_code.unwrap_or_default()) else {
        self::record_failure(context, now).await;
        return outcome(context, false, "");
    };
    let digest = code.digest();

    // "No" is a decision, and RFC 8628 §3.5 has a code for it: the device is
    // told `access_denied` on its next poll rather than left to time out.
    if form.get("decision").map(String::as_str) != Some("confirm") {
        match context.device_codes.deny(&digest, now).await {
            Ok(_) => {}
            Err(error) => {
                tracing::error!(%error, tenant = %context.tenant.id, "cannot refuse a device authorization");
                return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
            }
        }
        self::record(context, None, EventType::CONSENT_DENIED, now).await;
        return outcome(context, false, "");
    }

    let pending = match context.device_codes.pending(&digest, now).await {
        Ok(Some(pending)) => pending,
        Ok(None) => {
            // Expired, refused or approved between the two pages. The same
            // page an unknown code reaches, and a spent attempt.
            self::record_failure(context, now).await;
            return outcome(context, false, "");
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a device authorization");
            return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    let client_name = self::client_name(context, &pending.client_id).await;
    let Some(grant) = self::approval(context, &session, &pending, now).await else {
        // A failure here is this server's, not a wrong guess, so it does not
        // spend the row's budget — but it must not read as an approval
        // either.
        return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
    };

    match context
        .device_codes
        .approve(&digest, &UserId::new(session.user), &grant, now)
        .await
    {
        // The row moved on between the read above and this write — a second
        // tab, a double-clicked button, an expiry a moment ago. The grant just
        // created is left `Pending` and unclaimed, which is the state Grant
        // Management ID1 §5.6 has for an authorization no credential was ever
        // taken from, and retention removes it.
        Ok(false) => {
            self::failed_confirmation(context, &digest, now).await;
            outcome(context, false, "")
        }
        Ok(true) => {
            self::record(
                context,
                Some(&pending.client_id),
                EventType::CONSENT_GRANTED,
                now,
            )
            .await;
            outcome(context, true, &client_name)
        }
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot approve a device authorization");
            error_page(context, StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

/// Creates the grant an approval records (`ast-dlk`).
///
/// The same shape the consent screen writes: the scopes and rich authorization
/// the *device* asked for, the subject this client will see, and a snapshot of
/// how the approver authenticated — copied off the session at the one moment
/// it is certainly there, because a grant may outlive the session row.
///
/// `claimed_at` stays `None`: nothing has been taken from it yet. The token
/// endpoint stamps it when the device redeems.
async fn approval(
    context: &DeviceContext<'_>,
    session: &Session,
    pending: &asterius_store_pg::PendingDevice,
    now: OffsetDateTime,
) -> Option<asterius_domain::GrantId> {
    let client_id = asterius_domain::ClientId::new(pending.client_id.clone());
    let client = match context.clients.find(&client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            tracing::error!(
                tenant = %context.tenant.id,
                "a device authorization names a client that no longer exists"
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
            tracing::error!(%error, tenant = %context.tenant.id, "cannot record a device grant");
            None
        }
    }
}

/// The session behind the cookie, when it is one this tenant will let approve.
///
/// Two checks and not one. The session must be usable and belong to this
/// tenant — the repository is already scoped, and the comparison is the second
/// lock on that door — and its `amr` must reach a level this tenant defines,
/// when it defines any.
async fn admitted(
    context: &DeviceContext<'_>,
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
    // `ast-2vk.7`: a tenant with an authentication ladder gets to say that an
    // approval stands on a rung of it. One that has configured none has
    // expressed no requirement, and inventing one here would refuse every
    // approval on a deployment that never asked for that.
    if !context.acr.levels().is_empty() && context.acr.achieved(&session.amr).is_none() {
        tracing::info!(
            tenant = %context.tenant.id,
            "a device approval was asked for by a session this tenant cannot classify"
        );
        return None;
    }
    Some(session)
}

/// The synchroniser token for this session.
///
/// Derived rather than stored, and derived from something the browser does not
/// hold: the session's *digest*, which exists in the database and in this
/// process and nowhere a cross-site attacker can reach. A page forged on
/// another origin can make the browser send the session cookie, which is the
/// whole of what CSRF is; it cannot read it, so it cannot compute this.
///
/// The domain separator is what stops the value being usable as anything else
/// derived from the same digest.
fn csrf_for(session: &Session) -> String {
    asterius_domain::sha256_hex(
        format!("{}:device-verification-csrf", session.id_digest).as_bytes(),
    )
}

/// Compares a submitted token against the one this session's pages carry.
fn checked_csrf(session: &Session, presented: Option<&str>) -> bool {
    let Some(presented) = presented else {
        return false;
    };
    asterius_domain::ct_eq(presented.as_bytes(), csrf_for(session).as_bytes())
}

/// Whether this address has spent its budget (§5.1).
async fn throttled(context: &DeviceContext<'_>, now: OffsetDateTime) -> bool {
    let limit = attempt_limit();
    let bucket = device_verification_bucket(context.address);
    match context
        .limits
        .count(&context.tenant.id, &bucket, limit.window_start(now))
        .await
    {
        Ok(count) => count >= ATTEMPTS_PER_WINDOW,
        Err(error) => {
            // A limiter that cannot be read is not permission to stop
            // limiting: the safe direction here is to refuse, because the
            // thing on the other side of it is a code space small enough to
            // search.
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read the device attempt budget");
            true
        }
    }
}

/// Counts one failed attempt against this address.
async fn record_failure(context: &DeviceContext<'_>, now: OffsetDateTime) {
    let limit = attempt_limit();
    let bucket = device_verification_bucket(context.address);
    if let Err(error) = context
        .limits
        .record(
            &context.tenant.id,
            &bucket,
            limit.window_start(now),
            limit.window_end(now),
        )
        .await
    {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot count a device attempt");
    }
}

/// Counts one failed confirmation against the authorization itself, and
/// against the address that made it.
async fn failed_confirmation(context: &DeviceContext<'_>, digest: &str, now: OffsetDateTime) {
    self::record_failure(context, now).await;
    if let Err(error) = context
        .device_codes
        .record_failure(digest, FAILURES_PER_CODE, now)
        .await
    {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot count a device confirmation failure");
    }
}

/// The per-address budget, as the limiter's own type.
const fn attempt_limit() -> RateLimit {
    RateLimit {
        max: ATTEMPTS_PER_WINDOW,
        window: ATTEMPT_WINDOW,
    }
}

/// The client's registered name, or a placeholder.
///
/// A name chosen at registration, like the one on the consent screen, and
/// treated the same way: escaped into the markup and never trusted as an
/// identity. A client that has gone missing between the request and the
/// approval leaves a page that says so rather than a page with a hole in it.
async fn client_name(context: &DeviceContext<'_>, client_id: &str) -> String {
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

/// The RFC 9396 §2.2 fields of each stored element, for the page.
///
/// Only the members with an agreed meaning, and never the element itself:
/// §12 is explicit that a rich authorization is a document the *client*
/// composed, so rendering it whole would be asking a person to agree to
/// attacker-chosen text. A type this deployment has no sentence for renders as
/// its bare name, which the page says is undescribed.
fn detail_lines(details: &serde_json::Value) -> Vec<pages::DetailLine> {
    let strings = |element: &serde_json::Value, member: &str| -> Vec<String> {
        element
            .get(member)
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    details
        .as_array()
        .map(|elements| {
            elements
                .iter()
                .filter_map(|element| {
                    let name = element.get("type")?.as_str()?.to_owned();
                    Some(pages::DetailLine {
                        name,
                        description: None,
                        locations: strings(element, "locations"),
                        actions: strings(element, "actions"),
                        datatypes: strings(element, "datatypes"),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Renders the code-entry page.
fn entry_page(
    context: &DeviceContext<'_>,
    session: &Session,
    user_code: Option<&str>,
    message: Option<&str>,
    status: StatusCode,
) -> Response {
    // Where this page fetches its face, under the prefix routing removed (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    let action = context.mount.absolute(PAGE_PATH);
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&DevicePage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            action: &action,
            csrf: &csrf_for(session),
            user_code,
            message,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (status, no_store(), document).into_response()
}

/// Renders the terminal page (§3.3): the device is connected, or it is not.
fn outcome(context: &DeviceContext<'_>, connected: bool, client_name: &str) -> Response {
    // Where this page fetches its face, under the prefix routing removed (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&DeviceOutcomePage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            connected,
            client_name,
            nonce_attribute: nonce_attribute(nonce),
            theme_css: "",
            brand: Brand::new(&font_url),
        })
    });
    (StatusCode::OK, no_store(), document).into_response()
}

/// The page a failure of *this server* produces.
fn error_page(context: &DeviceContext<'_>, status: StatusCode) -> Response {
    // Where this page fetches its face, under the prefix routing removed (`ast-vn7`).
    let font_url = crate::http::font_url(&context.mount);
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            text: &crate::http::i18n::UNTRANSLATED,
            tenant_name: &context.tenant.display_name,
            message: "This did not work. Nothing was connected.",
            // Nothing to quote: the reason is in the log with the tenant, and
            // a person on this page cannot act on an identifier anyway.
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
/// The console's `begin`, with this page's destination: 303 so the browser
/// fetches the next page rather than repeating this request, the id in both
/// the URL and a `__Host-` cookie so a leaked URL is inert without the cookie
/// (FAPI 2.0 SP §6.5), and `no-store` because the response carries a
/// credential.
async fn begin(context: &DeviceContext<'_>, now: OffsetDateTime) -> Response {
    let id = InteractionId::generate();
    if let Err(error) = context
        .interactions
        .begin_first_party_interaction(
            &id.digest(),
            FirstPartyDestination::DeviceVerification,
            now + ENTRY_LIFETIME,
            now,
        )
        .await
    {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot open a device sign-in");
        return error_page(context, StatusCode::SERVICE_UNAVAILABLE);
    }

    // Relative, for the reason `console::location_of` gives: the tenant prefix
    // is not visible from here, and `interaction/{id}` resolved against
    // `/t/x/device` is this tenant's interaction page.
    let Ok(redirect) = SeeOther::to(&format!("interaction/{}", id.expose())) else {
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

/// Records what a person decided.
async fn record(
    context: &DeviceContext<'_>,
    client_id: Option<&str>,
    event: EventType,
    now: OffsetDateTime,
) {
    let mut record = AuditEvent::new(
        context.tenant.id.clone(),
        event,
        Outcome::Success,
        Actor::System,
        now,
    )
    .detail(Detail::new().label("flow", "device"));
    // A refusal is recorded before the row is read, so there may be no client
    // to name — and naming one this server has not confirmed would put a
    // guess in the trail.
    if let Some(client_id) = client_id {
        record = record.client(asterius_domain::ClientId::new(client_id.to_owned()));
    }
    if let Err(error) = context.audit.record(record).await {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot record a device decision");
    }
}

/// The form pairs of a submission, when the body is one.
fn form(body: &Bytes) -> Option<std::collections::BTreeMap<String, String>> {
    if body.len() > MAX_BODY {
        return None;
    }
    let text = std::str::from_utf8(body).ok()?;
    Some(
        url::form_urlencoded::parse(text.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
    )
}

/// Every response from these pages carries a decision or a credential.
fn no_store() -> [(header::HeaderName, HeaderValue); 1] {
    [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))]
}
