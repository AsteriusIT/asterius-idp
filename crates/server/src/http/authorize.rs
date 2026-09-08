//! `GET|POST /authorize` — where a client's request becomes a user's.
//!
//! RFC 9126 §4. The client has already pushed the whole authorization request
//! and holds a `request_uri`; it sends the user agent here with that plus
//! `client_id`, and nothing else that matters. This endpoint looks the request
//! up, checks it belongs to the client that is named, mints the browser's
//! credential, and redirects into the interaction.
//!
//! # Why almost nothing is validated here
//!
//! Because it already was. `asterius_oidc::authorize::validate` ran at push
//! time, against an *authenticated* client, and the result was stored. Nothing
//! reaching this endpoint can change it: the parameters are not in the URL,
//! and the only thing the browser carries is a reference. Re-validating would
//! mean a second implementation of the same rules — and the interesting bugs
//! in OAuth live in the gap between two implementations of one rule.
//!
//! What *is* checked here is the pair of things that are new: the `client_id`
//! in the URL against the one the request was pushed by, and the fact that the
//! request is still live.
//!
//! # Why an error here is a page and not a redirect
//!
//! RFC 6749 §4.1.2.1: the AS "MUST NOT automatically redirect the user-agent
//! to the invalid redirection URI". At this endpoint the request may be
//! unknown, expired, or for another client — in every one of those cases this
//! server has no redirect URI it has any business sending a browser to. So
//! every failure renders the error page, and `Location` appears only on the
//! success path.

use crate::http::redirect::SeeOther;
use asterius_domain::{AuthRequestRepository, InteractionRepository, Tenant};
use asterius_oidc::par;
use asterius_web::interaction::{self, InteractionId};
use asterius_web::pages::{ErrorPage, nonce_attribute};
use asterius_web::{Document, csp::Nonce};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use time::OffsetDateTime;

/// What the handler needs.
pub struct AuthorizeContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// The client's view of a pushed request.
    pub requests: &'a dyn AuthRequestRepository,
    /// The browser's view of the same rows.
    pub interactions: &'a dyn InteractionRepository,
    /// The CSP nonce for this response.
    pub nonce: &'a Nonce,
}

impl std::fmt::Debug for AuthorizeContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizeContext").finish_non_exhaustive()
    }
}

/// Handles an authorization request.
///
/// `parameters` are the query or form pairs, whichever verb was used — OIDC
/// Core §3.1.2.1 permits both and they carry the same two values.
pub async fn authorize(
    context: AuthorizeContext<'_>,
    parameters: &[(String, String)],
    now: OffsetDateTime,
) -> Response {
    let value = |name: &str| {
        let mut found = parameters.iter().filter(|(k, _)| k == name);
        let first = found.next().map(|(_, v)| v.as_str());
        // RFC 6749 §3.1 again: a repeated parameter is refused, not resolved.
        if found.next().is_some() { None } else { first }
    };

    // FAPI 2.0 SP §5.3.2.2 item 3: an authorization request that did not come
    // through PAR is rejected. There is no branch here that reads `scope` or
    // `redirect_uri` from the URL, so there is no path by which one could.
    let Some(request_uri) = value("request_uri") else {
        return error_page(&context, StatusCode::BAD_REQUEST);
    };
    let Some(client_id) = value("client_id") else {
        return error_page(&context, StatusCode::BAD_REQUEST);
    };

    // Shape first, so a guessed value costs a string comparison rather than a
    // query (RFC 9126 §7.1).
    let Ok(digest) = par::digest_of(request_uri) else {
        return error_page(&context, StatusCode::BAD_REQUEST);
    };

    // `peek`, not `consume`. FAPI 2.0 SP §5.3.2.2 Note 3 puts one-time use at
    // the *completion* of authorization, not at page load: a user who reloads
    // before deciding has done nothing wrong. The interaction's own
    // one-per-request guard is what stops this being reusable.
    let stored = match context.requests.peek(&digest, now).await {
        Ok(Some(stored)) => stored,
        // Unknown, expired and consumed are one answer. A browser that could
        // tell them apart could probe for live requests.
        Ok(None) => return error_page(&context, StatusCode::NOT_FOUND),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a pushed request");
            return error_page(&context, StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    // The check this endpoint exists to make. A `request_uri` issued to one
    // client, presented in a request naming another, is refused — and refused
    // as a *page*, because the redirect URI on the stored request belongs to
    // the client that pushed it, not to whoever is asking now.
    if stored.client.as_str() != client_id {
        tracing::warn!(
            tenant = %context.tenant.id,
            "a request_uri was presented under a different client_id"
        );
        return error_page(&context, StatusCode::BAD_REQUEST);
    }

    // The browser's credential. Minted here, never derived from the
    // `request_uri` — a client that could compute it could drive the user's
    // login.
    let id = InteractionId::generate();
    if let Err(error) = context
        .interactions
        .begin_interaction(&digest, &id.digest(), now)
        .await
    {
        // Either the request went away between the peek and here, or it
        // already has an interaction — a second `/authorize` on one
        // `request_uri` is a replay. Both render the same page.
        tracing::warn!(%error, tenant = %context.tenant.id, "cannot begin an interaction");
        return error_page(&context, StatusCode::BAD_REQUEST);
    }

    // Through `SeeOther`, never open-coded. `http::source_audit` enforces
    // that, and it is right to: 303 is the status that turns a POST into the
    // GET the interaction page expects, and the helper is also where response
    // splitting through a `Location` is refused. FAPI 2.0 SP §5.3.2.2 items
    // 10–11 forbid 307 outright.
    let Ok(redirect) = SeeOther::to(&format!("/interaction/{}", id.expose())) else {
        // Unreachable: the id is base64url. Refusing rather than sending a
        // header we could not build is the only safe reading.
        return error_page(&context, StatusCode::INTERNAL_SERVER_ERROR);
    };

    let mut response = redirect.into_response();
    let headers = response.headers_mut();
    if let Ok(value) = interaction::set_cookie(&id).parse() {
        headers.insert(header::SET_COOKIE, value);
    }
    // The redirect carries a credential in both the URL and the cookie.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The error page. Never a redirect — see the module documentation.
fn error_page(context: &AuthorizeContext<'_>, status: StatusCode) -> Response {
    let correlation = interaction::correlation_id();
    tracing::info!(
        correlation_id = %correlation,
        tenant = %context.tenant.id,
        %status,
        "authorization request refused"
    );

    let document = Document::render(context.nonce, |nonce| {
        asterius_web::pages::render(&ErrorPage {
            locale: "en",
            tenant_name: &context.tenant.display_name,
            message: "This sign-in request cannot be continued.",
            correlation_id: &correlation,
            nonce_attribute: nonce_attribute(nonce),
        })
    });
    (status, document).into_response()
}
