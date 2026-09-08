//! Transport-level security headers.
//!
//! The Content-Security-Policy that HTML pages need is a different problem with
//! a different owner: it needs a per-response nonce and it only applies to
//! documents, so it lives in [`asterius_web::document`] and runs one layer
//! further in. What lives here is the set that is correct on *every* response,
//! including JSON and redirects, and that is therefore safe to apply once at
//! the outermost layer where it cannot be forgotten.
//!
//! The two overlap on `X-Content-Type-Options`, `Referrer-Policy` and
//! `Permissions-Policy`, and the document layer wins on a document: it runs
//! first on the way out, and the insertions below are conditional. That is the
//! right way round — a login page needs the WebAuthn delegation this layer
//! cannot grant a token endpoint.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

/// FAPI 2.0 SP §5.2.3 requires HSTS to defend against TLS stripping.
///
/// One year, subdomains included, and `preload` so that the very first request
/// from a browser that has never seen this host is still protected — the
/// window HSTS otherwise leaves open is exactly the one a network attacker
/// (A2) wants.
const HSTS: HeaderValue = HeaderValue::from_static("max-age=31536000; includeSubDomains; preload");

/// `nosniff`: an error body that a browser decides to treat as script is a
/// cross-site scripting bug delivered by the server's own 400 handler.
const NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");

/// No framing, anywhere. The login and consent pages must not be embeddable —
/// clickjacking a consent screen is the cheapest way to obtain a grant — and
/// nothing else this server returns has any business in a frame either.
const FRAME_OPTIONS: HeaderValue = HeaderValue::from_static("DENY");

/// A `Referer` carrying an authorization request would leak `state`, and
/// carrying a `request_uri` would leak a one-time credential.
const REFERRER_POLICY: HeaderValue = HeaderValue::from_static("no-referrer");

/// Protocol endpoints are not a browsing context; nothing here needs a camera,
/// a microphone or a payment handler.
const PERMISSIONS_POLICY: HeaderValue =
    HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()");

const PERMISSIONS_POLICY_HEADER: HeaderName = HeaderName::from_static("permissions-policy");

/// Adds the headers above to every response, without overwriting a handler that
/// deliberately set one of them.
pub async fn layer(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    // `entry`-style insertion: a handler that has already made a considered
    // choice keeps it, and everything else gets the default.
    for (name, value) in [
        (header::STRICT_TRANSPORT_SECURITY, HSTS),
        (header::X_CONTENT_TYPE_OPTIONS, NOSNIFF),
        (header::X_FRAME_OPTIONS, FRAME_OPTIONS),
        (header::REFERRER_POLICY, REFERRER_POLICY),
        (PERMISSIONS_POLICY_HEADER, PERMISSIONS_POLICY),
    ] {
        if !headers.contains_key(&name) {
            headers.insert(name, value);
        }
    }
    response
}
