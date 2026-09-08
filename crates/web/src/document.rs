//! Document-level security: the headers that only make sense on an HTML page,
//! and the response type that cannot be built without a nonce.
//!
//! There are two header layers in this server on purpose.
//! `asterius_server::http::security_headers` holds what is correct on *every*
//! response — HSTS, `nosniff`, `X-Frame-Options`, a `Referrer-Policy` — and so
//! it sits at the outermost layer, where a 413 from the body limit and a 408
//! from the timeout still pass through it. This one holds what is only correct
//! on a *document*: a Content-Security-Policy carrying a per-response nonce,
//! `Cross-Origin-Opener-Policy`, a WebAuthn `Permissions-Policy`, and
//! `Cache-Control: no-store`.
//!
//! Keeping them apart is not tidiness. A nonce-based policy on a JSON response
//! would be a fresh 128-bit draw and a 200-byte header on every token request,
//! defending a parser that does not execute script; `Cache-Control: no-store`
//! on the discovery document would throw away the caching `ast-o0t.3`
//! deliberately built. So this layer looks at the `Content-Type` and does
//! nothing at all unless the response is a document.
//!
//! **Framing is defended twice.** `frame-ancestors 'none'` is here and
//! `X-Frame-Options: DENY` is in the transport layer. CSP Level 3 §6.4.2.2 says
//! that where both are understood the header is ignored — "if a resource is
//! delivered with a policy that includes a directive named `frame-ancestors`
//! and whose disposition is `enforce`, then the `X-Frame-Options` header will
//! be ignored" — so they cannot disagree in a browser that reads both. The
//! reason to keep the older one anyway is RFC 9700 §4.16: "Because some user
//! agents do not support [CSP-2], this technique SHOULD be combined with
//! others". A consent screen framed by an attacker is a grant obtained by
//! misdirection, and the cost of the second header is 24 bytes.
//!
//! RFC 9700 §4.16 also suggests an authorization server "SHOULD allow
//! administrators to configure allowed origins for particular clients". That is
//! declined: an embeddable consent screen is a clickjacking target for the sake
//! of an embedding nobody here has asked for, and `frame-ancestors 'none'` is
//! the setting that cannot be misconfigured. Reversing it needs an ADR.

use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::csp::{FormActionOrigin, Nonce, Policy};

/// A `Referer` carrying an interaction URL would hand a third party the
/// `request_uri`, the interaction id, or whatever the login form was posted
/// with. RFC 9700 §4.2.4 names the exact header: "Referrer-Policy: no-referrer
/// in the response completely suppresses the Referer header in all requests
/// originating from the resulting document."
const REFERRER_POLICY: HeaderValue = HeaderValue::from_static("no-referrer");

/// An HTML page that a browser decides to sniff as something else is a page
/// whose policy is somebody else's problem. Repeated from the transport layer
/// because a document is where it matters most, not because it is missing.
const NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");

/// Severs the `window.opener` relationship with whatever opened this page.
///
/// A login page opened as a popup by an attacker's document otherwise shares a
/// browsing-context group with it: the opener can navigate it, count its
/// frames, and use it as a cross-origin timing and navigation oracle.
/// `same-origin` puts the document in its own group.
const OPENER_POLICY: HeaderValue = HeaderValue::from_static("same-origin");

/// The union of the transport policy's denials and what a login page needs.
///
/// `publickey-credentials-get` and `-create` are allow-listed for `self`
/// because passkey login (`ast-2vk.4`) calls the WebAuthn API from this
/// document; the delegation is to the origin only, never to `*`, so an embedded
/// frame — if one could exist, which `frame-ancestors 'none'` says it cannot —
/// still could not ask for a credential. The camera, microphone, geolocation
/// and payment denials are carried over from the transport layer rather than
/// dropped: a single `Permissions-Policy` header replaces the other, so a
/// document-level value that omitted them would *widen* what a login page may
/// do, which is the opposite of what a stricter layer should mean.
const PERMISSIONS_POLICY: HeaderValue = HeaderValue::from_static(
    "camera=(), microphone=(), geolocation=(), payment=(), \
     publickey-credentials-get=(self), publickey-credentials-create=(self)",
);

/// No page this server renders may be stored.
///
/// Every one of them is per-session: a login form with a CSRF token, a consent
/// screen naming the subject, an error page quoting an interaction id. A
/// cached copy is that session shown to the next person on a shared machine, or
/// to the back button after a logout — the browser-history family of leaks that
/// RFC 9700 §4.3 is about, arriving through the cache instead of the URL.
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");

const OPENER_POLICY_HEADER: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
const PERMISSIONS_POLICY_HEADER: HeaderName = HeaderName::from_static("permissions-policy");

/// The policy served when a rendered one cannot be a header value.
///
/// It cannot happen: [`FormActionOrigin`] admits no character that
/// [`HeaderValue`] rejects, and a nonce is `base64url`. But "cannot happen" on
/// a request path is either a panic or a fallback, and a panic here is a page
/// an attacker can turn into a 500 if the reasoning above is ever wrong. This
/// is the fallback, and it fails *closed*: no nonce, so no script and no style
/// run at all.
const LOCKDOWN: HeaderValue = HeaderValue::from_static(
    "default-src 'none'; form-action 'self'; frame-ancestors 'none'; \
     base-uri 'none'; object-src 'none'",
);

/// An HTML response, and the only way this server produces one.
///
/// The constructor takes a [`Nonce`], which outside a test can only have come
/// from the request extensions [`layer`] populates. That is the whole design of
/// this module: "the page and the header agree" is not a rule a handler follows
/// but a consequence of there being one nonce per request and no way to render
/// without it. `every_html_response_is_produced_by_the_document_type` keeps
/// that true for pages nobody has written yet, by failing the build on a
/// `text/html` response built any other way.
#[derive(Debug)]
pub struct Document {
    body: String,
    policy: Policy,
}

impl Document {
    /// Renders a document, handing the renderer the nonce its tags need.
    ///
    /// The closure exists so the nonce arrives *in* the rendering scope rather
    /// than next to it: a template that needs `<script nonce="…">` has the
    /// value in hand, and one that has no script simply ignores it and is
    /// served under a policy that runs nothing.
    #[must_use]
    pub fn render(nonce: &Nonce, render: impl FnOnce(&Nonce) -> String) -> Self {
        Self {
            body: render(nonce),
            policy: Policy::strict(),
        }
    }

    /// Marks this document as a `response_mode=form_post` page submitting to
    /// `origin` (`ast-gxh.5`).
    ///
    /// The policy travels to [`layer`] in the response extensions rather than
    /// being written into a header here, so that there is still exactly one
    /// place that emits a `Content-Security-Policy` — a handler can widen
    /// `form-action` by one registered origin and can do nothing else.
    #[must_use]
    pub fn with_form_post_to(mut self, origin: FormActionOrigin) -> Self {
        self.policy = self.policy.with_form_post_to(origin);
        self
    }
}

impl IntoResponse for Document {
    fn into_response(self) -> Response {
        let mut response = (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            )],
            self.body,
        )
            .into_response();
        response.extensions_mut().insert(self.policy);
        response
    }
}

/// Draws a nonce for the request and hardens the response if it is a document.
///
/// The nonce is drawn on the way in, so a handler can extract it as
/// `Extension<Nonce>`, and the header is written on the way out from that same
/// value — the header and the page cannot name different nonces because there
/// is only one nonce, and nothing in between can reach it.
///
/// Every header here is written rather than defaulted, which is the opposite of
/// the transport layer's rule. There, a handler that set a header had made a
/// considered choice worth keeping. Here, the only choices are stricter or
/// weaker, weaker is never right, and the way to vary the policy is [`Policy`]
/// — so a hand-set `Content-Security-Policy` is overwritten rather than
/// honoured.
pub async fn layer(mut request: Request, next: Next) -> Response {
    let nonce = Nonce::generate();
    request.extensions_mut().insert(nonce.clone());

    let mut response = next.run(request).await;
    if !is_document(&response) {
        return response;
    }

    let policy = response
        .extensions()
        .get::<Policy>()
        .cloned()
        .unwrap_or_else(Policy::strict);
    let policy = HeaderValue::try_from(policy.header_value(&nonce)).unwrap_or(LOCKDOWN);

    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, policy);
    headers.insert(header::REFERRER_POLICY, REFERRER_POLICY);
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, NOSNIFF);
    headers.insert(OPENER_POLICY_HEADER, OPENER_POLICY);
    headers.insert(PERMISSIONS_POLICY_HEADER, PERMISSIONS_POLICY);
    headers.insert(header::CACHE_CONTROL, NO_STORE);
    response
}

/// Whether this response is something a browser will parse as a document.
///
/// The `Content-Type` decides, not the route, so a document served from
/// anywhere — a future console shell, an error page rendered by a fallback —
/// is covered, and a JSON protocol response is not.
fn is_document(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|essence| {
            let essence = essence.trim();
            essence.eq_ignore_ascii_case("text/html")
                || essence.eq_ignore_ascii_case("application/xhtml+xml")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn with_content_type(value: &str) -> Response {
        Response::builder()
            .header(header::CONTENT_TYPE, value)
            .body(Body::empty())
            .expect("a response")
    }

    #[test]
    fn only_a_document_content_type_is_hardened() {
        for document in [
            "text/html",
            "text/html; charset=utf-8",
            "text/html;charset=UTF-8",
            "TEXT/HTML",
            "application/xhtml+xml",
        ] {
            assert!(is_document(&with_content_type(document)), "{document}");
        }
        for other in [
            "application/json",
            "application/jwk-set+json",
            "text/plain; charset=utf-8",
            "application/x-www-form-urlencoded",
            // A JSON body whose type merely mentions html is still JSON.
            "application/vnd.html+json",
        ] {
            assert!(!is_document(&with_content_type(other)), "{other}");
        }
        // A 303 or a 204 carries no content type and is not a document.
        assert!(!is_document(&Response::new(Body::empty())));
    }

    /// The fallback is only worth having if it is the strict policy and not an
    /// empty one, so check what it says rather than that it exists.
    #[test]
    fn the_fallback_policy_still_forbids_everything() {
        let fallback = LOCKDOWN;
        let lockdown = fallback.to_str().expect("ascii");
        assert!(lockdown.contains("default-src 'none'"));
        assert!(lockdown.contains("frame-ancestors 'none'"));
        assert!(
            !lockdown.contains("nonce-"),
            "a fallback nonce would be a lie"
        );
        assert!(!lockdown.contains("unsafe-"));
    }

    /// A policy that cannot be a header value must degrade rather than panic on
    /// a request path.
    #[test]
    fn an_unrepresentable_policy_degrades_to_lockdown() {
        let hostile = "default-src 'none'\r\nX-Frame-Options: ALLOWALL".to_owned();
        assert_eq!(HeaderValue::try_from(hostile).unwrap_or(LOCKDOWN), LOCKDOWN);
    }

    #[test]
    fn a_document_carries_its_policy_and_an_html_content_type() {
        let nonce = Nonce::generate();
        let response = Document::render(&nonce, |nonce| {
            format!("<script {}></script>", nonce.attribute())
        })
        .into_response();

        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).expect("type"),
            "text/html; charset=utf-8"
        );
        assert!(is_document(&response));
        assert!(
            response.extensions().get::<Policy>().is_some(),
            "the policy did not reach the middleware"
        );
    }
}
