//! The document security headers, through the assembled middleware stack.
//!
//! No interaction page exists yet — `ast-2vk.1` builds the engine that renders
//! them — so the routes here are synthetic, mounted in the test and never in
//! the shipped router. That is the point: what is under test is the middleware,
//! and a handler that does nothing but render a page is the smallest thing that
//! makes it observable. When real pages land they inherit these properties by
//! going through the same [`asterius_web::Document`].
//!
//! The grep for `'unsafe-inline'` and `'unsafe-eval'` that `ast-ndk.3` asks for
//! lives where it can be exhaustive rather than per-route: over every policy
//! the builder can produce (`asterius_web::csp`) and over every source file in
//! the workspace (`asterius_web::source_audit`). Here the served header is
//! compared to the reviewed policy in full, which subsumes it.

use asterius_server::config::{Config, ServerConfig};
use asterius_server::http::server::with_middleware;
use asterius_web::{Document, FormActionOrigin, Nonce};
use axum::Router;
use axum::body::Body;
use axum::extract::Extension;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use std::collections::BTreeMap;
use std::path::Path;
use tower::ServiceExt as _;

const CONFIG: &str = r#"
    [keys]
    kek_env = "ASTERIUS_TEST_KEK"

    [database]
    url = "postgres://asterius@localhost/asterius"
"#;

const CLIENT_ORIGIN: &str = "https://rp.example";

fn server_config() -> ServerConfig {
    Config::parse(CONFIG, Path::new("asterius.toml"), &BTreeMap::new())
        .expect("valid test config")
        .server
}

/// A page, rendered the way every page will be: the nonce comes from the
/// request extensions the middleware populated, and goes into the one tag that
/// needs it.
async fn page(Extension(nonce): Extension<Nonce>) -> Document {
    Document::render(&nonce, |nonce| {
        format!(
            "<!doctype html><html><head><script {}>window.ready=1</script></head>\
             <body><form method=\"post\"><button>Continue</button></form></body></html>",
            nonce.attribute()
        )
    })
}

/// The `response_mode=form_post` shape (`ast-gxh.5`), which is the only page
/// that submits anywhere but back to this server.
async fn form_post(Extension(nonce): Extension<Nonce>) -> Document {
    let origin = FormActionOrigin::parse(CLIENT_ORIGIN).expect("a registered origin");
    Document::render(&nonce, |_| {
        "<!doctype html><html><body><form method=\"post\"></form></body></html>".to_owned()
    })
    .with_form_post_to(origin)
}

/// A handler that tries to relax its own page: a permissive policy and a
/// cacheable response. Both must be overwritten.
async fn opinionated(Extension(nonce): Extension<Nonce>) -> Response {
    let mut response =
        Document::render(&nonce, |_| "<!doctype html><html></html>".to_owned()).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src *"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=600"),
    );
    response
}

/// A protocol response, which must not pay for any of this.
async fn protocol() -> Response {
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        r#"{"issuer":"https://as.example"}"#,
    )
        .into_response()
}

fn app() -> Router {
    with_middleware(
        Router::new()
            .route("/page", get(page))
            .route("/form-post", get(form_post))
            .route("/opinionated", get(opinionated))
            .route("/protocol", get(protocol)),
        &server_config(),
    )
}

async fn get_response(path: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let response = app()
        .oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("router is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

fn policy_of(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::CONTENT_SECURITY_POLICY)
        .expect("a Content-Security-Policy")
        .to_str()
        .expect("the policy is ASCII")
        .to_owned()
}

/// The nonce the policy names, read back out of the header.
fn nonce_in(policy: &str) -> String {
    let after = policy
        .split_once("'nonce-")
        .expect("script-src names a nonce")
        .1;
    after
        .split_once('\'')
        .expect("the nonce is quoted")
        .0
        .to_owned()
}

/// The policy `ast-ndk.3` specifies, for a given nonce.
fn expected_policy(nonce: &str, form_action: &str) -> String {
    format!(
        "default-src 'none'; \
         script-src 'nonce-{nonce}' 'strict-dynamic'; \
         style-src 'nonce-{nonce}'; \
         img-src 'self' data:; \
         font-src 'self'; \
         connect-src 'self'; \
         form-action 'self'{form_action}; \
         frame-ancestors 'none'; \
         base-uri 'none'; \
         object-src 'none'"
    )
}

// ---------------------------------------------------------------------------
// The header set
// ---------------------------------------------------------------------------

/// Every header the story names, on a document, in one assertion block — so
/// that dropping one is a failure and not a smaller diff.
#[tokio::test]
async fn a_document_carries_the_whole_header_set() {
    let (status, headers, _) = get_response("/page").await;
    assert_eq!(status, StatusCode::OK);

    let nonce = nonce_in(&policy_of(&headers));
    assert_eq!(policy_of(&headers), expected_policy(&nonce, ""));

    for (name, value) in [
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cache-control", "no-store"),
        // FAPI 2.0 SP §5.2.3, from the transport layer: a document is a
        // browser-facing response, so it gets everything that layer sets too.
        (
            "strict-transport-security",
            "max-age=31536000; includeSubDomains; preload",
        ),
    ] {
        assert_eq!(
            headers.get(name).unwrap_or_else(|| panic!("no {name}")),
            value,
            "{name}"
        );
    }

    let permissions = headers
        .get("permissions-policy")
        .expect("permissions-policy")
        .to_str()
        .expect("ASCII");
    assert!(
        permissions.contains("publickey-credentials-get=(self)")
            && permissions.contains("publickey-credentials-create=(self)"),
        "a login page cannot do WebAuthn: {permissions}"
    );
    // The document value replaces the transport one, so it has to carry the
    // denials as well as the delegations.
    assert!(permissions.contains("camera=()"), "{permissions}");
}

/// RFC 9700 §4.16 requires clickjacking to be prevented, and says the CSP
/// technique "SHOULD be combined with others" because some user agents do not
/// support CSP. So both spellings are served; CSP Level 3 §6.4.2.2 says the
/// directive wins wherever both are understood.
#[tokio::test]
async fn framing_is_refused_twice_over() {
    let (_, headers, _) = get_response("/page").await;
    assert!(policy_of(&headers).contains("frame-ancestors 'none'"));
    assert_eq!(headers.get("x-frame-options").expect("XFO"), "DENY");
}

// ---------------------------------------------------------------------------
// The nonce
// ---------------------------------------------------------------------------

/// The property the whole design exists for: the page's nonce *is* the
/// header's, and neither is reused.
#[tokio::test]
async fn the_page_nonce_is_the_header_nonce_and_changes_every_response() {
    let (_, first_headers, first_body) = get_response("/page").await;
    let (_, second_headers, second_body) = get_response("/page").await;

    let first = nonce_in(&policy_of(&first_headers));
    let second = nonce_in(&policy_of(&second_headers));

    assert!(
        first_body.contains(&format!("nonce=\"{first}\"")),
        "the page does not carry the nonce its policy names:\n{first_body}"
    );
    assert!(second_body.contains(&format!("nonce=\"{second}\"")));

    // CSP Level 3 §7.1: a unique value each time a policy is transmitted.
    assert_ne!(first, second, "the nonce was reused across responses");
    assert!(
        !second_body.contains(&first),
        "the second page carries the first page's nonce"
    );
    assert_eq!(first.len(), 22, "128 bits of base64url");
}

// ---------------------------------------------------------------------------
// What the policy does not apply to, and what cannot weaken it
// ---------------------------------------------------------------------------

/// A JSON protocol response is not a document: it executes nothing, it is not
/// framed, and `ast-o0t.3` deliberately made some of them cacheable.
#[tokio::test]
async fn a_protocol_response_does_not_get_the_document_policy() {
    let (_, headers, _) = get_response("/protocol").await;

    for absent in [
        "content-security-policy",
        "cross-origin-opener-policy",
        "cache-control",
    ] {
        assert!(
            !headers.contains_key(absent),
            "a JSON response got {absent}: {:?}",
            headers.get(absent)
        );
    }
    // ...but the transport headers, which apply to everything, are still there.
    assert!(headers.contains_key("strict-transport-security"));
    assert_eq!(headers.get("x-frame-options").expect("XFO"), "DENY");
    assert!(
        !headers
            .get("permissions-policy")
            .expect("permissions-policy")
            .to_str()
            .expect("ASCII")
            .contains("publickey-credentials"),
        "a token endpoint has no use for a WebAuthn delegation"
    );
}

/// The document layer overwrites rather than defaults, because on a page the
/// only alternatives to the reviewed policy are weaker ones.
#[tokio::test]
async fn a_handler_cannot_relax_its_own_page() {
    let (_, headers, _) = get_response("/opinionated").await;
    let nonce = nonce_in(&policy_of(&headers));
    assert_eq!(
        policy_of(&headers),
        expected_policy(&nonce, ""),
        "a handler's own policy survived"
    );
    assert_eq!(
        headers.get(header::CACHE_CONTROL).expect("cache-control"),
        "no-store",
        "an interaction page was left cacheable"
    );
}

/// `ast-gxh.5`: the `form_post` page — and only that page — names the client's
/// origin, and names exactly that origin.
#[tokio::test]
async fn a_form_post_page_names_exactly_the_redirect_uri_origin() {
    let (_, headers, _) = get_response("/form-post").await;
    let policy = policy_of(&headers);
    let nonce = nonce_in(&policy);
    assert_eq!(
        policy,
        expected_policy(&nonce, &format!(" {CLIENT_ORIGIN}"))
    );

    // The next page over is back to `'self'`, so the widening cannot leak from
    // one response into another.
    let (_, plain, _) = get_response("/page").await;
    let plain = policy_of(&plain);
    assert!(plain.contains("form-action 'self';"), "{plain}");
    assert!(!plain.contains(CLIENT_ORIGIN));
}
