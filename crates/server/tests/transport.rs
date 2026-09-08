//! Transport hardening, exercised through the assembled middleware stack.
//!
//! These drive the router directly with `oneshot` rather than over a socket:
//! the properties under test are all response-shaped, and a test that binds a
//! port is a test that is slow and occasionally flaky for reasons that have
//! nothing to do with the property. The TLS half of `ast-83p.4` is unit-tested
//! against the rustls configuration in `http::tls`.

use asterius_server::config::{Config, ServerConfig};
use asterius_server::http::server::with_middleware;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::routing::{any, get};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
use tower::ServiceExt as _;

const CONFIG: &str = r#"
    [database]
    url = "postgres://asterius@localhost/asterius"

    [[tenant]]
    id = "demo"
    issuer = "https://as.example/t/demo"
"#;

fn server_config() -> ServerConfig {
    Config::parse(CONFIG, Path::new("asterius.toml"), &BTreeMap::new())
        .expect("valid test config")
        .server
}

/// The routes that exist today, plus stand-ins for the protocol endpoints whose
/// own stories have not landed. The middleware stack is what is under test; the
/// handlers only need to produce a response for it to wrap.
fn app() -> Router {
    let routes = Router::new()
        .route("/authorize", any(|| async { "authorization endpoint" }))
        .route("/token", any(|| async { "token endpoint" }))
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                "never"
            }),
        )
        .route(
            "/echo",
            axum::routing::post(|body: String| async move { body }),
        );
    with_middleware(routes, &server_config())
}

fn app_with(config: &ServerConfig) -> Router {
    with_middleware(
        Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                "never"
            }),
        ),
        config,
    )
}

async fn send(request: Request<Body>) -> axum::response::Response {
    app().oneshot(request).await.expect("router is infallible")
}

fn get_request(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .body(Body::empty())
        .expect("request")
}

// ---------------------------------------------------------------------------
// No CORS, anywhere
// ---------------------------------------------------------------------------

/// FAPI 2.0 SP §5.2.3: the authorization endpoint must not be reachable from a
/// cross-origin script. There is no CORS layer to misconfigure, so the test is
/// that no `Access-Control-*` header appears — on a preflight, on a real
/// request with an `Origin`, or on an error.
#[tokio::test]
async fn no_endpoint_ever_answers_with_cors_headers() {
    for (method, path) in [
        ("OPTIONS", "/authorize"),
        ("GET", "/authorize"),
        ("POST", "/authorize"),
        ("OPTIONS", "/token"),
        ("POST", "/token"),
        ("GET", "/does-not-exist"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::ORIGIN, "https://attacker.example")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "authorization,dpop")
            .body(Body::empty())
            .expect("request");

        let response = send(request).await;
        let offenders: Vec<&str> = response
            .headers()
            .keys()
            .map(axum::http::HeaderName::as_str)
            .filter(|name| name.starts_with("access-control-"))
            .collect();
        assert!(
            offenders.is_empty(),
            "{method} {path} returned CORS headers: {offenders:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

/// FAPI 2.0 SP §5.2.3 requires HSTS. The value is fixed: one year, subdomains
/// included, preload — anything shorter leaves the TLS-stripping window that
/// attacker A2 is looking for.
#[tokio::test]
async fn hsts_is_present_and_exact() {
    let response = send(get_request("/authorize")).await;
    assert_eq!(
        response
            .headers()
            .get(header::STRICT_TRANSPORT_SECURITY)
            .expect("HSTS"),
        "max-age=31536000; includeSubDomains; preload"
    );
}

/// A security header that is only on the happy path is not a security header.
/// 404s and 405s come from axum's own routing, below our middleware, so they
/// are the ones most likely to be missed.
#[tokio::test]
async fn security_headers_survive_error_responses() {
    for request in [
        get_request("/does-not-exist"),
        Request::builder()
            .method("PATCH")
            .uri("/slow")
            .body(Body::empty())
            .expect("request"),
    ] {
        let response = send(request).await;
        assert!(
            response.status().is_client_error(),
            "expected an error response"
        );
        let headers = response.headers();
        assert!(
            headers.contains_key(header::STRICT_TRANSPORT_SECURITY),
            "no HSTS on an error"
        );
        assert_eq!(
            headers
                .get(header::X_CONTENT_TYPE_OPTIONS)
                .expect("nosniff"),
            "nosniff"
        );
        assert_eq!(
            headers.get(header::X_FRAME_OPTIONS).expect("frame options"),
            "DENY"
        );
        assert_eq!(
            headers.get(header::REFERRER_POLICY).expect("referrer"),
            "no-referrer"
        );
        assert!(headers.contains_key("permissions-policy"));
    }
}

// ---------------------------------------------------------------------------
// Request identity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn every_response_carries_a_fresh_request_id() {
    let first = send(get_request("/authorize")).await;
    let second = send(get_request("/authorize")).await;
    let a = first
        .headers()
        .get("x-request-id")
        .expect("request id")
        .to_str()
        .expect("ascii");
    let b = second
        .headers()
        .get("x-request-id")
        .expect("request id")
        .to_str()
        .expect("ascii");
    assert_eq!(a.len(), 32);
    assert_ne!(a, b, "the request id must not repeat");
}

/// Request ids reach the audit trail, so a caller must not be able to choose
/// one — otherwise it could collide with, or impersonate, another caller's
/// entries.
#[tokio::test]
async fn a_client_supplied_request_id_is_ignored() {
    let request = Request::builder()
        .uri("/authorize")
        .header("x-request-id", "attacker-chosen")
        .body(Body::empty())
        .expect("request");
    let response = send(request).await;
    let ids: Vec<_> = response.headers().get_all("x-request-id").iter().collect();
    assert_eq!(ids.len(), 1, "the client's id was kept alongside ours");
    assert_ne!(ids[0], "attacker-chosen");
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_body_within_the_limit_is_accepted() {
    let body = "x".repeat(64 * 1024);
    let request = Request::builder()
        .method("POST")
        .uri("/echo")
        .body(Body::from(body))
        .expect("request");
    assert_eq!(send(request).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_oversized_body_is_refused_with_413() {
    let body = "x".repeat(64 * 1024 + 1);
    let request = Request::builder()
        .method("POST")
        .uri("/echo")
        .body(Body::from(body))
        .expect("request");
    let response = send(request).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Even a refusal is a response, and it still needs the headers.
    assert!(
        response
            .headers()
            .contains_key(header::STRICT_TRANSPORT_SECURITY)
    );
}

#[tokio::test]
async fn a_request_that_outlives_its_timeout_is_abandoned_with_408() {
    let mut config = server_config();
    config.request_timeout = Duration::from_millis(50);
    let response = app_with(&config)
        .oneshot(get_request("/slow"))
        .await
        .expect("router is infallible");
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(
        response
            .headers()
            .contains_key(header::STRICT_TRANSPORT_SECURITY)
    );
    assert!(response.headers().contains_key("x-request-id"));
}
