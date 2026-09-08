//! The token endpoint framework (RFC 6749 §3.2, §5.1, §5.2).
//!
//! No grant is implemented yet, so what is under test is the framework: the
//! transport rules, the dispatch, the error shape, and the caching headers
//! that must be on every response whichever grant eventually answers.

use asterius_domain::entities::client::GrantType;
use asterius_domain::{
    Capabilities, Client, ClientId, ClientRegistration, ClientRepository, ClientStatus,
    DomainError, Issuer, Tenant, TenantId, TenantStatus,
};
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::form::Parameters;
use asterius_server::http::token::{GrantHandler, MAX_BODY_BYTES, TokenContext, token};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

const ISSUER: &str = "https://as.example/t/demo";
const CLIENT: &str = "billing";

#[derive(Debug, Default)]
struct FakeClients;

#[async_trait::async_trait]
impl ClientRepository for FakeClients {
    async fn find(&self, _client_id: &ClientId) -> Result<Option<Client>, DomainError> {
        Ok(Some(client(&["authorization_code", "refresh_token"])))
    }
}

/// A handler that answers, so the framework's post-processing can be observed.
struct Stub;

#[async_trait::async_trait]
impl GrantHandler for Stub {
    fn grant(&self) -> GrantType {
        GrantType::AuthorizationCode
    }

    async fn handle(&self, _tenant: &Tenant, _client: &Client, _params: &Parameters) -> Response {
        // Deliberately sets no caching headers: RFC 6749 §5.1 is the
        // framework's job, and this asserts it does not depend on the handler.
        (
            StatusCode::OK,
            axum::Json(json!({"access_token": "t", "token_type": "DPoP"})),
        )
            .into_response()
    }
}

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::new("demo"),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        custom_host: None,
        display_name: "demo".into(),
        status: TenantStatus::Active,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

fn client(grants: &[&str]) -> Client {
    Client {
        tenant: TenantId::new("demo"),
        id: ClientId::new(CLIENT),
        registration: ClientRegistration::from_json(
            &serde_json::to_vec(&json!({
                "client_name": "Billing",
                "redirect_uris": ["https://rp.example/cb"],
                "grant_types": grants,
                "scope": "openid",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }))
            .expect("serialise"),
            Capabilities::default(),
        )
        .expect("a valid registration"),
        status: ClientStatus::Active,
        created_at: time::OffsetDateTime::UNIX_EPOCH,
        updated_at: time::OffsetDateTime::UNIX_EPOCH,
    }
}

fn form(pairs: &[(&str, &str)]) -> Bytes {
    let mut encoder = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        encoder.append_pair(k, v);
    }
    Bytes::from(encoder.finish())
}

fn form_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/x-www-form-urlencoded".parse().expect("header"),
    );
    headers
}

async fn run_with(
    pairs: &[(&str, &str)],
    grants: &[&dyn GrantHandler],
    auth: Result<Client, ClientAuthError>,
) -> (StatusCode, Value, HeaderMap) {
    let tenant = tenant();
    let clients = FakeClients;
    let response = token(
        TokenContext {
            tenant: &tenant,
            clients: &clients,
            capabilities: Capabilities::default(),
            grants,
        },
        &form_headers(),
        &form(pairs),
        async |_: &Attempt<'_>, _: &AssertionRules| auth,
    )
    .await;

    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
        headers,
    )
}

async fn run(pairs: &[(&str, &str)]) -> (StatusCode, Value, HeaderMap) {
    run_with(
        pairs,
        &[],
        Ok(client(&["authorization_code", "refresh_token"])),
    )
    .await
}

// ---- RFC 6749 §5.1: caching -------------------------------------------

/// The header that must be on every response, whoever produced it.
///
/// The stub handler deliberately sets none, so this proves the framework
/// applies it rather than each grant remembering to.
#[tokio::test]
async fn a_success_is_never_cacheable_even_when_the_handler_forgets() {
    let stub = Stub;
    let (status, body, headers) = run_with(
        &[("grant_type", "authorization_code")],
        &[&stub],
        Ok(client(&["authorization_code"])),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["access_token"], "t");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::PRAGMA], "no-cache");
}

#[tokio::test]
async fn an_error_is_never_cacheable_either() {
    let (_, _, headers) = run(&[("grant_type", "password")]).await;
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(headers[header::PRAGMA], "no-cache");
}

// ---- RFC 6749 §5.2: the error vocabulary --------------------------------

#[tokio::test]
async fn an_unknown_grant_type_is_unsupported() {
    let (status, body, _) = run(&[("grant_type", "password")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn a_grant_the_client_did_not_register_is_unauthorized() {
    let (status, body, _) = run_with(
        &[("grant_type", "refresh_token")],
        &[],
        Ok(client(&["authorization_code"])),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unauthorized_client");
}

/// RFC 6749 §3.2: "Request and response parameters MUST NOT be included more
/// than once."
#[tokio::test]
async fn a_repeated_parameter_is_refused() {
    let (status, body, _) = run(&[
        ("grant_type", "authorization_code"),
        ("grant_type", "refresh_token"),
    ])
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn a_request_without_a_grant_type_is_refused() {
    let (status, body, _) = run(&[("code", "abc")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn an_unauthenticated_request_is_refused_before_the_grant_is_considered() {
    let (status, body, _) = run_with(
        &[("grant_type", "password")],
        &[],
        Err(ClientAuthError::NoMethod),
    )
    .await;
    // `invalid_client`, not `unsupported_grant_type`: an unauthenticated
    // caller must not learn which grants this deployment implements.
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
}

/// A grant that is advertised, permitted, and not built answers 501 — the
/// client did nothing wrong.
#[tokio::test]
async fn a_grant_with_no_handler_is_not_implemented() {
    let (status, body, headers) = run(&[("grant_type", "authorization_code")]).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["error"], "temporarily_unavailable");
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
}

/// RFC 6749 §5.2 restricts `error_description` to a printable ASCII subset.
/// A description that escaped it would break a conforming client's parser.
#[tokio::test]
async fn an_error_description_is_printable_ascii() {
    let (_, body, _) = run(&[("grant_type", "unknown\u{1F600}\u{0007}")]).await;
    let description = body["error_description"].as_str().expect("description");
    assert!(
        description.chars().all(|c| (' '..='~').contains(&c)),
        "description left the ASCII subset: {description:?}"
    );
    assert!(!description.contains('"'), "{description}");
    assert!(!description.contains('\\'), "{description}");
}

/// The client-facing description is a constant, never the request.
///
/// `TokenError`'s own `Display` names the offending parameter, because an
/// operator reading a log needs to know which one. That detail must not reach
/// the response body: the parameter name was chosen by whoever sent the
/// request.
#[tokio::test]
async fn an_error_description_never_echoes_the_request() {
    let marker = "zzmarkerzz";
    for pairs in [
        vec![("grant_type", marker)],
        vec![(marker, "1"), (marker, "2")],
        vec![("grant_type", "authorization_code"), ("grant_type", marker)],
    ] {
        let (_, body, _) = run(&pairs).await;
        let rendered = body.to_string();
        assert!(
            !rendered.contains(marker),
            "the response echoed a value the client chose: {rendered}"
        );
    }
}

// ---- transport -----------------------------------------------------------

#[tokio::test]
async fn a_body_that_is_not_a_form_is_refused() {
    let tenant = tenant();
    let clients = FakeClients;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse().expect("h"));

    let response = token(
        TokenContext {
            tenant: &tenant,
            clients: &clients,
            capabilities: Capabilities::default(),
            grants: &[],
        },
        &headers,
        &Bytes::from_static(br#"{"grant_type":"authorization_code"}"#),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client(&["authorization_code"])),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn an_oversized_body_is_refused_before_authentication_runs() {
    let tenant = tenant();
    let clients = FakeClients;
    let response = token(
        TokenContext {
            tenant: &tenant,
            clients: &clients,
            capabilities: Capabilities::default(),
            grants: &[],
        },
        &form_headers(),
        &Bytes::from(vec![b'a'; MAX_BODY_BYTES + 1]),
        async |_: &Attempt<'_>, _: &AssertionRules| {
            panic!("authentication ran on an oversized body");
        },
    )
    .await;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// Unknown parameters are ignored, not refused: RFC 6749 §3.2 does not forbid
/// them, and rejecting them would break every client that adds an extension
/// parameter this server has not heard of.
#[tokio::test]
async fn unknown_parameters_are_ignored() {
    let stub = Stub;
    let (status, _, _) = run_with(
        &[
            ("grant_type", "authorization_code"),
            ("code", "abc"),
            ("some_extension", "value"),
        ],
        &[&stub],
        Ok(client(&["authorization_code"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
