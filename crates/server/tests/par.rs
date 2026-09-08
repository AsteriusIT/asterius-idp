//! The pushed authorization request endpoint, end to end (RFC 9126).
//!
//! In-memory fakes for the store, so the whole file runs in milliseconds. What
//! is *not* faked is the validation: these push real form bodies through the
//! real parameter rules, because the endpoint's job is to be the one place
//! those rules are applied.

use asterius_domain::{
    AuthRequestRepository, Capabilities, Client, ClientId, ClientRegistration, ClientRepository,
    ClientStatus, Consumed, DomainError, Issuer, PushedRequest, Tenant, TenantId, TenantStatus,
};
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::par::{MAX_LIFETIME, REQUEST_URI_PREFIX, digest_of};
use asterius_server::http::par::{MAX_BODY_BYTES, PushContext, push};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::{Value, json};
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};

const ISSUER: &str = "https://as.example/t/demo";
const CLIENT: &str = "billing";
const REDIRECT: &str = "https://rp.example/cb";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

// ---- fakes ---------------------------------------------------------------

#[derive(Debug, Default)]
struct FakeClients(Option<Client>);

#[async_trait::async_trait]
impl ClientRepository for FakeClients {
    async fn find(&self, client_id: &ClientId) -> Result<Option<Client>, DomainError> {
        Ok(self.0.as_ref().filter(|c| c.id == *client_id).cloned())
    }
}

#[derive(Debug, Default)]
struct FakeRequests(Mutex<Vec<PushedRequest>>);

#[async_trait::async_trait]
impl AuthRequestRepository for FakeRequests {
    async fn push(&self, request: &PushedRequest) -> Result<(), DomainError> {
        self.0.lock().expect("lock").push(request.clone());
        Ok(())
    }

    async fn consume(&self, digest: &str, now: OffsetDateTime) -> Result<Consumed, DomainError> {
        let mut stored = self.0.lock().expect("lock");
        match stored.iter().position(|r| r.request_uri_digest == digest) {
            None => Ok(Consumed::NotFound),
            Some(i) if stored[i].expires_at <= now => Ok(Consumed::Expired),
            Some(i) => Ok(Consumed::Request(Box::new(stored.remove(i)))),
        }
    }

    async fn peek(
        &self,
        digest: &str,
        _now: OffsetDateTime,
    ) -> Result<Option<PushedRequest>, DomainError> {
        Ok(self
            .0
            .lock()
            .expect("lock")
            .iter()
            .find(|r| r.request_uri_digest == digest)
            .cloned())
    }
}

/// A store that refuses to write, for the one path that has to survive it.
#[derive(Debug)]
struct BrokenRequests;

#[async_trait::async_trait]
impl AuthRequestRepository for BrokenRequests {
    async fn push(&self, _request: &PushedRequest) -> Result<(), DomainError> {
        Err(DomainError::Storage("the database is gone".into()))
    }
    async fn consume(&self, _d: &str, _n: OffsetDateTime) -> Result<Consumed, DomainError> {
        Err(DomainError::Storage("the database is gone".into()))
    }
    async fn peek(
        &self,
        _d: &str,
        _n: OffsetDateTime,
    ) -> Result<Option<PushedRequest>, DomainError> {
        Err(DomainError::Storage("the database is gone".into()))
    }
}

// ---- fixtures ------------------------------------------------------------

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("fixed instant")
}

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::new("demo"),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: "demo".into(),
        status: TenantStatus::Active,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn client() -> Client {
    Client {
        tenant: TenantId::new("demo"),
        id: ClientId::new(CLIENT),
        registration: ClientRegistration::from_json(
            &serde_json::to_vec(&json!({
                "client_name": "Billing",
                "redirect_uris": [REDIRECT],
                "grant_types": ["authorization_code"],
                "scope": "openid profile",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }))
            .expect("serialise"),
            Capabilities::default(),
        )
        .expect("a valid registration"),
        status: ClientStatus::Active,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
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

fn valid_pairs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
        ("scope", "openid profile"),
        ("state", "xyz"),
    ]
}

/// Runs a push against a live store, with client authentication succeeding.
async fn pushed(pairs: &[(&str, &str)]) -> (StatusCode, Value, FakeRequests) {
    let requests = FakeRequests::default();
    let response = run(pairs, &requests, Ok(client())).await;
    (response.0, response.1, requests)
}

async fn run(
    pairs: &[(&str, &str)],
    requests: &dyn AuthRequestRepository,
    auth: Result<Client, ClientAuthError>,
) -> (StatusCode, Value, HeaderMap) {
    let tenant = tenant();
    let clients = FakeClients(Some(client()));
    let context = PushContext {
        tenant: &tenant,
        clients: &clients,
        requests,
        lifetime: Duration::seconds(90),
    };

    let response = push(
        context,
        &form_headers(),
        &form(pairs),
        async |_: &Attempt<'_>, _: &AssertionRules| auth,
        None,
        now(),
    )
    .await;

    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, json, headers)
}

// ---- the happy path ------------------------------------------------------

/// RFC 9126 §2.2: 201, `request_uri`, `expires_in`.
#[tokio::test]
async fn a_conforming_push_returns_a_request_uri() {
    let (status, body, store) = pushed(&valid_pairs()).await;

    assert_eq!(status, StatusCode::CREATED, "RFC 9126 §2.2 requires 201");
    let uri = body["request_uri"].as_str().expect("request_uri");
    assert!(uri.starts_with(REQUEST_URI_PREFIX), "{uri}");
    assert_eq!(body["expires_in"], 90);

    // FAPI 2.0 SP §5.3.2.2 item 12: less than 600 seconds.
    let expires_in = body["expires_in"].as_i64().expect("expires_in");
    assert!(expires_in < 600, "expires_in was {expires_in}");
    assert!(expires_in <= MAX_LIFETIME.whole_seconds());

    // Exactly one row, and it holds the digest rather than the reference.
    let stored = store.0.lock().expect("lock");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].request_uri_digest, digest_of(uri).expect("ours"));
    assert!(
        !stored[0]
            .request_uri_digest
            .contains(uri.strip_prefix(REQUEST_URI_PREFIX).expect("prefix")),
        "the reference itself reached the store"
    );
    assert_eq!(stored[0].client.as_str(), CLIENT);
    assert_eq!(stored[0].expires_at, now() + Duration::seconds(90));
}

/// The response carries a credential, so it must not be stored anywhere.
#[tokio::test]
async fn the_response_is_not_cacheable() {
    let requests = FakeRequests::default();
    let (_, _, headers) = run(&valid_pairs(), &requests, Ok(client())).await;
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
}

/// Two pushes of the same request are two independent references.
#[tokio::test]
async fn each_push_mints_a_fresh_reference() {
    let (_, first, _) = pushed(&valid_pairs()).await;
    let (_, second, _) = pushed(&valid_pairs()).await;
    assert_ne!(first["request_uri"], second["request_uri"]);
}

// ---- client authentication (FAPI 2.0 SP §5.3.2.2 item 4) ----------------

#[tokio::test]
async fn an_unauthenticated_push_is_refused() {
    let requests = FakeRequests::default();
    let (status, body, headers) =
        run(&valid_pairs(), &requests, Err(ClientAuthError::NoMethod)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
    // This server accepts no header-based scheme, so RFC 6749 §5.2's
    // `WWW-Authenticate` requirement does not apply and none is sent.
    assert!(!headers.contains_key(header::WWW_AUTHENTICATE));
    // Nothing was stored for a request that never authenticated.
    assert!(requests.0.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn a_malformed_authentication_attempt_is_a_bad_request_not_a_bad_credential() {
    let requests = FakeRequests::default();
    let (status, body, _) = run(
        &valid_pairs(),
        &requests,
        Err(ClientAuthError::MultipleMethods),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

/// An error body must not quote the request back: this endpoint is reachable
/// before authentication, so a reflected value is a reflected value.
#[tokio::test]
async fn an_error_does_not_echo_the_request() {
    let mut pairs = valid_pairs();
    pairs.retain(|(k, _)| *k != "redirect_uri");
    pairs.push(("redirect_uri", "https://attacker.example/cb"));

    let (_, body, _) = pushed(&pairs).await;
    let rendered = body.to_string();
    assert!(!rendered.contains("attacker.example"), "{rendered}");
}

// ---- the request itself --------------------------------------------------

/// RFC 9126 §2.1: `request_uri` MUST NOT be provided.
#[tokio::test]
async fn a_push_carrying_a_request_uri_is_refused() {
    let mut pairs = valid_pairs();
    pairs.push(("request_uri", "urn:ietf:params:oauth:request_uri:abc"));

    let (status, body, store) = pushed(&pairs).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(store.0.lock().expect("lock").is_empty());
}

/// FAPI 2.0 SP §5.3.2.2 item 6.
#[tokio::test]
async fn a_push_without_a_redirect_uri_is_refused() {
    let pairs: Vec<_> = valid_pairs()
        .into_iter()
        .filter(|(k, _)| *k != "redirect_uri")
        .collect();
    let (status, body, _) = pushed(&pairs).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

/// The rule that makes PAR safe to reject loudly: never redirect from here.
#[tokio::test]
async fn an_unregistered_redirect_uri_is_refused_without_a_redirect() {
    let mut pairs = valid_pairs();
    pairs.retain(|(k, _)| *k != "redirect_uri");
    pairs.push(("redirect_uri", "https://attacker.example/cb"));

    let requests = FakeRequests::default();
    let (status, body, headers) = run(&pairs, &requests, Ok(client())).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(
        !headers.contains_key(header::LOCATION),
        "a PAR endpoint that redirects is an open redirector"
    );
    assert!(!(300..400).contains(&status.as_u16()));
}

/// FAPI 2.0 SP §5.3.2.2 item 5.
#[tokio::test]
async fn a_push_without_pkce_is_refused() {
    let pairs: Vec<_> = valid_pairs()
        .into_iter()
        .filter(|(k, _)| *k != "code_challenge" && *k != "code_challenge_method")
        .collect();
    let (status, body, _) = pushed(&pairs).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

/// RFC 6749 §3.1: a parameter must not appear twice.
#[tokio::test]
async fn a_repeated_parameter_is_refused() {
    let mut pairs = valid_pairs();
    pairs.push(("scope", "openid"));
    let (status, body, store) = pushed(&pairs).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(store.0.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn only_the_code_response_type_is_accepted() {
    for wrong in ["token", "id_token", "code id_token"] {
        let mut pairs = valid_pairs();
        pairs.retain(|(k, _)| *k != "response_type");
        pairs.push(("response_type", wrong));
        let (status, body, _) = pushed(&pairs).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {wrong}");
        assert_eq!(body["error"], "unsupported_response_type");
    }
}

// ---- the transport -------------------------------------------------------

#[tokio::test]
async fn a_body_that_is_not_a_form_is_refused() {
    let tenant = tenant();
    let clients = FakeClients(Some(client()));
    let requests = FakeRequests::default();
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/json".parse().expect("h"));

    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            lifetime: Duration::seconds(90),
        },
        &headers,
        &Bytes::from_static(br#"{"response_type":"code"}"#),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client()),
        None,
        now(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

/// A charset parameter is part of the media type, not a different one.
#[tokio::test]
async fn a_form_content_type_with_a_charset_is_accepted() {
    let tenant = tenant();
    let clients = FakeClients(Some(client()));
    let requests = FakeRequests::default();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/x-www-form-urlencoded; charset=UTF-8"
            .parse()
            .expect("h"),
    );

    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            lifetime: Duration::seconds(90),
        },
        &headers,
        &form(&valid_pairs()),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client()),
        None,
        now(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
}

/// RFC 9126 §2.3 names 413.
#[tokio::test]
async fn an_oversized_body_is_refused_before_it_is_parsed() {
    let tenant = tenant();
    let clients = FakeClients(Some(client()));
    let requests = FakeRequests::default();

    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            lifetime: Duration::seconds(90),
        },
        &form_headers(),
        &Bytes::from(vec![b'a'; MAX_BODY_BYTES + 1]),
        async |_: &Attempt<'_>, _: &AssertionRules| {
            panic!("authentication ran on an oversized body");
        },
        None,
        now(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// A store that cannot write must not return a `request_uri` that refers to
/// nothing: a client would carry it to `/authorize` and be told it is invalid.
#[tokio::test]
async fn a_failed_write_is_reported_rather_than_papered_over() {
    let (status, body, _) = run(&valid_pairs(), &BrokenRequests, Ok(client())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "temporarily_unavailable");
    assert!(body["request_uri"].is_null());
}

// ---- DPoP key pinning at PAR (RFC 9449 §10.1, ast-a05.10) ---------------

/// A push carrying a proof pins the code to that key, with no `dpop_jkt`.
#[tokio::test]
async fn a_proof_on_the_push_pins_the_code_to_its_key() {
    let requests = FakeRequests::default();
    let key = asterius_domain::Kid::new("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    let tenant = tenant();
    let clients = FakeClients(Some(client()));

    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            lifetime: Duration::seconds(90),
        },
        &form_headers(),
        &form(&valid_pairs()),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client()),
        Some(&key),
        now(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let stored = requests.0.lock().expect("lock");
    assert_eq!(
        stored[0].dpop_jkt.as_deref(),
        Some("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"),
        "the proof's key was not pinned to the request"
    );
}

/// RFC 9449 §10.1 supports both spellings. A request that uses both and
/// disagrees with itself does not name a key, so it is refused rather than
/// resolved — picking one would let whoever controls the other choose.
#[tokio::test]
async fn a_proof_and_a_dpop_jkt_that_disagree_are_refused() {
    let requests = FakeRequests::default();
    let key = asterius_domain::Kid::new("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");
    let tenant = tenant();
    let clients = FakeClients(Some(client()));

    let mut pairs = valid_pairs();
    // A different, well-formed thumbprint.
    pairs.push(("dpop_jkt", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));

    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            lifetime: Duration::seconds(90),
        },
        &form_headers(),
        &form(&pairs),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client()),
        Some(&key),
        now(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        requests.0.lock().expect("lock").is_empty(),
        "a request naming two keys was stored anyway"
    );
}

/// Both spellings, agreeing, is the ordinary case and must be accepted.
#[tokio::test]
async fn a_proof_and_a_matching_dpop_jkt_are_accepted() {
    let requests = FakeRequests::default();
    let thumbprint = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    let key = asterius_domain::Kid::new(thumbprint);
    let tenant = tenant();
    let clients = FakeClients(Some(client()));

    let mut pairs = valid_pairs();
    pairs.push(("dpop_jkt", thumbprint));

    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            lifetime: Duration::seconds(90),
        },
        &form_headers(),
        &form(&pairs),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client()),
        Some(&key),
        now(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        requests.0.lock().expect("lock")[0].dpop_jkt.as_deref(),
        Some(thumbprint)
    );
}

/// `dpop_jkt` alone, with no proof on the push, is the other legal spelling.
#[tokio::test]
async fn a_dpop_jkt_without_a_proof_still_pins_the_code() {
    let thumbprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut pairs = valid_pairs();
    pairs.push(("dpop_jkt", thumbprint));

    let (status, _, store) = pushed(&pairs).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        store.0.lock().expect("lock")[0].dpop_jkt.as_deref(),
        Some(thumbprint)
    );
}
