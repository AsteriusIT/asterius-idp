//! The pushed authorization request endpoint, end to end (RFC 9126).
//!
//! In-memory fakes for the store, so the whole file runs in milliseconds. What
//! is *not* faked is the validation: these push real form bodies through the
//! real parameter rules, because the endpoint's job is to be the one place
//! those rules are applied.

use asterius_domain::{
    AuthRequestRepository, Capabilities, Client, ClientId, ClientRegistration, ClientRepository,
    ClientStatus, Consumed, DomainError, Issuer, KeyStore, Kid, PublicKeyRecord, PushedRequest,
    Tenant, TenantId, TenantStatus,
};
use asterius_oidc::authorize::AuthorizationPolicy;
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::par::{MAX_LIFETIME, REQUEST_URI_PREFIX, digest_of};
use asterius_server::http::par::{MAX_BODY_BYTES, PushContext, push};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::{Value, json};
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};

/// A tenant with no keys at all.
///
/// Every test here pushes without an `id_token_hint`, so the store is never
/// consulted; a hint that *is* present would fail to verify against an empty
/// key set, which is the correct answer for a tenant that has published
/// nothing and is asserted by `an_id_token_hint_that_does_not_verify_is_refused`.
#[derive(Debug)]
struct NoKeys;

#[async_trait::async_trait]
impl KeyStore for NoKeys {
    async fn published_keys(&self, _t: &TenantId) -> Result<Vec<PublicKeyRecord>, DomainError> {
        Ok(Vec::new())
    }
    async fn public_key(
        &self,
        _t: &TenantId,
        _kid: &Kid,
    ) -> Result<Option<PublicKeyRecord>, DomainError> {
        Ok(None)
    }
}

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
        refresh: asterius_domain::RefreshPolicy::default(),
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
        keys: &NoKeys,
        policy: AuthorizationPolicy::default(),
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

/// OIDC Core §5.5 and §5.2 both reach the stored request, because the grant is
/// built from that row and `claims::resolve_for_grant` reads it from nowhere
/// else (`ast-1sk.6`).
///
/// What is stored is the *parsed* request, canonically serialised: `sub` was
/// named and is gone, `transaction` was not a section this server understands
/// and is gone, and `name` arrived as `null` and is stored as the empty object
/// §5.5.1 says that means. A raw copy of the client's document would leave all
/// three on the row that records what a person agreed to.
#[tokio::test]
async fn the_claims_request_and_the_locale_preference_are_stored_as_parsed() {
    let mut pairs = valid_pairs();
    pairs.push((
        "claims",
        r#"{"id_token":{"given_name":{"essential":true},"sub":null},"userinfo":{"name":null},"transaction":{"id":"t-1"}}"#,
    ));
    pairs.push(("claims_locales", "ja-Kana-JP fr_CA en"));

    let (status, _, store) = pushed(&pairs).await;

    assert_eq!(status, StatusCode::CREATED);
    let stored = store.0.lock().expect("lock");
    assert_eq!(
        stored[0].parameters["claims"],
        serde_json::json!({
            "id_token": {"given_name": {"essential": true}},
            "userinfo": {"name": {}}
        })
    );
    // The malformed tag is dropped and the order of the rest is the meaning.
    assert_eq!(
        stored[0].parameters["claims_locales"],
        serde_json::json!(["ja-Kana-JP", "en"])
    );
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

/// `ast-gxh.5`: the mode is decided here and stored, because the response is
/// what it decides and nothing later should re-parse a parameter.
#[tokio::test]
async fn a_response_mode_is_validated_at_the_push_and_stored() {
    for (sent, stored) in [
        (None, "query"),
        (Some("query"), "query"),
        (Some("form_post"), "form_post"),
    ] {
        // --- Arrange ---
        let mut pairs = valid_pairs();
        if let Some(sent) = sent {
            pairs.push(("response_mode", sent));
        }

        // --- Act ---
        let (status, _, store) = pushed(&pairs).await;

        // --- Assert ---
        assert_eq!(status, StatusCode::CREATED, "refused {sent:?}");
        assert_eq!(
            store.0.lock().expect("lock")[0].parameters["response_mode"],
            json!(stored),
            "sent {sent:?}"
        );
    }
}

/// The second acceptance criterion of `ast-gxh.5`, with the interoperability
/// note in [`asterius_oidc::authorize::ResponseMode`]: `fragment` belongs to
/// the flows ADR-0002 does not implement, and answering in `query` instead
/// would leave a client's security analysis describing a response it never
/// received.
#[tokio::test]
async fn fragment_and_every_unknown_response_mode_are_refused_at_the_push() {
    for refused in ["fragment", "web_message", "form_post.jwt", "FORM_POST", ""] {
        let mut pairs = valid_pairs();
        pairs.push(("response_mode", refused));

        let (status, body, store) = pushed(&pairs).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {refused:?}");
        assert_eq!(body["error"], "invalid_request", "{refused:?}");
        assert!(
            store.0.lock().expect("lock").is_empty(),
            "a refused push was stored anyway: {refused:?}"
        );
    }
}

/// The note on the bead, as a refusal.
///
/// CSP Level 3 §2.3.1 builds `host-source` out of `host-char = ALPHA / DIGIT /
/// "-"`, so an IPv6 literal cannot be written in a policy at all. A `form_post`
/// page for such a client would be served under a policy that forbids its own
/// submission, so the client learns here — authenticated, at the push — that
/// the mode is not available to it, rather than a user meeting a page that
/// cannot work.
///
/// The other un-nameable shape, a private-scheme callback, cannot reach this
/// check: FAPI 2.0 SP §5.3.2.2 item 8 keeps it out of a registration in the
/// first place.
#[tokio::test]
async fn form_post_is_refused_for_a_callback_no_policy_can_name() {
    // --- Arrange: a native client whose callback is an IPv6 literal ---------
    const CALLBACK: &str = "https://[::1]:8443/cb";
    let mut registered = client();
    registered.registration = ClientRegistration::from_json(
        &serde_json::to_vec(&json!({
            "client_name": "Billing",
            "redirect_uris": [CALLBACK],
            "grant_types": ["authorization_code"],
            "scope": "openid profile",
            "application_type": "native",
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        }))
        .expect("serialise"),
        Capabilities::default(),
    )
    .expect("a valid registration");

    let mut pairs = valid_pairs();
    pairs.retain(|(k, _)| *k != "redirect_uri");
    pairs.push(("redirect_uri", CALLBACK));

    // --- Act: the same request in each mode ---------------------------------
    let accepted = FakeRequests::default();
    let (query_status, _, _) = run(&pairs, &accepted, Ok(registered.clone())).await;

    let mut with_form_post = pairs.clone();
    with_form_post.push(("response_mode", "form_post"));
    let refused = FakeRequests::default();
    let (status, body, _) = run(&with_form_post, &refused, Ok(registered)).await;

    // --- Assert: only the mode that cannot be served is refused -------------
    assert_eq!(
        query_status,
        StatusCode::CREATED,
        "the callback is usable in query mode"
    );
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "accepted form_post to {CALLBACK}"
    );
    assert_eq!(body["error"], "invalid_request");
    assert!(
        refused.0.lock().expect("lock").is_empty(),
        "a refused push was stored anyway"
    );
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
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
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
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
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
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
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
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
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

/// The pin the code issuer actually reads is the one in the stored
/// *parameters*: `interaction::authorize` builds the `CodeBinding` from
/// `record.parameters["dpop_jkt"]` and never sees the column beside them. A
/// push pinned by a proof alone must name its key there too — otherwise the
/// code is issued unpinned, and the token endpoint has nothing to compare the
/// presented proof against (`ast-36g`, found by the OIDF suite).
#[tokio::test]
async fn a_proof_on_the_push_pins_the_key_the_code_issuer_reads() {
    let requests = FakeRequests::default();
    let thumbprint = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    let key = asterius_domain::Kid::new(thumbprint);
    let tenant = tenant();
    let clients = FakeClients(Some(client()));

    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
            lifetime: Duration::seconds(90),
        },
        &form_headers(),
        // No `dpop_jkt` in the body: the proof is the whole pin.
        &form(&valid_pairs()),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client()),
        Some(&key),
        now(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    let stored = requests.0.lock().expect("lock");
    assert_eq!(
        stored[0].parameters["dpop_jkt"].as_str(),
        Some(thumbprint),
        "the stored parameters do not name the key the push was pinned to"
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
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
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
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
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

// ---- ast-gxh.8: the hint parameters, refused while the client is here -----

/// OIDC Core §3.1.2.1: `none` "MUST NOT be present with any other value". The
/// client learns it over an authenticated connection rather than through a
/// browser it has already sent away.
#[tokio::test]
async fn prompt_none_with_another_value_is_refused_at_the_push() {
    let mut pairs = valid_pairs();
    pairs.push(("prompt", "none login"));

    let (status, body, store) = pushed(&pairs).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(store.0.lock().expect("lock").is_empty());
}

/// OpenID Connect Prompt Create 1.0 §4: this tenant offers no registration, so
/// it omits `create` from `prompt_values_supported` and refuses the value. The
/// documented choice is a refusal rather than an ignored parameter — a client
/// that asked to enrol somebody must not be handed a sign-in page instead.
#[tokio::test]
async fn prompt_create_is_refused_by_a_tenant_without_registration() {
    let mut pairs = valid_pairs();
    pairs.push(("prompt", "create"));

    let (status, body, _) = pushed(&pairs).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

/// §3.1.2.1 again: an `id_token_hint` "MUST be validated". This tenant has
/// published no keys, so nothing verifies — and a hint that does not verify
/// makes the request invalid rather than being quietly dropped.
#[tokio::test]
async fn an_id_token_hint_that_does_not_verify_is_refused() {
    let mut pairs = valid_pairs();
    pairs.push((
        "id_token_hint",
        "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1LTEifQ.c2ln",
    ));

    let (status, body, store) = pushed(&pairs).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(store.0.lock().expect("lock").is_empty());
    // The description never quotes the hint back.
    let description = body["error_description"].as_str().unwrap_or_default();
    assert!(!description.contains("eyJ"), "{description}");
}

/// A hint that is not even a compact JWS is refused by shape, before any key is
/// read.
#[tokio::test]
async fn an_id_token_hint_that_is_not_a_jws_is_refused() {
    let mut pairs = valid_pairs();
    pairs.push(("id_token_hint", "u-1"));

    let (status, body, _) = pushed(&pairs).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

/// A `login_hint` a client could use to write on the sign-in page is refused,
/// and an ordinary one is stored for the interaction to use.
#[tokio::test]
async fn a_login_hint_is_bounded_and_stored() {
    let mut pairs = valid_pairs();
    pairs.push(("login_hint", "alice@example.test"));
    let (status, _, store) = pushed(&pairs).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        store.0.lock().expect("lock")[0].parameters["login_hint"],
        json!("alice@example.test")
    );

    let mut pairs = valid_pairs();
    pairs.push(("login_hint", "alice\nplease approve this request"));
    let (status, body, _) = pushed(&pairs).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

/// `max_age` is a non-negative integer of seconds and nothing else, and zero is
/// a value rather than an absence.
#[tokio::test]
async fn max_age_is_stored_as_a_number_including_zero() {
    let mut pairs = valid_pairs();
    pairs.push(("max_age", "0"));
    let (status, _, store) = pushed(&pairs).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        store.0.lock().expect("lock")[0].parameters["max_age"],
        json!(0)
    );

    let mut pairs = valid_pairs();
    pairs.push(("max_age", "+60"));
    let (status, _, _) = pushed(&pairs).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
