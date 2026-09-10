//! The pushed authorization request endpoint, end to end (RFC 9126).
//!
//! In-memory fakes for the store, so the whole file runs in milliseconds. What
//! is *not* faked is the validation: these push real form bodies through the
//! real parameter rules, because the endpoint's job is to be the one place
//! those rules are applied.

use asterius_domain::{
    AuthRequestRepository, AuthorizationDetailsType, AuthorizationDetailsTypeRepository,
    Capabilities, Client, ClientId, ClientRegistration, ClientRepository, ClientStatus, Consumed,
    DomainError, Issuer, JsonSchema, KeyStore, Kid, PublicKeyRecord, PushedRequest,
    ResourceIdentifier, ResourceServer, ResourceServerRepository, Tenant, TenantId, TenantStatus,
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

/// A tenant's registered resource servers (RFC 8707), in memory.
///
/// Default is a tenant that has registered exactly [`RESOURCE`], which is what
/// a deployment looks like the moment it is created: the tenant's own default
/// audience is registered with it.
#[derive(Debug, Default)]
struct FakeResourceServers(Vec<ResourceServer>);

#[async_trait::async_trait]
impl ResourceServerRepository for FakeResourceServers {
    async fn list(&self) -> Result<Vec<ResourceServer>, DomainError> {
        Ok(self.0.clone())
    }
}

/// The registry every test here pushes against.
fn registry() -> FakeResourceServers {
    FakeResourceServers(vec![ResourceServer {
        identifier: ResourceIdentifier::parse(RESOURCE).expect("a resource indicator"),
        scopes: None,
        default_token_lifetime: None,
    }])
}

/// A tenant's registered authorization details types (RFC 9396 §2.1), in
/// memory.
#[derive(Debug, Default)]
struct FakeDetailTypes(Vec<AuthorizationDetailsType>);

#[async_trait::async_trait]
impl AuthorizationDetailsTypeRepository for FakeDetailTypes {
    async fn list(&self) -> Result<Vec<AuthorizationDetailsType>, DomainError> {
        Ok(self.0.clone())
    }
}

/// The authorization details type registry every test here pushes against.
///
/// One type, whose schema requires the RFC 9396 §2 `type` and a
/// type-specific `instructedAmount` object — the shape §2's own payment example
/// uses, so that "fails its schema" is a case the tests can actually reach.
fn detail_types() -> FakeDetailTypes {
    FakeDetailTypes(vec![AuthorizationDetailsType {
        name: DETAIL_TYPE.to_owned(),
        schema: JsonSchema::parse(&serde_json::json!({
            "type": "object",
            "required": ["type", "instructedAmount"],
            "properties": {"instructedAmount": {"type": "object"}}
        }))
        .expect("a supported schema"),
        consent_template: Some("Initiate a payment".to_owned()),
    }])
}

const ISSUER: &str = "https://as.example/t/demo";
/// The one authorization details type the fixture tenant registers.
const DETAIL_TYPE: &str = "payment_initiation";
/// The one resource server the fixture tenant registers.
const RESOURCE: &str = "https://api.example/v1";
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
        resource_servers: &registry(),
        authorization_details_types: &detail_types(),
        keys: &NoKeys,
        policy: AuthorizationPolicy::default(),
        lifetime: Duration::seconds(90),
        certificate: None,
        request_objects: None,
        grants: None,
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
            resource_servers: &registry(),
            authorization_details_types: &detail_types(),
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
            lifetime: Duration::seconds(90),
            certificate: None,
            request_objects: None,
            grants: None,
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
            resource_servers: &registry(),
            authorization_details_types: &detail_types(),
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
            lifetime: Duration::seconds(90),
            certificate: None,
            request_objects: None,
            grants: None,
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
            resource_servers: &registry(),
            authorization_details_types: &detail_types(),
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
            lifetime: Duration::seconds(90),
            certificate: None,
            request_objects: None,
            grants: None,
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

/// The pin the code issuer reads is the one in the stored *parameters*:
/// `interaction::authorize` builds the `CodeBinding` from
/// `record.parameters["dpop_jkt"]`, and since `ast-rno` dropped the column
/// that held a second copy, those parameters are the only place it lives. A
/// push pinned by a proof alone must name its key there — otherwise the code
/// is issued unpinned, and the token endpoint has nothing to compare the
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
            resource_servers: &registry(),
            authorization_details_types: &detail_types(),
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
            lifetime: Duration::seconds(90),
            certificate: None,
            request_objects: None,
            grants: None,
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
            resource_servers: &registry(),
            authorization_details_types: &detail_types(),
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
            lifetime: Duration::seconds(90),
            certificate: None,
            request_objects: None,
            grants: None,
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
            resource_servers: &registry(),
            authorization_details_types: &detail_types(),
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
            lifetime: Duration::seconds(90),
            certificate: None,
            request_objects: None,
            grants: None,
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
        requests.0.lock().expect("lock")[0].parameters["dpop_jkt"].as_str(),
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
        store.0.lock().expect("lock")[0].parameters["dpop_jkt"].as_str(),
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

// ---- RFC 8707: resource indicators ---------------------------------------

/// A client allowed to name the tenant's registered resource server.
fn client_allowed_resources(allowed: &[&str]) -> Client {
    let mut client = client();
    client.registration.resources = allowed.iter().map(|r| (*r).to_owned()).collect();
    client
}

/// Runs a push as a client with its own resource allow-list, against the
/// fixture registry.
async fn pushed_as(client: Client, pairs: &[(&str, &str)]) -> (StatusCode, Value) {
    let tenant = tenant();
    let clients = FakeClients(Some(client.clone()));
    let requests = FakeRequests::default();
    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            resource_servers: &registry(),
            authorization_details_types: &detail_types(),
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
            lifetime: Duration::seconds(90),
            certificate: None,
            request_objects: None,
            grants: None,
        },
        &form_headers(),
        &form(pairs),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client.clone()),
        None,
        now(),
    )
    .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

/// RFC 8707 §2.1 with §2's shape rules: a fragment, a relative URI or a value
/// this deployment does not register is `invalid_target` at the pushed
/// authorization request endpoint, where the client is still on the connection
/// to be told.
#[tokio::test]
async fn a_resource_that_is_malformed_or_unregistered_is_invalid_target_at_the_push() {
    for wrong in [
        // §2: "MUST NOT include a fragment component".
        "https://api.example/v1#section",
        // §2: an *absolute* URI.
        "/v1/accounts",
        "not-a-uri",
        // §3: well formed, and not a resource server this tenant serves.
        "https://elsewhere.example/",
    ] {
        // Allowed by the client's own registration, so the only thing left to
        // refuse it is the rule under test.
        let client = client_allowed_resources(&[wrong, RESOURCE]);
        let mut pairs = valid_pairs();
        pairs.push(("resource", wrong));
        let (status, body) = pushed_as(client, &pairs).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {wrong:?}");
        assert_eq!(body["error"], "invalid_target", "for {wrong:?}: {body}");
    }
}

/// RFC 8707 §2.1: a registered resource the client may name is carried onto the
/// stored request, because §2.2's subset check at the token endpoint has
/// nothing to compare against otherwise.
#[tokio::test]
async fn a_registered_resource_is_stored_with_the_request() {
    let tenant = tenant();
    let client = client_allowed_resources(&[RESOURCE]);
    let clients = FakeClients(Some(client.clone()));
    let requests = FakeRequests::default();
    let mut pairs = valid_pairs();
    pairs.push(("resource", RESOURCE));

    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            resource_servers: &registry(),
            authorization_details_types: &detail_types(),
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
            lifetime: Duration::seconds(90),
            certificate: None,
            request_objects: None,
            grants: None,
        },
        &form_headers(),
        &form(&pairs),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client.clone()),
        None,
        now(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        requests.0.lock().expect("lock")[0].parameters["resources"],
        json!([RESOURCE])
    );
}

// ---- rich authorization requests (RFC 9396) ------------------------------

/// A client registered for [`DETAIL_TYPE`] and allowed to name [`RESOURCE`].
fn client_allowed_details(types: &[&str]) -> Client {
    let mut client = client_allowed_resources(&[RESOURCE]);
    client.registration.authorization_details_types =
        types.iter().map(|t| (*t).to_owned()).collect();
    client
}

/// RFC 9396 §2 and §5, with the acceptance criteria's limits: anything that is
/// not a bounded JSON array of objects each carrying a registered, permitted
/// `type` is `invalid_authorization_details` at the pushed authorization
/// request endpoint, where the client is still on the connection to be told.
#[tokio::test]
async fn a_malformed_authorization_details_is_refused_at_the_push() {
    let over_sixteen = serde_json::to_string(&vec![
        json!({"type": DETAIL_TYPE, "instructedAmount": {}});
        17
    ])
    .expect("serialise");
    let too_deep = format!(
        r#"[{{"type":"{DETAIL_TYPE}","instructedAmount":{{}},"d":{}{}}}]"#,
        "[".repeat(16),
        "]".repeat(16)
    );
    let too_long = json!([{
        "type": DETAIL_TYPE,
        "instructedAmount": {},
        "note": "a".repeat(9 * 1024)
    }])
    .to_string();
    let schema_failure = format!(r#"[{{"type":"{DETAIL_TYPE}"}}]"#);

    for wrong in [
        // §2: a JSON array of objects.
        "{}",
        "[7]",
        "[{}]",
        // §2: `type` is REQUIRED and a string.
        r#"[{"instructedAmount":{}}]"#,
        // §2.1: a type this tenant has not registered.
        r#"[{"type":"account_information"}]"#,
        // The element does not satisfy its type's schema.
        &schema_failure,
        // The limits, applied before any schema is consulted.
        &over_sixteen,
        &too_deep,
        &too_long,
    ] {
        let mut pairs = valid_pairs();
        pairs.push(("authorization_details", wrong));
        let (status, body) = pushed_as(client_allowed_details(&[DETAIL_TYPE]), &pairs).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {wrong:?}");
        assert_eq!(
            body["error"], "invalid_authorization_details",
            "for {wrong:?}: {body}"
        );
    }
}

/// RFC 9396 §9.2: `authorization_details_types` is the client's list, and a
/// client that registered none may name none — even a type this tenant defines.
#[tokio::test]
async fn a_type_the_client_did_not_register_is_refused_at_the_push() {
    let details = json!([{"type": DETAIL_TYPE, "instructedAmount": {}}]).to_string();
    let mut pairs = valid_pairs();
    pairs.push(("authorization_details", &details));
    let (status, body) = pushed_as(client_allowed_details(&[]), &pairs).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_authorization_details", "{body}");
}

/// The acceptance criterion: §2.2 `locations` must be a subset of the resources
/// this client may be issued a token for — the client's RFC 8707 allow-list
/// intersected with this tenant's resource server registry.
#[tokio::test]
async fn a_location_outside_the_clients_resources_is_refused_at_the_push() {
    for location in [
        // Not on this client's allow-list.
        "https://elsewhere.example/",
        // On no allow-list and in no registry.
        "https://api.example/v2",
    ] {
        let details =
            json!([{"type": DETAIL_TYPE, "instructedAmount": {}, "locations": [location]}])
                .to_string();
        let mut pairs = valid_pairs();
        pairs.push(("authorization_details", &details));
        let (status, body) = pushed_as(client_allowed_details(&[DETAIL_TYPE]), &pairs).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {location}");
        assert_eq!(
            body["error"], "invalid_authorization_details",
            "for {location}: {body}"
        );
    }
}

/// RFC 9396 §3: a well-formed, registered, permitted `authorization_details` is
/// carried onto the stored request whole — the consent page renders it and the
/// grant records it, and neither can do so from something this endpoint
/// trimmed.
#[tokio::test]
async fn an_accepted_authorization_details_is_stored_with_the_request() {
    let tenant = tenant();
    let client = client_allowed_details(&[DETAIL_TYPE]);
    let clients = FakeClients(Some(client.clone()));
    let requests = FakeRequests::default();
    let element = json!({
        "type": DETAIL_TYPE,
        "instructedAmount": {"currency": "EUR", "amount": "30"},
        "locations": [RESOURCE]
    });
    let details = json!([element]).to_string();
    let mut pairs = valid_pairs();
    pairs.push(("authorization_details", &details));

    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            resource_servers: &registry(),
            authorization_details_types: &detail_types(),
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
            lifetime: Duration::seconds(90),
            certificate: None,
            request_objects: None,
            grants: None,
        },
        &form_headers(),
        &form(&pairs),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client.clone()),
        None,
        now(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        requests.0.lock().expect("lock")[0].parameters["authorization_details"],
        json!([element])
    );
}

// ---- signed request objects (JAR, RFC 9101) -------------------------------
//
// RFC 9126 §3 allows `request` in a pushed request and forbids `request_uri`
// there. Everything below pushes a *real* signed JWT through the real
// verifier: the key is generated, the signature is checked against the JWK Set
// the client registered, and the claims reach `authorize::validate` — because
// the property under test is that a signed request and a plain one are checked
// by the same code.

/// The `kid` of the request-object signing key every JAR test uses.
const JAR_KID: &str = "jar-1";

/// A `jwks_uri` fetcher that fails, so a test that reaches the network is a
/// test that has stopped exercising what it says it does. Every client here
/// registers its keys inline.
#[derive(Debug)]
struct NoFetch;

#[async_trait::async_trait]
impl asterius_domain::ports::ClientUrlFetcher for NoFetch {
    async fn fetch(&self, _url: &str) -> Result<Vec<u8>, DomainError> {
        Err(DomainError::Invalid {
            field: "jwks_uri",
            reason: "no fetch in this test".to_owned(),
        })
    }
}

/// The client's request-object signing key, generated once for the file.
fn jar_key() -> &'static asterius_jose::SigningKey {
    static KEY: std::sync::OnceLock<asterius_jose::SigningKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        asterius_jose::SigningKey::generate(asterius_domain::SigningAlgorithm::EdDsa)
            .expect("a generated key")
    })
}

/// The same client as [`client`], holding [`jar_key`] and registered for
/// `EdDSA` request objects (OIDC Registration §2).
fn jar_client() -> Client {
    let mut jwk = jar_key().public_jwk().expect("a public JWK");
    jwk["kid"] = json!(JAR_KID);
    Client {
        registration: ClientRegistration::from_json(
            &serde_json::to_vec(&json!({
                "client_name": "Billing",
                "redirect_uris": [REDIRECT],
                "grant_types": ["authorization_code"],
                "scope": "openid profile",
                "jwks": {"keys": [jwk]},
                "request_object_signing_alg": "EdDSA",
            }))
            .expect("serialise"),
            Capabilities::default(),
        )
        .expect("a valid registration"),
        ..client()
    }
}

/// The claims of a well-formed request object, with `overrides` merged in. A
/// `null` override removes the claim.
fn jar_claims(overrides: &Value) -> Value {
    let mut claims = json!({
        "iss": CLIENT,
        "aud": ISSUER,
        "exp": now().unix_timestamp() + 60,
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "scope": "openid profile",
        "state": "xyz",
    });
    let object = claims.as_object_mut().expect("object");
    for (name, value) in overrides.as_object().expect("an object of overrides") {
        if value.is_null() {
            object.remove(name);
        } else {
            object.insert(name.clone(), value.clone());
        }
    }
    claims
}

/// Signs `claims` as a request object with `typ` and whichever key is given.
fn signed(claims: &Value, typ: &str, key: &asterius_jose::SigningKey) -> String {
    asterius_jose::jws::sign(key, &Kid::new(JAR_KID), typ, claims)
        .expect("a signed request object")
        .as_str()
        .to_owned()
}

/// A request object this client would ordinarily send.
fn request_object(overrides: &Value) -> String {
    signed(&jar_claims(overrides), "oauth-authz-req+jwt", jar_key())
}

/// Pushes `pairs` with request objects switched **on** for the tenant.
async fn pushed_with_jar(
    pairs: &[(&str, &str)],
    client: &Client,
) -> (StatusCode, Value, FakeRequests) {
    let tenant = tenant();
    let clients = FakeClients(Some(client.clone()));
    let requests = FakeRequests::default();
    let keys = asterius_jose::client_keys::ClientKeyCache::new(std::sync::Arc::new(NoFetch));

    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            resource_servers: &registry(),
            authorization_details_types: &detail_types(),
            keys: &NoKeys,
            policy: AuthorizationPolicy::default(),
            lifetime: Duration::seconds(90),
            certificate: None,
            request_objects: Some(&keys),
            grants: None,
        },
        &form_headers(),
        &form(pairs),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client.clone()),
        None,
        now(),
    )
    .await;

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, json, requests)
}

/// The parameters the client authenticates with, which RFC 9101 §6.1 keeps
/// outside the object.
fn jar_form(object: &str) -> Vec<(&'static str, String)> {
    vec![
        ("client_id", CLIENT.to_owned()),
        ("request", object.to_owned()),
    ]
}

fn borrowed<'a>(pairs: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    pairs.iter().map(|(k, v)| (*k, v.as_str())).collect()
}

/// RFC 9126 §3 and RFC 9101 §6.1: the request is the object's claims, and the
/// stored row is what the ordinary validator made of them.
#[tokio::test]
async fn a_signed_request_object_becomes_the_authorization_request() {
    // Arrange
    let pairs = jar_form(&request_object(&json!({})));

    // Act
    let (status, body, store) = pushed_with_jar(&borrowed(&pairs), &jar_client()).await;

    // Assert
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let stored = store.0.lock().expect("lock");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].parameters["redirect_uri"], json!(REDIRECT));
    assert_eq!(stored[0].parameters["state"], json!("xyz"));
}

/// RFC 9101 §6.1: "parameters ... outside the Request Object are ignored". A
/// server that read the form as well would honour exactly the values the
/// signature exists to fix.
#[tokio::test]
async fn parameters_outside_the_object_are_ignored() {
    // Arrange: the form asks for a different state and a smaller scope.
    let mut pairs = jar_form(&request_object(&json!({})));
    pairs.push(("state", "from-the-form".to_owned()));
    pairs.push(("scope", "openid".to_owned()));

    // Act
    let (status, body, store) = pushed_with_jar(&borrowed(&pairs), &jar_client()).await;

    // Assert
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let stored = store.0.lock().expect("lock");
    assert_eq!(stored[0].parameters["state"], json!("xyz"));
    assert_eq!(stored[0].parameters["scopes"], json!(["openid", "profile"]));
}

/// RFC 9101 §6.1's exception: the client authentication parameters are not
/// ignored, and `client_id` is one of them. A form naming one client and an
/// object signed by another is a request with two authors.
#[tokio::test]
async fn a_client_id_outside_the_object_that_disagrees_with_iss_is_refused() {
    // Arrange
    let pairs = vec![
        ("client_id", "somebody-else".to_owned()),
        ("request", request_object(&json!({}))),
    ];

    // Act
    let (status, body, _) = pushed_with_jar(&borrowed(&pairs), &jar_client()).await;

    // Assert
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], json!("invalid_request"));
}

/// RFC 9126 §3: `request_uri` "MUST NOT be provided" in a pushed request, with
/// or without an object beside it.
#[tokio::test]
async fn a_request_uri_in_a_pushed_request_is_refused() {
    for extra in [
        vec![(
            "request_uri",
            "urn:ietf:params:oauth:request_uri:abc".to_owned(),
        )],
        vec![
            (
                "request_uri",
                "urn:ietf:params:oauth:request_uri:abc".to_owned(),
            ),
            ("request", request_object(&json!({}))),
        ],
    ] {
        // Arrange
        let mut pairs: Vec<(&'static str, String)> = vec![("client_id", CLIENT.to_owned())];
        pairs.extend(extra);

        // Act
        let (status, body, _) = pushed_with_jar(&borrowed(&pairs), &jar_client()).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("invalid_request"), "{body}");
    }
}

/// RFC 9101 §6.3 and ADR-0003: the object is signed with the algorithm the
/// client registered, and `none` is not an algorithm that exists here.
#[tokio::test]
async fn an_object_whose_signature_is_not_the_clients_is_refused() {
    let other = asterius_jose::SigningKey::generate(asterius_domain::SigningAlgorithm::Ps256)
        .expect("a generated key");
    let unsigned = {
        // `alg: none`, the classic. It never reaches a key: `jws::parse`
        // refuses the algorithm before anything else happens.
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(br#"{"alg":"none","typ":"oauth-authz-req+jwt"}"#);
        let payload = b64.encode(serde_json::to_vec(&jar_claims(&json!({}))).expect("serialise"));
        format!("{header}.{payload}.")
    };

    for object in [
        // Signed by a key the client never registered, with an algorithm it
        // did not register either.
        signed(&jar_claims(&json!({})), "oauth-authz-req+jwt", &other),
        unsigned,
        // Not a JWS at all.
        "not.a.jwt".to_owned(),
    ] {
        // Arrange
        let pairs = jar_form(&object);

        // Act
        let (status, body, _) = pushed_with_jar(&borrowed(&pairs), &jar_client()).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], json!("invalid_request_object"), "{body}");
    }
}

/// RFC 9101 §10.8 and RFC 8725 §3.11: a JWT minted for one purpose must not be
/// presentable as another, and only `typ` says which purpose that was.
#[tokio::test]
async fn an_object_without_the_registered_media_type_is_refused() {
    for typ in ["JWT", "at+jwt", "dpop+jwt"] {
        // Arrange
        let pairs = jar_form(&signed(&jar_claims(&json!({})), typ, jar_key()));

        // Act
        let (status, body, _) = pushed_with_jar(&borrowed(&pairs), &jar_client()).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "accepted typ {typ}");
        assert_eq!(body["error"], json!("invalid_request_object"));
    }
}

/// OIDC Core §6.3 items 2 and 3, and RFC 9101 §10.2: the object names this
/// client, this issuer as a string, and an expiry that is soon.
#[tokio::test]
async fn the_claims_oidc_core_requires_are_checked() {
    for overrides in [
        json!({"iss": "somebody-else"}),
        json!({"iss": null}),
        json!({"aud": "https://other.example"}),
        json!({"aud": [ISSUER]}),
        json!({"aud": null}),
        json!({"exp": null}),
        json!({"exp": now().unix_timestamp() - 1}),
        json!({"exp": now().unix_timestamp() + 601}),
    ] {
        // Arrange
        let pairs = jar_form(&request_object(&overrides));

        // Act
        let (status, body, _) = pushed_with_jar(&borrowed(&pairs), &jar_client()).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "accepted {overrides}");
        assert_eq!(
            body["error"],
            json!("invalid_request_object"),
            "{overrides}"
        );
    }
}

/// OIDC Registration §2: a client that registered no
/// `request_object_signing_alg` never asked to send request objects, and there
/// is no default that would not be this server choosing an algorithm for it.
#[tokio::test]
async fn a_client_that_registered_no_algorithm_may_not_send_an_object() {
    // Arrange: the file's ordinary client, which registers none.
    let pairs = jar_form(&request_object(&json!({})));

    // Act
    let (status, body, _) = pushed_with_jar(&borrowed(&pairs), &client()).await;

    // Assert
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], json!("invalid_request_object"), "{body}");
}

/// The point of the whole module: the object is an envelope, so a parameter
/// that is invalid inside it fails the same way it fails in a plain push.
#[tokio::test]
async fn an_invalid_parameter_inside_the_object_gives_the_plain_error() {
    // Arrange: an `authorization_details` element with no `type`, sent both
    // ways (RFC 9396 §2).
    let broken = json!([{"actions": ["read"]}]);
    let encoded = broken.to_string();
    let mut plain = valid_pairs();
    plain.push(("authorization_details", &encoded));

    // Act
    let (plain_status, plain_body, _) = pushed(&plain).await;
    let pairs = jar_form(&request_object(&json!({"authorization_details": broken})));
    let (jar_status, jar_body, _) = pushed_with_jar(&borrowed(&pairs), &jar_client()).await;

    // Assert
    assert_eq!(plain_status, StatusCode::BAD_REQUEST, "{plain_body}");
    assert_eq!(jar_status, plain_status);
    assert_eq!(jar_body["error"], plain_body["error"]);
    assert_eq!(
        jar_body["error_description"],
        plain_body["error_description"]
    );
}

/// RFC 9396 §3 and OIDC Core §5.5: JSON inside the object, a JSON string in a
/// form, and one validator for both — so a *valid* rich request survives the
/// crossing intact.
#[tokio::test]
async fn json_valued_parameters_survive_the_crossing() {
    // Arrange
    let element = json!({
        "type": DETAIL_TYPE,
        "instructedAmount": {"currency": "EUR", "amount": "12.00"},
    });
    let pairs = jar_form(&request_object(
        &json!({"authorization_details": [element.clone()]}),
    ));
    let mut client = jar_client();
    client.registration.authorization_details_types =
        std::iter::once(DETAIL_TYPE.to_owned()).collect();

    // Act
    let (status, body, store) = pushed_with_jar(&borrowed(&pairs), &client).await;

    // Assert
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(
        store.0.lock().expect("lock")[0].parameters["authorization_details"],
        json!([element])
    );
}

/// The flag and the behaviour are one decision: with request objects off, the
/// parameter is refused with the code OIDC Core §3.1.2.6 defines, which is what
/// `request_parameter_supported: false` tells a client to expect.
#[tokio::test]
async fn a_request_object_is_refused_when_the_tenant_does_not_accept_them() {
    // Arrange
    let object = request_object(&json!({}));
    let mut pairs = valid_pairs();
    pairs.push(("request", object.as_str()));

    // Act
    let (status, body, _) = pushed(&pairs).await;

    // Assert
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], json!("request_not_supported"));
}

// ---- Grant Management (ID1 §5.1, §5.2, §5.4, §7.1) ------------------------

/// This tenant's grants, in memory, for the `grant_id` lookup §5.4 needs.
///
/// `amend` is never reached from this endpoint — the push validates and stores,
/// and the amendment happens after a person consents — so it records what it
/// was asked to do and asserts nothing more.
#[derive(Debug, Default)]
struct FakeGrants(Vec<asterius_domain::Grant>);

#[async_trait::async_trait]
impl asterius_domain::GrantAmendments for FakeGrants {
    async fn find(
        &self,
        id: &asterius_domain::GrantId,
    ) -> Result<Option<asterius_domain::Grant>, DomainError> {
        Ok(self.0.iter().find(|grant| grant.id == *id).cloned())
    }

    async fn amend(
        &self,
        _grant: &asterius_domain::Grant,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        panic!("the pushed request endpoint must never amend a grant")
    }
}

/// A store whose every read fails, so that "we cannot tell" can be told apart
/// from "no such grant".
#[derive(Debug)]
struct UnreachableGrants;

#[async_trait::async_trait]
impl asterius_domain::GrantAmendments for UnreachableGrants {
    async fn find(
        &self,
        _id: &asterius_domain::GrantId,
    ) -> Result<Option<asterius_domain::Grant>, DomainError> {
        Err(DomainError::Storage("the store is unreachable".into()))
    }

    async fn amend(
        &self,
        _grant: &asterius_domain::Grant,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Err(DomainError::Storage("the store is unreachable".into()))
    }
}

/// A live grant of the fixture client, held by somebody.
fn held_grant() -> asterius_domain::Grant {
    let mut grant = asterius_domain::Grant::new(
        TenantId::parse("demo").expect("a tenant id"),
        ClientId::new(CLIENT),
        now(),
    );
    grant.user = Some(asterius_domain::UserId::generate());
    grant.scopes = ["openid".to_owned()].into_iter().collect();
    grant
}

/// The push a tenant with `Feature::GrantManagement` on would run.
async fn pushed_with_grant_management(
    pairs: &[(&str, &str)],
    grants: &dyn asterius_domain::GrantAmendments,
    action_required: bool,
) -> (StatusCode, Value, FakeRequests) {
    let tenant = tenant();
    let clients = FakeClients(Some(client()));
    let requests = FakeRequests::default();
    let context = PushContext {
        tenant: &tenant,
        clients: &clients,
        requests: &requests,
        resource_servers: &registry(),
        authorization_details_types: &detail_types(),
        keys: &NoKeys,
        policy: AuthorizationPolicy::default().with_grant_management(
            asterius_oidc::grant_management::Policy::new(true, action_required),
        ),
        lifetime: Duration::seconds(90),
        certificate: None,
        request_objects: None,
        grants: Some(grants),
    };

    let response = push(
        context,
        &form_headers(),
        &form(pairs),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client()),
        None,
        now(),
    )
    .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, json, requests)
}

/// §5.4: "`grant_management_action` is set to `create` and a `grant_id` is
/// present".
#[tokio::test]
async fn create_with_a_grant_id_is_refused_at_the_push() {
    let held = held_grant();
    let mut pairs = valid_pairs();
    pairs.push(("grant_management_action", "create"));
    let id = held.id.as_str().to_owned();
    pairs.push(("grant_id", &id));

    let (status, body, store) =
        pushed_with_grant_management(&pairs, &FakeGrants(vec![held.clone()]), false).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
    assert!(store.0.lock().expect("lock").is_empty());
}

/// §5.4: "a `grant_id` is present but `grant_management_action` is missing".
#[tokio::test]
async fn a_grant_id_without_an_action_is_refused_at_the_push() {
    let held = held_grant();
    let mut pairs = valid_pairs();
    let id = held.id.as_str().to_owned();
    pairs.push(("grant_id", &id));

    let (status, body, _) =
        pushed_with_grant_management(&pairs, &FakeGrants(vec![held]), false).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

/// §5.4: an action this server does not support.
#[tokio::test]
async fn an_unsupported_action_is_refused_at_the_push() {
    let mut pairs = valid_pairs();
    pairs.push(("grant_management_action", "revoke"));

    let (status, body, _) =
        pushed_with_grant_management(&pairs, &FakeGrants::default(), false).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");
}

/// §5.4's `invalid_grant_id`: a grant this tenant does not hold, and a grant
/// held by another client, are told apart from nothing and get one code.
#[tokio::test]
async fn an_unknown_grant_or_another_clients_grant_is_invalid_grant_id() {
    let mut theirs = held_grant();
    theirs.client = ClientId::new("somebody-else");
    let unknown = held_grant();

    for (label, store) in [
        ("unknown", FakeGrants::default()),
        ("another client's", FakeGrants(vec![theirs.clone()])),
    ] {
        let target = if label == "unknown" {
            &unknown
        } else {
            &theirs
        };
        let id = target.id.as_str().to_owned();
        let mut pairs = valid_pairs();
        pairs.push(("grant_management_action", "merge"));
        pairs.push(("grant_id", &id));

        let (status, body, requests) = pushed_with_grant_management(&pairs, &store, false).await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{label}");
        assert_eq!(body["error"], "invalid_grant_id", "{label}");
        assert!(
            requests.0.lock().expect("lock").is_empty(),
            "{label}: a refused push stored a request"
        );
    }
}

/// §5.2 amends "an existing grant", and a revoked one is not that: merging into
/// it would bring a withdrawn authorization back under an id the client holds.
#[tokio::test]
async fn a_revoked_grant_is_invalid_grant_id() {
    let mut revoked = held_grant();
    revoked.revoked_at = Some(now());
    revoked.revocation_reason = Some(asterius_domain::RevocationReason::UserRevoked);
    let id = revoked.id.as_str().to_owned();
    let mut pairs = valid_pairs();
    pairs.push(("grant_management_action", "replace"));
    pairs.push(("grant_id", &id));

    let (status, body, _) =
        pushed_with_grant_management(&pairs, &FakeGrants(vec![revoked]), false).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant_id");
}

/// A store that cannot be read is an outage, not a withdrawn grant. Telling a
/// client `invalid_grant_id` would make every client believe its authorizations
/// were revoked.
#[tokio::test]
async fn a_grant_store_that_cannot_be_read_is_temporarily_unavailable() {
    let id = held_grant().id.as_str().to_owned();
    let mut pairs = valid_pairs();
    pairs.push(("grant_management_action", "merge"));
    pairs.push(("grant_id", &id));

    let (status, body, _) = pushed_with_grant_management(&pairs, &UnreachableGrants, false).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "temporarily_unavailable");
}

/// The accepted pair reaches the stored request, because the handler that
/// applies §5.2 runs an hour later and has no other way to learn what was
/// asked for.
#[tokio::test]
async fn an_accepted_action_and_grant_id_are_stored_with_the_request() {
    let held = held_grant();
    let id = held.id.as_str().to_owned();
    let mut pairs = valid_pairs();
    pairs.push(("grant_management_action", "merge"));
    pairs.push(("grant_id", &id));

    let (status, _, store) =
        pushed_with_grant_management(&pairs, &FakeGrants(vec![held]), false).await;

    assert_eq!(status, StatusCode::CREATED);
    let stored = store.0.lock().expect("lock");
    assert_eq!(stored[0].parameters["grant_management_action"], "merge");
    assert_eq!(stored[0].parameters["grant_id"], id);
}

/// §7.1: a tenant that requires the action refuses a request without one, and
/// the metadata it publishes says so — `provider_metadata`'s own test.
#[tokio::test]
async fn a_tenant_that_requires_an_action_refuses_a_request_without_one() {
    let (status, body, _) =
        pushed_with_grant_management(&valid_pairs(), &FakeGrants::default(), true).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_request");

    // And the same request naming an action is accepted.
    let mut pairs = valid_pairs();
    pairs.push(("grant_management_action", "create"));
    let (status, _, store) =
        pushed_with_grant_management(&pairs, &FakeGrants::default(), true).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(
        store.0.lock().expect("lock")[0].parameters["grant_management_action"],
        "create"
    );
}

/// With the flag off, both parameters are ignored: the push succeeds and the
/// stored request carries neither. A refusal would be worse — a client that
/// sends a parameter this deployment never advertised gets the ordinary
/// authorization a server built before the draft would have given it.
#[tokio::test]
async fn with_the_flag_off_both_parameters_are_ignored() {
    let mut pairs = valid_pairs();
    pairs.push(("grant_management_action", "merge"));
    pairs.push(("grant_id", "1e6f1b1a-0000-4000-8000-000000000000"));

    // `pushed` builds the context with `grants: None` and the default policy,
    // which is a deployment that does not offer Grant Management.
    let (status, _, store) = pushed(&pairs).await;

    assert_eq!(status, StatusCode::CREATED);
    let stored = store.0.lock().expect("lock");
    assert_eq!(stored[0].parameters["grant_management_action"], Value::Null);
    assert_eq!(stored[0].parameters["grant_id"], Value::Null);
}

/// §5.1: "Grant Management is only supported for confidential clients."
///
/// Nothing validates that here, and this test is why it does not need to: a
/// push without client authentication never reaches the validator at all (ADR
/// -0002 makes PAR the only way in, FAPI 2.0 SP §5.3.2.2 item 4 makes it
/// authenticated), so a public client cannot express these parameters. Every
/// client this server registers is confidential for the same reason.
#[tokio::test]
async fn a_public_client_cannot_reach_these_parameters_at_all() {
    let mut pairs = valid_pairs();
    pairs.push(("grant_management_action", "create"));
    let requests = FakeRequests::default();

    let (status, body, _) = run(&pairs, &requests, Err(ClientAuthError::NoMethod)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid_client");
    assert!(requests.0.lock().expect("lock").is_empty());
}

/// The two parameters are read from a signed request object by the same
/// validator that reads them from the form (RFC 9101 §6.1, `ast-gxh.9`).
///
/// Nothing in this feature knows about JAR, and that is the point: the pushed
/// request endpoint unwraps the object *before* validation, so `grant_id` and
/// `grant_management_action` are ordinary parameters by the time §5.4 sees
/// them. This test is what keeps that true — a second reader for the signed
/// spelling would be a second set of rules about the same request.
#[tokio::test]
async fn the_parameters_are_validated_the_same_way_inside_a_request_object() {
    // Arrange: a signed object that breaks §5.4 by naming a grant with
    // `create`, and one that asks for a merge of a grant this client holds.
    let held = held_grant();
    let id = held.id.as_str().to_owned();
    let contradictory = request_object(&json!({
        "grant_management_action": "create",
        "grant_id": id,
    }));
    let mergeable = request_object(&json!({
        "grant_management_action": "merge",
        "grant_id": id,
    }));

    // Act
    let refused = pushed_with_jar_and_grant_management(
        &borrowed(&jar_form(&contradictory)),
        &FakeGrants(vec![held.clone()]),
    )
    .await;
    let accepted = pushed_with_jar_and_grant_management(
        &borrowed(&jar_form(&mergeable)),
        &FakeGrants(vec![held]),
    )
    .await;

    // Assert
    assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{:?}", refused.1);
    assert_eq!(refused.1["error"], "invalid_request");
    assert_eq!(accepted.0, StatusCode::CREATED, "{:?}", accepted.1);
    let stored = accepted.2.0.lock().expect("lock");
    assert_eq!(stored[0].parameters["grant_management_action"], "merge");
    assert_eq!(stored[0].parameters["grant_id"], id);
}

/// A push with both request objects and Grant Management switched on.
async fn pushed_with_jar_and_grant_management(
    pairs: &[(&str, &str)],
    grants: &dyn asterius_domain::GrantAmendments,
) -> (StatusCode, Value, FakeRequests) {
    let tenant = tenant();
    let client = jar_client();
    let clients = FakeClients(Some(client.clone()));
    let requests = FakeRequests::default();
    let keys = asterius_jose::client_keys::ClientKeyCache::new(std::sync::Arc::new(NoFetch));

    let response = push(
        PushContext {
            tenant: &tenant,
            clients: &clients,
            requests: &requests,
            resource_servers: &registry(),
            authorization_details_types: &detail_types(),
            keys: &NoKeys,
            policy: AuthorizationPolicy::default()
                .with_grant_management(asterius_oidc::grant_management::Policy::new(true, false)),
            lifetime: Duration::seconds(90),
            certificate: None,
            request_objects: Some(&keys),
            grants: Some(grants),
        },
        &form_headers(),
        &form(pairs),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client.clone()),
        None,
        now(),
    )
    .await;

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, json, requests)
}
