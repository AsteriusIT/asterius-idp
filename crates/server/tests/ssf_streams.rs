//! The SSF Stream Configuration endpoint (SSF 1.0 §8.1.1, `ast-0ju.3`).
//!
//! Every test here goes through the real handler with a real signed access
//! token, a real DPoP proof and the real verifier — only the rows are faked,
//! exactly as `userinfo.rs` does. An endpoint whose credential checks were
//! stubbed would be an endpoint whose tests pass for tokens it should refuse,
//! and this one hands a third party a subscription to signals about a tenant's
//! users.
//!
//! The store's own half — the uniqueness behind §8.1.1.1's 409, the receiver
//! in every `WHERE` clause, and the abandoned events of §8.1.1.5 — is in
//! `crates/store-pg/tests/ssf_streams.rs`, where there is a database to prove
//! it against.

use asterius_domain::audit::{AuditEvent, AuditSink, EventType};
use asterius_domain::keys::{Signer as _, SigningAlgorithm};
use asterius_domain::{
    ClientId, DomainError, Grant, GrantId, Issuer, ReplayCheck, ReplayGuard, ReplayPurpose, Tenant,
    TenantId, TenantStatus,
};
use asterius_jose::{LocalKeyStore, SigningKey, thumbprint};
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::{AccessToken, Audience, Confirmation};
use asterius_server::http::dpop::{DpopEndpoint, HEADER as DPOP_HEADER};
use asterius_server::http::ssf::{
    CONFIGURATION_PATH, POLL_PATH, SsfContext, SsfStreamStore, SsfTokenStatus, streams,
};
use asterius_ssf::stream::{
    Delivery, MIN_VERIFICATION_INTERVAL, SCOPE_MANAGE, StreamConfiguration, StreamId,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";
const RECEIVER: &str = "receiver";
const SESSION_REVOKED: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
const ACCOUNT_DISABLED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled";

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
}

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::new("demo"),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: "demo".to_owned(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn configuration_url() -> String {
    format!("{ISSUER}{CONFIGURATION_PATH}")
}

fn poll_url() -> String {
    format!("{ISSUER}{POLL_PATH}")
}

// ---------------------------------------------------------------------------
// The fakes
// ---------------------------------------------------------------------------

/// The streams, in memory, keyed by receiver and identifier.
#[derive(Debug, Default)]
struct FakeStreams {
    rows: Mutex<BTreeMap<(String, String), StreamConfiguration>>,
    /// Audiences already taken, per receiver: the unique index of the real
    /// table, which is what §8.1.1.1's 409 comes from.
    denied_second_stream: bool,
}

impl FakeStreams {
    fn with_conflicts() -> Self {
        Self {
            rows: Mutex::new(BTreeMap::new()),
            denied_second_stream: true,
        }
    }

    fn key(receiver: &ClientId, stream: &StreamId) -> (String, String) {
        (receiver.as_str().to_owned(), stream.as_str().to_owned())
    }
}

#[async_trait::async_trait]
impl SsfStreamStore for FakeStreams {
    async fn create(
        &self,
        receiver: &ClientId,
        stream: &StreamConfiguration,
    ) -> Result<(), DomainError> {
        let mut rows = self.rows.lock().expect("an uncontended lock");
        if self.denied_second_stream
            && rows.iter().any(|((client, _), existing)| {
                client == receiver.as_str() && existing.audience == stream.audience
            })
        {
            return Err(DomainError::Conflict("one stream per audience".to_owned()));
        }
        rows.insert(Self::key(receiver, &stream.stream_id), stream.clone());
        Ok(())
    }

    async fn find(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
    ) -> Result<Option<StreamConfiguration>, DomainError> {
        Ok(self
            .rows
            .lock()
            .expect("an uncontended lock")
            .get(&Self::key(receiver, stream))
            .cloned())
    }

    async fn list(&self, receiver: &ClientId) -> Result<Vec<StreamConfiguration>, DomainError> {
        Ok(self
            .rows
            .lock()
            .expect("an uncontended lock")
            .iter()
            .filter(|((client, _), _)| client == receiver.as_str())
            .map(|(_, stream)| stream.clone())
            .collect())
    }

    async fn save(
        &self,
        receiver: &ClientId,
        stream: &StreamConfiguration,
    ) -> Result<bool, DomainError> {
        let mut rows = self.rows.lock().expect("an uncontended lock");
        let key = Self::key(receiver, &stream.stream_id);
        if !rows.contains_key(&key) {
            return Ok(false);
        }
        rows.insert(key, stream.clone());
        Ok(true)
    }

    async fn delete(&self, receiver: &ClientId, stream: &StreamId) -> Result<bool, DomainError> {
        Ok(self
            .rows
            .lock()
            .expect("an uncontended lock")
            .remove(&Self::key(receiver, stream))
            .is_some())
    }
}

#[async_trait::async_trait]
impl SsfTokenStatus for FakeStreams {
    async fn is_denylisted(&self, _jti: &str) -> Result<bool, DomainError> {
        Ok(false)
    }

    async fn access_tokens_revoked_before(
        &self,
        _client: &ClientId,
        _grant: Option<&GrantId>,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        Ok(None)
    }
}

#[derive(Debug)]
struct FakeReplay;

#[async_trait::async_trait]
impl ReplayGuard for FakeReplay {
    async fn claim(
        &self,
        _tenant: &TenantId,
        _purpose: ReplayPurpose,
        _subject: &str,
        _jti: &str,
        _expires_at: OffsetDateTime,
    ) -> Result<ReplayCheck, DomainError> {
        Ok(ReplayCheck::FirstUse)
    }
}

/// The trail, kept so a test can assert what was written to it.
#[derive(Debug, Default)]
struct FakeAudit(Mutex<Vec<EventType>>);

#[async_trait::async_trait]
impl AuditSink for FakeAudit {
    async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
        self.0
            .lock()
            .expect("an uncontended lock")
            .push(event.event_type);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

struct Fixture {
    keys: Arc<LocalKeyStore>,
    dpop_key: SigningKey,
    store: FakeStreams,
    audit: FakeAudit,
    access_token: String,
    dpop: DpopEndpoint,
    events_supported: BTreeSet<String>,
}

impl Fixture {
    /// A receiver holding a `client_credentials` token for the management
    /// endpoint, with `ssf.manage`.
    async fn new() -> Self {
        Self::with_token(&[SCOPE_MANAGE], &configuration_url()).await
    }

    /// The same, with the scopes and the audience a test wants to vary.
    async fn with_token(scopes: &[&str], audience: &str) -> Self {
        let keys = Arc::new(LocalKeyStore::new());
        keys.generate(&TenantId::new("demo"), SigningAlgorithm::DEFAULT)
            .expect("a tenant key");
        let dpop_key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("a DPoP key");
        let jkt = thumbprint(&dpop_key.public_jwk().expect("jwk")).expect("thumbprint");

        let mut grant = Grant::new(TenantId::new("demo"), ClientId::new(RECEIVER), now());
        grant.scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
        grant.claimed_at = Some(now());
        let claimed = grant.claim(now()).expect("a live grant");
        let unsigned = AccessToken::new(
            &Issuer::parse(ISSUER).expect("issuer"),
            &grant,
            &claimed,
            Audience::new([audience]).expect("audience"),
            Confirmation::dpop(&jkt).expect("confirmation"),
            JwtId::generate(),
            now(),
        )
        .with_grant_id()
        .build()
        .expect("an access token");
        let access_token = keys
            .sign(
                &TenantId::new("demo"),
                unsigned.required_algorithm(),
                unsigned.typ(),
                unsigned.claims(),
            )
            .await
            .expect("signed")
            .as_str()
            .to_owned();

        Self {
            keys,
            dpop_key,
            store: FakeStreams::default(),
            audit: FakeAudit::default(),
            access_token,
            dpop: DpopEndpoint::new(Arc::new(FakeReplay), None),
            events_supported: BTreeSet::new(),
        }
    }

    /// A transmitter that can emit `events`, so the intersection rule of
    /// §8.1.1 can be asserted before any emitter exists.
    fn emitting(mut self, events: &[&str]) -> Self {
        self.events_supported = events.iter().map(|event| (*event).to_owned()).collect();
        self
    }

    /// A transmitter that allows one stream per receiver per audience, which
    /// is what the real table's unique index enforces.
    fn one_stream_per_audience(mut self) -> Self {
        self.store = FakeStreams::with_conflicts();
        self
    }

    async fn call(
        &self,
        method: Method,
        headers: HeaderMap,
        query: Option<&str>,
        body: &[u8],
    ) -> Response {
        let tenant = tenant();
        streams(
            SsfContext {
                tenant: &tenant,
                store: &self.store,
                keys: self.keys.as_ref(),
                dpop: &self.dpop,
                audit: &self.audit,
                certificate: None,
                events_supported: &self.events_supported,
                now: now(),
            },
            &method,
            &headers,
            query,
            body,
        )
        .await
    }

    /// The request a conforming receiver makes.
    async fn request(&self, method: Method, query: Option<&str>, body: Value) -> Response {
        let rendered = serde_json::to_vec(&body).expect("a JSON body");
        let headers = self.authorized_headers(method.as_str());
        self.call(method, headers, query, &rendered).await
    }

    async fn post(&self, body: Value) -> Response {
        self.request(Method::POST, None, body).await
    }

    fn authorized_headers(&self, method: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", self.access_token)).expect("header"),
        );
        headers.insert(
            DPOP_HEADER,
            HeaderValue::from_str(&self.proof(method)).expect("header"),
        );
        headers
    }

    /// The proof a well-behaved receiver sends: `ath` over the token it
    /// presents, `htu` over the endpoint's URL.
    fn proof(&self, method: &str) -> String {
        let mut jwk = self.dpop_key.public_jwk().expect("jwk");
        if let Some(object) = jwk.as_object_mut() {
            object.remove("use");
        }
        let header = json!({
            "typ": "dpop+jwt",
            "alg": self.dpop_key.algorithm().as_str(),
            "jwk": jwk,
        });
        let claims = json!({
            "jti": unique_jti(),
            "htm": method,
            "htu": configuration_url(),
            "iat": now().unix_timestamp(),
            "ath": B64.encode(Sha256::digest(self.access_token.as_bytes())),
        });
        sign_by_hand(&self.dpop_key, &header, &claims)
    }

    fn trail(&self) -> Vec<EventType> {
        self.audit.0.lock().expect("an uncontended lock").clone()
    }

    /// Creates a stream and returns its identifier, for the tests that are
    /// about what happens next.
    async fn existing_stream(&self, body: Value) -> String {
        let response = self.post(body).await;
        assert_eq!(response.status(), StatusCode::CREATED, "the fixture stream");
        body_of(response).await["stream_id"]
            .as_str()
            .expect("a stream_id")
            .to_owned()
    }
}

fn sign_by_hand(key: &SigningKey, header: &Value, claims: &Value) -> String {
    let signing_input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(header).expect("header")),
        B64.encode(serde_json::to_vec(claims).expect("claims"))
    );
    let signature = key.sign(signing_input.as_bytes()).expect("sign");
    format!("{signing_input}.{}", B64.encode(signature))
}

/// A `jti` that is unique per proof, so a test that sends two is not a replay.
fn unique_jti() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("proof-{}", NEXT.fetch_add(1, Ordering::SeqCst))
}

async fn body_of(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("a JSON body")
}

// ---------------------------------------------------------------------------
// §8.1.1.1 — creation
// ---------------------------------------------------------------------------

/// §8.1.1.1: a `POST` with no `delivery` is created as a poll stream, and the
/// `endpoint_url` a receiver polls is the transmitter's.
#[tokio::test]
async fn a_creation_without_a_delivery_gets_a_poll_stream_with_our_endpoint() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture.post(json!({})).await;

    // Assert
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = body_of(response).await;
    assert_eq!(body["delivery"]["method"], json!("urn:ietf:rfc:8936"));
    let stream_id = body["stream_id"].as_str().expect("a stream_id");
    assert_eq!(
        body["delivery"]["endpoint_url"],
        json!(format!("{}/{stream_id}", poll_url())),
        "SSF 1.0 §6.1.2: the polling URL is unique per stream"
    );
}

/// RFC 8935 §2.2: a push delivery is configured over https and nothing else.
#[tokio::test]
async fn a_push_delivery_must_be_https() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let refused = fixture
        .post(json!({"delivery": {
            "method": "urn:ietf:rfc:8935",
            "endpoint_url": "http://receiver.example/events",
        }}))
        .await;
    let accepted = fixture
        .post(json!({"delivery": {
            "method": "urn:ietf:rfc:8935",
            "endpoint_url": "https://receiver.example/events",
        }}))
        .await;

    // Assert
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    assert_eq!(accepted.status(), StatusCode::CREATED);
    assert_eq!(
        body_of(accepted).await["delivery"]["endpoint_url"],
        json!("https://receiver.example/events")
    );
}

/// §8.1.1.1: a delivery method this transmitter does not support is a 400.
#[tokio::test]
async fn an_unsupported_delivery_method_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture
        .post(json!({"delivery": {"method": "urn:example:carrier-pigeon"}}))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_of(response).await["error"], json!("invalid_request"));
}

/// §8.1.1: the response carries every member the section defines, and
/// `events_delivered` is the intersection — an event this transmitter cannot
/// emit is ignored rather than refused.
#[tokio::test]
async fn the_created_stream_carries_every_member_and_the_intersection() {
    // Arrange
    let fixture = Fixture::new().await.emitting(&[SESSION_REVOKED]);

    // Act
    let response = fixture
        .post(json!({"events_requested": [SESSION_REVOKED, ACCOUNT_DISABLED]}))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = body_of(response).await;
    for member in [
        "stream_id",
        "iss",
        "aud",
        "events_supported",
        "events_requested",
        "events_delivered",
        "delivery",
        "min_verification_interval",
    ] {
        assert!(
            body.get(member).is_some(),
            "{member} is missing from {body}"
        );
    }
    assert_eq!(body["iss"], json!(ISSUER));
    assert_eq!(body["aud"], json!(RECEIVER));
    assert_eq!(body["events_delivered"], json!([SESSION_REVOKED]));
    assert_eq!(
        body["min_verification_interval"],
        json!(MIN_VERIFICATION_INTERVAL)
    );
}

/// §8.1.1.1: a receiver that already has a stream for this audience is told
/// so, rather than given a second one.
#[tokio::test]
async fn a_second_stream_for_the_same_audience_is_a_conflict() {
    // Arrange
    let fixture = Fixture::new().await.one_stream_per_audience();
    assert_eq!(fixture.post(json!({})).await.status(), StatusCode::CREATED);

    // Act
    let response = fixture.post(json!({})).await;

    // Assert
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

/// Every change to a stream is in the trail (§8, and this server's own rule).
#[tokio::test]
async fn every_change_to_a_stream_is_recorded() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream_id = fixture.existing_stream(json!({})).await;

    // Act
    fixture
        .request(
            Method::PATCH,
            None,
            json!({"stream_id": stream_id, "description": "prod"}),
        )
        .await;
    fixture
        .request(
            Method::DELETE,
            Some(&format!("stream_id={stream_id}")),
            json!({}),
        )
        .await;

    // Assert
    assert_eq!(
        fixture.trail(),
        vec![
            EventType::SSF_STREAM_CREATED,
            EventType::SSF_STREAM_UPDATED,
            EventType::SSF_STREAM_DELETED,
        ]
    );
}

// ---------------------------------------------------------------------------
// §8.1.1.2 — reading
// ---------------------------------------------------------------------------

/// §8.1.1.2: `GET` with a `stream_id` answers the stream, and never from a
/// cache.
#[tokio::test]
async fn a_get_with_a_stream_id_answers_that_stream_and_is_never_cached() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream_id = fixture
        .existing_stream(json!({"description": "prod"}))
        .await;

    // Act
    let response = fixture
        .request(
            Method::GET,
            Some(&format!("stream_id={stream_id}")),
            json!({}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .expect("no-store"),
        "no-store"
    );
    let body = body_of(response).await;
    assert_eq!(body["stream_id"], json!(stream_id));
    assert_eq!(body["description"], json!("prod"));
}

/// §8.1.1.2: `GET` with no `stream_id` lists the caller's streams, and a
/// receiver with none gets an empty list rather than an error.
#[tokio::test]
async fn a_get_without_a_stream_id_lists_the_callers_streams() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let empty = fixture.request(Method::GET, None, json!({})).await;
    let empty_body = body_of(empty).await;
    fixture.existing_stream(json!({})).await;
    let listed = fixture.request(Method::GET, None, json!({})).await;

    // Assert
    assert_eq!(empty_body, json!([]));
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(body_of(listed).await.as_array().expect("an array").len(), 1);
}

/// §8.1.1.2: a `stream_id` that is not this receiver's is a 404 — the same
/// answer an identifier that never existed gets, so the endpoint is not an
/// oracle for other receivers' streams.
#[tokio::test]
async fn another_receivers_stream_is_not_found() {
    // Arrange
    let fixture = Fixture::new().await;
    let theirs = StreamId::generate();
    fixture
        .store
        .create(
            &ClientId::new("other-receiver"),
            &StreamConfiguration {
                stream_id: theirs.clone(),
                audience: vec!["https://other.example/events".to_owned()],
                events_requested: Vec::new(),
                delivery: Delivery::Poll,
                description: None,
                inactivity_timeout: None,
            },
        )
        .await
        .expect("their stream");

    // Act
    let theirs = fixture
        .request(Method::GET, Some(&format!("stream_id={theirs}")), json!({}))
        .await;
    let invented = fixture
        .request(Method::GET, Some("stream_id=made-up"), json!({}))
        .await;

    // Assert
    assert_eq!(theirs.status(), StatusCode::NOT_FOUND);
    assert_eq!(invented.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// §8.1.1.3 — PATCH
// ---------------------------------------------------------------------------

/// §8.1.1.3: a receiver-supplied member the request does not carry is left
/// alone.
#[tokio::test]
async fn a_patch_leaves_the_members_it_does_not_carry_unchanged() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream_id = fixture
        .existing_stream(json!({"description": "prod", "inactivity_timeout": 3600}))
        .await;

    // Act
    let response = fixture
        .request(
            Method::PATCH,
            None,
            json!({"stream_id": stream_id, "description": "staging"}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_of(response).await;
    assert_eq!(body["description"], json!("staging"));
    assert_eq!(body["inactivity_timeout"], json!(3600));
}

/// §8.1.1.3: a transmitter-supplied member sent with the wrong value is an
/// error, not a change.
#[tokio::test]
async fn a_patch_that_rewrites_a_transmitter_supplied_member_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream_id = fixture.existing_stream(json!({})).await;

    // Act
    let response = fixture
        .request(
            Method::PATCH,
            None,
            json!({"stream_id": stream_id, "iss": "https://attacker.example"}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// §8.1.1: `aud` is immutable, and asking for another one is asking to be sent
/// somebody else's signals.
#[tokio::test]
async fn a_patch_cannot_move_the_audience() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream_id = fixture.existing_stream(json!({})).await;

    // Act
    let response = fixture
        .request(
            Method::PATCH,
            None,
            json!({"stream_id": stream_id, "aud": "https://elsewhere.example/events"}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// §8.1.1.3: `stream_id` is REQUIRED, and a request without one addresses
/// nothing.
#[tokio::test]
async fn a_patch_without_a_stream_id_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    fixture.existing_stream(json!({})).await;

    // Act
    let response = fixture
        .request(Method::PATCH, None, json!({"description": "prod"}))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// §8.1.1.4 — PUT
// ---------------------------------------------------------------------------

/// §8.1.1.4: a receiver-supplied member the request does not carry is deleted.
#[tokio::test]
async fn a_put_deletes_the_members_it_does_not_carry() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream_id = fixture
        .existing_stream(json!({"description": "prod", "inactivity_timeout": 3600}))
        .await;

    // Act
    let response = fixture
        .request(
            Method::PUT,
            None,
            json!({"stream_id": stream_id, "description": "staging"}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_of(response).await;
    assert_eq!(body["description"], json!("staging"));
    assert!(
        body.get("inactivity_timeout").is_none(),
        "a member the replacement did not carry survived: {body}"
    );
}

/// §8.1.1.4 replaces the receiver-supplied set and nothing else: the stream is
/// still the same stream, with the same audience.
#[tokio::test]
async fn a_put_keeps_the_identifier_and_the_audience() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream_id = fixture
        .existing_stream(json!({"description": "prod"}))
        .await;

    // Act
    let response = fixture
        .request(Method::PUT, None, json!({"stream_id": stream_id}))
        .await;

    // Assert
    let body = body_of(response).await;
    assert_eq!(body["stream_id"], json!(stream_id));
    assert_eq!(body["aud"], json!(RECEIVER));
}

// ---------------------------------------------------------------------------
// §8.1.1.5 — DELETE
// ---------------------------------------------------------------------------

/// §8.1.1.5: 204, and the stream is gone.
#[tokio::test]
async fn a_delete_answers_204_and_removes_the_stream() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream_id = fixture.existing_stream(json!({})).await;

    // Act
    let deleted = fixture
        .request(
            Method::DELETE,
            Some(&format!("stream_id={stream_id}")),
            json!({}),
        )
        .await;
    let gone = fixture
        .request(
            Method::GET,
            Some(&format!("stream_id={stream_id}")),
            json!({}),
        )
        .await;

    // Assert
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert_eq!(gone.status(), StatusCode::NOT_FOUND);
}

/// A second `DELETE` finds nothing, and says so rather than reporting a
/// deletion it did not make.
#[tokio::test]
async fn a_second_delete_is_not_found() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream_id = fixture.existing_stream(json!({})).await;
    let query = format!("stream_id={stream_id}");
    fixture
        .request(Method::DELETE, Some(&query), json!({}))
        .await;

    // Act
    let again = fixture
        .request(Method::DELETE, Some(&query), json!({}))
        .await;

    // Assert
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// §8 — the credential
// ---------------------------------------------------------------------------

/// §8: the management API is protected, and a request with no credential at
/// all reaches nothing.
#[tokio::test]
async fn a_request_without_a_token_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture.call(Method::GET, HeaderMap::new(), None, b"").await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// The token has to be for *this* resource: a receiver's token for a business
/// API is a perfectly good token and is not one this endpoint answers.
#[tokio::test]
async fn a_token_audienced_elsewhere_is_refused() {
    // Arrange
    let fixture = Fixture::with_token(&[SCOPE_MANAGE], "https://api.example/").await;

    // Act
    let response = fixture.request(Method::GET, None, json!({})).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// §8 with RFC 6749 §3.3: the token has to carry `ssf.manage`, and a receiver
/// that holds a token without it is told which scope it needs.
#[tokio::test]
async fn a_token_without_the_management_scope_is_refused() {
    // Arrange
    let fixture = Fixture::with_token(&["profile"], &configuration_url()).await;

    // Act
    let response = fixture.request(Method::GET, None, json!({})).await;

    // Assert
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("a challenge")
        .to_str()
        .expect("ASCII")
        .to_owned();
    assert!(
        challenge.contains("insufficient_scope") && challenge.contains(SCOPE_MANAGE),
        "the challenge does not name the scope: {challenge}"
    );
}

/// RFC 9449 §7.1: a DPoP-bound token presented without a proof is not a
/// credential this endpoint accepts.
#[tokio::test]
async fn a_bound_token_without_a_proof_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("DPoP {}", fixture.access_token)).expect("header"),
    );

    // Act
    let response = fixture.call(Method::GET, headers, None, b"").await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A verb §8.1.1 does not define is not one this endpoint answers, and the
/// refusal still carries the `Cache-Control` every response of this endpoint
/// does.
#[tokio::test]
async fn a_verb_the_section_does_not_define_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture.request(Method::HEAD, None, json!({})).await;

    // Assert
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .expect("no-store"),
        "no-store"
    );
}
