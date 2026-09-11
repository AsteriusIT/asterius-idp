//! The poll delivery endpoint (RFC 8936 §2, `ast-0ju.7`).
//!
//! Every test here goes through the real handler with a real signed access
//! token, a real DPoP proof and the real verifier — only the rows are faked,
//! exactly as `ssf_streams.rs` does. An endpoint whose credential checks were
//! stubbed would be an endpoint whose tests pass for tokens it should refuse,
//! and this one hands a third party a batch of security signals about a
//! tenant's users.
//!
//! # The reference receiver
//!
//! There is no RFC 8936 receiver test suite in this repository, so
//! [`Receiver`] is one: a small client that speaks §2.1 and §2.4 the way a
//! conforming receiver does — poll, read `sets`, acknowledge every `jti` it
//! processed on the *next* request, report the ones it could not in `setErrs`,
//! and keep going while `moreAvailable` is true. The interoperability test at
//! the bottom drives a backlog through it and asserts the two properties a
//! receiver depends on: every SET arrives, and none arrives twice once it has
//! been acknowledged.
//!
//! The queue's own half — redelivery, `moreAvailable` against real rows, and
//! SSF 1.0 §8.1.1.5's rule that a deleted stream delivers nothing more — is in
//! `crates/store-pg/tests/ssf_poll.rs`, where there is a database to prove it
//! against.

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
use asterius_server::http::ssf::{POLL_PATH, SsfTokenStatus};
use asterius_server::http::ssf_poll::{
    Batch, PollTiming, QueuedSet, SsfPollContext, SsfPollStore, poll,
};
use asterius_ssf::poll::MAX_EVENTS;
use asterius_ssf::stream::{
    Delivery, SCOPE_POLL, StreamConfiguration, StreamId, poll_endpoint_for,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";
const RECEIVER: &str = "receiver";
const OTHER_RECEIVER: &str = "other-receiver";

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

/// The base polling endpoint: the `aud` a receiver's token carries.
fn poll_url() -> String {
    format!("{ISSUER}{POLL_PATH}")
}

// ---------------------------------------------------------------------------
// The fakes
// ---------------------------------------------------------------------------

/// The streams and their queues, in memory.
///
/// The queue behaves as `0030_ssf_poll_queue.sql` does: a delivery removes
/// nothing, an acknowledgement and an error report each remove what they name.
#[derive(Debug, Default)]
struct FakeQueue {
    streams: Mutex<BTreeMap<(String, String), StreamConfiguration>>,
    /// Per stream, the SETs in the order they were queued.
    sets: Mutex<BTreeMap<String, Vec<QueuedSet>>>,
}

impl FakeQueue {
    fn add_stream(&self, receiver: &str, stream: &StreamConfiguration) {
        self.streams.lock().expect("an uncontended lock").insert(
            (receiver.to_owned(), stream.stream_id.to_string()),
            stream.clone(),
        );
    }

    fn queue_set(&self, stream: &StreamId, jti: &str) {
        self.sets
            .lock()
            .expect("an uncontended lock")
            .entry(stream.as_str().to_owned())
            .or_default()
            .push(QueuedSet {
                jti: jti.to_owned(),
                jws: format!("jws.of.{jti}"),
            });
    }

    fn held(&self, stream: &StreamId) -> Vec<String> {
        self.sets
            .lock()
            .expect("an uncontended lock")
            .get(stream.as_str())
            .map(|sets| sets.iter().map(|set| set.jti.clone()).collect())
            .unwrap_or_default()
    }

    fn remove(&self, stream: &StreamId, jtis: &[String]) -> u64 {
        let mut sets = self.sets.lock().expect("an uncontended lock");
        let Some(queued) = sets.get_mut(stream.as_str()) else {
            return 0;
        };
        let before = queued.len();
        queued.retain(|set| !jtis.contains(&set.jti));
        u64::try_from(before - queued.len()).expect("a count")
    }
}

#[async_trait::async_trait]
impl SsfPollStore for FakeQueue {
    async fn find(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
    ) -> Result<Option<StreamConfiguration>, DomainError> {
        Ok(self
            .streams
            .lock()
            .expect("an uncontended lock")
            .get(&(receiver.as_str().to_owned(), stream.to_string()))
            .cloned())
    }

    async fn deliver(
        &self,
        stream: &StreamId,
        limit: usize,
        _now: OffsetDateTime,
    ) -> Result<Batch, DomainError> {
        let sets = self.sets.lock().expect("an uncontended lock");
        let held = sets.get(stream.as_str()).cloned().unwrap_or_default();
        let taken: Vec<QueuedSet> = held.iter().take(limit).cloned().collect();
        Ok(Batch {
            more_available: held.len() > taken.len(),
            sets: taken,
        })
    }

    async fn acknowledge(&self, stream: &StreamId, jtis: &[String]) -> Result<u64, DomainError> {
        Ok(self.remove(stream, jtis))
    }

    async fn reject(&self, stream: &StreamId, jtis: &[String]) -> Result<u64, DomainError> {
        Ok(self.remove(stream, jtis))
    }

    async fn has_pending(&self, stream: &StreamId) -> Result<bool, DomainError> {
        Ok(!self.held(stream).is_empty())
    }
}

#[async_trait::async_trait]
impl SsfTokenStatus for FakeQueue {
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
struct FakeAudit(Mutex<Vec<AuditEvent>>);

#[async_trait::async_trait]
impl AuditSink for FakeAudit {
    async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
        self.0.lock().expect("an uncontended lock").push(event);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

struct Fixture {
    keys: Arc<LocalKeyStore>,
    dpop_key: SigningKey,
    store: Arc<FakeQueue>,
    audit: FakeAudit,
    access_token: String,
    dpop: DpopEndpoint,
    timing: PollTiming,
    /// The stream this receiver polls.
    stream: StreamId,
}

impl Fixture {
    /// A receiver holding a `client_credentials` token for the polling
    /// endpoint, with `ssf.poll`, and one poll stream of its own.
    async fn new() -> Self {
        Self::with_token(&[SCOPE_POLL], &poll_url()).await
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

        let store = Arc::new(FakeQueue::default());
        let stream = stream_of(Delivery::Poll);
        store.add_stream(RECEIVER, &stream);

        Self {
            keys,
            dpop_key,
            store,
            audit: FakeAudit::default(),
            access_token,
            dpop: DpopEndpoint::new(Arc::new(FakeReplay), None),
            // Milliseconds, so a long-poll test is not half a minute long.
            timing: PollTiming {
                wait: Duration::from_millis(150),
                interval: Duration::from_millis(10),
            },
            stream: stream.stream_id,
        }
    }

    /// Queues `count` SETs, named `set-0`, `set-1`, …
    fn queued(self, count: usize) -> Self {
        for index in 0..count {
            self.store.queue_set(&self.stream, &format!("set-{index}"));
        }
        self
    }

    async fn call(
        &self,
        method: Method,
        headers: HeaderMap,
        addressed: &str,
        body: &[u8],
    ) -> Response {
        let tenant = tenant();
        poll(
            SsfPollContext {
                tenant: &tenant,
                store: self.store.as_ref(),
                keys: self.keys.as_ref(),
                dpop: &self.dpop,
                audit: &self.audit,
                certificate: None,
                timing: self.timing,
                now: now(),
            },
            &method,
            &headers,
            addressed,
            body,
        )
        .await
    }

    /// The request a conforming receiver makes.
    async fn post(&self, body: Value) -> Response {
        self.post_to(&self.stream.to_string(), body).await
    }

    async fn post_to(&self, addressed: &str, body: Value) -> Response {
        let rendered = serde_json::to_vec(&body).expect("a JSON body");
        let headers = self.authorized_headers("POST", addressed);
        self.call(Method::POST, headers, addressed, &rendered).await
    }

    fn authorized_headers(&self, method: &str, addressed: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", self.access_token)).expect("header"),
        );
        headers.insert(
            DPOP_HEADER,
            HeaderValue::from_str(&self.proof(method, addressed)).expect("header"),
        );
        headers
    }

    /// The proof a well-behaved receiver sends: `ath` over the token it
    /// presents, `htu` over the per-stream polling URL (SSF 1.0 §6.1.2).
    fn proof(&self, method: &str, addressed: &str) -> String {
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
            "htu": format!("{}/{addressed}", poll_url()),
            "iat": now().unix_timestamp(),
            "ath": B64.encode(Sha256::digest(self.access_token.as_bytes())),
        });
        sign_by_hand(&self.dpop_key, &header, &claims)
    }

    fn trail(&self) -> Vec<EventType> {
        self.audit
            .0
            .lock()
            .expect("an uncontended lock")
            .iter()
            .map(|event| event.event_type)
            .collect()
    }
}

/// A stream of `delivery`, the shape a `POST` with an empty body makes.
fn stream_of(delivery: Delivery) -> StreamConfiguration {
    StreamConfiguration {
        stream_id: StreamId::generate(),
        audience: vec![RECEIVER.to_owned()],
        events_requested: Vec::new(),
        delivery,
        description: None,
        inactivity_timeout: None,
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
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("a JSON body")
}

/// The identifiers a §2.3 response carries, in order.
fn delivered(body: &Value) -> Vec<String> {
    body["sets"]
        .as_object()
        .expect("§2.3's `sets` is an object")
        .keys()
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// §2.3 — the response
// ---------------------------------------------------------------------------

/// §2.3: the response maps each `jti` to the SET itself, and says whether
/// anything is being held back.
#[tokio::test]
async fn a_poll_returns_the_queued_sets_by_identifier() {
    // Arrange
    let fixture = Fixture::new().await.queued(2);

    // Act
    let response = fixture.post(json!({"returnImmediately": true})).await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_of(response).await;
    assert_eq!(delivered(&body), vec!["set-0", "set-1"]);
    assert_eq!(body["sets"]["set-0"], json!("jws.of.set-0"));
    assert_eq!(body["moreAvailable"], json!(false));
}

/// §2.1: `maxEvents` bounds the batch, and §2.3's `moreAvailable` is how the
/// receiver learns the rest are still waiting.
#[tokio::test]
async fn max_events_bounds_the_batch_and_more_is_reported() {
    // Arrange
    let fixture = Fixture::new().await.queued(3);

    // Act
    let response = fixture
        .post(json!({"maxEvents": 2, "returnImmediately": true}))
        .await;

    // Assert
    let body = body_of(response).await;
    assert_eq!(delivered(&body), vec!["set-0", "set-1"]);
    assert_eq!(body["moreAvailable"], json!(true));
}

/// This transmitter's cap: a receiver asking for more than
/// `asterius_ssf::poll::MAX_EVENTS` gets the cap, and `moreAvailable` tells it
/// to come back — so a cap costs a round trip and never an event.
#[tokio::test]
async fn a_receiver_cannot_ask_for_more_than_the_cap() {
    // Arrange
    let fixture = Fixture::new().await.queued(MAX_EVENTS + 5);

    // Act
    let response = fixture
        .post(json!({"maxEvents": 10_000, "returnImmediately": true}))
        .await;

    // Assert
    let body = body_of(response).await;
    assert_eq!(delivered(&body).len(), MAX_EVENTS);
    assert_eq!(body["moreAvailable"], json!(true));
}

/// §2.1's acknowledge-only poll: `maxEvents: 0` asks for nothing.
#[tokio::test]
async fn a_poll_for_no_events_returns_none() {
    // Arrange
    let fixture = Fixture::new().await.queued(1);

    // Act
    let response = fixture.post(json!({"maxEvents": 0})).await;

    // Assert
    let body = body_of(response).await;
    assert!(delivered(&body).is_empty());
    assert_eq!(body["moreAvailable"], json!(true));
}

// ---------------------------------------------------------------------------
// §2.4 — acknowledgement, redelivery and error reports
// ---------------------------------------------------------------------------

/// §2.4: "SETs that are not acknowledged are returned again in the response to
/// the next poll".
#[tokio::test]
async fn an_unacknowledged_set_is_delivered_again() {
    // Arrange
    let fixture = Fixture::new().await.queued(1);
    let first = body_of(fixture.post(json!({"returnImmediately": true})).await).await;

    // Act
    let second = body_of(fixture.post(json!({"returnImmediately": true})).await).await;

    // Assert
    assert_eq!(delivered(&first), vec!["set-0"]);
    assert_eq!(delivered(&second), vec!["set-0"]);
}

/// §2.4: an acknowledgement is what stops a SET coming back, and it is applied
/// before the batch is selected — so an acknowledged SET is not in the very
/// response that acknowledges it.
#[tokio::test]
async fn an_acknowledgement_removes_the_set_from_this_response_and_the_next() {
    // Arrange
    let fixture = Fixture::new().await.queued(2);

    // Act
    let response = fixture
        .post(json!({"ack": ["set-0"], "returnImmediately": true}))
        .await;

    // Assert
    let body = body_of(response).await;
    assert_eq!(delivered(&body), vec!["set-1"]);
    assert_eq!(fixture.store.held(&fixture.stream), vec!["set-1"]);
    assert!(fixture.trail().contains(&EventType::SSF_SETS_ACKNOWLEDGED));
}

/// §2.4's `setErrs`, with this deployment's policy: the report is recorded and
/// the SET is retired rather than handed over for ever.
#[tokio::test]
async fn a_reported_set_is_recorded_and_not_delivered_again() {
    // Arrange
    let fixture = Fixture::new().await.queued(1);

    // Act
    let response = fixture
        .post(json!({
            "setErrs": {"set-0": {"err": "invalid_issuer", "description": "not our issuer"}},
            "returnImmediately": true,
        }))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert!(fixture.store.held(&fixture.stream).is_empty());
    assert!(fixture.trail().contains(&EventType::SSF_SET_REJECTED));
    let next = body_of(fixture.post(json!({"returnImmediately": true})).await).await;
    assert!(delivered(&next).is_empty());
}

/// §2.4: a `setErrs` entry with no `err` is not a report this transmitter can
/// act on, and a 400 says so rather than a silent retirement.
#[tokio::test]
async fn a_set_error_without_a_code_is_refused() {
    // Arrange
    let fixture = Fixture::new().await.queued(1);

    // Act
    let response = fixture
        .post(json!({"setErrs": {"set-0": {"description": "no code"}}}))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        fixture.store.held(&fixture.stream),
        vec!["set-0"],
        "a refused request must not have retired anything"
    );
}

// ---------------------------------------------------------------------------
// §2.1 — long polling
// ---------------------------------------------------------------------------

/// §2.1: `returnImmediately: false` holds the request open, and answers with
/// an empty `sets` when nothing arrives. Empty is a response, not an error.
#[tokio::test]
async fn a_long_poll_with_nothing_to_deliver_returns_empty() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture.post(json!({"returnImmediately": false})).await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_of(response).await;
    assert!(delivered(&body).is_empty());
    assert_eq!(body["moreAvailable"], json!(false));
}

/// §2.1, the other half: a SET queued while the request is held open is
/// delivered to it rather than left for the next poll.
#[tokio::test]
async fn a_long_poll_delivers_a_set_that_arrives_while_it_waits() {
    // Arrange
    let fixture = Fixture::new().await;
    let store = Arc::clone(&fixture.store);
    let stream = fixture.stream.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        store.queue_set(&stream, "set-late");
    });

    // Act
    let response = fixture.post(json!({"returnImmediately": false})).await;

    // Assert
    let body = body_of(response).await;
    assert_eq!(delivered(&body), vec!["set-late"]);
}

// ---------------------------------------------------------------------------
// Who may poll what (SSF 1.0 §7.1.1, §6.1.2)
// ---------------------------------------------------------------------------

/// §6.1.2: the URL names the stream, and the token decides whether it is
/// yours. Another receiver's stream is a 404 — the same answer an identifier
/// that never existed gets, so the endpoint is not an oracle.
#[tokio::test]
async fn another_receivers_stream_is_not_found() {
    // Arrange
    let fixture = Fixture::new().await;
    let theirs = stream_of(Delivery::Poll);
    fixture.store.add_stream(OTHER_RECEIVER, &theirs);
    fixture.store.queue_set(&theirs.stream_id, "set-theirs");

    // Act
    let response = fixture
        .post_to(
            &theirs.stream_id.to_string(),
            json!({"returnImmediately": true}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        fixture.store.held(&theirs.stream_id),
        vec!["set-theirs"],
        "their queue must be untouched"
    );
}

/// An identifier this server could never have issued is a 404 before any work
/// is done.
#[tokio::test]
async fn a_stream_identifier_this_server_never_issued_is_not_found() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture.post_to("../../etc/passwd", json!({})).await;

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// A push stream (RFC 8935) has no polling URL at all, so this address does
/// not exist for it.
#[tokio::test]
async fn a_push_stream_cannot_be_polled() {
    // Arrange
    let fixture = Fixture::new().await;
    let pushed = stream_of(Delivery::Push {
        endpoint_url: "https://receiver.example/push".to_owned(),
        authorization_header: None,
    });
    fixture.store.add_stream(RECEIVER, &pushed);

    // Act
    let response = fixture
        .post_to(&pushed.stream_id.to_string(), json!({}))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// §7.1.1: the polling endpoint is protected, and the scope that protects it
/// is not the one that configures streams.
#[tokio::test]
async fn a_token_without_the_poll_scope_is_refused() {
    // Arrange
    let fixture = Fixture::with_token(&["ssf.manage"], &poll_url()).await;

    // Act
    let response = fixture.post(json!({"returnImmediately": true})).await;

    // Assert
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("a challenge")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert!(challenge.contains("insufficient_scope"), "{challenge}");
    assert!(challenge.contains(SCOPE_POLL), "{challenge}");
}

/// A receiver's token for another resource is a perfectly good token and is
/// not one this endpoint answers (RFC 6750 §3.1).
#[tokio::test]
async fn a_token_audienced_elsewhere_is_refused() {
    // Arrange
    let fixture = Fixture::with_token(&[SCOPE_POLL], "https://api.example/").await;

    // Act
    let response = fixture.post(json!({"returnImmediately": true})).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// No credential at all is a 401 with a challenge, not a 404: the caller has
/// not earned an answer about whether the stream exists.
#[tokio::test]
async fn a_poll_without_a_credential_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let addressed = fixture.stream.to_string();

    // Act
    let response = fixture
        .call(Method::POST, HeaderMap::new(), &addressed, b"{}")
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
}

/// RFC 9449 §7.1: the proof is made over the URL that was called. A proof for
/// another stream's URL does not authorize this one.
#[tokio::test]
async fn a_proof_for_another_streams_url_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let elsewhere = StreamId::generate();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("DPoP {}", fixture.access_token)).expect("header"),
    );
    headers.insert(
        DPOP_HEADER,
        HeaderValue::from_str(&fixture.proof("POST", elsewhere.as_str())).expect("header"),
    );
    let addressed = fixture.stream.to_string();

    // Act
    let response = fixture.call(Method::POST, headers, &addressed, b"{}").await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// RFC 8936 §2 defines one verb here. Anything else is a 405, and the refusal
/// still carries the `Cache-Control` every response of this endpoint does.
#[tokio::test]
async fn a_verb_the_specification_does_not_define_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let addressed = fixture.stream.to_string();
    let headers = fixture.authorized_headers("GET", &addressed);

    // Act
    let response = fixture.call(Method::GET, headers, &addressed, b"").await;

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

/// A poll response is a batch of security signals about a tenant's users. No
/// shared cache may keep one.
#[tokio::test]
async fn no_poll_response_may_be_cached() {
    // Arrange
    let fixture = Fixture::new().await.queued(1);

    // Act
    let response = fixture.post(json!({"returnImmediately": true})).await;

    // Assert
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .expect("no-store"),
        "no-store"
    );
}

/// A body that is not a §2.1 request is a 400 that names the member, and takes
/// nothing off the queue.
#[tokio::test]
async fn a_body_that_is_not_a_poll_request_is_refused() {
    // Arrange
    let fixture = Fixture::new().await.queued(1);

    // Act
    let response = fixture.post(json!({"maxEvents": "all of them"})).await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_of(response).await;
    assert_eq!(body["error"], json!("invalid_request"));
    assert_eq!(fixture.store.held(&fixture.stream), vec!["set-0"]);
}

// ---------------------------------------------------------------------------
// Interoperability: a reference RFC 8936 receiver
// ---------------------------------------------------------------------------

/// A receiver that speaks §2.1 and §2.4 the way a conforming one does.
///
/// It holds what it has processed but not yet acknowledged, and sends that in
/// the *next* request — which is what §2.4 describes and what makes the
/// redelivery rule observable from the outside.
struct Receiver {
    /// Every `jti` this receiver has seen, in the order it saw them.
    seen: Vec<String>,
    /// What the next request will acknowledge.
    pending_ack: Vec<String>,
    /// Identifiers this receiver refuses to process, and the code it reports.
    refuses: BTreeMap<String, &'static str>,
}

impl Receiver {
    fn new() -> Self {
        Self {
            seen: Vec::new(),
            pending_ack: Vec::new(),
            refuses: BTreeMap::new(),
        }
    }

    fn refusing(mut self, jti: &str, code: &'static str) -> Self {
        self.refuses.insert(jti.to_owned(), code);
        self
    }

    /// One poll, as §2.1 has a receiver make it. Returns `moreAvailable`.
    async fn poll_once(&mut self, fixture: &Fixture, max_events: u64) -> bool {
        let mut request = serde_json::Map::new();
        request.insert("maxEvents".to_owned(), json!(max_events));
        request.insert("returnImmediately".to_owned(), json!(true));
        if !self.pending_ack.is_empty() {
            request.insert("ack".to_owned(), json!(self.pending_ack));
        }
        let response = fixture.post(Value::Object(request)).await;
        assert_eq!(response.status(), StatusCode::OK, "a poll must be answered");
        let body = body_of(response).await;
        self.pending_ack.clear();

        let sets = body["sets"].as_object().expect("§2.3's `sets`").clone();
        let mut errs = serde_json::Map::new();
        for (jti, jws) in sets {
            assert_eq!(
                jws,
                json!(format!("jws.of.{jti}")),
                "§2.3 maps each identifier to its own SET"
            );
            if let Some(code) = self.refuses.get(&jti) {
                errs.insert(jti.clone(), json!({"err": code, "description": "refused"}));
            } else {
                self.seen.push(jti.clone());
                self.pending_ack.push(jti);
            }
        }
        if !errs.is_empty() {
            // §2.4: errors are reported on a request of their own here, so the
            // acknowledgement of the rest is not held up by them.
            let response = fixture.post(json!({"maxEvents": 0, "setErrs": errs})).await;
            assert_eq!(response.status(), StatusCode::OK);
        }
        body["moreAvailable"].as_bool().unwrap_or(false)
    }
}

/// The interoperability test: a reference receiver drains a backlog and every
/// SET arrives exactly once.
#[tokio::test]
async fn a_reference_receiver_drains_a_backlog_without_loss_or_duplication() {
    // Arrange
    let fixture = Fixture::new().await.queued(5);
    let mut receiver = Receiver::new();

    // Act: poll in batches of two until the transmitter says there is no more,
    // then once more to acknowledge the last batch.
    let mut polls = 0;
    while receiver.poll_once(&fixture, 2).await {
        polls += 1;
        assert!(polls < 10, "a backlog of five must drain in a few polls");
    }
    receiver.poll_once(&fixture, 2).await;

    // Assert
    assert_eq!(
        receiver.seen,
        vec!["set-0", "set-1", "set-2", "set-3", "set-4"],
        "every SET arrives, in order"
    );
    let mut unique = receiver.seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), receiver.seen.len(), "and none arrives twice");
    assert!(
        fixture.store.held(&fixture.stream).is_empty(),
        "an acknowledged backlog leaves nothing behind"
    );
}

/// The same receiver, refusing one SET: §2.4's `setErrs` takes it off the
/// queue and the rest of the backlog still drains.
#[tokio::test]
async fn a_reference_receiver_that_refuses_a_set_still_drains_the_rest() {
    // Arrange
    let fixture = Fixture::new().await.queued(3);
    let mut receiver = Receiver::new().refusing("set-1", "invalid_key");

    // Act
    let mut polls = 0;
    while receiver.poll_once(&fixture, 2).await {
        polls += 1;
        assert!(polls < 10, "the queue must drain");
    }
    receiver.poll_once(&fixture, 2).await;

    // Assert
    assert_eq!(receiver.seen, vec!["set-0", "set-2"]);
    assert!(fixture.store.held(&fixture.stream).is_empty());
    assert!(fixture.trail().contains(&EventType::SSF_SET_REJECTED));
}

/// The polling endpoint's URL is the one the stream configuration hands out
/// (§6.1.2), so a receiver that reads its stream and polls where it says
/// reaches this endpoint.
#[tokio::test]
async fn the_configured_endpoint_url_is_the_one_that_answers() {
    // Arrange
    let fixture = Fixture::new().await.queued(1);
    let configured = poll_endpoint_for(&poll_url(), &fixture.stream);

    // Act
    let addressed = configured
        .strip_prefix(&format!("{}/", poll_url()))
        .expect("the configured URL is under the polling endpoint")
        .to_owned();
    let response = fixture
        .post_to(&addressed, json!({"returnImmediately": true}))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(delivered(&body_of(response).await), vec!["set-0"]);
}
