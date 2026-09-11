//! The SSF status and subject endpoints (SSF 1.0 §8.1.2, §8.1.3, `ast-0ju.4`).
//!
//! Every test here goes through the real handler with a real signed access
//! token, a real DPoP proof and the real verifier — only the rows are faked,
//! exactly as `ssf_streams.rs` does. These two endpoints decide who hears
//! about whom, and an endpoint whose credential checks were stubbed would be
//! one whose tests pass for tokens it should refuse.
//!
//! The store's own half — the status column, the held queue of a paused
//! stream, and the cascade that takes a deleted stream's memberships with it —
//! is in `crates/store-pg/tests/ssf_management.rs`, where there is a database
//! to prove it against.

use asterius_domain::audit::{AuditEvent, AuditSink, EventType};
use asterius_domain::keys::Kid;
use asterius_domain::keys::{Signer as _, SigningAlgorithm};
use asterius_domain::rate_limit::{
    Bucket, EndpointLimit, EndpointLimits, RateLimit, RateLimitStore,
};
use asterius_domain::{
    ClientId, DomainError, Grant, GrantId, Issuer, ReplayCheck, ReplayGuard, ReplayPurpose, Tenant,
    TenantId, TenantStatus,
};
use asterius_jose::{LocalKeyStore, SigningKey, thumbprint};
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::{AccessToken, Audience, Confirmation};
use asterius_server::http::dpop::{DpopEndpoint, HEADER as DPOP_HEADER};
use asterius_server::http::limits::{EndpointThrottle, LimitContext};
use asterius_server::http::ssf::SsfTokenStatus;
use asterius_server::http::ssf_management::{
    ADD_SUBJECT_PATH, Membership, REMOVE_SUBJECT_PATH, Recognised, STATUS_PATH,
    SsfManagementContext, SsfManagementStore, SsfVerifier, SubjectDirectory, SubjectOutcome,
    VERIFICATION_PATH, Verified, status, subjects, verification,
};
use asterius_ssf::VerificationState;
use asterius_ssf::stream::{SCOPE_MANAGE, StreamId, StreamStatus};
use asterius_ssf::subject::Subject;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";
const RECEIVER: &str = "receiver";
/// A subject this tenant's directory knows.
const KNOWN: &str = "known@example.com";
/// One it does not. §9.1: the answer must not say so.
const UNKNOWN: &str = "nobody@example.com";

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

fn url_of(path: &str) -> String {
    format!("{ISSUER}{path}")
}

// ---------------------------------------------------------------------------
// The fakes
// ---------------------------------------------------------------------------

/// One stream's status and membership, in memory.
#[derive(Debug, Default, Clone)]
struct FakeStream {
    status: StreamStatus,
    reason: Option<String>,
    subjects: Vec<Subject>,
}

/// The rows, keyed by receiver and stream.
#[derive(Debug, Default)]
struct FakeRows {
    streams: Mutex<BTreeMap<(String, String), FakeStream>>,
    /// How many subjects a stream may hold, so the quota refusal can be
    /// asserted without writing ten thousand rows.
    capacity: usize,
}

impl FakeRows {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            streams: Mutex::new(BTreeMap::new()),
            capacity,
        }
    }

    fn key(receiver: &ClientId, stream: &StreamId) -> (String, String) {
        (receiver.as_str().to_owned(), stream.as_str().to_owned())
    }

    fn insert(&self, receiver: &str, stream: &StreamId) {
        self.streams.lock().expect("lock").insert(
            (receiver.to_owned(), stream.as_str().to_owned()),
            FakeStream::default(),
        );
    }

    fn subjects_of(&self, receiver: &str, stream: &StreamId) -> Vec<Subject> {
        self.streams
            .lock()
            .expect("lock")
            .get(&(receiver.to_owned(), stream.as_str().to_owned()))
            .map(|row| row.subjects.clone())
            .unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl SsfManagementStore for FakeRows {
    async fn status(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
    ) -> Result<Option<(StreamStatus, Option<String>)>, DomainError> {
        Ok(self
            .streams
            .lock()
            .expect("lock")
            .get(&Self::key(receiver, stream))
            .map(|row| (row.status, row.reason.clone())))
    }

    async fn set_status(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
        status: StreamStatus,
        reason: Option<&str>,
        _now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut rows = self.streams.lock().expect("lock");
        let Some(row) = rows.get_mut(&Self::key(receiver, stream)) else {
            return Ok(false);
        };
        row.status = status;
        row.reason = reason.map(str::to_owned);
        Ok(true)
    }

    async fn add_subject(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
        subject: &Subject,
        _verified: Option<bool>,
        _now: OffsetDateTime,
    ) -> Result<SubjectOutcome, DomainError> {
        let mut rows = self.streams.lock().expect("lock");
        let Some(row) = rows.get_mut(&Self::key(receiver, stream)) else {
            return Ok(SubjectOutcome::NoSuchStream);
        };
        if row.subjects.contains(subject) {
            return Ok(SubjectOutcome::Member);
        }
        if row.subjects.len() >= self.capacity {
            return Ok(SubjectOutcome::Full);
        }
        row.subjects.push(subject.clone());
        Ok(SubjectOutcome::Member)
    }

    async fn remove_subject(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
        subject: &Subject,
    ) -> Result<bool, DomainError> {
        let mut rows = self.streams.lock().expect("lock");
        let Some(row) = rows.get_mut(&Self::key(receiver, stream)) else {
            return Ok(false);
        };
        row.subjects.retain(|member| member != subject);
        Ok(true)
    }
}

#[async_trait::async_trait]
impl SsfTokenStatus for FakeRows {
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

/// §8.1.4.2's queue and its interval, in memory.
///
/// It records what the endpoint asked it to queue — one entry per admitted
/// request, with the `state` exactly as it arrived — and it enforces the
/// interval the way the repository does: the first request on a stream is
/// admitted, the next one inside the interval is refused with the seconds
/// left. The point of the fake is that the *endpoint* is real: the credential
/// checks, the parse and the status codes are the ones a receiver meets.
#[derive(Debug, Default)]
struct FakeVerifier {
    /// `(receiver, stream, state)` per queued verification event.
    queued: Mutex<Vec<(String, String, Option<String>)>>,
    /// Streams this receiver owns, so "no such stream" can be asserted.
    streams: Mutex<Vec<(String, String)>>,
    /// When each stream was last verified, in seconds from the fixed `now`.
    verified_at: Mutex<BTreeMap<String, i64>>,
}

impl FakeVerifier {
    /// §7.1's `min_verification_interval`, as the repository applies it.
    const INTERVAL: i64 = 60;

    fn owns(&self, receiver: &str, stream: &StreamId) {
        self.streams
            .lock()
            .expect("lock")
            .push((receiver.to_owned(), stream.as_str().to_owned()));
    }

    fn queued(&self) -> Vec<(String, String, Option<String>)> {
        self.queued.lock().expect("lock").clone()
    }
}

#[async_trait::async_trait]
impl SsfVerifier for FakeVerifier {
    async fn verify(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
        state: Option<&VerificationState>,
        now: OffsetDateTime,
    ) -> Result<Verified, DomainError> {
        let owned = self
            .streams
            .lock()
            .expect("lock")
            .iter()
            .any(|(owner, held)| owner == receiver.as_str() && held == stream.as_str());
        if !owned {
            return Ok(Verified::NoSuchStream);
        }
        let mut verified_at = self.verified_at.lock().expect("lock");
        let at = now.unix_timestamp();
        if let Some(last) = verified_at.get(stream.as_str()) {
            let elapsed = at - last;
            if elapsed < Self::INTERVAL {
                return Ok(Verified::TooSoon {
                    retry_after: (Self::INTERVAL - elapsed).max(1),
                });
            }
        }
        verified_at.insert(stream.as_str().to_owned(), at);
        drop(verified_at);
        self.queued.lock().expect("lock").push((
            receiver.as_str().to_owned(),
            stream.as_str().to_owned(),
            state.map(|state| state.as_str().to_owned()),
        ));
        Ok(Verified::Queued)
    }
}

/// A directory that knows one address and nobody else.
#[derive(Debug, Default)]
struct FakeDirectory(Mutex<Vec<Subject>>);

#[async_trait::async_trait]
impl SubjectDirectory for FakeDirectory {
    async fn recognises(&self, subject: &Subject) -> Result<Recognised, DomainError> {
        self.0.lock().expect("lock").push(subject.clone());
        let json = subject.to_json();
        Ok(match json.get("format").and_then(Value::as_str) {
            Some("email") => {
                if json.get("email").and_then(Value::as_str) == Some(KNOWN) {
                    Recognised::Known
                } else {
                    Recognised::Unknown
                }
            }
            // An opaque identifier is opaque to this server too.
            _ => Recognised::Unresolvable,
        })
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

/// The trail, kept so a test can assert what was written.
#[derive(Debug, Default)]
struct FakeAudit(Mutex<Vec<AuditEvent>>);

#[async_trait::async_trait]
impl AuditSink for FakeAudit {
    async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
        self.0.lock().expect("lock").push(event);
        Ok(())
    }
}

/// Fixed-window counters in memory.
#[derive(Debug, Default)]
struct FakeLimiter(Mutex<BTreeMap<(String, i64), u32>>);

#[async_trait::async_trait]
impl RateLimitStore for FakeLimiter {
    async fn count(
        &self,
        _tenant: &TenantId,
        bucket: &Bucket,
        window_start: OffsetDateTime,
    ) -> Result<u32, DomainError> {
        Ok(*self
            .0
            .lock()
            .expect("lock")
            .get(&(bucket.as_str().to_owned(), window_start.unix_timestamp()))
            .unwrap_or(&0))
    }

    async fn record(
        &self,
        _tenant: &TenantId,
        bucket: &Bucket,
        window_start: OffsetDateTime,
        _expires_at: OffsetDateTime,
    ) -> Result<u32, DomainError> {
        let mut counters = self.0.lock().expect("lock");
        let entry = counters
            .entry((bucket.as_str().to_owned(), window_start.unix_timestamp()))
            .or_default();
        *entry += 1;
        Ok(*entry)
    }

    async fn clear(&self, _tenant: &TenantId, bucket: &Bucket) -> Result<(), DomainError> {
        self.0
            .lock()
            .expect("lock")
            .retain(|(key, _), _| key != bucket.as_str());
        Ok(())
    }
}

fn address() -> IpAddr {
    "198.51.100.7".parse().expect("a literal address")
}

fn limits(max: u32) -> EndpointLimits {
    let limit = RateLimit {
        max,
        window: time::Duration::seconds(60),
    };
    let plain = EndpointLimit {
        per_address: limit,
        per_client: None,
        per_subject: None,
    };
    EndpointLimits {
        registration: plain,
        client_configuration: plain,
        par: plain,
        token: plain,
        userinfo: plain,
        ssf_subjects: EndpointLimit {
            per_address: limit,
            per_client: Some(limit),
            per_subject: None,
        },
        backchannel: EndpointLimit {
            per_address: limit,
            per_client: Some(limit),
            per_subject: Some(limit),
        },
        access_evaluation: EndpointLimit {
            per_address: limit,
            per_client: Some(limit),
            per_subject: None,
        },
    }
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

struct Fixture {
    keys: Arc<LocalKeyStore>,
    dpop_key: SigningKey,
    rows: FakeRows,
    verifier: FakeVerifier,
    directory: FakeDirectory,
    audit: FakeAudit,
    limiter: FakeLimiter,
    limits: EndpointLimits,
    /// One token per endpoint, since each names its own `aud`.
    tokens: BTreeMap<String, String>,
}

impl Fixture {
    async fn new() -> Self {
        Self::with_scopes(&[SCOPE_MANAGE]).await
    }

    async fn with_scopes(scopes: &[&str]) -> Self {
        let keys = Arc::new(LocalKeyStore::new());
        keys.generate(&TenantId::new("demo"), SigningAlgorithm::DEFAULT)
            .expect("a tenant key");
        let dpop_key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("a DPoP key");
        let jkt = thumbprint(&dpop_key.public_jwk().expect("jwk")).expect("thumbprint");

        let mut tokens = BTreeMap::new();
        for path in [
            STATUS_PATH,
            ADD_SUBJECT_PATH,
            REMOVE_SUBJECT_PATH,
            VERIFICATION_PATH,
        ] {
            let token = sign_token(&keys, &jkt, scopes, &url_of(path)).await;
            tokens.insert(path.to_owned(), token);
        }

        Self {
            keys,
            dpop_key,
            rows: FakeRows::with_capacity(64),
            verifier: FakeVerifier::default(),
            directory: FakeDirectory::default(),
            audit: FakeAudit::default(),
            limiter: FakeLimiter::default(),
            limits: limits(1_000),
            tokens,
        }
    }

    /// The same fixture, with a subject budget a test can exhaust.
    fn allowing(mut self, requests: u32) -> Self {
        self.limits = limits(requests);
        self
    }

    /// A stream this receiver owns.
    fn stream(&self) -> StreamId {
        let stream = StreamId::generate();
        self.rows.insert(RECEIVER, &stream);
        stream
    }

    fn context<'a>(
        &'a self,
        tenant: &'a Tenant,
        dpop: &'a DpopEndpoint,
    ) -> SsfManagementContext<'a> {
        SsfManagementContext {
            tenant,
            store: &self.rows,
            directory: &self.directory,
            verifier: &self.verifier,
            keys: self.keys.as_ref(),
            dpop,
            audit: &self.audit,
            certificate: None,
            limits: LimitContext {
                tenant: &tenant.id,
                throttle: EndpointThrottle::new(&self.limiter, self.limits, Some(address())),
                audit: &self.audit,
                now: now(),
            },
            now: now(),
        }
    }

    async fn status_request(&self, method: Method, query: Option<&str>, body: Value) -> Response {
        let tenant = tenant();
        let dpop = DpopEndpoint::new(Arc::new(FakeReplay), None);
        let rendered = serde_json::to_vec(&body).expect("a JSON body");
        let headers = self.headers(STATUS_PATH, method.as_str());
        status(
            self.context(&tenant, &dpop),
            &method,
            &headers,
            query,
            &rendered,
        )
        .await
    }

    async fn subject_request(&self, membership: Membership, body: Value) -> Response {
        let path = match membership {
            Membership::Add => ADD_SUBJECT_PATH,
            Membership::Remove => REMOVE_SUBJECT_PATH,
        };
        let tenant = tenant();
        let dpop = DpopEndpoint::new(Arc::new(FakeReplay), None);
        let rendered = serde_json::to_vec(&body).expect("a JSON body");
        let headers = self.headers(path, "POST");
        subjects(
            self.context(&tenant, &dpop),
            membership,
            &Method::POST,
            &headers,
            &rendered,
        )
        .await
    }

    /// A stream this receiver owns, as the verification endpoint sees it.
    fn verifiable_stream(&self) -> StreamId {
        let stream = StreamId::generate();
        self.verifier.owns(RECEIVER, &stream);
        stream
    }

    async fn verification_request(&self, body: Value) -> Response {
        self.verification_with(Method::POST, body).await
    }

    async fn verification_with(&self, method: Method, body: Value) -> Response {
        let tenant = tenant();
        let dpop = DpopEndpoint::new(Arc::new(FakeReplay), None);
        let rendered = serde_json::to_vec(&body).expect("a JSON body");
        let headers = self.headers(VERIFICATION_PATH, method.as_str());
        verification(self.context(&tenant, &dpop), &method, &headers, &rendered).await
    }

    fn headers(&self, path: &str, method: &str) -> HeaderMap {
        let token = self.tokens.get(path).expect("a token for this endpoint");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {token}")).expect("header"),
        );
        headers.insert(
            DPOP_HEADER,
            HeaderValue::from_str(&self.proof(path, method, token)).expect("header"),
        );
        headers
    }

    fn proof(&self, path: &str, method: &str, token: &str) -> String {
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
            "htu": url_of(path),
            "iat": now().unix_timestamp(),
            "ath": B64.encode(Sha256::digest(token.as_bytes())),
        });
        sign_by_hand(&self.dpop_key, &header, &claims)
    }

    fn trail(&self) -> Vec<EventType> {
        self.audit
            .0
            .lock()
            .expect("lock")
            .iter()
            .map(|event| event.event_type)
            .collect()
    }
}

async fn sign_token(keys: &LocalKeyStore, jkt: &Kid, scopes: &[&str], audience: &str) -> String {
    let mut grant = Grant::new(TenantId::new("demo"), ClientId::new(RECEIVER), now());
    grant.scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    grant.claimed_at = Some(now());
    let claimed = grant.claim(now()).expect("a live grant");
    let unsigned = AccessToken::new(
        &Issuer::parse(ISSUER).expect("issuer"),
        &grant,
        &claimed,
        Audience::new([audience]).expect("audience"),
        Confirmation::dpop(jkt).expect("confirmation"),
        JwtId::generate(),
        now(),
    )
    .with_grant_id()
    .build()
    .expect("an access token");
    keys.sign(
        &TenantId::new("demo"),
        unsigned.required_algorithm(),
        unsigned.typ(),
        unsigned.claims(),
    )
    .await
    .expect("signed")
    .as_str()
    .to_owned()
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

/// The response body, whatever it is. §8.1.3.2's answers carry none at all,
/// and "none" is exactly what has to be the same for a known subject and an
/// unknown one — so this reads bytes rather than parsing JSON.
async fn bytes_of(response: Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body")
        .to_vec()
}

async fn body_of(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("a JSON body")
}

fn email(address: &str) -> Value {
    json!({"format": "email", "email": address})
}

// ---------------------------------------------------------------------------
// §8.1.2.1 — reading a status
// ---------------------------------------------------------------------------

/// §8.1.2.1: the response names the stream and its status.
#[tokio::test]
async fn a_status_read_names_the_stream_and_its_state() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let response = fixture
        .status_request(
            Method::GET,
            Some(&format!("stream_id={stream}")),
            Value::Null,
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_of(response).await,
        json!({"stream_id": stream.as_str(), "status": "enabled"})
    );
}

/// §8.1.1.1 creates a usable stream, so a receiver that never called §8.1.2.2
/// reads `enabled` back.
#[tokio::test]
async fn a_new_stream_reads_back_as_enabled() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let response = fixture
        .status_request(
            Method::GET,
            Some(&format!("stream_id={stream}")),
            Value::Null,
        )
        .await;

    // Assert
    assert_eq!(body_of(response).await["status"], json!("enabled"));
}

/// §8: the authorization associates a receiver with the streams it may act
/// on. Another receiver's stream is not one this token reaches.
#[tokio::test]
async fn a_stream_this_receiver_does_not_own_is_not_found() {
    // Arrange
    let fixture = Fixture::new().await;
    let theirs = StreamId::generate();
    fixture.rows.insert("someone-else", &theirs);

    // Act
    let response = fixture
        .status_request(
            Method::GET,
            Some(&format!("stream_id={theirs}")),
            Value::Null,
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_status_read_without_a_stream_id_addresses_nothing() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture.status_request(Method::GET, None, Value::Null).await;

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// §8.1.1.2's rule, kept for every SSF response: a status names a stream a
/// receiver holds, and a shared cache must not keep it.
#[tokio::test]
async fn every_status_response_is_uncacheable() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let response = fixture
        .status_request(
            Method::GET,
            Some(&format!("stream_id={stream}")),
            Value::Null,
        )
        .await;

    // Assert
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
}

// ---------------------------------------------------------------------------
// §8.1.2.2 — changing a status
// ---------------------------------------------------------------------------

/// §8.1.2.2: the change takes, and the response is the new state. 200 rather
/// than 202, because this transmitter decides immediately.
#[tokio::test]
async fn a_status_change_takes_effect_and_is_answered_with_the_new_state() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let response = fixture
        .status_request(
            Method::POST,
            None,
            json!({
                "stream_id": stream.as_str(),
                "status": "paused",
                "reason": "maintenance",
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_of(response).await,
        json!({
            "stream_id": stream.as_str(),
            "status": "paused",
            "reason": "maintenance",
        })
    );
    assert_eq!(
        fixture
            .rows
            .status(&ClientId::new(RECEIVER), &stream)
            .await
            .expect("the stream"),
        Some((StreamStatus::Paused, Some("maintenance".to_owned())))
    );
}

/// Every state §8.1.2 defines is reachable, including back to `enabled` —
/// which is what releases the events a paused stream held.
#[tokio::test]
async fn every_status_the_spec_defines_can_be_set() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    for (requested, expected) in [
        ("paused", StreamStatus::Paused),
        ("disabled", StreamStatus::Disabled),
        ("enabled", StreamStatus::Enabled),
    ] {
        // Act
        let response = fixture
            .status_request(
                Method::POST,
                None,
                json!({"stream_id": stream.as_str(), "status": requested}),
            )
            .await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK, "{requested}");
        assert_eq!(
            fixture
                .rows
                .status(&ClientId::new(RECEIVER), &stream)
                .await
                .expect("the stream"),
            Some((expected, None)),
            "{requested}"
        );
    }
}

/// A status change is a thing an operator has to be able to find afterwards:
/// a stream that stopped delivering and nobody knows why is an incident
/// nobody can close.
#[tokio::test]
async fn a_status_change_is_written_to_the_trail() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let _ = fixture
        .status_request(
            Method::POST,
            None,
            json!({"stream_id": stream.as_str(), "status": "disabled"}),
        )
        .await;

    // Assert
    assert_eq!(fixture.trail(), vec![EventType::SSF_STREAM_STATUS_CHANGED]);
}

#[tokio::test]
async fn a_status_the_spec_does_not_define_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let response = fixture
        .status_request(
            Method::POST,
            None,
            json!({"stream_id": stream.as_str(), "status": "sleeping"}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_of(response).await["error"], json!("invalid_request"));
}

#[tokio::test]
async fn a_status_change_for_a_stream_that_does_not_exist_is_not_found() {
    // Arrange
    let fixture = Fixture::new().await;
    let unknown = StreamId::generate();

    // Act
    let response = fixture
        .status_request(
            Method::POST,
            None,
            json!({"stream_id": unknown.as_str(), "status": "paused"}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_status_endpoint_answers_only_get_and_post() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture
        .status_request(Method::DELETE, None, Value::Null)
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

// ---------------------------------------------------------------------------
// §8.1.3.2 — adding a subject
// ---------------------------------------------------------------------------

/// §8.1.3.2: a subject this tenant knows is recorded, and the answer is 200.
#[tokio::test]
async fn adding_a_known_subject_records_it_and_answers_200() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let response = fixture
        .subject_request(
            Membership::Add,
            json!({
                "stream_id": stream.as_str(),
                "subject": email(KNOWN),
                "verified": true,
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fixture.rows.subjects_of(RECEIVER, &stream).len(), 1);
}

/// §9.1: a subject this tenant does not hold gets the same answer as one it
/// does — and is not written down, because no event will ever be about it.
#[tokio::test]
async fn adding_an_unknown_subject_answers_200_and_records_nothing() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let response = fixture
        .subject_request(
            Membership::Add,
            json!({"stream_id": stream.as_str(), "subject": email(UNKNOWN)}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        fixture.rows.subjects_of(RECEIVER, &stream).is_empty(),
        "an identifier that belongs to nobody here was written down"
    );
}

/// The property §9.1 actually asks for: the two answers are indistinguishable,
/// header for header and byte for byte.
#[tokio::test]
async fn a_known_and_an_unknown_subject_get_the_same_answer() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let known = fixture
        .subject_request(
            Membership::Add,
            json!({"stream_id": stream.as_str(), "subject": email(KNOWN)}),
        )
        .await;
    let unknown = fixture
        .subject_request(
            Membership::Add,
            json!({"stream_id": stream.as_str(), "subject": email(UNKNOWN)}),
        )
        .await;

    // Assert
    assert_eq!(known.status(), unknown.status());
    assert_eq!(known.headers(), unknown.headers());
    assert_eq!(
        bytes_of(known).await,
        bytes_of(unknown).await,
        "the two answers differ in their body"
    );
}

/// A subject this server cannot resolve in this direction — an opaque
/// identifier — is recorded rather than dropped: "not found" and "we cannot
/// look" are different facts, and dropping the second would silently discard
/// a legitimate subscription.
#[tokio::test]
async fn a_subject_this_server_cannot_resolve_is_still_recorded() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let response = fixture
        .subject_request(
            Membership::Add,
            json!({
                "stream_id": stream.as_str(),
                "subject": {"format": "opaque", "id": "o-1"},
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(fixture.rows.subjects_of(RECEIVER, &stream).len(), 1);
}

/// §8.1.3.2 describes a membership, not a counter: a receiver repeating a
/// request it is unsure about must not be punished for it.
#[tokio::test]
async fn adding_one_subject_twice_is_one_membership() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();
    let body = json!({"stream_id": stream.as_str(), "subject": email(KNOWN)});

    // Act
    let first = fixture.subject_request(Membership::Add, body.clone()).await;
    let second = fixture.subject_request(Membership::Add, body).await;

    // Assert
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(fixture.rows.subjects_of(RECEIVER, &stream).len(), 1);
}

/// §8.1.3.2's 404 is about the *stream*, which is a resource the caller either
/// owns or does not — unlike a subject, about which it learns nothing.
#[tokio::test]
async fn adding_to_a_stream_this_receiver_does_not_own_is_not_found() {
    // Arrange
    let fixture = Fixture::new().await;
    let theirs = StreamId::generate();
    fixture.rows.insert("someone-else", &theirs);

    // Act
    let response = fixture
        .subject_request(
            Membership::Add,
            json!({"stream_id": theirs.as_str(), "subject": email(KNOWN)}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// An unknown subject must not turn the stream's own 404 into a 200: §9.1 is
/// silence about people, not about a receiver's own resources.
#[tokio::test]
async fn adding_an_unknown_subject_to_a_stream_that_is_not_ours_is_still_not_found() {
    // Arrange
    let fixture = Fixture::new().await;
    let theirs = StreamId::generate();
    fixture.rows.insert("someone-else", &theirs);

    // Act
    let response = fixture
        .subject_request(
            Membership::Add,
            json!({"stream_id": theirs.as_str(), "subject": email(UNKNOWN)}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_subject_this_transmitter_cannot_read_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let response = fixture
        .subject_request(
            Membership::Add,
            json!({
                "stream_id": stream.as_str(),
                "subject": {"format": "badge_number", "id": "42"},
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// A stream's membership is bounded: an endpoint one access token reaches must
/// not be a way to fill a tenant's database.
#[tokio::test]
async fn a_stream_stops_accepting_subjects_once_it_is_full() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = StreamId::generate();
    fixture.rows.insert(RECEIVER, &stream);
    {
        let mut rows = fixture.rows.streams.lock().expect("lock");
        let row = rows
            .get_mut(&(RECEIVER.to_owned(), stream.as_str().to_owned()))
            .expect("the stream");
        row.subjects = (0..64)
            .map(|index| {
                Subject::from_json(&json!({"format": "opaque", "id": format!("o-{index}")}))
                    .expect("a subject")
            })
            .collect();
    }

    // Act
    let response = fixture
        .subject_request(
            Membership::Add,
            json!({
                "stream_id": stream.as_str(),
                "subject": {"format": "opaque", "id": "one-too-many"},
            }),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// §8.1.3.3 — removing a subject
// ---------------------------------------------------------------------------

/// §8.1.3.3: 204, and the membership is gone.
#[tokio::test]
async fn removing_a_subject_answers_204_and_removes_the_membership() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();
    let body = json!({"stream_id": stream.as_str(), "subject": email(KNOWN)});
    let _ = fixture.subject_request(Membership::Add, body.clone()).await;

    // Act
    let response = fixture.subject_request(Membership::Remove, body).await;

    // Assert
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(fixture.rows.subjects_of(RECEIVER, &stream).is_empty());
}

/// §9.1 again, on the other endpoint: removing a subject that was never a
/// member is a 204, and removing one this tenant has never heard of is the
/// same 204.
#[tokio::test]
async fn removing_a_subject_that_was_never_a_member_is_the_same_204() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();

    // Act
    let member = fixture
        .subject_request(
            Membership::Remove,
            json!({"stream_id": stream.as_str(), "subject": email(KNOWN)}),
        )
        .await;
    let stranger = fixture
        .subject_request(
            Membership::Remove,
            json!({"stream_id": stream.as_str(), "subject": email(UNKNOWN)}),
        )
        .await;

    // Assert
    assert_eq!(member.status(), StatusCode::NO_CONTENT);
    assert_eq!(stranger.status(), StatusCode::NO_CONTENT);
    assert_eq!(member.headers(), stranger.headers());
}

// ---------------------------------------------------------------------------
// §9.1 — the remaining way to probe is volume
// ---------------------------------------------------------------------------

/// §8.1.3.2's 429, with the `Retry-After` every throttled endpoint here
/// answers with: the answers are indistinguishable, so the way to enumerate is
/// to ask many times, and that is what is bounded.
#[tokio::test]
async fn a_receiver_over_its_budget_is_refused_with_a_retry_after() {
    // Arrange
    let fixture = Fixture::new().await.allowing(1);
    let stream = fixture.stream();
    let body = json!({"stream_id": stream.as_str(), "subject": email(KNOWN)});

    // Act
    let admitted = fixture.subject_request(Membership::Add, body.clone()).await;
    let refused = fixture.subject_request(Membership::Add, body).await;

    // Assert
    assert_eq!(admitted.status(), StatusCode::OK);
    assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        refused.headers().contains_key(header::RETRY_AFTER),
        "a 429 without a Retry-After tells a receiver nothing about when to come back"
    );
    assert_eq!(
        refused.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
}

/// The limiter runs after the credential checks, so the budget it spends
/// belongs to a receiver that proved who it is — and an unauthenticated caller
/// cannot spend another receiver's.
#[tokio::test]
async fn a_refused_credential_never_reaches_the_directory() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();
    let tenant = tenant();
    let dpop = DpopEndpoint::new(Arc::new(FakeReplay), None);
    let body = serde_json::to_vec(&json!({
        "stream_id": stream.as_str(),
        "subject": email(KNOWN),
    }))
    .expect("a JSON body");

    // Act
    let response = subjects(
        fixture.context(&tenant, &dpop),
        Membership::Add,
        &Method::POST,
        &HeaderMap::new(),
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        fixture.directory.0.lock().expect("lock").is_empty(),
        "an unauthenticated request asked the directory about a person"
    );
}

/// §7.1.1: the management API has one scope, and a token without it does not
/// reach these endpoints either.
#[tokio::test]
async fn a_token_without_the_management_scope_is_refused() {
    // Arrange
    let fixture = Fixture::with_scopes(&["openid"]).await;
    let stream = fixture.stream();

    // Act
    let response = fixture
        .subject_request(
            Membership::Add,
            json!({"stream_id": stream.as_str(), "subject": email(KNOWN)}),
        )
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(challenge.contains("insufficient_scope"), "{challenge}");
}

/// A token audienced at another URL of this same API is not one this endpoint
/// answers: the `aud` is the endpoint, not the deployment.
#[tokio::test]
async fn a_token_for_another_endpoint_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();
    let tenant = tenant();
    let dpop = DpopEndpoint::new(Arc::new(FakeReplay), None);
    // The token minted for the *status* endpoint, presented at add-subject.
    let token = fixture.tokens.get(STATUS_PATH).expect("a token").clone();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("DPoP {token}")).expect("header"),
    );
    headers.insert(
        DPOP_HEADER,
        HeaderValue::from_str(&fixture.proof(ADD_SUBJECT_PATH, "POST", &token)).expect("header"),
    );
    let body = serde_json::to_vec(&json!({
        "stream_id": stream.as_str(),
        "subject": email(KNOWN),
    }))
    .expect("a JSON body");

    // Act
    let response = subjects(
        fixture.context(&tenant, &dpop),
        Membership::Add,
        &Method::POST,
        &headers,
        &body,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// The membership changes are in the trail; the subject identifier is not.
#[tokio::test]
async fn a_membership_change_is_recorded_without_the_subject_identifier() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.stream();
    let body = json!({"stream_id": stream.as_str(), "subject": email(KNOWN)});

    // Act
    let _ = fixture.subject_request(Membership::Add, body.clone()).await;
    let _ = fixture.subject_request(Membership::Remove, body).await;

    // Assert
    assert_eq!(
        fixture.trail(),
        vec![EventType::SSF_SUBJECT_ADDED, EventType::SSF_SUBJECT_REMOVED]
    );
    let written = format!("{:?}", fixture.audit.0.lock().expect("lock"));
    assert!(
        !written.contains(KNOWN),
        "a subject identifier reached the trail: {written}"
    );
}

// ---------------------------------------------------------------------------
// §8.1.4.2 — the verification endpoint
// ---------------------------------------------------------------------------

/// §8.1.4.2: a receiver asks its transmitter to verify a stream and gets 204,
/// with the `state` carried to the queue exactly as it sent it.
#[tokio::test]
async fn a_receiver_asks_for_a_verification_and_the_set_carries_its_state() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.verifiable_stream();

    // Act
    let response = fixture
        .verification_request(json!({
            "stream_id": stream.as_str(),
            "state": "VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo=",
        }))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        fixture.verifier.queued(),
        vec![(
            RECEIVER.to_owned(),
            stream.as_str().to_owned(),
            Some("VGhpcyBpcyBhbiBleGFtcGxlIHN0YXRlIHZhbHVlLgo=".to_owned()),
        )]
    );
    assert!(
        fixture
            .trail()
            .contains(&EventType::SSF_VERIFICATION_REQUESTED)
    );
}

/// `state` is OPTIONAL (§8.1.4.2): a request without one is still 204.
#[tokio::test]
async fn a_verification_without_a_state_is_accepted() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.verifiable_stream();

    // Act
    let response = fixture
        .verification_request(json!({"stream_id": stream.as_str()}))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(fixture.verifier.queued().len(), 1);
    assert_eq!(fixture.verifier.queued()[0].2, None);
}

/// > If the Event Receiver requests verification more frequently than the
/// > `min_verification_interval`, the Event Transmitter MUST respond with 429.
///
/// And the refusal says how long to wait, so a receiver retries once rather
/// than in a loop.
#[tokio::test]
async fn a_second_verification_inside_the_interval_is_refused_with_a_retry_after() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.verifiable_stream();
    let first = fixture
        .verification_request(json!({"stream_id": stream.as_str()}))
        .await;
    assert_eq!(first.status(), StatusCode::NO_CONTENT);

    // Act
    let second = fixture
        .verification_request(json!({"stream_id": stream.as_str()}))
        .await;

    // Assert
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        second
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("60")
    );
    // And the refusal queued nothing: one SET for two requests.
    assert_eq!(fixture.verifier.queued().len(), 1);
}

/// §8: the stream a receiver may verify is one of its own. Another
/// receiver's is 404, the same answer as a stream that does not exist.
#[tokio::test]
async fn another_receivers_stream_cannot_be_verified() {
    // Arrange
    let fixture = Fixture::new().await;
    let theirs = StreamId::generate();
    fixture.verifier.owns("other-receiver", &theirs);

    // Act
    let response = fixture
        .verification_request(json!({"stream_id": theirs.as_str()}))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(fixture.verifier.queued().is_empty());
}

/// §8.1.4.2 makes `stream_id` REQUIRED: a request without one addresses no
/// stream and is a 400, not a 404 about a stream nobody named.
#[tokio::test]
async fn a_verification_without_a_stream_id_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture
        .verification_request(json!({"state": "corr-1"}))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// The `state` ends up in a signed token handed to a third party, so the
/// endpoint refuses what the model refuses — before anything is queued, and
/// without echoing the value.
#[tokio::test]
async fn a_state_with_a_control_character_is_refused_before_anything_is_queued() {
    // Arrange
    let fixture = Fixture::new().await;
    let stream = fixture.verifiable_stream();

    // Act
    let response = fixture
        .verification_request(json!({
            "stream_id": stream.as_str(),
            "state": "secret-value\r\n",
        }))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.verifier.queued().is_empty());
    let body = body_of(response).await.to_string();
    assert!(!body.contains("secret-value"), "{body}");
}

/// §8.1.4.2 is a `POST`. A `GET` at this URL is 405, not a verification.
#[tokio::test]
async fn the_verification_endpoint_answers_only_post() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture
        .verification_with(Method::GET, json!({"stream_id": "s"}))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}
