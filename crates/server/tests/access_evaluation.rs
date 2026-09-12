//! The AuthZEN Access Evaluation and Access Evaluations endpoints
//! (Authorization API 1.0 §6, §7, §10.1, `ast-pj0.1`, `ast-pj0.2`).
//!
//! Every test here goes through the real handler with a real signed access
//! token, a real DPoP proof, the real verifier and the real
//! [`asterius_domain::policy::DeclarativeEngine`] — only the rows are faked,
//! exactly as `ssf_management.rs` does. This endpoint decides who reaches what
//! in somebody else's application; an endpoint whose credential checks or whose
//! evaluator were stubbed would be one whose tests pass for requests it should
//! refuse.
//!
//! # What the interop cases are, and what they are not
//!
//! `the_authzen_interop_todo_scenario_is_reproduced` replays the 40
//! request/expectation pairs of the AuthZEN interop "todo" scenario, taken from
//! `openid/authzen`, `interop/authzen-todo-backend/test/`
//! `decisions-authorization-api-1_0-02.json` (read at commit 78a7402). The
//! requests and the expected decisions are the interop suite's; the *policy*
//! is written here, because a PDP's rule catalogue is out of the specification's
//! scope (§2) and the interop suite carries one per participating PDP.
//!
//! Two of those rules are per-person, and that is worth being honest about.
//! The todo application's real rule is "an editor may change a todo they own",
//! which compares `resource.properties.ownerID` against the subject — a
//! comparison between two entities that ADR-0011's rule language does not have.
//! What it does have is an attribute test against a *literal*, so the two
//! editors get a rule each. Everything else — the roles, the deny-by-default,
//! the viewer who may read and not write — is expressed as the catalogue was
//! meant to be.

use asterius_domain::audit::{AuditEvent, AuditSink, DetailValue, EventType, Outcome};
use asterius_domain::entities::application_role::HeldRoles;
use asterius_domain::keys::Kid;
use asterius_domain::keys::{Signer as _, SigningAlgorithm};
use asterius_domain::policy::{DeclarativeEngine, RuleSet, StoredPolicy};
use asterius_domain::ports::PolicyStore;
use asterius_domain::rate_limit::{
    Bucket, EndpointLimit, EndpointLimits, RateLimit, RateLimitStore,
};
use asterius_domain::{
    AcrPolicy, ClientId, DomainError, Grant, GrantId, Issuer, ReplayCheck, ReplayGuard,
    ReplayPurpose, RoleName, Tenant, TenantId, TenantStatus,
};
use asterius_jose::{LocalKeyStore, SigningKey, thumbprint};
use asterius_oidc::authzen::{MAX_DEPTH, MAX_EVALUATIONS, MAX_REQUEST_BYTES, SCOPE_EVALUATE};
use asterius_oidc::metadata::Endpoint;
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::{AccessToken, Audience, Confirmation};
use asterius_server::http::access_evaluation::{
    AccessEvaluationContext, PdpTokenStatus, ResolvedSubject, SubjectFacts, evaluate, evaluate_many,
};
use asterius_server::http::dpop::{DpopEndpoint, HEADER as DPOP_HEADER};
use asterius_server::http::limits::{EndpointThrottle, LimitContext};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";
/// The policy enforcement point, as a registered client.
const PEP: &str = "todo-api";
/// A subject this tenant holds, and the `sub` a PEP would have been given.
const ALICE: &str = "alice-subject-id";

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
}

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::new("demo"),
        issuer: Issuer::parse(ISSUER).expect("an issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: "demo".to_owned(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// The endpoint's path and URL, from the registry the metadata is rendered
/// from — so a test cannot pass against a URL the router does not mount.
fn path() -> &'static str {
    Endpoint::AccessEvaluation.path()
}

fn url() -> String {
    format!("{ISSUER}{}", path())
}

/// §7's boxcar, from the same registry (§10.1's default path).
fn many_path() -> &'static str {
    Endpoint::AccessEvaluations.path()
}

fn many_url() -> String {
    format!("{ISSUER}{}", many_path())
}

// ---------------------------------------------------------------------------
// The fakes
// ---------------------------------------------------------------------------

/// A tenant's policy in memory, and a store that can be made to fail.
#[derive(Debug)]
struct FakePolicies {
    rules: Mutex<Option<RuleSet>>,
    unreadable: Mutex<bool>,
    /// How many times the engine has been asked for a decision.
    ///
    /// `DeclarativeEngine` loads the document once per evaluation, so this is
    /// how a test proves that a short circuit (§7.1.2.1) stopped rather than
    /// evaluated the rest of the array and truncated the answer.
    loads: AtomicU64,
}

impl FakePolicies {
    fn holding(rules: RuleSet) -> Self {
        Self {
            rules: Mutex::new(Some(rules)),
            unreadable: Mutex::new(false),
            loads: AtomicU64::new(0),
        }
    }

    fn evaluations(&self) -> u64 {
        self.loads.load(Ordering::SeqCst)
    }

    fn breaks(&self) {
        *self.unreadable.lock().expect("lock") = true;
    }
}

#[async_trait::async_trait]
impl PolicyStore for FakePolicies {
    async fn load(&self, _tenant: &TenantId) -> Result<Option<StoredPolicy>, DomainError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        if *self.unreadable.lock().expect("lock") {
            return Err(DomainError::Storage(
                "the policy store is unreachable".into(),
            ));
        }
        Ok(self
            .rules
            .lock()
            .expect("lock")
            .clone()
            .map(|rules| StoredPolicy {
                rules,
                updated_at: now(),
            }))
    }

    async fn replace(
        &self,
        _tenant: &TenantId,
        rules: &RuleSet,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        *self.rules.lock().expect("lock") = Some(rules.clone());
        Ok(())
    }

    async fn clear(&self, _tenant: &TenantId) -> Result<bool, DomainError> {
        Ok(self.rules.lock().expect("lock").take().is_some())
    }
}

/// The facts this tenant holds about its people.
///
/// Keyed by the subject identifier, because that is what the endpoint resolves
/// by. A subject nobody knows resolves to nothing, which is the fail-closed
/// direction rather than an error.
#[derive(Debug, Default)]
struct FakeFacts {
    people: Mutex<BTreeMap<String, ResolvedSubject>>,
    unreadable: Mutex<bool>,
    /// The subjects this directory will not answer for, so that a boxcar can
    /// have one evaluation fail and the others decided (§7.2.1).
    unreadable_for: Mutex<BTreeSet<String>>,
    /// Every `(type, id)` this endpoint asked about, so a test can prove the
    /// resolution happened at all.
    asked: Mutex<Vec<(String, String)>>,
}

impl FakeFacts {
    fn holds(&self, subject: &str, facts: ResolvedSubject) {
        self.people
            .lock()
            .expect("lock")
            .insert(subject.to_owned(), facts);
    }

    fn breaks(&self) {
        *self.unreadable.lock().expect("lock") = true;
    }

    fn breaks_for(&self, subject: &str) {
        self.unreadable_for
            .lock()
            .expect("lock")
            .insert(subject.to_owned());
    }
}

#[async_trait::async_trait]
impl SubjectFacts for FakeFacts {
    async fn resolve(
        &self,
        _tenant: &TenantId,
        kind: &str,
        id: &str,
    ) -> Result<ResolvedSubject, DomainError> {
        self.asked
            .lock()
            .expect("lock")
            .push((kind.to_owned(), id.to_owned()));
        if *self.unreadable.lock().expect("lock")
            || self.unreadable_for.lock().expect("lock").contains(id)
        {
            return Err(DomainError::Storage("the directory is unreachable".into()));
        }
        Ok(self
            .people
            .lock()
            .expect("lock")
            .get(id)
            .cloned()
            .unwrap_or_default())
    }
}

#[derive(Debug, Default)]
struct FakeTokens {
    denylisted: Mutex<BTreeSet<String>>,
}

#[async_trait::async_trait]
impl PdpTokenStatus for FakeTokens {
    async fn is_denylisted(&self, jti: &str) -> Result<bool, DomainError> {
        Ok(self.denylisted.lock().expect("lock").contains(jti))
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
        ssf_subjects: plain,
        backchannel: plain,
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
    policies: Arc<FakePolicies>,
    facts: FakeFacts,
    tokens: FakeTokens,
    audit: FakeAudit,
    limiter: FakeLimiter,
    limits: EndpointLimits,
    acr: AcrPolicy,
    token: String,
    /// Whether this fixture posts to §7's endpoint rather than §6.1's.
    boxcar: bool,
}

impl Fixture {
    /// A deployment whose tenant permits `alice` to read her own account.
    async fn new() -> Self {
        Self::with_policy(catalogue(
            r#"[{"id": "read-own-account", "effect": "permit",
                 "subject_type": "user", "resource_type": "account",
                 "actions": ["can_read"]}]"#,
        ))
        .await
    }

    async fn with_policy(rules: RuleSet) -> Self {
        Self::with(rules, &[SCOPE_EVALUATE], &url()).await
    }

    /// A deployment whose PEP holds a token for §7's endpoint.
    async fn boxcarring(rules: RuleSet) -> Self {
        let mut fixture = Self::with(rules, &[SCOPE_EVALUATE], &many_url()).await;
        fixture.boxcar = true;
        fixture
    }

    /// The URL this fixture's requests are made to: the audience its token
    /// carries, and the `htu` its DPoP proofs are made over.
    fn target(&self) -> String {
        if self.boxcar { many_url() } else { url() }
    }

    async fn with(rules: RuleSet, scopes: &[&str], audience: &str) -> Self {
        let keys = Arc::new(LocalKeyStore::new());
        keys.generate(&TenantId::new("demo"), SigningAlgorithm::DEFAULT)
            .expect("a tenant key");
        let dpop_key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("a DPoP key");
        let jkt = thumbprint(&dpop_key.public_jwk().expect("a jwk")).expect("a thumbprint");
        let token = sign_token(&keys, &jkt, scopes, audience).await;

        Self {
            keys,
            dpop_key,
            policies: Arc::new(FakePolicies::holding(rules)),
            facts: FakeFacts::default(),
            tokens: FakeTokens::default(),
            audit: FakeAudit::default(),
            limiter: FakeLimiter::default(),
            limits: limits(1_000),
            acr: AcrPolicy::default(),
            token,
            boxcar: false,
        }
    }

    fn allowing(mut self, requests: u32) -> Self {
        self.limits = limits(requests);
        self
    }

    /// One request, with the credential and the media type §10.1 requires.
    async fn post(&self, body: &Value) -> Response {
        self.post_with(&self.headers("POST", None), &Method::POST, body)
            .await
    }

    async fn post_with(&self, headers: &HeaderMap, method: &Method, body: &Value) -> Response {
        let rendered = serde_json::to_vec(body).expect("a JSON body");
        self.post_bytes(headers, method, &rendered).await
    }

    async fn post_bytes(&self, headers: &HeaderMap, method: &Method, body: &[u8]) -> Response {
        let tenant = tenant();
        let dpop = DpopEndpoint::new(Arc::new(FakeReplay), None);
        let engine = DeclarativeEngine::new(Arc::clone(&self.policies) as Arc<dyn PolicyStore>);
        let context = AccessEvaluationContext {
            tenant: &tenant,
            engine: &engine,
            subjects: &self.facts,
            tokens: &self.tokens,
            keys: self.keys.as_ref(),
            dpop: &dpop,
            audit: &self.audit,
            certificate: None,
            acr: &self.acr,
            limits: LimitContext {
                tenant: &tenant.id,
                throttle: EndpointThrottle::new(&self.limiter, self.limits, Some(address())),
                audit: &self.audit,
                now: now(),
            },
            now: now(),
        };
        if self.boxcar {
            evaluate_many(context, method, headers, body).await
        } else {
            evaluate(context, method, headers, body).await
        }
    }

    /// The headers a well-formed request carries, plus an optional
    /// `X-Request-ID` (§10.1.3).
    fn headers(&self, method: &str, request_id: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", self.token)).expect("a header value"),
        );
        headers.insert(
            DPOP_HEADER,
            HeaderValue::from_str(&self.proof(method)).expect("a header value"),
        );
        if let Some(id) = request_id {
            headers.insert(
                "x-request-id",
                HeaderValue::from_str(id).expect("a header value"),
            );
        }
        headers
    }

    fn proof(&self, method: &str) -> String {
        let mut jwk = self.dpop_key.public_jwk().expect("a jwk");
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
            "htu": self.target(),
            "iat": now().unix_timestamp(),
            "ath": B64.encode(Sha256::digest(self.token.as_bytes())),
        });
        sign_by_hand(&self.dpop_key, &header, &claims)
    }

    fn trail(&self) -> Vec<AuditEvent> {
        self.audit.0.lock().expect("lock").clone()
    }
}

async fn sign_token(keys: &LocalKeyStore, jkt: &Kid, scopes: &[&str], audience: &str) -> String {
    let mut grant = Grant::new(TenantId::new("demo"), ClientId::new(PEP), now());
    grant.scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    grant.claimed_at = Some(now());
    let claimed = grant.claim(now()).expect("a live grant");
    let unsigned = AccessToken::new(
        &Issuer::parse(ISSUER).expect("an issuer"),
        &grant,
        &claimed,
        Audience::new([audience]).expect("an audience"),
        Confirmation::dpop(jkt).expect("a confirmation"),
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
    .expect("a signature")
    .as_str()
    .to_owned()
}

fn sign_by_hand(key: &SigningKey, header: &Value, claims: &Value) -> String {
    let signing_input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(header).expect("a header")),
        B64.encode(serde_json::to_vec(claims).expect("claims"))
    );
    let signature = key.sign(signing_input.as_bytes()).expect("a signature");
    format!("{signing_input}.{}", B64.encode(signature))
}

/// A `jti` that is unique per proof, so a test that sends two is not a replay.
fn unique_jti() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("proof-{}", NEXT.fetch_add(1, Ordering::SeqCst))
}

fn catalogue(rules: &str) -> RuleSet {
    RuleSet::parse(&format!(r#"{{"version": 1, "rules": {rules}}}"#)).expect("a valid catalogue")
}

async fn body_of(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).expect("a JSON body")
}

async fn text_of(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("a body");
    String::from_utf8(bytes.to_vec()).expect("a UTF-8 body")
}

/// §6.1's example request, aimed at a subject this tenant holds.
fn request() -> Value {
    json!({
        "subject": {"type": "user", "id": ALICE},
        "action": {"name": "can_read"},
        "resource": {"type": "account", "id": "123"},
    })
}

fn role(name: &str) -> RoleName {
    RoleName::parse(name).expect("a role name")
}

fn holding_tenant_role(name: &str) -> HeldRoles {
    let mut roles = HeldRoles::empty();
    roles.tenant.insert(role(name));
    roles
}

// ---------------------------------------------------------------------------
// §6.1, §6.2 — the decision
// ---------------------------------------------------------------------------

/// §6.2 and §10.1: a permitted request is 200 and §5.5's Decision.
#[tokio::test]
async fn a_permitted_request_is_a_200_and_a_decision() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture.post(&request()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    // §5.5: `decision` is the REQUIRED member, and the context names the rule
    // that produced the permit — which is what makes it answerable for later.
    assert_eq!(
        body_of(response).await,
        json!({"decision": true, "context": {"id": "read-own-account"}})
    );
}

/// §10.1.2: "the PDP indicates to the PEP that the authorization request is
/// denied by sending a response with a 200 HTTPS status code, along with a
/// payload of `{ "decision": false }`" — and §5.5.1's context explains it.
#[tokio::test]
async fn a_denied_request_is_a_200_carrying_the_reason() {
    // Arrange
    let fixture = Fixture::with_policy(catalogue(
        r#"[{"id": "no-writes", "effect": "deny", "actions": ["can_read"],
             "reason_admin": "reads of accounts are closed",
             "reason_user": "you cannot read this account",
             "acr_values": ["urn:asterius:acr:passkey-uv"]}]"#,
    ))
    .await;

    // Act
    let response = fixture.post(&request()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_of(response).await;
    assert_eq!(body["decision"], json!(false));
    assert_eq!(body["context"]["id"], json!("no-writes"));
    assert_eq!(
        body["context"]["reason_user"],
        json!({"en": "you cannot read this account"})
    );
    assert_eq!(
        body["context"]["acr_values"],
        json!(["urn:asterius:acr:passkey-uv"])
    );
}

/// Default deny: a tenant with no document admits nobody, and says which
/// silence it was.
#[tokio::test]
async fn a_tenant_with_no_policy_denies_everything() {
    // Arrange
    let fixture = Fixture::new().await;
    fixture.policies.clear(&TenantId::new("demo")).await.ok();

    // Act
    let body = body_of(fixture.post(&request()).await).await;

    // Assert
    assert_eq!(body["decision"], json!(false));
    assert!(
        body["context"]["reason_admin"]["en"]
            .as_str()
            .is_some_and(|reason| reason.contains("no policy document")),
        "{body}"
    );
}

/// Every response, whatever it says.
#[tokio::test]
async fn no_decision_is_cacheable() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture.post(&request()).await;

    // Assert
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

// ---------------------------------------------------------------------------
// §10.1.1 — reading the request
// ---------------------------------------------------------------------------

/// §10.1.1: "If a required attribute in the information model is omitted, the
/// server MUST return a Bad Request error", whose body is an error message
/// string.
#[tokio::test]
async fn a_request_missing_a_required_member_is_a_400_with_a_message() {
    for (entity, field, expected) in [
        ("subject", "id", "subject.id"),
        ("resource", "type", "resource.type"),
        ("action", "name", "action.name"),
    ] {
        // Arrange
        let fixture = Fixture::new().await;
        let mut body = request();
        body[entity]
            .as_object_mut()
            .expect("an entity")
            .remove(field);

        // Act
        let response = fixture.post(&body).await;

        // Assert
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let message = text_of(response).await;
        assert!(message.contains(expected), "{message}");
        assert!(
            fixture.trail().is_empty(),
            "a request that was never a question was audited as a decision"
        );
    }
}

/// §10.1.1: unknown members are ignored, so a PEP built against a later
/// revision still gets an answer.
#[tokio::test]
async fn unknown_members_are_ignored() {
    // Arrange
    let fixture = Fixture::new().await;
    let mut body = request();
    body["subject"]["properties"] = json!({"department": "sales"});
    body["evaluations_semantic"] = json!("execute_all");
    body["action"]["unheard_of"] = json!([1, 2, 3]);

    // Act
    let response = fixture.post(&body).await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    // §5.5: `decision` is the REQUIRED member, and the context names the rule
    // that produced the permit — which is what makes it answerable for later.
    assert_eq!(
        body_of(response).await,
        json!({"decision": true, "context": {"id": "read-own-account"}})
    );
}

/// §11.7: a payload past the size bound is refused, and refused before it is
/// walked.
#[tokio::test]
async fn an_over_sized_payload_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let mut body = request();
    body["resource"]["properties"] = json!({"blob": "x".repeat(MAX_REQUEST_BYTES)});

    // Act
    let response = fixture.post(&body).await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(text_of(response).await.contains("longer than"));
}

/// §11.7's "nested JSON attacks".
#[tokio::test]
async fn an_over_nested_payload_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let mut nest = json!("leaf");
    for _ in 0..=MAX_DEPTH {
        nest = json!([nest]);
    }
    let mut body = request();
    body["context"] = json!({"deep": nest});

    // Act
    let response = fixture.post(&body).await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(text_of(response).await.contains("nests deeper"));
}

/// §10.1: `POST`, and the media type the binding names.
#[tokio::test]
async fn the_binding_is_post_with_json() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act: a GET, which the router accepts so that this refusal is the
    // endpoint's own rather than axum's empty one.
    let response = fixture
        .post_with(&fixture.headers("GET", None), &Method::GET, &request())
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        response
            .headers()
            .get(header::ALLOW)
            .and_then(|value| value.to_str().ok()),
        Some("POST")
    );
}

#[tokio::test]
async fn a_request_that_is_not_json_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let mut headers = fixture.headers("POST", None);
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    // Act
    let response = fixture.post_with(&headers, &Method::POST, &request()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(text_of(response).await.contains("application/json"));
}

// ---------------------------------------------------------------------------
// §11.2, §11.3 — authenticating the PEP
// ---------------------------------------------------------------------------

/// §11.3: no credential is a 401 with a `WWW-Authenticate` challenge, and no
/// decision at all.
#[tokio::test]
async fn an_unauthenticated_request_is_a_401_with_a_challenge() {
    // Arrange
    let fixture = Fixture::new().await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    // Act
    let response = fixture.post_with(&headers, &Method::POST, &request()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .any(|value| value.to_str().is_ok_and(|challenge| {
                challenge.starts_with("DPoP") || challenge.starts_with("Bearer")
            })),
        "no challenge on a 401"
    );
}

/// §11.2 with RFC 6750 §3.1: a token that authenticates the PEP and does not
/// carry the scope is a 403 naming the scope it needs.
#[tokio::test]
async fn a_token_without_the_scope_is_a_403() {
    // Arrange
    let fixture = Fixture::with(
        catalogue(r#"[{"id": "r", "effect": "permit"}]"#),
        &["openid"],
        &url(),
    )
    .await;

    // Act
    let response = fixture.post(&request()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .expect("a challenge")
        .to_owned();
    assert!(challenge.contains("insufficient_scope"), "{challenge}");
    assert!(challenge.contains(SCOPE_EVALUATE), "{challenge}");
}

/// RFC 9068 §3: a token audienced at somebody else's resource is not one this
/// PDP answers, however good it is.
#[tokio::test]
async fn a_token_audienced_elsewhere_is_refused() {
    // Arrange
    let fixture = Fixture::with(
        catalogue(r#"[{"id": "r", "effect": "permit"}]"#),
        &[SCOPE_EVALUATE],
        "https://api.example/",
    )
    .await;

    // Act
    let response = fixture.post(&request()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// RFC 9449 §7.1: the proof is made over the method and the URL of *this*
/// request.
#[tokio::test]
async fn a_proof_for_another_method_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    // A proof made for a GET, presented on the POST.
    let headers = fixture.headers("GET", None);

    // Act
    let response = fixture.post_with(&headers, &Method::POST, &request()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// RFC 7009: a token on the denylist is refused, even inside its `exp`.
#[tokio::test]
async fn a_revoked_token_is_refused() {
    // Arrange
    let fixture = Fixture::new().await;
    let jti = jti_of(&fixture.token);
    fixture.tokens.denylisted.lock().expect("lock").insert(jti);

    // Act
    let response = fixture.post(&request()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// The `jti` of a signed token, read from its payload.
fn jti_of(token: &str) -> String {
    let payload = token.split('.').nth(1).expect("a payload");
    let decoded = B64.decode(payload).expect("base64url");
    let claims: Value = serde_json::from_slice(&decoded).expect("JSON claims");
    claims["jti"].as_str().expect("a jti").to_owned()
}

// ---------------------------------------------------------------------------
// §11.4 — what a PEP may assert
// ---------------------------------------------------------------------------

/// The property the endpoint rests on: group membership is resolved here, and a
/// PEP that claims a group in `properties` does not get it.
#[tokio::test]
async fn a_pep_cannot_assert_a_group_it_does_not_hold() {
    // Arrange
    let fixture = Fixture::with_policy(catalogue(
        r#"[{"id": "finance-only", "effect": "permit", "actions": ["can_read"],
             "when": {"group": "finance"}}]"#,
    ))
    .await;
    let mut body = request();
    body["subject"]["properties"] = json!({"groups": ["finance"], "group": "finance"});

    // Act
    let response = fixture.post(&body).await;

    // Assert
    assert_eq!(body_of(response).await["decision"], json!(false));
}

/// …and the same request is permitted once this tenant actually holds the
/// subject in that group.
#[tokio::test]
async fn a_group_this_server_holds_satisfies_the_condition() {
    // Arrange
    let fixture = Fixture::with_policy(catalogue(
        r#"[{"id": "finance-only", "effect": "permit", "actions": ["can_read"],
             "when": {"group": "finance"}}]"#,
    ))
    .await;
    fixture.facts.holds(
        ALICE,
        ResolvedSubject {
            groups: ["finance".to_owned()].into_iter().collect(),
            ..ResolvedSubject::default()
        },
    );

    // Act
    let response = fixture.post(&request()).await;

    // Assert
    assert_eq!(body_of(response).await["decision"], json!(true));
    assert_eq!(
        fixture.facts.asked.lock().expect("lock").as_slice(),
        [("user".to_owned(), ALICE.to_owned())],
        "the endpoint did not resolve the subject it was asked about"
    );
}

/// An application role is resolved the same way, and a PEP cannot assert one.
#[tokio::test]
async fn an_application_role_is_resolved_by_this_server() {
    // Arrange
    let fixture = Fixture::with_policy(catalogue(
        r#"[{"id": "auditors", "effect": "permit", "actions": ["can_read"],
             "when": {"role": {"name": "auditor", "owner": "tenant"}}}]"#,
    ))
    .await;
    let mut claimed = request();
    claimed["subject"]["properties"] = json!({"roles": ["auditor"]});

    // Act: first as the PEP would like it to be, then as this tenant records it.
    let asserted = body_of(fixture.post(&claimed).await).await;
    fixture.facts.holds(
        ALICE,
        ResolvedSubject {
            roles: holding_tenant_role("auditor"),
            ..ResolvedSubject::default()
        },
    );
    let held = body_of(fixture.post(&request()).await).await;

    // Assert
    assert_eq!(asserted["decision"], json!(false));
    assert_eq!(held["decision"], json!(true));
}

// ---------------------------------------------------------------------------
// §10.1.2 — failing closed
// ---------------------------------------------------------------------------

/// §10.1.2, fail closed: a PDP that cannot read its policy answers a deny that
/// says so, and records the reason.
#[tokio::test]
async fn a_policy_store_that_cannot_be_read_is_a_deny_that_says_so() {
    // Arrange
    let fixture = Fixture::new().await;
    fixture.policies.breaks();

    // Act
    let response = fixture.post(&request()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_of(response).await;
    assert_eq!(body["decision"], json!(false));
    assert_eq!(body["context"]["error"]["status"], json!(500));

    let trail = fixture.trail();
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].event_type, EventType::ACCESS_EVALUATED);
    assert_eq!(trail[0].outcome, Outcome::Failure);
}

/// The same when the *facts* cannot be read: an outage in the directory is not
/// a permit either, and the trail carries the decision that was not taken.
#[tokio::test]
async fn a_directory_that_cannot_be_read_is_a_deny_that_says_so() {
    // Arrange
    let fixture = Fixture::new().await;
    fixture.facts.breaks();

    // Act
    let response = fixture.post(&request()).await;

    // Assert
    let body = body_of(response).await;
    assert_eq!(body["decision"], json!(false));
    assert_eq!(body["context"]["error"]["status"], json!(500));
}

// ---------------------------------------------------------------------------
// §10.1.3 — the request identifier
// ---------------------------------------------------------------------------

/// §10.1.3: "If the PEP specified a request identifier in the request, the PDP
/// MUST include the same identifier in the response to that request."
#[tokio::test]
async fn a_request_identifier_is_echoed() {
    // Arrange
    let fixture = Fixture::new().await;
    let identifier = "bfe9eb29-ab87-4ca3-be83-a1d5d8305716";
    let headers = fixture.headers("POST", Some(identifier));

    // Act
    let response = fixture.post_with(&headers, &Method::POST, &request()).await;

    // Assert
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(identifier)
    );
}

/// …on a refusal as much as on a decision: a PEP correlating a 401 needs it
/// more than one correlating a permit.
#[tokio::test]
async fn a_request_identifier_is_echoed_on_a_refusal_too() {
    // Arrange
    let fixture = Fixture::new().await;
    let identifier = "a-refused-request";
    let mut headers = fixture.headers("POST", Some(identifier));
    headers.remove(header::AUTHORIZATION);

    // Act
    let response = fixture.post_with(&headers, &Method::POST, &request()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(identifier)
    );
}

/// A request that sent none gets none from the handler: this server's own
/// identifier is put on by the middleware, which is what §10.1.3 leaves open.
#[tokio::test]
async fn a_request_with_no_identifier_gets_none_from_the_handler() {
    // Arrange
    let fixture = Fixture::new().await;

    // Act
    let response = fixture.post(&request()).await;

    // Assert
    assert!(response.headers().get("x-request-id").is_none());
}

// ---------------------------------------------------------------------------
// The trail
// ---------------------------------------------------------------------------

/// Every decision is recorded with a summary — and never with the
/// `properties` a PEP sent.
#[tokio::test]
async fn a_decision_is_audited_as_a_summary_and_not_as_the_request() {
    // Arrange
    let fixture = Fixture::new().await;
    let mut body = request();
    body["subject"]["properties"] = json!({"department": "a-secret-department"});
    body["resource"]["properties"] = json!({"classification": "restricted"});

    // Act
    fixture.post(&body).await;

    // Assert
    let trail = fixture.trail();
    assert_eq!(trail.len(), 1);
    let event = &trail[0];
    assert_eq!(event.event_type, EventType::ACCESS_EVALUATED);
    assert_eq!(event.outcome, Outcome::Success);
    assert_eq!(event.client.as_ref().map(ClientId::as_str), Some(PEP));

    let rendered = rendered_detail(event);
    assert!(rendered.contains("can_read"), "{rendered}");
    assert!(rendered.contains("account"), "{rendered}");
    assert!(rendered.contains("latency_us"), "{rendered}");
    assert!(
        !rendered.contains("a-secret-department"),
        "the trail carried the PEP's subject properties: {rendered}"
    );
    assert!(
        !rendered.contains("restricted"),
        "the trail carried the PEP's resource properties: {rendered}"
    );
    assert!(
        !rendered.contains(ALICE),
        "the trail carried the subject identifier in clear: {rendered}"
    );
}

/// A deny is recorded as a failure, so an operator filtering the trail for
/// refusals sees them without reading a detail map.
#[tokio::test]
async fn a_deny_is_recorded_as_a_failure() {
    // Arrange
    let fixture = Fixture::with_policy(RuleSet::deny_all()).await;

    // Act
    fixture.post(&request()).await;

    // Assert
    let trail = fixture.trail();
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].outcome, Outcome::Failure);
}

// ---------------------------------------------------------------------------
// §11.7 — rate limiting
// ---------------------------------------------------------------------------

/// §11.7: a PEP over its budget meets a 429 with a `Retry-After`, and the
/// policy is never read for the refused request.
#[tokio::test]
async fn a_pep_over_its_budget_is_throttled() {
    // Arrange: one request per window.
    let fixture = Fixture::new().await.allowing(1);

    // Act
    let first = fixture.post(&request()).await;
    let second = fixture.post(&request()).await;

    // Assert
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(second.headers().get(header::RETRY_AFTER).is_some());
}

// ---------------------------------------------------------------------------
// Latency
// ---------------------------------------------------------------------------

/// `ast-pj0.1`: the built-in engine decides within 5 ms at the 95th
/// percentile.
///
/// Measured from the endpoint's own record — `latency_us` covers the parsed
/// request, the resolution of this server's facts and the policy walk, which is
/// what "the built-in engine" means here; the credential checks in front of it
/// are RFC 9449's cryptography and are measured by nothing in this ticket.
///
/// A hundred requests against a catalogue of a hundred rules, which is the
/// bound the parser permits minus the margin a document has for growing.
#[tokio::test]
async fn the_built_in_engine_decides_within_five_milliseconds_at_the_95th_percentile() {
    // Arrange
    let rules: Vec<String> = (0..99)
        .map(|index| {
            format!(
                r#"{{"id": "r{index}", "effect": "permit", "actions": ["never_asked_{index}"],
                     "when": {{"all": [{{"group": "g{index}"}},
                                       {{"attribute": {{"of": "resource", "name": "tier",
                                                        "in": ["gold", "silver"]}}}}]}}}}"#
            )
        })
        .collect();
    let catalogue = catalogue(&format!(
        "[{}, {{\"id\": \"read-own-account\", \"effect\": \"permit\", \"actions\": [\"can_read\"]}}]",
        rules.join(", ")
    ));
    let fixture = Fixture::with_policy(catalogue).await;

    // Act
    for _ in 0..100 {
        assert_eq!(fixture.post(&request()).await.status(), StatusCode::OK);
    }

    // Assert
    let mut measured: Vec<i64> = fixture.trail().iter().filter_map(latency_of).collect();
    assert_eq!(measured.len(), 100, "not every decision recorded a latency");
    measured.sort_unstable();
    let p95 = measured[94];
    assert!(
        p95 <= 5_000,
        "p95 of the built-in engine was {p95} µs over 100 decisions"
    );
}

/// The `latency_us` an event recorded, as the trail stores it.
fn latency_of(event: &AuditEvent) -> Option<i64> {
    event.detail.iter().find_map(|(key, value)| match value {
        DetailValue::Number(micros) if key == "latency_us" => Some(*micros),
        _ => None,
    })
}

/// Every detail an event carries, rendered as one string — which is how a
/// test asks "is this value anywhere in the record", whichever key it might
/// have been put under.
fn rendered_detail(event: &AuditEvent) -> String {
    event
        .detail
        .iter()
        .map(|(key, value)| format!("{key}={value:?}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// §7 — the boxcar
// ---------------------------------------------------------------------------

/// §7.1.2.1's example catalogue: "read" is permitted on a document the tenant
/// has marked public, and refused otherwise.
///
/// The specification's own example asks `read` of documents `1`, `2` and `3`
/// and answers `true`, `false`, `true`. Which of the three is refused is a
/// property of the PDP's rules, which §2 puts out of scope, and ADR-0011's
/// language matches attributes rather than resource identifiers (`ast-pj0.1`
/// carries the same note) — so the three documents carry a `public` property
/// and the rule reads it. The decisions, their order, and the truncation of
/// each short circuit are the specification's.
fn public_documents() -> RuleSet {
    catalogue(
        r#"[{"id": "read-public", "effect": "permit",
             "resource_type": "document", "actions": ["read"],
             "when": {"attribute": {"of": "resource", "name": "public", "equals": true}}}]"#,
    )
}

/// §7.1.2.1's request, with the semantic under test.
fn three_documents(semantic: &str) -> Value {
    json!({
        "subject": {"type": "user", "id": ALICE},
        "action": {"name": "read"},
        "options": {"evaluations_semantic": semantic},
        "evaluations": [
            {"resource": {"type": "document", "id": "1", "properties": {"public": true}}},
            {"resource": {"type": "document", "id": "2", "properties": {"public": false}}},
            {"resource": {"type": "document", "id": "3", "properties": {"public": true}}},
        ]
    })
}

fn decisions_of(body: &Value) -> Vec<bool> {
    body["evaluations"]
        .as_array()
        .expect("§7.2's evaluations array")
        .iter()
        .map(|decision| decision["decision"].as_bool().expect("a decision"))
        .collect()
}

/// §7.1.2.1, all three semantics, on the section's own example: `execute_all`
/// answers every evaluation, and each short circuit truncates the array at the
/// decision that settled it — *and stops evaluating*, which is the saving the
/// option exists for.
#[tokio::test]
async fn the_three_semantics_answer_the_arrays_of_section_seven() {
    for (semantic, expected) in [
        ("execute_all", vec![true, false, true]),
        ("deny_on_first_deny", vec![true, false]),
        ("permit_on_first_permit", vec![true]),
    ] {
        // Arrange
        let fixture = Fixture::boxcarring(public_documents()).await;

        // Act
        let response = fixture.post(&three_documents(semantic)).await;

        // Assert
        assert_eq!(response.status(), StatusCode::OK, "{semantic}");
        let body = body_of(response).await;
        assert_eq!(decisions_of(&body), expected, "{semantic}");
        assert!(
            body.get("decision").is_none(),
            "§7.2: the top-level decision is omitted ({semantic})"
        );
        assert_eq!(
            fixture.policies.evaluations(),
            expected.len() as u64,
            "{semantic} evaluated the whole array and truncated the answer"
        );
    }
}

/// §7.1.2.1: "`execute_all` is the default semantic, so an evaluations request
/// without the `options.evaluations_semantic` flag will execute using this
/// semantic."
#[tokio::test]
async fn an_array_with_no_options_executes_every_evaluation() {
    // Arrange
    let fixture = Fixture::boxcarring(public_documents()).await;
    let mut body = three_documents("execute_all");
    body.as_object_mut().expect("an object").remove("options");

    // Act
    let response = fixture.post(&body).await;

    // Assert
    assert_eq!(decisions_of(&body_of(response).await), [true, false, true]);
}

/// §7.1.1: a required entity missing from an evaluation *and* from the
/// defaults is §10.1.1's 400 — for the whole request, because there is no
/// decision to report about an evaluation that was never a request.
#[tokio::test]
async fn an_entity_missing_after_the_defaults_refuses_the_whole_request() {
    // Arrange
    let fixture = Fixture::boxcarring(public_documents()).await;
    let body = json!({
        "subject": {"type": "user", "id": ALICE},
        "evaluations": [
            {"action": {"name": "read"}, "resource": {"type": "document", "id": "1"}},
            {"resource": {"type": "document", "id": "2"}},
        ]
    });

    // Act
    let response = fixture.post(&body).await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let message = text_of(response).await;
    assert!(message.contains("evaluations[1]"), "{message}");
    assert!(message.contains("action"), "{message}");
}

/// §7.2.1's second kind of error: one evaluation this PDP could not decide is
/// that evaluation's `decision: false` with an `error` in its context, and the
/// others are answered as if nothing had happened.
#[tokio::test]
async fn an_evaluation_that_cannot_be_decided_denies_only_itself() {
    // Arrange: the directory will not answer for the second subject.
    let fixture = Fixture::boxcarring(public_documents()).await;
    fixture.facts.breaks_for("bob-subject-id");
    let body = json!({
        "action": {"name": "read"},
        "resource": {"type": "document", "id": "1", "properties": {"public": true}},
        "evaluations": [
            {"subject": {"type": "user", "id": ALICE}},
            {"subject": {"type": "user", "id": "bob-subject-id"}},
            {"subject": {"type": "user", "id": ALICE}},
        ]
    });

    // Act
    let response = fixture.post(&body).await;

    // Assert
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a per-item error is not a status code"
    );
    let body = body_of(response).await;
    assert_eq!(decisions_of(&body), [true, false, true]);
    let failed = &body["evaluations"][1];
    assert_eq!(failed["context"]["error"]["status"], json!(500));
    assert!(body["evaluations"][0]["context"]["error"].is_null());
}

/// §11.7: the array is bounded, and an array over the bound is a 400 for the
/// whole request rather than the first hundred decisions.
#[tokio::test]
async fn an_array_over_the_cap_is_refused() {
    // Arrange
    let fixture = Fixture::boxcarring(public_documents()).await;
    let item = json!({"resource": {"type": "document", "id": "1", "properties": {"public": true}}});
    let mut body = json!({
        "subject": {"type": "user", "id": ALICE},
        "action": {"name": "read"},
    });
    body["evaluations"] = json!(vec![item; MAX_EVALUATIONS + 1]);

    // Act
    let response = fixture.post(&body).await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        fixture.policies.evaluations(),
        0,
        "an over-long array cost a policy walk"
    );
}

/// §11.7's payload bounds are the endpoint's, not the shape's: the same 64
/// kibibytes and the same nesting bound answer at §7's path.
#[tokio::test]
async fn the_payload_bounds_of_the_single_endpoint_apply_to_the_boxcar() {
    // Arrange
    let fixture = Fixture::boxcarring(public_documents()).await;
    let mut body = json!({
        "subject": {"type": "user", "id": ALICE},
        "action": {"name": "read"},
        "evaluations": [{"resource": {"type": "document", "id": "1",
                         "properties": {"blob": "x".repeat(MAX_REQUEST_BYTES)}}}],
    });
    let oversized = serde_json::to_vec(&body).expect("a JSON body");
    let mut nest = json!("leaf");
    for _ in 0..=MAX_DEPTH {
        nest = json!([nest]);
    }
    body["evaluations"] = json!([{"resource": {"type": "document", "id": "1"},
                                  "context": {"deep": nest}}]);

    // Act
    let too_long = fixture
        .post_bytes(&fixture.headers("POST", None), &Method::POST, &oversized)
        .await;
    let too_deep = fixture.post(&body).await;

    // Assert
    assert_eq!(too_long.status(), StatusCode::BAD_REQUEST);
    assert_eq!(too_deep.status(), StatusCode::BAD_REQUEST);
}

/// RFC 9068 §3: the two endpoints are two resources, and a token audienced at
/// §6.1's evaluation is not one §7's boxcar answers.
#[tokio::test]
async fn a_token_for_the_single_endpoint_is_not_accepted_at_the_boxcar() {
    // Arrange
    let mut fixture = Fixture::with(public_documents(), &[SCOPE_EVALUATE], &url()).await;
    fixture.boxcar = true;

    // Act
    let response = fixture.post(&three_documents("execute_all")).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// The same scope gates both (§11.2): one authority, asked in two shapes.
#[tokio::test]
async fn the_boxcar_needs_the_evaluate_scope() {
    // Arrange
    let mut fixture = Fixture::with(public_documents(), &["openid"], &many_url()).await;
    fixture.boxcar = true;

    // Act
    let response = fixture.post(&three_documents("execute_all")).await;

    // Assert
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(challenge.contains(SCOPE_EVALUATE), "{challenge}");
}

/// §11.7: one request is one token at the limiter, however many evaluations it
/// carries — and the budget is the PDP's, shared with §6.1's endpoint.
#[tokio::test]
async fn a_boxcar_costs_one_token_however_long_the_array_is() {
    // Arrange: a budget of one request per window.
    let fixture = Fixture::boxcarring(public_documents()).await.allowing(1);

    // Act
    let first = fixture.post(&three_documents("execute_all")).await;
    let second = fixture.post(&three_documents("execute_all")).await;

    // Assert
    assert_eq!(
        first.status(),
        StatusCode::OK,
        "three evaluations spent more than one token"
    );
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// The trail: one entry per request, carrying the semantic and the counts —
/// not one entry per evaluation, and not the resources of the array.
#[tokio::test]
async fn a_boxcar_is_one_audit_entry_naming_the_semantic_and_the_counts() {
    // Arrange
    let fixture = Fixture::boxcarring(public_documents()).await;

    // Act
    fixture.post(&three_documents("execute_all")).await;

    // Assert
    let trail = fixture.trail();
    assert_eq!(trail.len(), 1, "one entry per request, not per evaluation");
    let event = &trail[0];
    assert_eq!(event.event_type, EventType::ACCESS_EVALUATED);
    assert_eq!(
        event.outcome,
        Outcome::Failure,
        "an array holding a deny is a refusal an operator must be able to filter for"
    );
    let rendered = rendered_detail(event);
    assert!(rendered.contains("execute_all"), "{rendered}");
    assert!(rendered.contains("evaluations"), "{rendered}");
    assert!(rendered.contains("latency_us"), "{rendered}");
    assert!(
        !rendered.contains("subject-search"),
        "the trail carried the array's resources: {rendered}"
    );
}

/// A boxcar every one of whose evaluations permitted is a success in the
/// trail, and names the subject they all shared (§7.1.1's common case).
#[tokio::test]
async fn a_boxcar_that_permitted_everything_is_recorded_as_a_success() {
    // Arrange
    let fixture = Fixture::boxcarring(public_documents()).await;
    let body = json!({
        "subject": {"type": "user", "id": ALICE},
        "action": {"name": "read"},
        "evaluations": [
            {"resource": {"type": "document", "id": "1", "properties": {"public": true}}},
            {"resource": {"type": "document", "id": "3", "properties": {"public": true}}},
        ]
    });

    // Act
    fixture.post(&body).await;

    // Assert
    let event = &fixture.trail()[0];
    assert_eq!(event.outcome, Outcome::Success);
    assert!(rendered_detail(event).contains("subject_type"));
}

/// §7.1: "If an evaluations array is NOT present or is empty, the Access
/// Evaluations Request behaves in a backwards-compatible manner with the
/// (single) Access Evaluation API Request" — which means §6.2's response, a
/// Decision, and not an array of one.
#[tokio::test]
async fn an_empty_array_is_answered_as_a_single_decision() {
    // Arrange
    let fixture = Fixture::boxcarring(public_documents()).await;
    let body = json!({
        "subject": {"type": "user", "id": ALICE},
        "action": {"name": "read"},
        "resource": {"type": "document", "id": "1", "properties": {"public": true}},
        "evaluations": [],
    });

    // Act
    let response = fixture.post(&body).await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_of(response).await;
    assert_eq!(body["decision"], json!(true));
    assert!(body.get("evaluations").is_none());
}

/// §7.1.1's compact syntax is the common case, and it must not cost one
/// directory read per evaluation: the subject shared by a whole array is
/// resolved once, so the decisions are taken against one view of this tenant.
#[tokio::test]
async fn a_subject_shared_by_a_whole_array_is_resolved_once() {
    // Arrange
    let fixture = Fixture::boxcarring(public_documents()).await;

    // Act
    fixture.post(&three_documents("execute_all")).await;

    // Assert
    assert_eq!(
        fixture.facts.asked.lock().expect("lock").len(),
        1,
        "one subject, three evaluations, more than one directory read"
    );
}

/// §10.1 binds the whole API to POST, boxcar included.
#[tokio::test]
async fn the_boxcar_is_bound_to_post() {
    // Arrange
    let fixture = Fixture::boxcarring(public_documents()).await;
    let headers = fixture.headers("GET", None);

    // Act
    let response = fixture
        .post_with(&headers, &Method::GET, &three_documents("execute_all"))
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// §10.1.3: the request identifier comes back from this endpoint too.
#[tokio::test]
async fn the_boxcar_echoes_the_request_identifier() {
    // Arrange
    let fixture = Fixture::boxcarring(public_documents()).await;
    let identifier = "bfe9eb29-ab87-4ca3-be83-a1d5d8305716";
    let headers = fixture.headers("POST", Some(identifier));

    // Act
    let response = fixture
        .post_with(&headers, &Method::POST, &three_documents("execute_all"))
        .await;

    // Assert
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(identifier)
    );
}

// ---------------------------------------------------------------------------
// The AuthZEN interop scenario
// ---------------------------------------------------------------------------

/// The five people of the interop "todo" scenario: their subject id, the role
/// they hold and the address their todos are owned by.
const INTEROP_PEOPLE: [(&str, &str, &str); 5] = [
    (
        "CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs",
        "admin",
        "rick@the-citadel.com",
    ),
    (
        "CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs",
        "editor",
        "morty@the-citadel.com",
    ),
    (
        "CiRmZDI2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs",
        "editor",
        "summer@the-smiths.com",
    ),
    (
        "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs",
        "viewer",
        "beth@the-smiths.com",
    ),
    (
        "CiRmZDQ2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs",
        "viewer",
        "jerry@the-smiths.com",
    ),
];

/// The catalogue the scenario is played against.
///
/// The todo application's own policy, as far as this rule language reaches: a
/// viewer reads, an editor creates and changes what they own, an administrator
/// does anything. See the module documentation for the two per-person rules and
/// what they stand in for.
fn interop_catalogue() -> RuleSet {
    let mut rules = vec![
        r#"{"id": "read-users", "effect": "permit", "resource_type": "user",
            "actions": ["can_read_user"],
            "when": {"any": [{"role": {"name": "viewer", "owner": "tenant"}},
                             {"role": {"name": "editor", "owner": "tenant"}},
                             {"role": {"name": "admin", "owner": "tenant"}}]}}"#
            .to_owned(),
        r#"{"id": "read-todos", "effect": "permit", "resource_type": "todo",
            "actions": ["can_read_todos"],
            "when": {"any": [{"role": {"name": "viewer", "owner": "tenant"}},
                             {"role": {"name": "editor", "owner": "tenant"}},
                             {"role": {"name": "admin", "owner": "tenant"}}]}}"#
            .to_owned(),
        r#"{"id": "create-todo", "effect": "permit", "resource_type": "todo",
            "actions": ["can_create_todo"],
            "when": {"any": [{"role": {"name": "editor", "owner": "tenant"}},
                             {"role": {"name": "admin", "owner": "tenant"}}]}}"#
            .to_owned(),
        r#"{"id": "admin-writes", "effect": "permit", "resource_type": "todo",
            "actions": ["can_update_todo", "can_delete_todo"],
            "when": {"role": {"name": "admin", "owner": "tenant"}}}"#
            .to_owned(),
    ];
    for (_, held, owner) in INTEROP_PEOPLE {
        if held != "editor" {
            continue;
        }
        rules.push(format!(
            r#"{{"id": "own-todo-{owner}", "effect": "permit", "resource_type": "todo",
                 "actions": ["can_update_todo", "can_delete_todo"],
                 "when": {{"all": [{{"role": {{"name": "editor", "owner": "tenant"}}}},
                                   {{"group": "owner:{owner}"}},
                                   {{"attribute": {{"of": "resource", "name": "ownerID",
                                                    "equals": "{owner}"}}}}]}}}}"#
        ));
    }
    catalogue(&format!("[{}]", rules.join(", ")))
}

/// One interop case: who, what, on which resource, and what the suite expects.
struct InteropCase {
    subject: &'static str,
    action: &'static str,
    resource_type: &'static str,
    resource_id: &'static str,
    owner: Option<&'static str>,
    expected: bool,
}

/// The 40 evaluation cases of the scenario, in the order the suite lists them.
fn interop_cases() -> Vec<InteropCase> {
    let mut cases = Vec::new();
    for (subject, held, address) in INTEROP_PEOPLE {
        let writes = held == "admin";
        let own_writes = writes || held == "editor";
        cases.push(InteropCase {
            subject,
            action: "can_read_user",
            resource_type: "user",
            resource_id: "beth@the-smiths.com",
            owner: None,
            expected: true,
        });
        cases.push(InteropCase {
            subject,
            action: "can_read_user",
            resource_type: "user",
            resource_id: address,
            owner: None,
            expected: true,
        });
        cases.push(InteropCase {
            subject,
            action: "can_read_todos",
            resource_type: "todo",
            resource_id: "todo-1",
            owner: None,
            expected: true,
        });
        cases.push(InteropCase {
            subject,
            action: "can_create_todo",
            resource_type: "todo",
            resource_id: "todo-1",
            owner: None,
            expected: held != "viewer",
        });
        for action in ["can_update_todo", "can_delete_todo"] {
            // Somebody else's todo: only the administrator may touch it.
            cases.push(InteropCase {
                subject,
                action,
                resource_type: "todo",
                resource_id: "7240d0db-8ff0-41ec-98b2-34a096273b92",
                owner: Some("rick@the-citadel.com"),
                expected: writes,
            });
            // Their own: an editor may, a viewer may not.
            cases.push(InteropCase {
                subject,
                action,
                resource_type: "todo",
                resource_id: "7240d0db-8ff0-41ec-98b2-34a096273b91",
                owner: Some(address),
                expected: own_writes,
            });
        }
    }
    cases
}

/// The AuthZEN interop "todo" scenario, replayed through the endpoint.
///
/// Forty requests, forty expected decisions, one catalogue. See the module
/// documentation for where the cases come from and what the policy stands in
/// for.
#[tokio::test]
async fn the_authzen_interop_todo_scenario_is_reproduced() {
    // Arrange
    let fixture = Fixture::with_policy(interop_catalogue()).await;
    for (subject, held, address) in INTEROP_PEOPLE {
        fixture.facts.holds(
            subject,
            ResolvedSubject {
                groups: [format!("owner:{address}")].into_iter().collect(),
                roles: holding_tenant_role(held),
                ..ResolvedSubject::default()
            },
        );
    }

    // Act / Assert
    for case in interop_cases() {
        let mut resource = json!({"type": case.resource_type, "id": case.resource_id});
        if let Some(owner) = case.owner {
            resource["properties"] = json!({"ownerID": owner});
        }
        let body = json!({
            "subject": {"type": "user", "id": case.subject},
            "action": {"name": case.action},
            "resource": resource,
        });

        let response = fixture.post(&body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let decided = body_of(response).await;
        assert_eq!(
            decided["decision"],
            json!(case.expected),
            "{} on {} {} (owner {:?}) decided {} — the interop suite expects {}",
            case.action,
            case.resource_type,
            case.resource_id,
            case.owner,
            decided["decision"],
            case.expected
        );
    }
}
