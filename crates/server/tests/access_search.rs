//! The AuthZEN Search APIs (Authorization API 1.0 §8, §10.1, `ast-pj0.6`).
//!
//! Every test goes through the real handler with a real signed access token, a
//! real DPoP proof, the real verifier and the real
//! [`asterius_domain::policy::DeclarativeEngine`] — only the rows are faked,
//! exactly as `access_evaluation.rs` does. A search hands a PEP a *list* of
//! this tenant's entities; an endpoint whose credential checks or whose
//! evaluator were stubbed would be one whose tests pass for a caller that
//! should have got nothing.
//!
//! The property that matters most is §8's: the entities returned evaluate to
//! permit. `every_returned_subject_permits_in_a_follow_up_evaluation` asserts
//! it the way a PEP would find out — by sending each result back to §6.1's
//! evaluation endpoint — over seeded data where the answer is known.

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
    ReplayPurpose, Tenant, TenantId, TenantStatus,
};
use asterius_jose::{LocalKeyStore, SigningKey, thumbprint};
use asterius_oidc::authzen::SCOPE_EVALUATE;
use asterius_oidc::authzen_search::{DEFAULT_PAGE, MAX_PAGE, SearchKind};
use asterius_oidc::metadata::Endpoint;
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::{AccessToken, Audience, Confirmation};
use asterius_server::http::access_evaluation::{
    AccessEvaluationContext, PdpTokenStatus, ResolvedSubject, SubjectFacts, evaluate,
};
use asterius_server::http::access_search::{
    AccessSearchContext, DirectorySubject, SubjectDirectory, search,
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
const PEP: &str = "todo-api";

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

/// The registry entry of one search, which is its path and its audience.
fn endpoint(kind: SearchKind) -> Endpoint {
    match kind {
        SearchKind::Subject => Endpoint::SearchSubject,
        SearchKind::Resource => Endpoint::SearchResource,
        SearchKind::Action => Endpoint::SearchAction,
    }
}

fn url(kind: SearchKind) -> String {
    format!("{ISSUER}{}", endpoint(kind).path())
}

// ---------------------------------------------------------------------------
// The fakes
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct FakePolicies {
    rules: Mutex<Option<RuleSet>>,
    unreadable: Mutex<bool>,
}

impl FakePolicies {
    fn holding(rules: RuleSet) -> Self {
        Self {
            rules: Mutex::new(Some(rules)),
            unreadable: Mutex::new(false),
        }
    }

    fn breaks(&self) {
        *self.unreadable.lock().expect("lock") = true;
    }
}

#[async_trait::async_trait]
impl PolicyStore for FakePolicies {
    async fn load(&self, _tenant: &TenantId) -> Result<Option<StoredPolicy>, DomainError> {
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

#[derive(Debug, Default)]
struct FakeFacts {
    people: Mutex<BTreeMap<String, ResolvedSubject>>,
}

impl FakeFacts {
    fn holds(&self, subject: &str, facts: ResolvedSubject) {
        self.people
            .lock()
            .expect("lock")
            .insert(subject.to_owned(), facts);
    }
}

#[async_trait::async_trait]
impl SubjectFacts for FakeFacts {
    async fn resolve(
        &self,
        _tenant: &TenantId,
        _kind: &str,
        id: &str,
    ) -> Result<ResolvedSubject, DomainError> {
        Ok(self
            .people
            .lock()
            .expect("lock")
            .get(id)
            .cloned()
            .unwrap_or_default())
    }
}

/// This tenant's accounts, in one stable order (`ast-pj0.6`).
#[derive(Debug, Default)]
struct FakeDirectory {
    accounts: Mutex<Vec<DirectorySubject>>,
    /// Every `(after, limit)` the endpoint asked for, so a test can prove that
    /// a page is fetched by the page rather than the tenant walked whole.
    asked: Mutex<Vec<(Option<String>, usize)>>,
    unreadable: Mutex<bool>,
}

impl FakeDirectory {
    fn holding(accounts: &[(&str, &[&str])]) -> Self {
        Self {
            accounts: Mutex::new(
                accounts
                    .iter()
                    .map(|(username, ids)| DirectorySubject {
                        cursor: (*username).to_owned(),
                        ids: ids.iter().map(|id| (*id).to_owned()).collect(),
                    })
                    .collect(),
            ),
            asked: Mutex::new(Vec::new()),
            unreadable: Mutex::new(false),
        }
    }

    fn breaks(&self) {
        *self.unreadable.lock().expect("lock") = true;
    }
}

#[async_trait::async_trait]
impl SubjectDirectory for FakeDirectory {
    async fn page(
        &self,
        _tenant: &TenantId,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<DirectorySubject>, DomainError> {
        self.asked
            .lock()
            .expect("lock")
            .push((after.map(str::to_owned), limit));
        if *self.unreadable.lock().expect("lock") {
            return Err(DomainError::Storage("the directory is unreachable".into()));
        }
        Ok(self
            .accounts
            .lock()
            .expect("lock")
            .iter()
            .filter(|account| after.is_none_or(|after| account.cursor.as_str() > after))
            .take(limit)
            .cloned()
            .collect())
    }
}

#[derive(Debug, Default)]
struct FakeTokens;

#[async_trait::async_trait]
impl PdpTokenStatus for FakeTokens {
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

#[derive(Debug, Default)]
struct FakeAudit(Mutex<Vec<AuditEvent>>);

#[async_trait::async_trait]
impl AuditSink for FakeAudit {
    async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
        self.0.lock().expect("lock").push(event);
        Ok(())
    }
}

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
    kind: SearchKind,
    keys: Arc<LocalKeyStore>,
    dpop_key: SigningKey,
    policies: Arc<FakePolicies>,
    facts: FakeFacts,
    directory: FakeDirectory,
    tokens: FakeTokens,
    audit: FakeAudit,
    limiter: FakeLimiter,
    limits: EndpointLimits,
    acr: AcrPolicy,
    token: String,
}

impl Fixture {
    async fn new(kind: SearchKind, rules: RuleSet) -> Self {
        Self::with(kind, rules, &[SCOPE_EVALUATE], &url(kind)).await
    }

    async fn with(kind: SearchKind, rules: RuleSet, scopes: &[&str], audience: &str) -> Self {
        let keys = Arc::new(LocalKeyStore::new());
        keys.generate(&TenantId::new("demo"), SigningAlgorithm::DEFAULT)
            .expect("a tenant key");
        let dpop_key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("a DPoP key");
        let jkt = thumbprint(&dpop_key.public_jwk().expect("a jwk")).expect("a thumbprint");
        let token = sign_token(&keys, &jkt, scopes, audience).await;

        Self {
            kind,
            keys,
            dpop_key,
            policies: Arc::new(FakePolicies::holding(rules)),
            facts: FakeFacts::default(),
            directory: FakeDirectory::default(),
            tokens: FakeTokens,
            audit: FakeAudit::default(),
            limiter: FakeLimiter::default(),
            limits: limits(1_000),
            acr: AcrPolicy::default(),
            token,
        }
    }

    fn holding(mut self, accounts: &[(&str, &[&str])]) -> Self {
        self.directory = FakeDirectory::holding(accounts);
        self
    }

    fn allowing(mut self, requests: u32) -> Self {
        self.limits = limits(requests);
        self
    }

    async fn post(&self, body: &Value) -> Response {
        self.post_with(&self.headers("POST"), &Method::POST, body)
            .await
    }

    async fn post_with(&self, headers: &HeaderMap, method: &Method, body: &Value) -> Response {
        let rendered = serde_json::to_vec(body).expect("a JSON body");
        let tenant = tenant();
        let dpop = DpopEndpoint::new(Arc::new(FakeReplay), None);
        let engine = DeclarativeEngine::new(Arc::clone(&self.policies) as Arc<dyn PolicyStore>);
        let context = AccessSearchContext {
            pdp: self.pdp(&tenant, &engine, &dpop),
            policies: self.policies.as_ref(),
            directory: &self.directory,
        };
        search(self.kind, context, method, headers, &rendered).await
    }

    /// §6.1's endpoint, wired from the same fixture: this is how a PEP checks
    /// what a search told it (§8's "results SHOULD evaluate to permit").
    async fn evaluate(&self, body: &Value) -> Response {
        let tenant = tenant();
        let dpop = DpopEndpoint::new(Arc::new(FakeReplay), None);
        let engine = DeclarativeEngine::new(Arc::clone(&self.policies) as Arc<dyn PolicyStore>);
        let rendered = serde_json::to_vec(body).expect("a JSON body");
        // The follow-up evaluation is audienced at §6.1's endpoint, which is a
        // different resource from this search: a PEP asks its authorization
        // server for both.
        let token = sign_token(
            &self.keys,
            &thumbprint(&self.dpop_key.public_jwk().expect("a jwk")).expect("a thumbprint"),
            &[SCOPE_EVALUATE],
            &format!("{ISSUER}{}", Endpoint::AccessEvaluation.path()),
        )
        .await;
        let mut headers = self.headers("POST");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {token}")).expect("a header value"),
        );
        headers.insert(
            DPOP_HEADER,
            HeaderValue::from_str(&self.proof_for(
                "POST",
                &format!("{ISSUER}{}", Endpoint::AccessEvaluation.path()),
                &token,
            ))
            .expect("a header value"),
        );
        evaluate(
            self.pdp(&tenant, &engine, &dpop),
            &Method::POST,
            &headers,
            &rendered,
        )
        .await
    }

    fn pdp<'a>(
        &'a self,
        tenant: &'a Tenant,
        engine: &'a DeclarativeEngine,
        dpop: &'a DpopEndpoint,
    ) -> AccessEvaluationContext<'a> {
        AccessEvaluationContext {
            tenant,
            engine,
            subjects: &self.facts,
            tokens: &self.tokens,
            keys: self.keys.as_ref(),
            dpop,
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
        }
    }

    fn headers(&self, method: &str) -> HeaderMap {
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
            HeaderValue::from_str(&self.proof_for(method, &url(self.kind), &self.token))
                .expect("a header value"),
        );
        headers
    }

    fn proof_for(&self, method: &str, target: &str, token: &str) -> String {
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
            "htu": target,
            "iat": now().unix_timestamp(),
            "ath": B64.encode(Sha256::digest(token.as_bytes())),
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

/// The catalogue these tests search: readers of accounts are the `finance`
/// group, and nobody else reads anything.
fn finance_reads_accounts() -> RuleSet {
    catalogue(
        r#"[{"id": "finance-reads", "effect": "permit", "subject_type": "user",
             "resource_type": "account", "actions": ["can_read"],
             "when": {"group": "finance"}}]"#,
    )
}

fn in_finance() -> ResolvedSubject {
    ResolvedSubject {
        groups: BTreeSet::from(["finance".to_owned()]),
        roles: HeldRoles::default(),
        grants: Vec::new(),
    }
}

/// §8.4's request: the subject's type, and no id.
fn subject_search() -> Value {
    json!({
        "subject": {"type": "user"},
        "action": {"name": "can_read"},
        "resource": {"type": "account", "id": "123"},
    })
}

fn results(document: &Value) -> Vec<Value> {
    document["results"]
        .as_array()
        .expect("§8.3 makes results REQUIRED")
        .clone()
}

fn next_token(document: &Value) -> String {
    document["page"]["next_token"]
        .as_str()
        .expect("§8.2 makes next_token REQUIRED in a paginated response")
        .to_owned()
}

// ---------------------------------------------------------------------------
// §8.4 — the subject search
// ---------------------------------------------------------------------------

/// The property §8 describes and this build guarantees: every entity a search
/// returns evaluates to permit in the evaluation a PEP would make next.
///
/// Seeded data: three accounts, one of which is in `finance`, and a policy
/// that permits `finance` to read accounts. The assertion is not "alice is in
/// the list" — it is that *whatever* the list holds, each element comes back
/// `decision: true` from §6.1's endpoint, and that everything left out comes
/// back false.
#[tokio::test]
async fn every_returned_subject_permits_in_a_follow_up_evaluation() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts())
        .await
        .holding(&[
            ("alice", &["alice-sub"]),
            ("bob", &["bob-sub"]),
            ("carol", &["carol-sub"]),
        ]);
    fixture.facts.holds("alice-sub", in_finance());

    // Act
    let document = body_of(fixture.post(&subject_search()).await).await;

    // Assert
    let returned: BTreeSet<String> = results(&document)
        .iter()
        .map(|entity| {
            assert_eq!(entity["type"], json!("user"), "a result of another type");
            entity["id"].as_str().expect("an id").to_owned()
        })
        .collect();
    assert_eq!(returned, BTreeSet::from(["alice-sub".to_owned()]));

    for subject in ["alice-sub", "bob-sub", "carol-sub"] {
        let decision = body_of(
            fixture
                .evaluate(&json!({
                    "subject": {"type": "user", "id": subject},
                    "action": {"name": "can_read"},
                    "resource": {"type": "account", "id": "123"},
                }))
                .await,
        )
        .await;
        assert_eq!(
            decision["decision"],
            json!(returned.contains(subject)),
            "{subject} was searched and evaluated differently"
        );
    }
}

/// §8.4: the results are subjects — the type the request asked for, and the
/// identifier a PEP can present back to this PDP.
#[tokio::test]
async fn a_subject_search_returns_only_subjects_of_the_type_it_asked_for() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts())
        .await
        .holding(&[("alice", &["alice-sub"])]);
    fixture.facts.holds("alice-sub", in_finance());

    // Act
    let document = body_of(fixture.post(&subject_search()).await).await;

    // Assert
    assert_eq!(
        results(&document),
        vec![json!({"type": "user", "id": "alice-sub"})]
    );
}

/// An account known under two `sub`s is reachable under both (`ast-2vk.6`):
/// each identifier is a candidate, and each is evaluated.
#[tokio::test]
async fn an_account_is_searchable_under_every_identifier_it_is_known_by() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts())
        .await
        .holding(&[("alice", &["alice-public", "alice-pairwise"])]);
    fixture.facts.holds("alice-public", in_finance());
    fixture.facts.holds("alice-pairwise", in_finance());

    // Act
    let document = body_of(fixture.post(&subject_search()).await).await;

    // Assert
    assert_eq!(results(&document).len(), 2);
}

// ---------------------------------------------------------------------------
// §8.2 — pagination
// ---------------------------------------------------------------------------

/// §8.2: a page carries a token, the next request presents it, and the last
/// page carries the empty string. Nothing is returned twice.
#[tokio::test]
async fn pages_walk_the_directory_without_repeating_or_skipping() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts())
        .await
        .holding(&[
            ("alice", &["alice-sub"]),
            ("bob", &["bob-sub"]),
            ("carol", &["carol-sub"]),
        ]);
    for subject in ["alice-sub", "bob-sub", "carol-sub"] {
        fixture.facts.holds(subject, in_finance());
    }
    let mut request = subject_search();
    request["page"] = json!({"limit": 2});

    // Act
    let first = body_of(fixture.post(&request).await).await;
    let token = next_token(&first);
    let mut second_request = subject_search();
    second_request["page"] = json!({"limit": 2, "token": token});
    let second = body_of(fixture.post(&second_request).await).await;

    // Assert
    assert_eq!(results(&first).len(), 2);
    assert!(!next_token(&first).is_empty(), "a middle page has a token");
    assert_eq!(
        results(&second),
        vec![json!({"type": "user", "id": "carol-sub"})]
    );
    assert_eq!(
        next_token(&second),
        "",
        "§8.2: the last page's next_token is the empty string"
    );
}

/// §8.2: "the parameters of the request MUST be identical" between pages. A
/// PEP that changed one gets a 400 rather than a page of another query.
#[tokio::test]
async fn a_token_presented_against_changed_parameters_is_refused() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts())
        .await
        .holding(&[("alice", &["alice-sub"]), ("bob", &["bob-sub"])]);
    for subject in ["alice-sub", "bob-sub"] {
        fixture.facts.holds(subject, in_finance());
    }
    let mut request = subject_search();
    request["page"] = json!({"limit": 1});
    let token = next_token(&body_of(fixture.post(&request).await).await);

    // Act: the same token, a different action.
    let mut changed = subject_search();
    changed["action"]["name"] = json!("can_write");
    changed["page"] = json!({"limit": 1, "token": token});
    let response = fixture.post(&changed).await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// A token this PDP did not mint is refused rather than read as a first page.
#[tokio::test]
async fn a_forged_token_is_refused() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts()).await;
    let mut request = subject_search();
    request["page"] = json!({"token": "v1.bm90LWEtdG9rZW4"});

    // Act
    let response = fixture.post(&request).await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// The work of one request is bounded before it is done: the directory is
/// asked for one page, never for the tenant.
#[tokio::test]
async fn only_one_page_of_candidates_is_ever_fetched() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts())
        .await
        .holding(&[("alice", &["alice-sub"])]);
    let mut request = subject_search();
    request["page"] = json!({"limit": 10_000});

    // Act
    let _ = fixture.post(&request).await;
    let _ = fixture.post(&subject_search()).await;

    // Assert
    let asked = fixture.directory.asked.lock().expect("lock").clone();
    assert_eq!(
        asked,
        vec![(None, MAX_PAGE + 1), (None, DEFAULT_PAGE + 1)],
        "a search asked for more than one page of candidates"
    );
}

// ---------------------------------------------------------------------------
// §8.5 and §8.6 — resources and actions
// ---------------------------------------------------------------------------

/// §8.5: the resources are the ones this PDP can name — here, the literal a
/// rule names — and each of them permits.
#[tokio::test]
async fn a_resource_search_returns_the_resources_the_rules_name() {
    // Arrange
    // The rule *names* one account — which is what makes it enumerable — and
    // permits the `finance` group to read accounts. A rule that named no
    // resource would permit exactly as much and be searchable not at all,
    // which is the limit `asterius_domain::policy::search` documents.
    let rules = catalogue(
        r#"[{"id": "read-accounts", "effect": "permit", "subject_type": "user",
             "resource_type": "account", "actions": ["can_read"],
             "when": {"any": [
                 {"group": "finance"},
                 {"grant": {"resource": "https://api.example/accounts/1"}}
             ]}}]"#,
    );
    let fixture = Fixture::new(SearchKind::Resource, rules).await;
    fixture.facts.holds("alice-sub", in_finance());
    let request = json!({
        "subject": {"type": "user", "id": "alice-sub"},
        "action": {"name": "can_read"},
        "resource": {"type": "account"},
    });

    // Act
    let document = body_of(fixture.post(&request).await).await;

    // Assert
    assert_eq!(
        results(&document),
        vec![json!({"type": "account", "id": "https://api.example/accounts/1"})]
    );
    assert_eq!(next_token(&document), "");
}

/// §8.6: the actions are the ones the applicable rules name, and only those
/// that evaluate to permit for this subject and this resource.
#[tokio::test]
async fn an_action_search_returns_only_the_actions_that_permit() {
    // Arrange
    let rules = catalogue(
        r#"[
            {"id": "read", "effect": "permit", "subject_type": "user",
             "resource_type": "account", "actions": ["can_read"],
             "when": {"group": "finance"}},
            {"id": "write", "effect": "permit", "subject_type": "user",
             "resource_type": "account", "actions": ["can_write"],
             "when": {"group": "treasury"}}
        ]"#,
    );
    let fixture = Fixture::new(SearchKind::Action, rules).await;
    fixture.facts.holds("alice-sub", in_finance());
    let request = json!({
        "subject": {"type": "user", "id": "alice-sub"},
        "resource": {"type": "account", "id": "123"},
    });

    // Act
    let document = body_of(fixture.post(&request).await).await;

    // Assert
    assert_eq!(results(&document), vec![json!({"name": "can_read"})]);
}

// ---------------------------------------------------------------------------
// The credential, the trail, and failure
// ---------------------------------------------------------------------------

/// §11.2 and RFC 6750 §3.1: the same scope the evaluation endpoint needs, and
/// the same refusal when it is absent.
#[tokio::test]
async fn a_token_without_the_scope_is_refused() {
    // Arrange
    let fixture = Fixture::with(
        SearchKind::Subject,
        finance_reads_accounts(),
        &["openid"],
        &url(SearchKind::Subject),
    )
    .await;

    // Act
    let response = fixture.post(&subject_search()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// RFC 9068 §3: each search is its own resource (§9.1.1), so a token for the
/// evaluation endpoint is not a token for a search.
#[tokio::test]
async fn a_token_audienced_at_the_evaluation_endpoint_is_refused() {
    // Arrange
    let fixture = Fixture::with(
        SearchKind::Subject,
        finance_reads_accounts(),
        &[SCOPE_EVALUATE],
        &format!("{ISSUER}{}", Endpoint::AccessEvaluation.path()),
    )
    .await;

    // Act
    let response = fixture.post(&subject_search()).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// §10.1 binds this API to POST.
#[tokio::test]
async fn a_search_is_bound_to_post() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts()).await;

    // Act
    let response = fixture
        .post_with(&fixture.headers("GET"), &Method::GET, &subject_search())
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// §11.7: the searches and the evaluation share one budget, because they are
/// one authority.
#[tokio::test]
async fn a_search_is_charged_to_the_evaluation_budget() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts())
        .await
        .allowing(1);

    // Act
    let first = fixture.post(&subject_search()).await;
    let second = fixture.post(&subject_search()).await;

    // Assert
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// One `access.searched` per request, carrying the shape of the disclosure and
/// not the entities disclosed (`ast-pj0.6`).
#[tokio::test]
async fn every_search_is_recorded_once() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts())
        .await
        .holding(&[("alice", &["alice-sub"])]);
    fixture.facts.holds("alice-sub", in_finance());

    // Act
    let _ = fixture.post(&subject_search()).await;

    // Assert
    let trail = fixture.trail();
    assert_eq!(trail.len(), 1, "one entry per request");
    let entry = &trail[0];
    assert_eq!(entry.event_type, EventType::ACCESS_SEARCHED);
    assert_eq!(entry.outcome, Outcome::Success);
    let detail: BTreeMap<String, DetailValue> = entry
        .detail
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    assert_eq!(
        detail.get("search"),
        Some(&DetailValue::Text("subject".to_owned()))
    );
    assert_eq!(detail.get("results"), Some(&DetailValue::Number(1)));
    assert_eq!(detail.get("candidates"), Some(&DetailValue::Number(1)));
    assert!(
        detail.keys().all(|key| key != "result_ids"),
        "the trail records the shape of a search, not the entities it returned"
    );
}

/// §10.1.2, fail closed: a search this PDP could not perform answers an empty
/// page with an `error` context, so a PEP can tell an outage from "nobody".
#[tokio::test]
async fn a_search_that_cannot_be_performed_says_so() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Action, finance_reads_accounts()).await;
    fixture.policies.breaks();
    let request = json!({
        "subject": {"type": "user", "id": "alice-sub"},
        "resource": {"type": "account", "id": "123"},
    });

    // Act
    let response = fixture.post(&request).await;
    let status = response.status();
    let document = body_of(response).await;

    // Assert
    assert_eq!(status, StatusCode::OK);
    assert_eq!(results(&document), Vec::<Value>::new());
    assert_eq!(document["context"]["error"]["status"], json!(500));
    assert_eq!(
        fixture.trail()[0].outcome,
        Outcome::Failure,
        "a search that failed is recorded as a failure"
    );
}

/// The same, from the other store: a directory that cannot be walked is not an
/// empty tenant.
#[tokio::test]
async fn a_directory_that_cannot_be_walked_is_not_an_empty_answer() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts())
        .await
        .holding(&[("alice", &["alice-sub"])]);
    fixture.directory.breaks();

    // Act
    let document = body_of(fixture.post(&subject_search()).await).await;

    // Assert
    assert_eq!(document["context"]["error"]["status"], json!(500));
}

/// §8: the id of the entity being searched for is the PDP's to supply.
#[tokio::test]
async fn a_search_that_names_what_it_searches_for_is_refused() {
    // Arrange
    let fixture = Fixture::new(SearchKind::Subject, finance_reads_accounts()).await;
    let mut request = subject_search();
    request["subject"]["id"] = json!("alice-sub");

    // Act
    let response = fixture.post(&request).await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
