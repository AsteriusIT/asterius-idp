//! The interaction endpoints, end to end, with an in-memory store.
//!
//! What is under test is the order the checks run in and what each failure
//! produces — the two-credential rule, the CSRF token, and the fact that a
//! browser mismatch destroys the interaction rather than re-rendering it.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, EventType};
use asterius_domain::rate_limit::{Bucket, RateLimitStore};
use asterius_domain::{
    AuthenticationMethod, ClientId, CodeBinding, CodeIssuer, CredentialVerifier, DomainError,
    Grant, GrantRepository, InteractionRecord, InteractionRepository, Issuer, Lifetimes,
    LoginLimits, Participant, RateLimit, Secret, SectorIdentifier, Session, SessionRepository,
    SessionRevocation, SubjectId, SubjectResolver, Tenant, TenantId, TenantStatus, UserId,
};
use asterius_server::http::interaction::{InteractionContext, show, submit};
use asterius_server::http::throttle::LoginThrottle;
use asterius_web::csp::Nonce;
use asterius_web::interaction::{COOKIE_NAME, InteractionId, StoredState};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};

const ISSUER: &str = "https://as.example/t/demo";

/// One interaction, in memory.
#[derive(Debug, Default)]
struct FakeStore {
    record: Mutex<Option<(String, InteractionRecord)>>,
    destroyed: Mutex<Vec<String>>,
    completed: Mutex<Vec<String>>,
}

impl FakeStore {
    fn with(digest: &str, state: Value) -> Self {
        let store = Self::default();
        *store.record.lock().expect("lock") = Some((
            digest.to_owned(),
            InteractionRecord {
                tenant: TenantId::new("demo"),
                client: ClientId::new("billing"),
                // What `asterius_server::http::par::serialise` writes, which
                // is what the consent screen is built from.
                parameters: serde_json::json!({
                    "redirect_uri": "https://rp.example/cb",
                    "scopes": ["openid", "payments"],
                    "resources": [],
                    // FAPI 2.0 SP §5.3.2.2 item 5 makes PKCE mandatory, so
                    // every stored request has one.
                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    "nonce": "n-0S6_WzA2Mj",
                }),
                state,
                session: None,
                expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(10),
            },
        ));
        store
    }

    /// Puts a signed-in session behind the interaction, which is what the
    /// consent stage is reached with in reality.
    fn signed_in(self, session: &str) -> Self {
        if let Some((_, record)) = self.record.lock().expect("lock").as_mut() {
            record.session = Some(session.to_owned());
        }
        self
    }

    /// Sets the stored `response_mode`, which is what decides whether the
    /// authorization response is a redirect or a rendered form (`ast-gxh.5`).
    fn responding_with(&self, mode: &str) {
        if let Some((_, record)) = self.record.lock().expect("lock").as_mut() {
            record.parameters["response_mode"] = Value::String(mode.to_owned());
        }
    }

    /// Sets the stored `prompt` values, which `http::par` writes as an array.
    fn prompting(&self, prompt: &str) {
        if let Some((_, record)) = self.record.lock().expect("lock").as_mut() {
            record.parameters["prompts"] = serde_json::json!([prompt]);
        }
    }

    /// Replaces the stored `redirect_uri`, for the policy the consent screen is
    /// served under.
    fn redirecting_to(&self, redirect_uri: &str) {
        if let Some((_, record)) = self.record.lock().expect("lock").as_mut() {
            record.parameters["redirect_uri"] = Value::String(redirect_uri.to_owned());
        }
    }

    fn was_completed(&self, digest: &str) -> bool {
        self.completed
            .lock()
            .expect("lock")
            .iter()
            .any(|d| d == digest)
    }

    fn was_destroyed(&self, digest: &str) -> bool {
        self.destroyed
            .lock()
            .expect("lock")
            .iter()
            .any(|d| d == digest)
    }

    fn state(&self) -> Option<Value> {
        self.record
            .lock()
            .expect("lock")
            .as_ref()
            .map(|(_, r)| r.state.clone())
    }
}

#[async_trait::async_trait]
impl InteractionRepository for FakeStore {
    async fn begin_interaction(
        &self,
        _r: &str,
        _i: &str,
        _n: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn by_interaction(
        &self,
        digest: &str,
        _now: OffsetDateTime,
    ) -> Result<Option<InteractionRecord>, DomainError> {
        Ok(self
            .record
            .lock()
            .expect("lock")
            .as_ref()
            .filter(|(d, _)| d == digest)
            .map(|(_, r)| r.clone()))
    }
    async fn save_interaction_state(
        &self,
        digest: &str,
        state: &Value,
        _session: Option<&str>,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let mut held = self.record.lock().expect("lock");
        match held.as_mut() {
            Some((d, record)) if d == digest => {
                record.state = state.clone();
                Ok(())
            }
            _ => Err(DomainError::NotFound),
        }
    }
    async fn complete_interaction(
        &self,
        digest: &str,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let mut spent = self.completed.lock().expect("lock");
        if spent.iter().any(|d| d == digest) {
            // The second submission finds nothing live, exactly as the single
            // `update ... where consumed_at is null` does.
            return Err(DomainError::NotFound);
        }
        let held = self.record.lock().expect("lock");
        if held.as_ref().is_none_or(|(d, _)| d != digest) {
            return Err(DomainError::NotFound);
        }
        spent.push(digest.to_owned());
        Ok(())
    }
    async fn destroy_interaction(&self, digest: &str) -> Result<(), DomainError> {
        self.destroyed.lock().expect("lock").push(digest.to_owned());
        let mut held = self.record.lock().expect("lock");
        if held.as_ref().is_some_and(|(d, _)| d == digest) {
            *held = None;
        }
        Ok(())
    }
}

/// Always succeeds, so the login path can be exercised without a credential
/// store. Never used by a test that is about *failing* to authenticate.
#[derive(Debug)]
struct AlwaysSucceeds;

#[async_trait::async_trait]
impl CredentialVerifier for AlwaysSucceeds {
    async fn verify(
        &self,
        _username: &str,
        _password: Secret<String>,
    ) -> Result<Option<uuid::Uuid>, DomainError> {
        Ok(Some(uuid::Uuid::from_u128(1)))
    }
}

/// Records the sessions a sign-in creates, so a test can see one was made.
#[derive(Debug, Default)]
struct FakeSessions(Mutex<Vec<Session>>);

#[async_trait::async_trait]
impl SessionRepository for FakeSessions {
    async fn begin(&self, session: &Session) -> Result<(), DomainError> {
        self.0.lock().expect("lock").push(session.clone());
        Ok(())
    }
    async fn find(&self, digest: &str) -> Result<Option<Session>, DomainError> {
        Ok(self
            .0
            .lock()
            .expect("lock")
            .iter()
            .find(|s| s.id_digest == digest)
            .cloned())
    }
    async fn touch(
        &self,
        _d: &str,
        _n: OffsetDateTime,
        _i: time::Duration,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn rotate(
        &self,
        _o: &str,
        _n: &str,
        _m: &[AuthenticationMethod],
        _at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn revoke(
        &self,
        _d: &str,
        _r: SessionRevocation,
        _n: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn revoke_all_for_user(
        &self,
        _u: uuid::Uuid,
        _r: SessionRevocation,
        _n: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn record_participant(
        &self,
        _d: &str,
        _c: &ClientId,
        _n: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn participants(&self, _d: &str) -> Result<Vec<Participant>, DomainError> {
        Ok(Vec::new())
    }
}

impl FakeSessions {
    /// A store already holding one live session for `user`.
    fn holding(digest: &str, user: uuid::Uuid, now: OffsetDateTime) -> Self {
        let session = Session {
            tenant: TenantId::new("demo"),
            id_digest: digest.to_owned(),
            public_sid: "sid-for-a-test-session".to_owned(),
            user,
            created_at: now,
            authenticated_at: now,
            last_seen_at: now,
            expires_at: now + time::Duration::hours(8),
            idle_expires_at: now + time::Duration::minutes(30),
            acr: None,
            amr: vec![AuthenticationMethod::Password],
            revoked: None,
        };
        Self(Mutex::new(vec![session]))
    }
}

/// The grants a completed authorization writes.
#[derive(Debug, Default)]
struct FakeGrants(Mutex<Vec<Grant>>);

#[async_trait::async_trait]
impl GrantRepository for FakeGrants {
    async fn create(&self, grant: &Grant) -> Result<(), DomainError> {
        self.0.lock().expect("lock").push(grant.clone());
        Ok(())
    }

    async fn for_subject(
        &self,
        subject: &asterius_domain::SubjectId,
    ) -> Result<Vec<Grant>, DomainError> {
        Ok(self
            .0
            .lock()
            .expect("lock")
            .iter()
            .filter(|grant| grant.subject.as_ref() == Some(subject))
            .cloned()
            .collect())
    }
}

/// The codes it issues, by digest.
#[derive(Debug, Default)]
struct FakeCodes(Mutex<Vec<(String, CodeBinding)>>);

#[async_trait::async_trait]
impl CodeIssuer for FakeCodes {
    async fn issue(
        &self,
        digest: &str,
        binding: &CodeBinding,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.0
            .lock()
            .expect("lock")
            .push((digest.to_owned(), binding.clone()));
        Ok(())
    }
}

/// A deterministic `sub`, so a test can assert which one the grant recorded.
#[derive(Debug)]
struct FakeSubjects;

#[async_trait::async_trait]
impl SubjectResolver for FakeSubjects {
    async fn subject(
        &self,
        user: UserId,
        sector: &SectorIdentifier,
    ) -> Result<SubjectId, DomainError> {
        Ok(SubjectId::new(format!(
            "sub-{}-{}",
            sector.as_str(),
            user.as_uuid()
        )))
    }
}

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::new("demo"),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: "Demo".into(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn cookie_header(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{COOKIE_NAME}={value}").parse().expect("header"),
    );
    headers
}

async fn body_of(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("body");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Everything a completed authorization writes to, held together so a test can
/// look at what was written.
#[derive(Debug, Default)]
struct Issued {
    grants: FakeGrants,
    codes: FakeCodes,
    audit: FakeAudit,
    limiter: FakeLimiter,
}

/// The address every request in this file appears to come from.
fn client() -> IpAddr {
    "198.51.100.7".parse().expect("a literal address")
}

/// Fixed-window counters in memory.
///
/// The real ones are rows in `rate_limits`, for the reason
/// `asterius_domain::rate_limit` gives at length; what a handler test needs is
/// only that the counters move.
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
}

/// The audit trail, in memory.
#[derive(Debug, Default)]
struct FakeAudit(Mutex<Vec<AuditEvent>>);

#[async_trait::async_trait]
impl AuditSink for FakeAudit {
    async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
        self.0.lock().expect("lock").push(event);
        Ok(())
    }
}

impl FakeAudit {
    fn events(&self) -> Vec<AuditEvent> {
        self.0.lock().expect("lock").clone()
    }
}

fn context<'a>(
    tenant: &'a Tenant,
    store: &'a FakeStore,
    nonce: &'a Nonce,
    auth: Option<&'a dyn CredentialVerifier>,
    sessions: &'a FakeSessions,
    issued: &'a Issued,
) -> InteractionContext<'a> {
    context_with(
        tenant,
        store,
        nonce,
        auth,
        sessions,
        issued,
        generous_limits(),
    )
}

/// The same context, with the login limits a test chooses.
fn context_with<'a>(
    tenant: &'a Tenant,
    store: &'a FakeStore,
    nonce: &'a Nonce,
    auth: Option<&'a dyn CredentialVerifier>,
    sessions: &'a FakeSessions,
    issued: &'a Issued,
    limits: LoginLimits,
) -> InteractionContext<'a> {
    InteractionContext {
        tenant,
        requests: store,
        credentials: auth,
        sessions,
        lifetimes: Lifetimes::default(),
        username: Some("ada"),
        clients: &FakeClients,
        grants: &issued.grants,
        memory: asterius_oidc::consent_memory::MemoryPolicy::default(),
        codes: &issued.codes,
        subjects: &FakeSubjects,
        code_lifetime: asterius_oidc::code::DEFAULT_LIFETIME,
        nonce,
        throttle: LoginThrottle::new(&issued.limiter, limits, Some(client())),
        audit: &issued.audit,
    }
}

/// Limits far above anything these tests reach.
///
/// The limiter's own behaviour is asserted in `http::throttle`; what matters
/// here is that a sign-in goes through it, so the numbers are chosen not to
/// interfere. The one test that wants the limit reached lowers them itself.
fn generous_limits() -> LoginLimits {
    LoginLimits {
        per_address: RateLimit {
            max: 1_000,
            window: Duration::minutes(15),
        },
        per_account: RateLimit {
            max: 1_000,
            window: Duration::minutes(15),
        },
    }
}

/// One registered client, enough to describe a request on the consent screen.
#[derive(Debug)]
struct FakeClients;

#[async_trait::async_trait]
impl asterius_domain::ClientRepository for FakeClients {
    async fn find(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<asterius_domain::Client>, DomainError> {
        Ok(Some(asterius_domain::Client {
            tenant: TenantId::new("demo"),
            id: client_id.clone(),
            registration: asterius_domain::ClientRegistration::from_json(
                &serde_json::to_vec(&serde_json::json!({
                    "client_name": "Billing",
                    "redirect_uris": ["https://rp.example/cb"],
                    "grant_types": ["authorization_code"],
                    "scope": "openid payments",
                    "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
                }))
                .expect("serialise"),
                asterius_domain::Capabilities::default(),
            )
            .expect("a valid registration"),
            status: asterius_domain::ClientStatus::Active,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }))
    }
}

// ---- the audit trail ---------------------------------------------------

/// The handler's own sink is what a registered passkey must reach: the point
/// of the field is that a caller does not have to find a trail of its own.
#[tokio::test]
async fn a_registered_passkey_reaches_the_handler_sink() {
    let id = InteractionId::generate();
    let store = FakeStore::with(&id.digest(), serde_json::json!({"stage": "login"}));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();
    let user = UserId::generate();
    let credential = uuid::Uuid::new_v4();

    asterius_server::http::interaction::record_passkey_registered(
        &context(&tenant, &store, &nonce, None, &sessions, &issued),
        &user,
        &credential,
        OffsetDateTime::now_utc(),
    )
    .await;

    let events = issued.audit.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].event_type, EventType::CREDENTIAL_CREATED);
    assert_eq!(events[0].tenant, TenantId::new("demo"));
    assert_eq!(events[0].actor, Actor::User(user.as_uuid().to_string()));
}

// ---- the two-credential rule (FAPI 2.0 SP §6.5) ------------------------

#[tokio::test]
async fn a_matching_path_and_cookie_render_the_login_page() {
    let id = InteractionId::generate();
    let store = FakeStore::with(&id.digest(), serde_json::json!({"stage": "login"}));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();

    let response = show(
        context(&tenant, &store, &nonce, None, &sessions, &issued),
        id.expose(),
        &cookie_header(id.expose()),
        OffsetDateTime::now_utc(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let html = body_of(response).await;
    assert!(
        html.contains("name=\"csrf\""),
        "no synchroniser token: {html}"
    );
    assert!(html.contains("Demo"), "{html}");
}

#[tokio::test]
async fn a_url_without_the_cookie_does_not_render_a_form() {
    let id = InteractionId::generate();
    let store = FakeStore::with(&id.digest(), serde_json::json!({"stage": "login"}));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();

    let response = show(
        context(&tenant, &store, &nonce, None, &sessions, &issued),
        id.expose(),
        &HeaderMap::new(),
        OffsetDateTime::now_utc(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let html = body_of(response).await;
    assert!(
        !html.contains("name=\"csrf\""),
        "a form was rendered anyway"
    );
    // A leaked URL alone is not enough, and the interaction survives — the
    // legitimate browser may still arrive.
    assert!(!store.was_destroyed(&id.digest()));
}

/// The mismatch case: fatal, destroys the interaction, clears the cookie.
#[tokio::test]
async fn a_cookie_for_another_interaction_destroys_this_one() {
    let id = InteractionId::generate();
    let other = InteractionId::generate();
    let store = FakeStore::with(&id.digest(), serde_json::json!({"stage": "login"}));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();

    let response = show(
        context(&tenant, &store, &nonce, None, &sessions, &issued),
        id.expose(),
        &cookie_header(other.expose()),
        OffsetDateTime::now_utc(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        store.was_destroyed(&id.digest()),
        "a browser mismatch left the interaction alive"
    );
    let cleared = response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        cleared.contains("Max-Age=0"),
        "the cookie was not cleared: {cleared}"
    );
    assert!(cleared.contains(COOKIE_NAME), "{cleared}");
}

#[tokio::test]
async fn an_unknown_interaction_is_indistinguishable_from_an_expired_one() {
    let id = InteractionId::generate();
    let store = FakeStore::default();
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();

    let response = show(
        context(&tenant, &store, &nonce, None, &sessions, &issued),
        id.expose(),
        &cookie_header(id.expose()),
        OffsetDateTime::now_utc(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let html = body_of(response).await;
    // Generic, with a correlation id and nothing about which check failed.
    assert!(html.contains("Something went wrong"), "{html}");
    assert!(!html.contains("expired"), "{html}");
    assert!(
        !html.contains("billing"),
        "the client leaked onto the page: {html}"
    );
}

// ---- CSRF ---------------------------------------------------------------

#[tokio::test]
async fn a_submission_without_the_issued_token_is_forbidden() {
    let id = InteractionId::generate();
    let mut state = StoredState::default();
    let _issued = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();
    let auth = AlwaysSucceeds;

    for body in [
        "username=ada&password=hunter2",
        "csrf=&username=ada&password=hunter2",
        "csrf=forged&username=ada&password=hunter2",
    ] {
        let response = submit(
            context(&tenant, &store, &nonce, Some(&auth), &sessions, &issued),
            id.expose(),
            &cookie_header(id.expose()),
            &Bytes::from(body),
            OffsetDateTime::now_utc(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "accepted a submission with body {body:?}"
        );
    }
}

#[tokio::test]
async fn a_submission_with_the_issued_token_is_accepted() {
    let id = InteractionId::generate();
    let mut state = StoredState::default();
    let token = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();
    let auth = AlwaysSucceeds;

    let response = submit(
        context(&tenant, &store, &nonce, Some(&auth), &sessions, &issued),
        id.expose(),
        &cookie_header(id.expose()),
        &Bytes::from(format!(
            "csrf={}&username=ada&password=hunter2",
            token.expose()
        )),
        OffsetDateTime::now_utc(),
    )
    .await;

    // Authenticated, so the interaction moved on and the consent screen is
    // what comes back.
    assert_eq!(response.status(), StatusCode::OK);
    let state = store.state().expect("still present");
    assert_eq!(state["stage"], "consent", "the stage did not advance");

    let html = body_of(response).await;
    assert!(html.contains("would like access"), "{html}");
    assert!(
        html.contains("rp.example"),
        "the consent screen did not name the host: {html}"
    );
}

/// One submission per token.
#[tokio::test]
async fn a_token_cannot_be_submitted_twice() {
    let id = InteractionId::generate();
    let mut state = StoredState::default();
    let token = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();

    let body = Bytes::from(format!("csrf={}&username=ada", token.expose()));

    // First: accepted, and re-rendered with a message because no password.
    let first = submit(
        context(
            &tenant,
            &store,
            &nonce,
            Some(&AlwaysSucceeds),
            &sessions,
            &issued,
        ),
        id.expose(),
        &cookie_header(id.expose()),
        &body,
        OffsetDateTime::now_utc(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    // Second: the same body, now refused.
    let second = submit(
        context(
            &tenant,
            &store,
            &nonce,
            Some(&AlwaysSucceeds),
            &sessions,
            &issued,
        ),
        id.expose(),
        &cookie_header(id.expose()),
        &body,
        OffsetDateTime::now_utc(),
    )
    .await;
    assert_eq!(
        second.status(),
        StatusCode::FORBIDDEN,
        "a captured form body was replayable"
    );
}

/// A deployment with no authenticator says so rather than signing anybody in.
#[tokio::test]
async fn a_server_with_no_authentication_method_refuses_to_sign_anybody_in() {
    let id = InteractionId::generate();
    let mut state = StoredState::default();
    let token = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();

    let response = submit(
        context(&tenant, &store, &nonce, None, &sessions, &issued),
        id.expose(),
        &cookie_header(id.expose()),
        &Bytes::from(format!(
            "csrf={}&username=ada&password=hunter2",
            token.expose()
        )),
        OffsetDateTime::now_utc(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let html = body_of(response).await;
    assert!(html.contains("not available"), "{html}");
    // Still at login: nobody was signed in.
    assert_eq!(store.state().expect("present")["stage"], "login");
}

/// Every rendering carries its own token, and the previous one stops working.
#[tokio::test]
async fn reloading_the_page_issues_a_fresh_token() {
    let id = InteractionId::generate();
    let store = FakeStore::with(&id.digest(), serde_json::json!({"stage": "login"}));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();

    let first = body_of(
        show(
            context(&tenant, &store, &nonce, None, &sessions, &issued),
            id.expose(),
            &cookie_header(id.expose()),
            OffsetDateTime::now_utc(),
        )
        .await,
    )
    .await;
    let second = body_of(
        show(
            context(&tenant, &store, &nonce, None, &sessions, &issued),
            id.expose(),
            &cookie_header(id.expose()),
            OffsetDateTime::now_utc(),
        )
        .await,
    )
    .await;

    let token_of = |html: &str| {
        html.split(r#"name="csrf" value=""#)
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .map(ToOwned::to_owned)
            .expect("a token in the page")
    };
    assert_ne!(
        token_of(&first),
        token_of(&second),
        "two renderings shared a token"
    );
}

/// A successful sign-in creates a session and hands the browser its cookie.
///
/// The cookie is a fresh id the browser has never held: see
/// `asterius_domain::entities::session` on why an id it held *before*
/// authenticating is one an attacker may have planted.
#[tokio::test]
async fn signing_in_creates_a_session_and_sets_its_cookie() {
    let id = InteractionId::generate();
    let mut state = StoredState::default();
    let token = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();
    let auth = AlwaysSucceeds;

    let response = submit(
        context(&tenant, &store, &nonce, Some(&auth), &sessions, &issued),
        id.expose(),
        &cookie_header(id.expose()),
        &Bytes::from(format!(
            "csrf={}&username=ada&password=hunter2",
            token.expose()
        )),
        OffsetDateTime::now_utc(),
    )
    .await;

    // Exactly one session, for the user the verifier returned.
    let created = sessions.0.lock().expect("lock");
    assert_eq!(created.len(), 1, "no session was created");
    assert_eq!(created[0].user, uuid::Uuid::from_u128(1));
    assert_eq!(created[0].amr, vec![AuthenticationMethod::Password]);

    // The cookie carries every attribute, and the *id*, not the digest.
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("__Host-asterius_session="))
        .expect("no session cookie");
    for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(cookie.contains(attribute), "missing {attribute}: {cookie}");
    }
    assert!(
        !cookie.contains(&created[0].id_digest),
        "the digest was sent to the browser instead of the id"
    );
}

// ---- login abuse protection (ast-2vk.9) ---------------------------------

/// Never authenticates anybody, so the failure path can be exercised.
#[derive(Debug)]
struct AlwaysRefuses;

#[async_trait::async_trait]
impl CredentialVerifier for AlwaysRefuses {
    async fn verify(
        &self,
        _username: &str,
        _password: Secret<String>,
    ) -> Result<Option<uuid::Uuid>, DomainError> {
        Ok(None)
    }
}

/// Two failures per window, per address and per identifier.
fn tight_limits() -> LoginLimits {
    LoginLimits {
        per_address: RateLimit {
            max: 2,
            window: Duration::minutes(15),
        },
        per_account: RateLimit {
            max: 2,
            window: Duration::minutes(15),
        },
    }
}

/// Submits `count` wrong passwords for `username`, returning the last
/// response and its body.
async fn guess(
    username: &str,
    count: usize,
    issued: &Issued,
    now: OffsetDateTime,
) -> (StatusCode, String) {
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let auth = AlwaysRefuses;
    let mut last = None;
    for _ in 0..count {
        let id = InteractionId::generate();
        let mut state = StoredState::default();
        let token = state.issue_csrf();
        let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
        let response = submit(
            context_with(
                &tenant,
                &store,
                &nonce,
                Some(&auth),
                &sessions,
                issued,
                tight_limits(),
            ),
            id.expose(),
            &cookie_header(id.expose()),
            &Bytes::from(format!(
                "csrf={}&username={username}&password=wrong",
                token.expose()
            )),
            now,
        )
        .await;
        last = Some((response.status(), body_of(response).await));
    }
    last.expect("at least one attempt")
}

/// The criterion: past the limit the same page comes back, with a generic
/// message and a hint about when to return.
#[tokio::test]
async fn too_many_failures_answer_the_login_page_with_a_retry_hint() {
    let issued = Issued::default();
    let now = OffsetDateTime::now_utc();

    let (status, body) = guess("ada", 3, &issued, now).await;

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("Try again in"), "no retry hint: {body}");
    assert!(
        body.contains(r#"name="password""#),
        "the login form did not come back: {body}"
    );
}

/// The refusal is not just a page: a client that reads headers is told the
/// same thing.
#[tokio::test]
async fn a_throttled_sign_in_carries_a_retry_after_header() {
    let id = InteractionId::generate();
    let mut state = StoredState::default();
    let token = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();
    let auth = AlwaysRefuses;
    let now = OffsetDateTime::now_utc();
    guess("ada", 2, &issued, now).await;

    let response = submit(
        context_with(
            &tenant,
            &store,
            &nonce,
            Some(&auth),
            &sessions,
            &issued,
            tight_limits(),
        ),
        id.expose(),
        &cookie_header(id.expose()),
        &Bytes::from(format!(
            "csrf={}&username=ada&password=wrong",
            token.expose()
        )),
        now,
    )
    .await;

    let hint = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .expect("no Retry-After");
    assert!(hint >= 1, "the hint was not a positive number of seconds");
}

/// The trap this ticket exists to avoid: a per-account limit that only bites
/// for accounts that exist is an enumeration oracle. Here the two identifiers
/// differ only in whether the verifier would ever have said yes, and the
/// answers are byte-identical.
#[tokio::test]
async fn a_locked_identifier_and_an_unknown_one_answer_the_same_thing() {
    let now = OffsetDateTime::now_utc();
    let real = Issued::default();
    let invented = Issued::default();

    let (real_status, real_body) = guess("ada", 3, &real, now).await;
    let (invented_status, invented_body) = guess("nobody@example.test", 3, &invented, now).await;

    assert_eq!(real_status, invented_status);
    // What the person is told. The rest of the page differs only in the
    // per-render values — the interaction id, the CSP nonce, the synchroniser
    // token — none of which is derived from what was typed.
    let said = |html: &str| {
        html.split(r#"<p class="error">"#)
            .nth(1)
            .and_then(|rest| rest.split("</p>").next())
            .map(ToOwned::to_owned)
            .expect("a message on the page")
    };
    assert_eq!(said(&real_body), said(&invented_body));
    assert!(said(&real_body).contains("Try again in"));
}

/// A refusal that never reached the credential is still a refusal somebody
/// should be able to see afterwards.
#[tokio::test]
async fn a_throttled_sign_in_is_written_to_the_audit_trail() {
    let issued = Issued::default();
    let now = OffsetDateTime::now_utc();

    guess("ada", 3, &issued, now).await;

    let types: Vec<_> = issued
        .audit
        .events()
        .into_iter()
        .map(|event| event.event_type)
        .collect();
    assert!(
        types.contains(&EventType::AUTH_THROTTLED),
        "no throttle record: {types:?}"
    );
    assert!(
        types.contains(&EventType::AUTH_FAILED),
        "no failure record: {types:?}"
    );
}

/// A limit that never lifted would be a denial of service anybody could aim at
/// anybody.
#[tokio::test]
async fn the_limit_lifts_once_the_window_has_passed() {
    let issued = Issued::default();
    let now = OffsetDateTime::now_utc();
    guess("ada", 3, &issued, now).await;

    let (status, _) = guess("ada", 1, &issued, now + Duration::minutes(16)).await;

    assert_eq!(status, StatusCode::OK);
}

// ---- the consent decision (ast-uwv.1) -----------------------------------

/// The account behind every consent test.
const USER: u128 = 0x7a;

/// An interaction at the consent stage, signed in, with a token issued.
struct Consenting {
    id: InteractionId,
    store: FakeStore,
    csrf: String,
    sessions: FakeSessions,
}

fn at_consent() -> Consenting {
    let id = InteractionId::generate();
    let mut state = StoredState {
        stage: asterius_web::interaction::Stage::Consent,
        csrf_digest: None,
        decision: None,
    };
    let token = state.issue_csrf();
    let session = "0".repeat(64);
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"))
        .signed_in(&session);
    Consenting {
        id,
        store,
        csrf: token.expose().to_owned(),
        sessions: FakeSessions::holding(
            &session,
            uuid::Uuid::from_u128(USER),
            OffsetDateTime::now_utc(),
        ),
    }
}

async fn submit_decision(at: &Consenting, issued: &Issued, body: &str) -> axum::response::Response {
    let tenant = tenant();
    let nonce = Nonce::generate();
    submit(
        context(&tenant, &at.store, &nonce, None, &at.sessions, issued),
        at.id.expose(),
        &cookie_header(at.id.expose()),
        &Bytes::from(body.to_owned()),
        OffsetDateTime::now_utc(),
    )
    .await
}

/// The `Location` a response redirected to, parsed.
fn location_of(response: &axum::response::Response) -> url::Url {
    let raw = response
        .headers()
        .get(header::LOCATION)
        .expect("a redirect carries a Location")
        .to_str()
        .expect("a header value");
    url::Url::parse(raw).expect("a URL")
}

/// One query parameter, or `None` if it is absent.
fn parameter(url: &url::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

// ---- consent memory (ast-uwv.3) -----------------------------------------

/// The `sub` this client sees for the account behind the consent tests.
async fn subject_of_billing() -> SubjectId {
    let client = asterius_domain::ClientRepository::find(&FakeClients, &ClientId::new("billing"))
        .await
        .expect("a store")
        .expect("a client");
    let sector = SectorIdentifier::of_client(&client).expect("a sector");
    FakeSubjects
        .subject(UserId::new(uuid::Uuid::from_u128(USER)), &sector)
        .await
        .expect("a subject")
}

/// A grant this user already holds for this client, covering `scopes`.
async fn already_granted(scopes: &[&str]) -> Grant {
    let mut grant = Grant::new(
        TenantId::new("demo"),
        ClientId::new("billing"),
        OffsetDateTime::now_utc() - Duration::days(1),
    );
    grant.subject = Some(subject_of_billing().await);
    grant.scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
    grant
}

/// Renders the current stage, which is where a remembered consent is taken.
async fn render_stage(at: &Consenting, issued: &Issued) -> axum::response::Response {
    let tenant = tenant();
    let nonce = Nonce::generate();
    show(
        context(&tenant, &at.store, &nonce, None, &at.sessions, issued),
        at.id.expose(),
        &cookie_header(at.id.expose()),
        OffsetDateTime::now_utc(),
    )
    .await
}

/// The acceptance criterion: a previously granted superset means no screen.
#[tokio::test]
async fn a_previously_granted_superset_skips_the_consent_screen() {
    // Arrange: everything this request asks for has been granted before.
    let at = at_consent();
    let issued = Issued::default();
    let earlier = already_granted(&["openid", "payments"]).await;
    issued.grants.0.lock().expect("lock").push(earlier);

    // Act: the browser arrives at the consent stage.
    let response = render_stage(&at, &issued).await;

    // Assert: it is sent straight back to the client with a code, and the
    // interaction is spent — no page was drawn.
    assert!(response.status().is_redirection(), "{}", response.status());
    assert!(parameter(&location_of(&response), "code").is_some());
    assert!(at.store.was_completed(&at.id.digest()));
}

/// The widening rule, where a user would actually notice it: a consent for
/// `openid` is not a consent for `payments`.
#[tokio::test]
async fn a_narrower_earlier_consent_still_shows_the_screen() {
    // Arrange: only one of the two requested scopes was ever granted.
    let at = at_consent();
    let issued = Issued::default();
    let earlier = already_granted(&["openid"]).await;
    issued.grants.0.lock().expect("lock").push(earlier);

    // Act.
    let response = render_stage(&at, &issued).await;

    // Assert: the screen, not a code.
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!at.store.was_completed(&at.id.digest()));
}

/// OIDC Core §3.1.2.1: `prompt=consent` asks for the user to be prompted, and
/// a memory is not an answer to that.
#[tokio::test]
async fn prompt_consent_shows_the_screen_whatever_is_remembered() {
    // Arrange: the memory covers the request in full, and the client insists.
    let at = at_consent();
    at.store.prompting("consent");
    let issued = Issued::default();
    let earlier = already_granted(&["openid", "payments"]).await;
    issued.grants.0.lock().expect("lock").push(earlier);

    // Act.
    let response = render_stage(&at, &issued).await;

    // Assert.
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!at.store.was_completed(&at.id.digest()));
}

/// A remembered consent produces the same grant a submitted one would: the
/// scopes asked for, and no more.
#[tokio::test]
async fn a_skipped_screen_still_records_a_grant_saying_what_was_granted() {
    // Arrange: an earlier grant covering more than this request asks for.
    let at = at_consent();
    let issued = Issued::default();
    let earlier = already_granted(&["openid", "payments", "profile"]).await;
    issued.grants.0.lock().expect("lock").push(earlier);

    // Act.
    let _ = render_stage(&at, &issued).await;

    // Assert: the new grant covers this request, not the earlier one.
    let grants = issued.grants.0.lock().expect("lock");
    let minted = grants.last().expect("a grant was written");
    assert_eq!(
        minted.scopes,
        ["openid".to_owned(), "payments".to_owned()].into(),
        "a remembered consent widened the grant it produced"
    );
}

#[tokio::test]
async fn approving_records_the_scopes_that_were_granted() {
    let at = at_consent();
    let issued = Issued::default();

    let response = submit_decision(
        &at,
        &issued,
        &format!(
            "csrf={}&decision=allow&scope=openid&scope=payments",
            at.csrf
        ),
    )
    .await;

    assert_eq!(response.status().as_u16(), 303);
    let state = at.store.state().expect("present");
    assert_eq!(state["stage"], "response");
    assert_eq!(state["decision"]["outcome"], "approved");
    assert_eq!(
        state["decision"]["scopes"],
        serde_json::json!(["openid", "payments"])
    );

    let grants = issued.grants.0.lock().expect("lock");
    let grant = grants.first().expect("a grant was recorded");
    assert_eq!(
        grant.scopes,
        ["openid", "payments"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    );
    assert_eq!(grant.user, Some(UserId::new(uuid::Uuid::from_u128(USER))));
    assert!(grant.subject.is_some(), "the grant has no sub");
    // Grant Management ID1 §5.6: nothing has been claimed from it yet.
    assert!(grant.claimed_at.is_none());
}

/// The user may grant less than was asked, and the grant records what they
/// actually agreed to.
#[tokio::test]
async fn a_narrowed_approval_records_only_what_was_ticked() {
    let at = at_consent();
    let issued = Issued::default();

    let response = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;

    assert_eq!(response.status().as_u16(), 303);
    let state = at.store.state().expect("present");
    assert_eq!(
        state["decision"]["scopes"],
        serde_json::json!(["openid"]),
        "the decision recorded a scope the user unticked"
    );
    let grants = issued.grants.0.lock().expect("lock");
    assert_eq!(
        grants.first().expect("a grant").scopes,
        std::iter::once("openid".to_owned()).collect(),
        "the grant was written for more than the user allowed"
    );
}

/// Deny is a decision, not an error. It takes the same path as an approval.
#[tokio::test]
async fn denying_is_recorded_as_a_decision() {
    let at = at_consent();
    let issued = Issued::default();

    let response = submit_decision(&at, &issued, &format!("csrf={}&decision=deny", at.csrf)).await;

    assert_eq!(response.status().as_u16(), 303);
    let state = at.store.state().expect("present");
    assert_eq!(state["stage"], "response", "a denial did not advance");
    assert_eq!(state["decision"]["outcome"], "denied");
}

/// `openid` cannot be declined: dropping it would change what the client
/// receives without telling it.
#[tokio::test]
async fn an_approval_that_drops_a_required_scope_is_refused() {
    let at = at_consent();
    let issued = Issued::default();

    let response = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=payments", at.csrf),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let state = at.store.state().expect("present");
    assert_eq!(state["stage"], "consent", "the stage advanced anyway");
    assert!(state.get("decision").is_none_or(serde_json::Value::is_null));
}

/// A form field is a claim by the browser; what this server displayed is the
/// authority.
#[tokio::test]
async fn a_scope_that_was_never_offered_cannot_be_granted() {
    let at = at_consent();
    let issued = Issued::default();

    let response = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid&scope=admin", at.csrf),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(at.store.state().expect("present")["stage"], "consent");
}

#[tokio::test]
async fn a_submission_with_neither_button_is_refused() {
    let at = at_consent();
    let issued = Issued::default();
    let response = submit_decision(&at, &issued, &format!("csrf={}&scope=openid", at.csrf)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(at.store.state().expect("present")["stage"], "consent");
}

/// A decision needs the token like everything else.
#[tokio::test]
async fn a_decision_without_the_issued_token_is_forbidden() {
    let at = at_consent();
    let issued = Issued::default();
    let response = submit_decision(&at, &issued, "decision=allow&scope=openid").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(at.store.state().expect("present")["stage"], "consent");
}

// ---- the authorization response (ast-gxh.4) -----------------------------

/// FAPI 2.0 SP §5.3.2.2 items 10–11: 303, and to the registered URI.
#[tokio::test]
async fn an_approval_redirects_to_the_client_with_a_code() {
    let at = at_consent();
    let issued = Issued::default();

    let response = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;

    assert_eq!(response.status().as_u16(), 303);
    let location = location_of(&response);
    assert_eq!(location.host_str(), Some("rp.example"));
    assert_eq!(location.path(), "/cb");

    let code = parameter(&location, "code").expect("no code in the redirect");
    // The code goes to the browser; only its digest is stored.
    let stored = issued.codes.0.lock().expect("lock");
    let (digest, binding) = stored.first().expect("a code was stored");
    assert_ne!(digest, &code, "the code itself was stored");
    assert_eq!(
        digest,
        &asterius_oidc::code::digest_of(&code).expect("ours"),
        "the stored digest is not this code's"
    );
    assert_eq!(binding.redirect_uri, "https://rp.example/cb");
    assert_eq!(binding.client_id, "billing");
}

/// The URL carries a credential, so nothing may keep it.
#[tokio::test]
async fn the_redirect_is_not_cacheable_and_takes_the_cookie_with_it() {
    let at = at_consent();
    let issued = Issued::default();

    let response = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;

    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let cleared = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.starts_with(COOKIE_NAME) && v.contains("Max-Age=0"));
    assert!(cleared, "the interaction cookie outlived the interaction");
}

/// RFC 9207 §2. Both variants, because the mix-up attack works with an error
/// response too.
#[tokio::test]
async fn every_authorization_response_names_the_issuer() {
    for (body, expected) in [
        ("decision=allow&scope=openid", None),
        ("decision=deny", Some("access_denied")),
    ] {
        let at = at_consent();
        let issued = Issued::default();
        let response = submit_decision(&at, &issued, &format!("csrf={}&{body}", at.csrf)).await;

        assert_eq!(response.status().as_u16(), 303, "{body}");
        let location = location_of(&response);
        assert_eq!(
            parameter(&location, "iss").as_deref(),
            Some(ISSUER),
            "no iss on {body}"
        );
        assert_eq!(parameter(&location, "error").as_deref(), expected, "{body}");
    }
}

/// RFC 6749 §4.1.2.1: a refusal goes back through the same validated redirect
/// URI, and carries no code.
#[tokio::test]
async fn a_denial_redirects_with_access_denied_and_no_code() {
    let at = at_consent();
    let issued = Issued::default();

    let response = submit_decision(&at, &issued, &format!("csrf={}&decision=deny", at.csrf)).await;

    let location = location_of(&response);
    assert_eq!(location.host_str(), Some("rp.example"));
    assert_eq!(
        parameter(&location, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(parameter(&location, "code"), None);
    assert!(
        issued.codes.0.lock().expect("lock").is_empty(),
        "a refusal minted a code"
    );
    assert!(
        issued.grants.0.lock().expect("lock").is_empty(),
        "a refusal recorded a grant"
    );
}

/// FAPI 2.0 SP §5.3.2.1 item 11.
#[tokio::test]
async fn a_code_expires_within_sixty_seconds() {
    let at = at_consent();
    let issued = Issued::default();
    let before = OffsetDateTime::now_utc();

    submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;

    let after = OffsetDateTime::now_utc();
    let stored = issued.codes.0.lock().expect("lock");
    let (_, binding) = stored.first().expect("a code");
    assert!(
        binding.expires_at <= after + time::Duration::seconds(60),
        "a code outlived the cap: {}",
        binding.expires_at
    );
    assert!(
        binding.expires_at > before,
        "a code expired as it was issued"
    );
}

/// FAPI 2.0 SP §5.3.2.2 Note 3: one-time use at *completion*. Two tabs both
/// submitting must produce one authorization response.
#[tokio::test]
async fn a_second_submission_produces_no_second_response() {
    let at = at_consent();
    let issued = Issued::default();

    let first = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;
    assert_eq!(first.status().as_u16(), 303);
    assert!(at.store.was_completed(&at.id.digest()));

    // The token is spent too, so this is refused before the stage is even
    // consulted — but the request being spent is what would stop a submission
    // that arrived with a valid token from a concurrent rendering.
    let second = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;
    assert_ne!(second.status().as_u16(), 303, "a second response was sent");
    assert!(second.headers().get(header::LOCATION).is_none());
    assert_eq!(
        issued.codes.0.lock().expect("lock").len(),
        1,
        "two codes were minted for one authorization"
    );
}

/// The session is what says who this authorization is about. Without a usable
/// one there is nobody to bind a grant to, and the client is told the request
/// was denied rather than handed a code for a user who is not there.
#[tokio::test]
async fn an_authorization_whose_session_ended_mints_nothing() {
    let mut at = at_consent();
    at.sessions = FakeSessions::default();
    let issued = Issued::default();

    let response = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;

    let location = location_of(&response);
    assert_eq!(
        parameter(&location, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(parameter(&location, "code"), None);
    assert!(issued.codes.0.lock().expect("lock").is_empty());
}

// ---- form-action on the consent screen (ast-jsq) -------------------------

/// The `Content-Security-Policy` a rendered page will be served under.
///
/// The header itself is written by `asterius_web::document::layer`, which these
/// tests call the handlers underneath; what the handler decides is the
/// [`Policy`] it attaches, so that is what is read back and rendered here.
fn policy_of(response: &axum::response::Response) -> String {
    response
        .extensions()
        .get::<asterius_web::Policy>()
        .expect("a document carries its policy")
        .header_value(&Nonce::generate())
}

/// Renders the current stage of an interaction, the way a browser `GET` does.
async fn show_page(at: &Consenting, issued: &Issued) -> axum::response::Response {
    let tenant = tenant();
    let nonce = Nonce::generate();
    show(
        context(&tenant, &at.store, &nonce, None, &at.sessions, issued),
        at.id.expose(),
        &cookie_header(at.id.expose()),
        OffsetDateTime::now_utc(),
    )
    .await
}

/// A browser applies `form-action` to the redirects of a submission, so the
/// consent screen has to name the origin the authorization code is delivered
/// to or the flow cannot finish in a real browser.
#[tokio::test]
async fn the_consent_screen_lets_its_form_reach_the_client_origin() {
    let at = at_consent();
    let issued = Issued::default();

    let response = show_page(&at, &issued).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        policy_of(&response).contains("form-action 'self' https://rp.example;"),
        "the consent policy does not name the client origin: {}",
        policy_of(&response)
    );
}

/// One origin, from the `redirect_uri` this authorization was validated
/// against — not the client's registered set, and not the raw request.
#[tokio::test]
async fn the_consent_screen_names_only_this_authorization_s_origin() {
    let at = at_consent();
    at.store.redirecting_to("https://other.example:8443/cb");
    let issued = Issued::default();

    let policy = policy_of(&show_page(&at, &issued).await);

    assert!(
        policy.contains("form-action 'self' https://other.example:8443;"),
        "{policy}"
    );
    assert!(
        !policy.contains("rp.example"),
        "a second origin leaked: {policy}"
    );
}

/// The login page submits to this server and nowhere else. If the widening
/// ever attaches itself to a stage that does not need it, this fails.
#[tokio::test]
async fn no_other_page_inherits_the_widened_form_action() {
    let id = InteractionId::generate();
    let store = FakeStore::with(&id.digest(), serde_json::json!({"stage": "login"}));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();

    let response = show(
        context(&tenant, &store, &nonce, None, &sessions, &issued),
        id.expose(),
        &cookie_header(id.expose()),
        OffsetDateTime::now_utc(),
    )
    .await;

    let policy = policy_of(&response);
    assert!(policy.contains("form-action 'self';"), "{policy}");
    assert!(
        !policy.contains("rp.example"),
        "the login page inherited a client origin: {policy}"
    );
}

/// A callback a CSP `host-source` cannot express — a native client's private
/// scheme — widens nothing: that navigation leaves the browser instead of
/// happening inside it.
#[tokio::test]
async fn a_private_scheme_callback_widens_nothing() {
    let at = at_consent();
    at.store.redirecting_to("com.example.app:/cb");
    let issued = Issued::default();

    let policy = policy_of(&show_page(&at, &issued).await);

    assert!(policy.contains("form-action 'self';"), "{policy}");
}

// ---- response_mode=form_post (ast-gxh.5) ---------------------------------

/// The body of a response, with the form-post page's own assertions applied.
async fn form_post_page(response: axum::response::Response) -> String {
    assert_eq!(response.status(), StatusCode::OK, "not a rendered page");
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("text/html; charset=utf-8")
    );
    assert!(
        response.headers().get(header::LOCATION).is_none(),
        "a form_post response redirected as well"
    );
    body_of(response).await
}

/// The first acceptance criterion of `ast-gxh.5`, at the endpoint that
/// produces the response.
#[tokio::test]
async fn an_approval_in_form_post_mode_renders_a_form_to_the_client() {
    // --- Arrange ---
    let at = at_consent();
    at.store.responding_with("form_post");
    let issued = Issued::default();

    // --- Act ---
    let response = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;
    let html = form_post_page(response).await;

    // --- Assert ---
    assert!(html.contains(r#"method="post""#), "{html}");
    assert!(
        html.contains(r#"action="https://rp.example/cb""#),
        "the action is not the registered redirect_uri: {html}"
    );
    let code = issued
        .codes
        .0
        .lock()
        .expect("lock")
        .first()
        .map(|(digest, _)| digest.clone())
        .expect("a code was minted");
    assert!(
        html.contains(r#"<input type="hidden" name="code" value=""#),
        "the page carries no code: {html}"
    );
    assert!(!code.is_empty());
    assert!(
        html.contains(&format!(
            r#"<input type="hidden" name="iss" value="{ISSUER}">"#
        )),
        "RFC 9207: no iss on the form: {html}"
    );
    // The button a browser without script presses, and the one line that
    // presses it for every other browser.
    assert!(html.contains(r#"<button type="submit">"#), "{html}");
    assert_eq!(html.matches("<script").count(), 1, "{html}");
}

/// The third acceptance criterion, which is the easy one to forget: a client
/// that asked to be answered by POST is answered by POST when the answer is a
/// refusal.
#[tokio::test]
async fn a_denial_in_form_post_mode_is_also_a_form() {
    let at = at_consent();
    at.store.responding_with("form_post");
    let issued = Issued::default();

    let response = submit_decision(&at, &issued, &format!("csrf={}&decision=deny", at.csrf)).await;
    let html = form_post_page(response).await;

    assert!(
        html.contains(r#"<input type="hidden" name="error" value="access_denied">"#),
        "{html}"
    );
    assert!(!html.contains(r#"name="code""#), "a refusal carried a code");
}

/// The fourth: the policy this page is served under names the client's origin
/// and nothing else, so the browser is allowed to make exactly this
/// submission.
#[tokio::test]
async fn the_form_post_page_widens_form_action_by_the_client_origin_alone() {
    let at = at_consent();
    at.store.responding_with("form_post");
    let issued = Issued::default();

    let response = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;

    let policy = response
        .extensions()
        .get::<asterius_web::Policy>()
        .expect("the page carries no policy")
        .header_value(&Nonce::generate());
    assert!(
        policy.contains("form-action 'self' https://rp.example;"),
        "{policy}"
    );
    assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
}

/// A stored request that named no mode is what every request was before this
/// existed, and it still redirects.
#[tokio::test]
async fn a_request_with_no_stored_mode_still_redirects() {
    let at = at_consent();
    let issued = Issued::default();

    let response = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;

    assert_eq!(response.status().as_u16(), 303);
    assert_eq!(location_of(&response).host_str(), Some("rp.example"));
}

/// The interaction is spent by either delivery, so the cookie goes with both.
#[tokio::test]
async fn a_form_post_response_ends_the_interaction_and_clears_its_cookie() {
    let at = at_consent();
    at.store.responding_with("form_post");
    let issued = Issued::default();

    let response = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;

    assert!(at.store.was_completed(&at.id.digest()));
    let cleared = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.starts_with(COOKIE_NAME) && v.contains("Max-Age=0"));
    assert!(cleared, "the interaction cookie outlived the interaction");
}
