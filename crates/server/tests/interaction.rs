//! The interaction endpoints, end to end, with an in-memory store.
//!
//! What is under test is the order the checks run in and what each failure
//! produces — the two-credential rule, the CSRF token, and the fact that a
//! browser mismatch destroys the interaction rather than re-rendering it.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, EventType};
use asterius_domain::rate_limit::{Bucket, RateLimitStore};
use asterius_domain::{
    AuthenticationMethod, ClientId, CodeBinding, CodeIssuer, Continuation, CredentialVerifier,
    DomainError, FirstPartyDestination, Grant, GrantRepository, InteractionRecord,
    InteractionRepository, Issuer, Lifetimes, LoginLimits, Participant, RateLimit, Secret,
    SectorIdentifier, Session, SessionRepository, SessionRevocation, SubjectId, SubjectResolver,
    Tenant, TenantId, TenantStatus, UserId,
};
use asterius_server::http::interaction::{InteractionContext, show, submit};
use asterius_server::http::throttle::LoginThrottle;
use asterius_server::tenancy::MountPrefix;
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

/// The only redirect status this server emits, spelled as a number.
///
/// Not `StatusCode::SEE_OTHER`: `http::source_audit` confines that constant to
/// `http::redirect`, so that a redirect is always *built* by the helper. A test
/// asserting what came back is not building one, and the number says the same
/// thing.
const SEE_OTHER: u16 = 303;

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
                continuation: Continuation::for_client(
                    ClientId::new("billing"),
                    // What `asterius_server::http::par::serialise` writes,
                    // which is what the consent screen is built from.
                    serde_json::json!({
                    "redirect_uri": "https://rp.example/cb",
                    "scopes": ["openid", "payments"],
                    "resources": [],
                    // FAPI 2.0 SP §5.3.2.2 item 5 makes PKCE mandatory, so
                    // every stored request has one.
                    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        "nonce": "n-0S6_WzA2Mj",
                    }),
                ),
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

    /// Edits the stored authorization parameters in place.
    ///
    /// The fake is built with a client continuation, so the parameters are
    /// there; a first-party interaction has none, which is what
    /// [`FakeStore::first_party`] is for.
    fn with_parameters(&self, edit: impl FnOnce(&mut Value)) {
        if let Some((_, record)) = self.record.lock().expect("lock").as_mut() {
            match &mut record.continuation {
                Continuation::Client(request) => edit(&mut request.parameters),
                Continuation::FirstParty(_) => panic!("this interaction has no parameters"),
            }
        }
    }

    /// Replaces the continuation with a first-party one: no client, no
    /// redirect URI, no scopes (ADR-0009).
    fn first_party(self) -> Self {
        if let Some((_, record)) = self.record.lock().expect("lock").as_mut() {
            record.continuation = Continuation::FirstParty(FirstPartyDestination::AdminConsole);
        }
        self
    }

    /// Sets the stored `response_mode`, which is what decides whether the
    /// authorization response is a redirect or a rendered form (`ast-gxh.5`).
    fn responding_with(&self, mode: &str) {
        self.with_parameters(|parameters| {
            parameters["response_mode"] = Value::String(mode.to_owned());
        });
    }

    /// Sets the stored `prompt` values, which `http::par` writes as an array.
    fn prompting(&self, prompt: &str) {
        self.with_parameters(|parameters| {
            parameters["prompts"] = serde_json::json!([prompt]);
        });
    }

    /// Pins the stored request to a DPoP key, as `http::par::serialise` does
    /// for a push that named one (RFC 9449 §10.1).
    fn pinned_to(&self, thumbprint: &str) {
        self.with_parameters(|parameters| {
            parameters["dpop_jkt"] = Value::String(thumbprint.to_owned());
        });
    }

    /// Replaces the stored `redirect_uri`, for the policy the consent screen is
    /// served under.
    fn redirecting_to(&self, redirect_uri: &str) {
        self.with_parameters(|parameters| {
            parameters["redirect_uri"] = Value::String(redirect_uri.to_owned());
        });
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
    async fn begin_first_party_interaction(
        &self,
        digest: &str,
        destination: FirstPartyDestination,
        expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        *self.record.lock().expect("lock") = Some((
            digest.to_owned(),
            InteractionRecord {
                tenant: TenantId::new("demo"),
                continuation: Continuation::FirstParty(destination),
                state: serde_json::json!({}),
                session: None,
                expires_at,
            },
        ));
        Ok(())
    }

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
        _acr: Option<&str>,
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
struct FakeLimiter {
    counters: Mutex<BTreeMap<(String, i64), u32>>,
    /// Which operations the handler asked for, in order — not which buckets,
    /// which differ by construction between two identifiers. It is the *shape*
    /// of the work that has to match between a wrong password and an unknown
    /// identifier, because a clear that happened on one and not the other is an
    /// enumeration oracle and a difference in database round trips besides
    /// (`ast-b3u`).
    operations: Mutex<Vec<&'static str>>,
}

impl FakeLimiter {
    fn operations(&self) -> Vec<&'static str> {
        self.operations.lock().expect("lock").clone()
    }

    fn note(&self, operation: &'static str) {
        self.operations.lock().expect("lock").push(operation);
    }
}

#[async_trait::async_trait]
impl RateLimitStore for FakeLimiter {
    async fn count(
        &self,
        _tenant: &TenantId,
        bucket: &Bucket,
        window_start: OffsetDateTime,
    ) -> Result<u32, DomainError> {
        self.note("count");
        Ok(*self
            .counters
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
        self.note("record");
        let mut counters = self.counters.lock().expect("lock");
        let entry = counters
            .entry((bucket.as_str().to_owned(), window_start.unix_timestamp()))
            .or_default();
        *entry += 1;
        Ok(*entry)
    }

    async fn clear(&self, _tenant: &TenantId, bucket: &Bucket) -> Result<(), DomainError> {
        self.note("clear");
        self.counters
            .lock()
            .expect("lock")
            .retain(|(key, _), _| key != bucket.as_str());
        Ok(())
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

/// The language layers every context here is built with: no tenant settings and
/// no `Accept-Language`, which is the built-in default.
static ENGLISH: std::sync::LazyLock<asterius_server::http::i18n::PageLanguage> =
    std::sync::LazyLock::new(|| {
        asterius_server::http::i18n::PageLanguage::new(None, &axum::http::HeaderMap::new())
    });

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
        language: &ENGLISH,
        requests: store,
        credentials: auth,
        sessions,
        lifetimes: Lifetimes::default(),
        acr: acr_policy(),
        clients: &FakeClients,
        grants: &issued.grants,
        // Grant Management is off for these tenants, which is what the flag
        // defaults to: a stored request here never names a `grant_id`.
        grant_amendments: None,
        // No registry: these tests push no `authorization_details`, and a
        // deployment without one shows a rich authorization by type name.
        authorization_details_types: None,
        memory: asterius_oidc::consent_memory::MemoryPolicy::default(),
        codes: &issued.codes,
        subjects: &FakeSubjects,
        code_lifetime: asterius_oidc::code::DEFAULT_LIFETIME,
        nonce,
        throttle: LoginThrottle::new(&issued.limiter, limits, Some(client())),
        audit: &issued.audit,
        // The root: these tests call the handlers directly rather than through
        // the tenancy layer, so nothing removed a prefix. The tests that do
        // exercise a prefix set this field themselves.
        mount: MountPrefix::root(),
        // No registrar: `Feature::SelfRegistration` is off for these tenants,
        // which is what the flag defaults to. The sign-up stage is exercised
        // where the flag is on, in `crates/server/tests/self_registration.rs`.
        registrar: None,
        directory: &FakeDirectory,
    }
}

/// An account directory that holds nobody.
///
/// The sign-in path reads it only to put a display name on the screens that
/// follow, and `None` is the answer that makes it fall back to the identifier
/// that was typed — which is what these tests assert.
#[derive(Debug)]
struct FakeDirectory;

#[async_trait::async_trait]
impl asterius_domain::UserDirectory for FakeDirectory {
    async fn by_id(
        &self,
        _id: asterius_domain::UserId,
    ) -> Result<Option<asterius_domain::User>, DomainError> {
        Ok(None)
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
        None,
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
        None,
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
        None,
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
        None,
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
    assert!(html.contains("Allow access?"), "{html}");
    assert!(
        html.contains("rp.example"),
        "the consent screen did not name the host: {html}"
    );
}

/// **The consent screen names who signed in** (`ast-bo5`).
///
/// A person on a shared machine has to be able to see whose account is about
/// to be granted, so the name the sign-in proved is carried on the interaction
/// state rather than re-derived per screen.
#[tokio::test]
async fn the_consent_screen_names_who_signed_in() {
    // Arrange
    let id = InteractionId::generate();
    let mut state = StoredState::default();
    let token = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();
    let auth = AlwaysSucceeds;

    // Act
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

    // Assert
    let html = body_of(response).await;
    assert!(
        html.contains("Signed in as ada."),
        "the consent screen did not name who signed in: {html}"
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
            None,
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
            None,
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

// ---- the first-party continuation (ast-wr4, ADR-0009) -------------------

/// Signs in against an interaction whose continuation is the admin console,
/// with whatever extra form fields a caller wants to smuggle in.
async fn sign_in_to_the_console(
    extra: &str,
) -> (axum::response::Response, FakeSessions, FakeStore, String) {
    let id = InteractionId::generate();
    let mut state = StoredState::default();
    let token = state.issue_csrf();
    let store =
        FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json")).first_party();
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
            "csrf={}&username=ada&password=hunter2{extra}",
            token.expose()
        )),
        OffsetDateTime::now_utc(),
    )
    .await;

    (response, sessions, store, id.digest())
}

/// The header this response sends the browser to.
fn location(response: &axum::response::Response) -> String {
    response
        .headers()
        .get(header::LOCATION)
        .expect("a Location")
        .to_str()
        .expect("ascii")
        .to_owned()
}

/// The first criterion: a console login ends at the console, through the
/// interaction pages and not through a consent screen.
#[tokio::test]
async fn a_first_party_login_ends_at_its_destination() {
    // Arrange / Act
    let (response, _, store, digest) = sign_in_to_the_console("").await;

    // Assert
    assert_eq!(response.status().as_u16(), SEE_OTHER);
    assert_eq!(location(&response), "../admin/");
    assert!(
        store.was_completed(&digest),
        "the interaction was not spent: a second submission could open a second session"
    );
}

/// The criterion this bead exists for. A browser can put anything it likes in
/// the form; the destination is a variant of a closed enum, so none of it can
/// move the redirect. There is no allow-list to defeat because there is no
/// list.
#[tokio::test]
async fn nothing_the_browser_sends_can_move_the_destination() {
    for hostile in [
        "&next=https://evil.example/",
        "&redirect_uri=https://evil.example/",
        "&destination=https://evil.example/",
        "&continuation=admin_console&next=//evil.example",
        "&next=/admin/../../evil",
        "&destination=admin_console%0d%0aLocation:+https://evil.example/",
    ] {
        // Arrange / Act
        let (response, _, _, _) = sign_in_to_the_console(hostile).await;

        // Assert
        assert_eq!(response.status().as_u16(), SEE_OTHER, "for {hostile}");
        assert_eq!(
            location(&response),
            "../admin/",
            "a request field reached the destination: {hostile}"
        );
    }
}

/// The same session, from the same code. Both continuations go through
/// `interaction::submit` -> `sign_in`, so both get the rotation-safe fresh id,
/// the `amr` and the cookie attributes — and this asserts they are the *same*
/// facts rather than two similar ones.
#[tokio::test]
async fn a_console_login_and_an_authorization_login_open_the_same_kind_of_session() {
    // Arrange / Act: the first-party path.
    let (first_party, console_sessions, _, _) = sign_in_to_the_console("").await;

    // The authorization path, through the very same entry point.
    let id = InteractionId::generate();
    let mut state = StoredState::default();
    let token = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let client_sessions = FakeSessions::default();
    let issued = Issued::default();
    let auth = AlwaysSucceeds;
    let authorization = submit(
        context(
            &tenant,
            &store,
            &nonce,
            Some(&auth),
            &client_sessions,
            &issued,
        ),
        id.expose(),
        &cookie_header(id.expose()),
        &Bytes::from(format!(
            "csrf={}&username=ada&password=hunter2",
            token.expose()
        )),
        OffsetDateTime::now_utc(),
    )
    .await;

    // Assert: one session each, and the same shape.
    let console = console_sessions.0.lock().expect("lock");
    let client = client_sessions.0.lock().expect("lock");
    assert_eq!(console.len(), 1, "the console path opened no session");
    assert_eq!(client.len(), 1, "the authorization path opened no session");
    assert_eq!(console[0].user, client[0].user);
    assert_eq!(console[0].amr, client[0].amr);
    assert_eq!(console[0].acr, client[0].acr);
    // A fresh id on both, and never the digest.
    assert_ne!(
        console[0].id_digest, client[0].id_digest,
        "two sign-ins produced one session id"
    );

    for (response, session) in [(&first_party, &console[0]), (&authorization, &client[0])] {
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
            !cookie.contains(&session.id_digest),
            "the digest was sent to the browser instead of the id"
        );
    }
}

/// One sentence for "no such user" and for "wrong password", on this path as
/// on the other. The console is where an administrator signs in, which is the
/// account worth enumerating.
#[tokio::test]
async fn a_console_login_says_the_same_thing_to_every_failure() {
    let mut said = Vec::new();
    for verifier in [&AlwaysRefuses as &dyn CredentialVerifier, &AlwaysRefuses] {
        let id = InteractionId::generate();
        let mut state = StoredState::default();
        let token = state.issue_csrf();
        let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"))
            .first_party();
        let tenant = tenant();
        let nonce = Nonce::generate();
        let sessions = FakeSessions::default();
        let issued = Issued::default();

        let response = submit(
            context(&tenant, &store, &nonce, Some(verifier), &sessions, &issued),
            id.expose(),
            &cookie_header(id.expose()),
            &Bytes::from(format!(
                "csrf={}&username=ada&password=wrong",
                token.expose()
            )),
            OffsetDateTime::now_utc(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK, "a refusal is a page");
        assert!(sessions.0.lock().expect("lock").is_empty());
        // Only the message. Everything else on the page is per-rendering —
        // the interaction id, a fresh synchroniser token — and comparing whole
        // documents would compare those instead of what was *said*.
        let body = body_of(response).await;
        let start = body.find("role=\"alert\"").expect("an error summary");
        let end = body[start..].find("</div>").expect("a closed summary") + start;
        said.push(body[start..end].to_owned());
    }
    assert_eq!(said[0], said[1]);
    assert!(
        said[0].contains("Those details did not match."),
        "the shared message is not the one shown: {}",
        said[0]
    );
}

/// A first-party interaction has no client, no redirect URI and no scopes, and
/// nothing on this path asks for one. Rendering its login page is the same
/// page every other login gets.
#[tokio::test]
async fn a_first_party_interaction_renders_the_ordinary_login_page() {
    // Arrange
    let id = InteractionId::generate();
    let store = FakeStore::with(
        &id.digest(),
        serde_json::to_value(StoredState::default()).expect("json"),
    )
    .first_party();
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();

    // Act
    let response = show(
        context(&tenant, &store, &nonce, None, &sessions, &issued),
        id.expose(),
        None,
        &cookie_header(id.expose()),
        OffsetDateTime::now_utc(),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_of(response).await;
    assert!(
        body.contains("name=\"password\""),
        "not the login page: {body}"
    );
    assert!(
        !body.contains("name=\"decision\""),
        "a consent form was rendered for an interaction with nobody to consent to"
    );
}

/// The stage machine refuses it, and so does the handler: a first-party
/// interaction parked at `Consent` — which nothing can put it in — has no
/// offer to render and is refused rather than shown an empty screen.
#[tokio::test]
async fn a_first_party_interaction_cannot_be_shown_a_consent_screen() {
    // Arrange: a state that should not exist, written by hand.
    let id = InteractionId::generate();
    let state = StoredState {
        stage: asterius_web::interaction::Stage::Consent,
        csrf_digest: None,
        ..StoredState::default()
    };
    let store =
        FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json")).first_party();
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let issued = Issued::default();

    // Act
    let response = show(
        context(&tenant, &store, &nonce, None, &sessions, &issued),
        id.expose(),
        None,
        &cookie_header(id.expose()),
        OffsetDateTime::now_utc(),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_of(response).await;
    assert!(
        !body.contains("name=\"decision\""),
        "a consent form was rendered with no client behind it"
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
    // Read out of the error summary `error_summary.html` renders — a `<div
    // class="error" role="alert">`, which is where a failure is identified in
    // text (WCAG 2.2 SC 3.3.1).
    let said = |html: &str| {
        html.split(r#"<div class="error""#)
            .nth(1)
            .and_then(|rest| rest.split("</div>").next())
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

// ---- a proof empties the bucket (ast-b3u) --------------------------------

/// One account with one password. Unlike `AlwaysSucceeds` and `AlwaysRefuses`
/// it can tell "no such identifier" from "wrong password" — which is exactly
/// the difference that must not be observable outside it.
#[derive(Debug)]
struct SmallDirectory;

#[async_trait::async_trait]
impl CredentialVerifier for SmallDirectory {
    async fn verify(
        &self,
        username: &str,
        password: Secret<String>,
    ) -> Result<Option<uuid::Uuid>, DomainError> {
        // The identifier is not a secret and is matched first, on its own
        // line: an unknown user never reaches the password comparison.
        if username != "ada" {
            return Ok(None);
        }
        // The password leaves the wrapper only to be compared, which is what a
        // verifier is for, and the comparison is constant-time — the same
        // `ct_eq` a real verifier owes a secret, kept on a line of its own so
        // `secret_audit` reads this fixture the way it reads production code.
        let correct = asterius_domain::secret::ct_eq(password.expose().as_bytes(), b"hunter2");
        if correct {
            Ok(Some(uuid::Uuid::from_u128(1)))
        } else {
            Ok(None)
        }
    }
}

/// Ten failures per identifier, and an address limit no test here reaches: the
/// property under test is the account bucket, and a shared address limit would
/// refuse the attempts before it was consulted.
fn per_account_limits() -> LoginLimits {
    LoginLimits {
        per_address: RateLimit {
            max: 1_000,
            window: Duration::minutes(15),
        },
        per_account: RateLimit {
            max: 10,
            window: Duration::minutes(15),
        },
    }
}

/// Submits one sign-in against [`SmallDirectory`], sharing `issued` — and so
/// sharing the counters — with every other call.
async fn sign_in_attempt(
    username: &str,
    password: &str,
    issued: &Issued,
    now: OffsetDateTime,
) -> (StatusCode, String) {
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let auth = SmallDirectory;
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
            per_account_limits(),
        ),
        id.expose(),
        &cookie_header(id.expose()),
        &Bytes::from(format!(
            "csrf={}&username={username}&password={password}",
            token.expose()
        )),
        now,
    )
    .await;
    (response.status(), body_of(response).await)
}

/// Nine mistypes and then the right password: the quota is whole again, so the
/// next slip is an ordinary refusal rather than a lockout. Without the reset
/// the tenth failure would carry the bucket to its limit and the eleventh
/// attempt would be throttled, for somebody who has just proved who they are.
#[tokio::test]
async fn a_successful_sign_in_gives_the_identifier_its_quota_back() {
    // Arrange: nine failures, one short of the limit, then a real sign-in.
    let issued = Issued::default();
    let now = OffsetDateTime::now_utc();
    for _ in 0..9 {
        sign_in_attempt("ada", "wrong", &issued, now).await;
    }
    let (accepted, _) = sign_in_attempt("ada", "hunter2", &issued, now).await;
    assert_ne!(accepted, StatusCode::TOO_MANY_REQUESTS);

    // Act: two more slips, which a full bucket would have refused.
    sign_in_attempt("ada", "wrong", &issued, now).await;
    let (status, body) = sign_in_attempt("ada", "wrong", &issued, now).await;

    // Assert
    assert_eq!(
        status,
        StatusCode::OK,
        "the quota was not given back: {body}"
    );
    assert!(!body.contains("Try again in"), "throttled: {body}");
}

/// The reset must not become the oracle the account bucket exists to close: a
/// wrong password against an account that exists and a guess at an identifier
/// nobody owns must answer the same thing and do the same work — same page,
/// same counter operations, no clear on either.
#[tokio::test]
async fn a_wrong_password_and_an_unknown_identifier_answer_and_cost_the_same() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let real = Issued::default();
    let invented = Issued::default();

    // Act
    let mut real_answer = None;
    let mut invented_answer = None;
    for _ in 0..3 {
        real_answer = Some(sign_in_attempt("ada", "wrong", &real, now).await);
        invented_answer =
            Some(sign_in_attempt("nobody@example.test", "wrong", &invented, now).await);
    }

    // Assert: the same answer, and the same work behind it — in particular
    // neither sequence contains a `clear`, which only a proof may cause. The
    // pages are compared through what they *say*, for the reason
    // `a_locked_identifier_and_an_unknown_one_answer_the_same_thing` gives: the
    // rest differs only in the per-render values — the interaction id, the CSP
    // nonce, the synchroniser token — none of which is derived from what was
    // typed.
    let said = |answer: &Option<(StatusCode, String)>| {
        let (status, html) = answer.clone().expect("an answer");
        let message = html
            .split(r#"<div class="error""#)
            .nth(1)
            .and_then(|rest| rest.split("</div>").next())
            .map(ToOwned::to_owned)
            .expect("a message on the page");
        (status, message)
    };
    assert_eq!(said(&real_answer), said(&invented_answer));
    assert_eq!(real.limiter.operations(), invented.limiter.operations());
    assert!(
        !real.limiter.operations().contains(&"clear"),
        "a refused sign-in emptied a bucket: {:?}",
        real.limiter.operations()
    );
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
        ..StoredState::default()
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
        None,
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

/// RFC 9449 §10.1: a request pinned to a DPoP key issues a code pinned to it.
/// The pin travels in the stored parameters, and this is the half that copies
/// it onto the binding the token endpoint compares against (`ast-36g`).
#[tokio::test]
async fn a_pinned_request_issues_a_code_bound_to_that_key() {
    let thumbprint = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    let at = at_consent();
    at.store.pinned_to(thumbprint);
    let issued = Issued::default();

    let response = submit_decision(
        &at,
        &issued,
        &format!("csrf={}&decision=allow&scope=openid", at.csrf),
    )
    .await;

    assert_eq!(response.status().as_u16(), 303);
    let stored = issued.codes.0.lock().expect("lock");
    let (_, binding) = stored.first().expect("a code was stored");
    assert_eq!(
        binding.dpop_jkt.as_deref(),
        Some(thumbprint),
        "the code was issued unpinned, so any DPoP key could redeem it"
    );
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
        None,
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
        None,
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

// ---- the URLs the page hands back to the browser (ast-295) --------------
//
// Every test above calls `show` and `submit` directly, so every one of them
// sees a router mounted at the root — which is why 116 of them passed while
// the form action was a 404 for every path-based tenant. These drive the real
// router, behind the real tenancy layer, and follow the URL the page gives out
// instead of one the test made up.
//
// Both forms of tenancy are exercised, because both are real deployments:
// `/t/{id}` in the path (several tenants on one authority, which is what
// `deploy/compose` ships), and resolution by host (one hostname per tenant,
// which is what the conformance stack runs). The prefix restored is whatever
// the tenancy layer removed, and for the host form that is legitimately
// nothing.

/// Everything one browser journey needs, held where two requests can share it.
struct Journey {
    store: FakeStore,
    sessions: FakeSessions,
    issued: Issued,
    tenant: Tenant,
}

/// A tenant directory of exactly one tenant, read-only.
#[derive(Debug)]
struct OneTenant(Tenant);

#[async_trait::async_trait]
impl asterius_domain::ports::TenantRepository for OneTenant {
    async fn find_by_id(&self, _: &TenantId) -> Result<Option<Tenant>, DomainError> {
        unimplemented!("the directory only uses list()")
    }
    async fn find_by_issuer(&self, _: &Issuer) -> Result<Option<Tenant>, DomainError> {
        unimplemented!("the directory only uses list()")
    }
    async fn find_by_host(&self, _: &str) -> Result<Option<Tenant>, DomainError> {
        unimplemented!("the directory only uses list()")
    }
    async fn list(&self) -> Result<Vec<Tenant>, DomainError> {
        Ok(vec![self.0.clone()])
    }
    async fn upsert(&self, _: &Tenant) -> Result<(), DomainError> {
        unimplemented!("read-only")
    }
    async fn delete(&self, _: &TenantId) -> Result<(), DomainError> {
        unimplemented!("read-only")
    }
}

const TEST_CONFIG: &str = r#"
    [keys]
    kek_env = "ASTERIUS_TEST_KEK"

    [database]
    url = "postgres://asterius@localhost/asterius"
"#;

/// `GET /interaction/{id}`, as `http::protocol` mounts it.
async fn show_route(
    axum::extract::State(journey): axum::extract::State<std::sync::Arc<Journey>>,
    axum::Extension(nonce): axum::Extension<Nonce>,
    mount: Option<axum::Extension<MountPrefix>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    let issued = Issued::default();
    let mut context = context(
        &journey.tenant,
        &journey.store,
        &nonce,
        None,
        &journey.sessions,
        &issued,
    );
    context.mount = mount.map_or_else(MountPrefix::root, |axum::Extension(prefix)| prefix);
    show(context, &id, None, &headers, OffsetDateTime::now_utc()).await
}

/// `POST /interaction/{id}`, likewise.
async fn submit_route(
    axum::extract::State(journey): axum::extract::State<std::sync::Arc<Journey>>,
    axum::Extension(nonce): axum::Extension<Nonce>,
    mount: Option<axum::Extension<MountPrefix>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let auth = AlwaysSucceeds;
    let mut context = context(
        &journey.tenant,
        &journey.store,
        &nonce,
        Some(&auth),
        &journey.sessions,
        &journey.issued,
    );
    context.mount = mount.map_or_else(MountPrefix::root, |axum::Extension(prefix)| prefix);
    submit(context, &id, &headers, &body, OffsetDateTime::now_utc()).await
}

/// The two interaction routes behind the real tenancy layer.
fn routed(journey: std::sync::Arc<Journey>) -> axum::Router {
    let config = asterius_server::config::Config::parse(
        TEST_CONFIG,
        std::path::Path::new("asterius.toml"),
        &BTreeMap::new(),
    )
    .expect("valid test config")
    .server;
    let directory = asterius_server::tenancy::TenantDirectory::new(std::sync::Arc::new(OneTenant(
        journey.tenant.clone(),
    )));
    let state = asterius_server::tenancy::TenantState::new(directory, &config);

    // Mounted at the bare path, exactly as `http::protocol` mounts it: the
    // handler never sees `/t/{tenant}`.
    let routes = axum::Router::new()
        .route(
            "/interaction/{id}",
            axum::routing::get(show_route).post(submit_route),
        )
        .with_state(journey)
        .fallback(asterius_server::http::server::not_found);

    asterius_server::http::server::app(routes, state, None, &config)
}

/// One live login interaction for `tenant`.
fn journey_for(tenant: Tenant) -> (std::sync::Arc<Journey>, InteractionId) {
    let id = InteractionId::generate();
    let store = FakeStore::with(
        &id.digest(),
        serde_json::to_value(StoredState::default()).expect("json"),
    );
    (
        std::sync::Arc::new(Journey {
            store,
            sessions: FakeSessions::default(),
            issued: Issued::default(),
            tenant,
        }),
        id,
    )
}

/// The same tenant, served the two ways tenancy resolves one.
fn tenant_on_host(issuer: &str, custom_host: Option<&str>) -> Tenant {
    Tenant {
        issuer: Issuer::parse(issuer).expect("issuer"),
        custom_host: custom_host.map(str::to_owned),
        ..tenant()
    }
}

/// The value of the first `action="…"` in a page.
fn action_of(html: &str) -> String {
    html.split("action=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("no form action in the page: {html}"))
        .to_owned()
}

/// The value of an attribute the sign-in script reads.
fn attribute_of(html: &str, name: &str) -> String {
    let needle = format!("{name}=\"");
    html.split(&needle)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("no {name} in the page: {html}"))
        .to_owned()
}

/// One request through the assembled application.
async fn through(
    router: axum::Router,
    method: &str,
    host: &str,
    path: &str,
    cookie: &str,
    body: &str,
) -> axum::response::Response {
    use tower::ServiceExt as _;

    let request = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, host)
        .header(header::COOKIE, format!("{COOKIE_NAME}={cookie}"))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body.to_owned()))
        .expect("a request");
    router
        .oneshot(request)
        .await
        .expect("the router is infallible")
}

/// Under `/t/demo`, the login page posts back to a URL that is served.
///
/// This is the bug of `ast-295` in one test: before the fix the action was
/// `/interaction/{id}`, the POST that follows it reached the tenancy layer with
/// no tenant in the path and no tenant on the host, and the browser met a 404
/// instead of a session.
#[tokio::test]
async fn a_login_under_a_tenant_prefix_posts_back_to_a_url_that_exists() {
    // Arrange
    let (journey, id) = journey_for(tenant_on_host("https://as.example/t/demo", None));

    // Act: the page, as the browser was sent to it.
    let page = through(
        routed(std::sync::Arc::clone(&journey)),
        "GET",
        "as.example",
        &format!("/t/demo/interaction/{}", id.expose()),
        id.expose(),
        "",
    )
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    let html = body_of(page).await;
    let action = action_of(&html);
    let csrf = attribute_of(&html, "name=\"csrf\" value");

    // Assert: the URL the browser will use keeps the tenant.
    assert_eq!(action, format!("/t/demo/interaction/{}", id.expose()));

    // Act: submit it, to the URL the page gave out and no other.
    let response = through(
        routed(journey.clone()),
        "POST",
        "as.example",
        &action,
        id.expose(),
        &format!("csrf={csrf}&username=ada&password=hunter2"),
    )
    .await;

    // Assert: the route was reached and a session exists.
    assert_ne!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the form action is not served"
    );
    let created = journey.sessions.0.lock().expect("lock");
    assert_eq!(created.len(), 1, "no session was created");
}

/// The two endpoints the sign-in script fetches carry the prefix too.
#[tokio::test]
async fn the_passkey_endpoints_on_the_page_carry_the_tenant_prefix() {
    // Arrange
    let (journey, id) = journey_for(tenant_on_host("https://as.example/t/demo", None));

    // Act
    let page = through(
        routed(journey),
        "GET",
        "as.example",
        &format!("/t/demo/interaction/{}", id.expose()),
        id.expose(),
        "",
    )
    .await;
    let html = body_of(page).await;

    // Assert
    for suffix in ["passkey/options", "passkey/finish"] {
        let expected = format!("/t/demo/interaction/{}/{suffix}", id.expose());
        assert!(
            html.contains(&expected),
            "the script would fetch a path that is mounted nowhere: {expected} missing"
        );
    }
}

/// A tenant resolved by its hostname is served at the root, and its pages say
/// so: the prefix put back is the one that was removed, which here is none.
#[tokio::test]
async fn a_login_resolved_by_host_keeps_its_root_absolute_urls() {
    // Arrange
    let (journey, id) = journey_for(tenant_on_host(
        "https://login.demo.test",
        Some("login.demo.test"),
    ));

    // Act
    let page = through(
        routed(std::sync::Arc::clone(&journey)),
        "GET",
        "login.demo.test",
        &format!("/interaction/{}", id.expose()),
        id.expose(),
        "",
    )
    .await;
    assert_eq!(page.status(), StatusCode::OK);
    let html = body_of(page).await;
    let action = action_of(&html);
    let csrf = attribute_of(&html, "name=\"csrf\" value");

    // Assert
    assert_eq!(action, format!("/interaction/{}", id.expose()));

    let response = through(
        routed(std::sync::Arc::clone(&journey)),
        "POST",
        "login.demo.test",
        &action,
        id.expose(),
        &format!("csrf={csrf}&username=ada&password=hunter2"),
    )
    .await;

    assert_ne!(response.status(), StatusCode::NOT_FOUND);
    let created = journey.sessions.0.lock().expect("lock");
    assert_eq!(created.len(), 1, "no session was created");
}

/// The root path is not a way into a path-based tenant, and the fix does not
/// make it one: what makes the prefixed URL work is that it is prefixed.
#[tokio::test]
async fn the_root_path_still_reaches_no_path_based_tenant() {
    let (journey, id) = journey_for(tenant_on_host("https://as.example/t/demo", None));

    let response = through(
        routed(journey),
        "GET",
        "as.example",
        &format!("/interaction/{}", id.expose()),
        id.expose(),
        "",
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// The ladder these tests run against: the one the binary wires in
/// (`asterius_server::http::protocol`), built once so a context can borrow it.
fn acr_policy() -> &'static asterius_domain::AcrPolicy {
    static POLICY: std::sync::LazyLock<asterius_domain::AcrPolicy> =
        std::sync::LazyLock::new(asterius_domain::AcrPolicy::default);
    &POLICY
}
