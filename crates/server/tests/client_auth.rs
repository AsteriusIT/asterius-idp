//! Client authentication, end to end, with fakes for the store.
//!
//! Everything here runs in memory: the client repository and the replay guard
//! are `HashMap`s, and the client's keys are inline in its registration so no
//! fetch happens. That keeps the suite in the tens of milliseconds, which is
//! what makes it something to run on every change rather than occasionally.
//!
//! The cryptography is real. These sign actual assertions with actual keys,
//! because a test that stubs the signature check proves nothing about the one
//! thing this module exists to do.

use asterius_domain::audit::{AuditEvent, AuditSink, EventType, Outcome};
use asterius_domain::ports::ClientUrlFetcher;
use asterius_domain::{
    Capabilities, Client, ClientId, ClientRegistration, ClientRepository, ClientStatus,
    DomainError, Issuer, Kid, ReplayCheck, ReplayGuard, ReplayPurpose, SigningAlgorithm, Tenant,
    TenantId, TenantStatus,
};
use asterius_jose::client_keys::ClientKeyCache;
use asterius_jose::{SigningKey, jws};
use asterius_oidc::client_auth::{AssertionRules, Attempt, CLIENT_ASSERTION_TYPE, ClientAuthError};
use asterius_server::client_auth::ClientAuthenticator;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";
const CLIENT: &str = "billing";
const KID: &str = "client-key-1";

// ---- fakes ---------------------------------------------------------------

#[derive(Debug, Default)]
struct FakeClients(HashMap<String, Client>);

#[async_trait::async_trait]
impl ClientRepository for FakeClients {
    async fn find(&self, client_id: &ClientId) -> Result<Option<Client>, DomainError> {
        Ok(self.0.get(client_id.as_str()).cloned())
    }
}

/// A replay guard that remembers, and counts how often it was asked.
///
/// The count is the point of several tests below: an assertion rejected for
/// any other reason must not have reached this at all.
#[derive(Debug, Default)]
struct FakeReplay {
    seen: Mutex<HashSet<(String, String, String)>>,
    claims: Mutex<usize>,
}

impl FakeReplay {
    fn claim_count(&self) -> usize {
        *self.claims.lock().expect("lock")
    }
}

#[async_trait::async_trait]
impl ReplayGuard for FakeReplay {
    async fn claim(
        &self,
        tenant: &TenantId,
        purpose: ReplayPurpose,
        subject: &str,
        jti: &str,
        _expires_at: OffsetDateTime,
    ) -> Result<ReplayCheck, DomainError> {
        *self.claims.lock().expect("lock") += 1;
        let key = (
            format!("{}:{}", tenant.as_str(), purpose.as_str()),
            subject.to_owned(),
            jti.to_owned(),
        );
        if self.seen.lock().expect("lock").insert(key) {
            Ok(ReplayCheck::FirstUse)
        } else {
            Ok(ReplayCheck::Replay)
        }
    }
}

/// Never called: every client here carries its keys inline. Present because
/// the cache requires one, and it fails loudly so that a test which
/// accidentally takes the network path is a failure rather than a slow pass.
#[derive(Debug)]
struct NoFetching;

#[async_trait::async_trait]
impl ClientUrlFetcher for NoFetching {
    async fn fetch(&self, _url: &str) -> Result<Vec<u8>, DomainError> {
        panic!("a test reached the network; every fixture here has inline keys");
    }
}

// ---- fixtures ------------------------------------------------------------

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("fixed instant")
}

fn tenant(id: &str, issuer: &str) -> Tenant {
    Tenant {
        id: TenantId::new(id),
        issuer: Issuer::parse(issuer).expect("issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: id.to_owned(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn registration(jwks: &Value, auth_method: &str) -> Value {
    let mut document = json!({
        "client_name": "Billing",
        "redirect_uris": ["https://rp.example/cb"],
        "grant_types": ["authorization_code"],
        "scope": "openid",
        "token_endpoint_auth_method": auth_method,
        "jwks": jwks,
    });
    // RFC 8705 §2.1.2: a `tls_client_auth` client registers exactly one
    // certificate subject, and a document without one is not a registration.
    // Added here rather than at each call site so a fixture cannot ask for the
    // method and get a client no certificate could ever match.
    if auth_method == "tls_client_auth" {
        document
            .as_object_mut()
            .expect("object")
            .insert("tls_client_auth_subject_dn".to_owned(), json!("CN=billing"));
    }
    document
}

fn client_from(tenant_id: &str, id: &str, document: &Value, status: ClientStatus) -> Client {
    // mTLS is behind a feature flag, so a `tls_client_auth` registration is
    // not even a valid document unless the deployment offers it. The fixture
    // enables it because the point of the test below is a client registered
    // for mTLS reaching the assertion path — not whether it could register.
    let capabilities = Capabilities {
        mtls: true,
        ..Capabilities::default()
    };
    Client {
        tenant: TenantId::new(tenant_id),
        id: ClientId::new(id),
        registration: ClientRegistration::from_json(
            &serde_json::to_vec(document).expect("serialise"),
            capabilities,
        )
        .expect("a valid registration"),
        status,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// A client key, and the JWK Set a registration would carry for it.
fn client_key() -> (SigningKey, Value) {
    let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
    let mut jwk = key.public_jwk().expect("jwk");
    jwk["kid"] = json!(KID);
    (key, json!({"keys": [jwk]}))
}

fn assertion_claims(client: &str, audience: &str) -> Value {
    json!({
        "iss": client,
        "sub": client,
        "aud": audience,
        "jti": "assertion-1",
        "exp": now().unix_timestamp() + 60,
        "iat": now().unix_timestamp(),
    })
}

fn sign_with(key: &SigningKey, claims: &Value) -> String {
    jws::sign(key, &Kid::new(KID), "JWT", claims)
        .expect("sign")
        .as_str()
        .to_owned()
}

/// Every client this run recorded a use for (`ast-cu3`).
#[derive(Debug, Default)]
struct FakeUsage {
    recorded: std::sync::Mutex<Vec<(String, String, time::OffsetDateTime)>>,
    broken: bool,
}

impl FakeUsage {
    fn broken() -> Self {
        Self {
            broken: true,
            ..Self::default()
        }
    }

    fn recorded(&self) -> Vec<(String, String, time::OffsetDateTime)> {
        self.recorded.lock().expect("lock").clone()
    }
}

#[async_trait::async_trait]
impl asterius_domain::ClientUsageRecorder for FakeUsage {
    async fn record_use(
        &self,
        tenant: &asterius_domain::TenantId,
        client_id: &asterius_domain::ClientId,
        now: time::OffsetDateTime,
    ) -> Result<(), asterius_domain::DomainError> {
        if self.broken {
            return Err(asterius_domain::DomainError::Storage(
                "the database is gone".into(),
            ));
        }
        self.recorded.lock().expect("lock").push((
            tenant.as_str().to_owned(),
            client_id.as_str().to_owned(),
            now,
        ));
        Ok(())
    }
}

/// An audit trail that keeps what was written to it.
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

/// The world: one tenant, one active client with inline keys.
struct World {
    authenticator: ClientAuthenticator,
    clients: FakeClients,
    replay: Arc<FakeReplay>,
    usage: Arc<FakeUsage>,
    key: SigningKey,
    tenant: Tenant,
}

impl World {
    fn new() -> Self {
        Self::with_client(ClientStatus::Active, "private_key_jwt")
    }

    fn with_client(status: ClientStatus, auth_method: &str) -> Self {
        Self::recording(status, auth_method, Arc::new(FakeUsage::default()))
    }

    /// The ordinary world, with an audit trail wired in (`ast-4j1`).
    fn auditing(audit: Arc<FakeAudit>) -> Self {
        let mut world = Self::new();
        world.authenticator = world
            .authenticator
            .auditing(audit as Arc<dyn asterius_domain::audit::AuditSink>);
        world
    }

    fn recording(status: ClientStatus, auth_method: &str, usage: Arc<FakeUsage>) -> Self {
        let (key, jwks) = client_key();
        let mut clients = FakeClients::default();
        clients.0.insert(
            CLIENT.to_owned(),
            client_from("demo", CLIENT, &registration(&jwks, auth_method), status),
        );

        let replay = Arc::new(FakeReplay::default());
        let cache = Arc::new(ClientKeyCache::new(Arc::new(NoFetching)));
        Self {
            authenticator: ClientAuthenticator::new(cache, replay.clone())
                .expect("build")
                .recording_use(Arc::clone(&usage) as Arc<dyn asterius_domain::ClientUsageRecorder>),
            clients,
            replay,
            usage,
            key,
            tenant: tenant("demo", ISSUER),
        }
    }

    async fn authenticate(&self, attempt: &Attempt<'_>) -> Result<Client, ClientAuthError> {
        self.authenticator
            .authenticate(
                &self.tenant,
                &self.clients,
                attempt,
                &AssertionRules::for_issuer(ISSUER),
                now(),
            )
            .await
    }

    /// Authenticates with a freshly signed, otherwise-conforming assertion.
    async fn authenticate_claims(&self, claims: &Value) -> Result<Client, ClientAuthError> {
        let token = sign_with(&self.key, claims);
        self.authenticate(&attempt_with(&token)).await
    }
}

fn attempt_with(token: &str) -> Attempt<'_> {
    Attempt {
        assertion: Some(token),
        assertion_type: Some(CLIENT_ASSERTION_TYPE),
        ..Attempt::default()
    }
}

/// The smallest DER `ClientCertificate::from_der` accepts: an empty subject,
/// no extensions. These tests count credentials rather than read them.
fn a_certificate() -> asterius_oidc::mtls::ClientCertificate {
    asterius_oidc::mtls::ClientCertificate::from_der(vec![
        0x30, 0x15, 0x30, 0x0f, 0x02, 0x01, 0x01, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00,
        0x30, 0x02, 0x30, 0x00, 0x30, 0x00, 0x03, 0x00,
    ])
    .expect("a minimal certificate")
}

// ---- the happy path ------------------------------------------------------

#[tokio::test]
async fn a_conforming_assertion_authenticates_the_client() {
    let world = World::new();
    let client = world
        .authenticate_claims(&assertion_claims(CLIENT, ISSUER))
        .await
        .expect("must authenticate");
    assert_eq!(client.id.as_str(), CLIENT);
    assert_eq!(world.replay.claim_count(), 1);
}

/// RFC 7523 defines no `typ`, so an assertion without one is ordinary.
#[tokio::test]
async fn an_assertion_carrying_no_typ_header_is_accepted() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    let world = World::new();
    let claims = assertion_claims(CLIENT, ISSUER);
    let header = json!({"alg": "EdDSA", "kid": KID});
    let signing_input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).expect("json")),
        B64.encode(serde_json::to_vec(&claims).expect("json"))
    );
    let signature = world.key.sign(signing_input.as_bytes()).expect("sign");
    let token = format!("{signing_input}.{}", B64.encode(signature));

    world
        .authenticate(&attempt_with(&token))
        .await
        .expect("RFC 7523 requires no typ; refusing one without it breaks conforming clients");
}

/// Widened, not erased.
#[tokio::test]
async fn an_access_token_is_not_a_client_assertion() {
    let world = World::new();
    let token = jws::sign(
        &world.key,
        &Kid::new(KID),
        "at+jwt",
        &assertion_claims(CLIENT, ISSUER),
    )
    .expect("sign");

    assert_eq!(
        world.authenticate(&attempt_with(token.as_str())).await,
        Err(ClientAuthError::AssertionNotVerified)
    );
}

// ---- replay (RFC 7523 §3 item 7) -----------------------------------------

#[tokio::test]
async fn the_same_assertion_cannot_be_used_twice() {
    let world = World::new();
    let claims = assertion_claims(CLIENT, ISSUER);

    world.authenticate_claims(&claims).await.expect("first use");
    assert_eq!(
        world.authenticate_claims(&claims).await,
        Err(ClientAuthError::ReplayedAssertion),
        "a captured assertion is a bearer credential until it expires"
    );
}

/// A *different* `jti` from the same client is a different assertion, even
/// with every other claim identical.
#[tokio::test]
async fn a_fresh_jti_is_not_a_replay() {
    let world = World::new();
    let mut claims = assertion_claims(CLIENT, ISSUER);
    world.authenticate_claims(&claims).await.expect("first");

    claims["jti"] = json!("assertion-2");
    world.authenticate_claims(&claims).await.expect("second");
}

/// The ordering that matters: a rejected assertion must not consume its `jti`.
///
/// Otherwise anyone who can reach this endpoint can burn a client's
/// identifiers with assertions that were never going to be accepted — and the
/// client, having done nothing wrong, cannot reuse a `jti` it has not spent.
#[tokio::test]
async fn a_rejected_assertion_does_not_consume_its_jti() {
    let world = World::new();

    let mut wrong_audience = assertion_claims(CLIENT, ISSUER);
    wrong_audience["aud"] = json!("https://as.example/t/other");
    assert_eq!(
        world.authenticate_claims(&wrong_audience).await,
        Err(ClientAuthError::WrongAudience)
    );
    assert_eq!(
        world.replay.claim_count(),
        0,
        "the replay store was consulted for an assertion that failed earlier checks"
    );

    // The same `jti`, now in a correct assertion, is still available.
    world
        .authenticate_claims(&assertion_claims(CLIENT, ISSUER))
        .await
        .expect("the jti was never spent, so this must succeed");
}

// ---- tenancy (the debt named in ast-83p.10) ------------------------------

/// The same `client_id` registered in two tenants is two clients.
///
/// An assertion minted for tenant A names A's issuer in `aud`, so presenting
/// it at tenant B fails — and it fails on the audience, before B's client
/// registry is even consulted for a key that might verify it.
#[tokio::test]
async fn an_assertion_for_one_tenant_is_refused_at_another() {
    let (key, jwks) = client_key();
    let mut clients = FakeClients::default();
    // Same id, same keys, different tenant. The worst case: an operator who
    // provisioned the identical client into both.
    clients.0.insert(
        CLIENT.to_owned(),
        client_from(
            "other",
            CLIENT,
            &registration(&jwks, "private_key_jwt"),
            ClientStatus::Active,
        ),
    );

    let replay = Arc::new(FakeReplay::default());
    let authenticator = ClientAuthenticator::new(
        Arc::new(ClientKeyCache::new(Arc::new(NoFetching))),
        replay.clone(),
    )
    .expect("build");

    let other = tenant("other", "https://as.example/t/other");
    let for_demo = sign_with(&key, &assertion_claims(CLIENT, ISSUER));

    let result = authenticator
        .authenticate(
            &other,
            &clients,
            &attempt_with(&for_demo),
            &AssertionRules::for_issuer("https://as.example/t/other"),
            now(),
        )
        .await;

    assert_eq!(result, Err(ClientAuthError::WrongAudience));
    assert_eq!(replay.claim_count(), 0);
}

// ---- who the client is ---------------------------------------------------

#[tokio::test]
async fn an_unknown_client_is_refused_without_saying_so() {
    let world = World::new();
    let claims = assertion_claims("no-such-client", ISSUER);
    // Signed by a real key, so the only thing wrong is who it claims to be.
    assert_eq!(
        world.authenticate_claims(&claims).await,
        Err(ClientAuthError::UnknownClient)
    );
}

#[tokio::test]
async fn a_disabled_client_is_indistinguishable_from_an_absent_one() {
    let world = World::with_client(ClientStatus::Disabled, "private_key_jwt");
    assert_eq!(
        world
            .authenticate_claims(&assertion_claims(CLIENT, ISSUER))
            .await,
        Err(ClientAuthError::UnknownClient),
        "a disabled client must not be distinguishable from one that never existed"
    );
}

#[tokio::test]
async fn a_client_registered_for_mtls_cannot_authenticate_with_an_assertion() {
    let world = World::with_client(ClientStatus::Active, "tls_client_auth");
    assert_eq!(
        world
            .authenticate_claims(&assertion_claims(CLIENT, ISSUER))
            .await,
        Err(ClientAuthError::WrongMethodForClient)
    );
}

#[tokio::test]
async fn an_assertion_signed_by_the_wrong_key_does_not_verify() {
    let world = World::new();
    let stranger = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
    let token = sign_with(&stranger, &assertion_claims(CLIENT, ISSUER));

    assert_eq!(
        world.authenticate(&attempt_with(&token)).await,
        Err(ClientAuthError::AssertionNotVerified)
    );
    assert_eq!(world.replay.claim_count(), 0);
}

// ---- the shape of the request (RFC 6749 §2.3, RFC 7521 §4.2) -------------

#[tokio::test]
async fn a_client_id_parameter_disagreeing_with_the_subject_is_refused() {
    let world = World::new();
    let token = sign_with(&world.key, &assertion_claims(CLIENT, ISSUER));
    let attempt = Attempt {
        client_id: Some("someone-else"),
        ..attempt_with(&token)
    };

    assert_eq!(
        world.authenticate(&attempt).await,
        Err(ClientAuthError::ClientIdMismatch)
    );
}

#[tokio::test]
async fn a_client_id_parameter_agreeing_with_the_subject_is_fine() {
    let world = World::new();
    let token = sign_with(&world.key, &assertion_claims(CLIENT, ISSUER));
    let attempt = Attempt {
        client_id: Some(CLIENT),
        ..attempt_with(&token)
    };

    world
        .authenticate(&attempt)
        .await
        .expect("must authenticate");
}

#[tokio::test]
async fn presenting_a_certificate_and_an_assertion_is_a_malformed_request() {
    let world = World::new();
    let token = sign_with(&world.key, &assertion_claims(CLIENT, ISSUER));
    let certificate = a_certificate();
    let attempt = Attempt {
        certificate: Some(&certificate),
        ..attempt_with(&token)
    };

    let error = world
        .authenticate(&attempt)
        .await
        .expect_err("two credentials is not a request this server should resolve");
    assert_eq!(error, ClientAuthError::MultipleMethods);
    assert_eq!(error.code(), "invalid_request");
    assert_eq!(error.status(), 400);
}

/// FAPI 2.0 SP §5.3.2.1 item 8, through the whole stack rather than the unit.
#[tokio::test]
async fn an_array_audience_is_refused_end_to_end() {
    let world = World::new();
    let mut claims = assertion_claims(CLIENT, ISSUER);
    claims["aud"] = json!([ISSUER]);

    assert_eq!(
        world.authenticate_claims(&claims).await,
        Err(ClientAuthError::WrongAudience),
        "an array holding only the issuer is still an array"
    );
}

#[tokio::test]
async fn an_expired_assertion_is_refused() {
    let world = World::new();
    let mut claims = assertion_claims(CLIENT, ISSUER);
    claims["exp"] = json!(now().unix_timestamp() - 1);

    assert_eq!(
        world.authenticate_claims(&claims).await,
        Err(ClientAuthError::AssertionNotVerified)
    );
}

/// FAPI 2.0 SP §5.3.2.1 item 13: more than 60 seconds ahead is refused.
#[tokio::test]
async fn an_assertion_issued_too_far_in_the_future_is_refused() {
    let world = World::new();
    let mut claims = assertion_claims(CLIENT, ISSUER);
    claims["iat"] = json!(now().unix_timestamp() + 61);

    assert_eq!(
        world.authenticate_claims(&claims).await,
        Err(ClientAuthError::AssertionNotVerified)
    );
}

#[tokio::test]
async fn garbage_in_place_of_an_assertion_is_refused_without_panicking() {
    let world = World::new();
    for junk in [
        "",
        ".",
        "..",
        "a.b.c",
        "not a jwt at all",
        "eyJhbGciOiJub25lIn0..",
        &"a".repeat(100_000),
    ] {
        let result = world.authenticate(&attempt_with(junk)).await;
        assert!(
            matches!(result, Err(ClientAuthError::AssertionNotVerified)),
            "unexpected result for {junk:?}: {result:?}"
        );
    }
    assert_eq!(world.replay.claim_count(), 0);
}

// ---- recording a use (`ast-cu3`) -----------------------------------------

/// A client is "used" exactly when it authenticates, and this is the one
/// function both the token endpoint and PAR reach — so the tenant policy's
/// `unused_client_expiry_seconds` has one definition of idle, not two.
#[tokio::test]
async fn a_successful_authentication_records_that_the_client_was_used() {
    // Arrange
    let world = World::new();

    // Act
    let authenticated = world
        .authenticate_claims(&assertion_claims(CLIENT, ISSUER))
        .await;

    // Assert
    assert!(authenticated.is_ok());
    assert_eq!(
        world.usage.recorded(),
        vec![("demo".to_owned(), CLIENT.to_owned(), now())]
    );
}

/// A refused assertion is not a use. Recording one would keep a client alive
/// in the sweep on the strength of somebody failing to authenticate as it,
/// which is the opposite of what the setting is for.
#[tokio::test]
async fn a_refused_assertion_records_nothing() {
    // Arrange
    let world = World::new();
    let mut claims = assertion_claims(CLIENT, ISSUER);
    claims["aud"] = serde_json::json!("https://somewhere.else/");

    // Act
    let refused = world.authenticate_claims(&claims).await;

    // Assert
    assert!(refused.is_err());
    assert!(world.usage.recorded().is_empty());
}

/// A bookkeeping write that fails does not refuse a client that has
/// authenticated: the assertion verified and the `jti` was claimed, and a slow
/// `UPDATE` must not become an outage at the token endpoint.
#[tokio::test]
async fn a_client_still_authenticates_when_the_use_cannot_be_recorded() {
    // Arrange
    let world = World::recording(
        ClientStatus::Active,
        "private_key_jwt",
        Arc::new(FakeUsage::broken()),
    );

    // Act
    let authenticated = world
        .authenticate_claims(&assertion_claims(CLIENT, ISSUER))
        .await;

    // Assert
    assert!(
        authenticated.is_ok(),
        "a failed usage write refused a client that authenticated"
    );
}

// ---- the trail a refusal leaves (`ast-4j1`) -------------------------------
//
// A client that cannot authenticate gets `invalid_client` and nothing else,
// which is RFC 6749 §5.2 and is right. The operator, however, was getting
// nothing else either: a PAR refused for a missing `client_assertion` wrote no
// log record at any level and no audit row, so "the BFF gets a 401 and the IdP
// says nothing" was the whole of the diagnosis available. These fix the
// asymmetry — the caller still learns one word, and this server writes down
// which of a dozen reasons it was.

/// Collects a subscriber's output for inspection.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
    }
}

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tracing_subscriber::fmt::MakeWriter<'_> for Captured {
    type Writer = Self;
    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// Runs `work` under the real redacting formatter and returns what was logged.
///
/// The formatter is the production one rather than a bare collector, because
/// half of what is asserted below is what the formatter *removes*. A test that
/// captured raw fields would pass while the deployed server wrote an assertion
/// into a log file.
fn captured_logs<F>(work: F) -> String
where
    F: FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>,
{
    use tracing_subscriber::layer::SubscriberExt as _;

    let sink = Captured::default();
    let subscriber = tracing_subscriber::Registry::default().with(
        tracing_subscriber::fmt::layer()
            .fmt_fields(asterius_server::observability::redact::RedactingFields)
            .with_ansi(false)
            .with_writer(sink.clone()),
    );
    // A current-thread runtime under `with_default`: the subscriber is a
    // thread-local, so a work-stealing runtime could move the future to a
    // thread that cannot see it and the capture would come back empty.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    tracing::subscriber::with_default(subscriber, || runtime.block_on(work()));
    sink.contents()
}

/// The reported bug, reduced: a PAR body with no `client_assertion` at all.
///
/// This is what the owner's BFF sent — `client_id`, `redirect_uri`, `scope`,
/// PKCE, and no credential of any kind. The 401 is correct. The silence was
/// not.
#[test]
fn an_absent_credential_is_logged_with_the_reason() {
    // Arrange
    let audit = Arc::new(FakeAudit::default());
    let sink = Arc::clone(&audit);

    // Act
    let logs = captured_logs(move || {
        Box::pin(async move {
            let world = World::auditing(sink);
            let refused = world.authenticate(&Attempt::default()).await;
            assert_eq!(refused.unwrap_err(), ClientAuthError::NoMethod);
        })
    });

    // Assert
    assert!(
        logs.contains("client authentication failed"),
        "a refusal wrote no log record: {logs}"
    );
    assert!(
        logs.contains("no_client_authentication_presented"),
        "the log did not say why: {logs}"
    );
}

/// The refusal is in the trail, not only in a log file nobody kept.
#[test]
fn an_absent_credential_is_audited() {
    // Arrange
    let audit = Arc::new(FakeAudit::default());
    let sink = Arc::clone(&audit);

    // Act
    let _ = captured_logs(move || {
        Box::pin(async move {
            let world = World::auditing(sink);
            let _ = world.authenticate(&Attempt::default()).await;
        })
    });

    // Assert
    let events = audit.events();
    assert_eq!(events.len(), 1, "expected one audit record, got {events:?}");
    assert_eq!(events[0].event_type, EventType::CLIENT_AUTH_FAILED);
    assert_eq!(events[0].outcome, Outcome::Failure);
}

/// The `aud` case, which is the one a client integrator gets wrong most often
/// — and the one that is impossible to diagnose from `invalid_client`. The
/// record carries both sides of the comparison.
#[test]
fn a_wrong_audience_is_logged_with_what_was_expected_and_what_arrived() {
    // Arrange
    let audit = Arc::new(FakeAudit::default());
    let mut claims = assertion_claims(CLIENT, ISSUER);
    claims["aud"] = serde_json::json!("https://as.example/t/demo/token");

    // Act
    let logs = captured_logs(move || {
        Box::pin(async move {
            let world = World::auditing(audit);
            let _ = world.authenticate_claims(&claims).await;
        })
    });

    // Assert
    assert!(
        logs.contains("aud_is_not_this_issuer"),
        "the reason was not named: {logs}"
    );
    assert!(
        logs.contains("https://as.example/t/demo/token"),
        "the received audience was not recorded: {logs}"
    );
    assert!(
        logs.contains(ISSUER),
        "the expected audience was not recorded: {logs}"
    );
}

/// A client this tenant does not have is named, so that "registered in the
/// wrong tenant" is a fact an operator can read rather than infer.
#[test]
fn an_unknown_client_is_logged_with_the_client_id_and_tenant() {
    // Arrange
    let audit = Arc::new(FakeAudit::default());
    let claims = assertion_claims("c.not-registered-here", ISSUER);

    // Act
    let logs = captured_logs(move || {
        Box::pin(async move {
            let world = World::auditing(audit);
            let _ = world.authenticate_claims(&claims).await;
        })
    });

    // Assert
    assert!(
        logs.contains("unknown_or_disabled_client"),
        "the reason was not named: {logs}"
    );
    assert!(
        logs.contains("c.not-registered-here"),
        "the client_id was not recorded: {logs}"
    );
    assert!(logs.contains("demo"), "the tenant was not recorded: {logs}");
}

/// The whole point of logging more is that it must not log *that*.
///
/// The assertion is a bearer credential for this server: a refusal that copied
/// it into a log line would turn a diagnostic improvement into a credential
/// store. Same for the audit record, which is kept far longer.
#[test]
fn the_refusal_record_never_carries_the_assertion() {
    // Arrange
    let audit = Arc::new(FakeAudit::default());
    let sink = Arc::clone(&audit);
    let mut claims = assertion_claims(CLIENT, ISSUER);
    claims["aud"] = serde_json::json!("https://somewhere.else/");
    let token = sign_with(&client_key().0, &claims);
    let signed = token.clone();

    // Act
    let logs = captured_logs(move || {
        Box::pin(async move {
            let world = World::auditing(sink);
            let _ = world.authenticate(&attempt_with(&token)).await;
        })
    });

    // Assert
    assert!(
        !logs.contains(&signed),
        "the assertion was written to the log: {logs}"
    );
    let signature = signed.rsplit('.').next().expect("signature");
    assert!(
        !logs.contains(signature),
        "the assertion's signature was written to the log: {logs}"
    );
    for event in audit.events() {
        let rendered = format!("{event:?}");
        assert!(
            !rendered.contains(&signed),
            "the assertion reached the audit trail: {rendered}"
        );
    }
}
