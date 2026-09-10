//! Account recovery, over HTTP, against the assembled application.
//!
//! # Why this is an application test and not a handler test
//!
//! `end_to_end.rs` makes the general argument. The specific one here is that
//! almost every property this ticket asks for lives *between* two requests:
//! the link produced by one is spent by another, the second spend of one link
//! happens after the first, and the sessions that must be gone were created
//! before any of it. None of that is reachable from a handler called with a
//! fixture.
//!
//! So every request below is an `http::Request` handed to `server::app`, the
//! cookie jar is the browser's, and the reset link is read out of the outbox
//! the journal mail sender wrote it to — which is exactly what a person's
//! mailbox would have contained, and the only place the token exists in the
//! clear.
//!
//! # What is tested here and what is tested in `store-pg`
//!
//! Here: the flow, the pages, the oracle, the sessions, the trail. The clock
//! is not injectable through HTTP, so the *expiry* rule and the atomicity of a
//! single-use spend are tested against the store directly, in
//! `asterius-store-pg`'s `database.rs`, where a caller passes `now`.
//!
//! # No JavaScript anywhere
//!
//! `ast-ndk.4` is the repository's baseline, and this is the flow an account
//! depends on when everything else has failed. One test asserts the rendered
//! pages carry no script at all; the rest simply never run one, because forms
//! are all there is.
//!
//! # Isolation
//!
//! As in `end_to_end.rs`: `asterius-server` has no `sqlx` dependency
//! (ADR-0001), so there is no raw SQL here and no per-test schema. A unique
//! tenant per test, nothing touched outside it, deleted at the end.

use asterius_domain::audit::AuditRecord;
use asterius_domain::entities::session::{Lifetimes, Session, SessionId, SessionStatus};
use asterius_domain::ports::{SessionRepository as _, TenantRepository as _};
use asterius_domain::{
    Argon2Parameters, AuthenticationMethod, Capabilities, ClaimSet, EndpointLimit, EndpointLimits,
    Issuer, LoginLimits, RateLimit, RecoveryToken, Secret, Tenant, TenantId, TenantStatus, User,
    UserId, UserStatus,
};
use asterius_jose::LocalKek;
use asterius_jose::kek::Kek;
use asterius_server::config::{ServerConfig, TransportMode};
use asterius_server::http::dpop::DpopEndpoint;
use asterius_server::http::protocol::{self, ClientEndpoints, ProtocolState};
use asterius_server::http::register::RegistrationPolicy;
use asterius_server::http::server::app;
use asterius_server::signing::CachedSigner;
use asterius_server::tenancy::{TenantDirectory, TenantState};
use asterius_server::tenant_settings::SettingsDirectory;
use asterius_store_pg::{
    PgAuditSink, PgOutboxMailSender, PgPasswordVerifier, PgReplayGuard, PgSessionRepository,
    PgTenantRepository, PgTenantSettings, PgUserRepository, Store, TenantKeyStore,
};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use time::OffsetDateTime;
use tower::ServiceExt as _;

static COUNTER: AtomicU32 = AtomicU32::new(0);

const HOST: &str = "as.example";
/// The address on the account, and the one a link is sent to.
const ADDRESS: &str = "person@example.test";
/// An address this tenant has never heard of. The request page must answer for
/// it exactly as it answers for [`ADDRESS`].
const STRANGER: &str = "nobody@example.test";
/// Past the NIST SP 800-63B §5.1.1.2 floor, and not on the deny list
/// `AcceptedPassword::accept_locally` compiles in.
const NEW_PASSWORD: &str = "a rather long and unremarkable passphrase";

/// What came back.
struct Reply {
    status: StatusCode,
    body: String,
    set_cookies: Vec<String>,
}

/// A browser talking to one assembled server.
struct Flow {
    app: Router,
    store: Store,
    kek: Arc<dyn Kek>,
    tenant: Tenant,
    user: UserId,
    jar: BTreeMap<String, String>,
}

impl Flow {
    /// `None` without `DATABASE_URL`, so the default suite stays fast.
    async fn new() -> Option<Self> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let store = Store::connect(&url, 4)
            .await
            .expect("DATABASE_URL is set but unreachable; is `docker compose up -d db` running?");
        store.migrate().await.expect("migrate");

        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[7_u8; 32]).expect("a 32-byte KEK"));
        let now = OffsetDateTime::now_utc();
        let id = format!(
            "rec-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tenant = Tenant {
            id: TenantId::parse(&id).expect("a generated tenant id"),
            issuer: Issuer::parse(&format!("https://{HOST}/t/{id}")).expect("an issuer"),
            custom_host: None,
            display_name: "Recovery".to_owned(),
            default_resource: "https://api.example/".to_owned(),
            status: TenantStatus::Active,
            refresh: asterius_domain::RefreshPolicy::default(),
            created_at: now,
            updated_at: now,
        };
        PgTenantRepository::new(store.pool().clone(), Arc::clone(&kek))
            .upsert(&tenant)
            .await
            .expect("create the tenant");

        let audit = Arc::new(PgAuditSink::new(store.pool().clone()));
        let keys = TenantKeyStore::new(
            store.pool().clone(),
            Arc::clone(&kek),
            Arc::clone(&audit) as Arc<dyn asterius_domain::AuditSink>,
        );
        keys.apply_schedule(&tenant.id, now)
            .await
            .expect("prepare signing keys");

        let user = UserId::generate();
        PgUserRepository::new(store.pool().clone(), tenant.id.clone(), Arc::clone(&kek))
            .upsert(&User {
                tenant: tenant.id.clone(),
                id: user,
                username: user.as_uuid().to_string(),
                email: Some(ADDRESS.to_owned()),
                email_verified: true,
                status: UserStatus::Active,
                claims: ClaimSet::default(),
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("store the user");

        let settings =
            SettingsDirectory::new(Arc::new(PgTenantSettings::new(store.pool().clone())));
        Some(Self {
            app: assemble(&store, &kek, &keys, audit, settings),
            store,
            kek,
            tenant,
            user,
            jar: BTreeMap::new(),
        })
    }

    fn prefix(&self) -> String {
        format!("/t/{}", self.tenant.id.as_str())
    }

    /// Sends one request, applying and updating the cookie jar.
    async fn send(&mut self, mut request: Request<Body>) -> Reply {
        if !self.jar.is_empty() {
            let cookies = self
                .jar
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            request.headers_mut().insert(
                header::COOKIE,
                cookies.parse().expect("a cookie header value"),
            );
        }
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the application answered");
        let status = response.status();
        let set_cookies: Vec<String> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_owned)
            .collect();
        for cookie in &set_cookies {
            let pair = cookie.split(';').next().unwrap_or_default();
            if let Some((name, value)) = pair.split_once('=') {
                if value.is_empty() || cookie.contains("Max-Age=0") {
                    self.jar.remove(name);
                } else {
                    self.jar.insert(name.to_owned(), value.to_owned());
                }
            }
        }
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("a body");
        Reply {
            status,
            body: String::from_utf8_lossy(&body).into_owned(),
            set_cookies,
        }
    }

    async fn get(&mut self, path: &str) -> Reply {
        let request = Request::builder()
            .method("GET")
            .uri(format!("{}{path}", self.prefix()))
            .header(header::HOST, HOST)
            .body(Body::empty())
            .expect("a request");
        self.send(request).await
    }

    async fn post(&mut self, path: &str, form: &[(&str, &str)]) -> Reply {
        let body = form
            .iter()
            .map(|(key, value)| {
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair(key, value)
                    .finish()
            })
            .collect::<Vec<_>>()
            .join("&");
        let request = Request::builder()
            .method("POST")
            .uri(format!("{}{path}", self.prefix()))
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .expect("a request");
        self.send(request).await
    }

    /// Walks the request half and returns the link the mailbox received.
    ///
    /// Out of the outbox, because that is where the journal sender put it, and
    /// because a test that read `recovery_tokens` would be reading a digest —
    /// which is the whole point of storing a digest.
    async fn request_a_link(&mut self, address: &str) -> Option<String> {
        let page = self.get("/recovery").await;
        assert_eq!(page.status, StatusCode::OK);
        let csrf = csrf_from(&page.body);
        let sent = self
            .post("/recovery", &[("csrf", &csrf), ("email", address)])
            .await;
        assert_eq!(sent.status, StatusCode::OK);
        self.latest_link().await
    }

    /// The journal, as an operator would read it.
    async fn queued(&self) -> Vec<asterius_store_pg::QueuedNotification> {
        PgOutboxMailSender::new(self.store.pool().clone(), self.tenant.id.clone())
            .queued()
            .await
            .expect("read the outbox")
    }

    /// The most recent recovery link this tenant's outbox holds.
    async fn latest_link(&self) -> Option<String> {
        self.queued()
            .await
            .into_iter()
            .rfind(|message| message.kind == "account_recovery")
            .and_then(|message| {
                message
                    .payload
                    .get("link")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
    }

    /// How many queued messages of one kind.
    async fn queued_count(&self, kind: &str) -> usize {
        self.queued()
            .await
            .into_iter()
            .filter(|message| message.kind == kind)
            .count()
    }

    /// The audit trail, through the reader the console uses.
    async fn trail(&self) -> Vec<AuditRecord> {
        PgAuditSink::new(self.store.pool().clone())
            .read_trail(&self.tenant.id)
            .await
            .expect("read the trail")
    }

    /// How many records of one event type.
    async fn audit_count(&self, event_type: &str) -> usize {
        self.trail()
            .await
            .into_iter()
            .filter(|record| {
                record
                    .event()
                    .is_some_and(|event| event.event_type.as_str() == event_type)
            })
            .count()
    }

    /// Walks the use half: opens the link, fills the form, posts it.
    async fn use_the_link(&mut self, link: &str, password: &str) -> Reply {
        let page = self.get(&path_and_query(link)).await;
        if page.status != StatusCode::OK {
            return page;
        }
        let csrf = csrf_from(&page.body);
        let token = hidden_field(&page.body, "token");
        self.post(
            "/recovery/new",
            &[
                ("csrf", &csrf),
                ("token", &token),
                ("password", password),
                ("password_confirmation", password),
            ],
        )
        .await
    }

    /// Whether the tenant's own verifier — the one the login form uses —
    /// accepts this password for the account.
    async fn password_works(&self, password: &str) -> bool {
        let verifier = PgPasswordVerifier::new(
            self.store.pool().clone(),
            self.tenant.id.clone(),
            Argon2Parameters::default(),
        )
        .expect("a verifier");
        asterius_domain::CredentialVerifier::verify(
            &verifier,
            &self.user.as_uuid().to_string(),
            Secret::new(password.to_owned()),
        )
        .await
        .expect("the verifier answered")
            == Some(*self.user.as_uuid())
    }

    /// Starts a session for the account and answers with its digest.
    async fn begin_session(&self, now: OffsetDateTime) -> String {
        let id = SessionId::generate();
        let session = Session::begin(
            self.tenant.id.clone(),
            &id,
            *self.user.as_uuid(),
            vec![AuthenticationMethod::Password],
            now,
            Lifetimes::default().clamped(),
        );
        let digest = session.id_digest.clone();
        PgSessionRepository::new(self.store.pool().clone(), self.tenant.id.clone())
            .begin(&session)
            .await
            .expect("begin a session");
        digest
    }

    /// Whether a session is still usable.
    async fn session_is_active(&self, digest: &str) -> bool {
        PgSessionRepository::new(self.store.pool().clone(), self.tenant.id.clone())
            .find(digest)
            .await
            .expect("read the session")
            .is_some_and(|session| {
                session.status(OffsetDateTime::now_utc()) == SessionStatus::Active
            })
    }

    /// Deletes the tenant, and by cascade everything under it.
    async fn cleanup(&self) {
        PgTenantRepository::new(self.store.pool().clone(), Arc::clone(&self.kek))
            .delete(&self.tenant.id)
            .await
            .expect("drop the tenant");
    }
}

/// The application, assembled the way the binary assembles it.
fn assemble(
    store: &Store,
    kek: &Arc<dyn Kek>,
    keys: &TenantKeyStore,
    audit: Arc<PgAuditSink>,
    settings: SettingsDirectory,
) -> Router {
    let config = ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address"),
        mode: TransportMode::BehindProxy,
        tls: None,
        trusted_proxies: Vec::new(),
        request_body_limit: 64 * 1024,
        request_timeout: std::time::Duration::from_secs(30),
    };

    let key_store: Arc<dyn asterius_domain::KeyStore> = Arc::new(keys.clone());
    let signer: Arc<dyn asterius_domain::keys::Signer> = Arc::new(CachedSigner::new(
        keys.clone(),
        Arc::new(asterius_domain::ports::SystemClock),
    ));
    let outbound: Arc<dyn asterius_domain::ports::ClientUrlFetcher> = Arc::new(NoFetching);
    let replay: Arc<dyn asterius_domain::ReplayGuard> =
        Arc::new(PgReplayGuard::new(store.pool().clone()));
    let authenticator = Arc::new(
        asterius_server::client_auth::ClientAuthenticator::new(
            Arc::new(asterius_jose::client_keys::ClientKeyCache::new(Arc::clone(
                &outbound,
            ))),
            Arc::clone(&replay),
        )
        .expect("a client authenticator"),
    );
    let dpop = Arc::new(
        DpopEndpoint::for_capabilities(Arc::clone(&replay), &Capabilities::default(), None)
            .expect("a DPoP endpoint"),
    );

    let routes = protocol::routes(ProtocolState {
        keys: Arc::clone(&key_store),
        capabilities: Capabilities::default(),
        tenant_settings: Some(settings.clone()),
        clients: Some(Arc::new(ClientEndpoints {
            initial_access_tokens: None,
            authenticator,
            store: store.clone(),
            keys: key_store,
            capabilities: Capabilities::default(),
            par_lifetime: time::Duration::seconds(90),
            tenant_settings: Some(settings),
            lifetimes: asterius_domain::TokenLifetimes::default(),
            kek: Arc::clone(kek),
            registration: RegistrationPolicy::Closed,
            outbound,
            audit,
            session_lifetimes: Lifetimes::default().clamped(),
            argon2: Some(Argon2Parameters::default()),
            login_limits: generous_login_limits(),
            endpoint_limits: generous_endpoint_limits(),
            signer,
            dpop,
            // Account recovery does not queue outbox rows through this field;
            // the back-channel logout path is `end_to_end.rs`'s.
            outbox: None,
        })),
    });

    let directory = TenantDirectory::new(Arc::new(PgTenantRepository::new(
        store.pool().clone(),
        Arc::clone(kek),
    )));
    app(routes, TenantState::new(directory, &config), None, &config)
}

/// Never called. Loud rather than silent, so a test that reached the network
/// fails instead of hanging.
#[derive(Debug)]
struct NoFetching;

#[async_trait::async_trait]
impl asterius_domain::ports::ClientUrlFetcher for NoFetching {
    async fn fetch(&self, _url: &str) -> Result<Vec<u8>, asterius_domain::DomainError> {
        panic!("a test reached the network");
    }
}

fn generous_login_limits() -> LoginLimits {
    let limit = RateLimit {
        max: 1_000,
        window: time::Duration::minutes(15),
    };
    LoginLimits {
        per_address: limit,
        per_account: limit,
    }
}

fn generous_endpoint_limits() -> EndpointLimits {
    let limit = EndpointLimit {
        per_address: RateLimit {
            max: 1_000,
            window: time::Duration::minutes(15),
        },
        per_client: None,
    };
    EndpointLimits {
        registration: limit,
        client_configuration: limit,
        par: limit,
        token: limit,
        userinfo: limit,
    }
}

/// The `csrf` field of the form this server just rendered.
fn csrf_from(html: &str) -> String {
    hidden_field(html, "csrf")
}

/// One hidden field's value, read out of the HTML — the only copy a browser
/// has. A test that took it from the database would pass against a page that
/// never rendered one.
fn hidden_field(html: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no {name} field in the rendered page:\n{html}"))
        + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("the value is quoted");
    rest[..end].to_owned()
}

/// The page with its CSP nonces blanked out.
///
/// The nonce is drawn per response and must differ between any two responses —
/// that is what makes it a nonce — so two renderings of one page are never
/// byte-identical as they stand. Blanking it is the smallest normalisation
/// that leaves the property under test intact: everything else about the two
/// answers, including their length once the nonces are the same width, still
/// has to match. A test that compared whole bodies would be asserting the
/// nonce is *not* random.
fn without_nonces(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find(r#"nonce=""#) {
        out.push_str(&rest[..start]);
        out.push_str("nonce=");
        let after = &rest[start + r#"nonce=""#.len()..];
        let end = after.find('"').expect("the nonce is quoted");
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// The part of an absolute link that follows the tenant prefix.
///
/// `Flow::get` puts the prefix back, so taking it off here keeps the helper
/// honest: if the link ever stopped carrying the prefix, the dedicated test
/// for that is what would fail, not every test in the file.
fn path_and_query(link: &str) -> String {
    let after_scheme = link.split_once("://").map_or(link, |(_, rest)| rest);
    let path = after_scheme
        .find('/')
        .map_or("/", |index| &after_scheme[index..]);
    path.split_once("/recovery")
        .map_or_else(|| path.to_owned(), |(_, rest)| format!("/recovery{rest}"))
}

macro_rules! flow {
    () => {
        match Flow::new().await {
            Some(flow) => flow,
            None => {
                eprintln!("skipping: DATABASE_URL is not set");
                return;
            }
        }
    };
}

// ---- the request half ----------------------------------------------------

/// **The oracle test.** OWASP's Forgot Password Cheat Sheet, and RFC 9700 §4:
/// the answer to a reset request must not say whether the address has an
/// account. Not "the same message" — the same bytes, because a different page,
/// a different length or a different status would say it just as loudly.
#[tokio::test]
async fn a_request_answers_identically_for_a_known_and_an_unknown_address() {
    // Arrange
    let mut flow = flow!();

    // Act
    let page = flow.get("/recovery").await;
    let csrf = csrf_from(&page.body);
    let known = flow
        .post("/recovery", &[("csrf", &csrf), ("email", ADDRESS)])
        .await;

    let page = flow.get("/recovery").await;
    let csrf = csrf_from(&page.body);
    let unknown = flow
        .post("/recovery", &[("csrf", &csrf), ("email", STRANGER)])
        .await;

    // Assert
    assert_eq!(known.status, unknown.status);
    assert_eq!(without_nonces(&known.body), without_nonces(&unknown.body));
    flow.cleanup().await;
}

/// The other half of the same property: an address with an account produces a
/// message and one without produces none. Without this, the test above could
/// be passing because nothing ever happens.
#[tokio::test]
async fn only_a_known_address_produces_a_message() {
    // Arrange
    let mut flow = flow!();

    // Act
    let stranger = flow.request_a_link(STRANGER).await;
    let known = flow.request_a_link(ADDRESS).await;

    // Assert
    assert_eq!(stranger, None);
    assert!(known.is_some_and(|link| link.contains("/recovery/new?token=")));
    flow.cleanup().await;
}

/// Every request is recorded, including the ones that match nobody. A trail
/// that recorded only the matching ones would be the enumeration oracle the
/// page refuses to be, moved into the database.
#[tokio::test]
async fn every_request_is_recorded_whether_or_not_it_matched() {
    // Arrange
    let mut flow = flow!();

    // Act
    flow.request_a_link(STRANGER).await;
    flow.request_a_link(ADDRESS).await;

    // Assert
    assert_eq!(flow.audit_count("recovery.requested").await, 2);
    assert_eq!(flow.audit_count("recovery.sent").await, 1);
    flow.cleanup().await;
}

/// A cross-site POST arrives with no `SameSite=Lax` cookie, so it cannot carry
/// a matching synchroniser token. It must not send mail — otherwise any page
/// on the internet is a button that mails somebody a reset link.
#[tokio::test]
async fn a_request_without_the_synchroniser_cookie_sends_nothing() {
    // Arrange
    let mut flow = flow!();
    let page = flow.get("/recovery").await;
    let csrf = csrf_from(&page.body);
    flow.jar.clear();

    // Act
    let answered = flow
        .post("/recovery", &[("csrf", &csrf), ("email", ADDRESS)])
        .await;

    // Assert
    assert_eq!(answered.status, StatusCode::OK);
    assert_eq!(flow.latest_link().await, None);
    flow.cleanup().await;
}

// ---- the use half --------------------------------------------------------

/// The whole flow: ask, follow the link, choose a password, and have it be the
/// password the login form's own verifier accepts.
#[tokio::test]
async fn a_mailed_link_sets_a_password_the_verifier_accepts() {
    // Arrange
    let mut flow = flow!();
    let link = flow
        .request_a_link(ADDRESS)
        .await
        .expect("a link was produced");

    // Act
    let done = flow.use_the_link(&link, NEW_PASSWORD).await;

    // Assert
    assert_eq!(done.status, StatusCode::SEE_OTHER);
    assert!(flow.password_works(NEW_PASSWORD).await);
    assert_eq!(flow.audit_count("recovery.used").await, 1);
    assert_eq!(flow.audit_count("credential.changed").await, 1);
    flow.cleanup().await;
}

/// Single use, over HTTP. The second presentation of one link is refused and
/// the password it named is not written.
#[tokio::test]
async fn a_link_cannot_be_used_twice() {
    // Arrange
    let mut flow = flow!();
    let link = flow
        .request_a_link(ADDRESS)
        .await
        .expect("a link was produced");
    flow.use_the_link(&link, NEW_PASSWORD).await;

    // Act
    let again = flow
        .use_the_link(&link, "a completely different passphrase")
        .await;

    // Assert
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert!(flow.password_works(NEW_PASSWORD).await);
    flow.cleanup().await;
}

/// A second request supersedes the first. Two live links in one mailbox is two
/// account takeovers, and the one nobody used is the one nobody would notice
/// being used.
#[tokio::test]
async fn asking_again_kills_the_earlier_link() {
    // Arrange
    let mut flow = flow!();
    let first = flow.request_a_link(ADDRESS).await.expect("a first link");
    let second = flow.request_a_link(ADDRESS).await.expect("a second link");
    assert_ne!(first, second);

    // Act
    let refused = flow.use_the_link(&first, NEW_PASSWORD).await;

    // Assert
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(!flow.password_works(NEW_PASSWORD).await);
    flow.cleanup().await;
}

/// Every other session goes. Two of them, so that "every" is tested rather
/// than "the one".
#[tokio::test]
async fn a_recovery_ends_every_session_the_account_had() {
    // Arrange
    let mut flow = flow!();
    let now = OffsetDateTime::now_utc();
    let first = flow.begin_session(now).await;
    let second = flow.begin_session(now).await;
    let link = flow
        .request_a_link(ADDRESS)
        .await
        .expect("a link was produced");

    // Act
    flow.use_the_link(&link, NEW_PASSWORD).await;

    // Assert
    assert!(!flow.session_is_active(&first).await);
    assert!(!flow.session_is_active(&second).await);
    flow.cleanup().await;
}

/// The person is told their credentials changed. OWASP asks for it, and it is
/// how somebody learns their account was taken while they could still act.
#[tokio::test]
async fn a_completed_recovery_notifies_the_account() {
    // Arrange
    let mut flow = flow!();
    let link = flow
        .request_a_link(ADDRESS)
        .await
        .expect("a link was produced");

    // Act
    flow.use_the_link(&link, NEW_PASSWORD).await;

    // Assert
    assert_eq!(flow.queued_count("credential_changed").await, 1);
    flow.cleanup().await;
}

/// A password the policy refuses does not spend the link. Somebody who typed
/// `password123` gets another go, not a fifteen-minute wait.
#[tokio::test]
async fn a_refused_password_does_not_spend_the_link() {
    // Arrange
    let mut flow = flow!();
    let link = flow
        .request_a_link(ADDRESS)
        .await
        .expect("a link was produced");

    // Act
    let refused = flow.use_the_link(&link, "password").await;
    let accepted = flow.use_the_link(&link, NEW_PASSWORD).await;

    // Assert
    assert_eq!(refused.status, StatusCode::OK);
    assert_eq!(accepted.status, StatusCode::SEE_OTHER);
    assert!(flow.password_works(NEW_PASSWORD).await);
    flow.cleanup().await;
}

/// Two entries that do not match is a typo, not a reset, and it must not spend
/// the link either.
#[tokio::test]
async fn a_mistyped_confirmation_does_not_spend_the_link() {
    // Arrange
    let mut flow = flow!();
    let link = flow
        .request_a_link(ADDRESS)
        .await
        .expect("a link was produced");
    let page = flow.get(&path_and_query(&link)).await;
    let csrf = csrf_from(&page.body);
    let token = hidden_field(&page.body, "token");

    // Act
    let mismatched = flow
        .post(
            "/recovery/new",
            &[
                ("csrf", &csrf),
                ("token", &token),
                ("password", NEW_PASSWORD),
                ("password_confirmation", "something else entirely"),
            ],
        )
        .await;
    let accepted = flow.use_the_link(&link, NEW_PASSWORD).await;

    // Assert
    assert_eq!(mismatched.status, StatusCode::OK);
    assert_eq!(accepted.status, StatusCode::SEE_OTHER);
    flow.cleanup().await;
}

/// A token nobody issued is refused, and refusing it is recorded.
#[tokio::test]
async fn a_token_nobody_issued_is_refused() {
    // Arrange
    let mut flow = flow!();
    let invented = RecoveryToken::generate();

    // Act
    let refused = flow
        .get(&format!("/recovery/new?token={}", invented.expose()))
        .await;

    // Assert
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(flow.audit_count("recovery.refused").await, 1);
    flow.cleanup().await;
}

/// A token that is not even the right shape never reaches the database.
#[tokio::test]
async fn a_malformed_token_is_refused() {
    // Arrange
    let mut flow = flow!();

    // Act
    let refused = flow.get("/recovery/new?token=nonsense").await;

    // Assert
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    flow.cleanup().await;
}

// ---- the baseline --------------------------------------------------------

/// `ast-ndk.4`: the pages work with no JavaScript, and the way to be sure is
/// that there is none to run. This is the flow an account depends on when
/// everything else has failed; it must not need a script engine.
#[tokio::test]
async fn no_page_in_the_flow_carries_a_script() {
    // Arrange
    let mut flow = flow!();

    // Act
    let request = flow.get("/recovery").await;
    let csrf = csrf_from(&request.body);
    let sent = flow
        .post("/recovery", &[("csrf", &csrf), ("email", ADDRESS)])
        .await;
    let link = flow.latest_link().await.expect("a link was produced");
    let new_password = flow.get(&path_and_query(&link)).await;

    // Assert
    for page in [&request, &sent, &new_password] {
        assert!(
            !page.body.contains("<script"),
            "a recovery page carried a script:\n{}",
            page.body
        );
    }
    flow.cleanup().await;
}

/// The synchroniser cookie is `__Host-` prefixed with the attributes the
/// prefix requires. Asserted on the wire rather than on the helper, because
/// what a browser enforces is what it received.
#[tokio::test]
async fn the_synchroniser_cookie_is_host_prefixed() {
    // Arrange
    let mut flow = flow!();

    // Act
    let page = flow.get("/recovery").await;

    // Assert
    let cookie = page
        .set_cookies
        .iter()
        .find(|value| value.starts_with("__Host-asterius_rc="))
        .expect("the recovery synchroniser cookie");
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Lax"));
    assert!(!cookie.contains("Domain="));
    flow.cleanup().await;
}

/// The link a person receives goes back through the prefix their tenant is
/// mounted under (`ast-295`). A link to `/recovery/new` at the host root is a
/// 404 for every path-mounted tenant.
#[tokio::test]
async fn the_mailed_link_carries_the_mount_prefix() {
    // Arrange
    let mut flow = flow!();

    // Act
    let link = flow
        .request_a_link(ADDRESS)
        .await
        .expect("a link was produced");

    // Assert
    assert!(
        link.contains(&format!("/t/{}/recovery/new", flow.tenant.id.as_str())),
        "the link did not carry the mount prefix: {link}"
    );
    flow.cleanup().await;
}
