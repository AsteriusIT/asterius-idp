//! Email verification, over HTTP, against the assembled application.
//!
//! # Why this is an application test and not a handler test
//!
//! The same argument `recovery.rs` makes: every property worth asserting here
//! lives *between* two requests. The link produced by one is spent by another;
//! the second spend happens after the first; the address that moved out from
//! under a link moved between the two. None of that is reachable from a
//! handler called with a fixture.
//!
//! So every request below is an `http::Request` handed to `server::app`, the
//! cookie jar is the browser's, and the confirmation link is read out of the
//! outbox the journal mail sender wrote it to — which is exactly what a
//! person's mailbox would have contained, and the only place the token exists
//! in the clear.
//!
//! # What is tested here and what is tested elsewhere
//!
//! Here: the flow, the pages, the oracle, the trail, and the attack the stored
//! address exists to stop. The clock is not injectable through HTTP, so the
//! fifteen-minute rule and the atomicity of a single-use spend are asserted
//! against the store in `asterius-store-pg`'s `database.rs`, where a caller
//! passes `now`. The sign-in gate's *decision* is a unit test in
//! `asterius_server::http::verify_email`, because it is a decision taken
//! before a session exists and with no database in the way.
//!
//! # No JavaScript anywhere
//!
//! `ast-ndk.4` is the repository's baseline. One test asserts the rendered
//! pages carry no script at all; the rest simply never run one, because a link
//! and a button are all there is.
//!
//! # Isolation
//!
//! As in `recovery.rs`: a unique tenant per test, nothing touched outside it,
//! deleted at the end.

use asterius_domain::audit::AuditRecord;
use asterius_domain::entities::session::Lifetimes;
use asterius_domain::ports::{TenantRepository as _, UserDirectory as _};
use asterius_domain::{
    Argon2Parameters, Capabilities, ClaimSet, EndpointLimit, EndpointLimits, Issuer, LoginLimits,
    RateLimit, Tenant, TenantId, TenantStatus, User, UserId, UserStatus,
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
    PgAuditSink, PgOutboxMailSender, PgReplayGuard, PgTenantRepository, PgTenantSettings,
    PgUserRepository, Store, TenantKeyStore,
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
/// An address this tenant has never heard of. The resend must answer for it
/// exactly as it answers for [`ADDRESS`].
const STRANGER: &str = "nobody@example.test";
/// The mailbox an attacker would like a proof moved onto.
const VICTIM: &str = "victim@bank.test";

/// What came back.
struct Reply {
    status: StatusCode,
    body: String,
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

        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[9_u8; 32]).expect("a 32-byte KEK"));
        let now = OffsetDateTime::now_utc();
        let id = format!(
            "ver-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tenant = Tenant {
            id: TenantId::parse(&id).expect("a generated tenant id"),
            issuer: Issuer::parse(&format!("https://{HOST}/t/{id}")).expect("an issuer"),
            custom_host: None,
            display_name: "Verification".to_owned(),
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
        let flow = Self {
            app: assemble(
                &store,
                &kek,
                &keys,
                audit,
                SettingsDirectory::new(Arc::new(PgTenantSettings::new(store.pool().clone()))),
            ),
            store,
            kek,
            tenant,
            user,
            jar: BTreeMap::new(),
        };
        // Unconfirmed, which is what a self-service sign-up produces and what
        // every test here starts from.
        flow.write_account(Some(ADDRESS), false).await;
        Some(flow)
    }

    /// Writes the account this flow is about, in whatever state a test needs.
    async fn write_account(&self, email: Option<&str>, verified: bool) {
        let now = OffsetDateTime::now_utc();
        self.users()
            .upsert(&User {
                tenant: self.tenant.id.clone(),
                id: self.user,
                username: self.user.as_uuid().to_string(),
                email: email.map(str::to_owned),
                email_verified: verified,
                status: UserStatus::Active,
                claims: ClaimSet::default(),
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("store the user");
    }

    fn users(&self) -> PgUserRepository {
        PgUserRepository::new(
            self.store.pool().clone(),
            self.tenant.id.clone(),
            Arc::clone(&self.kek),
        )
    }

    /// Whether the account's address is confirmed, read back through the
    /// directory rather than from anything the page said.
    async fn is_confirmed(&self) -> bool {
        self.users()
            .by_id(self.user)
            .await
            .expect("read the account")
            .expect("the account exists")
            .email_verified
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

    /// Asks for a link the way the page's button does, and returns what the
    /// mailbox received.
    ///
    /// The synchroniser cookie is obtained by rendering a page that issues
    /// one. There is no `GET /verify-email` without a token — the waiting page
    /// is produced by the gate or by this POST — so the first request here
    /// deliberately fails its CSRF check and is answered with a fresh form,
    /// which is the state a browser that lost its cookie would be in.
    async fn ask_for_a_link(&mut self, address: &str) -> Option<String> {
        let form = self.post("/verify-email", &[("email", address)]).await;
        assert_eq!(form.status, StatusCode::OK);
        let csrf = csrf_from(&form.body);
        let sent = self
            .post("/verify-email", &[("csrf", &csrf), ("email", address)])
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

    /// The most recent confirmation link this tenant's outbox holds.
    async fn latest_link(&self) -> Option<String> {
        self.queued()
            .await
            .into_iter()
            .rfind(|message| message.kind == "email_verification")
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

    /// Follows a link the way a mail client would: a top-level GET.
    async fn follow(&mut self, link: &str) -> Reply {
        let path = path_and_query(link);
        self.get(&path).await
    }

    /// Deletes the tenant, and by cascade everything under it.
    async fn cleanup(&self) {
        PgTenantRepository::new(self.store.pool().clone(), Arc::clone(&self.kek))
            .delete(&self.tenant.id)
            .await
            .expect("drop the tenant");
    }
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
        signed_metadata: None,
        clients: Some(Arc::new(ClientEndpoints {
            // `ast-lh3.10`: no policy decision point, which is what a
            // deployment with `[features] authzen` off wires. Agents are
            // bounded by their registration and nothing here is consulted.
            issuance: None,
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
            // Verification does not queue outbox rows through this field; the
            // journal mail sender writes its own.
            outbox: None,
        })),
    });

    let directory = TenantDirectory::new(Arc::new(PgTenantRepository::new(
        store.pool().clone(),
        Arc::clone(kek),
    )));
    app(routes, TenantState::new(directory, &config), None, &config)
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
        per_subject: None,
    };
    EndpointLimits {
        registration: limit,
        client_configuration: limit,
        par: limit,
        token: limit,
        userinfo: limit,
        ssf_subjects: limit,
        // Generous here too, and present rather than absent: a fixture that
        // left `/bc-authorize` without a subject bucket would be a fixture
        // that could not notice `ast-5lw` regressing.
        backchannel: EndpointLimit {
            per_subject: Some(RateLimit {
                max: 1_000,
                window: time::Duration::minutes(15),
            }),
            ..limit
        },
        access_evaluation: limit,
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
/// that leaves the property under test intact.
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

/// The same page with the synchroniser token blanked too.
///
/// A fresh token per rendering is the other per-response value, and two
/// answers that must be identical are identical *apart from* the two values
/// that are required to differ.
fn comparable(html: &str) -> String {
    const MARKER: &str = r#"name="csrf" value=""#;
    // Rebuilt front to back rather than edited in place: blanking the value
    // leaves the marker exactly where it was, so a loop that searched the
    // whole string again would find the same one for ever.
    let mut out = String::new();
    let mut rest = without_nonces(html);
    while let Some(start) = rest.find(MARKER) {
        let head = start + MARKER.len();
        let end = rest[head..].find('"').expect("the value is quoted") + head;
        out.push_str(&rest[..head]);
        rest = rest[end..].to_owned();
    }
    out.push_str(&rest);
    out
}

/// The path and query of an absolute link, with the tenant prefix removed —
/// the caller adds it back, like a browser following the URL would.
fn path_and_query(link: &str) -> String {
    let after_scheme = link.split_once("://").map_or(link, |(_, rest)| rest);
    let path = after_scheme
        .find('/')
        .map_or("/", |index| &after_scheme[index..]);
    path.split_once("/verify-email").map_or_else(
        || path.to_owned(),
        |(_, rest)| format!("/verify-email{rest}"),
    )
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

// ---- the happy path ------------------------------------------------------

/// The whole point: a link that arrives in a mailbox confirms the address it
/// was sent to, and `email_verified` — OIDC Core §5.1 — becomes true.
#[tokio::test]
async fn following_a_link_confirms_the_address() {
    // Arrange
    let mut flow = flow!();
    let link = flow.ask_for_a_link(ADDRESS).await.expect("a link was sent");
    assert!(!flow.is_confirmed().await, "the fixture starts unconfirmed");

    // Act
    let page = flow.follow(&link).await;

    // Assert
    assert_eq!(page.status, StatusCode::OK);
    assert!(flow.is_confirmed().await);
    assert_eq!(flow.audit_count("email_verification.verified").await, 1);
    flow.cleanup().await;
}

/// **A confirmation is not an authentication.** Following a link must not hand
/// the browser a session: it proves a mailbox, and the person still has to
/// sign in with something they know or hold. This is the escalation the whole
/// module is shaped to prevent, so it is asserted on the wire.
#[tokio::test]
async fn following_a_link_does_not_sign_anybody_in() {
    // Arrange
    let mut flow = flow!();
    let link = flow.ask_for_a_link(ADDRESS).await.expect("a link was sent");

    // Act
    flow.follow(&link).await;

    // Assert
    assert!(
        !flow.jar.keys().any(|name| name.contains("session")),
        "a confirmation produced a session cookie: {:?}",
        flow.jar
    );
    flow.cleanup().await;
}

/// **Single use, over HTTP.** The second time a link is followed it is refused
/// rather than quietly re-confirming, so a link that leaked from an archive is
/// not a standing assertion about that mailbox.
#[tokio::test]
async fn a_link_works_once() {
    // Arrange
    let mut flow = flow!();
    let link = flow.ask_for_a_link(ADDRESS).await.expect("a link was sent");
    let first = flow.follow(&link).await;
    assert_eq!(first.status, StatusCode::OK);

    // Act
    let second = flow.follow(&link).await;

    // Assert
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
    assert_eq!(flow.audit_count("email_verification.refused").await, 1);
    flow.cleanup().await;
}

/// A token nobody issued is refused, and refused the same way a spent one is.
#[tokio::test]
async fn a_token_nobody_issued_is_refused() {
    // Arrange
    let mut flow = flow!();
    let invented = asterius_domain::EmailVerificationToken::generate();

    // Act
    let page = flow
        .get(&format!("/verify-email?token={}", invented.expose()))
        .await;

    // Assert
    assert_eq!(page.status, StatusCode::BAD_REQUEST);
    assert!(!flow.is_confirmed().await);
    flow.cleanup().await;
}

/// A malformed token costs a length check and not an index probe: the parser
/// runs before any database work, and its refusal looks like every other.
#[tokio::test]
async fn a_malformed_token_is_refused_like_any_other() {
    // Arrange
    let mut flow = flow!();

    // Act
    let page = flow.get("/verify-email?token=not-a-token").await;

    // Assert
    assert_eq!(page.status, StatusCode::BAD_REQUEST);
    flow.cleanup().await;
}

// ---- the attack the stored address exists for ----------------------------

/// **The change-address attack.** Ask for a link at a mailbox you control,
/// change the address on the account, then follow the link. The flag must not
/// land on the new mailbox — the token proved the old one and nothing else.
///
/// This is the reason `email_verification_tokens` has an `address` column, and
/// it is the test that would fail if somebody "simplified" the row away.
#[tokio::test]
async fn a_link_does_not_confirm_an_address_it_was_not_sent_to() {
    // Arrange
    let mut flow = flow!();
    let link = flow.ask_for_a_link(ADDRESS).await.expect("a link was sent");
    // The account moves to a mailbox nobody has proved.
    flow.write_account(Some(VICTIM), false).await;

    // Act
    let page = flow.follow(&link).await;

    // Assert
    assert_eq!(page.status, StatusCode::BAD_REQUEST);
    assert!(
        !flow.is_confirmed().await,
        "a proof about one mailbox confirmed another"
    );
    assert_eq!(flow.audit_count("email_verification.refused").await, 1);
    flow.cleanup().await;
}

/// The other half of the same guard: drawing a new link retires the one
/// before it, so an account never holds two live proofs of two mailboxes.
#[tokio::test]
async fn asking_again_retires_the_previous_link() {
    // Arrange
    let mut flow = flow!();
    let first = flow.ask_for_a_link(ADDRESS).await.expect("a link");
    let second = flow.ask_for_a_link(ADDRESS).await.expect("another link");
    assert_ne!(first, second, "the second request reissued the same token");

    // Act
    let stale = flow.follow(&first).await;

    // Assert
    assert_eq!(stale.status, StatusCode::BAD_REQUEST);
    assert!(!flow.is_confirmed().await);
    flow.cleanup().await;
}

// ---- the oracle ----------------------------------------------------------

/// **The oracle test.** RFC 9700 §4.4.1: the answer to a resend must not say
/// whether the address has an account. Not "the same message" — the same
/// bytes, because a different page, length or status would say it just as
/// loudly.
#[tokio::test]
async fn a_resend_answers_identically_for_a_known_and_an_unknown_address() {
    // Arrange
    let mut flow = flow!();
    let form = flow.post("/verify-email", &[("email", ADDRESS)]).await;
    let csrf = csrf_from(&form.body);

    // Act
    let known = flow
        .post("/verify-email", &[("csrf", &csrf), ("email", ADDRESS)])
        .await;
    let form = flow.post("/verify-email", &[("email", STRANGER)]).await;
    let csrf = csrf_from(&form.body);
    let unknown = flow
        .post("/verify-email", &[("csrf", &csrf), ("email", STRANGER)])
        .await;

    // Assert
    assert_eq!(known.status, unknown.status);
    // The address is echoed, and differs because the submission differed; what
    // must not differ is anything the *server* decided. Comparing the two with
    // each page's own address normalised out leaves exactly that.
    assert_eq!(
        comparable(&known.body).replace(ADDRESS, "<address>"),
        comparable(&unknown.body).replace(STRANGER, "<address>")
    );
    flow.cleanup().await;
}

/// An address that is already confirmed is answered the same way and is not
/// sent a second link. Otherwise the endpoint is a way to ask this server
/// which addresses it has proved — and a way to mail-bomb the ones it has.
#[tokio::test]
async fn a_resend_for_a_confirmed_address_sends_nothing_and_says_the_same() {
    // Arrange
    let mut flow = flow!();
    flow.write_account(Some(ADDRESS), true).await;

    // Act
    let link = flow.ask_for_a_link(ADDRESS).await;

    // Assert
    assert_eq!(link, None, "a confirmed address was sent a link");
    assert_eq!(flow.queued_count("email_verification").await, 0);
    flow.cleanup().await;
}

/// A cross-site POST carries no `__Host-` cookie, so it cannot make this
/// server send mail. The refusal re-renders the form rather than sending.
#[tokio::test]
async fn a_resend_without_the_synchroniser_token_sends_nothing() {
    // Arrange
    let mut flow = flow!();

    // Act
    let page = flow
        .post("/verify-email", &[("csrf", "forged"), ("email", ADDRESS)])
        .await;

    // Assert
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(flow.queued_count("email_verification").await, 0);
    flow.cleanup().await;
}

// ---- the pages -----------------------------------------------------------

/// `ast-ndk.4`: no page in this flow needs a line of JavaScript, and the way
/// to keep that true is to assert there is none.
#[tokio::test]
async fn no_page_in_this_flow_carries_a_script() {
    // Arrange
    let mut flow = flow!();
    let link = flow.ask_for_a_link(ADDRESS).await.expect("a link");

    // Act
    let waiting = flow.post("/verify-email", &[("email", ADDRESS)]).await;
    let confirmed = flow.follow(&link).await;

    // Assert
    for page in [&waiting.body, &confirmed.body] {
        assert!(
            !page.contains("<script"),
            "a verification page carried a script:\n{page}"
        );
    }
    flow.cleanup().await;
}

/// The link in the message is absolute and comes back through the prefix the
/// tenant is mounted under (`ast-295`). A relative link in a mailbox resolves
/// against nothing.
#[tokio::test]
async fn the_link_is_absolute_and_carries_the_tenant_prefix() {
    // Arrange
    let mut flow = flow!();

    // Act
    let link = flow.ask_for_a_link(ADDRESS).await.expect("a link");

    // Assert
    assert!(
        link.starts_with(&format!("https://{HOST}/t/{}", flow.tenant.id.as_str())),
        "the link is not under this tenant: {link}"
    );
    assert!(link.contains("/verify-email?token="), "{link}");
    flow.cleanup().await;
}

/// The outbox holds the link, so it holds a live credential until the token
/// expires — which is what the threat model says an operator must treat it as.
/// Asserted so the warning cannot quietly stop being true.
#[tokio::test]
async fn the_trail_records_a_sent_link_without_the_token() {
    // Arrange
    let mut flow = flow!();

    // Act
    let link = flow.ask_for_a_link(ADDRESS).await.expect("a link");

    // Assert
    assert_eq!(flow.audit_count("email_verification.sent").await, 1);
    let trail = flow.trail().await;
    let token = link.split("token=").nth(1).expect("the link carries one");
    assert!(
        !format!("{trail:?}").contains(token),
        "the audit trail carried the token"
    );
    flow.cleanup().await;
}

// ---- the sign-in gate ----------------------------------------------------
//
// The decision `authenticated` takes *before* it establishes a session, with
// fakes rather than a database: what is under test is the decision, not the
// storage. It lives here rather than beside the code because a nonce may only
// be drawn from the document middleware — `web`'s `source_audit` holds that
// rule over `src/`, and exempts `tests/` because an integration test has no
// middleware to draw from.

use asterius_domain::{DomainError, IssuedEmailVerification, Notification, VerifiedAddress};
use std::sync::Mutex;

/// A token store that remembers what it was asked to write.
#[derive(Debug, Default)]
struct Tokens {
    issued: Mutex<Vec<IssuedEmailVerification>>,
}

#[async_trait::async_trait]
impl asterius_domain::EmailVerificationStore for Tokens {
    async fn issue(&self, issued: &IssuedEmailVerification) -> Result<(), DomainError> {
        self.issued
            .lock()
            .expect("the fixture is not poisoned")
            .push(issued.clone());
        Ok(())
    }

    async fn spend(
        &self,
        _digest: &str,
        _now: OffsetDateTime,
    ) -> Result<Option<VerifiedAddress>, DomainError> {
        Ok(None)
    }

    async fn invalidate_for_user(
        &self,
        _user: UserId,
        _now: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        Ok(0)
    }
}

/// A sender that keeps what it was handed.
#[derive(Debug, Default)]
struct Mail {
    sent: Mutex<Vec<Notification>>,
}

#[async_trait::async_trait]
impl asterius_domain::MailSender for Mail {
    async fn send(&self, message: &Notification) -> Result<(), DomainError> {
        self.sent
            .lock()
            .expect("the fixture is not poisoned")
            .push(message.clone());
        Ok(())
    }
}

/// A trail that accepts everything and remembers nothing worth asserting
/// here: the trail's own shape is asserted where events are built.
#[derive(Debug)]
struct Trail;

#[async_trait::async_trait]
impl asterius_domain::audit::AuditSink for Trail {
    async fn record(&self, _event: asterius_domain::audit::AuditEvent) -> Result<(), DomainError> {
        Ok(())
    }
}

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::new("gate"),
        issuer: asterius_domain::Issuer::parse("https://as.example/t/gate")
            .expect("a literal issuer"),
        custom_host: None,
        display_name: "Gate".to_owned(),
        default_resource: "https://api.example/".to_owned(),
        status: asterius_domain::TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn account(email: Option<&str>, verified: bool) -> User {
    User {
        tenant: TenantId::new("gate"),
        id: UserId::generate(),
        username: "ada".to_owned(),
        email: email.map(str::to_owned),
        email_verified: verified,
        status: UserStatus::Active,
        claims: ClaimSet::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// Runs the gate against one account and answers what it decided, plus
/// what the fakes saw.
async fn decide(user: &User) -> (bool, Tokens, Mail) {
    let tokens = Tokens::default();
    let mail = Mail::default();
    let blocked = {
        let gated = asterius_server::http::verify_email::Gate {
            tokens: &tokens,
            mail: &mail,
        };
        asterius_server::http::verify_email::gate(
            &gated,
            &tenant(),
            &Trail,
            &asterius_web::csp::Nonce::generate(),
            &asterius_server::tenancy::MountPrefix::root(),
            user,
            OffsetDateTime::UNIX_EPOCH,
        )
        .await
        .is_some()
    };
    (blocked, tokens, mail)
}

/// **The rule the ticket names.** An account whose address has not been
/// proved does not get past this point, and the session the caller was
/// about to create is never created because the caller returns first.
#[tokio::test]
async fn an_unverified_address_stops_the_sign_in() {
    // Arrange
    let user = account(Some("ada@example.test"), false);

    // Act
    let (blocked, _, _) = decide(&user).await;

    // Assert
    assert!(blocked);
}

/// The ordinary case. A proved address is not stopped, or the gate would
/// be an outage.
#[tokio::test]
async fn a_verified_address_passes() {
    // Arrange
    let user = account(Some("ada@example.test"), true);

    // Act
    let (blocked, _, mail) = decide(&user).await;

    // Assert
    assert!(!blocked);
    assert!(
        mail.sent.lock().expect("not poisoned").is_empty(),
        "a confirmed account was sent a confirmation link"
    );
}

/// An account with no address at all is not stopped. The setting is about
/// *proving* an address, and a tenant whose accounts are passkey-only with
/// no mailbox would otherwise lock out everybody at once on the day it is
/// switched on.
#[tokio::test]
async fn an_account_with_no_address_passes() {
    // Arrange
    let user = account(None, false);

    // Act
    let (blocked, tokens, mail) = decide(&user).await;

    // Assert
    assert!(!blocked);
    assert!(tokens.issued.lock().expect("not poisoned").is_empty());
    assert!(mail.sent.lock().expect("not poisoned").is_empty());
}

/// Being stopped sends a link, because a page that said "ask us for one"
/// without having sent one is a page that looks broken to somebody who has
/// just proved a credential.
#[tokio::test]
async fn being_stopped_sends_a_link_to_the_address_on_the_account() {
    // Arrange
    let user = account(Some("ada@example.test"), false);

    // Act
    let (_, tokens, mail) = decide(&user).await;

    // Assert
    let issued = tokens.issued.lock().expect("not poisoned");
    let sent = mail.sent.lock().expect("not poisoned");
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0].address, "ada@example.test");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, "ada@example.test");
}

/// The row records the address the message went to — the fact the token
/// proves — and never the token itself.
#[tokio::test]
async fn the_row_holds_a_digest_and_the_message_holds_the_link() {
    // Arrange
    let user = account(Some("ada@example.test"), false);

    // Act
    let (_, tokens, mail) = decide(&user).await;

    // Assert
    let issued = tokens.issued.lock().expect("not poisoned");
    let sent = mail.sent.lock().expect("not poisoned");
    let asterius_domain::NotificationKind::EmailVerification { link, .. } = &sent[0].kind else {
        panic!("the gate sent something other than a verification message");
    };
    assert!(
        link.starts_with("https://as.example/t/gate/verify-email?token="),
        "the link is not absolute and under this tenant: {link}"
    );
    assert!(
        !link.contains(&issued[0].token_digest),
        "the link carried the digest rather than the token"
    );
}
