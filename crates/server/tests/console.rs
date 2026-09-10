//! The admin console's door (`ast-wr4`, ADR-0009).
//!
//! What is under test is the entry decision and nothing else: who is shown the
//! shell, who is sent to a login, and what the login that is opened for them
//! actually is. The login itself is `tests/interaction.rs`, because it is the
//! same login.

use asterius_admin_api::{Asset, Bundle};
use asterius_domain::{
    AuthenticationMethod, ClientId, Continuation, DomainError, FirstPartyDestination,
    InteractionRecord, InteractionRepository, Issuer, Participant, PasskeyEnrolment, Role, Session,
    SessionRepository, SessionRevocation, Tenant, TenantId, TenantStatus, UserId,
};
use asterius_server::http::console::{AdminStanding, ConsoleContext, enter};
use asterius_web::csp::Nonce;
use asterius_web::interaction::COOKIE_NAME as INTERACTION_COOKIE;
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::Value;
use std::sync::Mutex;
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";

/// The only redirect status this server emits, spelled as a number.
///
/// Not `StatusCode::SEE_OTHER`: `http::source_audit` confines that constant to
/// `http::redirect`, so that a redirect is always *built* by the helper. A test
/// asserting what came back is not building one, and the number says the same
/// thing.
const SEE_OTHER: u16 = 303;

// ---- the fakes ----------------------------------------------------------

/// Every first-party interaction this test opened.
#[derive(Debug, Default)]
struct FakeInteractions {
    opened: Mutex<Vec<(String, FirstPartyDestination, OffsetDateTime)>>,
    fail: bool,
}

#[async_trait::async_trait]
impl InteractionRepository for FakeInteractions {
    async fn begin_first_party_interaction(
        &self,
        digest: &str,
        destination: FirstPartyDestination,
        expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if self.fail {
            return Err(DomainError::Storage("the store is down".into()));
        }
        self.opened
            .lock()
            .expect("lock")
            .push((digest.to_owned(), destination, expires_at));
        Ok(())
    }

    async fn begin_interaction(
        &self,
        _r: &str,
        _i: &str,
        _n: OffsetDateTime,
    ) -> Result<(), DomainError> {
        panic!("the console never begins an authorization");
    }

    async fn by_interaction(
        &self,
        _d: &str,
        _n: OffsetDateTime,
    ) -> Result<Option<InteractionRecord>, DomainError> {
        Ok(None)
    }

    async fn save_interaction_state(
        &self,
        _d: &str,
        _s: &Value,
        _session: Option<&str>,
        _n: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn complete_interaction(&self, _d: &str, _n: OffsetDateTime) -> Result<(), DomainError> {
        Ok(())
    }

    async fn destroy_interaction(&self, _d: &str) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Sessions, keyed by digest exactly as the real store is.
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

/// What the visitor holds, and whether they have a passkey (`ast-895`).
///
/// The default is the shape every test before this bead assumed: no role, so
/// the deployment-scope rule does not apply and the entry decision is about
/// the session alone.
#[derive(Debug, Default)]
struct FakeStanding {
    roles: Vec<Role>,
    enrolment: Option<PasskeyEnrolment>,
    fail: bool,
}

impl FakeStanding {
    fn holding(roles: &[Role], enrolment: PasskeyEnrolment) -> Self {
        Self {
            roles: roles.to_vec(),
            enrolment: Some(enrolment),
            fail: false,
        }
    }
}

#[async_trait::async_trait]
impl AdminStanding for FakeStanding {
    async fn roles(&self, _user: UserId) -> Result<Vec<Role>, DomainError> {
        if self.fail {
            return Err(DomainError::Storage("the store is down".into()));
        }
        Ok(self.roles.clone())
    }

    async fn passkey_enrolment(&self, _user: UserId) -> Result<PasskeyEnrolment, DomainError> {
        if self.fail {
            return Err(DomainError::Storage("the store is down".into()));
        }
        // Asked only when it decides something. A test that did not say which
        // answer it wants has hit a path it did not mean to.
        Ok(self
            .enrolment
            .expect("this test did not expect a passkey lookup"))
    }
}

// ---- fixtures -----------------------------------------------------------

const SCRIPT: &str = "assets/main-abc123.js";
static FIXTURE: [Asset; 1] = [Asset {
    path: SCRIPT,
    bytes: b"export const ok = 1;",
    content_type: "text/javascript; charset=utf-8",
}];
static STYLES: [&str; 0] = [];

fn bundle() -> Bundle {
    Bundle::new(&FIXTURE, Some(SCRIPT), &STYLES)
}

fn tenant(id: &str) -> Tenant {
    Tenant {
        id: TenantId::new(id),
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

/// A live session of `tenant`, and the cookie value that presents it.
fn session_of(tenant: &str, now: OffsetDateTime) -> (Session, String) {
    let value = "a-session-value";
    let session = Session {
        tenant: TenantId::new(tenant),
        id_digest: asterius_domain::sha256_hex(value.as_bytes()),
        public_sid: "sid-for-a-test-session".to_owned(),
        user: uuid::Uuid::from_u128(1),
        created_at: now,
        authenticated_at: now,
        last_seen_at: now,
        expires_at: now + time::Duration::hours(8),
        idle_expires_at: now + time::Duration::minutes(30),
        acr: None,
        amr: vec![AuthenticationMethod::Password],
        revoked: None,
    };
    (session, value.to_owned())
}

fn cookie(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!(
            "{}={value}",
            asterius_domain::entities::session::COOKIE_NAME
        )
        .parse()
        .expect("header"),
    );
    headers
}

async fn body_of(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("a body");
    String::from_utf8(bytes.to_vec()).expect("utf-8")
}

async fn visit(
    tenant: &Tenant,
    interactions: &FakeInteractions,
    sessions: &FakeSessions,
    headers: &HeaderMap,
) -> axum::response::Response {
    visit_as(
        tenant,
        interactions,
        sessions,
        &FakeStanding::default(),
        headers,
    )
    .await
}

/// [`visit`], for a visitor whose roles and credentials matter (`ast-895`).
async fn visit_as(
    tenant: &Tenant,
    interactions: &FakeInteractions,
    sessions: &FakeSessions,
    standing: &FakeStanding,
    headers: &HeaderMap,
) -> axum::response::Response {
    let nonce = Nonce::generate();
    enter(
        &ConsoleContext {
            tenant,
            interactions,
            sessions,
            standing,
            nonce: &nonce,
            bundle: bundle(),
        },
        headers,
        OffsetDateTime::now_utc(),
    )
    .await
}

// ---- the criteria -------------------------------------------------------

/// The first criterion: no session, so a first-party interaction is opened and
/// the browser is sent to the login page that already exists.
#[tokio::test]
async fn a_visitor_with_no_session_is_sent_to_a_first_party_login() {
    // Arrange
    let tenant = tenant("demo");
    let interactions = FakeInteractions::default();
    let sessions = FakeSessions::default();

    // Act
    let response = visit(&tenant, &interactions, &sessions, &HeaderMap::new()).await;

    // Assert
    assert_eq!(response.status().as_u16(), SEE_OTHER);
    let opened = interactions.opened.lock().expect("lock");
    assert_eq!(opened.len(), 1, "no interaction was opened");
    assert_eq!(opened[0].1, FirstPartyDestination::AdminConsole);

    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("a Location")
        .to_str()
        .expect("ascii")
        .to_owned();
    assert!(
        location.starts_with("../interaction/"),
        "an absolute redirect would drop the tenant prefix: {location}"
    );

    // The id is in the URL *and* the cookie, and the row holds only its
    // digest (FAPI 2.0 SP §6.5).
    let id = location
        .strip_prefix("../interaction/")
        .expect("the id")
        .to_owned();
    let cookie = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(INTERACTION_COOKIE))
        .expect("no interaction cookie");
    assert!(cookie.contains(&id), "the cookie names another interaction");
    assert_eq!(opened[0].0, asterius_domain::sha256_hex(id.as_bytes()));
    assert_ne!(opened[0].0, id, "the id itself was stored");
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().expect("ascii")),
        Some("no-store"),
        "a response carrying a credential was cacheable"
    );
}

/// Nothing of the console is drawn for somebody who is not signed in: the
/// shell is not a page an unauthenticated visitor can make this server render.
#[tokio::test]
async fn no_console_document_is_rendered_without_a_session() {
    let tenant = tenant("demo");
    let interactions = FakeInteractions::default();
    let sessions = FakeSessions::default();

    let response = visit(&tenant, &interactions, &sessions, &HeaderMap::new()).await;

    assert_eq!(response.status().as_u16(), SEE_OTHER);
    assert!(!body_of(response).await.contains(SCRIPT));
}

/// A live session of this tenant gets the shell.
#[tokio::test]
async fn a_signed_in_visitor_gets_the_console() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let tenant = tenant("demo");
    let interactions = FakeInteractions::default();
    let sessions = FakeSessions::default();
    let (session, value) = session_of("demo", now);
    sessions.begin(&session).await.expect("a session");

    // Act
    let response = visit(&tenant, &interactions, &sessions, &cookie(&value)).await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        interactions.opened.lock().expect("lock").is_empty(),
        "a login was opened for somebody who is already signed in"
    );
    assert!(body_of(response).await.contains(SCRIPT));
}

/// The ADR-0010 criterion: sessions belong to tenants, so a session opened in
/// one tenant is not a way into another tenant's console.
#[tokio::test]
async fn a_session_of_another_tenant_does_not_open_this_console() {
    // Arrange: the session says `other`, the request arrived at `demo`.
    let now = OffsetDateTime::now_utc();
    let tenant = tenant("demo");
    let interactions = FakeInteractions::default();
    let sessions = FakeSessions::default();
    let (session, value) = session_of("other", now);
    sessions.begin(&session).await.expect("a session");

    // Act
    let response = visit(&tenant, &interactions, &sessions, &cookie(&value)).await;

    // Assert
    assert_eq!(
        response.status().as_u16(),
        SEE_OTHER,
        "another tenant's session opened this console"
    );
    assert!(!body_of(response).await.contains(SCRIPT));
}

/// A cookie naming nothing is a visitor with no session, not an error.
#[tokio::test]
async fn a_cookie_that_names_no_session_is_a_login() {
    let tenant = tenant("demo");
    let interactions = FakeInteractions::default();
    let sessions = FakeSessions::default();

    let response = visit(&tenant, &interactions, &sessions, &cookie("not-a-session")).await;

    assert_eq!(response.status().as_u16(), SEE_OTHER);
}

/// An expired session is not a session. `Session::status` decides, and the
/// entry does not second-guess it.
#[tokio::test]
async fn an_expired_session_is_a_login() {
    let now = OffsetDateTime::now_utc();
    let tenant = tenant("demo");
    let interactions = FakeInteractions::default();
    let sessions = FakeSessions::default();
    let (mut session, value) = session_of("demo", now);
    session.expires_at = now - time::Duration::minutes(1);
    sessions.begin(&session).await.expect("a session");

    let response = visit(&tenant, &interactions, &sessions, &cookie(&value)).await;

    assert_eq!(response.status().as_u16(), SEE_OTHER);
}

/// A store that cannot open a login says so, rather than serving a console to
/// somebody who has not signed in.
#[tokio::test]
async fn a_store_that_cannot_open_a_login_does_not_serve_the_console() {
    let tenant = tenant("demo");
    let interactions = FakeInteractions {
        fail: true,
        ..FakeInteractions::default()
    };
    let sessions = FakeSessions::default();

    let response = visit(&tenant, &interactions, &sessions, &HeaderMap::new()).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!body_of(response).await.contains(SCRIPT));
}

/// The continuation the entry writes carries no client, no redirect URI and no
/// scopes — there is nowhere in the type to put one.
#[test]
fn a_first_party_continuation_has_no_client() {
    let continuation = Continuation::FirstParty(FirstPartyDestination::AdminConsole);

    assert!(continuation.client_request().is_none());
    assert_eq!(
        continuation.first_party(),
        Some(FirstPartyDestination::AdminConsole)
    );
}
// ---- the authenticator a deployment admin must have used (`ast-895`) ------

/// A live session is not the whole answer. The account that reaches every
/// tenant needs a phishing-resistant authenticator (NIST SP 800-63B §5.2.5),
/// so a password-only session meets the login page that can ask for the
/// passkey instead of the console shell.
#[tokio::test]
async fn a_deployment_admin_on_a_password_meets_a_login_rather_than_the_console() {
    // Arrange
    let tenant = tenant("demo");
    let interactions = FakeInteractions::default();
    let sessions = FakeSessions::default();
    let now = OffsetDateTime::now_utc();
    let (session, value) = session_of("demo", now);
    sessions.begin(&session).await.expect("a session");
    let standing = FakeStanding::holding(&[Role::DeploymentAdmin], PasskeyEnrolment::Enrolled);

    // Act
    let response = visit_as(
        &tenant,
        &interactions,
        &sessions,
        &standing,
        &cookie(&value),
    )
    .await;

    // Assert
    assert_eq!(
        response.status().as_u16(),
        SEE_OTHER,
        "the console shell was drawn for a password-only deployment admin"
    );
    assert_eq!(
        interactions.opened.lock().expect("lock").len(),
        1,
        "no login was opened for them to present the passkey at"
    );
}

/// The same visitor, having presented the passkey.
#[tokio::test]
async fn a_deployment_admin_who_used_a_user_verified_passkey_sees_the_console() {
    // Arrange
    let tenant = tenant("demo");
    let interactions = FakeInteractions::default();
    let sessions = FakeSessions::default();
    let now = OffsetDateTime::now_utc();
    let (mut session, value) = session_of("demo", now);
    session.amr = vec![
        AuthenticationMethod::Passkey,
        AuthenticationMethod::UserVerified,
    ];
    sessions.begin(&session).await.expect("a session");
    let standing = FakeStanding::holding(&[Role::DeploymentAdmin], PasskeyEnrolment::Enrolled);

    // Act
    let response = visit_as(
        &tenant,
        &interactions,
        &sessions,
        &standing,
        &cookie(&value),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        body_of(response).await.contains(SCRIPT),
        "the console shell was not served"
    );
}

/// The bootstrap window: the seeded admin has a password and no passkey, and
/// it is the account that would have to enrol one. Written down here and in
/// `docs/threat-model.md` rather than left as an emergent property.
#[tokio::test]
async fn the_seeded_admin_reaches_the_console_before_it_has_enrolled_a_passkey() {
    // Arrange
    let tenant = tenant("demo");
    let interactions = FakeInteractions::default();
    let sessions = FakeSessions::default();
    let now = OffsetDateTime::now_utc();
    let (session, value) = session_of("demo", now);
    sessions.begin(&session).await.expect("a session");
    let standing = FakeStanding::holding(&[Role::DeploymentAdmin], PasskeyEnrolment::None);

    // Act
    let response = visit_as(
        &tenant,
        &interactions,
        &sessions,
        &standing,
        &cookie(&value),
    )
    .await;

    // Assert
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a fresh deployment would have nobody able to enrol the passkey it demands"
    );
}

/// "We cannot tell what you hold" is not "come in". A store that cannot be
/// read fails closed, and it fails closed *loudly* rather than by quietly
/// sending an admin round the login loop.
#[tokio::test]
async fn a_standing_lookup_that_fails_does_not_admit_anybody() {
    // Arrange
    let tenant = tenant("demo");
    let interactions = FakeInteractions::default();
    let sessions = FakeSessions::default();
    let now = OffsetDateTime::now_utc();
    let (session, value) = session_of("demo", now);
    sessions.begin(&session).await.expect("a session");
    let standing = FakeStanding {
        roles: vec![Role::DeploymentAdmin],
        enrolment: None,
        fail: true,
    };

    // Act
    let response = visit_as(
        &tenant,
        &interactions,
        &sessions,
        &standing,
        &cookie(&value),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        interactions.opened.lock().expect("lock").is_empty(),
        "an unreadable store should not look like a missing session"
    );
}
