//! The passkey enrolment endpoints, over fakes.
//!
//! What is asserted here is the *handler's* decisions, which are the ones no
//! store can make for it: who is allowed to reach the page at all, whether a
//! synchroniser token is checked before anything is spent, and whether every
//! refusal looks the same from outside. The store's own properties — a
//! challenge spent once, a credential id unique per tenant — belong to
//! `asterius-store-pg`'s database tests and are asserted there against real
//! constraints rather than a `HashMap`.

use asterius_domain::audit::{AuditEvent, AuditSink};
use asterius_domain::entities::session::{COOKIE_NAME, SessionId};
use asterius_domain::{
    AuthenticationMethod, ClaimSet, ClientId, DomainError, ENROLMENT_TTL, Enrolment, Issuer,
    NewPasskey, Participant, PasskeyRepository, RegisteredPasskey, Session, SessionRepository,
    SessionRevocation, Tenant, TenantId, TenantStatus, User, UserDirectory, UserId, UserStatus,
    sha256_hex,
};
use asterius_server::http::passkeys::{self, PasskeyContext};
use asterius_web::csp::Nonce;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use std::sync::Mutex;
use time::OffsetDateTime;

// ---- fakes --------------------------------------------------------------

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
struct FakeSessions(Mutex<Vec<Session>>);

impl FakeSessions {
    fn holding(digest: &str, user: uuid::Uuid, now: OffsetDateTime) -> Self {
        Self(Mutex::new(vec![Session {
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
        }]))
    }
}

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

#[derive(Debug)]
struct FakeUsers(User);

impl FakeUsers {
    fn active(id: UserId) -> Self {
        Self(User {
            tenant: TenantId::new("demo"),
            id,
            username: "ada".to_owned(),
            email: None,
            email_verified: false,
            status: UserStatus::Active,
            claims: ClaimSet::new(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        })
    }

    fn disabled(id: UserId) -> Self {
        let mut users = Self::active(id);
        users.0.status = UserStatus::Disabled;
        users
    }
}

#[async_trait::async_trait]
impl UserDirectory for FakeUsers {
    async fn by_id(&self, id: UserId) -> Result<Option<User>, DomainError> {
        Ok((self.0.id == id).then(|| self.0.clone()))
    }
}

/// An in-memory enrolment store, one row like the table it stands in for.
#[derive(Debug, Default)]
struct FakePasskeys {
    enrolment: Mutex<Option<(String, Enrolment)>>,
    registered: Mutex<Vec<NewPasskey>>,
}

#[async_trait::async_trait]
impl PasskeyRepository for FakePasskeys {
    async fn open_enrolment(
        &self,
        session_digest: &str,
        csrf_digest: &str,
        expires_at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        *self.enrolment.lock().expect("lock") = Some((
            session_digest.to_owned(),
            Enrolment {
                csrf_digest: csrf_digest.to_owned(),
                challenge: None,
                expires_at,
            },
        ));
        Ok(())
    }

    async fn issue_challenge(
        &self,
        session_digest: &str,
        challenge: &[u8],
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut held = self.enrolment.lock().expect("lock");
        match held.as_mut() {
            Some((digest, enrolment)) if digest == session_digest && enrolment.expires_at > now => {
                enrolment.challenge = Some(challenge.to_vec());
                enrolment.expires_at = expires_at;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn enrolment(
        &self,
        session_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Enrolment>, DomainError> {
        Ok(self
            .enrolment
            .lock()
            .expect("lock")
            .iter()
            .find(|(digest, enrolment)| digest == session_digest && enrolment.expires_at > now)
            .map(|(_, enrolment)| enrolment.clone()))
    }

    async fn spend_challenge(
        &self,
        session_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, DomainError> {
        let mut held = self.enrolment.lock().expect("lock");
        match held.as_mut() {
            Some((digest, enrolment)) if digest == session_digest && enrolment.expires_at > now => {
                Ok(enrolment.challenge.take())
            }
            _ => Ok(None),
        }
    }

    async fn register(&self, passkey: &NewPasskey) -> Result<uuid::Uuid, DomainError> {
        self.registered.lock().expect("lock").push(passkey.clone());
        Ok(uuid::Uuid::new_v4())
    }

    async fn credential_ids(&self, _user: &UserId) -> Result<Vec<Vec<u8>>, DomainError> {
        Ok(Vec::new())
    }

    // The authentication half of the port. Enrolment reaches none of it, and
    // these answer the way an empty store would: no challenge, no credential.
    // `tests/passkey_login.rs` is where it is exercised.
    async fn issue_assertion_challenge(
        &self,
        _interaction: &str,
        _challenge: &[u8],
        _expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        Ok(false)
    }

    async fn spend_assertion_challenge(
        &self,
        _interaction: &str,
        _now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, DomainError> {
        Ok(None)
    }

    async fn by_credential_id(
        &self,
        _credential_id: &[u8],
    ) -> Result<Option<RegisteredPasskey>, DomainError> {
        Ok(None)
    }

    async fn record_assertion(
        &self,
        _credential: uuid::Uuid,
        _sign_count: Option<u32>,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }

    async fn disable(
        &self,
        _credential: uuid::Uuid,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
}

// ---- the fixture --------------------------------------------------------

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::new("demo"),
        issuer: Issuer::parse("https://as.example/t/demo").expect("a valid issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: "Demo".to_owned(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// Everything a request needs, held so the borrows outlive the context.
struct Fixture {
    tenant: Tenant,
    passkeys: FakePasskeys,
    sessions: FakeSessions,
    users: FakeUsers,
    nonce: Nonce,
    audit: FakeAudit,
    session_id: SessionId,
}

impl Fixture {
    fn signed_in(now: OffsetDateTime) -> Self {
        let session_id = SessionId::generate();
        let user = UserId::generate();
        Self {
            tenant: tenant(),
            passkeys: FakePasskeys::default(),
            sessions: FakeSessions::holding(&session_id.digest(), *user.as_uuid(), now),
            users: FakeUsers::active(user),
            nonce: Nonce::generate(),
            audit: FakeAudit::default(),
            session_id,
        }
    }

    fn context(&self) -> PasskeyContext<'_> {
        PasskeyContext {
            tenant: &self.tenant,
            passkeys: &self.passkeys,
            sessions: &self.sessions,
            users: &self.users,
            nonce: &self.nonce,
            audit: &self.audit,
        }
    }

    fn cookie(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let value = format!("{COOKIE_NAME}={}", self.session_id.expose());
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&value).expect("a cookie header"),
        );
        headers
    }

    /// The token the page was rendered with, recovered from the stored digest
    /// by seeding the digest of a token this test chose.
    fn open_with_token(&self, token: &str, now: OffsetDateTime) {
        *self.passkeys.enrolment.lock().expect("lock") = Some((
            self.session_id.digest(),
            Enrolment {
                csrf_digest: sha256_hex(token.as_bytes()),
                challenge: None,
                expires_at: now + ENROLMENT_TTL,
            },
        ));
    }
}

async fn body_of(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read the body");
    String::from_utf8_lossy(&bytes).into_owned()
}

fn json(value: &serde_json::Value) -> Bytes {
    Bytes::from(value.to_string())
}

// ---- who may reach the page --------------------------------------------

#[tokio::test]
async fn without_a_session_cookie_there_is_no_enrolment_page() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::signed_in(now);

    // Act
    let response = passkeys::page(fixture.context(), &HeaderMap::new(), now).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        fixture.passkeys.enrolment.lock().expect("lock").is_none(),
        "an unauthenticated visitor must not open an enrolment"
    );
}

/// A disabled account must not be able to add a credential — least of all one
/// disabled *because* something went wrong.
#[tokio::test]
async fn a_disabled_account_cannot_open_an_enrolment() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let mut fixture = Fixture::signed_in(now);
    fixture.users = FakeUsers::disabled(fixture.users.0.id);

    // Act
    let response = passkeys::page(fixture.context(), &fixture.cookie(), now).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_signed_in_user_gets_the_page_and_an_open_enrolment() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::signed_in(now);

    // Act
    let response = passkeys::page(fixture.context(), &fixture.cookie(), now).await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "a page carrying a synchroniser token must not be cached"
    );
    let body = body_of(response).await;
    assert!(
        body.contains(r#"data-options-url="/passkeys/options""#),
        "{body}"
    );
    assert!(
        body.contains(r#"data-finish-url="/passkeys/finish""#),
        "{body}"
    );
    // `ast-ndk.7`'s no-JS requirement, still true through this wiring.
    assert!(body.contains(r#"id="passkey-register" hidden"#), "{body}");
    assert!(body.contains("<noscript>"), "{body}");
    assert!(
        fixture.passkeys.enrolment.lock().expect("lock").is_some(),
        "rendering the page opens the enrolment it is for"
    );
}

/// The token in the page is the token the store holds the digest of. Without
/// this the CSRF check could pass for the wrong reason in every test below.
#[tokio::test]
async fn the_rendered_token_matches_the_stored_digest() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::signed_in(now);

    // Act
    let body = body_of(passkeys::page(fixture.context(), &fixture.cookie(), now).await).await;

    // Assert
    let token = body
        .split(r#"data-csrf=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the page carries a token");
    let held = fixture.passkeys.enrolment.lock().expect("lock");
    let (_, enrolment) = held.as_ref().expect("an open enrolment");
    assert_eq!(enrolment.csrf_digest, sha256_hex(token.as_bytes()));
}

// ---- the options request ------------------------------------------------

#[tokio::test]
async fn options_describe_this_server_and_carry_the_challenge() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::signed_in(now);
    fixture.open_with_token("a-token", now);

    // Act
    let response = passkeys::options(
        fixture.context(),
        &fixture.cookie(),
        &json(&serde_json::json!({ "csrf": "a-token" })),
        now,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let document: serde_json::Value =
        serde_json::from_str(&body_of(response).await).expect("JSON options");
    assert_eq!(document["rp"]["id"], "as.example");
    assert_eq!(document["attestation"], "none");
    assert_eq!(
        document["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert!(
        document["challenge"]
            .as_str()
            .is_some_and(|c| !c.is_empty()),
        "{document}"
    );
    let held = fixture.passkeys.enrolment.lock().expect("lock");
    let (_, enrolment) = held.as_ref().expect("an open enrolment");
    assert!(
        enrolment.challenge.as_ref().is_some_and(|c| c.len() >= 16),
        "the challenge the browser was given must be the one that was stored"
    );
}

/// The whole reason the token exists: a request that did not come from the
/// page this server rendered gets nothing, and nothing is drawn for it.
#[tokio::test]
async fn options_with_the_wrong_token_draw_no_challenge() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::signed_in(now);
    fixture.open_with_token("a-token", now);

    // Act
    let response = passkeys::options(
        fixture.context(),
        &fixture.cookie(),
        &json(&serde_json::json!({ "csrf": "not-the-token" })),
        now,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let held = fixture.passkeys.enrolment.lock().expect("lock");
    let (_, enrolment) = held.as_ref().expect("an open enrolment");
    assert_eq!(enrolment.challenge, None);
}

#[tokio::test]
async fn options_without_a_session_are_unauthorised_rather_than_refused() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::signed_in(now);

    // Act
    let response = passkeys::options(
        fixture.context(),
        &HeaderMap::new(),
        &json(&serde_json::json!({ "csrf": "a-token" })),
        now,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---- the finish request -------------------------------------------------

/// A ceremony that never happened must not be storable, and the refusal must
/// say nothing about why.
#[tokio::test]
async fn finishing_with_no_outstanding_challenge_stores_nothing() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::signed_in(now);
    fixture.open_with_token("a-token", now);

    // Act
    let response = passkeys::finish(
        fixture.context(),
        &fixture.cookie(),
        &json(&serde_json::json!({
            "csrf": "a-token",
            "type": "public-key",
            "rawId": "AQID",
            "clientDataJSON": "e30",
            "attestationObject": "oA",
        })),
        now,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.passkeys.registered.lock().expect("lock").is_empty());
    assert!(
        fixture.audit.0.lock().expect("lock").is_empty(),
        "nothing was created, so nothing is recorded as created"
    );
}

/// Rubbish in the two halves fails the ceremony and — the part that matters —
/// still spends the challenge, so it cannot be tried again.
#[tokio::test]
async fn a_failed_ceremony_still_spends_its_challenge() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::signed_in(now);
    fixture.open_with_token("a-token", now);
    fixture
        .passkeys
        .issue_challenge(
            &fixture.session_id.digest(),
            &[9u8; 32],
            now + ENROLMENT_TTL,
            now,
        )
        .await
        .expect("issue");

    // Act
    let response = passkeys::finish(
        fixture.context(),
        &fixture.cookie(),
        &json(&serde_json::json!({
            "csrf": "a-token",
            "type": "public-key",
            "rawId": "AQID",
            "clientDataJSON": "e30",
            "attestationObject": "oA",
        })),
        now,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let held = fixture.passkeys.enrolment.lock().expect("lock");
    let (_, enrolment) = held.as_ref().expect("an open enrolment");
    assert_eq!(
        enrolment.challenge, None,
        "comparing is not consuming: the challenge goes whether the ceremony passed or not"
    );
}

/// The token is checked before the challenge is spent, or a forged request
/// could burn somebody else's ceremony.
#[tokio::test]
async fn finishing_with_the_wrong_token_does_not_spend_the_challenge() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::signed_in(now);
    fixture.open_with_token("a-token", now);
    fixture
        .passkeys
        .issue_challenge(
            &fixture.session_id.digest(),
            &[9u8; 32],
            now + ENROLMENT_TTL,
            now,
        )
        .await
        .expect("issue");

    // Act
    let response = passkeys::finish(
        fixture.context(),
        &fixture.cookie(),
        &json(&serde_json::json!({
            "csrf": "not-the-token",
            "type": "public-key",
            "rawId": "AQID",
            "clientDataJSON": "e30",
            "attestationObject": "oA",
        })),
        now,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let held = fixture.passkeys.enrolment.lock().expect("lock");
    let (_, enrolment) = held.as_ref().expect("an open enrolment");
    assert_eq!(enrolment.challenge, Some(vec![9u8; 32]));
}

/// The anti-enumeration requirement, from outside: four different failures,
/// one status and one error code.
#[tokio::test]
async fn every_way_of_failing_looks_the_same() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let bodies = [
        serde_json::json!({ "csrf": "a-token", "type": "public-key",
                            "clientDataJSON": "e30", "attestationObject": "oA" }),
        serde_json::json!({ "csrf": "wrong", "type": "public-key",
                            "clientDataJSON": "e30", "attestationObject": "oA" }),
        serde_json::json!({ "csrf": "a-token", "type": "other",
                            "clientDataJSON": "e30", "attestationObject": "oA" }),
        serde_json::json!({ "csrf": "a-token", "type": "public-key",
                            "clientDataJSON": "not base64!", "attestationObject": "oA" }),
    ];

    // Act
    let mut answers = Vec::new();
    for body in bodies {
        let fixture = Fixture::signed_in(now);
        fixture.open_with_token("a-token", now);
        let response =
            passkeys::finish(fixture.context(), &fixture.cookie(), &json(&body), now).await;
        let status = response.status();
        let parsed: serde_json::Value =
            serde_json::from_str(&body_of(response).await).expect("a JSON refusal");
        answers.push((
            status,
            parsed["error"].as_str().unwrap_or_default().to_owned(),
        ));
    }

    // Assert
    for (status, error) in &answers {
        assert_eq!(*status, StatusCode::BAD_REQUEST);
        assert_eq!(error, "registration_failed");
    }
}
