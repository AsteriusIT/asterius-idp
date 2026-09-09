//! The passkey authentication endpoints, over fakes and a real key pair.
//!
//! The ceremony itself is verified in `asterius-webauthn`, against §7.2, with
//! signatures this test suite's authenticator also produces. What is asserted
//! here is what only the *handler* decides: that the challenge is spent before
//! anything else, that every refusal is byte-for-byte the same, that a signed
//! assertion starts a session with the right `amr` and advances the
//! interaction, and that a signature counter which went backwards blocks the
//! credential and says so in the audit trail.
//!
//! The authenticator is a real ES256 pair, because a fake signature would
//! prove nothing about the one part of this flow that is cryptography.

use asterius_domain::audit::{AuditEvent, AuditSink, DetailValue};
use asterius_domain::entities::session::{Lifetimes, SessionId};
use asterius_domain::rate_limit::{Bucket, LoginLimits, RateLimit, RateLimitStore};
use asterius_domain::{
    AuthenticationMethod, ClaimSet, ClientId, DomainError, Enrolment, InteractionRecord,
    InteractionRepository, NewPasskey, Participant, PasskeyRepository, RegisteredPasskey, Session,
    SessionRepository, SessionRevocation, Tenant, TenantId, TenantStatus, User, UserDirectory,
    UserId, UserStatus, sha256_hex,
};
use asterius_server::http::passkeys::{self, PasskeyLoginContext};
use asterius_server::http::throttle::LoginThrottle;
use asterius_web::interaction::{Stage, StoredState};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair, UnparsedPublicKey,
};
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use ciborium::value::Value;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};

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
}

#[async_trait::async_trait]
impl UserDirectory for FakeUsers {
    async fn by_id(&self, id: UserId) -> Result<Option<User>, DomainError> {
        Ok((self.0.id == id).then(|| self.0.clone()))
    }
}

/// One interaction, one row, like the table it stands in for.
#[derive(Debug)]
struct FakeInteractions {
    digest: String,
    record: Mutex<Option<InteractionRecord>>,
    destroyed: Mutex<bool>,
}

impl FakeInteractions {
    fn at(digest: &str, stage: Stage, csrf: &str, now: OffsetDateTime) -> Self {
        let progress = StoredState {
            stage,
            csrf_digest: Some(sha256_hex(csrf.as_bytes())),
            decision: None,
        };
        Self {
            digest: digest.to_owned(),
            record: Mutex::new(Some(InteractionRecord {
                tenant: TenantId::new("demo"),
                client: ClientId::new("billing"),
                parameters: json!({}),
                state: serde_json::to_value(&progress).expect("a state serialises"),
                session: None,
                expires_at: now + time::Duration::minutes(10),
            })),
            destroyed: Mutex::new(false),
        }
    }

    /// The stage the interaction has reached, as the store now holds it.
    fn stage(&self) -> Option<Stage> {
        let held = self.record.lock().expect("lock");
        held.as_ref()
            .map(|record| StoredState::from_stored(&record.state).stage)
    }

    /// The session digest the interaction was advanced with, if any.
    fn session(&self) -> Option<String> {
        let held = self.record.lock().expect("lock");
        held.as_ref().and_then(|record| record.session.clone())
    }
}

#[async_trait::async_trait]
impl InteractionRepository for FakeInteractions {
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
        interaction_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<InteractionRecord>, DomainError> {
        if interaction_digest != self.digest {
            return Ok(None);
        }
        Ok(self
            .record
            .lock()
            .expect("lock")
            .clone()
            .filter(|record| record.expires_at > now))
    }

    async fn save_interaction_state(
        &self,
        interaction_digest: &str,
        state: &serde_json::Value,
        session: Option<&str>,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if interaction_digest != self.digest {
            return Err(DomainError::NotFound);
        }
        let mut held = self.record.lock().expect("lock");
        let record = held.as_mut().ok_or(DomainError::NotFound)?;
        record.state = state.clone();
        if let Some(session) = session {
            record.session = Some(session.to_owned());
        }
        Ok(())
    }

    async fn complete_interaction(&self, _d: &str, _n: OffsetDateTime) -> Result<(), DomainError> {
        Ok(())
    }

    async fn destroy_interaction(&self, _d: &str) -> Result<(), DomainError> {
        *self.destroyed.lock().expect("lock") = true;
        *self.record.lock().expect("lock") = None;
        Ok(())
    }
}

/// One credential and one outstanding challenge.
#[derive(Debug, Default)]
struct FakePasskeys {
    credential: Mutex<Option<RegisteredPasskey>>,
    challenge: Mutex<Option<Vec<u8>>>,
    recorded: Mutex<Vec<Option<u32>>>,
    disabled: Mutex<Vec<uuid::Uuid>>,
}

#[async_trait::async_trait]
impl PasskeyRepository for FakePasskeys {
    async fn open_enrolment(
        &self,
        _s: &str,
        _c: &str,
        _e: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn issue_challenge(
        &self,
        _s: &str,
        _c: &[u8],
        _e: OffsetDateTime,
        _n: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        Ok(true)
    }
    async fn enrolment(
        &self,
        _s: &str,
        _n: OffsetDateTime,
    ) -> Result<Option<Enrolment>, DomainError> {
        Ok(None)
    }
    async fn spend_challenge(
        &self,
        _s: &str,
        _n: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, DomainError> {
        Ok(None)
    }
    async fn register(&self, _p: &NewPasskey) -> Result<uuid::Uuid, DomainError> {
        Ok(uuid::Uuid::new_v4())
    }
    async fn credential_ids(&self, _u: &UserId) -> Result<Vec<Vec<u8>>, DomainError> {
        Ok(Vec::new())
    }

    async fn issue_assertion_challenge(
        &self,
        _interaction: &str,
        challenge: &[u8],
        _expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        *self.challenge.lock().expect("lock") = Some(challenge.to_vec());
        Ok(true)
    }

    async fn spend_assertion_challenge(
        &self,
        _interaction: &str,
        _now: OffsetDateTime,
    ) -> Result<Option<Vec<u8>>, DomainError> {
        Ok(self.challenge.lock().expect("lock").take())
    }

    async fn by_credential_id(
        &self,
        _credential_id: &[u8],
    ) -> Result<Option<RegisteredPasskey>, DomainError> {
        Ok(self.credential.lock().expect("lock").clone())
    }

    async fn record_assertion(
        &self,
        _credential: uuid::Uuid,
        sign_count: Option<u32>,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.recorded.lock().expect("lock").push(sign_count);
        Ok(())
    }

    async fn disable(
        &self,
        credential: uuid::Uuid,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.disabled.lock().expect("lock").push(credential);
        Ok(())
    }
}

// ---- an authenticator ---------------------------------------------------

/// The flag bits this suite sets (§6.1).
const UP: u8 = 1 << 0;
const UV: u8 = 1 << 2;

/// A real ES256 pair, standing in for the thing in somebody's pocket.
struct Authenticator {
    pair: EcdsaKeyPair,
    credential_id: Vec<u8>,
}

impl Authenticator {
    fn new() -> Self {
        let random = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
            .expect("a generated key");
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref())
            .expect("the generated key parses");
        Self {
            pair,
            credential_id: vec![9_u8; 20],
        }
    }

    /// The `COSE_Key` an enrolment would have stored.
    fn cose_key(&self) -> Vec<u8> {
        let point = self.pair.public_key().as_ref().to_vec();
        let map = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (
                Value::Integer((-2).into()),
                Value::Bytes(point[1..33].to_vec()),
            ),
            (
                Value::Integer((-3).into()),
                Value::Bytes(point[33..].to_vec()),
            ),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&map, &mut encoded).expect("a CBOR map encodes");
        encoded
    }

    /// Authenticator data for this relying party.
    fn authenticator_data(rp_id: &str, flags: u8, sign_count: u32) -> Vec<u8> {
        let mut data = asterius_domain::sha256(rp_id.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&sign_count.to_be_bytes());
        data
    }

    fn sign(&self, authenticator_data: &[u8], client_data: &[u8]) -> Vec<u8> {
        let mut signed = authenticator_data.to_vec();
        signed.extend_from_slice(&asterius_domain::sha256(client_data));
        self.pair
            .sign(&SystemRandom::new(), &signed)
            .expect("a signature")
            .as_ref()
            .to_vec()
    }
}

fn base64_url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn client_data(origin: &str, challenge: &[u8]) -> Vec<u8> {
    json!({
        "type": "webauthn.get",
        "challenge": base64_url(challenge),
        "origin": origin,
    })
    .to_string()
    .into_bytes()
}

// ---- the fixture --------------------------------------------------------

/// Fixed-window counters in memory. The real ones are rows in `rate_limits`.
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

/// Limits no ordinary ceremony test reaches.
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

const CSRF: &str = "a-synchroniser-token-for-a-test";
const ORIGIN: &str = "https://as.example";
const RP_ID: &str = "as.example";

struct Fixture {
    tenant: Tenant,
    passkeys: FakePasskeys,
    requests: FakeInteractions,
    sessions: FakeSessions,
    users: FakeUsers,
    audit: FakeAudit,
    limiter: FakeLimiter,
    limits: LoginLimits,
    authenticator: Authenticator,
    interaction: asterius_web::interaction::InteractionId,
    user: UserId,
}

impl Fixture {
    /// An interaction at the login stage, with one registered credential.
    fn at_login(now: OffsetDateTime, sign_count: u32) -> Self {
        let interaction = asterius_web::interaction::InteractionId::generate();
        let user = UserId::generate();
        let authenticator = Authenticator::new();
        let passkeys = FakePasskeys::default();
        *passkeys.credential.lock().expect("lock") = Some(RegisteredPasskey {
            row: uuid::Uuid::new_v4(),
            user,
            public_key: authenticator.cose_key(),
            sign_count,
            rp_id: RP_ID.to_owned(),
        });
        Self {
            tenant: Tenant {
                id: TenantId::new("demo"),
                issuer: asterius_domain::Issuer::parse("https://as.example/t/demo")
                    .expect("a valid issuer"),
                default_resource: "https://api.example/".to_owned(),
                custom_host: None,
                display_name: "Demo".to_owned(),
                status: TenantStatus::Active,
                created_at: OffsetDateTime::UNIX_EPOCH,
                updated_at: OffsetDateTime::UNIX_EPOCH,
            },
            passkeys,
            requests: FakeInteractions::at(&interaction.digest(), Stage::Login, CSRF, now),
            sessions: FakeSessions::default(),
            users: FakeUsers::active(user),
            audit: FakeAudit::default(),
            limiter: FakeLimiter::default(),
            limits: generous_limits(),
            authenticator,
            interaction,
            user,
        }
    }

    fn context(&self) -> PasskeyLoginContext<'_> {
        PasskeyLoginContext {
            tenant: &self.tenant,
            passkeys: &self.passkeys,
            requests: &self.requests,
            sessions: &self.sessions,
            users: &self.users,
            lifetimes: Lifetimes::default(),
            audit: &self.audit,
            throttle: LoginThrottle::new(
                &self.limiter,
                self.limits,
                Some("198.51.100.7".parse().expect("a literal address")),
            ),
        }
    }

    fn cookie(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let value = asterius_web::interaction::set_cookie(&self.interaction);
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(value.split(';').next().unwrap_or_default())
                .expect("a cookie header"),
        );
        headers
    }

    fn id(&self) -> String {
        self.interaction.expose().to_owned()
    }

    /// Draws options the way the script would, and returns the challenge.
    async fn options(&self, now: OffsetDateTime) -> (StatusCode, serde_json::Value) {
        let response = passkeys::login_options(
            self.context(),
            &self.id(),
            &self.cookie(),
            &json_body(&json!({ "csrf": CSRF })),
            now,
        )
        .await;
        let status = response.status();
        let body = body_of(response).await;
        (
            status,
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// A finish body for an assertion this fixture's authenticator produces.
    fn assertion(&self, challenge: &[u8], flags: u8, sign_count: u32) -> serde_json::Value {
        let client = client_data(ORIGIN, challenge);
        let data = Authenticator::authenticator_data(RP_ID, flags, sign_count);
        let signature = self.authenticator.sign(&data, &client);
        json!({
            "csrf": CSRF,
            "type": "public-key",
            "rawId": base64_url(&self.authenticator.credential_id),
            "clientDataJSON": base64_url(&client),
            "authenticatorData": base64_url(&data),
            "signature": base64_url(&signature),
            "userHandle": base64_url(self.user.as_bytes()),
        })
    }

    async fn finish(&self, body: &serde_json::Value, now: OffsetDateTime) -> Response {
        passkeys::login_finish(
            self.context(),
            &self.id(),
            &self.cookie(),
            &json_body(body),
            now,
        )
        .await
    }
}

// ---- abuse protection (ast-2vk.9) ---------------------------------------

/// The passkey ceremony names nobody, so the only bucket it has is the client
/// address — and that is exactly the one that bounds a credential-id sweep.
#[tokio::test]
async fn repeated_refused_assertions_from_one_address_are_throttled() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let mut fixture = Fixture::at_login(now, 0);
    fixture.limits = LoginLimits {
        per_address: RateLimit {
            max: 2,
            window: Duration::minutes(15),
        },
        per_account: RateLimit {
            max: 2,
            window: Duration::minutes(15),
        },
    };
    let nonsense = json!({ "csrf": CSRF, "type": "not-a-public-key" });

    // Act
    for _ in 0..2 {
        let refused = fixture.finish(&nonsense, now).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    }
    let throttled = fixture.finish(&nonsense, now).await;

    // Assert
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        throttled.headers().contains_key(header::RETRY_AFTER),
        "no Retry-After on a throttled assertion"
    );
}

/// A refusal that never reached the ceremony is still worth a trail record.
#[tokio::test]
async fn a_throttled_assertion_is_audited() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let mut fixture = Fixture::at_login(now, 0);
    fixture.limits = LoginLimits {
        per_address: RateLimit {
            max: 1,
            window: Duration::minutes(15),
        },
        per_account: RateLimit {
            max: 1,
            window: Duration::minutes(15),
        },
    };
    let nonsense = json!({ "csrf": CSRF, "type": "not-a-public-key" });

    // Act
    fixture.finish(&nonsense, now).await;
    fixture.finish(&nonsense, now).await;

    // Assert
    let recorded: Vec<_> = fixture
        .audit
        .0
        .lock()
        .expect("lock")
        .iter()
        .map(|event| event.event_type)
        .collect();
    assert!(
        recorded.contains(&asterius_domain::audit::EventType::AUTH_THROTTLED),
        "no throttle record: {recorded:?}"
    );
}

async fn body_of(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read the body");
    String::from_utf8_lossy(&bytes).into_owned()
}

fn json_body(value: &serde_json::Value) -> Bytes {
    Bytes::from(value.to_string())
}

/// A refusal, with the correlation id removed: two refusals are the same
/// answer when everything an attacker can see is the same, and a correlation
/// id is deliberately not the same twice.
async fn refusal(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let body = body_of(response).await;
    let mut value: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    if let Some(object) = value.as_object_mut() {
        object.remove("correlation_id");
    }
    (status, value.to_string())
}

// ---- options ------------------------------------------------------------

/// The username-less flow: nothing about a user is named in the options, so
/// nothing about a user can be learned from them.
#[tokio::test]
async fn options_name_no_credentials_and_no_user() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 0);

    // Act
    let (status, document) = fixture.options(now).await;

    // Assert
    assert_eq!(status, StatusCode::OK);
    assert_eq!(document["rpId"], RP_ID);
    assert_eq!(document["userVerification"], "required");
    assert!(
        document.get("allowCredentials").is_none(),
        "a discoverable-credential request names no credential ids: {document}"
    );
    assert!(
        document.get("user").is_none(),
        "the options must not describe an account: {document}"
    );
}

#[tokio::test]
async fn options_without_the_synchroniser_token_are_refused() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 0);

    // Act
    let response = passkeys::login_options(
        fixture.context(),
        &fixture.id(),
        &fixture.cookie(),
        &json_body(&json!({ "csrf": "not-the-token" })),
        now,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        fixture.passkeys.challenge.lock().expect("lock").is_none(),
        "a refused request must not leave a challenge outstanding"
    );
}

/// FAPI 2.0 SP §6.5: the id in the path and the id in the cookie must agree,
/// and a disagreement ends the flow rather than continuing it.
#[tokio::test]
async fn an_interaction_id_that_does_not_match_the_cookie_is_destroyed() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 0);
    let other = asterius_web::interaction::InteractionId::generate();

    // Act
    let response = passkeys::login_options(
        fixture.context(),
        other.expose(),
        &fixture.cookie(),
        &json_body(&json!({ "csrf": CSRF })),
        now,
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(*fixture.requests.destroyed.lock().expect("lock"));
}

// ---- finish -------------------------------------------------------------

#[tokio::test]
async fn a_verified_assertion_starts_a_session_and_advances_the_interaction() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 4);
    let (_, options) = fixture.options(now).await;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().expect("a challenge"))
        .expect("base64url");

    // Act
    let response = fixture
        .finish(&fixture.assertion(&challenge, UP | UV, 5), now)
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let sessions = fixture.sessions.0.lock().expect("lock");
    let session = sessions.first().expect("a session was started");
    assert_eq!(session.user, *fixture.user.as_uuid());
    assert_eq!(fixture.requests.stage(), Some(Stage::Consent));
    assert_eq!(fixture.requests.session(), Some(session.id_digest.clone()));
}

/// RFC 8176: `swk` because this server cannot prove hardware, and `user`
/// because the UV bit was set. No `pin`: nothing in an assertion says so.
#[tokio::test]
async fn a_user_verified_assertion_is_recorded_as_swk_and_user() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 0);
    let (_, options) = fixture.options(now).await;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().expect("a challenge"))
        .expect("base64url");

    // Act
    fixture
        .finish(&fixture.assertion(&challenge, UP | UV, 0), now)
        .await;

    // Assert
    let sessions = fixture.sessions.0.lock().expect("lock");
    let session = sessions.first().expect("a session was started");
    assert_eq!(
        session.amr,
        vec![
            AuthenticationMethod::Passkey,
            AuthenticationMethod::UserVerified
        ]
    );
    assert_eq!(
        session
            .amr
            .iter()
            .map(|m| m.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        "swk user"
    );
}

/// WebAuthn L3 §13.4.3: comparing a challenge is not consuming it. A second
/// finish with the same assertion is a replay, and the store must not answer
/// it twice.
#[tokio::test]
async fn a_challenge_is_spent_once() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 0);
    let (_, options) = fixture.options(now).await;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().expect("a challenge"))
        .expect("base64url");
    let assertion = fixture.assertion(&challenge, UP | UV, 1);

    // Act
    let first = fixture.finish(&assertion, now).await;
    let second = fixture.finish(&assertion, now).await;

    // Assert
    assert_eq!(first.status(), StatusCode::NO_CONTENT);
    assert_eq!(second.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        fixture.sessions.0.lock().expect("lock").len(),
        1,
        "a replayed assertion must not start a second session"
    );
}

/// §6.1.1: an authenticator that does not count reports zero for ever, and a
/// synchronised passkey generally does. Refusing it would refuse most of the
/// credentials this server exists to accept.
#[tokio::test]
async fn an_authenticator_that_reports_zero_signs_in() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 0);
    let (_, options) = fixture.options(now).await;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().expect("a challenge"))
        .expect("base64url");

    // Act
    let response = fixture
        .finish(&fixture.assertion(&challenge, UP | UV, 0), now)
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        *fixture.passkeys.recorded.lock().expect("lock"),
        vec![None],
        "a counter that does not count must not be written as if it had moved"
    );
    assert!(fixture.passkeys.disabled.lock().expect("lock").is_empty());
}

/// §7.2 step 21, and the bead's rule: a counter that went backwards blocks the
/// credential and is written to the trail.
#[tokio::test]
async fn a_counter_that_went_backwards_blocks_the_credential_and_is_audited() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 9);
    let (_, options) = fixture.options(now).await;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().expect("a challenge"))
        .expect("base64url");

    // Act
    let response = fixture
        .finish(&fixture.assertion(&challenge, UP | UV, 4), now)
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        fixture.sessions.0.lock().expect("lock").is_empty(),
        "a cloned authenticator must not sign anybody in"
    );
    assert_eq!(fixture.passkeys.disabled.lock().expect("lock").len(), 1);
    let events = fixture.audit.0.lock().expect("lock");
    let event = events.first().expect("a refusal is recorded");
    assert_eq!(event.event_type.as_str(), "auth.failed");
    let reason = event
        .detail
        .iter()
        .find(|(key, _)| key.as_str() == "reason")
        .map(|(_, value)| value.clone());
    assert_eq!(
        reason,
        Some(DetailValue::Text("sign_count_regression".to_owned())),
        "an operator has to be able to find this event by its reason"
    );
}

/// The anti-enumeration requirement: an unknown credential id and a signature
/// that does not verify are one answer, and neither says which.
#[tokio::test]
async fn an_unknown_credential_and_a_bad_signature_are_the_same_refusal() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let unknown = Fixture::at_login(now, 0);
    *unknown.passkeys.credential.lock().expect("lock") = None;
    let (_, options) = unknown.options(now).await;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().expect("a challenge"))
        .expect("base64url");

    let forged = Fixture::at_login(now, 0);
    let (_, other_options) = forged.options(now).await;
    let other_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(other_options["challenge"].as_str().expect("a challenge"))
        .expect("base64url");
    let mut bad = forged.assertion(&other_challenge, UP | UV, 1);
    bad["signature"] = json!(base64_url(&[3_u8; 70]));

    // Act
    let a = refusal(
        unknown
            .finish(&unknown.assertion(&challenge, UP | UV, 1), now)
            .await,
    )
    .await;
    let b = refusal(forged.finish(&bad, now).await).await;

    // Assert
    assert_eq!(a, b);
    assert_eq!(a.0, StatusCode::BAD_REQUEST);
}

/// §7.2 step 17, with `uv=required`: a credential that proved only presence is
/// not one this server treats as sufficient on its own.
#[tokio::test]
async fn an_assertion_without_user_verification_is_refused() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 0);
    let (_, options) = fixture.options(now).await;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().expect("a challenge"))
        .expect("base64url");

    // Act
    let response = fixture
        .finish(&fixture.assertion(&challenge, UP, 1), now)
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.sessions.0.lock().expect("lock").is_empty());
}

/// §7.2 steps 6 and 7: a user handle that is not the credential's owner is not
/// a request this server completes, whatever the signature says.
#[tokio::test]
async fn a_user_handle_for_another_account_is_refused() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 0);
    let (_, options) = fixture.options(now).await;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(options["challenge"].as_str().expect("a challenge"))
        .expect("base64url");
    let mut assertion = fixture.assertion(&challenge, UP | UV, 1);
    assertion["userHandle"] = json!(base64_url(UserId::generate().as_bytes()));

    // Act
    let response = fixture.finish(&assertion, now).await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.sessions.0.lock().expect("lock").is_empty());
}

/// A finish with no challenge outstanding is refused before anything is
/// parsed, which is what makes the challenge the gate rather than the
/// signature.
#[tokio::test]
async fn a_finish_without_an_outstanding_challenge_is_refused() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 0);

    // Act
    let response = fixture
        .finish(&fixture.assertion(&[7_u8; 32], UP | UV, 1), now)
        .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(fixture.sessions.0.lock().expect("lock").is_empty());
}

/// The signature this suite produces is the one the specification describes,
/// not one this code and its test agreed on: `authenticatorData ||
/// SHA-256(clientDataJSON)`, verified here against the raw public key.
#[tokio::test]
async fn the_signed_bytes_are_the_ones_the_specification_names() {
    // Arrange
    let authenticator = Authenticator::new();
    let client = client_data(ORIGIN, &[1_u8; 32]);
    let data = Authenticator::authenticator_data(RP_ID, UP | UV, 1);
    let signature = authenticator.sign(&data, &client);
    let mut signed = data.clone();
    signed.extend_from_slice(&asterius_domain::sha256(&client));

    // Act
    let outcome = UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        authenticator.pair.public_key().as_ref(),
    )
    .verify(&signed, &signature);

    // Assert
    assert!(outcome.is_ok());
}

/// A session is what these endpoints produce, so one must not be required to
/// reach them: the fixture sends no session cookie anywhere above, and this
/// says so once, deliberately.
#[tokio::test]
async fn signing_in_needs_no_session_cookie() {
    // Arrange
    let now = OffsetDateTime::now_utc();
    let fixture = Fixture::at_login(now, 0);
    let headers = fixture.cookie();

    // Act, Assert
    assert!(
        !headers
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .contains(asterius_domain::entities::session::COOKIE_NAME),
        "these endpoints are reached before any session exists"
    );
    let (status, _) = fixture.options(now).await;
    assert_eq!(status, StatusCode::OK);
    let _ = SessionId::generate();
}
