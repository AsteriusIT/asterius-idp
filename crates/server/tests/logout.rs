//! The end-session endpoint, end to end, with in-memory stores.
//!
//! OpenID Connect RP-Initiated Logout 1.0 (Final, 2022-09). What is under test
//! is the order things happen in and what each request produces:
//!
//! * §2: a request the OP cannot verify gets a question, and gets it *before*
//!   anything about the session changes.
//! * §2: a `client_id` that contradicts a verified `id_token_hint` identifies
//!   nobody, and the page that follows carries no relying-party text.
//! * §4: an expired ID Token is still a usable hint, and so is one signed by a
//!   key that has since been retired from the published JWKS.
//! * §3: a `post_logout_redirect_uri` is honoured only on an exact match with a
//!   registered value; otherwise the neutral page is shown and no `state` is
//!   echoed anywhere.
//! * The session is revoked, the participant list is read for the
//!   back-channel notification, and the cookie is cleared.

use asterius_domain::entities::session::COOKIE_NAME;
use asterius_domain::keys::{KeyPurpose, KeyState, Kid, PublicKeyRecord, SigningAlgorithm};
use asterius_domain::{
    Actor, AuditEvent, AuditSink, AuthenticationMethod, Capabilities, Client, ClientId,
    ClientRegistration, ClientRepository, ClientStatus, DomainError, EventType, Issuer, KeyStore,
    Participant, Session, SessionRepository, SessionRevocation, Tenant, TenantId, TenantStatus,
};
use asterius_jose::SigningKey;
use asterius_oidc::logout::confirmation_token;
use asterius_server::http::logout::{LogoutContext, show, submit};
use asterius_web::csp::Nonce;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::{Value, json};
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};

const ISSUER: &str = "https://as.example/t/demo";
const CLIENT: &str = "billing";
const SESSION_COOKIE_VALUE: &str = "a-session-id-that-only-the-browser-holds";
/// The one post-logout redirect URI [`FakeClients`] registers (§3.1). Every
/// other spelling in this file is deliberately *not* this string.
const REGISTERED_POST_LOGOUT: &str = "https://rp.example/after-logout";

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

/// One session, plus the order in which it was operated on.
///
/// The order is the point of one test: §3 has the relying parties notified as
/// part of ending the session, before the browser is sent anywhere, so
/// `participants` must be reached and it must be reached after the revocation.
#[derive(Debug, Default)]
struct FakeSessions {
    session: Mutex<Option<Session>>,
    calls: Mutex<Vec<&'static str>>,
    participants: Vec<Participant>,
}

impl FakeSessions {
    fn holding(digest: &str, now: OffsetDateTime) -> Self {
        Self {
            session: Mutex::new(Some(Session {
                tenant: TenantId::new("demo"),
                id_digest: digest.to_owned(),
                public_sid: "the-public-sid".to_owned(),
                user: uuid::Uuid::from_u128(1),
                created_at: now,
                authenticated_at: now,
                last_seen_at: now,
                expires_at: now + Duration::hours(8),
                idle_expires_at: now + Duration::minutes(30),
                acr: None,
                amr: vec![AuthenticationMethod::Password],
                revoked: None,
            })),
            calls: Mutex::new(Vec::new()),
            participants: vec![Participant {
                client: ClientId::new(CLIENT),
                first_seen_at: now,
                last_seen_at: now,
            }],
        }
    }

    fn empty() -> Self {
        Self::default()
    }

    fn was_revoked(&self) -> bool {
        self.session
            .lock()
            .expect("lock")
            .as_ref()
            .is_some_and(|session| session.revoked.is_some())
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().expect("lock").clone()
    }
}

#[async_trait::async_trait]
impl SessionRepository for FakeSessions {
    async fn begin(&self, _session: &Session) -> Result<(), DomainError> {
        Ok(())
    }
    async fn find(&self, digest: &str) -> Result<Option<Session>, DomainError> {
        self.calls.lock().expect("lock").push("find");
        Ok(self
            .session
            .lock()
            .expect("lock")
            .clone()
            .filter(|session| session.id_digest == digest))
    }
    async fn touch(&self, _d: &str, _n: OffsetDateTime, _i: Duration) -> Result<(), DomainError> {
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
        digest: &str,
        reason: SessionRevocation,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.calls.lock().expect("lock").push("revoke");
        if let Some(session) = self.session.lock().expect("lock").as_mut()
            && session.id_digest == digest
            && session.revoked.is_none()
        {
            session.revoked = Some((now, reason));
        }
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
        self.calls.lock().expect("lock").push("participants");
        Ok(self.participants.clone())
    }
}

/// One registered client, so an identified relying party resolves.
#[derive(Debug)]
struct FakeClients;

#[async_trait::async_trait]
impl ClientRepository for FakeClients {
    async fn find(&self, client_id: &ClientId) -> Result<Option<Client>, DomainError> {
        if client_id.as_str() != CLIENT {
            return Ok(None);
        }
        let registration = ClientRegistration::from_json(
            &serde_json::to_vec(&json!({
                "client_name": "Billing",
                "redirect_uris": ["https://rp.example/cb"],
                "post_logout_redirect_uris": [REGISTERED_POST_LOGOUT],
                "grant_types": ["authorization_code"],
                "scope": "openid",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }))
            .expect("serialise"),
            Capabilities::default(),
        )
        .expect("a valid registration");
        Ok(Some(Client {
            tenant: TenantId::new("demo"),
            id: ClientId::new(CLIENT),
            registration,
            status: ClientStatus::Active,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }))
    }
}

/// This tenant's keys. `published` is what the JWKS serves; `retired` resolves
/// by `kid` only, which is the §4 case that matters.
#[derive(Debug)]
struct FakeKeys {
    published: Vec<PublicKeyRecord>,
    retired: Vec<PublicKeyRecord>,
}

impl FakeKeys {
    fn record(kid: &str, jwk: Value, state: KeyState) -> PublicKeyRecord {
        PublicKeyRecord {
            tenant: TenantId::new("demo"),
            kid: Kid::new(kid),
            algorithm: SigningAlgorithm::EdDsa,
            purpose: KeyPurpose::Signing,
            state,
            public_jwk: jwk,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }
}

#[async_trait::async_trait]
impl KeyStore for FakeKeys {
    async fn published_keys(&self, _t: &TenantId) -> Result<Vec<PublicKeyRecord>, DomainError> {
        Ok(self.published.clone())
    }
    async fn public_key(
        &self,
        _t: &TenantId,
        kid: &Kid,
    ) -> Result<Option<PublicKeyRecord>, DomainError> {
        Ok(self
            .published
            .iter()
            .chain(self.retired.iter())
            .find(|record| &record.kid == kid)
            .cloned())
    }
}

/// The audit trail, as recorded.
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

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("a fixed instant")
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

fn digest() -> String {
    asterius_domain::sha256_hex(SESSION_COOKIE_VALUE.as_bytes())
}

fn cookie() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{COOKIE_NAME}={SESSION_COOKIE_VALUE}")
            .parse()
            .expect("header"),
    );
    headers
}

/// An ID token this server would have issued, signed by `key`.
fn id_token(key: &SigningKey, kid: &str, claims: &Value) -> String {
    asterius_jose::jws::sign(key, &Kid::new(kid), "JWT", claims)
        .expect("sign")
        .as_str()
        .to_owned()
}

fn claims(audience: &Value, exp: i64) -> Value {
    json!({
        "iss": ISSUER,
        "sub": "user-1",
        "aud": audience,
        "azp": CLIENT,
        "exp": exp,
        "iat": now().unix_timestamp() - 60,
        "sid": "the-public-sid",
    })
}

/// The signing key, its published record, and a hint signed with it.
struct Fixture {
    key: SigningKey,
    kid: String,
}

impl Fixture {
    fn new() -> Self {
        Self {
            key: SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate"),
            kid: "k1".to_owned(),
        }
    }

    fn jwk(&self) -> Value {
        let mut jwk = self.key.public_jwk().expect("jwk");
        jwk["kid"] = json!(self.kid);
        jwk
    }

    fn published(&self) -> FakeKeys {
        FakeKeys {
            published: vec![FakeKeys::record(&self.kid, self.jwk(), KeyState::Active)],
            retired: Vec::new(),
        }
    }

    /// The key has left the JWKS. §4 still expects the hint to verify.
    fn retired(&self) -> FakeKeys {
        FakeKeys {
            published: Vec::new(),
            retired: vec![FakeKeys::record(&self.kid, self.jwk(), KeyState::Retired)],
        }
    }

    fn hint(&self, claims: &Value) -> String {
        id_token(&self.key, &self.kid, claims)
    }
}

fn pairs(raw: &[(&str, &str)]) -> Vec<(String, String)> {
    raw.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

struct Harness {
    sessions: FakeSessions,
    clients: FakeClients,
    keys: FakeKeys,
    audit: FakeAudit,
    tenant: Tenant,
    nonce: Nonce,
}

impl Harness {
    fn new(sessions: FakeSessions, keys: FakeKeys) -> Self {
        Self {
            sessions,
            clients: FakeClients,
            keys,
            audit: FakeAudit::default(),
            tenant: tenant(),
            nonce: Nonce::generate(),
        }
    }

    fn context(&self) -> LogoutContext<'_> {
        LogoutContext {
            tenant: &self.tenant,
            sessions: &self.sessions,
            clients: &self.clients,
            keys: &self.keys,
            audit: &self.audit,
            nonce: &self.nonce,
            request_id: Some("test-request"),
        }
    }

    async fn get(
        &self,
        headers: &HeaderMap,
        params: &[(&str, &str)],
    ) -> (StatusCode, HeaderMap, String) {
        parts(show(self.context(), headers, &pairs(params), now()).await).await
    }

    async fn post(
        &self,
        headers: &HeaderMap,
        params: &[(&str, &str)],
    ) -> (StatusCode, HeaderMap, String) {
        parts(submit(self.context(), headers, &pairs(params), now()).await).await
    }
}

async fn parts(response: axum::response::Response) -> (StatusCode, HeaderMap, String) {
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap_or_else(|_| Bytes::new());
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn cookie_was_cleared(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.starts_with(&format!("{COOKIE_NAME}=;")) && value.contains("Max-Age=0"))
}

// ---------------------------------------------------------------------------
// §2 — a request that cannot be verified is a question, not an action
// ---------------------------------------------------------------------------

/// The MUST that is easiest to get wrong: ask *before* changing the session.
#[tokio::test]
async fn a_request_with_no_hint_asks_before_anything_is_ended() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    let (status, headers, body) = harness.get(&cookie(), &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Log out of Demo?"), "{body}");
    assert!(
        !harness.sessions.was_revoked(),
        "the session was ended before the user answered"
    );
    assert!(
        !cookie_was_cleared(&headers),
        "the cookie was cleared before the user answered"
    );
    assert!(harness.audit.events().is_empty());
    assert!(
        !harness.sessions.calls().contains(&"revoke"),
        "{:?}",
        harness.sessions.calls()
    );
}

/// A hint that does not verify identifies nobody, and the page that follows
/// must not carry the relying party's chosen text: this is the anti-phishing
/// half of §2.
#[tokio::test]
async fn an_unverifiable_hint_gets_a_page_with_no_relying_party_branding() {
    let ours = Fixture::new();
    let stranger = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), ours.published());

    let forged = stranger.hint(&claims(&json!(CLIENT), now().unix_timestamp() + 600));
    let (status, _, body) = harness
        .get(
            &cookie(),
            &[
                ("id_token_hint", &forged),
                ("client_id", CLIENT),
                ("post_logout_redirect_uri", "https://evil.example/after"),
                ("state", "attacker-state"),
            ],
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Log out of Demo?"), "{body}");
    assert!(
        !body.contains("Billing"),
        "the page named the client: {body}"
    );
    assert!(!body.contains("evil.example"), "{body}");
    assert!(!body.contains("attacker-state"), "{body}");
    assert!(!harness.sessions.was_revoked());
}

/// §2: `client_id` and the ID Token's client must match. A disagreement is two
/// contradictory statements, and the answer is to believe neither.
#[tokio::test]
async fn a_client_id_that_contradicts_the_hint_identifies_nobody() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    let hint = fixture.hint(&claims(&json!(CLIENT), now().unix_timestamp() + 600));
    let (status, _, body) = harness
        .get(
            &cookie(),
            &[("id_token_hint", &hint), ("client_id", "someone-else")],
        )
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Log out of Demo?"), "{body}");
    assert!(!harness.sessions.was_revoked());
}

// ---------------------------------------------------------------------------
// §4 — what makes a hint usable
// ---------------------------------------------------------------------------

/// A verified hint is a request the OP can act on: the session ends, the
/// cookie goes, and the trail records who asked.
#[tokio::test]
async fn a_verified_hint_ends_the_session_and_clears_the_cookie() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    let hint = fixture.hint(&claims(&json!(CLIENT), now().unix_timestamp() + 600));
    let (status, headers, body) = harness.get(&cookie(), &[("id_token_hint", &hint)]).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("You are signed out"), "{body}");
    assert!(
        harness.sessions.was_revoked(),
        "the session outlived a logout"
    );
    assert!(cookie_was_cleared(&headers), "{headers:?}");

    let events = harness.audit.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].event_type, EventType::SESSION_REVOKED);
    assert_eq!(events[0].client, Some(ClientId::new(CLIENT)));
    assert_eq!(
        events[0].actor,
        Actor::User("00000000-0000-0000-0000-000000000001".to_owned())
    );
}

/// §4: "the OP SHOULD accept ID Tokens [...] even if they are expired". An
/// expired hint is the normal case — the user has been idle.
#[tokio::test]
async fn an_expired_hint_is_still_a_hint() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    let hint = fixture.hint(&claims(&json!(CLIENT), now().unix_timestamp() - 86_400));
    let (_, _, body) = harness.get(&cookie(), &[("id_token_hint", &hint)]).await;

    assert!(body.contains("You are signed out"), "{body}");
    assert!(harness.sessions.was_revoked());
}

/// The key that signed the hint may have left the published JWKS. It still has
/// to verify, or every rotation would break every outstanding logout link.
#[tokio::test]
async fn a_hint_signed_by_a_retired_key_still_verifies() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.retired());

    let hint = fixture.hint(&claims(&json!(CLIENT), now().unix_timestamp() - 10));
    let (_, _, body) = harness.get(&cookie(), &[("id_token_hint", &hint)]).await;

    assert!(body.contains("You are signed out"), "{body}");
    assert!(harness.sessions.was_revoked());
}

/// A hint for another issuer is not this server's token, whoever signed it.
#[tokio::test]
async fn a_hint_from_another_issuer_identifies_nobody() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    let mut foreign = claims(&json!(CLIENT), now().unix_timestamp() + 600);
    foreign["iss"] = json!("https://as.example/t/other");
    let hint = fixture.hint(&foreign);
    let (_, _, body) = harness.get(&cookie(), &[("id_token_hint", &hint)]).await;

    assert!(body.contains("Log out of Demo?"), "{body}");
    assert!(!harness.sessions.was_revoked());
}

// ---------------------------------------------------------------------------
// §3 — redirection
// ---------------------------------------------------------------------------

/// §3, the whole way through: a client registered under §3.1, a verified
/// `id_token_hint` naming it, and a `post_logout_redirect_uri` equal to what it
/// registered. The browser is sent onward with the `state` repeated — and only
/// after the session has actually ended.
#[tokio::test]
async fn a_registered_post_logout_redirect_uri_is_honoured_after_the_session_ends() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    let hint = fixture.hint(&claims(&json!(CLIENT), now().unix_timestamp() + 600));
    let (status, headers, _body) = harness
        .get(
            &cookie(),
            &[
                ("id_token_hint", &hint),
                ("post_logout_redirect_uri", REGISTERED_POST_LOGOUT),
                ("state", "opaque-state"),
            ],
        )
        .await;

    // 303, compared as a number: naming the constant here would be a second
    // place in the tree that spells `See Other`, and `source_audit` keeps that
    // spelling to `http::redirect::SeeOther` alone.
    assert_eq!(status.as_u16(), 303);
    let location = headers
        .get(header::LOCATION)
        .expect("a registered URI must be redirected to")
        .to_str()
        .expect("an ASCII Location");
    // §3: "the `state` parameter … SHOULD be returned … as a query parameter".
    assert_eq!(
        location,
        format!("{REGISTERED_POST_LOGOUT}?state=opaque-state")
    );
    assert!(harness.sessions.was_revoked(), "redirected without ending");
    assert!(cookie_was_cleared(&headers), "{headers:?}");
}

/// §3's match is byte for byte. Every URI here is a near miss of the one
/// registered value, and none of them may become a `Location` — an unmatched
/// URI gets the neutral page, and the `state` is echoed nowhere.
#[tokio::test]
async fn an_unregistered_post_logout_redirect_uri_is_not_honoured() {
    for near in [
        "https://rp.example/after-logout/",
        "https://rp.example/after-Logout",
        "https://rp.example/after-logout?x=1",
        "https://rp.example.evil/after-logout",
        "https://rp.example/after-logout2",
        "http://rp.example/after-logout",
    ] {
        let fixture = Fixture::new();
        let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

        let hint = fixture.hint(&claims(&json!(CLIENT), now().unix_timestamp() + 600));
        let (status, headers, body) = harness
            .get(
                &cookie(),
                &[
                    ("id_token_hint", &hint),
                    ("post_logout_redirect_uri", near),
                    ("state", "opaque-state"),
                ],
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{near} was redirected to");
        assert!(
            headers.get(header::LOCATION).is_none(),
            "{near}: {headers:?}"
        );
        assert!(body.contains("You are signed out"), "{body}");
        assert!(
            !body.contains("opaque-state"),
            "the state was echoed: {body}"
        );
        assert!(!body.contains("rp.example"), "{body}");
        // The session still ends: the user asked to log out and did.
        assert!(harness.sessions.was_revoked());
    }
}

/// §3 puts the relying parties before the browser. The participant list is
/// read as part of ending the session, after the revocation and before the
/// response is built — which is the shape back-channel logout (`E10_02`) drops
/// into.
#[tokio::test]
async fn the_participants_are_read_after_revoking_and_before_answering() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    let hint = fixture.hint(&claims(&json!(CLIENT), now().unix_timestamp() + 600));
    let _ = harness.get(&cookie(), &[("id_token_hint", &hint)]).await;

    let calls = harness.sessions.calls();
    let revoke = calls.iter().position(|call| *call == "revoke");
    let participants = calls.iter().position(|call| *call == "participants");
    assert!(revoke.is_some() && participants.is_some(), "{calls:?}");
    assert!(revoke < participants, "{calls:?}");

    let events = harness.audit.events();
    let recorded = events[0]
        .detail
        .iter()
        .any(|(key, _)| key == "participants");
    assert!(
        recorded,
        "the trail does not say how many RPs were involved"
    );
}

// ---------------------------------------------------------------------------
// The confirmation page's answer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_confirmed_logout_ends_the_session() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    let token = confirmation_token(SESSION_COOKIE_VALUE);
    let (status, headers, body) = harness
        .post(&cookie(), &[("decision", "logout"), ("csrf", &token)])
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("You are signed out"), "{body}");
    assert!(harness.sessions.was_revoked());
    assert!(cookie_was_cleared(&headers));
}

/// A forged logout is a denial of service, so the answer needs the token the
/// page carried — which only the holder of the session cookie can derive.
#[tokio::test]
async fn an_answer_without_this_sessions_token_changes_nothing() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    for csrf in [
        confirmation_token("some-other-session"),
        String::new(),
        "0".repeat(64),
    ] {
        let (status, _, _) = harness
            .post(&cookie(), &[("decision", "logout"), ("csrf", &csrf)])
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{csrf:?}");
        assert!(!harness.sessions.was_revoked(), "{csrf:?}");
    }
}

#[tokio::test]
async fn choosing_to_stay_signed_in_changes_nothing() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    let token = confirmation_token(SESSION_COOKIE_VALUE);
    let (status, headers, body) = harness
        .post(&cookie(), &[("decision", "stay"), ("csrf", &token)])
        .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("You are still signed in"), "{body}");
    assert!(!harness.sessions.was_revoked());
    assert!(!cookie_was_cleared(&headers));
}

// ---------------------------------------------------------------------------
// Edges
// ---------------------------------------------------------------------------

/// No session and no hint: there is nothing to end and nothing to ask. The
/// neutral page is the truthful answer, and it is the same one whether the
/// session expired an hour ago or never existed.
#[tokio::test]
async fn a_visitor_with_no_session_gets_the_neutral_page() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::empty(), fixture.published());

    let (status, _, body) = harness.get(&HeaderMap::new(), &[]).await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("You are signed out"), "{body}");
    assert!(harness.audit.events().is_empty());
}

/// A malformed request never gets a redirect and never ends a session.
#[tokio::test]
async fn a_repeated_parameter_is_refused_without_touching_the_session() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    let (status, headers, _) = harness
        .get(&cookie(), &[("state", "one"), ("state", "two")])
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(headers.get(header::LOCATION).is_none());
    assert!(!harness.sessions.was_revoked());
}

/// A `state` that tries to write a header of its own is refused at the parser,
/// long before anything would echo it.
#[tokio::test]
async fn a_state_carrying_a_newline_is_refused() {
    let fixture = Fixture::new();
    let harness = Harness::new(FakeSessions::holding(&digest(), now()), fixture.published());

    let (status, _, body) = harness
        .get(
            &cookie(),
            &[("state", "x\r\nLocation: https://evil.example")],
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!body.contains("evil.example"), "{body}");
}
