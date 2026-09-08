//! The interaction endpoints, end to end, with an in-memory store.
//!
//! What is under test is the order the checks run in and what each failure
//! produces — the two-credential rule, the CSRF token, and the fact that a
//! browser mismatch destroys the interaction rather than re-rendering it.

use asterius_domain::{
    AuthenticationMethod, ClientId, CredentialVerifier, DomainError, InteractionRecord,
    InteractionRepository, Issuer, Lifetimes, Participant, Secret, Session, SessionRepository,
    SessionRevocation, Tenant, TenantId, TenantStatus,
};
use asterius_server::http::interaction::{InteractionContext, show, submit};
use asterius_web::csp::Nonce;
use asterius_web::interaction::{COOKIE_NAME, InteractionId, StoredState};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::Value;
use std::sync::Mutex;
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";

/// One interaction, in memory.
#[derive(Debug, Default)]
struct FakeStore {
    record: Mutex<Option<(String, InteractionRecord)>>,
    destroyed: Mutex<Vec<String>>,
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
                }),
                state,
                session: None,
                expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(10),
            },
        ));
        store
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
    async fn find(&self, _d: &str) -> Result<Option<Session>, DomainError> {
        Ok(None)
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

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::new("demo"),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        custom_host: None,
        display_name: "Demo".into(),
        status: TenantStatus::Active,
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

fn context<'a>(
    tenant: &'a Tenant,
    store: &'a FakeStore,
    nonce: &'a Nonce,
    auth: Option<&'a dyn CredentialVerifier>,
    sessions: &'a FakeSessions,
) -> InteractionContext<'a> {
    InteractionContext {
        tenant,
        requests: store,
        credentials: auth,
        sessions,
        lifetimes: Lifetimes::default(),
        username: Some("ada"),
        clients: &FakeClients,
        nonce,
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

// ---- the two-credential rule (FAPI 2.0 SP §6.5) ------------------------

#[tokio::test]
async fn a_matching_path_and_cookie_render_the_login_page() {
    let id = InteractionId::generate();
    let store = FakeStore::with(&id.digest(), serde_json::json!({"stage": "login"}));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();

    let response = show(
        context(&tenant, &store, &nonce, None, &sessions),
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

    let response = show(
        context(&tenant, &store, &nonce, None, &sessions),
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

    let response = show(
        context(&tenant, &store, &nonce, None, &sessions),
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

    let response = show(
        context(&tenant, &store, &nonce, None, &sessions),
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
    let auth = AlwaysSucceeds;

    for body in [
        "username=ada&password=hunter2",
        "csrf=&username=ada&password=hunter2",
        "csrf=forged&username=ada&password=hunter2",
    ] {
        let response = submit(
            context(&tenant, &store, &nonce, Some(&auth), &sessions),
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
    let issued = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let auth = AlwaysSucceeds;

    let response = submit(
        context(&tenant, &store, &nonce, Some(&auth), &sessions),
        id.expose(),
        &cookie_header(id.expose()),
        &Bytes::from(format!(
            "csrf={}&username=ada&password=hunter2",
            issued.expose()
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
    let issued = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();

    let body = Bytes::from(format!("csrf={}&username=ada", issued.expose()));

    // First: accepted, and re-rendered with a message because no password.
    let first = submit(
        context(&tenant, &store, &nonce, Some(&AlwaysSucceeds), &sessions),
        id.expose(),
        &cookie_header(id.expose()),
        &body,
        OffsetDateTime::now_utc(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    // Second: the same body, now refused.
    let second = submit(
        context(&tenant, &store, &nonce, Some(&AlwaysSucceeds), &sessions),
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
    let issued = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();

    let response = submit(
        context(&tenant, &store, &nonce, None, &sessions),
        id.expose(),
        &cookie_header(id.expose()),
        &Bytes::from(format!(
            "csrf={}&username=ada&password=hunter2",
            issued.expose()
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

    let first = body_of(
        show(
            context(&tenant, &store, &nonce, None, &sessions),
            id.expose(),
            &cookie_header(id.expose()),
            OffsetDateTime::now_utc(),
        )
        .await,
    )
    .await;
    let second = body_of(
        show(
            context(&tenant, &store, &nonce, None, &sessions),
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
    let issued = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    let auth = AlwaysSucceeds;

    let response = submit(
        context(&tenant, &store, &nonce, Some(&auth), &sessions),
        id.expose(),
        &cookie_header(id.expose()),
        &Bytes::from(format!(
            "csrf={}&username=ada&password=hunter2",
            issued.expose()
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

// ---- the consent decision (ast-uwv.1) -----------------------------------

/// Sets up an interaction already at the consent stage, with an issued token.
fn at_consent() -> (InteractionId, FakeStore, String) {
    let id = InteractionId::generate();
    let mut state = StoredState {
        stage: asterius_web::interaction::Stage::Consent,
        csrf_digest: None,
        decision: None,
    };
    let issued = state.issue_csrf();
    let store = FakeStore::with(&id.digest(), serde_json::to_value(&state).expect("json"));
    (id, store, issued.expose().to_owned())
}

async fn submit_decision(
    id: &InteractionId,
    store: &FakeStore,
    body: &str,
) -> axum::response::Response {
    let tenant = tenant();
    let nonce = Nonce::generate();
    let sessions = FakeSessions::default();
    submit(
        context(&tenant, store, &nonce, None, &sessions),
        id.expose(),
        &cookie_header(id.expose()),
        &Bytes::from(body.to_owned()),
        OffsetDateTime::now_utc(),
    )
    .await
}

#[tokio::test]
async fn approving_records_the_scopes_that_were_granted() {
    let (id, store, csrf) = at_consent();

    let response = submit_decision(
        &id,
        &store,
        &format!("csrf={csrf}&decision=allow&scope=openid&scope=payments"),
    )
    .await;

    // `ast-gxh.4` turns the decision into a code; until then the stage
    // advances and stops.
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let state = store.state().expect("present");
    assert_eq!(state["stage"], "response");
    assert_eq!(state["decision"]["outcome"], "approved");
    assert_eq!(
        state["decision"]["scopes"],
        serde_json::json!(["openid", "payments"])
    );
}

/// The user may grant less than was asked, and the grant records what they
/// actually agreed to.
#[tokio::test]
async fn a_narrowed_approval_records_only_what_was_ticked() {
    let (id, store, csrf) = at_consent();

    let response = submit_decision(
        &id,
        &store,
        &format!("csrf={csrf}&decision=allow&scope=openid"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let state = store.state().expect("present");
    assert_eq!(
        state["decision"]["scopes"],
        serde_json::json!(["openid"]),
        "the decision recorded a scope the user unticked"
    );
}

/// Deny is a decision, not an error. It takes the same path as an approval.
#[tokio::test]
async fn denying_is_recorded_as_a_decision() {
    let (id, store, csrf) = at_consent();

    let response = submit_decision(&id, &store, &format!("csrf={csrf}&decision=deny")).await;

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let state = store.state().expect("present");
    assert_eq!(state["stage"], "response", "a denial did not advance");
    assert_eq!(state["decision"]["outcome"], "denied");
}

/// `openid` cannot be declined: dropping it would change what the client
/// receives without telling it.
#[tokio::test]
async fn an_approval_that_drops_a_required_scope_is_refused() {
    let (id, store, csrf) = at_consent();

    let response = submit_decision(
        &id,
        &store,
        &format!("csrf={csrf}&decision=allow&scope=payments"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let state = store.state().expect("present");
    assert_eq!(state["stage"], "consent", "the stage advanced anyway");
    assert!(state.get("decision").is_none_or(serde_json::Value::is_null));
}

/// A form field is a claim by the browser; what this server displayed is the
/// authority.
#[tokio::test]
async fn a_scope_that_was_never_offered_cannot_be_granted() {
    let (id, store, csrf) = at_consent();

    let response = submit_decision(
        &id,
        &store,
        &format!("csrf={csrf}&decision=allow&scope=openid&scope=admin"),
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(store.state().expect("present")["stage"], "consent");
}

#[tokio::test]
async fn a_submission_with_neither_button_is_refused() {
    let (id, store, csrf) = at_consent();
    let response = submit_decision(&id, &store, &format!("csrf={csrf}&scope=openid")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(store.state().expect("present")["stage"], "consent");
}

/// A decision needs the token like everything else.
#[tokio::test]
async fn a_decision_without_the_issued_token_is_forbidden() {
    let (id, store, _csrf) = at_consent();
    let response = submit_decision(&id, &store, "decision=allow&scope=openid").await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(store.state().expect("present")["stage"], "consent");
}
