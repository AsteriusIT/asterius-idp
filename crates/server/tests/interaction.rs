//! The interaction endpoints, end to end, with an in-memory store.
//!
//! What is under test is the order the checks run in and what each failure
//! produces — the two-credential rule, the CSRF token, and the fact that a
//! browser mismatch destroys the interaction rather than re-rendering it.

use asterius_domain::{
    ClientId, DomainError, InteractionRecord, InteractionRepository, Issuer, Secret, Tenant,
    TenantId, TenantStatus,
};
use asterius_server::http::interaction::{InteractionContext, UserAuthentication, show, submit};
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
                parameters: serde_json::json!({"redirect_uri": "https://rp.example/cb"}),
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
impl UserAuthentication for AlwaysSucceeds {
    async fn verify(
        &self,
        _tenant: &Tenant,
        _username: &str,
        _password: Secret<String>,
    ) -> Result<Option<String>, DomainError> {
        Ok(Some("session-1".to_owned()))
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
    auth: Option<&'a dyn UserAuthentication>,
) -> InteractionContext<'a> {
    InteractionContext {
        tenant,
        requests: store,
        authentication: auth,
        nonce,
    }
}

// ---- the two-credential rule (FAPI 2.0 SP §6.5) ------------------------

#[tokio::test]
async fn a_matching_path_and_cookie_render_the_login_page() {
    let id = InteractionId::generate();
    let store = FakeStore::with(&id.digest(), serde_json::json!({"stage": "login"}));
    let tenant = tenant();
    let nonce = Nonce::generate();

    let response = show(
        context(&tenant, &store, &nonce, None),
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

    let response = show(
        context(&tenant, &store, &nonce, None),
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

    let response = show(
        context(&tenant, &store, &nonce, None),
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

    let response = show(
        context(&tenant, &store, &nonce, None),
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
    let auth = AlwaysSucceeds;

    for body in [
        "username=ada&password=hunter2",
        "csrf=&username=ada&password=hunter2",
        "csrf=forged&username=ada&password=hunter2",
    ] {
        let response = submit(
            context(&tenant, &store, &nonce, Some(&auth)),
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
    let auth = AlwaysSucceeds;

    let response = submit(
        context(&tenant, &store, &nonce, Some(&auth)),
        id.expose(),
        &cookie_header(id.expose()),
        &Bytes::from(format!(
            "csrf={}&username=ada&password=hunter2",
            issued.expose()
        )),
        OffsetDateTime::now_utc(),
    )
    .await;

    // Authenticated, so the interaction moved on. The consent page belongs to
    // ast-uwv.1, so the stage advanced but has nothing to render yet.
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let state = store.state().expect("still present");
    assert_eq!(state["stage"], "consent", "the stage did not advance");
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

    let body = Bytes::from(format!("csrf={}&username=ada", issued.expose()));

    // First: accepted, and re-rendered with a message because no password.
    let first = submit(
        context(&tenant, &store, &nonce, Some(&AlwaysSucceeds)),
        id.expose(),
        &cookie_header(id.expose()),
        &body,
        OffsetDateTime::now_utc(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    // Second: the same body, now refused.
    let second = submit(
        context(&tenant, &store, &nonce, Some(&AlwaysSucceeds)),
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

    let response = submit(
        context(&tenant, &store, &nonce, None),
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

    let first = body_of(
        show(
            context(&tenant, &store, &nonce, None),
            id.expose(),
            &cookie_header(id.expose()),
            OffsetDateTime::now_utc(),
        )
        .await,
    )
    .await;
    let second = body_of(
        show(
            context(&tenant, &store, &nonce, None),
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
