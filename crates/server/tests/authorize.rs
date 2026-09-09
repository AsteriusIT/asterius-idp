//! `/authorize`, end to end (RFC 9126 §4).
//!
//! The debt `ast-gxh.1` recorded is settled here: a `request_uri` issued to one
//! client and presented under another must render a page, never a redirect.

use asterius_domain::{
    AuthRequestRepository, ClientId, Consumed, DomainError, InteractionRecord,
    InteractionRepository, Issuer, PushedRequest, Tenant, TenantId, TenantStatus,
};
use asterius_oidc::decision::DecisionPolicy;
use asterius_oidc::par::MintedRequestUri;
use asterius_server::http::authorize::{AuthorizeContext, authorize};
use asterius_web::csp::Nonce;
use asterius_web::interaction::COOKIE_NAME;
use axum::http::{StatusCode, header};
use serde_json::Value;
use std::sync::Mutex;
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";

#[derive(Debug, Default)]
struct Store {
    pushed: Mutex<Vec<PushedRequest>>,
    begun: Mutex<Vec<(String, String)>>,
    fail_begin: bool,
}

impl Store {
    fn with(request: PushedRequest) -> Self {
        let store = Self::default();
        store.pushed.lock().expect("lock").push(request);
        store
    }
}

#[async_trait::async_trait]
impl AuthRequestRepository for Store {
    async fn push(&self, r: &PushedRequest) -> Result<(), DomainError> {
        self.pushed.lock().expect("lock").push(r.clone());
        Ok(())
    }
    async fn consume(&self, _d: &str, _n: OffsetDateTime) -> Result<Consumed, DomainError> {
        Ok(Consumed::NotFound)
    }
    async fn peek(
        &self,
        digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<PushedRequest>, DomainError> {
        Ok(self
            .pushed
            .lock()
            .expect("lock")
            .iter()
            .find(|r| r.request_uri_digest == digest && r.expires_at > now)
            .cloned())
    }
}

#[async_trait::async_trait]
impl InteractionRepository for Store {
    async fn begin_interaction(
        &self,
        request: &str,
        interaction: &str,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if self.fail_begin {
            return Err(DomainError::Conflict("already begun".to_owned()));
        }
        self.begun
            .lock()
            .expect("lock")
            .push((request.to_owned(), interaction.to_owned()));
        Ok(())
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
        _sess: Option<&str>,
        _n: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn complete_interaction(
        &self,
        _digest: &str,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Ok(())
    }
    async fn destroy_interaction(&self, _d: &str) -> Result<(), DomainError> {
        Ok(())
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

fn request(client: &str, digest: &str, expires_at: OffsetDateTime) -> PushedRequest {
    PushedRequest {
        tenant: TenantId::new("demo"),
        request_uri_digest: digest.to_owned(),
        client: ClientId::new(client),
        parameters: serde_json::json!({"redirect_uri": "https://rp.example/cb"}),
        dpop_jkt: None,
        pushed_at: OffsetDateTime::now_utc(),
        expires_at,
    }
}

fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

async fn run(store: &Store, params: &[(&str, &str)]) -> axum::response::Response {
    run_with(store, params, None).await
}

/// The same, for a browser that already has a session (`ast-gxh.8`).
async fn run_with(
    store: &Store,
    params: &[(&str, &str)],
    session: Option<&asterius_domain::Session>,
) -> axum::response::Response {
    let tenant = tenant();
    let nonce = Nonce::generate();
    authorize(
        AuthorizeContext {
            tenant: &tenant,
            requests: store,
            interactions: store,
            session,
            policy: DecisionPolicy::default(),
            nonce: &nonce,
        },
        &pairs(params),
        // The subject this client would see. Fixed, so a test that names a
        // different one in an `id_token_hint` is naming somebody else.
        async |_client: &ClientId, _user: uuid::Uuid| Some(SUBJECT.to_owned()),
        OffsetDateTime::now_utc(),
    )
    .await
}

/// The `sub` `run_with`'s resolver answers with.
const SUBJECT: &str = "sub-of-this-user";

/// A usable session, authenticated `age` ago.
fn session(age: time::Duration) -> asterius_domain::Session {
    let mut session = asterius_domain::Session::begin(
        TenantId::new("demo"),
        &asterius_domain::entities::session::SessionId::generate(),
        uuid::Uuid::nil(),
        vec![asterius_domain::AuthenticationMethod::Password],
        OffsetDateTime::now_utc(),
        asterius_domain::Lifetimes {
            idle: time::Duration::hours(1),
            absolute: time::Duration::days(1),
        },
    );
    session.authenticated_at = OffsetDateTime::now_utc() - age;
    session
}

/// A stored request with parameters of this test's choosing.
fn request_with(digest: &str, parameters: Value) -> PushedRequest {
    PushedRequest {
        parameters,
        ..request("billing", digest, later())
    }
}

fn later() -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::seconds(90)
}

// ---- the happy path ------------------------------------------------------

#[tokio::test]
async fn a_live_request_redirects_into_an_interaction() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request("billing", minted.digest(), later()));

    let response = run(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
    )
    .await;

    // RFC 9700 §4: 303, never 307. Compared as a number so this test does
    // not itself name the constant the source audit is looking for.
    assert_eq!(response.status().as_u16(), 303);
    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(location.starts_with("/interaction/"), "{location}");

    // The browser's credential, in a cookie with every attribute it needs.
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .expect("cookie");
    assert!(cookie.starts_with(COOKIE_NAME), "{cookie}");
    for attribute in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(cookie.contains(attribute), "missing {attribute}: {cookie}");
    }
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");

    // The interaction id in the URL is the one in the cookie, and neither is
    // the `request_uri`.
    let from_path = location.trim_start_matches("/interaction/");
    assert!(cookie.contains(from_path), "the URL and cookie disagree");
    assert!(
        !minted.uri().contains(from_path),
        "the interaction id was derived from the request_uri"
    );

    assert_eq!(store.begun.lock().expect("lock").len(), 1);
}

// ---- the debt ast-gxh.1 recorded ----------------------------------------

/// A `request_uri` issued to one client, presented under another.
#[tokio::test]
async fn a_request_uri_presented_under_another_client_is_refused_without_a_redirect() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request("billing", minted.digest(), later()));

    let response = run(
        &store,
        &[("client_id", "attacker"), ("request_uri", minted.uri())],
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        !response.headers().contains_key(header::LOCATION),
        "RFC 6749 §4.1.2.1: this must not redirect"
    );
    assert!(
        !response.headers().contains_key(header::SET_COOKIE),
        "an interaction cookie was issued to the wrong client"
    );
    assert!(
        store.begun.lock().expect("lock").is_empty(),
        "an interaction was begun for the wrong client"
    );
}

// ---- everything else is a page ------------------------------------------

#[tokio::test]
async fn an_unknown_or_expired_request_uri_is_one_answer() {
    let minted = MintedRequestUri::generate();

    // Never pushed.
    let empty = Store::default();
    let unknown = run(
        &empty,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
    )
    .await;

    // Pushed, but expired.
    let stale = Store::with(request(
        "billing",
        minted.digest(),
        OffsetDateTime::now_utc() - time::Duration::seconds(1),
    ));
    let expired = run(
        &stale,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
    )
    .await;

    assert_eq!(unknown.status(), expired.status());
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    for response in [unknown, expired] {
        assert!(!response.headers().contains_key(header::LOCATION));
    }
}

/// FAPI 2.0 SP §5.3.2.2 item 3: an authorization request that did not come
/// through PAR is rejected. There is no code path here that reads `scope` or
/// `redirect_uri` from the URL, so a full non-PAR request is simply missing
/// the only parameter that matters.
#[tokio::test]
async fn an_authorization_request_without_par_is_refused() {
    let store = Store::default();
    let response = run(
        &store,
        &[
            ("client_id", "billing"),
            ("response_type", "code"),
            ("redirect_uri", "https://rp.example/cb"),
            ("scope", "openid"),
            ("state", "xyz"),
        ],
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::LOCATION));
}

#[tokio::test]
async fn a_missing_client_id_is_refused() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request("billing", minted.digest(), later()));
    let response = run(&store, &[("request_uri", minted.uri())]).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(store.begun.lock().expect("lock").is_empty());
}

/// RFC 6749 §3.1: a repeated parameter is refused, not resolved. Two
/// `client_id` values would otherwise let an attacker choose which one this
/// server compares and which one an intermediary logs.
#[tokio::test]
async fn a_repeated_parameter_is_refused() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request("billing", minted.digest(), later()));

    let response = run(
        &store,
        &[
            ("client_id", "billing"),
            ("client_id", "attacker"),
            ("request_uri", minted.uri()),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(store.begun.lock().expect("lock").is_empty());
}

/// A value this server could not have issued never reaches the database.
#[tokio::test]
async fn a_malformed_request_uri_is_refused_without_a_lookup() {
    let store = Store::default();
    for wrong in [
        "urn:ietf:params:oauth:request_uri:short",
        "https://as.example/request/abc",
        "",
        "urn:ietf:params:oauth:request_uri:",
    ] {
        let response = run(&store, &[("client_id", "billing"), ("request_uri", wrong)]).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "accepted {wrong:?}"
        );
    }
}

/// A second `/authorize` on one `request_uri` is a replay, and the store
/// refuses it. The browser gets a page, not somebody else's flow.
#[tokio::test]
async fn a_second_authorize_on_one_request_uri_is_refused() {
    let minted = MintedRequestUri::generate();
    let mut store = Store::with(request("billing", minted.digest(), later()));
    store.fail_begin = true;

    let response = run(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
}

/// The error page says nothing about which client, which tenant, or which
/// check failed.
#[tokio::test]
async fn the_error_page_names_nothing_about_the_request() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request("billing", minted.digest(), later()));
    let response = run(
        &store,
        &[("client_id", "attacker"), ("request_uri", minted.uri())],
    )
    .await;

    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("body");
    let html = String::from_utf8_lossy(&body);
    assert!(!html.contains("billing"), "{html}");
    assert!(!html.contains("attacker"), "{html}");
    assert!(
        !html.contains(minted.uri()),
        "the request_uri was echoed onto the page"
    );
    assert!(html.contains("cannot be continued"), "{html}");
}

// ---- ast-gxh.8: prompt, max_age and the unmet-requirements error ---------

/// OIDC Core §3.1.2.1: with `prompt=none` the server "MUST NOT display any
/// authentication or consent user interface pages", and §3.1.2.6 gives the
/// answer instead — `login_required` when there is nobody signed in.
///
/// The assertion that matters is the *absence*: no interaction was begun and no
/// cookie was set, so nothing was put in front of a user.
#[tokio::test]
async fn prompt_none_without_a_session_redirects_login_required_without_a_page() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request_with(
        minted.digest(),
        serde_json::json!({
            "redirect_uri": "https://rp.example/cb",
            "prompts": ["none"],
            "state": "s-1",
        }),
    ));

    let response = run(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
    )
    .await;

    assert_eq!(response.status().as_u16(), 303);
    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(location.starts_with("https://rp.example/cb?"), "{location}");
    assert!(location.contains("error=login_required"), "{location}");
    // RFC 6749 §4.1.2.1 and RFC 9207 §3: the client's `state` comes back, and
    // so does the issuer that answered.
    assert!(location.contains("state=s-1"), "{location}");
    assert!(location.contains("iss="), "{location}");
    assert!(
        store.begun.lock().expect("lock").is_empty(),
        "an interaction was begun for a request that may not display one"
    );
    assert!(!response.headers().contains_key(header::SET_COOKIE));
}

/// The other half of §3.1.2.6, and the reason the four codes exist: a
/// signed-in browser is not refused `login_required` — it is refused
/// `consent_required`, which tells the client to retry *with* a prompt rather
/// than to sign the user in again.
///
/// Consent is required of every request today because nothing in this server
/// records that it was given before; `asterius_oidc::decision` documents that
/// seam, and its table already answers `Interaction::Silent` for the row a
/// consent memory would fill in. What is asserted here is what this server
/// actually does, not what it will do.
#[tokio::test]
async fn prompt_none_with_a_usable_session_is_refused_consent_required() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request_with(
        minted.digest(),
        serde_json::json!({
            "redirect_uri": "https://rp.example/cb",
            "prompts": ["none"],
        }),
    ));
    let session = session(time::Duration::minutes(1));

    let response = run_with(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
        Some(&session),
    )
    .await;

    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(location.contains("error=consent_required"), "{location}");
    assert!(
        store.begun.lock().expect("lock").is_empty(),
        "a request that may not display anything reached the interaction"
    );
}

/// §3.1.2.1: `max_age` is measured from `auth_time`, and an authentication
/// older than it must be repeated — which `prompt=none` forbids.
#[tokio::test]
async fn prompt_none_past_max_age_is_refused_login_required() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request_with(
        minted.digest(),
        serde_json::json!({
            "redirect_uri": "https://rp.example/cb",
            "prompts": ["none"],
            "max_age": 60,
        }),
    ));
    let session = session(time::Duration::minutes(10));

    let response = run_with(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
        Some(&session),
    )
    .await;

    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(location.contains("error=login_required"), "{location}");
    assert!(store.begun.lock().expect("lock").is_empty());
}

/// §3.1.2.1: the request is about the person the verified `id_token_hint`
/// named. A session about somebody else does not answer it, and without an
/// account chooser the code is `login_required` (§3.1.2.6).
#[tokio::test]
async fn a_hint_naming_another_subject_is_refused_login_required() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request_with(
        minted.digest(),
        serde_json::json!({
            "redirect_uri": "https://rp.example/cb",
            "prompts": ["none"],
            "id_token_hint_sub": "somebody-else",
        }),
    ));
    let session = session(time::Duration::minutes(1));

    let response = run_with(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
        Some(&session),
    )
    .await;

    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(location.contains("error=login_required"), "{location}");
}

/// OIDC Core Unmet Authentication Requirements 1.0 §2: an essential `acr` this
/// tenant cannot produce is refused as such, whatever `prompt` said — no
/// interaction would make it meetable.
#[tokio::test]
async fn an_essential_acr_the_tenant_cannot_meet_is_refused_as_unmet() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request_with(
        minted.digest(),
        serde_json::json!({
            "redirect_uri": "https://rp.example/cb",
            "claims": {"acr": {"essential": true, "values": ["urn:mace:incommon:iap:silver"]}},
        }),
    ));

    let response = run(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
    )
    .await;

    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(
        location.contains("error=unmet_authentication_requirements"),
        "{location}"
    );
    assert!(store.begun.lock().expect("lock").is_empty());
}

/// `ast-gxh.5`: an error reaches the client the way the client asked to be
/// answered. A `form_post` request that cannot be served gets the form, not a
/// query redirect it is not listening for.
#[tokio::test]
async fn an_unservable_form_post_request_is_refused_by_form_post() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request_with(
        minted.digest(),
        serde_json::json!({
            "redirect_uri": "https://rp.example/cb",
            "response_mode": "form_post",
            "prompts": ["none"],
            "state": "s-2",
        }),
    ));

    let response = run(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(header::LOCATION));
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .expect("body");
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("https://rp.example/cb"), "{html}");
    assert!(html.contains("login_required"), "{html}");
    assert!(html.contains("s-2"), "{html}");
}

/// An ordinary request — no `prompt`, no session — still walks into the
/// interaction. The decision must not have turned every first visit into an
/// error.
#[tokio::test]
async fn an_ordinary_request_still_reaches_the_interaction() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request("billing", minted.digest(), later()));

    let response = run(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
    )
    .await;

    assert_eq!(response.status().as_u16(), 303);
    assert_eq!(store.begun.lock().expect("lock").len(), 1);
}
