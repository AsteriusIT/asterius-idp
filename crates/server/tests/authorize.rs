//! `/authorize`, end to end (RFC 9126 §4).
//!
//! The debt `ast-gxh.1` recorded is settled here: a `request_uri` issued to one
//! client and presented under another must render a page, never a redirect.

use asterius_domain::{
    AuthRequestRepository, ClientId, Consumed, DomainError, InteractionRecord,
    InteractionRepository, Issuer, PushedRequest, Tenant, TenantId, TenantStatus,
};
use asterius_oidc::consent_memory::MemoryPolicy;
use asterius_oidc::decision::DecisionPolicy;
use asterius_oidc::par::MintedRequestUri;
use asterius_server::http::authorize::{AuthorizeContext, authorize};
use asterius_server::tenancy::MountPrefix;
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
    /// Every state this handler wrote: the interaction, the document, and the
    /// session it was attached to. Kept because *where an interaction begins*
    /// is a fact only this write records (`ast-ovr`, `ast-k7f`).
    states: Mutex<Vec<(String, Value, Option<String>)>>,
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
    /// `/authorize` never opens one: a first-party interaction has no
    /// `request_uri` behind it, and this store is the authorization one.
    async fn begin_first_party_interaction(
        &self,
        _digest: &str,
        _destination: asterius_domain::FirstPartyDestination,
        _expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        Err(DomainError::NotFound)
    }

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
        digest: &str,
        state: &Value,
        session: Option<&str>,
        _n: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.states.lock().expect("lock").push((
            digest.to_owned(),
            state.clone(),
            session.map(ToOwned::to_owned),
        ));
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

/// The grants this user already holds — the consent memory (`ast-uwv.3`).
///
/// There is no consent table: what a person has agreed to is what their grants
/// record, so a fake that returns grants is a fake that returns memories.
#[derive(Debug, Default)]
struct Grants(Vec<asterius_domain::Grant>);

#[async_trait::async_trait]
impl asterius_domain::GrantRepository for Grants {
    async fn create(&self, _grant: &asterius_domain::Grant) -> Result<(), DomainError> {
        Ok(())
    }

    async fn for_subject(
        &self,
        _subject: &asterius_domain::SubjectId,
    ) -> Result<Vec<asterius_domain::Grant>, DomainError> {
        Ok(self.0.clone())
    }
}

/// The accounts, for the one thing `/authorize` reads them for: the name the
/// consent screen puts on the person a session names (`ast-k7f`, `ast-bo5`).
#[derive(Debug, Default)]
struct Directory;

/// The username [`Directory`] answers with.
const USERNAME: &str = "ada";

#[async_trait::async_trait]
impl asterius_domain::UserDirectory for Directory {
    async fn by_id(
        &self,
        id: asterius_domain::UserId,
    ) -> Result<Option<asterius_domain::User>, DomainError> {
        Ok(Some(asterius_domain::User {
            tenant: TenantId::new("demo"),
            id,
            username: USERNAME.to_owned(),
            email: None,
            email_verified: false,
            status: asterius_domain::UserStatus::Active,
            claims: asterius_domain::ClaimSet::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }))
    }
}

/// The same, for a browser that already has a session (`ast-gxh.8`).
async fn run_with(
    store: &Store,
    params: &[(&str, &str)],
    session: Option<&asterius_domain::Session>,
) -> axum::response::Response {
    run_remembering(store, params, session, &Grants::default()).await
}

/// The same again, for a browser whose user already holds grants.
async fn run_remembering(
    store: &Store,
    params: &[(&str, &str)],
    session: Option<&asterius_domain::Session>,
    grants: &Grants,
) -> axum::response::Response {
    run_mounted(store, params, session, grants, MountPrefix::root()).await
}

/// The same again, for a request that arrived under a tenant prefix.
///
/// Everything else in this file runs at the root, which is the shape of a
/// host-resolved tenant; `mount` is what a path-resolved one carries
/// (`ast-295`).
async fn run_mounted(
    store: &Store,
    params: &[(&str, &str)],
    session: Option<&asterius_domain::Session>,
    grants: &Grants,
    mount: MountPrefix,
) -> axum::response::Response {
    let tenant = tenant();
    let nonce = Nonce::generate();
    authorize(
        AuthorizeContext {
            tenant: &tenant,
            requests: store,
            interactions: store,
            session,
            grants,
            users: &Directory,
            policy: DecisionPolicy::default(),
            acr: &asterius_domain::AcrPolicy::default(),
            memory: MemoryPolicy::default(),
            nonce: &nonce,
            mount,
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

/// A stored `claims` request, in the shape `/par` writes down.
///
/// The parsed request re-emitted by `ClaimsRequest::to_json`, never the
/// client's document: `http::par` stores `request.claims.to_json()` and
/// `/authorize` reads it back with `ClaimsRequest::from_json`. A fixture
/// holding a hand-written document would assert against a value this server
/// never stores — once parsed, `acr` lives under `id_token` (OIDC Core
/// §5.5.1.1).
fn stored_claims(document: &str) -> Value {
    asterius_oidc::claims::ClaimsRequest::parse(document)
        .expect("a claims request this server accepts")
        .to_json()
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

/// The same redirect, for a tenant named by the path rather than the host.
///
/// `/interaction/{id}` is mounted under the tenant and nowhere else, so a
/// `Location` without the prefix is a 404 the browser meets on its way to the
/// login page (`ast-295`).
#[tokio::test]
async fn the_redirect_keeps_the_prefix_the_request_arrived_under() {
    let minted = MintedRequestUri::generate();
    let store = Store::with(request("billing", minted.digest(), later()));

    let response = run_mounted(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
        None,
        &Grants::default(),
        MountPrefix::for_tenant(&asterius_domain::TenantId::new("demo")),
    )
    .await;

    assert_eq!(response.status().as_u16(), 303);
    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(
        location.starts_with("/t/demo/interaction/"),
        "the tenant fell out of the redirect: {location}"
    );
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
/// This user holds no grant for this client, so the consent memory has nothing
/// to say and the honest answer is that consent is required (`ast-uwv.3`).
#[tokio::test]
async fn prompt_none_with_a_usable_session_and_no_memory_is_refused_consent_required() {
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

// ---- consent memory (`ast-uwv.3`) ----------------------------------------

/// A grant this user already holds, covering `scopes`.
fn held(scopes: &[&str]) -> asterius_domain::Grant {
    let mut grant = asterius_domain::Grant::new(
        TenantId::new("demo"),
        ClientId::new("billing"),
        OffsetDateTime::now_utc() - time::Duration::days(1),
    );
    grant.subject = Some(asterius_domain::SubjectId::new(SUBJECT.to_owned()));
    grant.scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
    grant
}

/// A stored `prompt=none` request asking for `scopes`.
fn silent_request(digest: &str, scopes: &[&str]) -> PushedRequest {
    request_with(
        digest,
        serde_json::json!({
            "redirect_uri": "https://rp.example/cb",
            "prompts": ["none"],
            "scopes": scopes,
        }),
    )
}

/// The row of `asterius_oidc::decision`'s table that had nothing to fill it in:
/// everything is in place *including* consent, so the request is answered
/// without disturbing anybody. Without this a hidden-frame session poll can
/// never succeed, which is the blockage `ast-gxh.8` recorded at the HTTP level.
#[tokio::test]
async fn prompt_none_over_a_remembered_consent_is_answered_silently() {
    // Arrange: the user has already granted this client exactly this.
    let minted = MintedRequestUri::generate();
    let store = Store::with(silent_request(minted.digest(), &["openid", "profile"]));
    let session = session(time::Duration::minutes(1));
    let grants = Grants(vec![held(&["openid", "profile"])]);

    // Act.
    let response = run_remembering(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
        Some(&session),
        &grants,
    )
    .await;

    // Assert: no refusal — the request continues into the interaction, which
    // is what every non-refusing decision does.
    assert!(response.status().is_redirection(), "{}", response.status());
    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(location.starts_with("/interaction/"), "{location}");
    assert_eq!(store.begun.lock().expect("lock").len(), 1);
}

/// The widening rule, at the HTTP level: the same test as
/// `a_remembered_scope_does_not_widen_to_one_that_was_never_granted` in
/// `asterius_oidc::consent_memory`, asserted where it matters — a client that
/// asks for more than was granted is refused rather than answered.
#[tokio::test]
async fn a_remembered_consent_does_not_widen_to_a_scope_that_was_never_granted() {
    // Arrange: `openid` was granted; `payments` never was.
    let minted = MintedRequestUri::generate();
    let store = Store::with(silent_request(minted.digest(), &["openid", "payments"]));
    let session = session(time::Duration::minutes(1));
    let grants = Grants(vec![held(&["openid"])]);

    // Act.
    let response = run_remembering(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
        Some(&session),
        &grants,
    )
    .await;

    // Assert: the new scope has to be consented to, and `prompt=none` forbids
    // asking, so the client is told so.
    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(location.contains("error=consent_required"), "{location}");
}

/// OIDC Core §11: the OP "MUST obtain explicit consent" for offline access. A
/// consent for ordinary scopes is not that consent, so a client adding
/// `offline_access` to a request it has made before still meets the screen.
#[tokio::test]
async fn offline_access_is_not_covered_by_an_ordinary_remembered_consent() {
    // Arrange: everything but `offline_access` has been granted.
    let minted = MintedRequestUri::generate();
    let store = Store::with(silent_request(
        minted.digest(),
        &["openid", "profile", "offline_access"],
    ));
    let session = session(time::Duration::minutes(1));
    let grants = Grants(vec![held(&["openid", "profile"])]);

    // Act.
    let response = run_remembering(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
        Some(&session),
        &grants,
    )
    .await;

    // Assert.
    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(location.contains("error=consent_required"), "{location}");
}

/// Point 3 of the ticket, end to end: revocation traverses the memory. A grant
/// the user withdrew must not answer for them at the next request.
#[tokio::test]
async fn a_revoked_grant_does_not_answer_for_the_user_again() {
    // Arrange: the grant that covered this request has been revoked.
    let minted = MintedRequestUri::generate();
    let store = Store::with(silent_request(minted.digest(), &["openid", "profile"]));
    let session = session(time::Duration::minutes(1));
    let mut revoked = held(&["openid", "profile"]);
    revoked.revoked_at = Some(OffsetDateTime::now_utc() - time::Duration::hours(1));
    let grants = Grants(vec![revoked]);

    // Act.
    let response = run_remembering(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
        Some(&session),
        &grants,
    )
    .await;

    // Assert.
    let location = response.headers()[header::LOCATION]
        .to_str()
        .expect("location");
    assert!(location.contains("error=consent_required"), "{location}");
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
            "claims": stored_claims(
                r#"{"id_token": {"acr": {"essential": true, "values": ["urn:mace:incommon:iap:silver"]}}}"#,
            ),
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

// ---- where an interaction begins (`ast-ovr`, `ast-k7f`) ------------------

/// The state this handler wrote for the interaction it began, and the session
/// it attached to it.
fn beginning(store: &Store) -> (Value, Option<String>) {
    let states = store.states.lock().expect("lock");
    let (_, state, session) = states
        .last()
        .expect("the handler recorded where the interaction begins");
    (state.clone(), session.clone())
}

/// **`ast-k7f`**: a signed-in user meeting a client they have never consented
/// to begins at the consent stage, not at the sign-in form.
///
/// The decision is `Interaction::Consent`, and `decide` returns it only for a
/// session that is usable, fresh and about the right person. What is left to
/// do is one screen, and the session goes with the stage because the browser's
/// cookie is not something the interaction handler re-resolves.
#[tokio::test]
async fn a_signed_in_user_with_no_memory_of_this_client_begins_at_consent() {
    // Arrange: a live session, and a user holding no grant at all.
    let minted = MintedRequestUri::generate();
    let store = Store::with(request("billing", minted.digest(), later()));
    let session = session(time::Duration::minutes(1));

    // Act
    let response = run_with(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
        Some(&session),
    )
    .await;

    // Assert
    assert_eq!(response.status().as_u16(), 303);
    let (state, attached) = beginning(&store);
    assert_eq!(
        state["stage"],
        serde_json::json!("consent"),
        "a signed-in user was sent back to the login stage: {state}"
    );
    assert_eq!(
        attached.as_deref(),
        Some(session.id_digest.as_str()),
        "the stage was recorded without the session it is about"
    );
    // `ast-bo5`: no sign-in step ran, so this is the only place the name the
    // consent screen displays can come from.
    assert_eq!(
        state["username"],
        serde_json::json!(USERNAME),
        "the consent screen would name nobody: {state}"
    );
}

/// **OIDC Core §3.1.2.1**: `prompt=login` is not answered from a session,
/// however much a memory would have covered.
#[tokio::test]
async fn prompt_login_begins_at_the_login_stage_whatever_the_session_says() {
    // Arrange
    let minted = MintedRequestUri::generate();
    let store = Store::with(request_with(
        minted.digest(),
        serde_json::json!({
            "redirect_uri": "https://rp.example/cb",
            "prompts": ["login"],
        }),
    ));
    let session = session(time::Duration::minutes(1));

    // Act
    let response = run_with(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
        Some(&session),
    )
    .await;

    // Assert: nothing was recorded, which is how this handler says an
    // interaction starts at the beginning — `Stage::Login` is the default of
    // the state the interaction writes for itself.
    assert_eq!(response.status().as_u16(), 303);
    assert!(
        store.states.lock().expect("lock").is_empty(),
        "prompt=login began somewhere other than the sign-in form"
    );
}

/// **OIDC Core §3.1.2.3**: an authentication older than `max_age` is stale, and
/// a stale session cannot skip the sign-in form either.
#[tokio::test]
async fn an_exceeded_max_age_begins_at_the_login_stage() {
    // Arrange
    let minted = MintedRequestUri::generate();
    let store = Store::with(request_with(
        minted.digest(),
        serde_json::json!({
            "redirect_uri": "https://rp.example/cb",
            "max_age": 0,
        }),
    ));
    let session = session(time::Duration::minutes(30));

    // Act
    let response = run_with(
        &store,
        &[("client_id", "billing"), ("request_uri", minted.uri())],
        Some(&session),
    )
    .await;

    // Assert
    assert_eq!(response.status().as_u16(), 303);
    assert!(
        store.states.lock().expect("lock").is_empty(),
        "max_age was answered from an authentication that is too old"
    );
}
