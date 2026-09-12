//! The token introspection endpoint (RFC 7662 §2.1, §2.2, §2.3, §4; RFC 9449
//! §6.2; RFC 8693 §4).
//!
//! Every test goes through the real handler with a real signed access token
//! and the real verifier — only the rows and the client authentication are
//! faked. An endpoint whose signature check was stubbed would be an endpoint
//! whose tests pass for tokens it must refuse.
//!
//! The tests are grouped by the question they answer:
//!
//! * who may call at all (§2.1, §2.3's 401);
//! * who may be told about a given token (§2.2's note, §4);
//! * what an active answer contains (§2.2, RFC 9449 §6.2, RFC 8693 §4);
//! * what makes a token inactive (expiry, denylist, cutoff, grant status);
//! * and that the answer costs the same whoever asks.

use asterius_domain::keys::{Signer as _, SigningAlgorithm};
use asterius_domain::{
    Capabilities, Client, ClientId, ClientRegistration, ClientRepository, ClientStatus,
    DomainError, Grant, GrantId, Issuer, ResourceIdentifier, ResourceRegistry, ResourceServer,
    SubjectId, Tenant, TenantId, TenantStatus,
};
use asterius_jose::{LocalKeyStore, SigningKey, thumbprint};
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::{AccessToken, Audience, Confirmation};
use asterius_server::http::introspection::{
    IntrospectionContext, IntrospectionSource, RefreshTokenFacts, introspect,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::{Duration, OffsetDateTime};

const ISSUER: &str = "https://as.example/t/demo";
const OWNER: &str = "billing";
const ACCOUNTS_API: &str = "https://api.example/accounts";
const PAYMENTS_API: &str = "https://api.example/payments";
const ACCOUNTS_RS: &str = "accounts-resource-server";
const PAYMENTS_RS: &str = "payments-resource-server";
const SUBJECT: &str = "SUBJECT-1";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
}

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::new("demo"),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        default_resource: ACCOUNTS_API.to_owned(),
        custom_host: None,
        display_name: "demo".to_owned(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn client(id: &str) -> Client {
    Client {
        tenant: TenantId::new("demo"),
        id: ClientId::new(id),
        registration: ClientRegistration::from_json(
            &serde_json::to_vec(&json!({
                "client_name": id,
                "redirect_uris": ["https://client.example/cb"],
                "grant_types": ["authorization_code", "refresh_token"],
                "scope": "openid accounts",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }))
            .expect("serialise"),
            Capabilities::default(),
        )
        .expect("a valid registration"),
        status: ClientStatus::Active,
        created_at: now(),
        updated_at: now(),
    }
}

/// A claimed grant for `scopes`, owned by [`OWNER`].
fn grant(scopes: &[&str]) -> Grant {
    let mut grant = Grant::new(TenantId::new("demo"), ClientId::new(OWNER), now());
    grant.user = Some(asterius_domain::UserId::generate());
    grant.subject = Some(SubjectId::new(SUBJECT));
    grant.scopes = scopes
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<BTreeSet<_>>();
    grant.claimed_at = Some(now());
    grant
}

/// The registry the tests push against: `accounts` is fronted by
/// [`ACCOUNTS_RS`], `payments` by [`PAYMENTS_RS`], and neither by the other.
fn registry() -> ResourceRegistry {
    ResourceRegistry::new([
        ResourceServer {
            identifier: ResourceIdentifier::parse(ACCOUNTS_API).expect("an identifier"),
            scopes: None,
            default_token_lifetime: None,
            introspection_clients: [ClientId::new(ACCOUNTS_RS)].into_iter().collect(),
        },
        ResourceServer {
            identifier: ResourceIdentifier::parse(PAYMENTS_API).expect("an identifier"),
            scopes: None,
            default_token_lifetime: None,
            introspection_clients: [ClientId::new(PAYMENTS_RS)].into_iter().collect(),
        },
    ])
}

/// The rows, as this endpoint sees them, and a count of what it asked for.
#[derive(Debug)]
struct FakeRows {
    grant: Option<Grant>,
    denylisted: bool,
    revoked_before: Option<OffsetDateTime>,
    refresh: Option<RefreshTokenFacts>,
    /// The client the refresh lookup will match, so that "not yours" can be a
    /// miss rather than a comparison in the test.
    refresh_owner: ClientId,
    registry: ResourceRegistry,
    reads: AtomicUsize,
}

impl Default for FakeRows {
    fn default() -> Self {
        Self {
            grant: Some(grant(&["openid", "accounts"])),
            denylisted: false,
            revoked_before: None,
            refresh: None,
            refresh_owner: ClientId::new(OWNER),
            registry: registry(),
            reads: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl IntrospectionSource for FakeRows {
    async fn is_denylisted(&self, _jti: &str) -> Result<bool, DomainError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.denylisted)
    }

    async fn access_tokens_revoked_before(
        &self,
        _client: &ClientId,
        _grant: Option<&GrantId>,
    ) -> Result<Option<OffsetDateTime>, DomainError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.revoked_before)
    }

    async fn grant(&self, _id: &GrantId) -> Result<Option<Grant>, DomainError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.grant.clone())
    }

    async fn resource_servers(&self) -> Result<ResourceRegistry, DomainError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.registry.clone())
    }

    async fn refresh_token(
        &self,
        _digest: &str,
        client: &ClientId,
        _now: OffsetDateTime,
    ) -> Result<Option<RefreshTokenFacts>, DomainError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        // The client is half of the lookup, exactly as in SQL.
        Ok(if *client == self.refresh_owner {
            self.refresh.clone()
        } else {
            None
        })
    }
}

/// A client directory that answers for every id the tests use.
#[derive(Debug)]
struct FakeClients;

#[async_trait::async_trait]
impl ClientRepository for FakeClients {
    async fn find(&self, id: &ClientId) -> Result<Option<Client>, DomainError> {
        Ok(Some(client(id.as_str())))
    }
}

/// An audit sink that keeps what it was given.
#[derive(Debug, Default)]
struct FakeAudit(std::sync::Mutex<Vec<asterius_domain::audit::AuditEvent>>);

#[async_trait::async_trait]
impl asterius_domain::audit::AuditSink for FakeAudit {
    async fn record(&self, event: asterius_domain::audit::AuditEvent) -> Result<(), DomainError> {
        self.0.lock().expect("a test lock").push(event);
        Ok(())
    }
}

struct Fixture {
    keys: Arc<LocalKeyStore>,
    rows: FakeRows,
    audit: FakeAudit,
    access_token: String,
    grant_id_exposed: bool,
}

impl Fixture {
    /// A token audienced at `audiences`, minted from a live grant of
    /// [`OWNER`].
    async fn new(audiences: &[&str]) -> Self {
        let keys = Arc::new(LocalKeyStore::new());
        keys.generate(&TenantId::new("demo"), SigningAlgorithm::DEFAULT)
            .expect("a tenant key");
        let dpop_key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("a DPoP key");
        let jkt = thumbprint(&dpop_key.public_jwk().expect("jwk")).expect("thumbprint");

        let grant = grant(&["openid", "accounts"]);
        let claimed = grant.claim(now()).expect("a live grant");
        let unsigned = AccessToken::new(
            &Issuer::parse(ISSUER).expect("issuer"),
            &grant,
            &claimed,
            Audience::new(audiences.iter().copied()).expect("audience"),
            Confirmation::dpop(&jkt).expect("confirmation"),
            JwtId::generate(),
            now(),
        )
        .with_grant_id()
        .build()
        .expect("an access token");
        let access_token = keys
            .sign(
                &TenantId::new("demo"),
                unsigned.required_algorithm(),
                unsigned.typ(),
                unsigned.claims(),
            )
            .await
            .expect("signed")
            .as_str()
            .to_owned();

        Self {
            keys,
            rows: FakeRows {
                grant: Some(grant),
                ..FakeRows::default()
            },
            audit: FakeAudit::default(),
            access_token,
            grant_id_exposed: true,
        }
    }

    /// Introspects `token` as `caller`, at `at`.
    async fn ask_at(&self, caller: &str, token: &str, at: OffsetDateTime) -> Response {
        let tenant = tenant();
        let clients = FakeClients;
        let body = axum::body::Bytes::from(format!(
            "token={}&token_type_hint=access_token",
            url::form_urlencoded::byte_serialize(token.as_bytes()).collect::<String>()
        ));
        let caller = caller.to_owned();
        introspect(
            IntrospectionContext {
                tenant: &tenant,
                clients: &clients,
                source: &self.rows,
                keys: self.keys.as_ref(),
                audit: &self.audit,
                grant_id_exposed: self.grant_id_exposed,
                now: at,
                certificate: None,
            },
            &form_headers(),
            &body,
            async move |_: &Attempt<'_>, _: &AssertionRules| Ok(client(&caller)),
        )
        .await
    }

    async fn ask(&self, caller: &str, token: &str) -> Response {
        self.ask_at(caller, token, now()).await
    }

    /// The answer as JSON.
    async fn answer(&self, caller: &str) -> Value {
        let response = self.ask(caller, &self.access_token).await;
        assert_eq!(response.status(), StatusCode::OK);
        body_json(response).await
    }
}

fn form_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers
}

async fn body_json(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).expect("JSON")
}

// ---------------------------------------------------------------------------
// §2.1 and §2.3 — who may call at all
// ---------------------------------------------------------------------------

/// §2.3: "If the protected resource uses OAuth 2.0 client credentials to
/// authenticate to the introspection endpoint and its credentials are invalid,
/// the authorization server responds with an HTTP 401". A statement about the
/// caller, not about any token, so it is the one refusal that is not
/// `active: false`.
#[tokio::test]
async fn an_unauthenticated_caller_is_refused_with_401() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;
    let tenant = tenant();
    let clients = FakeClients;
    let body = axum::body::Bytes::from(format!("token={}", fixture.access_token));

    // Act
    let response = introspect(
        IntrospectionContext {
            tenant: &tenant,
            clients: &clients,
            source: &fixture.rows,
            keys: fixture.keys.as_ref(),
            audit: &fixture.audit,
            grant_id_exposed: true,
            now: now(),
            certificate: None,
        },
        &form_headers(),
        &body,
        async |_: &Attempt<'_>, _: &AssertionRules| Err(ClientAuthError::UnknownClient),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        fixture.rows.reads.load(Ordering::SeqCst),
        0,
        "a caller that did not authenticate caused a store read"
    );
}

/// §2.1: `token` is REQUIRED, and a request without one is a malformed request
/// rather than a token that is not active. Nothing is looked up.
#[tokio::test]
async fn a_request_without_a_token_is_a_400() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;
    let tenant = tenant();
    let clients = FakeClients;

    // Act
    let response = introspect(
        IntrospectionContext {
            tenant: &tenant,
            clients: &clients,
            source: &fixture.rows,
            keys: fixture.keys.as_ref(),
            audit: &fixture.audit,
            grant_id_exposed: true,
            now: now(),
            certificate: None,
        },
        &form_headers(),
        &axum::body::Bytes::from_static(b"token_type_hint=access_token"),
        async |_: &Attempt<'_>, _: &AssertionRules| Ok(client(OWNER)),
    )
    .await;

    // Assert
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(response).await["error"], json!("invalid_request"));
}

// ---------------------------------------------------------------------------
// §2.2's note and §4 — who may be told about this token
// ---------------------------------------------------------------------------

/// §2.1: the client the token was issued to is an authorized caller. It could
/// have read every member of this answer out of its own token.
#[tokio::test]
async fn the_token_s_own_client_is_told() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;

    // Act
    let answer = fixture.answer(OWNER).await;

    // Assert
    assert_eq!(answer["active"], json!(true));
}

/// §4: "only allow … protected resources that are authorized to introspect".
/// The operator registered this client as the mouth of the accounts API.
#[tokio::test]
async fn a_registered_resource_server_for_the_audience_is_told() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;

    // Act
    let answer = fixture.answer(ACCOUNTS_RS).await;

    // Assert
    assert_eq!(answer["active"], json!(true));
}

/// The acceptance criterion, and §2.2's note: a caller that is neither the
/// token's client nor a resource server for its audience gets `active: false`
/// — a 200, not an error, and indistinguishable from an expired token.
#[tokio::test]
async fn an_unauthorised_caller_is_told_the_token_is_not_active() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;

    // Act
    let answer = fixture.answer(PAYMENTS_RS).await;

    // Assert
    assert_eq!(answer, json!({ "active": false }));
}

/// The same for a client the tenant registered but never named as a resource
/// server: a registration is not an entitlement.
#[tokio::test]
async fn a_registered_client_that_fronts_nothing_is_told_nothing() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;

    // Act
    let answer = fixture.answer("some-other-client").await;

    // Assert
    assert_eq!(answer, json!({ "active": false }));
}

/// A token minted for two APIs is introspectable by each of them: the one it
/// is presented at is the one entitled to decide about it.
#[tokio::test]
async fn either_named_resource_server_is_told() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API, PAYMENTS_API]).await;

    // Act
    let accounts = fixture.answer(ACCOUNTS_RS).await;
    let payments = fixture.answer(PAYMENTS_RS).await;

    // Assert
    assert_eq!(accounts["active"], json!(true));
    assert_eq!(payments["active"], json!(true));
}

/// §4 again, from the other side: an unauthorized caller must not be able to
/// tell "this token is not yours" from "this token does not exist". The two
/// requests produce byte-identical bodies.
#[tokio::test]
async fn not_yours_and_never_existed_are_the_same_answer() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;

    // Act
    let not_yours = fixture.answer(PAYMENTS_RS).await;
    let never_existed = body_json(fixture.ask(PAYMENTS_RS, "not-a-token-at-all").await).await;

    // Assert
    assert_eq!(not_yours, never_existed);
}

// ---------------------------------------------------------------------------
// The non-divergence property
// ---------------------------------------------------------------------------

/// The acceptance criterion's "constant response time", asserted by counting
/// the work rather than by timing it (see the module documentation of
/// `asterius_server::http::introspection`).
///
/// An authorized caller and an unauthorized one must make this endpoint do the
/// same reads. A short-circuit that skipped the denylist, the cutoffs, the
/// grant and the registry for the unauthorized caller would be visible in
/// latency and in database load — §4's oracle by another route.
#[tokio::test]
async fn an_unauthorised_caller_costs_exactly_what_an_authorised_one_costs() {
    // Arrange
    let authorised = Fixture::new(&[ACCOUNTS_API]).await;
    let unauthorised = Fixture::new(&[ACCOUNTS_API]).await;

    // Act
    let told = authorised.answer(ACCOUNTS_RS).await;
    let refused = unauthorised.answer(PAYMENTS_RS).await;

    // Assert
    assert_eq!(told["active"], json!(true));
    assert_eq!(refused["active"], json!(false));
    assert_eq!(
        authorised.rows.reads.load(Ordering::SeqCst),
        unauthorised.rows.reads.load(Ordering::SeqCst),
        "the two callers did different amounts of work"
    );
    assert!(
        authorised.rows.reads.load(Ordering::SeqCst) >= 4,
        "the fixture did not exercise the reads it is meant to count"
    );
}

/// The same property for a *revoked* token: the reads happen before the
/// liveness decision too, so "revoked" and "live" cost the same.
#[tokio::test]
async fn a_revoked_token_costs_what_a_live_one_costs() {
    // Arrange
    let live = Fixture::new(&[ACCOUNTS_API]).await;
    let mut revoked = Fixture::new(&[ACCOUNTS_API]).await;
    revoked.rows.denylisted = true;

    // Act
    let live_answer = live.answer(ACCOUNTS_RS).await;
    let revoked_answer = revoked.answer(ACCOUNTS_RS).await;

    // Assert
    assert_eq!(live_answer["active"], json!(true));
    assert_eq!(revoked_answer, json!({ "active": false }));
    assert_eq!(
        live.rows.reads.load(Ordering::SeqCst),
        revoked.rows.reads.load(Ordering::SeqCst),
    );
}

// ---------------------------------------------------------------------------
// §2.2 — what an active answer contains
// ---------------------------------------------------------------------------

/// §2.2's members, plus RFC 9449 §6.2's `cnf`. Read off a token this server
/// actually signed, so the answer is checked against the claims rather than
/// against a hand-written expectation.
#[tokio::test]
async fn an_active_answer_carries_the_members_a_resource_server_needs() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;

    // Act
    let answer = fixture.answer(ACCOUNTS_RS).await;

    // Assert
    assert_eq!(answer["active"], json!(true));
    assert_eq!(answer["token_type"], json!("Bearer"));
    assert_eq!(answer["iss"], json!(ISSUER));
    assert_eq!(answer["client_id"], json!(OWNER));
    assert_eq!(answer["sub"], json!(SUBJECT));
    assert_eq!(answer["scope"], json!("accounts openid"));
    assert_eq!(answer["aud"], json!(ACCOUNTS_API));
    assert_eq!(answer["iat"], json!(now().unix_timestamp()));
    assert!(answer["exp"].is_i64(), "{answer}");
    assert!(answer["jti"].is_string(), "{answer}");
    // RFC 9449 §6.2: the binding, so a resource server that did not verify the
    // token itself does not treat a DPoP-bound token as a bearer one.
    assert!(answer["cnf"]["jkt"].is_string(), "{answer}");
}

/// `ast-txw`: the private correlator follows the tenant's switch, and this
/// endpoint takes that decision rather than making a second one.
#[tokio::test]
async fn the_grant_id_is_withheld_when_the_tenant_withholds_it() {
    // Arrange
    let mut fixture = Fixture::new(&[ACCOUNTS_API]).await;
    let exposed = fixture.answer(ACCOUNTS_RS).await;
    fixture.grant_id_exposed = false;

    // Act
    let withheld = fixture.answer(ACCOUNTS_RS).await;

    // Assert
    assert!(exposed["grant_id"].is_string(), "{exposed}");
    assert!(withheld.get("grant_id").is_none(), "{withheld}");
}

// ---------------------------------------------------------------------------
// §2.2 — what makes a token inactive
// ---------------------------------------------------------------------------

/// §2.2: `active` means "the token was issued … and has not expired". A token
/// past its own `exp` is not active — and the caller is told nothing else.
#[tokio::test]
async fn an_expired_token_is_not_active() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;
    let long_after = now() + Duration::days(365);

    // Act
    let response = fixture
        .ask_at(ACCOUNTS_RS, &fixture.access_token, long_after)
        .await;

    // Assert
    assert_eq!(body_json(response).await, json!({ "active": false }));
}

/// FAPI 2.0 SP §5.3.4 item 3: a `jti` on the denylist is a token this server
/// no longer stands behind, whoever asks.
#[tokio::test]
async fn a_denylisted_token_is_not_active() {
    // Arrange
    let mut fixture = Fixture::new(&[ACCOUNTS_API]).await;
    fixture.rows.denylisted = true;

    // Act
    let answer = fixture.answer(ACCOUNTS_RS).await;

    // Assert
    assert_eq!(answer, json!({ "active": false }));
}

/// RFC 7009 §2.1 and RFC 7592 §2.3: the bulk withdrawal nobody can enumerate.
/// A cutoff after the token's `iat` withdraws it.
#[tokio::test]
async fn a_token_behind_a_revocation_cutoff_is_not_active() {
    // Arrange
    let mut fixture = Fixture::new(&[ACCOUNTS_API]).await;
    fixture.rows.revoked_before = Some(now() + Duration::seconds(1));

    // Act
    let answer = fixture.answer(ACCOUNTS_RS).await;

    // Assert
    assert_eq!(answer, json!({ "active": false }));
}

/// A token whose grant has been revoked is not active, even though the token
/// itself is inside its `exp` and carries no denylisted `jti`.
#[tokio::test]
async fn a_token_of_a_revoked_grant_is_not_active() {
    // Arrange
    let mut fixture = Fixture::new(&[ACCOUNTS_API]).await;
    let mut revoked = fixture.rows.grant.clone().expect("a fixture grant");
    revoked.revoked_at = Some(now());
    revoked.revocation_reason = Some(asterius_domain::RevocationReason::UserRevoked);
    fixture.rows.grant = Some(revoked);

    // Act
    let answer = fixture.answer(ACCOUNTS_RS).await;

    // Assert
    assert_eq!(answer, json!({ "active": false }));
}

/// A token naming a grant this tenant does not hold is not active. The row is
/// the authority the token draws on, and a token whose authority cannot be
/// found is not one this server will describe.
#[tokio::test]
async fn a_token_whose_grant_is_gone_is_not_active() {
    // Arrange
    let mut fixture = Fixture::new(&[ACCOUNTS_API]).await;
    fixture.rows.grant = None;

    // Act
    let answer = fixture.answer(ACCOUNTS_RS).await;

    // Assert
    assert_eq!(answer, json!({ "active": false }));
}

/// A value this server never issued — a forgery, another issuer's token, a
/// random string — is `active: false` and not an error. §2.2's note again, and
/// §4's reason: the alternative answers "is this a live credential here?".
#[tokio::test]
async fn a_token_this_server_did_not_issue_is_not_active() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;

    // Act
    let response = fixture.ask(ACCOUNTS_RS, "eyJhbGciOiJub25lIn0.e30.").await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await, json!({ "active": false }));
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

fn refresh_facts() -> RefreshTokenFacts {
    RefreshTokenFacts {
        grant: GrantId::new("11111111-1111-4111-8111-111111111111"),
        scopes: ["accounts".to_owned(), "offline_access".to_owned()]
            .into_iter()
            .collect(),
        issued_at: now(),
        expires_at: now() + Duration::days(30),
        confirmation: Some(json!({ "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" })),
    }
}

/// A refresh token is introspectable by the client it was issued to.
#[tokio::test]
async fn a_client_may_introspect_its_own_refresh_token() {
    // Arrange
    let mut fixture = Fixture::new(&[ACCOUNTS_API]).await;
    fixture.rows.refresh = Some(refresh_facts());
    let minted = asterius_oidc::refresh::MintedRefreshToken::generate();

    // Act
    let response = fixture.ask(OWNER, minted.expose()).await;

    // Assert
    let answer = body_json(response).await;
    assert_eq!(answer["active"], json!(true));
    assert_eq!(answer["client_id"], json!(OWNER));
    assert_eq!(answer["scope"], json!("accounts offline_access"));
    assert_eq!(
        answer["exp"],
        json!((now() + Duration::days(30)).unix_timestamp())
    );
    // A refresh token has no audience: it is presented at the token endpoint,
    // and inventing one would tell a resource server it is something it could
    // be shown.
    assert!(answer.get("aud").is_none(), "{answer}");
}

/// The acceptance criterion: a refresh token is introspectable **only** by its
/// client. A resource server registered for every audience this tenant has is
/// still told nothing, because there is no audience a refresh token names.
#[tokio::test]
async fn a_resource_server_may_not_introspect_a_refresh_token() {
    // Arrange
    let mut fixture = Fixture::new(&[ACCOUNTS_API]).await;
    fixture.rows.refresh = Some(refresh_facts());
    let minted = asterius_oidc::refresh::MintedRefreshToken::generate();

    // Act
    let response = fixture.ask(ACCOUNTS_RS, minted.expose()).await;

    // Assert
    assert_eq!(body_json(response).await, json!({ "active": false }));
}

// ---------------------------------------------------------------------------
// The trail
// ---------------------------------------------------------------------------

/// Every call is recorded, whatever the answer: a scan is invisible in any
/// single response, so a run of entries against one caller is the only place
/// it shows (RFC 7662 §4).
#[tokio::test]
async fn every_call_is_recorded_including_the_ones_that_said_nothing() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;

    // Act
    let _told = fixture.answer(ACCOUNTS_RS).await;
    let _refused = fixture.answer(PAYMENTS_RS).await;

    // Assert
    let recorded = fixture.audit.0.lock().expect("a test lock");
    assert_eq!(recorded.len(), 2, "an introspection went unrecorded");
    for event in recorded.iter() {
        assert_eq!(
            event.event_type,
            asterius_domain::audit::EventType::TOKEN_INTROSPECTED
        );
    }
}

/// The trail records the outcome but never the credential: no entry may
/// contain the token, and none may name the client the token was issued to —
/// which would be the map of which resource server holds whose tokens.
#[tokio::test]
async fn the_trail_holds_neither_the_token_nor_the_client_it_was_issued_to() {
    // Arrange
    let fixture = Fixture::new(&[ACCOUNTS_API]).await;

    // Act
    let _answer = fixture.answer(ACCOUNTS_RS).await;

    // Assert
    let recorded = fixture.audit.0.lock().expect("a test lock");
    let rendered = format!("{:?}", recorded[0]);
    assert!(
        !rendered.contains(&fixture.access_token),
        "the trail holds a live credential"
    );
    assert!(
        !rendered.contains(OWNER),
        "the trail names the client a token was issued to: {rendered}"
    );
    assert!(
        rendered.contains(ACCOUNTS_RS),
        "the trail does not name the caller: {rendered}"
    );
}
