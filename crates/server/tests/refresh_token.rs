//! The `refresh_token` grant (RFC 6749 §6, OIDC Core §12, FAPI 2.0 SP
//! §5.3.2.1).
//!
//! Every case here is an acceptance criterion on `ast-a05.5`, and the file is
//! organised the way the risk is. A refresh token is presented by a machine
//! with no user watching, weeks after anybody consented to anything, so the
//! tests that matter most are the ones about what a *stolen* token is worth:
//! without the client's credentials, without its DPoP key, after the grant was
//! revoked, or past either of the two deadlines.
//!
//! The two rotation modes are both exercised, deliberately. Not rotating is
//! the FAPI 2.0 requirement and the default; the migration mode is Note 1's
//! exception and exists to be switched off again. A file that tested only one
//! of them would leave the other free to drift into whatever the code happens
//! to do.
//!
//! # Isolation
//!
//! As in `authorization_code.rs`: `asterius-server` has no `sqlx` dependency
//! (ADR-0001), so there is no per-test schema. Every test mints a unique
//! tenant, touches nothing outside it, and deletes it at the end, which
//! cascades its clients, grants and refresh tokens away.

use asterius_domain::audit::{AuditEvent, AuditSink};
use asterius_domain::entities::session::{AuthenticationMethod, Lifetimes, Session, SessionId};
use asterius_domain::entities::tenant::{RefreshPolicy, Rotation};
use asterius_domain::entities::user::{User, UserStatus};
use asterius_domain::ports::{SessionRepository, TenantRepository};
use asterius_domain::{
    Capabilities, Client, ClientId, ClientRegistration, ClientStatus, CodeBinding, Grant, GrantId,
    Issuer, KeyStore, Kid, RevocationReason, SubjectId, Tenant, TenantId, TenantStatus, UserId,
};
use asterius_jose::kek::Kek;
use asterius_jose::{LocalKek, jws, keys_from_jwk_set};
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::mtls::ClientCertificate;
use asterius_oidc::refresh::MintedRefreshToken;
use asterius_server::http::authorization_code::AuthorizationCode;
use asterius_server::http::issuance::SenderConstraint;
use asterius_server::http::refresh::RefreshToken;
use asterius_server::http::token::{GrantHandler, TokenContext, token};
use asterius_server::signing::CachedSigner;
use asterius_store_pg::{
    NewRefreshToken, PgAuditSink, PgCodeRepository, PgGrantRepository, PgRefreshTokenRepository,
    PgResourceServers, PgSessionRepository, PgTenantRepository, PgUserRepository, RefreshBinding,
    Store, TenantKeyStore,
};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use time::{Duration, OffsetDateTime};

/// The audit trail, in memory.
///
/// `asterius-server` has no `sqlx` dependency (ADR-0001), so a test in this
/// crate cannot read `audit_events` back. The sink is a port, so the honest
/// substitute is a port implementation rather than a query.
#[derive(Debug, Default)]
struct FakeAudit(Mutex<Vec<AuditEvent>>);

#[async_trait::async_trait]
impl AuditSink for FakeAudit {
    async fn record(&self, event: AuditEvent) -> Result<(), asterius_domain::DomainError> {
        self.0.lock().expect("lock").push(event);
        Ok(())
    }
}

impl FakeAudit {
    fn events(&self) -> Vec<AuditEvent> {
        self.0.lock().expect("lock").clone()
    }
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

const REDIRECT: &str = "https://rp.example/cb";
const CLIENT: &str = "billing";
const OTHER_CLIENT: &str = "reporting";
const RESOURCE: &str = "https://api.example/";

/// Everything one test needs, in a tenant nothing else touches.
struct Fixture {
    store: Store,
    keys: TenantKeyStore,
    audit: Arc<FakeAudit>,
    tenant: Tenant,
    signer: Arc<CachedSigner>,
    kek: Arc<dyn Kek>,
    now: OffsetDateTime,
}

impl Fixture {
    /// `None` without `DATABASE_URL`, so the default `cargo test` stays fast.
    async fn new(policy: RefreshPolicy) -> Option<Self> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let store = Store::connect(&url, 4)
            .await
            .expect("DATABASE_URL is set but unreachable; is `docker compose up -d db` running?");
        store.migrate().await.expect("migrate");

        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[5_u8; 32]).expect("a 32-byte KEK"));
        // The trail is read back in this file, and `asterius-server` has no
        // `sqlx` to read `audit_events` with (ADR-0001). The sink the *key
        // store* needs is the real one; the sink the handler writes to is
        // this, which is the object under test as far as these assertions go.
        let audit = Arc::new(FakeAudit::default());
        let now = OffsetDateTime::now_utc();

        let id = format!(
            "rt-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tenant = Tenant {
            id: TenantId::parse(&id).expect("a generated tenant id"),
            issuer: Issuer::parse(&format!("https://as.example/t/{id}")).expect("issuer"),
            custom_host: None,
            display_name: "Refresh".to_owned(),
            default_resource: RESOURCE.to_owned(),
            status: TenantStatus::Active,
            refresh: policy,
            created_at: now,
            updated_at: now,
        };
        PgTenantRepository::new(store.pool().clone(), Arc::clone(&kek))
            .upsert(&tenant)
            .await
            .expect("create tenant");

        let keys = TenantKeyStore::new(
            store.pool().clone(),
            Arc::clone(&kek),
            Arc::new(PgAuditSink::new(store.pool().clone())),
        );
        keys.apply_schedule(&tenant.id, now)
            .await
            .expect("prepare signing keys");

        let signer = Arc::new(CachedSigner::new(
            keys.clone(),
            Arc::new(asterius_domain::ports::SystemClock),
        ));

        Some(Self {
            store,
            keys,
            audit,
            tenant,
            signer,
            kek,
            now,
        })
    }

    fn grants(&self) -> PgGrantRepository {
        PgGrantRepository::new(self.store.pool().clone(), self.tenant.id.clone())
    }

    fn refresh_tokens(&self) -> PgRefreshTokenRepository {
        PgRefreshTokenRepository::new(self.store.pool().clone(), self.tenant.id.clone())
    }

    fn sessions(&self) -> PgSessionRepository {
        PgSessionRepository::new(self.store.pool().clone(), self.tenant.id.clone())
    }

    /// This tenant's registered resource servers (RFC 8707).
    fn resource_servers(&self) -> PgResourceServers {
        PgResourceServers::new(self.store.pool().clone(), self.tenant.id.clone())
    }

    /// The policy this tenant was created with, as the handler reads it.
    fn policy(&self) -> RefreshPolicy {
        self.tenant.refresh
    }

    /// A client registered for this grant, stored so the endpoint can load it.
    async fn client(&self, id: &str) -> Client {
        let client = Client {
            tenant: self.tenant.id.clone(),
            id: ClientId::new(id),
            registration: ClientRegistration::from_json(
                &serde_json::to_vec(&json!({
                    "client_name": "Billing",
                    "redirect_uris": [REDIRECT],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "scope": "openid profile payments offline_access",
                    "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
                }))
                .expect("serialise"),
                Capabilities::default(),
            )
            .expect("a valid registration"),
            status: ClientStatus::Active,
            created_at: self.now,
            updated_at: self.now,
        };
        self.store
            .scope(self.tenant.id.clone())
            .clients(Capabilities::default())
            .upsert(&client)
            .await
            .expect("store the client");
        client
    }

    /// The same client, registered for certificate-bound tokens
    /// (RFC 8705 §3.4) instead of DPoP. Stored under mTLS capabilities,
    /// because the member is refused without the flag on the way in and on the
    /// way back out.
    async fn certificate_bound_client(&self, id: &str) -> Client {
        let client = Client {
            tenant: self.tenant.id.clone(),
            id: ClientId::new(id),
            registration: ClientRegistration::from_json(
                &serde_json::to_vec(&json!({
                    "client_name": "Billing",
                    "redirect_uris": [REDIRECT],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "scope": "openid profile payments offline_access",
                    "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
                    "dpop_bound_access_tokens": false,
                    "tls_client_certificate_bound_access_tokens": true,
                }))
                .expect("serialise"),
                mtls_on(),
            )
            .expect("a valid registration"),
            status: ClientStatus::Active,
            created_at: self.now,
            updated_at: self.now,
        };
        self.store
            .scope(self.tenant.id.clone())
            .clients(mtls_on())
            .upsert(&client)
            .await
            .expect("store the client");
        client
    }

    /// A refresh token bound to a certificate rather than to a DPoP key
    /// (RFC 8705 §3).
    async fn issue_certificate_bound(
        &self,
        grant: &Grant,
        certificate: &ClientCertificate,
        scopes: &[&str],
    ) -> String {
        let minted = MintedRefreshToken::generate();
        self.refresh_tokens()
            .issue(
                minted.digest(),
                &NewRefreshToken {
                    grant: grant.id.clone(),
                    client: grant.client.clone(),
                    scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                    binding: RefreshBinding::Certificate(certificate.thumbprint()),
                    absolute_expires_at: self.now + self.policy().absolute_lifetime,
                    idle_expires_at: self.policy().idle_lifetime.map(|idle| self.now + idle),
                },
                self.now,
            )
            .await
            .expect("issue the refresh token");
        minted.expose().to_owned()
    }

    /// A refresh presented over a connection carrying `certificate`.
    async fn refresh_presenting(
        &self,
        client: &Client,
        pairs: &[(&str, &str)],
        certificate: Option<&ClientCertificate>,
    ) -> (StatusCode, Value) {
        let tokens = self.refresh_tokens();
        let grants = self.grants();
        let sessions = self.sessions();
        let resource_servers = self.resource_servers();
        let users = PgUserRepository::new(
            self.store.pool().clone(),
            self.tenant.id.clone(),
            Arc::clone(&self.kek),
        );
        let handler = RefreshToken {
            tokens: &tokens,
            grants: &grants,
            sessions: &sessions,
            users: &users,
            resource_servers: &resource_servers,
            signer: self.signer.as_ref(),
            audit: self.audit.as_ref(),
            grant_id_claim: true,
            grant_management: false,
            lifetimes: asterius_domain::TokenLifetimes::default(),
            constraint: SenderConstraint {
                proof_key: None,
                certificate,
            },
            now: self.now,
        };
        self.post(client, &handler, pairs).await
    }

    /// A user, the session they authenticated in, and a grant naming both.
    async fn grant(&self, scopes: &[&str]) -> (Grant, Session) {
        self.grant_claimed(scopes, true).await
    }

    /// The same, with `claimed_at` left as the consent screen leaves it.
    ///
    /// An unclaimed grant is what the authorization endpoint writes; the code
    /// redemption is what stamps it. A test that seeds the stamp is a test
    /// that cannot see the redemption failing to write it.
    async fn grant_claimed(&self, scopes: &[&str], claimed: bool) -> (Grant, Session) {
        let user = UserId::generate();
        let user_id = *user.as_uuid();
        PgUserRepository::new(
            self.store.pool().clone(),
            self.tenant.id.clone(),
            Arc::clone(&self.kek),
        )
        .upsert(&User {
            tenant: self.tenant.id.clone(),
            id: user,
            username: user_id.to_string(),
            email: None,
            email_verified: false,
            status: UserStatus::Active,
            claims: asterius_domain::entities::user::ClaimSet::default(),
            created_at: self.now,
            updated_at: self.now,
        })
        .await
        .expect("store the user");

        let session_id = SessionId::generate();
        let session = Session::begin(
            self.tenant.id.clone(),
            &session_id,
            user_id,
            vec![AuthenticationMethod::Passkey],
            self.now,
            Lifetimes::default(),
        );
        self.sessions()
            .begin(&session)
            .await
            .expect("store the session");

        let grant = Grant {
            tenant: self.tenant.id.clone(),
            id: GrantId::new(uuid::Uuid::new_v4().to_string()),
            client: ClientId::new(CLIENT),
            user: Some(user),
            subject: Some(SubjectId::new("alice-pairwise")),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            claims: json!({}),
            claims_locales: Vec::new(),
            authorization_details: Vec::new(),
            resources: BTreeSet::new(),
            actor_chain: Vec::new(),
            parent: None,
            session: Some(asterius_domain::SessionId::new(session.id_digest.clone())),
            // What the authorization copied off the session (`ast-dlk`), which
            // is what a refresh reads once the session row is gone.
            authentication: Some(asterius_domain::GrantAuthentication {
                authenticated_at: session.authenticated_at,
                acr: session.acr.clone(),
                amr: session.amr.clone(),
            }),
            created_at: self.now,
            updated_at: self.now,
            expires_at: None,
            revoked_at: None,
            revocation_reason: None,
            // Claimed at the code redemption that produced this refresh token.
            // A `Pending` grant is one nobody has taken a credential from, and
            // a refresh token is a credential.
            claimed_at: claimed.then_some(self.now),
        };
        self.grants().create(&grant).await.expect("store the grant");
        (grant, session)
    }

    /// Issues a refresh token the way the code redemption does.
    async fn issue(&self, grant: &Grant, jkt: &Kid, scopes: &[&str]) -> String {
        self.issue_expiring(
            grant,
            jkt,
            scopes,
            self.now + self.policy().absolute_lifetime,
            self.policy().idle_lifetime.map(|idle| self.now + idle),
        )
        .await
    }

    /// The same, with the two deadlines chosen by the test.
    async fn issue_expiring(
        &self,
        grant: &Grant,
        jkt: &Kid,
        scopes: &[&str],
        absolute_expires_at: OffsetDateTime,
        idle_expires_at: Option<OffsetDateTime>,
    ) -> String {
        let minted = MintedRefreshToken::generate();
        self.refresh_tokens()
            .issue(
                minted.digest(),
                &NewRefreshToken {
                    grant: grant.id.clone(),
                    client: grant.client.clone(),
                    scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                    binding: RefreshBinding::Dpop(jkt.as_str().to_owned()),
                    absolute_expires_at,
                    idle_expires_at,
                },
                self.now,
            )
            .await
            .expect("issue the refresh token");
        minted.expose().to_owned()
    }

    /// Mints a refresh token the way a client actually gets one: by redeeming
    /// an authorization code at the real token endpoint.
    ///
    /// Returns the whole token response, so a caller can assert on the value
    /// it hands to the client rather than on a value a test wrote itself.
    async fn refresh_token_from_a_code_redemption(
        &self,
        client: &Client,
        grant: &Grant,
        jkt: &Kid,
    ) -> (StatusCode, Value) {
        let codes = PgCodeRepository::new(self.store.pool().clone(), self.tenant.id.clone());
        let minted = asterius_oidc::code::MintedCode::generate();
        codes
            .issue(
                minted.digest(),
                &CodeBinding {
                    client_id: client.id.as_str().to_owned(),
                    grant_id: grant.id.clone(),
                    // RFC 7636 Appendix B's published pair, as in
                    // `authorization_code.rs`.
                    code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
                    redirect_uri: REDIRECT.to_owned(),
                    nonce: Some("n-0S6_WzA2Mj".to_owned()),
                    // RFC 9449 §10: the authorization request pinned the key,
                    // which is what the conformance suite's client does.
                    dpop_jkt: Some(jkt.as_str().to_owned()),
                    grant_management_action: None,
                    expires_at: self.now + Duration::seconds(60),
                },
                self.now,
            )
            .await
            .expect("issue the code");

        let grants = self.grants();
        let refresh_tokens = self.refresh_tokens();
        let sessions = self.sessions();
        let resource_servers = self.resource_servers();
        let users = PgUserRepository::new(
            self.store.pool().clone(),
            self.tenant.id.clone(),
            Arc::clone(&self.kek),
        );
        let handler = AuthorizationCode {
            codes: &codes,
            grants: &grants,
            refresh_tokens: &refresh_tokens,
            sessions: &sessions,
            users: &users,
            resource_servers: &resource_servers,
            signer: self.signer.as_ref(),
            // The deployment fallback: these tests write the tenant no
            // settings of its own (`ast-5c6`).
            grant_id_claim: true,
            grant_management: false,
            lifetimes: asterius_domain::TokenLifetimes::default(),
            constraint: SenderConstraint {
                proof_key: Some(jkt),
                certificate: None,
            },
            now: self.now,
        };
        self.post(
            client,
            &handler,
            &[
                ("grant_type", "authorization_code"),
                ("code", minted.expose()),
                ("redirect_uri", REDIRECT),
                (
                    "code_verifier",
                    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                ),
            ],
        )
        .await
    }

    /// Runs a token request through the real endpoint and the real handler.
    async fn refresh(
        &self,
        client: &Client,
        pairs: &[(&str, &str)],
        proof_key: Option<&Kid>,
    ) -> (StatusCode, Value) {
        let tokens = self.refresh_tokens();
        let grants = self.grants();
        let sessions = self.sessions();
        let resource_servers = self.resource_servers();
        let users = PgUserRepository::new(
            self.store.pool().clone(),
            self.tenant.id.clone(),
            Arc::clone(&self.kek),
        );
        let handler = RefreshToken {
            tokens: &tokens,
            grants: &grants,
            sessions: &sessions,
            users: &users,
            resource_servers: &resource_servers,
            signer: self.signer.as_ref(),
            audit: self.audit.as_ref(),
            grant_id_claim: true,
            grant_management: false,
            lifetimes: asterius_domain::TokenLifetimes::default(),
            constraint: SenderConstraint {
                proof_key,
                certificate: None,
            },
            now: self.now,
        };
        self.post(client, &handler, pairs).await
    }

    /// Posts one form to the real token endpoint, with one grant handler
    /// registered.
    ///
    /// Shared by the two grants this file drives: `authorization_code`, which
    /// is where a refresh token comes from, and `refresh_token`, which is
    /// where it goes.
    async fn post(
        &self,
        client: &Client,
        handler: &dyn GrantHandler,
        pairs: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let handlers: [&dyn GrantHandler; 1] = [handler];

        let clients = self
            .store
            .scope(self.tenant.id.clone())
            .clients(Capabilities::default());

        let mut encoder = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            encoder.append_pair(k, v);
        }
        let body = Bytes::from(encoder.finish());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().expect("header"),
        );

        let authenticated = client.clone();
        let response = token(
            TokenContext {
                certificate: None,
                tenant: &self.tenant,
                clients: &clients,
                capabilities: Capabilities::default(),
                grants: &handlers,
            },
            &headers,
            &body,
            async |_: &Attempt<'_>, _: &AssertionRules| {
                Ok::<Client, ClientAuthError>(authenticated)
            },
        )
        .await;

        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    /// The shorthand every happy-path test uses.
    async fn present(
        &self,
        client: &Client,
        refresh_token: &str,
        jkt: &Kid,
    ) -> (StatusCode, Value) {
        self.refresh(
            client,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
            Some(jkt),
        )
        .await
    }

    /// Verifies a token the way a relying party does, and returns its claims.
    async fn verify(&self, token: &str) -> Value {
        let parsed = jws::parse(token).expect("a compact JWS");
        let kid = parsed.kid().expect("every token names its key");
        let published = self
            .keys
            .published_keys(&self.tenant.id)
            .await
            .expect("published keys");
        let jwk = published
            .iter()
            .find(|record| record.kid == kid)
            .map(|record| record.public_jwk.clone())
            .expect("the kid names a key in the published set");
        let set = keys_from_jwk_set(&json!({ "keys": [jwk] })).expect("a JWK set");
        let key = set
            .verifying_keys()
            .into_iter()
            .next()
            .expect("one verifying key");
        let payload = parsed.verify(&key).expect("the signature must check out");
        serde_json::from_slice(&payload).expect("claims")
    }

    async fn tear_down(self) {
        PgTenantRepository::new(self.store.pool().clone(), self.kek)
            .delete(&self.tenant.id)
            .await
            .expect("delete tenant");
    }
}

/// A test whose tenant uses the FAPI 2.0 default policy.
macro_rules! db_test {
    ($(#[$meta:meta])* async fn $name:ident($f:ident) $body:block) => {
        db_test! { $(#[$meta])* async fn $name($f, RefreshPolicy::default()) $body }
    };
    ($(#[$meta:meta])* async fn $name:ident($f:ident, $policy:expr) $body:block) => {
        $(#[$meta])*
        #[tokio::test]
        async fn $name() {
            let Some($f) = Fixture::new($policy).await else {
                eprintln!("skipping {}: DATABASE_URL is not set", stringify!($name));
                return;
            };
            $body
        }
    };
}

/// A DPoP thumbprint that is the right shape without being a real key's.
fn thumbprint(seed: u8) -> Kid {
    use base64::Engine as _;
    Kid::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([seed; 32]))
}

/// The migration rotation mode, with a window long enough that a test's clock
/// cannot walk out of it.
fn migrating() -> RefreshPolicy {
    RefreshPolicy {
        rotation: Rotation::Migration {
            grace: Duration::minutes(10),
        },
        ..RefreshPolicy::default()
    }
}

// ---- The gap this story closes -------------------------------------------

/// Discovery has advertised `refresh_token` in `grant_types_supported` since
/// the metadata document existed, while the grant itself did not: the token
/// endpoint answered a `grant_type=refresh_token` request with 501, because no
/// handler claimed it. A discovery document that promises a capability the
/// endpoint does not have is worse than one that omits it — a client reads it
/// once, at registration time, and builds on what it said.
///
/// This asserts the advertisement, and the file it is in asserts the other
/// half: every test below drives the real token endpoint, which now finds a
/// handler for the grant rather than falling through to 501.
#[test]
fn discovery_advertises_the_grant_this_file_implements() {
    // Arrange / Act
    let advertised = asterius_oidc::metadata::grant_types(&Capabilities::default());

    // Assert
    assert!(
        advertised.contains(&"refresh_token"),
        "discovery must advertise the grant: {advertised:?}"
    );
}

// ---- The seam: where a refresh token actually comes from -----------------

db_test! {
    /// The whole life of a refresh token, through the two real handlers: an
    /// authorization code mints it, and the refresh grant redeems it, with one
    /// DPoP key throughout.
    ///
    /// This is the case the OIDF suite ran first and this file never did
    /// (`ast-1h1`). Every other test here seeds its refresh token with
    /// `Fixture::issue`, so nothing asserted that the row the *code* redemption
    /// writes is a row the *refresh* redemption accepts.
    async fn a_refresh_token_minted_by_a_code_redemption_can_be_redeemed(fixture) {
        // Arrange
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        // Unclaimed, as the authorization endpoint leaves it.
        let (grant, _) = fixture.grant_claimed(&["openid", "offline_access"], false).await;

        // Act
        let (issued, tokens) = fixture
            .refresh_token_from_a_code_redemption(&client, &grant, &jkt)
            .await;
        let refresh_token = tokens["refresh_token"]
            .as_str()
            .expect("an offline_access grant earns a refresh token")
            .to_owned();
        let (status, body) = fixture.present(&client, &refresh_token, &jkt).await;

        // Assert
        assert_eq!(issued, StatusCode::OK, "{tokens}");
        assert_eq!(
            status,
            StatusCode::OK,
            "the first refresh of a freshly minted token must be accepted: {body}"
        );
        assert_eq!(body["refresh_token"], refresh_token.as_str());
        fixture.tear_down().await;
    }
}

// ---- No rotation: the default, and the FAPI 2.0 requirement ---------------

db_test! {
    /// FAPI 2.0 SP §5.3.2.1 item 9. The value that comes back is the value
    /// that went in — not a new one, and not an absent one.
    async fn the_default_policy_returns_the_same_refresh_token(fixture) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;

        let (status, body) = fixture.present(&client, &refresh_token, &jkt).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["refresh_token"], refresh_token,
            "FAPI 2.0 SP §5.3.2.1 item 9 forbids rotation; the same token must come back"
        );
        assert_eq!(body["token_type"], "DPoP");
        fixture.tear_down().await;
    }
}

db_test! {
    /// The consequence that makes not rotating worth having: a client that
    /// loses a response can simply try again, and its authorization survives.
    async fn a_token_that_does_not_rotate_can_be_presented_twice(fixture) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;

        let (first, _) = fixture.present(&client, &refresh_token, &jkt).await;
        let (second, body) = fixture.present(&client, &refresh_token, &jkt).await;

        assert_eq!(first, StatusCode::OK);
        assert_eq!(second, StatusCode::OK, "{body}");
        assert_eq!(body["refresh_token"], refresh_token);
        fixture.tear_down().await;
    }
}

db_test! {
    /// RFC 9449 §6.1: the new access token is bound to the key that proved
    /// this request, and it is a `DPoP` token rather than a bearer one.
    async fn the_new_access_token_is_bound_to_the_presented_key(fixture) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;

        let (status, body) = fixture.present(&client, &refresh_token, &jkt).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        let access = fixture
            .verify(body["access_token"].as_str().expect("access_token"))
            .await;
        assert_eq!(access["cnf"]["jkt"], jkt.as_str());
        assert_eq!(access["aud"], RESOURCE);
        fixture.tear_down().await;
    }
}

// ---- The migration mode: FAPI 2.0 SP Note 1 -------------------------------

db_test! {
    /// The other half of the rotation criterion. A migration tenant issues a
    /// *new* token, and the one presented is not it.
    async fn the_migration_policy_issues_a_new_refresh_token(fixture, migrating()) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;

        let (status, body) = fixture.present(&client, &refresh_token, &jkt).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        let returned = body["refresh_token"].as_str().expect("refresh_token");
        assert_ne!(returned, refresh_token, "the migration mode must rotate");
        fixture.tear_down().await;
    }
}

db_test! {
    /// FAPI 2.0 SP Note 1's grace window: the superseded token still works,
    /// so a client that crashed before storing the replacement can retry.
    async fn a_superseded_token_still_works_inside_the_grace_window(fixture, migrating()) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;
        let (_, first) = fixture.present(&client, &refresh_token, &jkt).await;

        let (status, body) = fixture.present(&client, &refresh_token, &jkt).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "the old token must be honoured inside the grace window: {body}"
        );
        assert_ne!(body["refresh_token"], first["refresh_token"]);
        fixture.tear_down().await;
    }
}

db_test! {
    /// And the replacement itself works, which is what the client was told to
    /// use. A rotation that hands out a token the server will not accept is
    /// the failure mode rotation is famous for.
    async fn the_replacement_token_is_redeemable(fixture, migrating()) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;
        let (_, first) = fixture.present(&client, &refresh_token, &jkt).await;
        let replacement = first["refresh_token"].as_str().expect("refresh_token").to_owned();

        let (status, body) = fixture.present(&client, &replacement, &jkt).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        fixture.tear_down().await;
    }
}

db_test! {
    /// The window is a window. A grace of one second, and a token superseded
    /// long enough ago, is refused — which is what stops the migration mode
    /// from being "two live tokens for ever".
    async fn a_superseded_token_stops_working_past_the_grace_window(fixture, RefreshPolicy {
        rotation: Rotation::Migration { grace: Duration::seconds(1) },
        ..RefreshPolicy::default()
    }) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;
        // Supersede it directly, an hour in the past: the handler's `now` is
        // the fixture's, so this is "the grace window closed long ago" without
        // a test that sleeps.
        let stale = fixture.now - Duration::hours(1);
        let replacement = MintedRefreshToken::generate();
        fixture
            .refresh_tokens()
            .supersede(
                &asterius_oidc::refresh::digest_of(&refresh_token).expect("a minted token"),
                replacement.digest(),
                &NewRefreshToken {
                    grant: grant.id.clone(),
                    client: grant.client.clone(),
                    scopes: ["openid".to_owned(), "offline_access".to_owned()].into(),
                    binding: RefreshBinding::Dpop(jkt.as_str().to_owned()),
                    absolute_expires_at: fixture.now + Duration::days(1),
                    idle_expires_at: None,
                },
                stale,
            )
            .await
            .expect("supersede");

        let (status, body) = fixture.present(&client, &refresh_token, &jkt).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant", "{body}");
        fixture.tear_down().await;
    }
}

// ---- Sender constraining --------------------------------------------------

db_test! {
    /// The tenant option, doing the thing it exists for: the same token, the
    /// same client, a different key, and no tokens. Opt-in, because the
    /// default is RFC 9449 §5's rule for a confidential client — see the test
    /// below, which is the one the OIDF suite runs.
    async fn a_bound_token_presented_with_another_key_is_refused(fixture, RefreshPolicy {
        bind_to_dpop_key: true,
        ..RefreshPolicy::default()
    }) {
        let client = fixture.client(CLIENT).await;
        let issued_to = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &issued_to, &["openid", "offline_access"]).await;

        let (status, body) = fixture.present(&client, &refresh_token, &thumbprint(2)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant", "{body}");
        fixture.tear_down().await;
    }
}

db_test! {
    /// RFC 9449 §5, under the *default* policy: a refresh token issued to a
    /// confidential client — which every client here is — is not bound to the
    /// proof key, so a new key is accepted and the new access token is bound
    /// to *that* key rather than to the one the refresh token remembers.
    ///
    /// The regression test for `ast-1h1`. The OIDF module
    /// `fapi2-security-profile-final-refresh-token` mints a fresh DPoP key for
    /// the refresh request on purpose — "we generate a new key here, to check
    /// the server handles that correctly" — and this server refused it with
    /// `invalid_grant`, because the default pinned the key it was issued to.
    async fn the_default_policy_lets_a_client_refresh_with_a_new_dpop_key(fixture) {
        let client = fixture.client(CLIENT).await;
        let issued_to = thumbprint(1);
        let presented = thumbprint(2);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &issued_to, &["openid", "offline_access"]).await;

        let (status, body) = fixture.present(&client, &refresh_token, &presented).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        let access = fixture
            .verify(body["access_token"].as_str().expect("access_token"))
            .await;
        assert_eq!(access["cnf"]["jkt"], presented.as_str());
        fixture.tear_down().await;
    }
}

db_test! {
    /// FAPI 2.0 SP §5.3.2.1 item 4 admits no unbound access token, so a
    /// request with no proof at all has nothing this handler could issue.
    async fn a_refresh_without_a_dpop_proof_is_refused(fixture) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;

        let (status, body) = fixture
            .refresh(
                &client,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh_token),
                ],
                None,
            )
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant", "{body}");
        fixture.tear_down().await;
    }
}

db_test! {
    /// RFC 6749 §6: the token was issued to one client. Another registered
    /// client holding it — from a log, from a shared host — gets nothing.
    async fn another_clients_refresh_token_is_refused(fixture) {
        let owner = fixture.client(CLIENT).await;
        let other = fixture.client(OTHER_CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;

        let (status, body) = fixture.present(&other, &refresh_token, &jkt).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant", "{body}");
        // And the owner still holds a working token: refusing somebody else's
        // presentation must not spend it.
        let (owner_status, _) = fixture.present(&owner, &refresh_token, &jkt).await;
        assert_eq!(owner_status, StatusCode::OK);
        fixture.tear_down().await;
    }
}

// ---- Scope ----------------------------------------------------------------

db_test! {
    /// RFC 6749 §6: "MUST NOT include any scope not originally granted".
    async fn a_widening_request_is_invalid_scope(fixture) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;

        let (status, body) = fixture
            .refresh(
                &client,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh_token),
                    ("scope", "openid payments"),
                ],
                Some(&jkt),
            )
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"], "invalid_scope",
            "§6 gives scope its own code: {body}"
        );
        fixture.tear_down().await;
    }
}

db_test! {
    /// Narrowing is permitted, and it reaches the access token's `scope`
    /// claim — which is the only place a resource server will look.
    async fn a_narrowed_request_narrows_the_access_token(fixture) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "profile", "offline_access"]).await;
        let refresh_token = fixture
            .issue(&grant, &jkt, &["openid", "profile", "offline_access"])
            .await;

        let (status, body) = fixture
            .refresh(
                &client,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh_token),
                    ("scope", "openid"),
                ],
                Some(&jkt),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["scope"], "openid");
        let access = fixture
            .verify(body["access_token"].as_str().expect("access_token"))
            .await;
        assert_eq!(access["scope"], "openid", "the narrowing must reach the token");
        fixture.tear_down().await;
    }
}

db_test! {
    /// A refresh that drops `openid` gets no ID token: the request is no
    /// longer an OpenID Connect one, and an authentication assertion nobody
    /// asked for is one more thing to leak.
    async fn narrowing_away_openid_drops_the_id_token(fixture) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "profile", "offline_access"]).await;
        let refresh_token = fixture
            .issue(&grant, &jkt, &["openid", "profile", "offline_access"])
            .await;

        let (status, body) = fixture
            .refresh(
                &client,
                &[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", &refresh_token),
                    ("scope", "profile"),
                ],
                Some(&jkt),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("id_token").is_none(), "{body}");
        fixture.tear_down().await;
    }
}

// ---- The ID token ---------------------------------------------------------

db_test! {
    /// OIDC Core §12.2: the ID token MAY be returned, its `sub` MUST be the
    /// original one, and `auth_time` says when the person actually
    /// authenticated rather than when this request arrived.
    async fn an_openid_refresh_returns_an_id_token_with_the_same_sub_and_auth_time(fixture) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, session) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;

        let (status, body) = fixture.present(&client, &refresh_token, &jkt).await;

        assert_eq!(status, StatusCode::OK, "{body}");
        let id_token = fixture
            .verify(body["id_token"].as_str().expect("id_token"))
            .await;
        assert_eq!(id_token["sub"], "alice-pairwise");
        assert_eq!(id_token["aud"], CLIENT);
        assert_eq!(
            id_token["auth_time"],
            session.authenticated_at.unix_timestamp(),
            "auth_time must be the authentication's, not this request's"
        );
        // §12.2: no new `nonce`. There is no authorization request to echo one
        // from, and echoing the original would be a replay defence checked
        // against a round trip nobody is making.
        assert!(id_token.get("nonce").is_none(), "{id_token}");
        fixture.tear_down().await;
    }
}

// ---- Revocation and the two deadlines -------------------------------------

db_test! {
    /// The whole point of a grant-bound refresh token: revoking the grant
    /// revokes it, and the endpoint says `invalid_grant` rather than issuing.
    async fn a_revoked_grant_refuses_its_refresh_tokens(fixture) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;
        let revocation = fixture
            .grants()
            .revoke(&grant.id, RevocationReason::UserRevoked, &[], fixture.now)
            .await
            .expect("revoke the grant");

        let (status, body) = fixture.present(&client, &refresh_token, &jkt).await;

        assert_eq!(
            revocation.refresh_tokens_revoked, 1,
            "the cascade must reach the refresh token"
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant", "{body}");
        fixture.tear_down().await;
    }
}

db_test! {
    /// The absolute deadline. It does not move, so a token past it is dead
    /// however recently it was used.
    async fn a_token_past_its_absolute_deadline_is_refused(fixture) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture
            .issue_expiring(
                &grant,
                &jkt,
                &["openid", "offline_access"],
                fixture.now - Duration::seconds(1),
                None,
            )
            .await;

        let (status, body) = fixture.present(&client, &refresh_token, &jkt).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant", "{body}");
        fixture.tear_down().await;
    }
}

db_test! {
    /// The idle deadline, which is a different rule: the token is well inside
    /// its absolute lifetime and is refused for having sat unused.
    async fn a_token_past_its_idle_deadline_is_refused(fixture) {
        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture
            .issue_expiring(
                &grant,
                &jkt,
                &["openid", "offline_access"],
                fixture.now + Duration::days(30),
                Some(fixture.now - Duration::seconds(1)),
            )
            .await;

        let (status, body) = fixture.present(&client, &refresh_token, &jkt).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant", "{body}");
        fixture.tear_down().await;
    }
}

// ---- The trail ------------------------------------------------------------

db_test! {
    /// Every refresh is recorded. A grant acted on months after anybody
    /// consented to it is exactly the thing an operator has to be able to see.
    async fn a_refresh_is_written_to_the_audit_trail(fixture) {
        use asterius_domain::audit::{EventType, Outcome};

        let client = fixture.client(CLIENT).await;
        let jkt = thumbprint(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture.issue(&grant, &jkt, &["openid", "offline_access"]).await;

        let (status, _) = fixture.present(&client, &refresh_token, &jkt).await;

        assert_eq!(status, StatusCode::OK);
        let events = fixture.audit.events();
        assert_eq!(events.len(), 1, "a refresh left no trail");
        assert_eq!(events[0].event_type, EventType::TOKEN_REFRESHED);
        assert_eq!(events[0].outcome, Outcome::Success);
        assert_eq!(
            events[0].grant.as_ref().map(ToString::to_string),
            Some(grant.id.to_string()),
            "the trail must name the grant that was acted on"
        );
        fixture.tear_down().await;
    }
}

db_test! {
    /// And a refusal is recorded too: a run of them against one tenant is a
    /// stolen token being tried, which is only visible if failures are written.
    async fn a_refused_refresh_is_written_to_the_audit_trail(fixture) {
        use asterius_domain::audit::{EventType, Outcome};

        let client = fixture.client(CLIENT).await;
        // Well formed and never issued, which is what a guess looks like.
        let guessed = MintedRefreshToken::generate();

        let (status, _) = fixture
            .present(&client, guessed.expose(), &thumbprint(1))
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        let events = fixture.audit.events();
        assert_eq!(events.len(), 1, "a refusal left no trail");
        assert_eq!(events[0].event_type, EventType::TOKEN_REFRESHED);
        assert_eq!(events[0].outcome, Outcome::Failure);
        fixture.tear_down().await;
    }
}

// ---- Shape ----------------------------------------------------------------

db_test! {
    /// A value that could not have been issued here is refused on its shape,
    /// before any query. `invalid_grant`, like every other credential failure.
    async fn a_malformed_refresh_token_is_refused(fixture) {
        let client = fixture.client(CLIENT).await;

        let (status, body) = fixture.present(&client, "not-a-refresh-token", &thumbprint(1)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant", "{body}");
        fixture.tear_down().await;
    }
}

db_test! {
    /// RFC 6749 §6 makes `refresh_token` REQUIRED, and §5.2 makes a missing
    /// required parameter `invalid_request` rather than `invalid_grant`: it is
    /// a statement about the form, not about a credential.
    async fn a_request_without_a_refresh_token_is_invalid_request(fixture) {
        let client = fixture.client(CLIENT).await;

        let (status, body) = fixture
            .refresh(&client, &[("grant_type", "refresh_token")], Some(&thumbprint(1)))
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_request", "{body}");
        fixture.tear_down().await;
    }
}

// ---- Certificate-bound refresh tokens (RFC 8705 §3) -----------------------

/// A deployment with RFC 8705 turned on.
fn mtls_on() -> Capabilities {
    Capabilities {
        mtls: true,
        ..Capabilities::default()
    }
}

/// A DER `Certificate` with the shape `ClientCertificate::from_der` reads and
/// nothing else in it: what binds a token is the SHA-256 of these bytes, and
/// `serial` is what makes two of these different certificates.
fn certificate(serial: u8) -> ClientCertificate {
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let length = u8::try_from(value.len()).expect("a short fixture");
        let mut encoded = vec![tag, length];
        encoded.extend_from_slice(value);
        encoded
    }
    const SEQUENCE: u8 = 0x30;

    let mut tbs = tlv(0x02, &[serial]);
    for _ in 0..5 {
        tbs.extend(tlv(SEQUENCE, &[]));
    }
    let mut body = tlv(SEQUENCE, &tbs);
    body.extend(tlv(SEQUENCE, &[]));
    body.extend(tlv(0x03, &[0x00]));
    ClientCertificate::from_der(tlv(SEQUENCE, &body)).expect("a DER certificate")
}

db_test! {
    /// The holder of the certificate the token was issued under refreshes, and
    /// the new access token is bound to that same certificate (RFC 8705 §3.1).
    async fn a_certificate_bound_refresh_token_is_redeemed_by_its_certificate(fixture) {
        let client = fixture.certificate_bound_client(CLIENT).await;
        let held = certificate(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture
            .issue_certificate_bound(&grant, &held, &["openid", "offline_access"])
            .await;

        let (status, body) = fixture
            .refresh_presenting(
                &client,
                &[("grant_type", "refresh_token"), ("refresh_token", &refresh_token)],
                Some(&held),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["token_type"], "Bearer");
        let access = fixture.verify(body["access_token"].as_str().expect("access_token")).await;
        assert_eq!(access["cnf"]["x5t#S256"], held.thumbprint_b64url());

        fixture.tear_down().await;
    }
}

db_test! {
    /// The same refusal a DPoP-bound token gets under another key, for the
    /// same reason: whoever is presenting this holds the token and not the
    /// thing it is bound to. One `invalid_grant`, which does not say which of
    /// the two it was (RFC 6749 §5.2).
    async fn a_certificate_bound_refresh_token_is_not_redeemable_under_another_certificate(fixture) {
        let client = fixture.certificate_bound_client(CLIENT).await;
        let held = certificate(1);
        let another = certificate(2);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture
            .issue_certificate_bound(&grant, &held, &["openid", "offline_access"])
            .await;

        let (status, body) = fixture
            .refresh_presenting(
                &client,
                &[("grant_type", "refresh_token"), ("refresh_token", &refresh_token)],
                Some(&another),
            )
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_grant");

        fixture.tear_down().await;
    }
}

db_test! {
    /// And with no certificate at all, which is the same answer: a
    /// certificate-bound credential is not redeemable by a caller who presents
    /// nothing.
    async fn a_certificate_bound_refresh_token_is_not_redeemable_without_a_certificate(fixture) {
        let client = fixture.certificate_bound_client(CLIENT).await;
        let held = certificate(1);
        let (grant, _) = fixture.grant(&["openid", "offline_access"]).await;
        let refresh_token = fixture
            .issue_certificate_bound(&grant, &held, &["openid", "offline_access"])
            .await;

        let (status, body) = fixture
            .refresh_presenting(
                &client,
                &[("grant_type", "refresh_token"), ("refresh_token", &refresh_token)],
                None,
            )
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");

        fixture.tear_down().await;
    }
}
