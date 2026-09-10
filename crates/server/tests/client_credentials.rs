//! The `client_credentials` grant (RFC 6749 §4.4, RFC 9068 §2.2, RFC 8707
//! §2.2, RFC 9449 §5, FAPI 2.0 SP §5.3.2.1 items 4 and 14).
//!
//! Every case here is an acceptance criterion on `ast-a05.8`. What makes this
//! grant different from the two beside it is that nobody is present and nobody
//! ever was: there is no authorization request, no consent screen and no
//! resource owner. A client asks for a token about *itself*, and the only
//! things standing between "a registration exists" and "a token exists" are
//! the four checks this file is organised around — the grant the client
//! registered for, the scopes it registered for, the audience this tenant
//! registers, and the DPoP key it proved.
//!
//! # Isolation
//!
//! As in `refresh_token.rs`: `asterius-server` has no `sqlx` dependency
//! (ADR-0001), so there is no per-test schema. Every test mints a unique
//! tenant, touches nothing outside it, and deletes it at the end, which
//! cascades its clients and grants away.

use asterius_domain::audit::{AuditEvent, AuditSink, EventType, Outcome};
use asterius_domain::entities::grant::GrantStatus;
use asterius_domain::ports::TenantRepository;
use asterius_domain::{
    Capabilities, Client, ClientId, ClientRegistration, ClientStatus, GrantId, Issuer, KeyStore,
    Kid, ResourceIdentifier, ResourceServer, Tenant, TenantId, TenantStatus,
};
use asterius_jose::kek::Kek;
use asterius_jose::{LocalKek, jws, keys_from_jwk_set};
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_server::http::client_credentials::ClientCredentials;
use asterius_server::http::issuance::SenderConstraint;
use asterius_server::http::token::{GrantHandler, TokenContext, token};
use asterius_server::signing::CachedSigner;
use asterius_store_pg::{
    PgAuditSink, PgGrantRepository, PgResourceServers, PgTenantRepository, Store, TenantKeyStore,
};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use time::OffsetDateTime;

/// The audit trail, in memory: `asterius-server` cannot read `audit_events`
/// back (ADR-0001), and the sink is a port, so the honest substitute is a port
/// implementation rather than a query.
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

const CLIENT: &str = "billing";
const RESOURCE: &str = "https://api.example/";
const OTHER_RESOURCE: &str = "https://reports.example/";
/// What the machine client registered. `openid` and `offline_access` are in
/// there deliberately: they are the two scopes a client-only token must not
/// carry, and a registration that cannot hold them cannot show that.
const REGISTERED_SCOPE: &str = "payments.read payments.write openid offline_access";

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
    /// `None` without `DATABASE_URL`, so the default suite stays fast.
    async fn new() -> Option<Self> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let store = Store::connect(&url, 4)
            .await
            .expect("DATABASE_URL is set but unreachable; is `docker compose up -d db` running?");
        store.migrate().await.expect("migrate");

        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[5_u8; 32]).expect("a 32-byte KEK"));
        let audit = Arc::new(FakeAudit::default());
        let now = OffsetDateTime::now_utc();

        let id = format!(
            "cc-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tenant = Tenant {
            id: TenantId::parse(&id).expect("a generated tenant id"),
            issuer: Issuer::parse(&format!("https://as.example/t/{id}")).expect("issuer"),
            custom_host: None,
            display_name: "Client credentials".to_owned(),
            default_resource: RESOURCE.to_owned(),
            status: TenantStatus::Active,
            refresh: asterius_domain::RefreshPolicy::default(),
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

    fn resource_servers(&self) -> PgResourceServers {
        PgResourceServers::new(self.store.pool().clone(), self.tenant.id.clone())
    }

    /// Registers a second resource server, so that a request naming one can be
    /// told apart from a request naming nothing.
    async fn register_resource_server(&self, identifier: &str) {
        self.resource_servers()
            .register(&ResourceServer {
                identifier: ResourceIdentifier::parse(identifier).expect("a resource indicator"),
                scopes: None,
                default_token_lifetime: None,
            })
            .await
            .expect("register the resource server");
    }

    /// A client registered for whichever grants a test names.
    ///
    /// RFC 7591 §2.1's table makes `response_types` and `grant_types`
    /// correspond, and the registration validator enforces it in both
    /// directions: a machine client reaches no authorization endpoint and says
    /// so with an empty `response_types` and no redirect URI, while a client
    /// registered for the code flow must carry both.
    async fn client(&self, grants: &[&str]) -> Client {
        let code_flow = grants.contains(&"authorization_code");
        let mut document = json!({
            "client_name": "Billing",
            "grant_types": grants,
            "response_types": if code_flow { json!(["code"]) } else { json!([]) },
            "scope": REGISTERED_SCOPE,
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        });
        if code_flow && let Some(object) = document.as_object_mut() {
            object.insert("redirect_uris".to_owned(), json!(["https://rp.example/cb"]));
        }
        let client = Client {
            tenant: self.tenant.id.clone(),
            id: ClientId::new(CLIENT),
            registration: ClientRegistration::from_json(
                &serde_json::to_vec(&document).expect("serialise"),
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

    /// Puts `allowed` on the client's own resource allow-list, which is policy
    /// beside the registration rather than registration metadata.
    async fn allow_resources(&self, client: &Client, allowed: &[&str]) -> Client {
        let mut client = client.clone();
        client.registration.resources = allowed.iter().map(|r| (*r).to_owned()).collect();
        self.store
            .scope(self.tenant.id.clone())
            .clients(Capabilities::default())
            .upsert(&client)
            .await
            .expect("store the client");
        client
    }

    /// One token request through the real endpoint and the real handler.
    async fn post(
        &self,
        client: &Client,
        pairs: &[(&str, &str)],
        proof_key: Option<&Kid>,
    ) -> (StatusCode, Value) {
        let grants = self.grants();
        let resource_servers = self.resource_servers();
        let handler = ClientCredentials {
            grants: &grants,
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
        let handlers: [&dyn GrantHandler; 1] = [&handler];

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

    /// The shorthand every happy-path test uses: a proof, and nothing else.
    async fn request(&self, client: &Client, extra: &[(&str, &str)]) -> (StatusCode, Value) {
        let mut pairs = vec![("grant_type", "client_credentials")];
        pairs.extend_from_slice(extra);
        self.post(client, &pairs, Some(&thumbprint(7))).await
    }

    /// Verifies a token the way a resource server does, and returns its claims.
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

    /// The response body and the claims of the access token in it.
    async fn issued(&self, client: &Client, extra: &[(&str, &str)]) -> (Value, Value) {
        let (status, body) = self.request(client, extra).await;
        assert_eq!(status, StatusCode::OK, "the request was refused: {body}");
        let claims = self
            .verify(body["access_token"].as_str().expect("an access token"))
            .await;
        (body, claims)
    }

    /// The grant a token names, read back through the repository.
    async fn grant_of(&self, claims: &Value) -> asterius_domain::Grant {
        let id = claims["grant_id"]
            .as_str()
            .expect("the token names its grant");
        self.grants()
            .find(&GrantId::new(id.to_owned()))
            .await
            .expect("read the grant")
            .expect("the grant the token names exists")
    }

    async fn tear_down(self) {
        PgTenantRepository::new(self.store.pool().clone(), self.kek)
            .delete(&self.tenant.id)
            .await
            .expect("delete tenant");
    }
}

macro_rules! db_test {
    ($(#[$meta:meta])* async fn $name:ident($f:ident) $body:block) => {
        $(#[$meta])*
        #[tokio::test]
        async fn $name() {
            let Some($f) = Fixture::new().await else {
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

// ---- The gap this story closes -------------------------------------------

/// The other half of `token.rs`'s guard: discovery advertised no
/// `client_credentials` while the endpoint answered 501 for it, and the two
/// move together.
#[test]
fn discovery_advertises_the_grant_this_file_implements() {
    // Arrange / Act
    let advertised = asterius_oidc::metadata::grant_types(&Capabilities::default());

    // Assert
    assert!(
        advertised.contains(&"client_credentials"),
        "discovery must advertise the grant: {advertised:?}"
    );
}

// ---- Who may ask ---------------------------------------------------------

db_test! {
    /// RFC 6749 §5.2: "The authenticated client is not authorized to use this
    /// authorization grant type." A registration is what says a client acts on
    /// its own behalf, and one that does not carry the grant does not get to.
    async fn a_client_that_did_not_register_for_the_grant_is_refused(f) {
        // Arrange
        let client = f.client(&["authorization_code", "refresh_token"]).await;

        // Act
        let (status, body) = f.request(&client, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "unauthorized_client");
        f.tear_down().await;
    }
}

// ---- The proof (RFC 9449 §5, FAPI 2.0 SP §5.3.2.1 item 4) ----------------

db_test! {
    /// FAPI 2.0 SP §5.3.2.1 item 4 admits no unbound access token, so a request
    /// with no proof has no token this handler could issue. RFC 9449 §5.2 makes
    /// that `invalid_dpop_proof` rather than `invalid_request`: the request is
    /// well formed, and what is missing is the proof.
    async fn a_request_with_no_dpop_proof_is_refused(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (status, body) = f
            .post(&client, &[("grant_type", "client_credentials")], None)
            .await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_dpop_proof");
        f.tear_down().await;
    }
}

db_test! {
    /// RFC 9449 §6.1: the token is bound to the key the request proved, and §5
    /// makes it a `DPoP` token rather than a `Bearer` one.
    async fn the_access_token_is_bound_to_the_proved_key(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (body, claims) = f.issued(&client, &[]).await;

        // Assert
        assert_eq!(body["token_type"], "DPoP");
        assert_eq!(claims["cnf"]["jkt"], json!(thumbprint(7).as_str()));
        f.tear_down().await;
    }
}

// ---- What the token says -------------------------------------------------

db_test! {
    /// RFC 9068 §2.2: "In cases of access tokens obtained through grants where
    /// no resource owner is involved, such as the client credentials grant, the
    /// value of `sub` SHOULD correspond to an identifier the authorization
    /// server uses to indicate the client application."
    async fn the_subject_of_a_client_only_token_is_the_client(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (_, claims) = f.issued(&client, &[]).await;

        // Assert
        assert_eq!(claims["sub"], json!(CLIENT));
        assert_eq!(claims["client_id"], json!(CLIENT));
        f.tear_down().await;
    }
}

db_test! {
    /// RFC 6749 §4.4.3: "A refresh token SHOULD NOT be included." There is
    /// nobody to come back on behalf of, and a long-lived credential for a
    /// client that can re-authenticate at will buys nothing and can be stolen.
    async fn no_refresh_token_is_issued(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (body, _) = f.issued(&client, &[]).await;

        // Assert
        assert!(
            body.get("refresh_token").is_none(),
            "a client-only grant handed out a refresh token: {body}"
        );
        f.tear_down().await;
    }
}

db_test! {
    /// OIDC Core §5.3 and §11: `openid` asks for an authentication about a
    /// person and `offline_access` asks for a refresh token, and this grant can
    /// produce neither. They are no part of what a client-only token may carry,
    /// so a request naming one is `invalid_scope` rather than a token that says
    /// something this server cannot stand behind.
    async fn the_two_user_facing_scopes_are_not_available_to_a_client(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (status, body) = f.request(&client, &[("scope", "openid")]).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_scope");
        f.tear_down().await;
    }
}

db_test! {
    /// RFC 6749 §3.3: an omitted `scope` is the server's own choice, and the
    /// choice here is everything the client registered for that this grant can
    /// actually issue — which excludes the two user-facing scopes above.
    async fn an_omitted_scope_defaults_to_the_registration(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (body, claims) = f.issued(&client, &[]).await;

        // Assert
        assert_eq!(body["scope"], json!("payments.read payments.write"));
        assert_eq!(claims["scope"], json!("payments.read payments.write"));
        f.tear_down().await;
    }
}

db_test! {
    /// RFC 6749 §3.3 and §5.2: a scope the client never registered for is
    /// `invalid_scope`, and the whole request fails rather than being trimmed —
    /// a client silently handed less than it asked for believes it holds more.
    async fn a_scope_outside_the_registration_is_refused(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (status, body) = f
            .request(&client, &[("scope", "payments.read ledger.write")])
            .await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_scope");
        f.tear_down().await;
    }
}

db_test! {
    /// A narrowing is what the parameter is for (RFC 6749 §3.3), and the token
    /// carries what was asked for rather than what was registered.
    async fn a_narrower_scope_is_the_one_the_token_carries(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (body, claims) = f.issued(&client, &[("scope", "payments.read")]).await;

        // Assert
        assert_eq!(body["scope"], json!("payments.read"));
        assert_eq!(claims["scope"], json!("payments.read"));
        f.tear_down().await;
    }
}

// ---- The audience (RFC 8707 §2.2, FAPI 2.0 SP §5.3.2.1 item 14) ----------

db_test! {
    /// RFC 8707 §2.2 and `ast-gxh.7`: a request that names no `resource` is
    /// audienced at the tenant's default, which the registry has to register.
    async fn a_request_naming_no_resource_is_audienced_at_the_tenants_default(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (_, claims) = f.issued(&client, &[]).await;

        // Assert
        assert_eq!(claims["aud"], json!(RESOURCE));
        f.tear_down().await;
    }
}

db_test! {
    /// The client's own allow-list comes first, exactly as it does for the
    /// authorization-code grant: one resolution, one answer.
    async fn the_clients_allow_list_decides_before_the_tenants_default(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;
        f.register_resource_server(OTHER_RESOURCE).await;
        let client = f.allow_resources(&client, &[OTHER_RESOURCE]).await;

        // Act
        let (_, claims) = f.issued(&client, &[]).await;

        // Assert
        assert_eq!(claims["aud"], json!(OTHER_RESOURCE));
        f.tear_down().await;
    }
}

db_test! {
    /// RFC 8707 §2: a `resource` this tenant does not register is
    /// `invalid_target`, not `invalid_scope` and not a token for it.
    async fn a_resource_the_tenant_does_not_register_is_invalid_target(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (status, body) = f
            .request(&client, &[("resource", "https://unknown.example/")])
            .await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_target");
        f.tear_down().await;
    }
}

db_test! {
    /// A registered resource the client's allow-list does not cover is refused
    /// for the same reason and with the same code: RFC 8707 §2.2 makes the
    /// requested set a subset of the authorized one.
    async fn a_resource_outside_the_clients_allow_list_is_invalid_target(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;
        f.register_resource_server(OTHER_RESOURCE).await;
        let client = f.allow_resources(&client, &[RESOURCE]).await;

        // Act
        let (status, body) = f.request(&client, &[("resource", OTHER_RESOURCE)]).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_target");
        f.tear_down().await;
    }
}

// ---- The grant row: audit and revocation ---------------------------------

db_test! {
    /// FAPI 2.0 SP §6.8 item 4 and Grant Management ID1 §5.6: every credential
    /// this server issues traces back to a revocable grant. A client-only token
    /// has no authorization behind it, so one is created here — already
    /// claimed, because the credential is taken the instant the row exists.
    async fn a_client_only_grant_row_is_created_for_the_token(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (_, claims) = f.issued(&client, &[]).await;

        // Assert
        let grant = f.grant_of(&claims).await;
        assert_eq!(grant.client, ClientId::new(CLIENT));
        assert_eq!(grant.user, None, "a client-only grant has no resource owner");
        assert_eq!(grant.subject, None, "a client-only grant has no sub");
        assert_eq!(grant.session, None, "a client-only grant has no session");
        assert_eq!(
            grant.status(f.now),
            GrantStatus::Active,
            "the grant was created without being claimed"
        );
        f.tear_down().await;
    }
}

db_test! {
    /// RFC 7009 and `ast-1sk.2`: `/revoke` reaches an access token through the
    /// `grant_id` it carries, so a token whose grant row does not answer to
    /// that claim is one nothing can revoke.
    async fn the_grant_row_records_what_the_token_was_issued_for(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (_, claims) = f.issued(&client, &[("scope", "payments.read")]).await;

        // Assert
        let grant = f.grant_of(&claims).await;
        assert_eq!(
            grant.scopes.iter().cloned().collect::<Vec<_>>(),
            vec!["payments.read".to_owned()]
        );
        assert_eq!(
            grant.resources.iter().cloned().collect::<Vec<_>>(),
            vec![RESOURCE.to_owned()],
            "the grant does not record the audience the token was minted at"
        );
        f.tear_down().await;
    }
}

// ---- The trail -----------------------------------------------------------

db_test! {
    /// A new grant is a new frontier: a client obtains a token with nobody
    /// present. The trail is what makes that visible afterwards, so an issuance
    /// is recorded with the client and the grant it was minted from.
    async fn an_issuance_is_recorded_in_the_trail(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (_, claims) = f.issued(&client, &[]).await;

        // Assert
        let events = f.audit.events();
        let event = events.first().expect("an issuance is recorded");
        assert_eq!(event.event_type, EventType::TOKEN_ISSUED);
        assert_eq!(event.outcome, Outcome::Success);
        assert_eq!(
            event.client.as_ref().map(ClientId::as_str),
            Some(CLIENT),
        );
        assert_eq!(
            event.grant.as_ref().map(GrantId::as_str),
            claims["grant_id"].as_str(),
            "the trail entry does not name the grant the token was minted from"
        );
        f.tear_down().await;
    }
}

db_test! {
    /// A refusal is recorded too: a run of them against one client is a
    /// credential being tried, and a trail that only holds successes hides it.
    async fn a_refusal_is_recorded_in_the_trail(f) {
        // Arrange
        let client = f.client(&["client_credentials"]).await;

        // Act
        let (status, _) = f
            .request(&client, &[("resource", "https://unknown.example/")])
            .await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let events = f.audit.events();
        let event = events.first().expect("a refusal is recorded");
        assert_eq!(event.event_type, EventType::TOKEN_ISSUED);
        assert_eq!(event.outcome, Outcome::Failure);
        f.tear_down().await;
    }
}
