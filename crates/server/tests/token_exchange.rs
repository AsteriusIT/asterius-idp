//! Token Exchange (RFC 8693 §2.1, §2.2, §3, §4.1, §4.4, §5).
//!
//! Every case here is an acceptance criterion on `ast-lh3.2`, and every one of
//! them is a subtraction. An exchange takes a token an agent holds and returns
//! a weaker one: fewer scopes, no wider an audience, no longer a life, and one
//! more entry in the `act` chain that says who is answerable.
//!
//! What this file guards, in the order the criteria are written:
//!
//! * the subject token is one *this* server issued, still alive, not revoked,
//!   and held by the party presenting it (§2.1, ADR-0002);
//! * the issued token records the actor (§4.1), within the depth the client's
//!   policy permits, and drops it only where the policy says impersonation
//!   (§5);
//! * `may_act` decides when it is there (§4.4);
//! * nothing widens (§2.2.2's `invalid_scope` and `invalid_target`);
//! * the response is §2.2.1's, with no refresh token;
//! * the trail records the whole chain.
//!
//! # Isolation
//!
//! As in `client_credentials.rs`: every test mints a unique tenant, touches
//! nothing outside it, and deletes it at the end.

use asterius_domain::audit::{AuditEvent, AuditSink, EventType, Outcome};
use asterius_domain::entities::client::GrantType;
use asterius_domain::issuance::{IssuanceAction, IssuanceDecision, IssuancePolicy, IssuanceQuery};
use asterius_domain::keys::Signer;
use asterius_domain::ports::TenantRepository;
use asterius_domain::{
    AgentLimits, Capabilities, Client, ClientId, ClientRegistration, ClientStatus, Grant, Issuer,
    KeyStore, Kid, ResourceIdentifier, ResourceServer, SubjectId, Tenant, TenantId, TenantStatus,
    User, UserId, UserStatus,
};
use asterius_jose::kek::Kek;
use asterius_jose::{LocalKek, jws, keys_from_jwk_set};
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::{AccessToken, Audience, Confirmation};
use asterius_server::http::agent_issuance::AgentPolicy;
use asterius_server::http::issuance::SenderConstraint;
use asterius_server::http::token::{GrantHandler, TokenContext, token};
use asterius_server::http::token_exchange::TokenExchange;
use asterius_server::signing::CachedSigner;
use asterius_store_pg::{
    PgAuditSink, PgGrantRepository, PgResourceServers, PgTenantRepository, PgUserRepository, Store,
    TenantKeyStore,
};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use time::{Duration, OffsetDateTime};

/// The audit trail, in memory: `asterius-server` cannot read `audit_events`
/// back (ADR-0001), and the sink is a port.
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

const AGENT: &str = "agent";
const HOLDER: &str = "holder";
const RESOURCE: &str = "https://api.example/";
const OTHER_RESOURCE: &str = "https://reports.example/";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
/// What both clients registered. The two scopes are what the narrowing tests
/// move between; `openid` is there so that "an exchanged token never carries
/// it" is a statement about a client that could have asked.
const REGISTERED_SCOPE: &str = "payments.read payments.write openid";

/// What this deployment offers. Token exchange is a flag, and a test that ran
/// with it off would be testing the dispatch rather than the grant.
fn capabilities() -> Capabilities {
    Capabilities {
        token_exchange: true,
        ..Capabilities::default()
    }
}

/// The pre-issuance decision point (`ast-lh3.10`), as a port implementation.
///
/// It records the questions it was asked, which is how a test can assert the
/// §5.2 action this grant uses without reading the engine.
#[derive(Debug)]
struct FakePolicy {
    answer: Answer,
    asked: Mutex<Vec<IssuanceQuery>>,
}

#[derive(Debug, Clone, Copy)]
enum Answer {
    Permit,
    Deny,
    Unavailable,
}

impl FakePolicy {
    /// A decision point that permits everything.
    fn permit() -> Self {
        Self::answering(Answer::Permit)
    }

    /// One that refuses everything, with a reason.
    fn deny() -> Self {
        Self::answering(Answer::Deny)
    }

    /// One that cannot answer at all.
    fn unavailable() -> Self {
        Self::answering(Answer::Unavailable)
    }

    fn answering(answer: Answer) -> Self {
        Self {
            answer,
            asked: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl IssuancePolicy for FakePolicy {
    async fn permits(
        &self,
        _tenant: &TenantId,
        query: &IssuanceQuery,
    ) -> Result<IssuanceDecision, asterius_domain::DomainError> {
        self.asked.lock().expect("lock").push(query.clone());
        match self.answer {
            Answer::Permit => Ok(IssuanceDecision::permit(None)),
            Answer::Deny => Ok(IssuanceDecision::deny(Some(
                "rule no-delegation denied".to_owned(),
            ))),
            Answer::Unavailable => Err(asterius_domain::DomainError::Storage(
                "the policy store is unreachable".into(),
            )),
        }
    }
}

struct Fixture {
    /// The decision point this fixture's handler consults (`ast-lh3.10`).
    /// `None` in every test but the ones about it, which is a deployment with
    /// `[features] authzen` off.
    policy: Option<Arc<FakePolicy>>,
    store: Store,
    keys: TenantKeyStore,
    audit: Arc<FakeAudit>,
    tenant: Tenant,
    signer: Arc<CachedSigner>,
    kek: Arc<dyn Kek>,
    user: UserId,
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

        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[9_u8; 32]).expect("a 32-byte KEK"));
        let audit = Arc::new(FakeAudit::default());
        let now = OffsetDateTime::now_utc();

        let id = format!(
            "tx-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tenant = Tenant {
            id: TenantId::parse(&id).expect("a generated tenant id"),
            issuer: Issuer::parse(&format!("https://as.example/t/{id}")).expect("issuer"),
            custom_host: None,
            display_name: "Token exchange".to_owned(),
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

        let user = UserId::generate();
        PgUserRepository::new(store.pool().clone(), tenant.id.clone(), Arc::clone(&kek))
            .upsert(&User {
                tenant: tenant.id.clone(),
                id: user,
                username: user.to_string(),
                email: None,
                email_verified: false,
                status: UserStatus::Active,
                claims: asterius_domain::entities::user::ClaimSet::default(),
                created_at: now,
                updated_at: now,
            })
            .await
            .expect("create the person the agent acts for");

        Some(Self {
            policy: None,
            store,
            keys,
            audit,
            tenant,
            signer,
            kek,
            user,
            now,
        })
    }

    fn grants(&self) -> PgGrantRepository {
        PgGrantRepository::new(self.store.pool().clone(), self.tenant.id.clone())
    }

    fn resource_servers(&self) -> PgResourceServers {
        PgResourceServers::new(self.store.pool().clone(), self.tenant.id.clone())
    }

    async fn register_resource_server(&self, identifier: &str) {
        self.resource_servers()
            .register(&ResourceServer {
                identifier: ResourceIdentifier::parse(identifier).expect("a resource indicator"),
                scopes: None,
                default_token_lifetime: None,
                introspection_clients: std::collections::BTreeSet::new(),
            })
            .await
            .expect("register the resource server");
    }

    /// An agent client under `limits`, owned by the fixture's account.
    ///
    /// The owner is a real row: migration `0021` makes it a foreign key, so a
    /// test that invented one would be testing a shape the database refuses.
    async fn agent(&self, id: &str, limits: AgentLimits) -> Client {
        let document = json!({
            "client_name": "Reconciler",
            "grant_types": [GRANT_TYPE],
            "response_types": [],
            "scope": REGISTERED_SCOPE,
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            "client_kind": "agent",
            "agent_owner": self.user.to_string(),
        });
        let mut registration = ClientRegistration::from_json(
            &serde_json::to_vec(&document).expect("serialise"),
            capabilities(),
        )
        .expect("a valid agent registration");
        // What `POST /register` does with the tenant's policy, done here.
        registration.agent = registration
            .agent
            .take()
            .map(|profile| profile.under(limits));
        registration.resources = [RESOURCE.to_owned()].into_iter().collect();

        self.store_client(id, registration).await
    }

    /// An ordinary confidential client — the party a subject token was minted
    /// for when it is not the agent itself.
    async fn client(&self, id: &str) -> Client {
        let document = json!({
            "client_name": "Billing",
            "grant_types": ["client_credentials"],
            "response_types": [],
            "scope": REGISTERED_SCOPE,
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        });
        let registration = ClientRegistration::from_json(
            &serde_json::to_vec(&document).expect("serialise"),
            capabilities(),
        )
        .expect("a valid registration");
        self.store_client(id, registration).await
    }

    async fn store_client(&self, id: &str, registration: ClientRegistration) -> Client {
        let client = Client {
            tenant: self.tenant.id.clone(),
            id: ClientId::new(id),
            registration,
            status: ClientStatus::Active,
            created_at: self.now,
            updated_at: self.now,
        };
        self.store
            .scope(self.tenant.id.clone())
            .clients(capabilities())
            .upsert(&client)
            .await
            .expect("store the client");
        client
    }

    /// The authorization a subject token is minted from.
    ///
    /// A user's grant: `sub` is the person, and the scopes and resources are
    /// the ceiling every exchange below narrows from.
    /// The same fixture with a decision point behind the issuance check.
    fn under_policy(mut self, policy: FakePolicy) -> Self {
        self.policy = Some(Arc::new(policy));
        self
    }

    /// The questions the decision point was asked.
    fn asked(&self) -> Vec<IssuanceQuery> {
        self.policy
            .as_ref()
            .map(|policy| policy.asked.lock().expect("lock").clone())
            .unwrap_or_default()
    }

    async fn subject_grant(&self, client: &Client, scopes: &[&str]) -> Grant {
        self.subject_grant_after(client, scopes, &[]).await
    }

    /// The same, for an authorization that has already been delegated once:
    /// `chain` is §4.1's actors, current first, as the grant stores them.
    async fn subject_grant_after(
        &self,
        client: &Client,
        scopes: &[&str],
        chain: &[Value],
    ) -> Grant {
        let mut grant = Grant::new(self.tenant.id.clone(), client.id.clone(), self.now);
        grant.actor_chain = chain.to_vec();
        grant.user = Some(self.user);
        grant.subject = Some(SubjectId::new(self.user.to_string()));
        grant.scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
        grant.resources = [RESOURCE.to_owned()].into_iter().collect();
        grant.claimed_at = Some(self.now);
        grant.expires_at = Some(self.now + Duration::minutes(10));
        self.grants()
            .create(&grant)
            .await
            .expect("create the grant");
        grant
    }

    /// A signed access token for `grant`, the way the server mints one.
    async fn subject_token(&self, grant: &Grant, jkt: &Kid, lifetime: Duration) -> String {
        self.subject_token_with(grant, jkt, lifetime, None).await
    }

    /// The same, with one extra claim — `may_act` (§4.4), which no issuance
    /// path in this build writes yet and which a subject token may carry.
    async fn subject_token_with(
        &self,
        grant: &Grant,
        jkt: &Kid,
        lifetime: Duration,
        extra: Option<(&str, Value)>,
    ) -> String {
        let claimed = grant.claim(self.now).expect("an issuable grant");
        let access = AccessToken::new(
            &self.tenant.issuer,
            grant,
            &claimed,
            Audience::new([RESOURCE]).expect("an audience"),
            Confirmation::dpop(jkt).expect("a thumbprint"),
            JwtId::generate(),
            self.now,
        )
        .with_grant_id()
        .for_lifetime(lifetime)
        .build()
        .expect("a well-formed access token");
        let mut claims = access.claims().clone();
        if let Some((name, value)) = extra
            && let Some(object) = claims.as_object_mut()
        {
            object.insert(name.to_owned(), value);
        }
        self.signer
            .sign(
                &self.tenant.id,
                access.required_algorithm(),
                access.typ(),
                &claims,
            )
            .await
            .expect("sign the subject token")
            .as_str()
            .to_owned()
    }

    /// One exchange through the real endpoint and the real handler.
    async fn post(
        &self,
        client: &Client,
        pairs: &[(&str, &str)],
        proof_key: Option<&Kid>,
    ) -> (StatusCode, Value) {
        let grants = self.grants();
        let resource_servers = self.resource_servers();
        let clients = self
            .store
            .scope(self.tenant.id.clone())
            .clients(capabilities());
        let handler = TokenExchange {
            clients: &clients,
            grants: &grants,
            resource_servers: &resource_servers,
            keys: &self.keys,
            signer: self.signer.as_ref(),
            audit: self.audit.as_ref(),
            grant_id_claim: true,
            grant_management: false,
            lifetimes: asterius_domain::TokenLifetimes::default(),
            constraint: SenderConstraint {
                proof_key,
                certificate: None,
            },
            agent_policy: AgentPolicy {
                policy: self
                    .policy
                    .clone()
                    .map(|policy| policy as Arc<dyn IssuancePolicy>),
                fail_open: false,
                audit: self.audit.as_ref(),
            },
            now: self.now,
        };
        let handlers: [&dyn GrantHandler; 1] = [&handler];

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

        let dispatch_clients = self
            .store
            .scope(self.tenant.id.clone())
            .clients(capabilities());
        let authenticated = client.clone();
        let response = token(
            TokenContext {
                certificate: None,
                tenant: &self.tenant,
                clients: &dispatch_clients,
                capabilities: capabilities(),
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

    /// The shorthand: a subject token, a proof, and whatever else a test adds.
    async fn exchange(
        &self,
        agent: &Client,
        subject_token: &str,
        proof_key: &Kid,
        extra: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let mut pairs = vec![
            ("grant_type", GRANT_TYPE),
            ("subject_token", subject_token),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
        ];
        pairs.extend_from_slice(extra);
        self.post(agent, &pairs, Some(proof_key)).await
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

/// The limits a tenant gives an agent that may exchange tokens at all.
fn exchanging(depth: u8) -> AgentLimits {
    AgentLimits::default()
        .with_grant_types([GrantType::TokenExchange])
        .with_max_delegation_depth(depth)
}

// ---- Metadata and routes move together -----------------------------------

/// The other half of the dispatch: a grant advertised and not implemented
/// answers 501, and a grant implemented and not advertised is unreachable.
#[test]
fn discovery_advertises_the_grant_this_file_implements() {
    // Arrange / Act
    let advertised = asterius_oidc::metadata::grant_types(&capabilities());

    // Assert
    assert!(
        advertised.contains(&GRANT_TYPE),
        "discovery must advertise the grant: {advertised:?}"
    );
}

/// And it is advertised only where the flag is on: a client cannot reach a
/// grant this deployment turned off by naming it in a form field.
#[test]
fn the_grant_is_not_advertised_where_the_flag_is_off() {
    // Arrange
    let off = Capabilities {
        token_exchange: false,
        ..Capabilities::default()
    };

    // Act
    let advertised = asterius_oidc::metadata::grant_types(&off);

    // Assert
    assert!(!advertised.contains(&GRANT_TYPE), "{advertised:?}");
}

// ---- The happy path (§2.2.1, §4.1) ---------------------------------------

db_test! {
    /// The whole criterion in one exchange: §2.2.1's response, §4.1's `act`,
    /// the new token bound to the key that asked, and a grant row whose parent
    /// is the authorization the subject token came from.
    async fn an_exchange_returns_a_delegated_token_that_names_its_actor(f) {
        // Arrange
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&agent, &["payments.read", "payments.write"]).await;
        let key = thumbprint(7);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::OK, "{body}");
        // §2.2.1: `issued_token_type` is REQUIRED, and there is no refresh
        // token — a credential that renews a delegation unattended is §5's
        // warning.
        assert_eq!(body["issued_token_type"], ACCESS_TOKEN_TYPE);
        assert_eq!(body["token_type"], "DPoP");
        assert!(body["expires_in"].as_i64().expect("a lifetime") > 0);
        assert!(body["refresh_token"].is_null(), "{body}");

        let claims = f.verify(body["access_token"].as_str().expect("a token")).await;
        // §4.1: the current actor, outermost, and no prior actor to nest.
        assert_eq!(claims["act"], json!({ "client_id": AGENT }));
        // The subject is unchanged: an exchange changes who acts, never who is
        // acted for.
        assert_eq!(claims["sub"], json!(f.user.to_string()));
        // The token is bound to the key that asked for it (RFC 9449 §6.1).
        assert_eq!(claims["cnf"]["jkt"], json!(key.as_str()));
        assert_eq!(claims["aud"], json!(RESOURCE));

        // The child grant points at the authorization behind it, so revoking
        // the parent is a decision about the delegation too.
        let child = f
            .grants()
            .find(&asterius_domain::GrantId::new(
                claims["grant_id"].as_str().expect("a grant id").to_owned(),
            ))
            .await
            .expect("read the grant")
            .expect("the grant the token names exists");
        assert_eq!(child.parent, Some(grant.id));

        f.tear_down().await;
    }
}

db_test! {
    /// §4.1: "The outermost `act` claim represents the current actor while
    /// nested `act` claims represent prior actors." A second hop nests the
    /// first inside the second, never the other way round.
    async fn a_second_hop_nests_the_previous_actor_inside_the_current_one(f) {
        // Arrange: a subject token that already names an actor, and a policy
        // that permits two hops.
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(2)).await;
        let grant = f
            .subject_grant_after(
                &agent,
                &["payments.read"],
                &[json!({ "client_id": "c.first" })],
            )
            .await;
        let key = thumbprint(7);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::OK, "{body}");
        let claims = f.verify(body["access_token"].as_str().expect("a token")).await;
        assert_eq!(
            claims["act"],
            json!({ "client_id": AGENT, "act": { "client_id": "c.first" } })
        );

        f.tear_down().await;
    }
}

db_test! {
    /// A chain deeper than the policy permits is `invalid_request`: the bound
    /// is the tenant's answer to "how far may this delegation travel".
    async fn a_chain_deeper_than_the_policy_is_refused(f) {
        // Arrange: one hop permitted, and a token that has already had one.
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f
            .subject_grant_after(
                &agent,
                &["payments.read"],
                &[json!({ "client_id": "c.first" })],
            )
            .await;
        let key = thumbprint(7);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");

        f.tear_down().await;
    }
}

db_test! {
    /// §5: impersonation only where the policy says so, and then the issued
    /// token carries no `act` at all — which is exactly what makes it
    /// indistinguishable from one minted for the person.
    async fn impersonation_drops_the_act_claim_and_only_where_policy_permits(f) {
        // Arrange
        f.register_resource_server(RESOURCE).await;
        let agent = f
            .agent(AGENT, exchanging(1).with_impersonation(true))
            .await;
        let grant = f.subject_grant(&agent, &["payments.read"]).await;
        let key = thumbprint(7);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::OK, "{body}");
        let claims = f.verify(body["access_token"].as_str().expect("a token")).await;
        assert!(claims.get("act").is_none(), "{claims}");
        assert_eq!(claims["sub"], json!(f.user.to_string()));

        f.tear_down().await;
    }
}

// ---- Which tokens may be exchanged (§2.1) --------------------------------

db_test! {
    /// A token presented without the key it is bound to has left its holder.
    /// The default answer is `invalid_grant`, whoever is asking.
    async fn a_token_not_bound_to_the_presented_key_is_refused(f) {
        // Arrange: the subject token belongs to another client, bound to
        // another key, and that client's policy says nothing.
        f.register_resource_server(RESOURCE).await;
        let holder = f.client(HOLDER).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&holder, &["payments.read"]).await;
        let subject = f.subject_token(&grant, &thumbprint(9), Duration::minutes(5)).await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &thumbprint(7), &[]).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_grant");

        f.tear_down().await;
    }
}

db_test! {
    /// …unless the client the token was minted for is marked `exchangeable`,
    /// which is an operator's explicit decision that its tokens may travel.
    async fn a_token_marked_exchangeable_by_its_own_client_may_be_exchanged(f) {
        // Arrange
        f.register_resource_server(RESOURCE).await;
        let holder = f
            .agent(HOLDER, exchanging(1).with_exchangeable(true))
            .await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&holder, &["payments.read"]).await;
        let subject = f.subject_token(&grant, &thumbprint(9), Duration::minutes(5)).await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &thumbprint(7), &[]).await;

        // Assert
        assert_eq!(status, StatusCode::OK, "{body}");
        let claims = f.verify(body["access_token"].as_str().expect("a token")).await;
        assert_eq!(claims["act"], json!({ "client_id": AGENT }));
        // Bound to the key that asked, not to the one the subject token had.
        assert_eq!(claims["cnf"]["jkt"], json!(thumbprint(7).as_str()));

        f.tear_down().await;
    }
}

db_test! {
    /// A revoked authorization takes its exchanges with it. Anything else
    /// would make this endpoint a way to outlive a revocation.
    async fn a_token_whose_grant_was_revoked_cannot_be_exchanged(f) {
        // Arrange
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&agent, &["payments.read"]).await;
        let key = thumbprint(7);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;
        let _revocation = f
            .grants()
            .revoke(
                &grant.id,
                asterius_domain::entities::grant::RevocationReason::UserRevoked,
                &[],
                f.now,
            )
            .await
            .expect("revoke the authorization");

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_grant");

        f.tear_down().await;
    }
}

db_test! {
    /// §4.4: "a claim that asserts that a party is authorized to become the
    /// actor". When the subject token names somebody else, this actor is not
    /// authorized — whatever the client's own policy says.
    async fn a_may_act_naming_another_party_refuses_the_exchange(f) {
        // Arrange: `may_act` is a claim of the subject token, so it is minted
        // onto one and signed with this tenant's key — the same signature the
        // handler will check.
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&agent, &["payments.read"]).await;
        let key = thumbprint(7);
        let subject = f
            .subject_token_with(
                &grant,
                &key,
                Duration::minutes(5),
                Some(("may_act", json!({ "client_id": "c.somebody-else" }))),
            )
            .await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_grant");

        f.tear_down().await;
    }
}

db_test! {
    /// The same claim naming *this* actor authorizes it.
    async fn a_may_act_naming_this_actor_authorizes_the_exchange(f) {
        // Arrange
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&agent, &["payments.read"]).await;
        let key = thumbprint(7);
        let subject = f
            .subject_token_with(
                &grant,
                &key,
                Duration::minutes(5),
                Some(("may_act", json!({ "client_id": AGENT }))),
            )
            .await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::OK, "{body}");

        f.tear_down().await;
    }
}

// ---- Everything narrows (§2.2.2) -----------------------------------------

db_test! {
    /// A requested scope the subject token does not carry is `invalid_scope`,
    /// not a token with the scope quietly dropped.
    async fn a_scope_the_subject_token_does_not_carry_is_refused(f) {
        // Arrange
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&agent, &["payments.read"]).await;
        let key = thumbprint(7);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f
            .exchange(&agent, &subject, &key, &[("scope", "payments.write")])
            .await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_scope");

        f.tear_down().await;
    }
}

db_test! {
    /// A requested scope the subject token does carry narrows the token.
    async fn a_requested_scope_narrows_the_issued_token(f) {
        // Arrange
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f
            .subject_grant(&agent, &["payments.read", "payments.write"])
            .await;
        let key = thumbprint(7);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f
            .exchange(&agent, &subject, &key, &[("scope", "payments.read")])
            .await;

        // Assert
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["scope"], "payments.read");
        let claims = f.verify(body["access_token"].as_str().expect("a token")).await;
        assert_eq!(claims["scope"], "payments.read");

        f.tear_down().await;
    }
}

db_test! {
    /// §2.2.2: `invalid_target` for "the requested resource or audience is
    /// unacceptable". A resource the subject token's authorization never
    /// named is exactly that.
    async fn an_audience_the_subject_token_never_had_is_invalid_target(f) {
        // Arrange: both resources exist, and only one is the subject's.
        f.register_resource_server(RESOURCE).await;
        f.register_resource_server(OTHER_RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&agent, &["payments.read"]).await;
        let key = thumbprint(7);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f
            .exchange(&agent, &subject, &key, &[("audience", OTHER_RESOURCE)])
            .await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_target");

        f.tear_down().await;
    }
}

db_test! {
    /// The issued token never outlives the one it came from. A delegation that
    /// could be renewed by exchanging it in a loop is not a delegation.
    async fn the_issued_token_lives_no_longer_than_the_subject_token(f) {
        // Arrange: a subject token with well under a tenant lifetime left.
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&agent, &["payments.read"]).await;
        let key = thumbprint(7);
        let subject = f.subject_token(&grant, &key, Duration::seconds(30)).await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["expires_in"].as_i64().expect("a lifetime") <= 30,
            "the exchanged token outlived its subject: {body}"
        );

        f.tear_down().await;
    }
}

db_test! {
    /// v1 mints access tokens (§2.1's `requested_token_type`), and says so
    /// rather than issuing something the client did not ask for.
    async fn asking_for_another_token_type_is_invalid_request(f) {
        // Arrange
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&agent, &["payments.read"]).await;
        let key = thumbprint(7);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f
            .exchange(
                &agent,
                &subject,
                &key,
                &[("requested_token_type", "urn:ietf:params:oauth:token-type:id_token")],
            )
            .await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");

        f.tear_down().await;
    }
}

// ---- The trail (§4.1, `ast-lh3.9`) ---------------------------------------

db_test! {
    /// An entry naming only the agent answers "who called" and not "who is
    /// answerable". The chain is what makes the second question answerable.
    async fn the_trail_records_the_whole_chain(f) {
        // Arrange
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(2)).await;
        let grant = f
            .subject_grant_after(
                &agent,
                &["payments.read"],
                &[json!({ "client_id": "c.first" })],
            )
            .await;
        let key = thumbprint(7);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::OK, "{body}");
        let events = f.audit.events();
        let event = events
            .iter()
            .find(|event| event.event_type == EventType::TOKEN_EXCHANGED)
            .expect("the exchange is on the trail");
        assert_eq!(event.outcome, Outcome::Success);
        assert_eq!(
            event.actor_chain,
            vec![
                asterius_domain::audit::Actor::Client(ClientId::new(AGENT)),
                asterius_domain::audit::Actor::Client(ClientId::new("c.first")),
            ]
        );

        f.tear_down().await;
    }
}

// ---- The pre-issuance policy (`ast-lh3.10`) -------------------------------

db_test! {
    /// A policy deny stops the exchange. The action asked about is
    /// `exchange_token` and not `obtain_token`: passing an authority on is a
    /// different thing for a rule to decide than creating one.
    async fn a_policy_deny_stops_an_exchange(f) {
        // Arrange
        let f = f.under_policy(FakePolicy::deny());
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&agent, &["payments.read"]).await;
        let key = thumbprint(21);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "access_denied");
        assert!(body["access_token"].is_null(), "{body}");

        f.tear_down().await;
    }
}

db_test! {
    /// The action the policy is asked about, read off the request the fake
    /// recorded: §5.2's `name`, and the one thing that tells this grant's
    /// question from the three that mint a fresh token.
    async fn an_exchange_asks_the_exchange_token_action(f) {
        // Arrange
        let f = f.under_policy(FakePolicy::permit());
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&agent, &["payments.read"]).await;
        let key = thumbprint(22);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            f.asked().first().map(|query| query.action),
            Some(IssuanceAction::ExchangeToken)
        );

        f.tear_down().await;
    }
}

db_test! {
    /// Fail closed, for the grant that carries a delegation: a decision point
    /// that cannot answer mints nothing.
    async fn an_unavailable_policy_stops_an_exchange(f) {
        // Arrange
        let f = f.under_policy(FakePolicy::unavailable());
        f.register_resource_server(RESOURCE).await;
        let agent = f.agent(AGENT, exchanging(1)).await;
        let grant = f.subject_grant(&agent, &["payments.read"]).await;
        let key = thumbprint(23);
        let subject = f.subject_token(&grant, &key, Duration::minutes(5)).await;

        // Act
        let (status, body) = f.exchange(&agent, &subject, &key, &[]).await;

        // Assert
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "access_denied");

        f.tear_down().await;
    }
}
