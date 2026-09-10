//! The whole chain, over HTTP: push, sign in, consent, redeem, refresh.
//!
//! # Why this file exists
//!
//! `ast-1h1` was a refresh token that every one of 116 integration tests said
//! worked and that the OIDF conformance suite found broken on its first real
//! run. The gap was not subtle in hindsight: every one of those tests seeded a
//! refresh token through a fixture and presented it with the key the fixture
//! had seeded, so neither the seam from an authorization code to a refresh
//! token nor a change of DPoP key between two token requests was ever crossed.
//! Nothing in the repository drove a request through the router.
//!
//! So this does. Every request below is an `http::Request` handed to the
//! assembled application — the same `protocol::routes` the binary mounts, under
//! the same tenancy middleware and the same security layers — and the only
//! things this test knows about the server are the ones a client knows: a URL,
//! a form body, a cookie it was handed, and the HTML it was served.
//!
//! What it therefore covers that a handler-level test cannot:
//!
//! * the tenancy layer resolving `/t/{tenant}` and the handlers producing URLs
//!   under that prefix (`ast-295`);
//! * a `request_uri` surviving from the push to the authorization request;
//! * an authorization code crossing from the interaction into the token
//!   endpoint, in the response body of one request and the form body of the
//!   next;
//! * `offline_access` actually earning a refresh token, and that token being
//!   redeemed at the endpoint — which is `ast-1h1`'s scenario exactly;
//! * a refresh presented under a *different* DPoP key from the one that
//!   redeemed the code, which is what the conformance suite does and what no
//!   fixture-seeded test did.
//!
//! # Isolation
//!
//! As in `authorization_code.rs`: `asterius-server` has no `sqlx` dependency
//! (ADR-0001), so there is no per-test schema. The test mints a unique tenant,
//! touches nothing outside it, and deletes it at the end.

use asterius_domain::entities::user::{User, UserStatus};
use asterius_domain::ports::{PasskeyRepository, TenantRepository, TenantSettingsRepository};
use asterius_domain::{
    Argon2Parameters, Capabilities, ClaimSet, Client, ClientId, ClientRegistration, ClientStatus,
    EndpointLimit, EndpointLimits, Issuer, Kid, Lifetimes, LoginLimits, NewPasskey, RateLimit,
    SigningAlgorithm, Tenant, TenantId, TenantSettings, TenantStatus, UserId,
};
use asterius_jose::kek::Kek;
use asterius_jose::{LocalKek, SigningKey, jws};
use asterius_oidc::client_auth::CLIENT_ASSERTION_TYPE;
use asterius_oidc::metadata::Endpoint;
use asterius_server::config::{ServerConfig, TransportMode};
use asterius_server::http::dpop::DpopEndpoint;
use asterius_server::http::protocol::{self, ClientEndpoints, ProtocolState};
use asterius_server::http::register::RegistrationPolicy;
use asterius_server::http::server::app;
use asterius_server::signing::CachedSigner;
use asterius_server::tenancy::{TenantDirectory, TenantState};
use asterius_server::tenant_settings::SettingsDirectory;
use asterius_store_pg::{
    PgAuditSink, PgPasskeyRepository, PgReplayGuard, PgSessionRepository, PgTenantRepository,
    PgTenantSettings, PgUserRepository, Redemption, Store, TenantKeyStore,
};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ciborium::value::Value as Cbor;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use time::OffsetDateTime;
use tower::ServiceExt as _;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// The host every request carries, and the host the tenant's issuer names.
///
/// They have to be the same string: the tenancy layer refuses a request whose
/// `Host` is not one the resolved tenant answers to, because a token minted
/// under an issuer the request never reached would satisfy a client's `iss`
/// check against a server it never spoke to.
const HOST: &str = "as.example";
const ORIGIN: &str = "https://as.example";
const CLIENT: &str = "billing";
/// A second registered client, for RFC 7009 §2.2: a token issued to one
/// client is not revocable by another.
const OTHER_CLIENT: &str = "reporting";
/// A machine client, for RFC 6749 §4.4: it acts for itself, and there is no
/// person anywhere in its story.
const SERVICE_CLIENT: &str = "ledger";
const REDIRECT: &str = "https://rp.example/cb";
const RESOURCE: &str = "https://api.example/";
const NONCE: &str = "n-0S6_WzA2Mj";
const STATE: &str = "xyz";
const CLIENT_KID: &str = "client-key-1";

/// RFC 7636 Appendix B's own published pair.
///
/// Hard-coded rather than derived, for the reason `authorization_code.rs`
/// gives: a test that computed the challenge from the verifier would assert
/// this server agrees with itself, and this pair asserts it agrees with the
/// specification.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The WebAuthn flag bits (§6.1): user present, user verified.
const UP: u8 = 1 << 0;
const UV: u8 = 1 << 2;

// ---- the authenticator ---------------------------------------------------

/// A real ES256 pair, standing in for the thing in somebody's pocket.
///
/// The same shape as `passkey_login.rs`'s, and real for the same reason: a
/// stubbed signature would prove nothing about the one part of a sign-in that
/// is cryptography, and a sign-in that did not really happen would leave this
/// file asserting a chain with a hole in the middle.
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
            credential_id: vec![7_u8; 20],
        }
    }

    /// The `COSE_Key` an enrolment would have stored.
    fn cose_key(&self) -> Vec<u8> {
        let point = self.pair.public_key().as_ref().to_vec();
        let map = Cbor::Map(vec![
            (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
            (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
            (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
            (
                Cbor::Integer((-2).into()),
                Cbor::Bytes(point[1..33].to_vec()),
            ),
            (
                Cbor::Integer((-3).into()),
                Cbor::Bytes(point[33..].to_vec()),
            ),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&map, &mut encoded).expect("a CBOR map encodes");
        encoded
    }

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

fn client_data(challenge: &[u8]) -> Vec<u8> {
    json!({
        "type": "webauthn.get",
        "challenge": B64.encode(challenge),
        "origin": ORIGIN,
    })
    .to_string()
    .into_bytes()
}

// ---- a client's DPoP key -------------------------------------------------

/// One DPoP key and the proofs it makes.
struct ProofKey(SigningKey);

impl ProofKey {
    fn generate() -> Self {
        Self(SigningKey::generate(SigningAlgorithm::EdDsa).expect("a generated key"))
    }

    /// The JWK the proof header carries, and that `jkt` is the thumbprint of.
    fn jwk(&self) -> Value {
        let mut jwk = self.0.public_jwk().expect("a public JWK");
        if let Some(object) = jwk.as_object_mut() {
            object.remove("use");
        }
        jwk
    }

    fn thumbprint(&self) -> Kid {
        asterius_jose::thumbprint(&self.jwk()).expect("a thumbprint")
    }

    /// A proof for one request, signed by hand: there is no builder, and a
    /// client is exactly the thing that assembles these itself.
    fn proof(&self, method: &str, url: &str, jti: &str) -> String {
        self.proof_over(method, url, jti, None)
    }

    /// The same proof, carrying `ath` over the access token it is presented
    /// with (RFC 9449 §4.3 item 12, which a protected resource requires).
    fn proof_over(&self, method: &str, url: &str, jti: &str, access_token: Option<&str>) -> String {
        let header = json!({
            "typ": "dpop+jwt",
            "alg": self.0.algorithm().as_str(),
            "jwk": self.jwk(),
        });
        let mut claims = json!({
            "jti": jti,
            "htm": method,
            "htu": url,
            "iat": OffsetDateTime::now_utc().unix_timestamp(),
        });
        if let Some(token) = access_token {
            claims["ath"] = json!(B64.encode(Sha256::digest(token.as_bytes())));
        }
        let signing_input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).expect("a header serialises")),
            B64.encode(serde_json::to_vec(&claims).expect("claims serialise"))
        );
        let signature = self.0.sign(signing_input.as_bytes()).expect("a signature");
        format!("{signing_input}.{}", B64.encode(signature))
    }
}

// ---- the fixture ---------------------------------------------------------

/// One response, in the three parts a client reads.
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    /// The reference a successful push handed back (RFC 9126 §2.2).
    ///
    /// The success assertion lives here rather than in `push_with`, because a
    /// *refused* push is a scenario this file tests: a caller that wants the
    /// reference says so by asking for it.
    fn request_uri(&self) -> String {
        assert_eq!(
            self.status,
            StatusCode::CREATED,
            "the push was refused: {}",
            self.text()
        );
        self.json()["request_uri"]
            .as_str()
            .expect("RFC 9126 §2.2 requires a request_uri")
            .to_owned()
    }

    fn location(&self) -> String {
        self.headers
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    }
}

/// A browser and a client, sharing one assembled server.
struct Flow {
    app: Router,
    store: Store,
    kek: Arc<dyn Kek>,
    tenant: Tenant,
    /// The same settings cache the application reads its per-tenant lifetimes
    /// from, held so that a test can drop it after writing a row.
    settings: SettingsDirectory,
    /// What the browser is holding, by cookie name.
    jar: BTreeMap<String, String>,
    client_key: SigningKey,
    authenticator: Authenticator,
    user: UserId,
    jti: AtomicU32,
}

impl Flow {
    /// `None` without `DATABASE_URL`, so the default suite stays fast.
    async fn new() -> Option<Self> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let store = Store::connect(&url, 4)
            .await
            .expect("DATABASE_URL is set but unreachable; is `docker compose up -d db` running?");
        store.migrate().await.expect("migrate");

        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[5_u8; 32]).expect("a 32-byte KEK"));
        let now = OffsetDateTime::now_utc();
        let id = format!(
            "e2e-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tenant = Tenant {
            id: TenantId::parse(&id).expect("a generated tenant id"),
            issuer: Issuer::parse(&format!("https://{HOST}/t/{id}")).expect("an issuer"),
            custom_host: None,
            display_name: "End to end".to_owned(),
            default_resource: RESOURCE.to_owned(),
            status: TenantStatus::Active,
            refresh: asterius_domain::RefreshPolicy::default(),
            created_at: now,
            updated_at: now,
        };
        let tenants = PgTenantRepository::new(store.pool().clone(), Arc::clone(&kek));
        tenants.upsert(&tenant).await.expect("create the tenant");

        let audit = Arc::new(PgAuditSink::new(store.pool().clone()));
        let keys = TenantKeyStore::new(
            store.pool().clone(),
            Arc::clone(&kek),
            Arc::clone(&audit) as Arc<dyn asterius_domain::AuditSink>,
        );
        keys.apply_schedule(&tenant.id, now)
            .await
            .expect("prepare signing keys");

        let (client_key, jwks) = client_credentials();
        let user = UserId::generate();
        let authenticator = Authenticator::new();

        let settings =
            SettingsDirectory::new(Arc::new(PgTenantSettings::new(store.pool().clone())));
        let flow = Self {
            app: assemble(&store, &kek, &keys, Arc::clone(&audit), settings.clone()),
            store,
            kek,
            tenant,
            settings,
            jar: BTreeMap::new(),
            client_key,
            authenticator,
            user,
            jti: AtomicU32::new(0),
        };
        flow.register_client(&jwks).await;
        flow.register_user().await;
        Some(flow)
    }

    /// The client this flow acts as: `private_key_jwt`, and asking for
    /// `offline_access` so that a redemption earns a refresh token.
    async fn register_client(&self, jwks: &Value) {
        let now = OffsetDateTime::now_utc();
        let client = Client {
            tenant: self.tenant.id.clone(),
            id: ClientId::new(CLIENT),
            registration: ClientRegistration::from_json(
                &serde_json::to_vec(&json!({
                    "client_name": "Billing",
                    "redirect_uris": [REDIRECT],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "scope": "openid offline_access",
                    "token_endpoint_auth_method": "private_key_jwt",
                    "jwks": jwks,
                }))
                .expect("serialise"),
                Capabilities::default(),
            )
            .expect("a valid registration"),
            status: ClientStatus::Active,
            created_at: now,
            updated_at: now,
        };
        self.store
            .scope(self.tenant.id.clone())
            .clients(Capabilities::default())
            .upsert(&client)
            .await
            .expect("store the client");
    }

    /// The person: an account, and the passkey they will sign in with.
    async fn register_user(&self) {
        let now = OffsetDateTime::now_utc();
        PgUserRepository::new(
            self.store.pool().clone(),
            self.tenant.id.clone(),
            Arc::clone(&self.kek),
        )
        .upsert(&User {
            tenant: self.tenant.id.clone(),
            id: self.user,
            username: self.user.as_uuid().to_string(),
            email: None,
            email_verified: false,
            status: UserStatus::Active,
            claims: ClaimSet::default(),
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("store the user");

        PgPasskeyRepository::new(self.store.pool().clone(), self.tenant.id.clone())
            .register(&NewPasskey {
                user: self.user,
                credential_id: self.authenticator.credential_id.clone(),
                public_key: self.authenticator.cose_key(),
                sign_count: 0,
                aaguid: None,
                backup_eligible: false,
                backup_state: false,
                user_verified: true,
                rp_id: HOST.to_owned(),
                label: Some("a test authenticator".to_owned()),
            })
            .await
            .expect("enrol the passkey");
    }

    fn prefix(&self) -> String {
        format!("/t/{}", self.tenant.id.as_str())
    }

    /// A `jti` nothing else in this flow has used: RFC 9449 §11.1 makes a
    /// proof single-use, and the replay guard here is the real one.
    fn next_jti(&self) -> String {
        format!("proof-{}", self.jti.fetch_add(1, Ordering::Relaxed))
    }

    /// Sends one request through the assembled application.
    ///
    /// The cookie jar is applied on the way out and updated on the way back,
    /// because the two-credential rule on an interaction (the id in the path
    /// and the id in the `__Host-` cookie) is exactly the sort of thing a test
    /// that forged its own cookies would not really exercise.
    async fn send(&mut self, mut request: Request<Body>) -> Reply {
        if !self.jar.is_empty() {
            let cookies = self
                .jar
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; ");
            request.headers_mut().insert(
                header::COOKIE,
                cookies.parse().expect("a cookie header value"),
            );
        }
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the application answers");
        let status = response.status();
        let headers = response.headers().clone();
        for value in headers.get_all(header::SET_COOKIE) {
            let Ok(raw) = value.to_str() else { continue };
            let Some((pair, _)) = raw.split_once(';') else {
                continue;
            };
            if let Some((name, value)) = pair.split_once('=') {
                self.jar
                    .insert(name.trim().to_owned(), value.trim().to_owned());
            }
        }
        let body = axum::body::to_bytes(response.into_body(), 256 * 1024)
            .await
            .expect("a body")
            .to_vec();
        Reply {
            status,
            headers,
            body,
        }
    }

    async fn get(&mut self, path: &str) -> Reply {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header(header::HOST, HOST)
            .body(Body::empty())
            .expect("a request");
        self.send(request).await
    }

    async fn post_form(&mut self, path: &str, pairs: &[(&str, &str)], dpop: Option<&str>) -> Reply {
        let mut encoder = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in pairs {
            encoder.append_pair(key, value);
        }
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(proof) = dpop {
            builder = builder.header(asterius_server::http::dpop::HEADER, proof);
        }
        let request = builder
            .body(Body::from(encoder.finish()))
            .expect("a request");
        self.send(request).await
    }

    async fn post_json(&mut self, path: &str, body: &Value) -> Reply {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("a request");
        self.send(request).await
    }

    /// RFC 9126 §2: pushes the request, pinned to `key`, and returns the
    /// reference the client is handed.
    ///
    /// The proof is on the push as well as on the redemption because that is
    /// the shape `ast-36g` was found in: pinning through the `DPoP` header of
    /// a push is what the conformance suite does, and it went to a different
    /// column from the one the code issuer reads.
    async fn push(&mut self, key: &ProofKey) -> String {
        self.push_with(key, &[]).await.request_uri()
    }

    /// The push itself, with whatever `extra` parameters a test is about, and
    /// the raw reply — a refused push is a scenario here, not an accident.
    ///
    /// `extra` is appended to the form, so a test that needs `claims`,
    /// `acr_values` or `resource` sends them the way a client does: through the
    /// pushed request, where the validator sees them and the store keeps them.
    async fn push_with(&mut self, key: &ProofKey, extra: &[(&str, &str)]) -> Reply {
        self.push_as(CLIENT, None, "openid offline_access", key, extra)
            .await
    }

    /// The same push, made by whichever client holds `signing_key`.
    ///
    /// `None` is this flow's own client. `scope` is a parameter rather than a
    /// constant because a second client is registered for a smaller set, and a
    /// push asking for a scope its client is not registered for is refused
    /// before any of this reaches `/authorize` (RFC 9126 §2.1).
    async fn push_as(
        &mut self,
        client_id: &str,
        signing_key: Option<&SigningKey>,
        scope: &str,
        key: &ProofKey,
        extra: &[(&str, &str)],
    ) -> Reply {
        let url = Endpoint::PushedAuthorizationRequest.url(&self.tenant.issuer);
        let proof = key.proof("POST", &url, &self.next_jti());
        self.push_proved(client_id, signing_key, scope, Some(&proof), extra)
            .await
    }

    /// This flow's own push with **no** `DPoP` header at all.
    ///
    /// RFC 9449 §10.1's other spelling: a client that cannot attach a proof to
    /// the push names the key it will redeem under in `dpop_jkt`, and that
    /// parameter is then the whole pin. A test that always sent a proof would
    /// never find out whether the parameter alone reaches the code.
    async fn push_unproved(&mut self, extra: &[(&str, &str)]) -> Reply {
        self.push_proved(CLIENT, None, "openid offline_access", None, extra)
            .await
    }

    /// The form every push sends, with whatever proof the caller has.
    async fn push_proved(
        &mut self,
        client_id: &str,
        signing_key: Option<&SigningKey>,
        scope: &str,
        proof: Option<&str>,
        extra: &[(&str, &str)],
    ) -> Reply {
        let path = format!(
            "{}{}",
            self.prefix(),
            Endpoint::PushedAuthorizationRequest.path()
        );
        // A fresh `jti` per push: RFC 7523 §3 item 7 makes a client assertion
        // single-use and the replay guard here is the real one, so a test that
        // pushes twice must not present one assertion twice.
        let assertion = self.assertion_for(
            client_id,
            signing_key,
            &format!("assertion-par-{}", self.next_jti()),
        );
        let mut pairs = vec![
            ("client_id", client_id),
            ("client_assertion_type", CLIENT_ASSERTION_TYPE),
            ("client_assertion", assertion.as_str()),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT),
            ("scope", scope),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("state", STATE),
            ("nonce", NONCE),
        ];
        pairs.extend_from_slice(extra);
        self.post_form(&path, &pairs, proof).await
    }

    /// Registers a resource server for this tenant (RFC 8707).
    ///
    /// The administrative API for this is follow-up work, so the registry is
    /// written through its repository — which is what an operator's SQL does
    /// today and what the token endpoint reads.
    async fn register_resource_server(&self, identifier: &str, scopes: Option<&[&str]>) {
        asterius_store_pg::PgResourceServers::new(
            self.store.pool().clone(),
            self.tenant.id.clone(),
        )
        .register(&asterius_domain::ResourceServer {
            identifier: asterius_domain::ResourceIdentifier::parse(identifier)
                .expect("a resource indicator"),
            scopes: scopes.map(|s| s.iter().map(|s| (*s).to_owned()).collect()),
            default_token_lifetime: None,
        })
        .await
        .expect("register the resource server");
    }

    /// Withdraws one, which is how a tenant ends up with no default audience.
    async fn withdraw_resource_server(&self, identifier: &str) {
        assert!(
            asterius_store_pg::PgResourceServers::new(
                self.store.pool().clone(),
                self.tenant.id.clone(),
            )
            .withdraw(identifier)
            .await
            .expect("withdraw the resource server"),
            "there was no resource server to withdraw: {identifier}"
        );
    }

    /// Puts `allowed` on the client's own resource allow-list.
    ///
    /// Not registration metadata (RFC 7591 has no such member): it is policy,
    /// written beside the registration, so it is set on the stored client.
    /// Registers an authorization details type for this tenant (RFC 9396
    /// §2.1).
    ///
    /// The administrative API for this is follow-up work, so the registry is
    /// written through its repository — which is what an operator's SQL does
    /// today and what the pushed request endpoint reads.
    async fn register_authorization_details_type(&self, name: &str, schema: &Value) {
        asterius_store_pg::PgAuthorizationDetailsTypes::new(
            self.store.pool().clone(),
            self.tenant.id.clone(),
        )
        .register(
            &asterius_domain::AuthorizationDetailsType {
                name: name.to_owned(),
                schema: asterius_domain::JsonSchema::parse(schema).expect("a supported schema"),
                consent_template: Some("Initiate a payment".to_owned()),
            },
            schema,
        )
        .await
        .expect("register the authorization details type");
    }

    /// RFC 9396 §9.2: the types this client is registered to ask for.
    async fn allow_client_detail_types(&self, allowed: &[&str]) {
        let scope = self.store.scope(self.tenant.id.clone());
        let clients = scope.clients(Capabilities::default());
        let mut client = asterius_domain::ClientRepository::find(&clients, &ClientId::new(CLIENT))
            .await
            .expect("read the client")
            .expect("the client is registered");
        client.registration.authorization_details_types =
            allowed.iter().map(|t| (*t).to_owned()).collect();
        clients.upsert(&client).await.expect("store the client");
    }

    async fn allow_client_resources(&self, allowed: &[&str]) {
        let scope = self.store.scope(self.tenant.id.clone());
        let clients = scope.clients(Capabilities::default());
        let mut client = asterius_domain::ClientRepository::find(&clients, &ClientId::new(CLIENT))
            .await
            .expect("read the client")
            .expect("the client is registered");
        client.registration.resources = allowed.iter().map(|r| (*r).to_owned()).collect();
        clients.upsert(&client).await.expect("store the client");
    }

    /// The raw reply to an authorization request.
    ///
    /// Separate from [`Flow::authorize`] because an interaction is not the
    /// only lawful answer: a `prompt=none` request that cannot be served is
    /// refused straight to the client (OIDC Core §3.1.2.6), and a request the
    /// session already covers is answered without a page (`ast-ovr`). A caller
    /// that wants the interaction says so by asking for it.
    async fn authorize_raw(&mut self, request_uri: &str) -> Reply {
        self.authorize_raw_as(CLIENT, request_uri).await
    }

    /// The same arrival, under whichever client pushed the request.
    ///
    /// RFC 9126 §4: the `client_id` in the URL is checked against the one the
    /// request was pushed by, so the two travel together.
    async fn authorize_raw_as(&mut self, client_id: &str, request_uri: &str) -> Reply {
        let path = format!(
            "{}{}?client_id={client_id}&request_uri={}",
            self.prefix(),
            Endpoint::Authorization.path(),
            url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect::<String>()
        );
        self.get(&path).await
    }

    /// OIDC Core §3.1.2.1: the browser arrives at the authorization endpoint
    /// carrying nothing but the reference, and is sent into an interaction.
    async fn authorize(&mut self, request_uri: &str) -> String {
        self.authorize_as(CLIENT, request_uri).await
    }

    /// The same, under whichever client pushed the request.
    async fn authorize_as(&mut self, client_id: &str, request_uri: &str) -> String {
        let started = self.authorize_raw_as(client_id, request_uri).await;
        assert_eq!(
            started.status,
            StatusCode::SEE_OTHER,
            "the authorization request did not start an interaction: {}",
            started.text()
        );
        let interaction = started.location();
        // `ast-295`: the URL handed to the browser carries the mount prefix,
        // or the next request lands outside the tenant.
        assert!(
            interaction.starts_with(&self.prefix()),
            "the interaction URL dropped the tenant prefix: {interaction}"
        );
        interaction
    }

    /// The login page, and a passkey assertion against the challenge it drew.
    async fn sign_in(&mut self, interaction: &str) {
        let login = self.get(interaction).await;
        assert_eq!(login.status, StatusCode::OK, "{}", login.text());
        let csrf = csrf_from(&login.text());

        let options = self
            .post_json(
                &format!("{interaction}/passkey/options"),
                &json!({ "csrf": csrf }),
            )
            .await;
        assert_eq!(options.status, StatusCode::OK, "{}", options.text());
        let challenge = B64
            .decode(
                options.json()["challenge"]
                    .as_str()
                    .expect("the options carry a challenge"),
            )
            .expect("the challenge is base64url");

        let data = Authenticator::authenticator_data(HOST, UP | UV, 1);
        let client = client_data(&challenge);
        let signature = self.authenticator.sign(&data, &client);
        let raw_id = B64.encode(&self.authenticator.credential_id);
        let handle = B64.encode(self.user.as_bytes());
        let signed_in = self
            .post_json(
                &format!("{interaction}/passkey/finish"),
                &json!({
                    "csrf": csrf,
                    "type": "public-key",
                    "rawId": raw_id,
                    "clientDataJSON": B64.encode(&client),
                    "authenticatorData": B64.encode(&data),
                    "signature": B64.encode(&signature),
                    "userHandle": handle,
                }),
            )
            .await;
        assert_eq!(
            signed_in.status,
            StatusCode::NO_CONTENT,
            "the passkey assertion was refused: {}",
            signed_in.text()
        );
    }

    /// The consent screen, approved in full, and the code it redirects with.
    async fn consent(&mut self, interaction: &str) -> String {
        let consent = self.get(interaction).await;
        assert_eq!(consent.status, StatusCode::OK, "{}", consent.text());
        let html = consent.text();
        // OIDC Core §11: the screen has to say that "later, without you" is
        // what is being asked for, or the grant that follows records a consent
        // nobody gave.
        assert!(
            html.contains("offline_access") || html.contains("when you are not"),
            "the consent screen did not mention offline access:\n{html}"
        );
        // `ast-bo5`: the sign-in above was a passkey ceremony, where nobody
        // typed a name. The screen still has to say whose account is about to
        // be granted, or a person on a shared machine reads "Signed in as ."
        assert!(
            html.contains(&format!("Signed in as {}.", self.user.as_uuid())),
            "the consent screen did not name who signed in:\n{html}"
        );
        let csrf = csrf_from(&html);
        let decided = self
            .post_form(
                interaction,
                &[
                    ("csrf", &csrf),
                    ("decision", "allow"),
                    ("scope", "openid"),
                    ("scope", "offline_access"),
                ],
                None,
            )
            .await;
        assert_eq!(
            decided.status,
            StatusCode::SEE_OTHER,
            "consent did not produce an authorization response: {}",
            decided.text()
        );
        let back = decided.location();
        assert!(
            back.starts_with(REDIRECT),
            "the browser was sent somewhere else: {back}"
        );
        // RFC 6749 §4.1.2: `state` comes back as it was sent, which is what
        // the client matches against its own request.
        assert_eq!(parameter(&back, "state").as_deref(), Some(STATE));
        parameter(&back, "code").expect("RFC 6749 §4.1.2 requires a code")
    }

    /// One token request, authenticated as this client and proved under `key`.
    async fn token(&mut self, key: &ProofKey, jti: &str, pairs: &[(&str, &str)]) -> Reply {
        self.token_as(CLIENT, None, key, jti, pairs).await
    }

    /// The same request, made by whichever client holds `signing_key`.
    ///
    /// `None` is this flow's own client. The parameter exists for the
    /// `client_credentials` grant, which is asked for by a client that reaches
    /// no authorization endpoint at all and so cannot be this one.
    async fn token_as(
        &mut self,
        client_id: &str,
        signing_key: Option<&SigningKey>,
        key: &ProofKey,
        jti: &str,
        pairs: &[(&str, &str)],
    ) -> Reply {
        let url = Endpoint::Token.url(&self.tenant.issuer);
        let path = format!("{}{}", self.prefix(), Endpoint::Token.path());
        let assertion = self.assertion_for(client_id, signing_key, jti);
        let proof = key.proof("POST", &url, &self.next_jti());
        let mut form = pairs.to_vec();
        form.push(("client_id", client_id));
        form.push(("client_assertion_type", CLIENT_ASSERTION_TYPE));
        form.push(("client_assertion", &assertion));
        self.post_form(&path, &form, Some(&proof)).await
    }

    /// A machine client: `client_credentials` and nothing else, no redirect
    /// URI, no response type (RFC 7591 §2.1's table). It never reaches the
    /// authorization endpoint, because there is no user for it to send there.
    async fn register_service_client(&self) -> SigningKey {
        let (key, jwks) = client_credentials();
        let now = OffsetDateTime::now_utc();
        let client = Client {
            tenant: self.tenant.id.clone(),
            id: ClientId::new(SERVICE_CLIENT),
            registration: ClientRegistration::from_json(
                &serde_json::to_vec(&json!({
                    "client_name": "Ledger",
                    "grant_types": ["client_credentials"],
                    "response_types": [],
                    "scope": "ledger.read openid",
                    "token_endpoint_auth_method": "private_key_jwt",
                    "jwks": jwks,
                }))
                .expect("serialise"),
                Capabilities::default(),
            )
            .expect("a valid machine registration"),
            status: ClientStatus::Active,
            created_at: now,
            updated_at: now,
        };
        self.store
            .scope(self.tenant.id.clone())
            .clients(Capabilities::default())
            .upsert(&client)
            .await
            .expect("store the service client");
        key
    }

    /// One revocation request (RFC 7009 §2.1), authenticated as this client.
    ///
    /// No DPoP proof: nothing is issued here, so there is no key to bind, and
    /// a client that had to prove one to hand a token back would be unable to
    /// revoke a credential whose key it has already thrown away.
    async fn revoke(&mut self, jti: &str, pairs: &[(&str, &str)]) -> Reply {
        self.revoke_as(CLIENT, None, jti, pairs).await
    }

    /// The same request, made by whichever client `key` belongs to.
    ///
    /// `None` is this flow's own client. The parameter exists for RFC 7009
    /// §2.2's rule — a client may not revoke another client's token — which
    /// cannot be tested with one registration.
    async fn revoke_as(
        &mut self,
        client_id: &str,
        key: Option<&SigningKey>,
        jti: &str,
        pairs: &[(&str, &str)],
    ) -> Reply {
        let path = format!("{}{}", self.prefix(), Endpoint::Revocation.path());
        let assertion = self.assertion_for(client_id, key, jti);
        let mut form = pairs.to_vec();
        form.push(("client_id", client_id));
        form.push(("client_assertion_type", CLIENT_ASSERTION_TYPE));
        form.push(("client_assertion", &assertion));
        self.post_form(&path, &form, None).await
    }

    /// One UserInfo request, presenting `access_token` under the key it is
    /// bound to.
    ///
    /// RFC 9449 §4.3 item 12: at a protected resource the proof carries `ath`
    /// over the token that arrived, so this is the request a well-behaved
    /// client makes and the one the revocation test needs to fail afterwards.
    async fn userinfo(&mut self, key: &ProofKey, access_token: &str) -> Reply {
        let url = Endpoint::UserInfo.url(&self.tenant.issuer);
        let path = format!("{}{}", self.prefix(), Endpoint::UserInfo.path());
        let proof = key.proof_over("GET", &url, &self.next_jti(), Some(access_token));
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header(header::HOST, HOST)
            .header(header::AUTHORIZATION, format!("DPoP {access_token}"))
            .header(asterius_server::http::dpop::HEADER, proof)
            .body(Body::empty())
            .expect("a request");
        self.send(request).await
    }

    /// A second registered client, with a key of its own.
    ///
    /// It asks for nothing and is never authorized: its only job is to
    /// authenticate at `/revoke` and be told, in the same words as everybody
    /// else, that nothing happened.
    async fn register_other_client(&self) -> SigningKey {
        let (key, jwks) = client_credentials();
        let now = OffsetDateTime::now_utc();
        let client = Client {
            tenant: self.tenant.id.clone(),
            id: ClientId::new(OTHER_CLIENT),
            registration: ClientRegistration::from_json(
                &serde_json::to_vec(&json!({
                    "client_name": "Reporting",
                    "redirect_uris": [REDIRECT],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "scope": "openid",
                    "token_endpoint_auth_method": "private_key_jwt",
                    "jwks": jwks,
                }))
                .expect("serialise"),
                Capabilities::default(),
            )
            .expect("a valid registration"),
            status: ClientStatus::Active,
            created_at: now,
            updated_at: now,
        };
        self.store
            .scope(self.tenant.id.clone())
            .clients(Capabilities::default())
            .upsert(&client)
            .await
            .expect("store the second client");
        key
    }

    /// A `private_key_jwt` assertion for a client (OIDC Core §9).
    ///
    /// `key` is `None` for this flow's own client.
    fn assertion_for(&self, client_id: &str, key: Option<&SigningKey>, jti: &str) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = json!({
            "iss": client_id,
            "sub": client_id,
            "aud": self.tenant.issuer.as_str(),
            "jti": jti,
            "iat": now,
            "exp": now + 60,
        });
        jws::sign(
            key.unwrap_or(&self.client_key),
            &Kid::new(CLIENT_KID),
            "JWT",
            &claims,
        )
        .expect("a signed assertion")
        .as_str()
        .to_owned()
    }

    /// Writes this tenant's lifetimes, the way the admin API writes them, and
    /// drops the cache in front of them so the next request reads the row.
    async fn set_lifetimes(
        &self,
        authorization_code: time::Duration,
        access_token: time::Duration,
    ) {
        let settings = TenantSettings::validated(BTreeSet::new(), authorization_code, access_token)
            .expect("lifetimes within the profile's caps");
        PgTenantSettings::new(self.store.pool().clone())
            .save(&self.tenant.id, &settings)
            .await
            .expect("store the tenant's settings");
        self.settings.invalidate();
    }

    /// The stored binding of a code this flow was just handed.
    ///
    /// Read through the repository port rather than by a query of its own, and
    /// it spends the code: that is what `redeem` is, and a test that wanted the
    /// row without spending it would be reaching past the port.
    async fn spend(&self, code: &str, now: OffsetDateTime) -> asterius_domain::CodeBinding {
        let digest =
            asterius_oidc::code::digest_of(code).expect("a code this server has just issued");
        match self
            .store
            .scope(self.tenant.id.clone())
            .codes()
            .redeem(&digest, now)
            .await
            .expect("read the stored code")
        {
            Redemption::Redeemed(binding) => *binding,
            other => panic!("the code was not redeemable: {other:?}"),
        }
    }

    async fn tear_down(self) {
        PgTenantRepository::new(self.store.pool().clone(), self.kek)
            .delete(&self.tenant.id)
            .await
            .expect("delete the tenant");
    }
}

/// The client's signing key, and the JWK Set its registration carries.
fn client_credentials() -> (SigningKey, Value) {
    let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("a generated key");
    let mut jwk = key.public_jwk().expect("a public JWK");
    jwk["kid"] = json!(CLIENT_KID);
    (key, json!({ "keys": [jwk] }))
}

/// Assembles the application the binary assembles.
///
/// Deliberately through `protocol::routes` and `server::app` rather than
/// through a router built here: what this file is for is the wiring, and a
/// second assembly could be wired correctly while the real one is not.
fn assemble(
    store: &Store,
    kek: &Arc<dyn Kek>,
    keys: &TenantKeyStore,
    audit: Arc<PgAuditSink>,
    settings: SettingsDirectory,
) -> Router {
    let config = ServerConfig {
        bind: "127.0.0.1:0".parse().expect("a literal address"),
        mode: TransportMode::BehindProxy,
        tls: None,
        trusted_proxies: Vec::new(),
        request_body_limit: 64 * 1024,
        request_timeout: std::time::Duration::from_secs(30),
    };

    let key_store: Arc<dyn asterius_domain::KeyStore> = Arc::new(keys.clone());
    let signer: Arc<dyn asterius_domain::keys::Signer> = Arc::new(CachedSigner::new(
        keys.clone(),
        Arc::new(asterius_domain::ports::SystemClock),
    ));
    let outbound: Arc<dyn asterius_domain::ports::JwksFetcher> = Arc::new(NoFetching);
    let replay: Arc<dyn asterius_domain::ReplayGuard> =
        Arc::new(PgReplayGuard::new(store.pool().clone()));
    let authenticator = Arc::new(
        asterius_server::client_auth::ClientAuthenticator::new(
            Arc::new(asterius_jose::client_keys::ClientKeyCache::new(Arc::clone(
                &outbound,
            ))),
            Arc::clone(&replay),
        )
        .expect("a client authenticator"),
    );
    let dpop = Arc::new(
        DpopEndpoint::for_capabilities(Arc::clone(&replay), &Capabilities::default(), None)
            .expect("a DPoP endpoint"),
    );

    let routes = protocol::routes(ProtocolState {
        keys: Arc::clone(&key_store),
        capabilities: Capabilities::default(),
        // The real repository, as the binary wires it: a tenant that has
        // never expressed an opinion reads back the defaults, and one that has
        // gets what it asked for (`ast-f7m.4`, `ast-5c6`).
        tenant_settings: Some(settings.clone()),
        clients: Some(Arc::new(ClientEndpoints {
            initial_access_tokens: None,
            authenticator,
            store: store.clone(),
            keys: key_store,
            capabilities: Capabilities::default(),
            par_lifetime: time::Duration::seconds(90),
            tenant_settings: Some(settings),
            // The deployment fallback. Every test here that cares about a
            // lifetime writes the tenant a setting instead (`ast-5c6`).
            lifetimes: asterius_domain::TokenLifetimes::default(),
            kek: Arc::clone(kek),
            registration: RegistrationPolicy::Closed,
            outbound,
            audit,
            session_lifetimes: Lifetimes::default().clamped(),
            argon2: Some(Argon2Parameters::default()),
            login_limits: generous_login_limits(),
            endpoint_limits: generous_endpoint_limits(),
            signer,
            dpop,
        })),
    });

    let directory = TenantDirectory::new(Arc::new(PgTenantRepository::new(
        store.pool().clone(),
        Arc::clone(kek),
    )));
    app(routes, TenantState::new(directory, &config), None, &config)
}

/// Never called: the client's keys are inline in its registration. Loud rather
/// than silent, so a test that reached the network fails instead of hanging.
#[derive(Debug)]
struct NoFetching;

#[async_trait::async_trait]
impl asterius_domain::ports::JwksFetcher for NoFetching {
    async fn fetch(&self, _url: &str) -> Result<Vec<u8>, asterius_domain::DomainError> {
        panic!("a test reached the network; the client's keys are inline");
    }
}

fn generous_login_limits() -> LoginLimits {
    let limit = RateLimit {
        max: 1_000,
        window: time::Duration::minutes(15),
    };
    LoginLimits {
        per_address: limit,
        per_account: limit,
    }
}

fn generous_endpoint_limits() -> EndpointLimits {
    let limit = EndpointLimit {
        per_address: RateLimit {
            max: 1_000,
            window: time::Duration::minutes(15),
        },
        per_client: None,
    };
    EndpointLimits {
        registration: limit,
        client_configuration: limit,
        par: limit,
        token: limit,
        userinfo: limit,
    }
}

/// The value of the `csrf` field on the form this server just rendered.
///
/// Read out of the HTML rather than out of the store, because that is the only
/// copy a browser has: a test that took the token from the database would pass
/// against a page that never rendered one.
fn csrf_from(html: &str) -> String {
    let marker = r#"name="csrf" value=""#;
    let start = html
        .find(marker)
        .unwrap_or_else(|| panic!("no csrf field in the rendered page:\n{html}"))
        + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("the csrf value is quoted");
    rest[..end].to_owned()
}

/// One query parameter of a URL.
fn parameter(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

// ---- the chain -----------------------------------------------------------

/// **The scenario the conformance suite runs, in one test** (`ast-ixl`).
///
/// Push, authorize, sign in with a passkey, consent, redeem the code, then
/// refresh — every step an HTTP request against the assembled application.
///
/// The last step is the one `ast-1h1` was about: the refresh is presented
/// under a **fresh** DPoP key, which is what the OIDF module does and what
/// every fixture-seeded test avoided by re-using the key it had seeded. With
/// `bind_to_dpop_key` back on, that request is `invalid_grant` and this test
/// fails at the last assertion — which is how it was checked to be about
/// something.
#[tokio::test]
async fn a_push_becomes_a_code_becomes_a_token_becomes_a_refresh() {
    // Arrange: a tenant, a client, a person with a passkey — and the DPoP key
    // the client will pin its request to and redeem the code under.
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let redemption_key = ProofKey::generate();

    // Act: the browser half of the flow, each step an HTTP request.
    let request_uri = flow.push(&redemption_key).await;
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let code = flow.consent(&interaction).await;

    // Act: RFC 6749 §4.1.3 — redeem the code under the pinned key.
    let redeemed = flow
        .token(
            &redemption_key,
            "assertion-code",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    assert_eq!(
        redeemed.status,
        StatusCode::OK,
        "the code was refused: {}",
        redeemed.text()
    );
    let tokens = redeemed.json();
    assert_eq!(tokens["token_type"], "DPoP", "{tokens}");
    assert!(tokens["access_token"].is_string(), "{tokens}");
    assert!(tokens["id_token"].is_string(), "{tokens}");
    // OIDC Core §11, and the half of `ast-1h1` no test asserted: a grant
    // carrying `offline_access` earns a refresh token here, or the step below
    // has nothing to present.
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("an offline_access grant earns a refresh token")
        .to_owned();

    // Act: RFC 6749 §6, with a **different** DPoP key. This is `ast-1h1`: the
    // conformance suite generates a fresh key for the refresh, and every
    // integration test presented the seeded one.
    let refresh_key = ProofKey::generate();
    assert_ne!(
        refresh_key.thumbprint().as_str(),
        redemption_key.thumbprint().as_str(),
        "the refresh must be proved with a key the redemption did not use"
    );
    let refreshed = flow
        .token(
            &refresh_key,
            "assertion-refresh",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
            ],
        )
        .await;

    // Assert: RFC 6749 §5.1, and the status the conformance suite checks.
    assert_eq!(
        refreshed.status,
        StatusCode::OK,
        "the first refresh was refused: {}",
        refreshed.text()
    );
    let refreshed = refreshed.json();
    assert!(refreshed["access_token"].is_string(), "{refreshed}");
    // RFC 9449 §5: the response is still a DPoP one, bound to the key that
    // proved *this* request rather than the one that redeemed the code.
    assert_eq!(refreshed["token_type"], "DPoP", "{refreshed}");

    flow.tear_down().await;
}

/// **A client with no user gets a token for itself, and it is not a user's**
/// (`ast-a05.8`).
///
/// The whole `client_credentials` story against the assembled application: a
/// machine client authenticates with `private_key_jwt`, proves a DPoP key, and
/// is handed an access token — with no refresh token (RFC 6749 §4.4.3), no ID
/// token, and `sub` equal to its own `client_id` (RFC 9068 §2.2).
///
/// Then it presents that token at UserInfo and is **refused**, which is the
/// decision this test exists to pin. OIDC Core §5.3.2 requires UserInfo to
/// answer with the `sub` of an end user, and a client-only token has none: the
/// grant behind it names no person. So the token does not carry `openid` —
/// this grant excludes it — and the refusal is the ordinary insufficient-scope
/// one a client can read, rather than a server-side inconsistency discovered
/// halfway through resolving claims about nobody.
#[tokio::test]
async fn a_machine_client_gets_a_token_for_itself_and_is_refused_at_userinfo() {
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    // Arrange
    let service_key = flow.register_service_client().await;
    let key = ProofKey::generate();

    // Act
    let issued = flow
        .token_as(
            SERVICE_CLIENT,
            Some(&service_key),
            &key,
            "assertion-client-credentials",
            &[("grant_type", "client_credentials")],
        )
        .await;

    // Assert: the response
    assert_eq!(
        issued.status,
        StatusCode::OK,
        "the client credentials request was refused: {}",
        issued.text()
    );
    let body = issued.json();
    assert_eq!(body["token_type"], "DPoP", "{body}");
    assert!(
        body.get("refresh_token").is_none(),
        "RFC 6749 §4.4.3: no refresh token: {body}"
    );
    assert!(
        body.get("id_token").is_none(),
        "there is no user to assert an authentication about: {body}"
    );
    assert_eq!(body["scope"], "ledger.read", "{body}");

    // Assert: the token
    let access_token = body["access_token"].as_str().expect("an access token");
    let claims = claims_of(access_token);
    assert_eq!(claims["sub"], SERVICE_CLIENT, "RFC 9068 §2.2: {claims}");
    assert_eq!(claims["client_id"], SERVICE_CLIENT, "{claims}");
    assert_eq!(claims["aud"], RESOURCE, "{claims}");
    assert_eq!(
        claims["cnf"]["jkt"],
        json!(key.thumbprint().as_str()),
        "RFC 9449 §6.1: the token is bound to the key that proved this request"
    );

    // Assert: it is not a credential for a person
    let userinfo = flow.userinfo(&key, access_token).await;
    assert_eq!(
        userinfo.status,
        StatusCode::FORBIDDEN,
        "a client-only token was accepted at UserInfo: {}",
        userinfo.text()
    );

    flow.tear_down().await;
}

/// **A tenant's authorization-code lifetime is the one issuance uses**
/// (`ast-5c6`).
///
/// The setting is written the way the admin API writes it, the flow runs to a
/// code, and the stored binding is read back through the repository. Before the
/// wiring existed this failed with the process-wide sixty seconds, which is how
/// it was checked to be about something.
#[tokio::test]
async fn a_code_expires_when_the_tenants_setting_says_so() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    flow.set_lifetimes(time::Duration::seconds(30), time::Duration::minutes(2))
        .await;
    let key = ProofKey::generate();

    // Act
    let request_uri = flow.push(&key).await;
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let before = OffsetDateTime::now_utc();
    let code = flow.consent(&interaction).await;
    let binding = flow.spend(&code, before).await;

    // Assert: the code was issued at some instant at or after `before`, so the
    // window is bounded below by the setting and above by it plus the time the
    // consent request took.
    let lifetime = binding.expires_at - before;
    assert!(
        lifetime >= time::Duration::seconds(30) && lifetime < time::Duration::seconds(40),
        "the code did not follow the tenant's 30-second setting: {lifetime}"
    );

    flow.tear_down().await;
}

/// **A tenant's access-token lifetime is the one issuance uses** (`ast-5c6`).
///
/// Both halves are asserted: `expires_in`, which is what a client reads, and
/// the `exp` of the token itself, which is what a resource server enforces. A
/// response that said one thing and signed another would be the worse bug.
#[tokio::test]
async fn an_access_token_expires_when_the_tenants_setting_says_so() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    flow.set_lifetimes(time::Duration::seconds(60), time::Duration::minutes(2))
        .await;
    let key = ProofKey::generate();
    let request_uri = flow.push(&key).await;
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let code = flow.consent(&interaction).await;

    // Act
    let redeemed = flow
        .token(
            &key,
            "assertion-code",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;

    // Assert
    assert_eq!(
        redeemed.status,
        StatusCode::OK,
        "the code was refused: {}",
        redeemed.text()
    );
    let tokens = redeemed.json();
    assert_eq!(tokens["expires_in"], 120, "{tokens}");
    let claims = claims_of(
        tokens["access_token"]
            .as_str()
            .expect("RFC 6749 §5.1 requires an access token"),
    );
    let exp = claims["exp"].as_i64().expect("RFC 9068 §2.2 requires exp");
    let iat = claims["iat"].as_i64().expect("RFC 9068 §2.2 requires iat");
    assert_eq!(exp - iat, 120, "the signed token disagrees with expires_in");

    flow.tear_down().await;
}

/// **An essential `acr`, over the wire, from the push to the ID token**
/// (`ast-2vk.7`, absorbing `ast-0zg`).
///
/// OIDC Core §5.5.1.1: when `acr` is requested as an Essential Claim through
/// `claims`, the response "MUST return an `acr` Claim Value that matches one of
/// the requested values". Nothing in this repository crossed that path: the
/// claims request is serialised at `/par` and parsed back at `/authorize`, and
/// `ast-33b` only ever fixed the *fixture* it was read from. Here the document
/// travels as a client sends it, through the store, into the decision, through
/// a real ES256 passkey ceremony with the UV bit set, and out the other end as
/// a claim.
///
/// The ceremony reaches `urn:asterius:acr:passkey-uv` — the strongest rung of
/// the default ladder — so the requirement is met by the sign-in the flow
/// performs, and the assertion is on the claim rather than on an error.
#[tokio::test]
async fn an_essential_acr_travels_from_the_push_into_the_id_token() {
    // Arrange: a tenant, a client, a person with a UV-capable passkey.
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let key = ProofKey::generate();
    let claims = json!({
        "id_token": {
            "acr": {
                "essential": true,
                "values": [asterius_domain::acr::PASSKEY_USER_VERIFIED],
            }
        }
    })
    .to_string();

    // Act: the browser half, with the essential request on the push.
    let request_uri = flow
        .push_with(&key, &[("claims", &claims)])
        .await
        .request_uri();
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let code = flow.consent(&interaction).await;
    let redeemed = flow
        .token(
            &key,
            "assertion-code",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    assert_eq!(
        redeemed.status,
        StatusCode::OK,
        "the code was refused: {}",
        redeemed.text()
    );

    // Assert: §5.5.1.1's claim, and §2's `amr` beside it.
    let id_token = redeemed.json()["id_token"]
        .as_str()
        .expect("an openid grant earns an ID token")
        .to_owned();
    let claims = claims_of(&id_token);
    assert_eq!(
        claims["acr"],
        json!(asterius_domain::acr::PASSKEY_USER_VERIFIED),
        "OIDC Core §5.5.1.1: the acr must match a requested value: {claims}"
    );
    assert_eq!(
        claims["amr"],
        json!(["swk", "user"]),
        "OIDC Core §2: the methods the authentication used: {claims}"
    );

    flow.tear_down().await;
}

/// The payload of a JWS this server signed, unverified.
///
/// Unverified on purpose: what is under test is a number the server put in the
/// token, and the signature is checked by every other test that presents one.
fn claims_of(jwt: &str) -> Value {
    let payload = jwt.split('.').nth(1).expect("a JWS has three parts");
    serde_json::from_slice(&B64.decode(payload).expect("the payload is base64url"))
        .expect("the payload is JSON")
}

// ---- revocation (RFC 7009) -----------------------------------------------

/// The tokens one full flow produces, so a revocation test starts from a real
/// credential rather than a seeded row.
struct Issued {
    access_token: String,
    refresh_token: String,
    key: ProofKey,
}

/// Push, sign in, consent, redeem: the chain above, condensed, for the tests
/// that are about what happens *after* a token exists.
async fn issue_tokens(flow: &mut Flow) -> Issued {
    let key = ProofKey::generate();
    let request_uri = flow.push(&key).await;
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let code = flow.consent(&interaction).await;
    let redeemed = flow
        .token(
            &key,
            "assertion-code",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    assert_eq!(
        redeemed.status,
        StatusCode::OK,
        "the code was refused: {}",
        redeemed.text()
    );
    let tokens = redeemed.json();
    Issued {
        access_token: tokens["access_token"]
            .as_str()
            .expect("an access token")
            .to_owned(),
        refresh_token: tokens["refresh_token"]
            .as_str()
            .expect("an offline_access grant earns a refresh token")
            .to_owned(),
        key,
    }
}

/// RFC 7009 §2.1: a refresh token handed back is revoked, and §2.2's 200 says
/// so. What proves it is the next refresh — RFC 6749 §5.2's `invalid_grant`,
/// from the endpoint that would have minted a token a moment earlier.
#[tokio::test]
async fn a_revoked_refresh_token_can_no_longer_be_refreshed() {
    // Arrange: a real refresh token, from a real authorization.
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let issued = issue_tokens(&mut flow).await;

    // Act
    let revoked = flow
        .revoke(
            "assertion-revoke",
            &[
                ("token", &issued.refresh_token),
                ("token_type_hint", "refresh_token"),
            ],
        )
        .await;

    // Assert: §2.2 — 200, and nothing in the body for a client to read.
    assert_eq!(
        revoked.status,
        StatusCode::OK,
        "the revocation was refused: {}",
        revoked.text()
    );
    assert!(revoked.body.is_empty(), "{}", revoked.text());

    let refreshed = flow
        .token(
            &ProofKey::generate(),
            "assertion-refresh",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &issued.refresh_token),
            ],
        )
        .await;
    assert_eq!(
        refreshed.status,
        StatusCode::BAD_REQUEST,
        "a revoked refresh token was still redeemable: {}",
        refreshed.text()
    );
    assert_eq!(refreshed.json()["error"], "invalid_grant");

    flow.tear_down().await;
}

/// The same request, made by a client the token was not issued to. RFC 7009
/// §2.2: "the client MUST NOT be able to revoke a token issued to another
/// client" — treated as an invalid token, which is a 200 and no action.
#[tokio::test]
async fn another_clients_refresh_token_is_not_revocable() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let other_key = flow.register_other_client().await;
    let issued = issue_tokens(&mut flow).await;

    // Act: the second client asks for the first client's token.
    let answered = flow
        .revoke_as(
            OTHER_CLIENT,
            Some(&other_key),
            "assertion-revoke-other",
            &[("token", &issued.refresh_token)],
        )
        .await;

    // Assert: indistinguishable from a successful revocation — which is the
    // point, since telling the two apart answers "is this a live token here?"
    // — and the token still works.
    assert_eq!(
        answered.status,
        StatusCode::OK,
        "another client's request should look like every other one: {}",
        answered.text()
    );
    let refreshed = flow
        .token(
            &ProofKey::generate(),
            "assertion-refresh-after",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &issued.refresh_token),
            ],
        )
        .await;
    assert_eq!(
        refreshed.status,
        StatusCode::OK,
        "a client revoked a token it was not issued: {}",
        refreshed.text()
    );

    flow.tear_down().await;
}

/// An access token's `jti` goes on the denylist until its own `exp`, and the
/// one place this server verifies its own access tokens reads it: UserInfo
/// (FAPI 2.0 SP §5.3.4 item 3). Introspection will read the same rows.
#[tokio::test]
async fn a_revoked_access_token_is_refused_at_userinfo() {
    // Arrange: a token that works, so the assertion below is about the
    // revocation rather than about the request.
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let issued = issue_tokens(&mut flow).await;
    let before = flow.userinfo(&issued.key, &issued.access_token).await;
    assert_eq!(
        before.status,
        StatusCode::OK,
        "the access token did not work before it was revoked: {}",
        before.text()
    );

    // Act
    let revoked = flow
        .revoke(
            "assertion-revoke-at",
            &[
                ("token", &issued.access_token),
                ("token_type_hint", "access_token"),
            ],
        )
        .await;
    assert_eq!(
        revoked.status,
        StatusCode::OK,
        "the revocation was refused: {}",
        revoked.text()
    );

    // Assert: RFC 6750 §3.1 — the credential is no longer good for anything.
    let after = flow.userinfo(&issued.key, &issued.access_token).await;
    assert_eq!(
        after.status,
        StatusCode::UNAUTHORIZED,
        "a revoked access token still bought claims: {}",
        after.text()
    );

    flow.tear_down().await;
}

/// §2.1: `token_type_hint` is a hint. A value this server has never heard of
/// does not fail the request — the server "MUST extend its search across all
/// of its supported token types" — and an unknown token is §2.2's 200.
#[tokio::test]
async fn an_unknown_hint_and_an_unknown_token_are_both_a_success() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    // Act
    let answered = flow
        .revoke(
            "assertion-revoke-unknown",
            &[
                ("token", "a-value-this-server-never-issued"),
                ("token_type_hint", "device_code"),
            ],
        )
        .await;

    // Assert
    assert_eq!(
        answered.status,
        StatusCode::OK,
        "an unknown hint or token must not be an error: {}",
        answered.text()
    );

    flow.tear_down().await;
}

/// §2.1 makes `token` REQUIRED, and a request without one is not a request
/// about a token at all — so it is RFC 6749 §5.2's `invalid_request` rather
/// than §2.2's 200.
#[tokio::test]
async fn a_revocation_without_a_token_is_invalid_request() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    // Act
    let answered = flow.revoke("assertion-revoke-empty", &[]).await;

    // Assert
    assert_eq!(
        answered.status,
        StatusCode::BAD_REQUEST,
        "{}",
        answered.text()
    );
    assert_eq!(answered.json()["error"], "invalid_request");

    flow.tear_down().await;
}

/// §2.2.1: `unsupported_token_type` when the presented token's type is one
/// this server cannot revoke. An ID token is signed by this tenant and looks
/// like a credential; it is not one this endpoint withdraws.
#[tokio::test]
async fn an_id_token_presented_for_revocation_is_an_unsupported_token_type() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let key = ProofKey::generate();
    let request_uri = flow.push(&key).await;
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let code = flow.consent(&interaction).await;
    let redeemed = flow
        .token(
            &key,
            "assertion-code",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    let id_token = redeemed.json()["id_token"]
        .as_str()
        .expect("an openid request earns an ID token")
        .to_owned();

    // Act
    let answered = flow
        .revoke("assertion-revoke-id", &[("token", &id_token)])
        .await;

    // Assert
    assert_eq!(
        answered.status,
        StatusCode::BAD_REQUEST,
        "{}",
        answered.text()
    );
    assert_eq!(answered.json()["error"], "unsupported_token_type");

    flow.tear_down().await;
}

// ---- RFC 8707: resource indicators drive `aud` ---------------------------

/// A second API this tenant serves, for the multi-audience and subset cases.
const OTHER_RESOURCE: &str = "https://reports.example/";

/// Drives push, sign-in, consent and redemption, with `push_extra` on the
/// pushed request and `token_extra` on the token request.
async fn redeemed(
    flow: &mut Flow,
    push_extra: &[(&str, &str)],
    token_extra: &[(&str, &str)],
) -> Reply {
    let key = ProofKey::generate();
    let request_uri = flow.push_with(&key, push_extra).await.request_uri();
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let code = flow.consent(&interaction).await;

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
    ];
    form.extend_from_slice(token_extra);
    flow.token(&key, "assertion-code", &form).await
}

/// **RFC 8707 §2 and §2.1**: a `resource` with a fragment, a relative URI, or a
/// value this tenant has not registered is `invalid_target` at the pushed
/// authorization request endpoint — where an authenticated client is still on
/// the connection to be told.
#[tokio::test]
async fn a_bad_resource_is_invalid_target_at_the_pushed_request_endpoint() {
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    // Everything the client asks for below is on its own allow-list, so the
    // only rules left to refuse it are RFC 8707 §2's shape and §3's registry.
    flow.allow_client_resources(&[
        RESOURCE,
        "https://api.example/v1#section",
        "/v1/accounts",
        "https://unregistered.example/",
    ])
    .await;
    let key = ProofKey::generate();

    for wrong in [
        "https://api.example/v1#section",
        "/v1/accounts",
        "https://unregistered.example/",
    ] {
        let pushed = flow.push_with(&key, &[("resource", wrong)]).await;
        assert_eq!(
            pushed.status,
            StatusCode::BAD_REQUEST,
            "the push was accepted with resource {wrong:?}"
        );
        assert_eq!(
            pushed.json()["error"],
            "invalid_target",
            "for resource {wrong:?}: {}",
            pushed.text()
        );
    }

    flow.tear_down().await;
}

/// **RFC 8707 §2.2**: "the requested resources MUST be a subset of the
/// resources authorized" — a token request cannot reach past the authorization
/// request it is redeeming.
#[tokio::test]
async fn a_token_request_naming_a_resource_the_authorization_did_not_is_invalid_target() {
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    flow.register_resource_server(OTHER_RESOURCE, None).await;
    flow.allow_client_resources(&[RESOURCE, OTHER_RESOURCE])
        .await;

    // Authorized for one API; redeemed asking for the other.
    let refused = redeemed(
        &mut flow,
        &[("resource", RESOURCE)],
        &[("resource", OTHER_RESOURCE)],
    )
    .await;

    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "a token was issued for a resource the authorization never named: {}",
        refused.text()
    );
    assert_eq!(
        refused.json()["error"],
        "invalid_target",
        "{}",
        refused.text()
    );

    flow.tear_down().await;
}

/// **RFC 9068 §3**: "the `aud` claim […] SHOULD be the same value as the
/// `resource` parameter in the request", and RFC 8707 §2 lets the AS narrow the
/// scope to what that resource understands.
#[tokio::test]
async fn the_access_token_is_audienced_at_the_requested_resource_with_its_scopes() {
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    // A resource server that understands `openid` and nothing else, so the
    // `offline_access` the grant carries must not reach it.
    flow.register_resource_server(OTHER_RESOURCE, Some(&["openid"]))
        .await;
    flow.allow_client_resources(&[OTHER_RESOURCE]).await;

    let issued = redeemed(
        &mut flow,
        &[("resource", OTHER_RESOURCE)],
        &[("resource", OTHER_RESOURCE)],
    )
    .await;
    assert_eq!(
        issued.status,
        StatusCode::OK,
        "the code was refused: {}",
        issued.text()
    );
    let claims = claims_of(issued.json()["access_token"].as_str().expect("a token"));
    assert_eq!(claims["aud"], json!(OTHER_RESOURCE), "{claims}");
    assert_eq!(
        claims["scope"],
        json!("openid"),
        "the token carried a scope the resource server does not understand: {claims}"
    );

    flow.tear_down().await;
}

/// **RFC 8707 §2**: "Multiple `resource` parameters MAY be used". The policy
/// this server chose is one token with an `aud` array rather than a refusal —
/// and the scopes are the ones *both* resource servers understand, so widening
/// the audience never widens the authority.
#[tokio::test]
async fn two_resources_are_one_token_with_an_array_audience() {
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    flow.register_resource_server(RESOURCE, Some(&["openid", "offline_access"]))
        .await;
    flow.register_resource_server(OTHER_RESOURCE, Some(&["openid"]))
        .await;
    flow.allow_client_resources(&[RESOURCE, OTHER_RESOURCE])
        .await;

    let issued = redeemed(
        &mut flow,
        &[("resource", RESOURCE), ("resource", OTHER_RESOURCE)],
        &[],
    )
    .await;
    assert_eq!(
        issued.status,
        StatusCode::OK,
        "the code was refused: {}",
        issued.text()
    );
    let claims = claims_of(issued.json()["access_token"].as_str().expect("a token"));
    assert_eq!(claims["aud"], json!([RESOURCE, OTHER_RESOURCE]), "{claims}");
    assert_eq!(
        claims["scope"],
        json!("openid"),
        "a two-audience token carried a scope only one of them understands: {claims}"
    );

    flow.tear_down().await;
}

/// **RFC 9068 §2.2 and §3**: `aud` is REQUIRED, so a client that names no
/// `resource` and has no default audience left gets `invalid_target` rather
/// than a token nothing can safely accept.
///
/// The tenant's own default audience is a registered resource server; this
/// withdraws it, which is the only way to have no default at all.
#[tokio::test]
async fn a_client_with_no_resource_and_no_default_audience_gets_no_token() {
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    flow.withdraw_resource_server(RESOURCE).await;

    let refused = redeemed(&mut flow, &[], &[]).await;

    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "an audience-less access token was issued: {}",
        refused.text()
    );
    assert_eq!(
        refused.json()["error"],
        "invalid_target",
        "{}",
        refused.text()
    );

    flow.tear_down().await;
}

/// **RFC 9068 §3**: a client that names no `resource` still gets an
/// audience-bound token — the tenant's registered default, which is what its
/// tokens have always carried.
#[tokio::test]
async fn no_resource_falls_back_to_the_registered_default_audience() {
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let issued = redeemed(&mut flow, &[], &[]).await;
    assert_eq!(
        issued.status,
        StatusCode::OK,
        "the code was refused: {}",
        issued.text()
    );
    let claims = claims_of(issued.json()["access_token"].as_str().expect("a token"));
    assert_eq!(claims["aud"], json!(RESOURCE), "{claims}");

    flow.tear_down().await;
}

// ---- single sign-on (`ast-ovr`) ------------------------------------------

/// The `auth_time` of an ID token this flow has just been issued.
///
/// Read off the token rather than off the session row, because it is the
/// number the client sees and the only one OIDC Core §2 makes a statement
/// about: "the time when the End-User authentication occurred". A second
/// authorization that reused the session must report the same instant, and a
/// second authorization that quietly signed the user in again would not.
async fn auth_time_of(flow: &mut Flow, key: &ProofKey, jti: &str, code: &str) -> i64 {
    let redeemed = flow
        .token(
            key,
            jti,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    assert_eq!(
        redeemed.status,
        StatusCode::OK,
        "the code was refused: {}",
        redeemed.text()
    );
    let id_token = redeemed.json()["id_token"]
        .as_str()
        .expect("an openid grant earns an ID token")
        .to_owned();
    claims_of(&id_token)["auth_time"]
        .as_i64()
        .expect("OIDC Core §2: an ID token from a session carries auth_time")
}

/// Signs this browser in and records a consent, so the tests below start from
/// a returning user rather than from a fresh one.
///
/// Returns the `auth_time` the first authorization reported.
async fn sign_in_and_consent(flow: &mut Flow) -> i64 {
    let key = ProofKey::generate();
    let request_uri = flow.push(&key).await;
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let code = flow.consent(&interaction).await;
    auth_time_of(flow, &key, "assertion-sso-first", &code).await
}

/// **`ast-ovr`**: a user who is signed in and has consented sees nothing at
/// all.
///
/// The whole point of the consent memory (`ast-uwv.3`) and of the decision
/// table (`ast-gxh.8`): the second identical request is answered from the
/// session, so no page is rendered and the browser is sent back to the client
/// with a code. The `auth_time` is what proves the *session* was reused rather
/// than silently replaced — a server that started a new one would report a
/// later instant and OIDC Core §3.1.2.3's `max_age` would mean nothing.
///
/// Before the fix this failed at the interaction: `/authorize` answered
/// `Interaction::Silent` and the interaction still began at `Stage::Login`, so
/// the returning user met a sign-in form.
#[tokio::test]
async fn a_returning_user_is_sent_back_to_the_client_without_a_screen() {
    // Arrange: signed in, and having consented once.
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let first = sign_in_and_consent(&mut flow).await;

    // Act: the same request again, from the same browser.
    let key = ProofKey::generate();
    let request_uri = flow.push(&key).await;
    let started = flow.authorize_raw(&request_uri).await;
    assert_eq!(
        started.status,
        StatusCode::SEE_OTHER,
        "the authorization request did not start: {}",
        started.text()
    );
    let interaction = started.location();
    let answered = flow.get(&interaction).await;

    // Assert: a redirect to the client, not a page.
    assert_eq!(
        answered.status,
        StatusCode::SEE_OTHER,
        "a screen was served to a user who had already decided:\n{}",
        answered.text()
    );
    let back = answered.location();
    assert!(
        back.starts_with(REDIRECT),
        "the browser was sent somewhere else: {back}"
    );
    assert_eq!(parameter(&back, "state").as_deref(), Some(STATE));
    let code = parameter(&back, "code").expect("RFC 6749 §4.1.2 requires a code");

    // Assert: the session was reused, not replaced.
    let second = auth_time_of(&mut flow, &key, "assertion-sso-second", &code).await;
    assert_eq!(
        second, first,
        "OIDC Core §2: a reused session keeps its auth_time"
    );

    flow.tear_down().await;
}

/// A second client, and a request pushed for it by a browser that is already
/// signed in to the first.
///
/// Returns the `auth_time` the first client's ID token reported, the second
/// client's signing key, the DPoP key the push was made under, and the
/// interaction the browser was sent into — everything the assertions below
/// need, so that each test says only what it is about.
async fn meet_a_new_client(
    flow: &mut Flow,
    extra: &[(&str, &str)],
) -> (i64, SigningKey, ProofKey, String) {
    let first = sign_in_and_consent(flow).await;
    let other = flow.register_other_client().await;
    let key = ProofKey::generate();
    let request_uri = flow
        .push_as(OTHER_CLIENT, Some(&other), "openid", &key, extra)
        .await
        .request_uri();
    let interaction = flow.authorize_as(OTHER_CLIENT, &request_uri).await;
    (first, other, key, interaction)
}

/// **`ast-k7f`**: single sign-on is about the *second client*, not about the
/// second visit.
///
/// A user who is signed in and meets a client they have never consented to has
/// one thing left to do — decide — and OIDC Core §3.1.2.1 has nothing that
/// asks them to authenticate again for it: the session is live, it is recent
/// enough, and it is about the right person. Before the fix, `/authorize`
/// answered `Interaction::Consent` and the interaction still began at
/// `Stage::Login`, so every new client cost the user their credentials again.
///
/// The `auth_time` is what proves the session was reused rather than quietly
/// replaced: a server that signed the user in again would report a later
/// instant, and `max_age` would mean nothing across clients.
#[tokio::test]
async fn a_new_client_asks_a_signed_in_user_to_consent_and_not_to_sign_in_again() {
    // Arrange: signed in and consented for one client; a second one asking.
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let (first, other, key, interaction) = meet_a_new_client(&mut flow, &[]).await;

    // Act
    let page = flow.get(&interaction).await;

    // Assert: the consent screen, and no sign-in form.
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let html = page.text();
    assert!(
        !html.contains(r#"id="passkey-signin-button""#),
        "a signed-in user was sent back to the sign-in form by a new client:\n{html}"
    );
    assert!(
        html.contains("Reporting"),
        "the consent screen did not name the client that is asking:\n{html}"
    );
    // `ast-bo5`: the screen has to say whose account is about to be granted,
    // and nobody typed a name on this request at all.
    assert!(
        html.contains(&format!("Signed in as {}.", flow.user.as_uuid())),
        "the consent screen did not name who is signed in:\n{html}"
    );

    // Act: the decision the user does still owe.
    let csrf = csrf_from(&html);
    let decided = flow
        .post_form(
            &interaction,
            &[("csrf", &csrf), ("decision", "allow"), ("scope", "openid")],
            None,
        )
        .await;
    assert_eq!(
        decided.status,
        StatusCode::SEE_OTHER,
        "consent did not produce an authorization response: {}",
        decided.text()
    );
    let back = decided.location();
    assert!(
        back.starts_with(REDIRECT),
        "the browser was sent somewhere else: {back}"
    );
    let code = parameter(&back, "code").expect("RFC 6749 §4.1.2 requires a code");

    // Assert: the session was reused, not replaced.
    let redeemed = flow
        .token_as(
            OTHER_CLIENT,
            Some(&other),
            &key,
            "assertion-sso-new-client",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    assert_eq!(
        redeemed.status,
        StatusCode::OK,
        "the code was refused: {}",
        redeemed.text()
    );
    let claims = claims_of(
        redeemed.json()["id_token"]
            .as_str()
            .expect("an openid grant earns an ID token"),
    );
    assert_eq!(
        claims["auth_time"].as_i64(),
        Some(first),
        "OIDC Core §2: a reused session keeps its auth_time: {claims}"
    );

    flow.tear_down().await;
}

/// **OIDC Core §3.1.2.1**: `prompt=login` is not weakened by a new client.
///
/// The guard on the rule above: the session is live and the client is new, and
/// the request still asked for the user to authenticate again.
#[tokio::test]
async fn a_new_client_asking_prompt_login_still_gets_the_sign_in_form() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let (_, _, _, interaction) = meet_a_new_client(&mut flow, &[("prompt", "login")]).await;

    // Act
    let page = flow.get(&interaction).await;

    // Assert
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let html = page.text();
    assert!(
        html.contains(r#"id="passkey-signin-button""#),
        "prompt=login did not ask the user to authenticate again:\n{html}"
    );

    flow.tear_down().await;
}

/// **OIDC Core §3.1.2.3**: `max_age=0` is not weakened by a new client either.
#[tokio::test]
async fn a_new_client_asking_max_age_zero_still_gets_the_sign_in_form() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let (_, _, _, interaction) = meet_a_new_client(&mut flow, &[("max_age", "0")]).await;

    // Act
    let page = flow.get(&interaction).await;

    // Assert
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let html = page.text();
    assert!(
        html.contains(r#"id="passkey-signin-button""#),
        "max_age=0 did not ask the user to authenticate again:\n{html}"
    );

    flow.tear_down().await;
}

/// **OIDC Core §5.5.1.1**: an essential `acr` the session does not carry sends
/// the user through the step-up, new client or not.
///
/// The session was established by a user-verified passkey, so it carries
/// `urn:asterius:acr:passkey-uv` and satisfies nothing else by name. A client
/// asking for a context this tenant *can* produce and this session has not is
/// `Interaction::StepUp`, which renders the authentication page — the one
/// screen a consent-first shortcut must never skip.
#[tokio::test]
async fn a_new_client_asking_an_unmet_essential_acr_still_gets_the_step_up() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let claims = json!({
        "id_token": {
            "acr": {
                "essential": true,
                "values": [asterius_domain::acr::PASSWORD],
            }
        }
    })
    .to_string();
    let (_, _, _, interaction) = meet_a_new_client(&mut flow, &[("claims", &claims)]).await;

    // Act
    let page = flow.get(&interaction).await;

    // Assert
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let html = page.text();
    assert!(
        html.contains(r#"id="passkey-signin-button""#),
        "an unmet essential acr was answered with a consent screen:\n{html}"
    );

    flow.tear_down().await;
}

/// **OIDC Core §3.1.2.1**: `prompt=login` means ask again, whatever the
/// session says.
#[tokio::test]
async fn prompt_login_returns_a_signed_in_user_to_the_sign_in_form() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    sign_in_and_consent(&mut flow).await;

    // Act
    let key = ProofKey::generate();
    let request_uri = flow
        .push_with(&key, &[("prompt", "login")])
        .await
        .request_uri();
    let interaction = flow.authorize(&request_uri).await;
    let page = flow.get(&interaction).await;

    // Assert
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let html = page.text();
    assert!(
        html.contains(r#"id="passkey-signin-button""#),
        "prompt=login did not ask the user to authenticate again:\n{html}"
    );

    flow.tear_down().await;
}

/// **OIDC Core §3.1.2.3**: `max_age=0` makes every authentication too old.
#[tokio::test]
async fn max_age_zero_returns_a_signed_in_user_to_the_sign_in_form() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    sign_in_and_consent(&mut flow).await;

    // Act
    let key = ProofKey::generate();
    let request_uri = flow
        .push_with(&key, &[("max_age", "0")])
        .await
        .request_uri();
    let interaction = flow.authorize(&request_uri).await;
    let page = flow.get(&interaction).await;

    // Assert
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let html = page.text();
    assert!(
        html.contains(r#"id="passkey-signin-button""#),
        "max_age=0 did not ask the user to authenticate again:\n{html}"
    );

    flow.tear_down().await;
}

/// **OIDC Core §3.1.2.6**: `prompt=none` on a browser with no session is
/// `login_required`, and never a page.
#[tokio::test]
async fn prompt_none_without_a_session_is_login_required() {
    // Arrange: a browser that has never signed in.
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    // Act
    let key = ProofKey::generate();
    let request_uri = flow
        .push_with(&key, &[("prompt", "none")])
        .await
        .request_uri();
    let answered = flow.authorize_raw(&request_uri).await;

    // Assert
    assert_eq!(
        answered.status,
        StatusCode::SEE_OTHER,
        "a page was served to a prompt=none request:\n{}",
        answered.text()
    );
    let back = answered.location();
    assert!(
        back.starts_with(REDIRECT),
        "the browser was sent somewhere else: {back}"
    );
    assert_eq!(parameter(&back, "error").as_deref(), Some("login_required"));

    flow.tear_down().await;
}

/// **OIDC Core §3.1.2.6**: `prompt=none` from a signed-in user who has not
/// consented is `consent_required` — the one error that says the session was
/// found and only the decision is missing.
#[tokio::test]
async fn prompt_none_without_a_remembered_consent_is_consent_required() {
    // Arrange: signed in, and having refused the consent screen, so there is a
    // session and no grant.
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let key = ProofKey::generate();
    let request_uri = flow.push(&key).await;
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let consent = flow.get(&interaction).await;
    assert_eq!(consent.status, StatusCode::OK, "{}", consent.text());
    let csrf = csrf_from(&consent.text());
    let denied = flow
        .post_form(&interaction, &[("csrf", &csrf), ("decision", "deny")], None)
        .await;
    assert_eq!(
        denied.status,
        StatusCode::SEE_OTHER,
        "a refusal did not answer the client: {}",
        denied.text()
    );
    assert_eq!(
        parameter(&denied.location(), "error").as_deref(),
        Some("access_denied")
    );

    // Act
    let key = ProofKey::generate();
    let request_uri = flow
        .push_with(&key, &[("prompt", "none")])
        .await
        .request_uri();
    let answered = flow.authorize_raw(&request_uri).await;

    // Assert
    assert_eq!(
        answered.status,
        StatusCode::SEE_OTHER,
        "a page was served to a prompt=none request:\n{}",
        answered.text()
    );
    let back = answered.location();
    assert_eq!(
        parameter(&back, "error").as_deref(),
        Some("consent_required"),
        "the session was there; only the decision was missing: {back}"
    );

    flow.tear_down().await;
}

/// The type the rich-authorization tests register, and the schema it must
/// satisfy — RFC 9396 §2's own payment example, narrowed to the subset
/// `asterius_domain::JsonSchema` validates against.
const DETAIL_TYPE: &str = "payment_initiation";

fn detail_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "instructedAmount"],
        "properties": {
            "instructedAmount": {
                "type": "object",
                "required": ["currency"],
                "properties": {"currency": {"type": "string", "maxLength": 3}}
            }
        }
    })
}

/// **RFC 9396 §2, §2.1, §5**: an `authorization_details` that is not an array
/// of objects, names a type this tenant has not registered or the client may
/// not ask for, breaks the limits, or fails its type's schema is
/// `invalid_authorization_details` at the pushed authorization request
/// endpoint — where an authenticated client is still on the connection to be
/// told.
#[tokio::test]
async fn a_bad_authorization_details_is_refused_at_the_pushed_request_endpoint() {
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    flow.register_authorization_details_type(DETAIL_TYPE, &detail_schema())
        .await;
    flow.allow_client_detail_types(&[DETAIL_TYPE]).await;

    let over_sixteen = serde_json::to_string(&vec![
        json!({"type": DETAIL_TYPE, "instructedAmount": {}});
        17
    ])
    .expect("serialise");
    let too_long = json!([{
        "type": DETAIL_TYPE,
        "instructedAmount": {"currency": "EUR"},
        "note": "a".repeat(9 * 1024)
    }])
    .to_string();
    let schema_failure = json!([{"type": DETAIL_TYPE}]).to_string();
    let bad_currency =
        json!([{"type": DETAIL_TYPE, "instructedAmount": {"currency": "EURO"}}]).to_string();

    for wrong in [
        // §2: a JSON array of objects, each with a string `type`.
        "{}",
        "[7]",
        "[{}]",
        // §2.1: a type this tenant has not registered.
        r#"[{"type":"account_information"}]"#,
        // §2: the element must satisfy its type's schema.
        &schema_failure,
        &bad_currency,
        // The limits, applied before any schema is consulted.
        &over_sixteen,
        &too_long,
    ] {
        let key = ProofKey::generate();
        let refused = flow
            .push_with(&key, &[("authorization_details", wrong)])
            .await;
        assert_eq!(
            refused.status,
            StatusCode::BAD_REQUEST,
            "the push was accepted for {wrong:?}: {}",
            refused.text()
        );
        assert_eq!(
            refused.json()["error"],
            json!("invalid_authorization_details"),
            "for {wrong:?}"
        );
    }

    flow.tear_down().await;
}

/// **RFC 9396 §9.2**: `authorization_details_types` is the client's own list,
/// and a client registered for none may name none — even a type the tenant
/// defines.
#[tokio::test]
async fn a_type_the_client_is_not_registered_for_is_refused() {
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    flow.register_authorization_details_type(DETAIL_TYPE, &detail_schema())
        .await;
    flow.allow_client_detail_types(&[]).await;

    let details =
        json!([{"type": DETAIL_TYPE, "instructedAmount": {"currency": "EUR"}}]).to_string();
    let key = ProofKey::generate();
    let refused = flow
        .push_with(&key, &[("authorization_details", &details)])
        .await;

    assert_eq!(
        refused.status,
        StatusCode::BAD_REQUEST,
        "a client registered for no type was allowed one: {}",
        refused.text()
    );
    assert_eq!(
        refused.json()["error"],
        json!("invalid_authorization_details")
    );

    flow.tear_down().await;
}

/// **RFC 9396 §6 and §8.1**: the granted details come back in the token
/// response, and the JWT access token carries them as a top-level
/// `authorization_details` claim.
#[tokio::test]
async fn granted_authorization_details_reach_the_token_response_and_the_access_token() {
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    flow.register_authorization_details_type(DETAIL_TYPE, &detail_schema())
        .await;
    flow.allow_client_detail_types(&[DETAIL_TYPE]).await;
    flow.allow_client_resources(&[RESOURCE]).await;

    let element = json!({
        "type": DETAIL_TYPE,
        "instructedAmount": {"currency": "EUR", "amount": "30.00"},
        "locations": [RESOURCE]
    });
    let details = json!([element]).to_string();

    let issued = redeemed(
        &mut flow,
        &[("authorization_details", &details), ("resource", RESOURCE)],
        &[],
    )
    .await;
    assert_eq!(
        issued.status,
        StatusCode::OK,
        "the code was refused: {}",
        issued.text()
    );

    let body = issued.json();
    // §6: the AS returns the granted details — the *grant's*, not the
    // request's, because consent is what decides them.
    assert_eq!(
        body["authorization_details"],
        json!([element]),
        "the token response did not echo the granted details: {body}"
    );

    // §8.1: and the access token carries them.
    let claims = claims_of(body["access_token"].as_str().expect("a token"));
    assert_eq!(
        claims["authorization_details"],
        json!([element]),
        "the access token did not carry the granted details: {claims}"
    );

    flow.tear_down().await;
}

/// **RFC 9396 §9.1**: `authorization_details_types_supported` is the tenant's
/// registry, published where a client reads it — and absent for a tenant that
/// has registered none, because a client seeing the member treats rich
/// authorization requests as available.
#[tokio::test]
async fn the_metadata_document_publishes_the_registered_types() {
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };

    let path = format!("{}/.well-known/openid-configuration", flow.prefix());
    let before = flow.get(&path).await;
    assert_eq!(before.status, StatusCode::OK, "{}", before.text());
    assert!(
        before
            .json()
            .get("authorization_details_types_supported")
            .is_none(),
        "a tenant that registered no type advertised the member: {}",
        before.text()
    );

    flow.register_authorization_details_type(DETAIL_TYPE, &detail_schema())
        .await;

    let after = flow.get(&path).await;
    assert_eq!(after.status, StatusCode::OK, "{}", after.text());
    assert_eq!(
        after.json()["authorization_details_types_supported"],
        json!([DETAIL_TYPE]),
        "the document did not publish the registry: {}",
        after.text()
    );

    flow.tear_down().await;
}

// ---- RFC 9449 §10: the key a pushed request pinned the code to -----------

/// The redemption of `code` under `key`, whatever it answers.
async fn redeem_under(flow: &mut Flow, key: &ProofKey, jti: &str, code: &str) -> Reply {
    flow.token(
        key,
        jti,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", VERIFIER),
        ],
    )
    .await
}

/// Asserts that a redemption was refused *because of the key* (RFC 9449 §10).
///
/// The RFC says only "MUST reject" and both spellings are in use — this server
/// answers `invalid_dpop_proof`, a conformance suite would also accept
/// `invalid_grant` — so the assertion is about the refusal and its reason, not
/// about which of the two words was chosen.
fn assert_refused_for_the_wrong_key(reply: &Reply) {
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "a code pinned to another key was redeemed: {}",
        reply.text()
    );
    let body = reply.json();
    let error = body["error"].as_str().unwrap_or_default();
    assert!(
        matches!(error, "invalid_dpop_proof" | "invalid_grant"),
        "RFC 9449 §10 requires a refusal about the key, got: {body}"
    );
}

/// The code of a second authorization by a browser that has already decided.
///
/// A test that checks both the wrong key and the right one needs two codes:
/// redemption consumes the code in the statement that reads it, before the key
/// is looked at, so the refused attempt spends the first one.
async fn second_code(flow: &mut Flow, request_uri: &str) -> String {
    let started = flow.authorize_raw(request_uri).await;
    assert_eq!(
        started.status,
        StatusCode::SEE_OTHER,
        "the authorization request did not start: {}",
        started.text()
    );
    let interaction = started.location();
    let answered = flow.get(&interaction).await;
    assert_eq!(
        answered.status,
        StatusCode::SEE_OTHER,
        "a screen was served to a user who had already decided: {}",
        answered.text()
    );
    parameter(&answered.location(), "code").expect("RFC 6749 §4.1.2 requires a code")
}

/// **RFC 9449 §10.1**: a `DPoP` header on the push pins the code to that key,
/// and no other key redeems it.
///
/// This is `ast-36g`'s shape end to end, through the assembled application:
/// the pin travels push → stored request → code → token endpoint, and the only
/// thing that proves it travelled is a redemption under a *different* key
/// being refused. Dropping `"dpop_jkt": dpop_jkt` from `par::serialise`, or the
/// `dpop_jkt: string("dpop_jkt")` the code binding is built with, makes the
/// first redemption below succeed.
#[tokio::test]
async fn a_push_proved_with_one_key_yields_a_code_no_other_key_redeems() {
    // Arrange: a browser that has signed in and consented, holding a code from
    // a push proved with `pinned`.
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let pinned = ProofKey::generate();
    let stranger = ProofKey::generate();
    assert_ne!(pinned.thumbprint(), stranger.thumbprint());
    let request_uri = flow.push(&pinned).await;
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let code = flow.consent(&interaction).await;

    // Act: the code, presented with a well formed proof for the wrong key.
    let stolen = redeem_under(&mut flow, &stranger, "assertion-header-pin-wrong", &code).await;

    // Assert: refused, and about the key.
    assert_refused_for_the_wrong_key(&stolen);

    // Act & assert: the same flow under the pinned key is a token, so the
    // refusal above was the pin and not some unrelated breakage.
    let again = flow.push(&pinned).await;
    let code = second_code(&mut flow, &again).await;
    let issued = redeem_under(&mut flow, &pinned, "assertion-header-pin-right", &code).await;
    assert_eq!(
        issued.status,
        StatusCode::OK,
        "the pinned key was refused its own code: {}",
        issued.text()
    );
    assert_eq!(issued.json()["token_type"], "DPoP", "{}", issued.text());

    flow.tear_down().await;
}

/// **RFC 9449 §10.1**: `dpop_jkt` on the push pins the code just as a proof
/// does, for a client that sends no `DPoP` header at the pushed request
/// endpoint.
///
/// The parameter spelling is what a client uses when the push is made by a back
/// end that does not hold the DPoP key. Nothing else in this suite redeems a
/// code pinned that way, so this test is what says the parameter reaches the
/// token endpoint at all.
#[tokio::test]
async fn a_push_naming_dpop_jkt_without_a_proof_pins_the_code_too() {
    // Arrange
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let pinned = ProofKey::generate();
    let stranger = ProofKey::generate();
    let thumbprint = pinned.thumbprint();
    let request_uri = flow
        .push_unproved(&[("dpop_jkt", thumbprint.as_str())])
        .await
        .request_uri();
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let code = flow.consent(&interaction).await;

    // Act: another key's proof against a code pinned by parameter alone.
    let stolen = redeem_under(&mut flow, &stranger, "assertion-parameter-pin-wrong", &code).await;

    // Assert
    assert_refused_for_the_wrong_key(&stolen);

    // Act & assert: the named key redeems.
    let again = flow
        .push_unproved(&[("dpop_jkt", thumbprint.as_str())])
        .await
        .request_uri();
    let code = second_code(&mut flow, &again).await;
    let issued = redeem_under(&mut flow, &pinned, "assertion-parameter-pin-right", &code).await;
    assert_eq!(
        issued.status,
        StatusCode::OK,
        "the key named in dpop_jkt was refused its own code: {}",
        issued.text()
    );
    assert_eq!(issued.json()["token_type"], "DPoP", "{}", issued.text());

    flow.tear_down().await;
}

/// **OIDC Core §11**: an `offline_access` grant outlives the session it was
/// made in — including the retention sweep that deletes the row (`ast-dlk`).
///
/// §11 defines `offline_access` as access "when the End-User is not present",
/// and the browser session is exactly the thing that records presence. So a
/// sweep, a sign-out or a retention policy removing that row must not turn a
/// refresh token into a credential the server refuses: the authorization is
/// still there, and the client is not asking about the browser.
///
/// What made that impossible before this test is that `auth_time`, `acr` and
/// `amr` were read from the session and from nowhere else, so a vanished
/// session left the server with no honest `auth_time` to assert and it refused
/// — the failure `ast-uwv.3` deliberately left behind. The fix copies the three
/// onto the grant at its creation, and this asserts the values, not merely the
/// status: an ID token minted after the purge that reported *this request's*
/// instant, or another session's, would satisfy a status assertion and lie
/// about when the person authenticated.
///
/// The purge is `PgSessionRepository::purge_expired`, which is the retention
/// sweep itself rather than a hand-written `delete` — a test that removed the
/// row its own way could pass against a sweep that does something else.
#[tokio::test]
async fn an_offline_access_grant_outlives_the_purge_of_its_session() {
    // Arrange: one full flow, so the refresh token and the ID token that names
    // the authentication both come from the real chain.
    let Some(mut flow) = Flow::new().await else {
        eprintln!("skipping: DATABASE_URL is not set");
        return;
    };
    let redemption_key = ProofKey::generate();
    let request_uri = flow.push(&redemption_key).await;
    let interaction = flow.authorize(&request_uri).await;
    flow.sign_in(&interaction).await;
    let code = flow.consent(&interaction).await;
    let redeemed = flow
        .token(
            &redemption_key,
            "assertion-code",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    assert_eq!(
        redeemed.status,
        StatusCode::OK,
        "the code was refused: {}",
        redeemed.text()
    );
    let tokens = redeemed.json();
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("an offline_access grant earns a refresh token")
        .to_owned();
    let first = claims_of(tokens["id_token"].as_str().expect("an ID token"));

    // Act: the retention sweep takes every session of this tenant. A deadline
    // far in the future means "everything", which is what a purge after a long
    // enough silence does to a grant that is still perfectly live.
    let purged = PgSessionRepository::new(flow.store.pool().clone(), flow.tenant.id.clone())
        .purge_expired(OffsetDateTime::now_utc() + time::Duration::days(3650))
        .await
        .expect("purge the sessions");
    assert!(purged >= 1, "the flow left no session to purge");

    // Act: the client refreshes, as it may — it never held the session.
    let refresh_key = ProofKey::generate();
    let refreshed = flow
        .token(
            &refresh_key,
            "assertion-refresh",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh_token),
            ],
        )
        .await;

    // Assert: RFC 6749 §5.1 — a new access token, not a refusal.
    assert_eq!(
        refreshed.status,
        StatusCode::OK,
        "the refresh was refused after the session was purged: {}",
        refreshed.text()
    );
    let body = refreshed.json();
    assert!(body["access_token"].is_string(), "no access token: {body}");

    // Assert: and the ID token OIDC Core §12.2 allows still says when and how
    // the person authenticated — the original values, from the grant.
    let again = claims_of(body["id_token"].as_str().expect("an ID token"));
    assert_eq!(again["sub"], first["sub"], "the subject changed: {again}");
    assert_eq!(
        again["auth_time"], first["auth_time"],
        "auth_time is not the one the authentication happened at: {again}"
    );
    assert_eq!(
        again["acr"], first["acr"],
        "acr is not the one the authentication reached: {again}"
    );
    assert_eq!(
        again["amr"], first["amr"],
        "amr is not the one the authentication used: {again}"
    );

    flow.tear_down().await;
}
