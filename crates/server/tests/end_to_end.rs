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
use asterius_domain::ports::{PasskeyRepository, TenantRepository};
use asterius_domain::{
    Argon2Parameters, Capabilities, ClaimSet, Client, ClientId, ClientRegistration, ClientStatus,
    EndpointLimit, EndpointLimits, Issuer, Kid, Lifetimes, LoginLimits, NewPasskey, RateLimit,
    SigningAlgorithm, Tenant, TenantId, TenantStatus, UserId,
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
use asterius_store_pg::{
    PgAuditSink, PgPasskeyRepository, PgReplayGuard, PgTenantRepository, PgUserRepository, Store,
    TenantKeyStore,
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
use std::collections::BTreeMap;
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
        let header = json!({
            "typ": "dpop+jwt",
            "alg": self.0.algorithm().as_str(),
            "jwk": self.jwk(),
        });
        let claims = json!({
            "jti": jti,
            "htm": method,
            "htu": url,
            "iat": OffsetDateTime::now_utc().unix_timestamp(),
        });
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

        let flow = Self {
            app: assemble(&store, &kek, &keys, Arc::clone(&audit)),
            store,
            kek,
            tenant,
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
        let url = Endpoint::PushedAuthorizationRequest.url(&self.tenant.issuer);
        let path = format!(
            "{}{}",
            self.prefix(),
            Endpoint::PushedAuthorizationRequest.path()
        );
        let assertion = self.assertion("assertion-par");
        let proof = key.proof("POST", &url, &self.next_jti());
        let pushed = self
            .post_form(
                &path,
                &[
                    ("client_id", CLIENT),
                    ("client_assertion_type", CLIENT_ASSERTION_TYPE),
                    ("client_assertion", &assertion),
                    ("response_type", "code"),
                    ("redirect_uri", REDIRECT),
                    ("scope", "openid offline_access"),
                    ("code_challenge", CHALLENGE),
                    ("code_challenge_method", "S256"),
                    ("state", STATE),
                    ("nonce", NONCE),
                ],
                Some(&proof),
            )
            .await;
        assert_eq!(
            pushed.status,
            StatusCode::CREATED,
            "the push was refused: {}",
            pushed.text()
        );
        pushed.json()["request_uri"]
            .as_str()
            .expect("RFC 9126 §2.2 requires a request_uri")
            .to_owned()
    }

    /// OIDC Core §3.1.2.1: the browser arrives at the authorization endpoint
    /// carrying nothing but the reference, and is sent into an interaction.
    async fn authorize(&mut self, request_uri: &str) -> String {
        let path = format!(
            "{}{}?client_id={CLIENT}&request_uri={}",
            self.prefix(),
            Endpoint::Authorization.path(),
            url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect::<String>()
        );
        let started = self.get(&path).await;
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
        let url = Endpoint::Token.url(&self.tenant.issuer);
        let path = format!("{}{}", self.prefix(), Endpoint::Token.path());
        let assertion = self.assertion(jti);
        let proof = key.proof("POST", &url, &self.next_jti());
        let mut form = pairs.to_vec();
        form.push(("client_id", CLIENT));
        form.push(("client_assertion_type", CLIENT_ASSERTION_TYPE));
        form.push(("client_assertion", &assertion));
        self.post_form(&path, &form, Some(&proof)).await
    }

    /// A `private_key_jwt` assertion for this client (OIDC Core §9).
    fn assertion(&self, jti: &str) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = json!({
            "iss": CLIENT,
            "sub": CLIENT,
            "aud": self.tenant.issuer.as_str(),
            "jti": jti,
            "iat": now,
            "exp": now + 60,
        });
        jws::sign(&self.client_key, &Kid::new(CLIENT_KID), "JWT", &claims)
            .expect("a signed assertion")
            .as_str()
            .to_owned()
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
        // No tenant has settings of its own here, so the document describes
        // exactly the deployment's capabilities (`ast-f7m.4`).
        tenant_settings: None,
        clients: Some(Arc::new(ClientEndpoints {
            authenticator,
            store: store.clone(),
            keys: key_store,
            capabilities: Capabilities::default(),
            par_lifetime: time::Duration::seconds(90),
            code_lifetime: time::Duration::seconds(60),
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
