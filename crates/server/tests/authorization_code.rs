//! Redeeming an authorization code (RFC 6749 §4.1.3, OIDC Core §3.1.3).
//!
//! Every case here is one of the acceptance criteria on `ast-a05.2`, and every
//! one of those is a binding recorded when the code was issued. The code is a
//! bearer credential that travels through a browser and through whatever the
//! browser's address bar is logged into, so these checks are the whole of what
//! stands between a stolen code and a token.
//!
//! The happy path is asserted against the *published* JWK Set rather than
//! against the signer, because that is what a relying party actually does: take
//! `kid` from the header, find that key in the tenant's JWKS, check the
//! signature under it.
//!
//! # Isolation
//!
//! As in `signing.rs`: `asterius-server` has no `sqlx` dependency (ADR-0001),
//! so there is no per-test schema. Every test mints a unique tenant, touches
//! nothing outside it, and deletes it at the end, which cascades its clients,
//! grants and codes away.

use asterius_domain::entities::session::{AuthenticationMethod, Lifetimes, Session, SessionId};
use asterius_domain::entities::user::{User, UserStatus};
use asterius_domain::ports::{SessionRepository, TenantRepository};
use asterius_domain::{
    Capabilities, Client, ClientId, ClientRegistration, ClientStatus, CodeBinding, Grant, GrantId,
    Issuer, KeyStore, Kid, RevocationReason, SubjectId, Tenant, TenantId, TenantStatus, UserId,
};
use asterius_jose::kek::Kek;
use asterius_jose::{LocalKek, jws, keys_from_jwk_set};
use asterius_oidc::client_auth::{AssertionRules, Attempt, ClientAuthError};
use asterius_server::http::authorization_code::AuthorizationCode;
use asterius_server::http::token::{GrantHandler, TokenContext, token};
use asterius_server::signing::CachedSigner;
use asterius_store_pg::{
    PgAuditSink, PgCodeRepository, PgGrantRepository, PgSessionRepository, PgTenantRepository,
    PgUserRepository, Store, TenantKeyStore,
};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use time::OffsetDateTime;

static COUNTER: AtomicU32 = AtomicU32::new(0);

const REDIRECT: &str = "https://rp.example/cb";
const CLIENT: &str = "billing";
const RESOURCE: &str = "https://api.example/";

/// A `code_verifier` and the `S256` challenge it derives.
///
/// RFC 7636 Appendix B's own published pair, not one computed here. The `S256`
/// transformation is deliberately private — the only way to relate a verifier
/// to a challenge is the constant-time comparison — so a test cannot derive
/// one, and should not want to: a hard-coded pair from the specification also
/// asserts that this server's idea of `S256` is the specification's.
struct Pkce {
    verifier: &'static str,
    challenge: &'static str,
}

/// RFC 7636 Appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

impl Pkce {
    const fn generate() -> Self {
        Self {
            verifier: VERIFIER,
            challenge: CHALLENGE,
        }
    }
}

/// Everything one test needs, in a tenant nothing else touches.
struct Fixture {
    store: Store,
    keys: TenantKeyStore,
    tenant: Tenant,
    signer: Arc<CachedSigner>,
    kek: Arc<dyn Kek>,
    now: OffsetDateTime,
}

impl Fixture {
    /// `None` without `DATABASE_URL`, so the default `cargo test` stays fast.
    async fn new() -> Option<Self> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let store = Store::connect(&url, 4)
            .await
            .expect("DATABASE_URL is set but unreachable; is `docker compose up -d db` running?");
        store.migrate().await.expect("migrate");

        let kek: Arc<dyn Kek> = Arc::new(LocalKek::from_bytes(&[3_u8; 32]).expect("a 32-byte KEK"));
        let audit = Arc::new(PgAuditSink::new(store.pool().clone()));
        let now = OffsetDateTime::now_utc();

        let id = format!(
            "code-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let tenant = Tenant {
            id: TenantId::parse(&id).expect("a generated tenant id"),
            issuer: Issuer::parse(&format!("https://as.example/t/{id}")).expect("issuer"),
            custom_host: None,
            display_name: "Codes".to_owned(),
            default_resource: RESOURCE.to_owned(),
            status: TenantStatus::Active,
            created_at: now,
            updated_at: now,
        };
        PgTenantRepository::new(store.pool().clone(), Arc::clone(&kek))
            .upsert(&tenant)
            .await
            .expect("create tenant");

        let keys = TenantKeyStore::new(store.pool().clone(), Arc::clone(&kek), audit);
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
            tenant,
            signer,
            kek,
            now,
        })
    }

    fn codes(&self) -> PgCodeRepository {
        PgCodeRepository::new(self.store.pool().clone(), self.tenant.id.clone())
    }

    fn grants(&self) -> PgGrantRepository {
        PgGrantRepository::new(self.store.pool().clone(), self.tenant.id.clone())
    }

    fn sessions(&self) -> PgSessionRepository {
        PgSessionRepository::new(self.store.pool().clone(), self.tenant.id.clone())
    }

    /// A client registered for this grant, stored so the endpoint can load it.
    async fn client(&self) -> Client {
        let client = Client {
            tenant: self.tenant.id.clone(),
            id: ClientId::new(CLIENT),
            registration: ClientRegistration::from_json(
                &serde_json::to_vec(&json!({
                    "client_name": "Billing",
                    "redirect_uris": [REDIRECT],
                    "grant_types": ["authorization_code"],
                    "scope": "openid",
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

    /// A user, a session they authenticated in, and a grant naming both.
    ///
    /// The session is what carries `auth_time`, `acr` and `amr` into both
    /// tokens, so it is not optional scaffolding — a grant without one cannot
    /// produce an honest ID token.
    async fn grant(&self, scopes: &[&str]) -> Grant {
        let (session, user) = self.session().await;
        self.grant_in(scopes, &session, user).await
    }

    /// A user and the session they authenticated in.
    async fn session(&self) -> (Session, UserId) {
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
        (session, user)
    }

    /// A grant naming an existing session.
    async fn grant_in(&self, scopes: &[&str], session: &Session, user: UserId) -> Grant {
        let grant = Grant {
            tenant: self.tenant.id.clone(),
            id: GrantId::new(uuid::Uuid::new_v4().to_string()),
            client: ClientId::new(CLIENT),
            user: Some(user),
            subject: Some(SubjectId::new("alice-pairwise")),
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            claims: json!({}),
            authorization_details: Vec::new(),
            resources: std::collections::BTreeSet::new(),
            actor_chain: Vec::new(),
            parent: None,
            // The store keeps the digest, which is what the token endpoint
            // looks the session up by.
            session: Some(asterius_domain::SessionId::new(session.id_digest.clone())),
            created_at: self.now,
            updated_at: self.now,
            expires_at: None,
            revoked_at: None,
            revocation_reason: None,
            claimed_at: None,
        };
        self.grants().create(&grant).await.expect("store the grant");
        grant
    }

    /// Issues a code the way the authorization endpoint does.
    async fn issue(&self, grant: &Grant, pkce: &Pkce, dpop_jkt: Option<&str>) -> String {
        let minted = asterius_oidc::code::MintedCode::generate();
        let binding = CodeBinding {
            client_id: CLIENT.to_owned(),
            grant_id: grant.id.clone(),
            code_challenge: pkce.challenge.to_owned(),
            redirect_uri: REDIRECT.to_owned(),
            nonce: Some("n-0S6_WzA2Mj".to_owned()),
            dpop_jkt: dpop_jkt.map(ToOwned::to_owned),
            expires_at: self.now + time::Duration::seconds(60),
        };
        self.codes()
            .issue(minted.digest(), &binding, self.now)
            .await
            .expect("issue the code");
        minted.expose().to_owned()
    }

    /// Runs a token request through the real endpoint and the real handler.
    async fn redeem(
        &self,
        client: &Client,
        pairs: &[(&str, &str)],
        proof_key: Option<&Kid>,
    ) -> (StatusCode, Value) {
        let codes = self.codes();
        let grants = self.grants();
        let sessions = self.sessions();
        let handler = AuthorizationCode {
            codes: &codes,
            grants: &grants,
            sessions: &sessions,
            signer: self.signer.as_ref(),
            proof_key,
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

// ---- The happy path ------------------------------------------------------

db_test! {
    /// OIDC Core §3.1.3.3. Both tokens, verified against the published JWK Set
    /// rather than against the thing that signed them.
    async fn a_valid_redemption_issues_both_tokens(fixture) {
        let client = fixture.client().await;
        let pkce = Pkce::generate();
        let (session, user) = fixture.session().await;
        let session_digest = session.id_digest.clone();
        let grant = fixture.grant_in(&["openid", "profile"], &session, user).await;
        let jkt = thumbprint(1);
        let code = fixture.issue(&grant, &pkce, Some(jkt.as_str())).await;

        let (status, body) = fixture
            .redeem(
                &client,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", REDIRECT),
                    ("code_verifier", pkce.verifier),
                ],
                Some(&jkt),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        // RFC 9449 §5: a DPoP-bound token is not a bearer token, and saying so
        // is what stops a client presenting it as one.
        assert_eq!(body["token_type"], "DPoP");
        assert_eq!(body["expires_in"], 300);

        let access = fixture.verify(body["access_token"].as_str().expect("access_token")).await;
        assert_eq!(access["iss"], fixture.tenant.issuer.as_str());
        assert_eq!(access["client_id"], CLIENT);
        // RFC 9449 §6.1: the whole point of the grant's DPoP binding.
        assert_eq!(access["cnf"]["jkt"], jkt.as_str());
        // RFC 9068 §3 with no `resource` on the request: the tenant's default.
        assert_eq!(access["aud"], RESOURCE);

        let id_token = fixture.verify(body["id_token"].as_str().expect("id_token")).await;
        assert_eq!(id_token["iss"], fixture.tenant.issuer.as_str());
        assert_eq!(id_token["aud"], CLIENT);
        assert_eq!(id_token["sub"], "alice-pairwise");
        // OIDC Core §3.1.3.7 item 11: echoed byte-exact from the authorization
        // request, which is what binds this token to that browser exchange.
        assert_eq!(id_token["nonce"], "n-0S6_WzA2Mj");
        // OIDC Core §2: always present, and from the session rather than from
        // the moment the token was minted.
        assert!(id_token["auth_time"].is_number(), "auth_time is missing");
        assert_eq!(id_token["amr"], json!(["swk"]));
        // §3.1.3.6, and the binding between the two halves of this response.
        assert!(id_token["at_hash"].is_string(), "at_hash is missing");
        // OIDC Back-Channel Logout 1.0 §2.4. The session's public identifier,
        // and emphatically not the digest the session store looks rows up by
        // (`ast-o4u.5`): handing a relying party that would publish an
        // internal key as a side effect of issuing a token.
        let sid = id_token["sid"].as_str().expect("sid is missing");
        assert_ne!(
            sid, session_digest,
            "the ID token published the session lookup digest as its sid"
        );

        fixture.tear_down().await;
    }
}

db_test! {
    /// Rotating the session id must not change `sid`.
    ///
    /// Rotation is the fixation defence — a new cookie value at every
    /// privilege change — but it is the same login and the same thing a
    /// relying party would later be asked to log out. A `sid` that moved with
    /// the digest would make one session look like several to an RP, and would
    /// leave back-channel logout (`ast-o4u.1`) naming a session nobody
    /// recognises.
    async fn the_sid_survives_a_session_rotation(fixture) {
        let (session, _) = fixture.session().await;
        let sessions = fixture.sessions();

        let rotated_id = SessionId::generate();
        sessions
            .rotate(
                &session.id_digest,
                &rotated_id.digest(),
                &[AuthenticationMethod::Password],
                fixture.now + time::Duration::minutes(1),
            )
            .await
            .expect("rotate the session");

        let after = sessions
            .find(&rotated_id.digest())
            .await
            .expect("read")
            .expect("the rotated session");

        assert_ne!(
            after.id_digest, session.id_digest,
            "the rotation did not change the lookup digest, so this proves nothing"
        );
        assert_eq!(
            after.public_sid, session.public_sid,
            "the sid changed when the session id rotated"
        );

        fixture.tear_down().await;
    }
}

db_test! {
    /// A grant with no `openid` scope is an OAuth grant, not an OpenID Connect
    /// one, and OIDC Core §3.1.3.3 gives it no ID token.
    async fn a_grant_without_openid_gets_no_id_token(fixture) {
        let client = fixture.client().await;
        let pkce = Pkce::generate();
        let grant = fixture.grant(&["payments"]).await;
        let jkt = thumbprint(2);
        let code = fixture.issue(&grant, &pkce, Some(jkt.as_str())).await;

        let (status, body) = fixture
            .redeem(
                &client,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", REDIRECT),
                    ("code_verifier", pkce.verifier),
                ],
                Some(&jkt),
            )
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["access_token"].is_string());
        assert_eq!(body.get("id_token"), None, "an ID token was issued anyway");
        assert_eq!(body["scope"], "payments");

        fixture.tear_down().await;
    }
}

// ---- The bindings --------------------------------------------------------

db_test! {
    /// The acceptance criteria, one refusal each. Every one is `invalid_grant`
    /// with the same description: RFC 6749 §5.2 puts five distinct facts behind
    /// that one code deliberately, and saying which applies would tell somebody
    /// holding a stolen code whether it was the code or the verifier that was
    /// wrong.
    async fn every_broken_binding_is_refused_as_invalid_grant(fixture) {
        let client = fixture.client().await;
        let jkt = thumbprint(3);

        // Each case gets its own code, because the first attempt spends it.
        for (label, mutate) in [
            (
                "a code that was never issued",
                Box::new(|form: &mut Vec<(String, String)>, _: &Pkce| {
                    set(form, "code", &"z".repeat(43));
                }) as Box<dyn Fn(&mut Vec<(String, String)>, &Pkce)>,
            ),
            (
                "a redirect_uri that is not the one the code was issued for",
                Box::new(|form: &mut Vec<(String, String)>, _: &Pkce| {
                    set(form, "redirect_uri", "https://rp.example/cb2");
                }),
            ),
            (
                "a code_verifier that does not derive the stored challenge",
                Box::new(|form: &mut Vec<(String, String)>, _: &Pkce| {
                    set(form, "code_verifier", &"b".repeat(64));
                }),
            ),
        ] {
            let pkce = Pkce::generate();
            let grant = fixture.grant(&["openid"]).await;
            let code = fixture.issue(&grant, &pkce, Some(jkt.as_str())).await;
            let mut form = base_form(&code, &pkce);
            mutate(&mut form, &pkce);

            let (status, body) = fixture.redeem(&client, &borrowed(&form), Some(&jkt)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {body}");
            assert_eq!(body["error"], "invalid_grant", "{label}");
            assert_eq!(
                body["error_description"], "the authorization code cannot be redeemed",
                "{label} named which check failed"
            );
        }

        fixture.tear_down().await;
    }
}

db_test! {
    /// OIDC Core §3.1.3.2: the code must have been issued to the client
    /// presenting it. Checked before anything else, so a client cannot use the
    /// token endpoint to ask questions about another client's code.
    async fn a_code_issued_to_another_client_is_refused(fixture) {
        let client = fixture.client().await;
        let pkce = Pkce::generate();
        let mut grant = fixture.grant(&["openid"]).await;
        grant.client = ClientId::new("someone-else");
        let jkt = thumbprint(4);

        // Issue the code against a binding naming the other client.
        let minted = asterius_oidc::code::MintedCode::generate();
        fixture
            .codes()
            .issue(
                minted.digest(),
                &CodeBinding {
                    client_id: "someone-else".to_owned(),
                    grant_id: grant.id.clone(),
                    code_challenge: pkce.challenge.to_owned(),
                    redirect_uri: REDIRECT.to_owned(),
                    nonce: None,
                    dpop_jkt: Some(jkt.as_str().to_owned()),
                    expires_at: fixture.now + time::Duration::seconds(60),
                },
                fixture.now,
            )
            .await
            .expect("issue");

        let (status, body) = fixture
            .redeem(
                &client,
                &borrowed(&base_form(minted.expose(), &pkce)),
                Some(&jkt),
            )
            .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");

        fixture.tear_down().await;
    }
}

db_test! {
    /// RFC 6749 §4.1.2 and RFC 9700 §4.1.2. A second use is not merely refused:
    /// the grant behind it is revoked, because a code that arrived twice
    /// reached somebody it should not have, and the tokens from the *first*
    /// use are the ones now in the wrong hands.
    async fn a_second_use_is_refused_and_revokes_the_grant(fixture) {
        let client = fixture.client().await;
        let pkce = Pkce::generate();
        let grant = fixture.grant(&["openid"]).await;
        let jkt = thumbprint(5);
        let code = fixture.issue(&grant, &pkce, Some(jkt.as_str())).await;
        let form = base_form(&code, &pkce);

        let (first, _) = fixture.redeem(&client, &borrowed(&form), Some(&jkt)).await;
        assert_eq!(first, StatusCode::OK, "the first use must succeed");

        let (second, body) = fixture.redeem(&client, &borrowed(&form), Some(&jkt)).await;
        assert_eq!(second, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");

        let after = fixture
            .grants()
            .find(&grant.id)
            .await
            .expect("read the grant")
            .expect("the grant still exists");
        assert!(
            after.revoked_at.is_some(),
            "a replayed code left its grant live"
        );
        assert_eq!(after.revocation_reason, Some(RevocationReason::CodeReplayed));

        fixture.tear_down().await;
    }
}

// ---- DPoP ----------------------------------------------------------------

db_test! {
    /// RFC 9449 §10 and FAPI 2.0 SP §5.3.2.1 item 12. A code pinned at PAR to
    /// one key is not redeemable with another — nor, explicitly, with no proof
    /// at all, which is the case an implementation that only compares two
    /// present thumbprints gets wrong.
    async fn a_code_pinned_to_a_key_refuses_another_key_and_no_key(fixture) {
        let client = fixture.client().await;
        let pinned = thumbprint(6);

        for presented in [Some(thumbprint(7)), None] {
            let pkce = Pkce::generate();
            let grant = fixture.grant(&["openid"]).await;
            let code = fixture.issue(&grant, &pkce, Some(pinned.as_str())).await;

            let (status, _) = fixture
                .redeem(
                    &client,
                    &borrowed(&base_form(&code, &pkce)),
                    presented.as_ref(),
                )
                .await;
            assert_ne!(
                status,
                StatusCode::OK,
                "a code pinned to {pinned} was redeemed with {presented:?}"
            );
        }

        fixture.tear_down().await;
    }
}

db_test! {
    /// FAPI 2.0 SP §5.3.2.1 item 4: every access token is sender-constrained.
    /// So a code that pinned *nothing* still cannot be redeemed without a
    /// proof — there is no unbound token to fall back to, and issuing one
    /// would be the single exception that makes `cnf` optional in practice.
    async fn a_code_that_pinned_nothing_still_requires_a_proof(fixture) {
        let client = fixture.client().await;
        let pkce = Pkce::generate();
        let grant = fixture.grant(&["openid"]).await;
        let code = fixture.issue(&grant, &pkce, None).await;

        let (status, body) = fixture
            .redeem(&client, &borrowed(&base_form(&code, &pkce)), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_grant");

        fixture.tear_down().await;
    }
}

db_test! {
    /// The other half of the previous test: a code that pinned nothing is
    /// redeemable with any proof, and the token is bound to whatever key
    /// actually turned up.
    async fn a_code_that_pinned_nothing_binds_to_the_key_that_arrives(fixture) {
        let client = fixture.client().await;
        let pkce = Pkce::generate();
        let grant = fixture.grant(&["openid"]).await;
        let code = fixture.issue(&grant, &pkce, None).await;
        let jkt = thumbprint(8);

        let (status, body) = fixture
            .redeem(&client, &borrowed(&base_form(&code, &pkce)), Some(&jkt))
            .await;

        assert_eq!(status, StatusCode::OK, "{body}");
        let access = fixture.verify(body["access_token"].as_str().expect("access_token")).await;
        assert_eq!(access["cnf"]["jkt"], jkt.as_str());

        fixture.tear_down().await;
    }
}

// ---- Helpers -------------------------------------------------------------

fn base_form(code: &str, pkce: &Pkce) -> Vec<(String, String)> {
    vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), code.to_owned()),
        ("redirect_uri".to_owned(), REDIRECT.to_owned()),
        ("code_verifier".to_owned(), pkce.verifier.to_owned()),
    ]
}

fn set(form: &mut Vec<(String, String)>, name: &str, value: &str) {
    for pair in form.iter_mut() {
        if pair.0 == name {
            value.clone_into(&mut pair.1);
            return;
        }
    }
    form.push((name.to_owned(), value.to_owned()));
}

fn borrowed(form: &[(String, String)]) -> Vec<(&str, &str)> {
    form.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}
