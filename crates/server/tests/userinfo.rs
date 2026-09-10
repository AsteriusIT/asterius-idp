//! The UserInfo endpoint (OIDC Core §5.3, RFC 6750 §3, RFC 9449 §7.1,
//! FAPI 2.0 SP §5.3.4).
//!
//! Every test here goes through the real handler with a real signed access
//! token, a real DPoP proof and the real verifier — only the rows are faked.
//! An endpoint whose credential checks were stubbed would be an endpoint whose
//! tests pass for tokens it should refuse.

use asterius_domain::keys::{KeyStore as _, Signer as _, SigningAlgorithm};
use asterius_domain::{
    Capabilities, Claim, ClaimName, ClaimSet, ClaimSource, ClientId, DomainError, Grant, GrantId,
    Issuer, ReplayCheck, ReplayGuard, ReplayPurpose, SubjectId, Tenant, TenantId, TenantStatus,
    User, UserId, UserStatus,
};
use asterius_jose::dpop::NonceIssuer;
use asterius_jose::{LocalKeyStore, SigningKey, thumbprint};
use asterius_oidc::mtls::ClientCertificate;
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::{AccessToken, Audience, Confirmation};
use asterius_server::http::dpop::{DpopEndpoint, HEADER as DPOP_HEADER, NONCE_HEADER};
use asterius_server::http::userinfo::{
    JWT_CONTENT_TYPE, UserInfoContext, UserInfoSource, userinfo,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";
const USERINFO: &str = "https://as.example/t/demo/userinfo";
const CLIENT: &str = "billing";
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
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: "demo".to_owned(),
        status: TenantStatus::Active,
        refresh: asterius_domain::RefreshPolicy::default(),
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn user() -> User {
    let mut claims = ClaimSet::default();
    for (name, value) in [
        ("name", json!("Ada Lovelace")),
        ("phone_number", json!("+44 20 7946 0000")),
    ] {
        claims.insert(
            ClaimName::parse(name).expect("a fixture claim name"),
            Claim::new(value, ClaimSource::Local).expect("a fixture claim"),
        );
    }
    User {
        tenant: TenantId::new("demo"),
        id: UserId::generate(),
        username: "ada".to_owned(),
        email: Some("ada@example.test".to_owned()),
        email_verified: true,
        status: UserStatus::Active,
        claims,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

/// A claimed grant for `scopes`, made for `user`.
fn grant(user: &User, scopes: &[&str]) -> Grant {
    let mut grant = Grant::new(TenantId::new("demo"), ClientId::new(CLIENT), now());
    grant.user = Some(user.id);
    grant.subject = Some(SubjectId::new(SUBJECT));
    grant.scopes = scopes
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<BTreeSet<_>>();
    grant.claimed_at = Some(now());
    grant
}

/// The rows, as this endpoint sees them.
#[derive(Debug, Default)]
struct FakeRows {
    grant: Option<Grant>,
    user: Option<User>,
    denylisted: Option<String>,
    /// What the client registered as `userinfo_signed_response_alg`.
    signed_response_alg: Option<SigningAlgorithm>,
    /// How often anything was read. A request refused before processing must
    /// leave this at zero.
    reads: AtomicUsize,
}

#[async_trait::async_trait]
impl UserInfoSource for FakeRows {
    async fn grant(&self, id: &GrantId) -> Result<Option<Grant>, DomainError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.grant.clone().filter(|grant| grant.id == *id))
    }

    async fn user(&self, id: UserId) -> Result<Option<User>, DomainError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.user.clone().filter(|user| user.id == id))
    }

    async fn is_denylisted(&self, jti: &str) -> Result<bool, DomainError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.denylisted.as_deref() == Some(jti))
    }

    async fn signed_response_alg(
        &self,
        client: &ClientId,
    ) -> Result<Option<SigningAlgorithm>, DomainError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        // Keyed on the client the grant names, so a test that changed it would
        // stop seeing the registration it set up.
        Ok(self
            .signed_response_alg
            .filter(|_| client.as_str() == CLIENT))
    }
}

#[derive(Debug, Default)]
struct FakeReplay;

#[async_trait::async_trait]
impl ReplayGuard for FakeReplay {
    async fn claim(
        &self,
        _tenant: &TenantId,
        _purpose: ReplayPurpose,
        _subject: &str,
        _jti: &str,
        _expires_at: OffsetDateTime,
    ) -> Result<ReplayCheck, DomainError> {
        Ok(ReplayCheck::FirstUse)
    }
}

/// One request's worth of wiring: a tenant key, a DPoP key, a grant and a
/// token minted from it.
struct Fixture {
    keys: Arc<LocalKeyStore>,
    dpop_key: SigningKey,
    rows: FakeRows,
    access_token: String,
    dpop: DpopEndpoint,
    /// The certificate the request arrives with, as the tenancy layer would
    /// have handed it over (RFC 8705 §2). `None` for the DPoP fixtures, which
    /// is what every deployment without mTLS sees.
    certificate: Option<ClientCertificate>,
}

impl Fixture {
    /// A grant for `scopes`, and a token minted from it.
    async fn new(scopes: &[&str]) -> Self {
        Self::with_grant(grant(&user(), scopes)).await
    }

    async fn with_grant(grant: Grant) -> Self {
        let keys = Arc::new(LocalKeyStore::new());
        keys.generate(&TenantId::new("demo"), SigningAlgorithm::DEFAULT)
            .expect("a tenant key");
        let dpop_key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("a DPoP key");
        let jkt = thumbprint(&dpop_key.public_jwk().expect("jwk")).expect("thumbprint");

        // The row the grant points at, so the endpoint's user lookup finds
        // the person the authorization was made for.
        let mut user = user();
        user.id = grant.user.expect("a fixture grant names a user");
        let claimed = grant.claim(now()).expect("a live grant");
        let unsigned = AccessToken::new(
            &Issuer::parse(ISSUER).expect("issuer"),
            &grant,
            &claimed,
            Audience::new(["https://api.example/"]).expect("audience"),
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
            dpop_key,
            rows: FakeRows {
                grant: Some(grant),
                user: Some(user),
                denylisted: None,
                signed_response_alg: None,
                reads: AtomicUsize::new(0),
            },
            access_token,
            dpop: DpopEndpoint::new(Arc::new(FakeReplay), None),
            certificate: None,
        }
    }

    /// The same grant, with a token bound to `certificate` instead
    /// (RFC 8705 §3.1).
    async fn certificate_bound(scopes: &[&str], certificate: &ClientCertificate) -> Self {
        let mut fixture = Self::new(scopes).await;
        let grant = fixture.rows.grant.clone().expect("a fixture grant");
        let claimed = grant.claim(now()).expect("a live grant");
        let unsigned = AccessToken::new(
            &Issuer::parse(ISSUER).expect("issuer"),
            &grant,
            &claimed,
            Audience::new(["https://api.example/"]).expect("audience"),
            Confirmation::certificate(&certificate.thumbprint_b64url()).expect("confirmation"),
            JwtId::generate(),
            now(),
        )
        .with_grant_id()
        .build()
        .expect("an access token");
        let signed = fixture
            .keys
            .sign(
                &TenantId::new("demo"),
                unsigned.required_algorithm(),
                unsigned.typ(),
                unsigned.claims(),
            )
            .await
            .expect("signed");
        signed.as_str().clone_into(&mut fixture.access_token);
        fixture.certificate = Some(certificate.clone());
        fixture
    }

    /// What a client holding a certificate-bound token sends: the token as a
    /// Bearer credential, and the certificate on the connection.
    fn bearer_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.access_token)).expect("header"),
        );
        headers
    }

    /// The proof a well-behaved client sends: `ath` over the token it presents.
    fn proof(&self) -> String {
        self.proof_over(&self.access_token, Some("GET"))
    }

    fn proof_over(&self, hashed: &str, method: Option<&str>) -> String {
        let mut jwk = self.dpop_key.public_jwk().expect("jwk");
        if let Some(object) = jwk.as_object_mut() {
            object.remove("use");
        }
        let header = json!({
            "typ": "dpop+jwt",
            "alg": self.dpop_key.algorithm().as_str(),
            "jwk": jwk,
        });
        let mut claims = json!({
            "jti": uuid_like(),
            "htu": USERINFO,
            "iat": now().unix_timestamp(),
            "ath": B64.encode(Sha256::digest(hashed.as_bytes())),
        });
        if let Some(method) = method {
            claims["htm"] = json!(method);
        }
        sign_by_hand(&self.dpop_key, &header, &claims)
    }

    /// A proof with no `ath` at all (RFC 9449 §4.3 item 12).
    fn proof_without_ath(&self) -> String {
        let mut jwk = self.dpop_key.public_jwk().expect("jwk");
        if let Some(object) = jwk.as_object_mut() {
            object.remove("use");
        }
        let header = json!({
            "typ": "dpop+jwt",
            "alg": self.dpop_key.algorithm().as_str(),
            "jwk": jwk,
        });
        let claims = json!({
            "jti": uuid_like(),
            "htm": "GET",
            "htu": USERINFO,
            "iat": now().unix_timestamp(),
        });
        sign_by_hand(&self.dpop_key, &header, &claims)
    }

    async fn call(&self, headers: HeaderMap, query: Option<&str>) -> Response {
        let tenant = tenant();
        userinfo(
            UserInfoContext {
                tenant: &tenant,
                source: &self.rows,
                keys: self.keys.as_ref(),
                signer: self.keys.as_ref(),
                dpop: &self.dpop,
                certificate: self.certificate.as_ref(),
                now: now(),
            },
            &Method::GET,
            &headers,
            query,
        )
        .await
    }

    /// The request a conforming client makes.
    async fn get(&self) -> Response {
        self.call(self.authorized_headers(), None).await
    }

    fn authorized_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("DPoP {}", self.access_token)).expect("header"),
        );
        headers.insert(
            DPOP_HEADER,
            HeaderValue::from_str(&self.proof()).expect("header"),
        );
        headers
    }
}

fn sign_by_hand(key: &SigningKey, header: &Value, claims: &Value) -> String {
    let signing_input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(header).expect("header")),
        B64.encode(serde_json::to_vec(claims).expect("claims"))
    );
    let signature = key.sign(signing_input.as_bytes()).expect("sign");
    format!("{signing_input}.{}", B64.encode(signature))
}

/// A `jti` that is unique per proof, so a test that sends two is not a replay.
fn uuid_like() -> String {
    use std::sync::atomic::AtomicU64;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!("proof-{}", NEXT.fetch_add(1, Ordering::SeqCst))
}

async fn body_of(response: Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("a JSON body")
}

async fn text_of(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    String::from_utf8(bytes.to_vec()).expect("UTF-8")
}

fn challenges(response: &Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::WWW_AUTHENTICATE)
        .iter()
        .map(|value| value.to_str().expect("ASCII").to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// The happy path (OIDC Core §5.3.2, RFC 9449 §7.1)
// ---------------------------------------------------------------------------

/// `Authorization: DPoP <at>` with a proof whose `ath` hashes it → 200, and
/// `sub` is the grant's.
#[tokio::test]
async fn a_dpop_bound_token_with_a_matching_proof_is_answered() {
    let fixture = Fixture::new(&["openid", "email"]).await;

    let response = fixture.get().await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .expect("no-store"),
        "no-store"
    );
    let body = body_of(response).await;
    assert_eq!(body["sub"], json!(SUBJECT));
    assert_eq!(body["email"], json!("ada@example.test"));
    assert_eq!(body["email_verified"], json!(true));
}

/// OIDC Core §5.4: the claims are the *grant's* scopes, not the user's row. A
/// grant covering only `openid` releases nothing about the person, however
/// much the record holds.
#[tokio::test]
async fn claims_are_bounded_by_the_grant_and_not_by_the_user_record() {
    let fixture = Fixture::new(&["openid"]).await;

    let body = body_of(fixture.get().await).await;

    assert_eq!(body["sub"], json!(SUBJECT));
    assert_eq!(
        body.as_object().expect("an object").len(),
        1,
        "a grant for `openid` alone released more than `sub`: {body}"
    );
}

/// The `profile` scope releases §5.4's list, and `email` is not in it.
#[tokio::test]
async fn the_scope_table_decides_which_claims_are_released() {
    let fixture = Fixture::new(&["openid", "profile"]).await;

    let body = body_of(fixture.get().await).await;

    assert_eq!(body["name"], json!("Ada Lovelace"));
    assert!(body.get("email").is_none(), "{body}");
    assert!(body.get("phone_number").is_none(), "{body}");
}

// ---------------------------------------------------------------------------
// Presentation (FAPI 2.0 SP §5.3.4, RFC 6750 §3)
// ---------------------------------------------------------------------------

/// FAPI 2.0 SP §5.3.4: a token in the query string is refused, and nothing is
/// read on the way — no grant, no user, no denylist lookup.
#[tokio::test]
async fn a_token_in_the_query_string_is_refused_and_never_processed() {
    let fixture = Fixture::new(&["openid"]).await;

    let response = fixture
        .call(
            fixture.authorized_headers(),
            Some(&format!("access_token={}", fixture.access_token)),
        )
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(fixture.rows.reads.load(Ordering::SeqCst), 0);
    assert!(
        challenges(&response)[0].contains(r#"error="invalid_request""#),
        "{:?}",
        challenges(&response)
    );
}

/// RFC 6750 §3 and the ticket: no credential is a 401, and both schemes are
/// offered.
#[tokio::test]
async fn a_request_with_no_token_is_challenged_with_dpop_and_bearer() {
    let fixture = Fixture::new(&["openid"]).await;

    let response = fixture.call(HeaderMap::new(), None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let offered = challenges(&response);
    assert!(offered[0].starts_with("DPoP "), "{offered:?}");
    assert!(
        offered[0].contains(r#"error="invalid_token""#),
        "{offered:?}"
    );
    assert!(offered[1].starts_with("Bearer"), "{offered:?}");
}

/// RFC 9449 §7.1: a DPoP-bound token presented as a bearer token is refused,
/// however good the token itself is. The `cnf` names a key, and the `Bearer`
/// scheme presents none.
#[tokio::test]
async fn a_dpop_bound_token_is_refused_under_the_bearer_scheme() {
    let fixture = Fixture::new(&["openid"]).await;
    let mut headers = fixture.authorized_headers();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", fixture.access_token)).expect("header"),
    );

    let response = fixture.call(headers, None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        challenges(&response)[0].contains(r#"error="invalid_token""#),
        "{:?}",
        challenges(&response)
    );
}

// ---------------------------------------------------------------------------
// The proof (RFC 9449 §4.3 item 12, §7.1)
// ---------------------------------------------------------------------------

/// The `ath` must hash *this* token. A proof made for another one is a
/// captured proof being reused.
#[tokio::test]
async fn a_proof_whose_ath_names_another_token_is_refused() {
    let fixture = Fixture::new(&["openid"]).await;
    let mut headers = fixture.authorized_headers();
    headers.insert(
        DPOP_HEADER,
        HeaderValue::from_str(&fixture.proof_over("some other token", Some("GET")))
            .expect("header"),
    );

    let response = fixture.call(headers, None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        challenges(&response)[0].contains("DPoP error=\"invalid_dpop_proof\""),
        "{:?}",
        challenges(&response)
    );
}

/// RFC 9449 §4.3 item 12 makes `ath` mandatory at a protected resource, so a
/// proof without one is not a proof here.
#[tokio::test]
async fn a_proof_without_ath_is_refused_at_a_protected_resource() {
    let fixture = Fixture::new(&["openid"]).await;
    let mut headers = fixture.authorized_headers();
    headers.insert(
        DPOP_HEADER,
        HeaderValue::from_str(&fixture.proof_without_ath()).expect("header"),
    );

    let response = fixture.call(headers, None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A bound token with no proof beside it is a bearer token in a DPoP costume.
#[tokio::test]
async fn a_bound_token_with_no_proof_is_refused() {
    let fixture = Fixture::new(&["openid"]).await;
    let mut headers = fixture.authorized_headers();
    headers.remove(DPOP_HEADER);

    let response = fixture.call(headers, None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        challenges(&response)[0].contains(r#"error="invalid_token""#),
        "{:?}",
        challenges(&response)
    );
}

/// The proof must be for the key the token is bound to (RFC 9449 §6.1).
#[tokio::test]
async fn a_valid_proof_for_another_key_does_not_unlock_this_token() {
    let mut fixture = Fixture::new(&["openid"]).await;
    let headers = {
        // A perfectly good proof over the same token, signed by a key the
        // token was never bound to.
        fixture.dpop_key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("another key");
        fixture.authorized_headers()
    };

    let response = fixture.call(headers, None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// RFC 9449 §7.2: a deployment that issues nonces answers a proof without one
/// with a challenge and a fresh nonce, not with a 400.
#[tokio::test]
async fn a_resource_server_nonce_is_asked_for_with_a_challenge() {
    let mut fixture = Fixture::new(&["openid"]).await;
    fixture.dpop = DpopEndpoint::new(
        Arc::new(FakeReplay),
        Some(NonceIssuer::from_secret(b"a shared secret")),
    );

    let response = fixture.get().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        challenges(&response)[0].contains("use_dpop_nonce"),
        "{:?}",
        challenges(&response)
    );
    assert!(response.headers().contains_key(NONCE_HEADER));
}

// ---------------------------------------------------------------------------
// The token (OIDC Core §5.3.3, FAPI 2.0 SP §5.3.4)
// ---------------------------------------------------------------------------

/// An access token without `openid` is a credential for something else.
#[tokio::test]
async fn a_token_without_the_openid_scope_is_forbidden() {
    let fixture = Fixture::new(&["profile"]).await;

    let response = fixture.get().await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        challenges(&response)[0].contains(r#"error="insufficient_scope""#),
        "{:?}",
        challenges(&response)
    );
}

/// FAPI 2.0 SP §5.3.4 item 3: a denylisted `jti` is a revoked token.
#[tokio::test]
async fn a_denylisted_token_is_invalid() {
    let mut fixture = Fixture::new(&["openid"]).await;
    let jti = unverified_claim(&fixture.access_token, "jti");
    fixture.rows.denylisted = Some(jti);

    let response = fixture.get().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        challenges(&response)[0].contains(r#"error="invalid_token""#),
        "{:?}",
        challenges(&response)
    );
}

/// Revoking the grant reaches the tokens minted from it, even the ones whose
/// `jti` never made it onto the denylist.
#[tokio::test]
async fn a_token_from_a_revoked_grant_is_invalid() {
    let mut revoked = grant(&user(), &["openid", "email"]);
    let mut fixture = Fixture::with_grant(revoked.clone()).await;
    revoked.revoked_at = Some(now());
    fixture.rows.grant = Some(revoked);

    let response = fixture.get().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        challenges(&response)[0].contains(r#"error="invalid_token""#),
        "{:?}",
        challenges(&response)
    );
}

/// A token this server did not sign is not a token, whatever it says.
#[tokio::test]
async fn a_token_signed_by_a_foreign_key_is_refused() {
    let mut fixture = Fixture::new(&["openid"]).await;
    let stranger = Arc::new(LocalKeyStore::new());
    stranger
        .generate(&TenantId::new("demo"), SigningAlgorithm::DEFAULT)
        .expect("a key");
    // Same claims, another signature: the store the endpoint verifies against
    // is replaced after the token was minted.
    fixture.keys = stranger;

    let response = fixture.get().await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// The signed response (OIDC Core §5.3.2)
// ---------------------------------------------------------------------------

/// `userinfo_signed_response_alg` set → `application/jwt` with `iss` and `aud`.
#[tokio::test]
async fn a_signed_response_is_a_jwt_naming_the_issuer_and_the_client() {
    let mut fixture = Fixture::new(&["openid", "email"]).await;
    fixture.rows.signed_response_alg = Some(SigningAlgorithm::DEFAULT);

    let response = fixture.get().await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content type"),
        JWT_CONTENT_TYPE
    );
    let jwt = text_of(response).await;
    assert_eq!(unverified_claim(&jwt, "iss"), ISSUER);
    assert_eq!(unverified_claim(&jwt, "aud"), CLIENT);
    assert_eq!(unverified_claim(&jwt, "sub"), SUBJECT);
    assert_eq!(unverified_claim(&jwt, "email"), "ada@example.test");
}

/// The `alg` comes from the deployment's closed set (ADR-0003), so a signed
/// response is verifiable with a key from `/jwks`.
#[tokio::test]
async fn a_signed_response_is_signed_with_a_published_key() {
    let mut fixture = Fixture::new(&["openid"]).await;
    fixture.rows.signed_response_alg = Some(SigningAlgorithm::DEFAULT);

    let jwt = text_of(fixture.get().await).await;

    let header: Value = serde_json::from_slice(
        &B64.decode(jwt.split('.').next().expect("a header"))
            .expect("base64"),
    )
    .expect("JSON");
    let published = fixture
        .keys
        .published_keys(&TenantId::new("demo"))
        .await
        .expect("keys");
    assert_eq!(header["alg"], json!(SigningAlgorithm::DEFAULT.as_str()));
    assert!(
        published
            .iter()
            .any(|key| Some(key.kid.as_str()) == header["kid"].as_str()),
        "signed with a key that is not published: {header}"
    );
}

/// OIDC Core §5.3.2: a client that registered no algorithm gets the JSON
/// object, and the endpoint asks the client's registration rather than being
/// told by its caller.
#[tokio::test]
async fn a_client_that_registered_no_algorithm_still_gets_json() {
    let fixture = Fixture::new(&["openid", "email"]).await;
    assert_eq!(fixture.rows.signed_response_alg, None);

    let response = fixture.get().await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content type"),
        "application/json"
    );
}

/// Reads a claim out of a JWT without verifying it. Test-only: the endpoint
/// under test does the verifying, and a test that re-verified would only be
/// asserting that the same function agrees with itself.
fn unverified_claim(jwt: &str, name: &str) -> String {
    let payload = jwt.split('.').nth(1).expect("a payload");
    let claims: Value =
        serde_json::from_slice(&B64.decode(payload).expect("base64")).expect("JSON");
    claims[name]
        .as_str()
        .unwrap_or_else(|| panic!("no {name} claim in {claims}"))
        .to_owned()
}

/// The capability set is irrelevant to this endpoint, but the fixture above
/// would silently rot if `Capabilities` grew a field that changed the DPoP
/// endpoint's construction. This is the one line that would fail.
#[test]
fn the_default_deployment_issues_no_dpop_nonce() {
    assert!(!Capabilities::default().dpop_nonce);
}

// ---------------------------------------------------------------------------
// Certificate-bound access tokens (RFC 8705 §3)
// ---------------------------------------------------------------------------

/// A DER `Certificate` with the shape `ClientCertificate::from_der` reads and
/// nothing else in it. Nothing here is signed or validated: what this endpoint
/// compares is the SHA-256 of the bytes, and `serial` is what makes two of
/// these different certificates.
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

/// RFC 8705 §3.1: the holder of the certificate the `cnf` names is answered.
#[tokio::test]
async fn a_certificate_bound_token_is_answered_to_the_certificate_it_names() {
    // Arrange
    let held = certificate(1);
    let fixture = Fixture::certificate_bound(&["openid", "profile"], &held).await;

    // Act
    let response = fixture.call(fixture.bearer_headers(), None).await;

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let claims = body_of(response).await;
    assert_eq!(claims["sub"], json!(SUBJECT));
}

/// The whole point of §3: a token taken from one connection and presented on
/// another is not usable. Two certificates, one token.
#[tokio::test]
async fn a_certificate_bound_token_presented_under_another_certificate_is_refused() {
    // Arrange
    let held = certificate(1);
    let another = certificate(2);
    let mut fixture = Fixture::certificate_bound(&["openid"], &held).await;
    fixture.certificate = Some(another);

    // Act
    let response = fixture.call(fixture.bearer_headers(), None).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenges = challenges(&response);
    assert!(
        challenges
            .iter()
            .any(|value| value.contains("invalid_token")),
        "unexpected challenges: {challenges:?}"
    );
}

/// No certificate reached this server — the deployment has no mTLS, or the
/// caller connected past the proxy that forwards one. Either way there is
/// nothing to compare `x5t#S256` against, and answering would turn a
/// sender-constrained token into a bearer token.
#[tokio::test]
async fn a_certificate_bound_token_presented_with_no_certificate_is_refused() {
    // Arrange
    let held = certificate(1);
    let mut fixture = Fixture::certificate_bound(&["openid"], &held).await;
    fixture.certificate = None;

    // Act
    let response = fixture.call(fixture.bearer_headers(), None).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// RFC 8705 §3 binds the token; it does not define a scheme. A client
/// presenting a certificate-bound token under `DPoP` is claiming a binding its
/// token does not carry, and no DPoP proof can be checked against an
/// `x5t#S256`.
#[tokio::test]
async fn a_certificate_bound_token_is_not_presentable_under_the_dpop_scheme() {
    // Arrange
    let held = certificate(1);
    let fixture = Fixture::certificate_bound(&["openid"], &held).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("DPoP {}", fixture.access_token)).expect("header"),
    );
    headers.insert(
        DPOP_HEADER,
        HeaderValue::from_str(&fixture.proof()).expect("header"),
    );

    // Act
    let response = fixture.call(headers, None).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// The mirror of the rule above: a DPoP-bound token is not made presentable by
/// a certificate. The `cnf` decides, and it names a key nobody proved.
#[tokio::test]
async fn a_dpop_bound_token_is_not_answered_because_a_certificate_was_presented() {
    // Arrange
    let mut fixture = Fixture::new(&["openid"]).await;
    fixture.certificate = Some(certificate(1));

    // Act
    let response = fixture.call(fixture.bearer_headers(), None).await;

    // Assert
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
