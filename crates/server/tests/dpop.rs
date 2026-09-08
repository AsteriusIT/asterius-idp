//! DPoP at an endpoint, end to end, with a fake for the replay store.
//!
//! Everything here runs in memory: the replay guard is a `HashSet`. The
//! cryptography is real — every proof below is signed with a freshly generated
//! key and verified through `aws-lc-rs` — because a test that stubs the
//! signature check proves nothing about the one thing a proof is for.
//!
//! What these cover that the unit tests in `asterius_jose::dpop` cannot: the
//! header, the endpoint URL the `htu` is compared against, the `jti` reaching
//! the store exactly once, the `use_dpop_nonce` handshake as a pair of HTTP
//! responses, and the rule that a rejected proof costs nothing.

use asterius_domain::{
    DomainError, Issuer, ReplayCheck, ReplayGuard, ReplayPurpose, SigningAlgorithm, Tenant,
    TenantId, TenantStatus,
};
use asterius_jose::SigningKey;
use asterius_jose::dpop::{self, NonceIssuer};
use asterius_oidc::metadata::Endpoint;
use asterius_server::http::dpop::{DpopEndpoint, HEADER, INVALID_PROOF, NONCE_HEADER, USE_NONCE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use time::{Duration, OffsetDateTime};

const ISSUER: &str = "https://as.example/t/demo";
const TOKEN_ENDPOINT: &str = "https://as.example/t/demo/token";

// ---- fakes ---------------------------------------------------------------

/// A replay guard that remembers, and counts how often it was asked.
///
/// The count is the point of several tests below: a proof rejected for any
/// other reason must not have reached this at all.
#[derive(Debug, Default)]
struct FakeReplay {
    seen: Mutex<HashSet<(String, String, String, String)>>,
    claims: Mutex<usize>,
}

impl FakeReplay {
    fn claim_count(&self) -> usize {
        *self.claims.lock().expect("lock")
    }
}

#[async_trait::async_trait]
impl ReplayGuard for FakeReplay {
    async fn claim(
        &self,
        tenant: &TenantId,
        purpose: ReplayPurpose,
        subject: &str,
        jti: &str,
        _expires_at: OffsetDateTime,
    ) -> Result<ReplayCheck, DomainError> {
        *self.claims.lock().expect("lock") += 1;
        let key = (
            tenant.as_str().to_owned(),
            purpose.as_str().to_owned(),
            subject.to_owned(),
            jti.to_owned(),
        );
        if self.seen.lock().expect("lock").insert(key) {
            Ok(ReplayCheck::FirstUse)
        } else {
            Ok(ReplayCheck::Replay)
        }
    }
}

/// A store that is down. An unavailable store is not permission to accept.
#[derive(Debug)]
struct BrokenReplay;

#[async_trait::async_trait]
impl ReplayGuard for BrokenReplay {
    async fn claim(
        &self,
        _: &TenantId,
        _: ReplayPurpose,
        _: &str,
        _: &str,
        _: OffsetDateTime,
    ) -> Result<ReplayCheck, DomainError> {
        Err(DomainError::invalid("replay", "the store is down"))
    }
}

// ---- fixtures ------------------------------------------------------------

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("fixed instant")
}

fn tenant() -> Tenant {
    Tenant {
        id: TenantId::new("demo"),
        issuer: Issuer::parse(ISSUER).expect("issuer"),
        default_resource: "https://api.example/".to_owned(),
        custom_host: None,
        display_name: "demo".to_owned(),
        status: TenantStatus::Active,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
    }
}

fn key() -> SigningKey {
    SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate")
}

/// Signs a proof by hand, so a test can put anything at all in either half.
fn sign(key: &SigningKey, header: &Value, claims: &Value) -> String {
    let signing_input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(header).expect("header")),
        B64.encode(serde_json::to_vec(claims).expect("claims"))
    );
    let signature = key.sign(signing_input.as_bytes()).expect("sign");
    format!("{signing_input}.{}", B64.encode(signature))
}

fn header_for(key: &SigningKey) -> Value {
    let mut jwk = key.public_jwk().expect("jwk");
    if let Some(object) = jwk.as_object_mut() {
        object.remove("use");
    }
    json!({ "typ": "dpop+jwt", "alg": key.algorithm().as_str(), "jwk": jwk })
}

fn claims_for(jti: &str) -> Value {
    json!({
        "jti": jti,
        "htm": "POST",
        "htu": TOKEN_ENDPOINT,
        "iat": now().unix_timestamp(),
    })
}

fn proof(key: &SigningKey, jti: &str) -> String {
    sign(key, &header_for(key), &claims_for(jti))
}

fn headers(proofs: &[&str]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for value in proofs {
        map.append(HEADER, HeaderValue::from_str(value).expect("header value"));
    }
    map
}

/// The error code and status of a refusal, as a client would see them.
async fn rendered(response: axum::response::Response) -> (StatusCode, Value, HeaderMap) {
    let status = response.status();
    let response_headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&bytes).expect("an RFC 6749 §5.2 error object");
    (status, body, response_headers)
}

fn checker(replay: Arc<dyn ReplayGuard>) -> DpopEndpoint {
    DpopEndpoint::new(replay, None)
}

fn checker_with_nonces(replay: Arc<dyn ReplayGuard>) -> DpopEndpoint {
    DpopEndpoint::new(replay, Some(NonceIssuer::from_secret(b"a shared secret")))
}

/// The flag decides whether nonces are required, and the constructor is where
/// that decision lives — so that a second endpoint wired up later cannot make
/// it differently and reintroduce RFC 9449 §11.3's downgrade.
#[tokio::test]
async fn the_capability_flag_decides_whether_a_nonce_is_required() {
    let key = key();
    for (dpop_nonce, expected) in [(false, true), (true, false)] {
        let capabilities = asterius_domain::Capabilities {
            dpop_nonce,
            ..asterius_domain::Capabilities::default()
        };
        let checker = DpopEndpoint::for_capabilities(
            Arc::new(FakeReplay::default()),
            &capabilities,
            Some(b"a shared secret"),
        )
        .expect("build");

        let accepted = checker
            .check(
                &tenant(),
                Endpoint::Token,
                &Method::POST,
                &headers(&[&proof(&key, "flagged")]),
                now(),
            )
            .await
            .is_ok();
        assert_eq!(
            accepted,
            expected,
            "with dpop_nonce={dpop_nonce}, a nonce-less proof was {}",
            if accepted { "accepted" } else { "refused" }
        );
    }
}

// ---- the happy path ------------------------------------------------------

#[tokio::test]
async fn a_valid_proof_binds_the_request_to_its_key_and_spends_its_jti_once() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker(replay.clone());
    let key = key();

    let binding = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&proof(&key, "first")]),
            now(),
        )
        .await
        .expect("accepted")
        .expect("a proof was presented");

    // The thumbprint is the one a token's `cnf.jkt` will carry (RFC 9449 §6.1),
    // recomputed here from the key rather than read back from the proof.
    let expected = asterius_jose::thumbprint(&key.public_jwk().expect("jwk")).expect("thumbprint");
    assert_eq!(binding.jkt, expected);
    assert_eq!(replay.claim_count(), 1);
    // No nonces in this deployment, so nothing to hand back.
    assert_eq!(binding.next_nonce, None);
}

/// The endpoint URL is built from the tenant's issuer, so a proof for one
/// tenant's token endpoint is not a proof for another's — even though both are
/// served by this process on the same host.
#[tokio::test]
async fn a_proof_for_another_tenants_endpoint_is_refused() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker(replay.clone());
    let key = key();
    let mut claims = claims_for("cross-tenant");
    claims["htu"] = json!("https://as.example/t/other/token");

    let refusal = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&sign(&key, &header_for(&key), &claims)]),
            now(),
        )
        .await
        .expect_err("refused");

    assert_eq!(refusal.code(), INVALID_PROOF);
    assert_eq!(replay.claim_count(), 0, "a rejected proof spent a jti");
}

/// One proof, two endpoints. The `htu` binding is what stops a proof captured
/// at the token endpoint from being presented at the introspection endpoint.
#[tokio::test]
async fn a_proof_minted_for_one_endpoint_is_not_accepted_at_another() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker(replay.clone());
    let key = key();
    let proof = proof(&key, "moved");

    assert!(
        checker
            .check(
                &tenant(),
                Endpoint::Token,
                &Method::POST,
                &headers(&[&proof]),
                now()
            )
            .await
            .is_ok()
    );
    let refusal = checker
        .check(
            &tenant(),
            Endpoint::Introspection,
            &Method::POST,
            &headers(&[&proof]),
            now(),
        )
        .await
        .expect_err("refused at the wrong endpoint");
    assert_eq!(refusal.code(), INVALID_PROOF);
}

/// RFC 8414 §2: metadata describes actual behaviour. This is the only place
/// the two halves can be compared — `asterius-oidc` writes the document and
/// `asterius-jose` verifies the proofs, and neither depends on the other.
///
/// Every algorithm the document advertises must produce a proof this server
/// accepts. A list with an entry that does not work sends a client to a
/// signature it cannot get validated; a list missing one it does accept is
/// merely a smaller list, which is why the assertion runs in this direction.
#[tokio::test]
async fn every_advertised_dpop_algorithm_produces_an_acceptable_proof() {
    let document = asterius_oidc::metadata::provider_metadata(
        &Issuer::parse(ISSUER).expect("issuer"),
        &asterius_domain::Capabilities::default(),
    );
    let advertised = document["dpop_signing_alg_values_supported"]
        .as_array()
        .expect("RFC 9449 §5.1 defines this member")
        .clone();
    assert!(!advertised.is_empty());

    let checker = checker(Arc::new(FakeReplay::default()));
    for entry in advertised {
        let name = entry.as_str().expect("an alg name");
        let algorithm = SigningAlgorithm::parse(name)
            .unwrap_or_else(|| panic!("advertised {name}, which this server cannot parse"));
        let key = SigningKey::generate(algorithm).expect("generate");
        assert!(
            checker
                .check(
                    &tenant(),
                    Endpoint::Token,
                    &Method::POST,
                    &headers(&[&proof(&key, name)]),
                    now()
                )
                .await
                .is_ok(),
            "the document advertises {name}, but a {name} proof is refused"
        );
    }
}

// ---- the rejections the ticket requires ----------------------------------

/// RFC 9449 §4.3 item 1.
#[tokio::test]
async fn two_dpop_headers_are_refused() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker(replay.clone());
    let key = key();
    let one = proof(&key, "one");
    let two = proof(&key, "two");

    let refusal = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&one, &two]),
            now(),
        )
        .await
        .expect_err("refused");

    let (status, body, _) = rendered(refusal.into_response()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], json!(INVALID_PROOF));
    assert_eq!(
        replay.claim_count(),
        0,
        "a request refused before parsing reached the store"
    );
}

/// RFC 9449 §4.3 item 8, with RFC 9110 §9.1's case sensitivity.
#[tokio::test]
async fn a_proof_for_the_wrong_method_is_refused() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker(replay.clone());
    let key = key();

    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let refusal = checker
            .check(
                &tenant(),
                Endpoint::Token,
                &method,
                &headers(&[&proof(&key, "wrong-method")]),
                now(),
            )
            .await
            .expect_err("refused");
        assert_eq!(refusal.code(), INVALID_PROOF, "{method} was accepted");
    }
    assert_eq!(replay.claim_count(), 0);
}

/// RFC 9449 §4.3 item 9.
#[tokio::test]
async fn a_proof_for_the_wrong_url_is_refused() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker(replay.clone());

    for htu in [
        "https://as.example/t/demo/par",
        "https://attacker.example/t/demo/token",
        "http://as.example/t/demo/token",
        "https://as.example/t/demo/token/",
        "https://as.example:8443/t/demo/token",
        "not a uri at all",
    ] {
        let key = key();
        let mut claims = claims_for("wrong-url");
        claims["htu"] = json!(htu);
        let refusal = checker
            .check(
                &tenant(),
                Endpoint::Token,
                &Method::POST,
                &headers(&[&sign(&key, &header_for(&key), &claims)]),
                now(),
            )
            .await
            .expect_err("refused");
        assert_eq!(refusal.code(), INVALID_PROOF, "htu {htu:?} was accepted");
    }
    assert_eq!(replay.claim_count(), 0);
}

/// RFC 9449 §11.1: the `jti` is what makes a captured proof single use.
#[tokio::test]
async fn a_replayed_jti_is_refused() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker(replay.clone());
    let key = key();
    let proof = proof(&key, "used-twice");

    assert!(
        checker
            .check(
                &tenant(),
                Endpoint::Token,
                &Method::POST,
                &headers(&[&proof]),
                now()
            )
            .await
            .is_ok(),
        "the first use was refused"
    );

    let refusal = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&proof]),
            now(),
        )
        .await
        .expect_err("the second use was accepted");
    assert_eq!(refusal.code(), INVALID_PROOF);
    assert_eq!(replay.claim_count(), 2);
}

/// Two keys may choose the same `jti`: the store is namespaced by thumbprint,
/// so one client cannot burn another's identifiers.
#[tokio::test]
async fn two_keys_may_choose_the_same_jti() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker(replay.clone());

    for _ in 0..2 {
        let key = key();
        assert!(
            checker
                .check(
                    &tenant(),
                    Endpoint::Token,
                    &Method::POST,
                    &headers(&[&proof(&key, "1")]),
                    now()
                )
                .await
                .is_ok(),
            "a key was denied a jti another key had used"
        );
    }
}

/// RFC 9449 §4.2: "It MUST NOT contain a private key."
#[tokio::test]
async fn a_proof_whose_jwk_carries_private_material_is_refused() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker(replay.clone());

    for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let key = key();
        let mut header = header_for(&key);
        header["jwk"][member] = json!("c2VjcmV0");
        let refusal = checker
            .check(
                &tenant(),
                Endpoint::Token,
                &Method::POST,
                &headers(&[&sign(&key, &header, &claims_for("private"))]),
                now(),
            )
            .await
            .expect_err("refused");
        assert_eq!(
            refusal.code(),
            INVALID_PROOF,
            "a jwk carrying `{member}` was accepted"
        );
        assert_eq!(
            format!("{:?}", refusal.detail()),
            format!("{:?}", Some(&dpop::DpopError::PrivateKeyMaterial)),
            "`{member}` was refused for the wrong reason"
        );
    }
    assert_eq!(replay.claim_count(), 0);
}

/// RFC 9449 §11.1 on the old end, FAPI 2.0 SP §5.3.2.1 item 13 on the new.
#[tokio::test]
async fn an_iat_outside_the_window_is_refused() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker(replay.clone());
    let window = dpop::DEFAULT_MAX_AGE.whole_seconds();

    for offset in [-window - 1, -3600, 11, 61, 86_400] {
        let key = key();
        let mut claims = claims_for("stale");
        claims["iat"] = json!(now().unix_timestamp() + offset);
        let refusal = checker
            .check(
                &tenant(),
                Endpoint::Token,
                &Method::POST,
                &headers(&[&sign(&key, &header_for(&key), &claims)]),
                now(),
            )
            .await
            .expect_err("refused");
        assert_eq!(
            refusal.code(),
            INVALID_PROOF,
            "an iat {offset}s away was accepted"
        );
    }

    // And the two edges that must be accepted: as old as the window allows,
    // and the ten seconds ahead FAPI 2.0 SP §5.3.2.1 item 13 requires.
    for offset in [-window, 0, 10] {
        let key = key();
        let mut claims = claims_for("fresh");
        claims["iat"] = json!(now().unix_timestamp() + offset);
        assert!(
            checker
                .check(
                    &tenant(),
                    Endpoint::Token,
                    &Method::POST,
                    &headers(&[&sign(&key, &header_for(&key), &claims)]),
                    now()
                )
                .await
                .is_ok(),
            "an iat {offset}s away was refused"
        );
    }
}

/// An unavailable replay store must not become permission to accept a replay.
#[tokio::test]
async fn an_unavailable_replay_store_refuses_rather_than_accepting() {
    let checker = checker(Arc::new(BrokenReplay));
    let key = key();
    let refusal = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&proof(&key, "store-down")]),
            now(),
        )
        .await
        .expect_err("refused");

    let (status, body, _) = rendered(refusal.into_response()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], json!("temporarily_unavailable"));
}

// ---- the nonce handshake (RFC 9449 §8) -----------------------------------

/// The whole exchange, as a client sees it: a proof with no nonce is refused
/// with `use_dpop_nonce` and a `DPoP-Nonce` header, and the retry carrying that
/// value is accepted.
#[tokio::test]
async fn a_nonce_deployment_refuses_once_and_then_accepts_the_retry() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker_with_nonces(replay.clone());
    let key = key();

    let refusal = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&proof(&key, "no-nonce")]),
            now(),
        )
        .await
        .expect_err("refused");
    assert_eq!(refusal.code(), USE_NONCE);
    let supplied = refusal.nonce().expect("a nonce to retry with").to_owned();

    let (status, body, response_headers) = rendered(refusal.into_response()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], json!(USE_NONCE));
    assert_eq!(
        response_headers
            .get(NONCE_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(supplied.as_str())
    );
    // RFC 9449 §8.2: a response carrying a nonce must not be cached.
    assert_eq!(
        response_headers
            .get(axum::http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(replay.claim_count(), 0, "a nonce-less proof spent a jti");

    // The retry.
    let mut claims = claims_for("with-nonce");
    claims["nonce"] = json!(supplied);
    let binding = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&sign(&key, &header_for(&key), &claims)]),
            now(),
        )
        .await
        .expect("the retry was refused")
        .expect("a proof was presented");

    // RFC 9449 §8.2's efficient path: the success carries the next nonce, so
    // the client never has to be told `use_dpop_nonce` again.
    assert_eq!(binding.next_nonce.as_deref(), Some(supplied.as_str()));
    let mut response = axum::response::Response::new(axum::body::Body::empty());
    DpopEndpoint::supply_nonce(&mut response, &binding);
    assert_eq!(
        response
            .headers()
            .get(NONCE_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(supplied.as_str())
    );
}

/// A nonce this server never issued is refused, and the client is handed one
/// it can use — the mismatch case RFC 9449 §8 calls self-correcting.
#[tokio::test]
async fn a_foreign_nonce_is_refused_with_a_usable_replacement() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker_with_nonces(replay.clone());
    let key = key();
    let mut claims = claims_for("guessed");
    claims["nonce"] = json!("a value the client made up");

    let refusal = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&sign(&key, &header_for(&key), &claims)]),
            now(),
        )
        .await
        .expect_err("refused");
    assert_eq!(refusal.code(), USE_NONCE);
    let supplied = refusal.nonce().expect("a replacement nonce").to_owned();

    let mut retry = claims_for("retried");
    retry["nonce"] = json!(supplied);
    assert!(
        checker
            .check(
                &tenant(),
                Endpoint::Token,
                &Method::POST,
                &headers(&[&sign(&key, &header_for(&key), &retry)]),
                now()
            )
            .await
            .is_ok(),
        "the nonce this server just supplied was not accepted"
    );
}

/// A nonce is bound to the tenant that issued it. RFC 9449 §9: a nonce "should
/// be used only at the issuing server", and two tenants are two issuers.
#[tokio::test]
async fn a_nonce_from_another_tenant_is_refused() {
    let issuer = NonceIssuer::from_secret(b"a shared secret");
    let elsewhere = issuer.issue("https://as.example/t/other", now());

    let checker = checker_with_nonces(Arc::new(FakeReplay::default()));
    let key = key();
    let mut claims = claims_for("cross-tenant-nonce");
    claims["nonce"] = json!(elsewhere);

    let refusal = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&sign(&key, &header_for(&key), &claims)]),
            now(),
        )
        .await
        .expect_err("refused");
    assert_eq!(refusal.code(), USE_NONCE);
}

/// The boundary the design turns on: a nonce handed out at any instant is
/// still good a whole window later, so a client that retries promptly never
/// loops. The other direction — a nonce two windows old — is refused.
#[tokio::test]
async fn a_nonce_survives_the_window_boundary_but_not_two() {
    let issuer = NonceIssuer::from_secret(b"a shared secret");
    let window = issuer.window();
    let nonce = issuer.issue(ISSUER, now());
    let checker = checker_with_nonces(Arc::new(FakeReplay::default()));
    let key = key();

    let with_nonce = |jti: &str, at: OffsetDateTime| {
        let mut claims = claims_for(jti);
        claims["nonce"] = json!(nonce);
        claims["iat"] = json!(at.unix_timestamp());
        sign(&key, &header_for(&key), &claims)
    };

    let later = now() + window;
    assert!(
        checker
            .check(
                &tenant(),
                Endpoint::Token,
                &Method::POST,
                &headers(&[&with_nonce("boundary", later)]),
                later
            )
            .await
            .is_ok(),
        "a nonce expired inside the window it was issued for"
    );

    let much_later = now() + window * 3;
    let refusal = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&with_nonce("stale", much_later)]),
            much_later,
        )
        .await
        .expect_err("a three-window-old nonce was accepted");
    assert_eq!(refusal.code(), USE_NONCE);
}

/// RFC 9449 §11.3, made deployment-wide: with the feature on, no proof is
/// accepted without a nonce, whether or not this client has been handed one.
#[tokio::test]
async fn a_nonce_deployment_never_accepts_a_proof_without_one() {
    let checker = checker_with_nonces(Arc::new(FakeReplay::default()));
    let key = key();
    for jti in ["a", "b", "c"] {
        assert_eq!(
            checker
                .check(
                    &tenant(),
                    Endpoint::Token,
                    &Method::POST,
                    &headers(&[&proof(&key, jti)]),
                    now()
                )
                .await
                .expect_err("accepted without a nonce")
                .code(),
            USE_NONCE
        );
    }
}

/// A deployment with nonces switched off must not start requiring one because
/// a client volunteered a value, and must not hand one back.
#[tokio::test]
async fn a_deployment_without_nonces_ignores_one_and_supplies_none() {
    let checker = checker(Arc::new(FakeReplay::default()));
    let key = key();
    let mut claims = claims_for("volunteered");
    claims["nonce"] = json!("whatever the client felt like");

    let binding = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&sign(&key, &header_for(&key), &claims)]),
            now(),
        )
        .await
        .expect("accepted")
        .expect("a proof was presented");
    assert_eq!(binding.next_nonce, None);

    let mut response = axum::response::Response::new(axum::body::Body::empty());
    DpopEndpoint::supply_nonce(&mut response, &binding);
    assert!(response.headers().get(NONCE_HEADER).is_none());
}

// ---- the response shape ---------------------------------------------------

/// Every refusal is an RFC 6749 §5.2 error object, and none of them echoes the
/// request back — this endpoint is reachable before client authentication.
#[tokio::test]
async fn a_refusal_never_echoes_the_request() {
    let checker = checker(Arc::new(FakeReplay::default()));
    let key = key();
    let mut claims = claims_for("<script>alert(1)</script>");
    claims["htu"] = json!("https://attacker.example/\"><script>");

    let refusal = checker
        .check(
            &tenant(),
            Endpoint::Token,
            &Method::POST,
            &headers(&[&sign(&key, &header_for(&key), &claims)]),
            now(),
        )
        .await
        .expect_err("refused");
    let (_, body, _) = rendered(refusal.into_response()).await;
    let description = body["error_description"]
        .as_str()
        .expect("a human-readable description")
        .to_owned();
    for injected in ["<script>", "alert(1)", "attacker.example", "\">"] {
        assert!(
            !description.contains(injected),
            "the refusal echoed {injected:?} back: {description}"
        );
    }
}

/// A proof older than the window is refused even if its `jti` is fresh, and a
/// fresh proof is refused if its `jti` is not — the two defences are separate.
#[tokio::test]
async fn the_age_window_and_the_jti_are_independent_defences() {
    let replay = Arc::new(FakeReplay::default());
    let checker = checker(replay.clone());
    let key = key();

    // Fresh proof, spent jti.
    let first = proof(&key, "shared");
    assert!(
        checker
            .check(
                &tenant(),
                Endpoint::Token,
                &Method::POST,
                &headers(&[&first]),
                now()
            )
            .await
            .is_ok()
    );
    assert!(
        checker
            .check(
                &tenant(),
                Endpoint::Token,
                &Method::POST,
                &headers(&[&first]),
                now()
            )
            .await
            .is_err()
    );

    // Unspent jti, stale proof.
    let mut claims = claims_for("never-used");
    claims["iat"] = json!((now() - dpop::DEFAULT_MAX_AGE - Duration::seconds(1)).unix_timestamp());
    assert!(
        checker
            .check(
                &tenant(),
                Endpoint::Token,
                &Method::POST,
                &headers(&[&sign(&key, &header_for(&key), &claims)]),
                now()
            )
            .await
            .is_err()
    );
    // And it never reached the store, so a stream of stale proofs cannot fill it.
    assert_eq!(replay.claim_count(), 2);
}
