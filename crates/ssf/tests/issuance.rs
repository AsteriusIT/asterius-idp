//! The SET issuance profile, end to end and against a foreign verifier.
//!
//! The unit tests in `crate::set` hold the claim set to SSF 1.0 §4. They
//! cannot answer the question a receiver actually asks — "does this token
//! verify against the JWKS this issuer publishes?" — because both halves of
//! that question would be this workspace's own code.
//!
//! So these tests sign with the production path (`LocalKeyStore` is the
//! tenant's `KeyStore` *and* its `Signer`, and `UnsignedSet::sign` goes
//! through the same port an ID token does) and verify with `jsonwebtoken`:
//! another JOSE implementation, reading the tenant's published JWKS. If the
//! two disagree, one of them is wrong and it is worth knowing which.
//!
//! The independence is at the JOSE layer, not below it. `jsonwebtoken` is
//! built here on `aws_lc_rs`, the backend `asterius-jose` also uses, because
//! its `rust_crypto` backend drags in the `rsa` crate and RUSTSEC-2023-0071
//! with it (see this crate's `Cargo.toml`). So these tests do not cross-check
//! the Ed25519 and P-256 primitives — they cross-check everything this
//! workspace built on top of them: the signing input, the base64url, `typ`,
//! `kid`, the shape of the published JWK and the claim validation a receiver
//! runs. A bug in one of those is what would actually break interoperability;
//! a bug in aws-lc-rs would not be caught here, and is not this test's to
//! catch.

use asterius_domain::{Issuer, KeyStore, SigningAlgorithm, TenantId};
use asterius_jose::LocalKeyStore;
use asterius_ssf::{
    EventUri, SET_TYP, SecurityEvent, Set, SimpleSubject, StreamAudience, Txn, UnsignedSet,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;
use time::OffsetDateTime;

const RECEIVER: &str = "https://receiver.example/events";
const EVENT_TYPE: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

fn tenant() -> TenantId {
    TenantId::parse("demo").expect("a tenant")
}

fn issuer() -> Issuer {
    Issuer::parse("https://as.example/t/demo").expect("an issuer")
}

fn audience() -> StreamAudience {
    StreamAudience::single(RECEIVER).expect("an audience")
}

fn event() -> SecurityEvent {
    SecurityEvent::new(EventUri::parse(EVENT_TYPE).expect("an event type"))
}

fn a_set() -> UnsignedSet {
    Set::about(SimpleSubject::opaque("u-1").expect("a subject"))
        .reporting(event())
        .issue(&issuer(), &audience(), OffsetDateTime::now_utc())
        .expect("a SET")
}

/// The independent half: the tenant's published JWKS, as `jsonwebtoken` sees
/// it, keyed by `kid`.
async fn published_key(keys: &LocalKeyStore, kid: &str) -> DecodingKey {
    let published = keys.published_keys(&tenant()).await.expect("a JWKS");
    let record = published
        .into_iter()
        .find(|record| record.kid.as_str() == kid)
        .expect("the signing key is in the published JWKS");
    let jwk: Jwk = serde_json::from_value(record.public_jwk).expect("a JWK jsonwebtoken can read");
    DecodingKey::from_jwk(&jwk).expect("a decoding key")
}

/// What a receiver checks: signature, issuer, audience — and nothing about
/// `exp`, because SSF 1.0 §4.1.7 says a SET has none.
fn receiver_validation(algorithm: Algorithm) -> Validation {
    let mut validation = Validation::new(algorithm);
    // `exp` is required by default. A SET that carried one would be violating
    // §4.1.7, so the receiver must not insist on it.
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.set_issuer(&[issuer().as_str()]);
    validation.set_audience(&[RECEIVER]);
    validation
}

/// ADR-0003's algorithms, as a foreign library names them.
fn foreign(algorithm: SigningAlgorithm) -> Algorithm {
    match algorithm {
        SigningAlgorithm::EdDsa => Algorithm::EdDSA,
        SigningAlgorithm::Es256 => Algorithm::ES256,
        other @ SigningAlgorithm::Ps256 => panic!("{other} is not a SET signing algorithm here"),
    }
}

/// SSF 1.0 §4.1.1: `typ` MUST be `secevent+jwt`, and the signature MUST check
/// out against the tenant's published key — under every algorithm ADR-0003
/// lets a tenant hold.
#[tokio::test]
async fn a_foreign_verifier_accepts_the_set_against_the_published_jwks() {
    for algorithm in [SigningAlgorithm::EdDsa, SigningAlgorithm::Es256] {
        let keys = LocalKeyStore::new();
        let kid = keys.generate(&tenant(), algorithm).expect("a key");

        let signed = a_set().sign(&keys, &tenant()).await.expect("a signed SET");
        let token = signed.jws().as_str();

        let header = decode_header(token).expect("a JOSE header");
        assert_eq!(header.typ.as_deref(), Some(SET_TYP), "§4.1.1");
        assert_eq!(header.alg, foreign(algorithm));
        assert_eq!(header.kid.as_deref(), Some(kid.as_str()));

        let key = published_key(&keys, kid.as_str()).await;
        let decoded = decode::<Value>(token, &key, &receiver_validation(foreign(algorithm)))
            .unwrap_or_else(|e| panic!("{algorithm}: an independent verifier refused it: {e}"));

        assert_eq!(decoded.claims["iss"], Value::from(issuer().as_str()));
        assert_eq!(decoded.claims["aud"], Value::from(RECEIVER));
        assert_eq!(decoded.claims["jti"], Value::from(signed.jti().as_str()));
        assert_eq!(decoded.claims["txn"], Value::from(signed.txn().as_str()));
        assert!(decoded.claims.get("sub").is_none(), "§4.1.2");
        assert!(decoded.claims.get("exp").is_none(), "§4.1.7");
        assert!(decoded.claims.get("sub_id").is_some(), "§3.1");
    }
}

/// A SET is not signed by a key of its own: it is signed by the key the rest
/// of the tenant signs with, which is the only reason a receiver resolving the
/// JWKS by `kid` finds it.
#[tokio::test]
async fn a_set_and_an_id_token_are_signed_by_the_same_key() {
    use asterius_domain::Signer as _;

    let keys = LocalKeyStore::new();
    let kid = keys
        .generate(&tenant(), SigningAlgorithm::EdDsa)
        .expect("a key");

    let signed = a_set().sign(&keys, &tenant()).await.expect("a signed SET");
    let id_token = keys
        .sign(&tenant(), None, "JWT", &serde_json::json!({"sub": "alice"}))
        .await
        .expect("an ID token");

    let set_kid = decode_header(signed.jws().as_str()).expect("header").kid;
    let id_kid = decode_header(id_token.as_str()).expect("header").kid;
    assert_eq!(set_kid.as_deref(), Some(kid.as_str()));
    assert_eq!(set_kid, id_kid);
}

/// A tenant with no key does not silently produce an unsigned or
/// self-signed SET.
#[tokio::test]
async fn a_tenant_with_no_active_key_cannot_issue_a_set() {
    let keys = LocalKeyStore::new();
    let refusal = a_set()
        .sign(&keys, &tenant())
        .await
        .expect_err("no key, no SET");
    assert!(matches!(refusal, asterius_ssf::SetError::Signing(_)));
}

/// Tampering with the payload of a delivered SET must not survive the
/// receiver's check. The forgery is built the way an attacker on the delivery
/// path would: keep the header and the signature, swap the claims.
#[tokio::test]
async fn a_receiver_rejects_a_set_whose_claims_were_swapped() {
    let keys = LocalKeyStore::new();
    let kid = keys
        .generate(&tenant(), SigningAlgorithm::EdDsa)
        .expect("a key");
    let signed = a_set().sign(&keys, &tenant()).await.expect("a signed SET");

    let segments: Vec<&str> = signed.jws().as_str().split('.').collect();
    let forged_claims = serde_json::json!({
        "iss": issuer().as_str(),
        "aud": RECEIVER,
        "iat": OffsetDateTime::now_utc().unix_timestamp(),
        "jti": "forged",
        "sub_id": {"format": "opaque", "id": "somebody-else"},
        "events": {EVENT_TYPE: {}},
    });
    let forged = format!(
        "{}.{}.{}",
        segments[0],
        B64.encode(serde_json::to_vec(&forged_claims).expect("json")),
        segments[2],
    );

    let key = published_key(&keys, kid.as_str()).await;
    assert!(
        decode::<Value>(&forged, &key, &receiver_validation(Algorithm::EdDSA)).is_err(),
        "a swapped subject verified"
    );
}

/// SSF 1.0 §4.1.9: every SET of one cause carries that cause's `txn`, and each
/// is still its own token — verified by a foreign library, so the sharing is
/// visible in the bytes a receiver reads and not only in our own accessors.
#[tokio::test]
async fn every_set_from_one_cause_reaches_the_receiver_with_the_same_txn() {
    let keys = LocalKeyStore::new();
    let kid = keys
        .generate(&tenant(), SigningAlgorithm::EdDsa)
        .expect("a key");
    let key = published_key(&keys, kid.as_str()).await;
    let cause = Txn::generate();

    let mut seen_jti = Vec::new();
    for receiver in ["https://one.example/events", "https://two.example/events"] {
        let audience = StreamAudience::single(receiver).expect("an audience");
        let signed = Set::about(SimpleSubject::opaque("u-1").expect("a subject"))
            .reporting(event())
            .caused_by(cause.clone())
            .issue(&issuer(), &audience, OffsetDateTime::now_utc())
            .expect("a SET")
            .sign(&keys, &tenant())
            .await
            .expect("a signed SET");

        let mut validation = receiver_validation(Algorithm::EdDSA);
        validation.set_audience(&[receiver]);
        let decoded = decode::<Value>(signed.jws().as_str(), &key, &validation).expect("verifies");

        assert_eq!(decoded.claims["txn"], Value::from(cause.as_str()));
        seen_jti.push(decoded.claims["jti"].clone());
    }

    assert_ne!(seen_jti[0], seen_jti[1], "one cause, but two tokens");
}

/// The profile's invariants, over whatever a caller can put in.
mod invariants {
    use super::{EVENT_TYPE, audience, event, issuer};
    use asterius_ssf::{ComplexSubject, SecurityEvent, Set, SimpleSubject, Subject, Txn};
    use proptest::prelude::*;
    use serde_json::Value;
    use time::OffsetDateTime;

    /// Anything a caller can legitimately name a subject with.
    fn any_subject() -> impl Strategy<Value = Subject> {
        let simple = prop_oneof![
            "[a-zA-Z0-9._-]{1,60}".prop_map(|id| SimpleSubject::opaque(&id).expect("opaque")),
            ("[a-z]{1,20}", "[a-z]{1,20}\\.example").prop_map(|(local, host)| {
                SimpleSubject::email(&format!("{local}@{host}")).expect("email")
            }),
            "[a-zA-Z0-9._-]{1,60}"
                .prop_map(|sub| SimpleSubject::iss_sub(&issuer(), &sub).expect("iss_sub")),
        ];
        prop_oneof![
            simple.clone().prop_map(Subject::from),
            (simple.clone(), simple).prop_map(|(user, session)| Subject::from(
                ComplexSubject::of_user(user).with_session(session)
            )),
        ]
    }

    fn any_event() -> impl Strategy<Value = SecurityEvent> {
        (any_subject(), proptest::option::of("[a-z]{1,20}")).prop_map(|(subject, detail)| {
            let mut built = event().about(&subject);
            if let Some(detail) = detail {
                built = built.with("reason", Value::from(detail));
            }
            built
        })
    }

    proptest! {
        /// §4.1.2, §4.1.7, §3.1 and §4.2.1 hold for every SET that can be
        /// built, not only the ones a unit test thought of.
        #[test]
        fn the_profile_holds_for_any_subject_and_event(
            subject in any_subject(),
            event in any_event(),
            shared in any::<bool>(),
            iat in 0_i64..4_000_000_000,
        ) {
            let now = OffsetDateTime::from_unix_timestamp(iat).expect("a time");
            let building = Set::about(subject).reporting(event);
            let set = if shared {
                building.caused_by(Txn::generate())
            } else {
                building
            }
            .issue(&issuer(), &audience(), now)
            .expect("a SET");

            let claims = set.claims();
            prop_assert!(claims.get("sub").is_none(), "§4.1.2");
            prop_assert!(claims.get("exp").is_none(), "§4.1.7");
            prop_assert!(claims["sub_id"].is_object(), "§3.1");
            prop_assert_eq!(&claims["iat"], &Value::from(iat));
            prop_assert_eq!(&claims["txn"], &Value::from(set.txn().as_str()));
            prop_assert_eq!(&claims["jti"], &Value::from(set.jti().as_str()));
            prop_assert_eq!(set.jti().as_str().len(), 22, "128 bits of base64url");

            let Value::Object(events) = &claims["events"] else {
                return Err(TestCaseError::fail("`events` is an object"));
            };
            prop_assert_eq!(events.len(), 1, "§4.2.1");
            prop_assert!(events.contains_key(EVENT_TYPE));
        }

        /// A `jti` a receiver deduplicates on never repeats.
        #[test]
        fn no_two_sets_share_a_jti(count in 2_usize..32) {
            let mut seen = std::collections::HashSet::new();
            for _ in 0..count {
                let set = Set::about(SimpleSubject::opaque("u-1").expect("a subject"))
                    .reporting(event())
                    .issue(&issuer(), &audience(), OffsetDateTime::now_utc())
                    .expect("a SET");
                prop_assert!(seen.insert(set.jti().clone()));
            }
        }
    }
}
