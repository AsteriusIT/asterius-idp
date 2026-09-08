//! The seam between the ID token builder and the signer (`ast-a05.12`).
//!
//! Three crates have to agree about one thing and none of them can check it
//! alone. `asterius-domain` stores the client's registered
//! `id_token_signed_response_alg`; `asterius-oidc` builds a claims set whose
//! `at_hash` is only correct under that algorithm; `asterius-jose` reaches for
//! a key. If the third one picks for itself, the second one's work is quietly
//! wrong and nothing in either crate's own tests can see it — which is exactly
//! how this bug existed: `Signer::sign` took no algorithm and preferred the
//! tenant's EdDSA key, so a client registered for ES256 was sent an ID token
//! signed with EdDSA carrying an `at_hash` computed with SHA-512.
//!
//! # What the client does with it
//!
//! OpenID Connect Dynamic Client Registration 1.0 §2 makes
//! `id_token_signed_response_alg` the "JWS `alg` algorithm \[JWA\] REQUIRED for
//! signing the ID Token issued to this Client" — the server's obligation.
//! OIDC Core §3.1.3.7 item 7 is the client's side: "The `alg` value SHOULD be
//! the default of `RS256` or the algorithm sent by the Client in the
//! `id_token_signed_response_alg` parameter during Registration."
//!
//! The `at_hash` is the half that fails silently. OIDC Core §3.1.3.6: its value
//! is "the base64url encoding of the left-most half of the hash of the octets
//! of the ASCII representation of the `access_token` value, where the hash
//! algorithm used is the hash algorithm used in the `alg` Header Parameter of
//! the ID Token's JOSE Header". A client that registered ES256 hashes with
//! SHA-256 and takes 128 bits; a token signed with EdDSA carries 256 bits of a
//! SHA-512 digest (RFC 8037 §3.1 leaves the variant to the key subtype, and
//! ADR-0003 pins EdDSA to Ed25519, which RFC 8032 §5.1 instantiates with
//! SHA-512). The two never match, and the client rejects its own token.
//!
//! These tests therefore check both halves, and from both ends: that the header
//! and the `at_hash` are what the *registration* asked for, and — reading only
//! the token, as a client does — that the `at_hash` is what the token's own
//! header implies. The second is the one that catches this bug, because the
//! builder's half was already right; it was the signer that overwrote the `alg`
//! above a correct hash. Every assertion runs for every algorithm the profile
//! permits, by iterating `SigningAlgorithm::ALL`.

use asterius_domain::{
    Capabilities, ClientId, ClientRegistration, DomainError, Grant, GrantId, Issuer, Signer,
    SigningAlgorithm, SubjectId, TenantId,
};
use asterius_jose::{LocalKeyStore, jws};
use asterius_oidc::tokens::id_token::ID_TOKEN_TYP;
use asterius_oidc::tokens::{Authentication, IdToken, token_hash};
use serde_json::{Value, json};
use time::OffsetDateTime;

const ISSUER: &str = "https://as.example/t/demo";
const CLIENT: &str = "billing";

/// A token that is not a JWS, so that nothing about the `at_hash` depends on
/// the access token's own signature.
const ACCESS_TOKEN: &str = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";

fn tenant() -> TenantId {
    TenantId::new("demo")
}

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a valid instant")
}

/// A registration document, as a client would send it, naming `alg`.
///
/// The point of going through `ClientRegistration::from_json` rather than
/// constructing the struct is that the registered value has to survive the
/// same parse the registration endpoint does. `id_token_signed_response_alg`
/// is the only field that varies.
fn registered_for(alg: SigningAlgorithm) -> ClientRegistration {
    ClientRegistration::from_json(
        &serde_json::to_vec(&json!({
            "client_name": "Billing",
            "redirect_uris": ["https://rp.example/cb"],
            "grant_types": ["authorization_code"],
            "scope": "openid",
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            "id_token_signed_response_alg": alg.as_str(),
        }))
        .expect("serialise"),
        Capabilities::default(),
    )
    .expect("a valid registration")
}

/// The claims of an ID token for a client registered for `alg`, unsigned.
fn unsigned_for(alg: SigningAlgorithm) -> asterius_oidc::tokens::UnsignedToken {
    let issuer = Issuer::parse(ISSUER).expect("issuer");
    let mut grant = Grant::new(tenant(), ClientId::new(CLIENT), now());
    grant.id = GrantId::new("2c1d4b1e-0000-4000-8000-000000000001");
    grant.subject = Some(SubjectId::new("SUBJECT-1"));
    let claimed = grant.claim(now()).expect("a live grant");

    IdToken::new(
        &issuer,
        &claimed,
        alg,
        Authentication {
            authenticated_at: now() - time::Duration::minutes(1),
            acr: None,
            amr: Vec::new(),
        },
        ACCESS_TOKEN,
        now(),
    )
    .build()
    .expect("a buildable token")
}

/// A tenant holding one active key per permitted algorithm.
fn keys_for_every_algorithm() -> LocalKeyStore {
    let store = LocalKeyStore::new();
    for algorithm in SigningAlgorithm::ALL {
        store.generate(&tenant(), algorithm).expect("generate");
    }
    store
}

/// Signs the way the token endpoint must: the builder's answer, passed
/// straight through. Nothing here chooses an algorithm.
async fn issue(store: &LocalKeyStore, unsigned: &asterius_oidc::tokens::UnsignedToken) -> String {
    store
        .sign(
            &tenant(),
            unsigned.required_algorithm(),
            unsigned.typ(),
            unsigned.claims(),
        )
        .await
        .expect("sign")
        .as_str()
        .to_owned()
}

/// The acceptance criterion of `ast-a05.12`, over the whole algorithm set.
///
/// Iterating `SigningAlgorithm::ALL` rather than naming three cases is
/// deliberate: a fourth algorithm added to the enum arrives here without anyone
/// remembering to extend the test, and either passes or fails on its own
/// merits. `token_hash` is a total function over the same enum, so "a new
/// algorithm whose hash nobody decided" cannot compile in the first place.
#[tokio::test]
async fn every_registered_algorithm_signs_its_own_id_token_and_at_hash() {
    let store = keys_for_every_algorithm();

    for algorithm in SigningAlgorithm::ALL {
        let registration = registered_for(algorithm);
        assert_eq!(
            registration.id_token_signed_response_alg, algorithm,
            "the registration document did not survive parsing"
        );

        let unsigned = unsigned_for(registration.id_token_signed_response_alg);
        let jwt = issue(&store, &unsigned).await;
        let parsed = jws::parse(&jwt).expect("parse");

        // OIDC Core §3.1.3.7 item 7: the header names the registered algorithm.
        assert_eq!(
            parsed.claimed_alg(),
            algorithm.as_str(),
            "a client registered for {algorithm} was sent {}",
            parsed.claimed_alg()
        );
        // RFC 8725 §3.11, and the reason an ID token cannot be replayed as an
        // access token.
        assert_eq!(parsed.claimed_typ(), Some(ID_TOKEN_TYP));

        // Read before `verify` consumes the token, so the hash below can be
        // taken from the header the way a client takes it.
        let header_alg =
            SigningAlgorithm::parse(parsed.claimed_alg()).expect("an allow-listed alg");

        // The header is not merely a claim: the signature checks under the
        // tenant's key of that algorithm. `Unverified::verify` refuses a key
        // whose algorithm disagrees with the header, so a pass here is the
        // header, the `kid` and the key material all agreeing.
        let verifying = store
            .verifying_key(&tenant(), &parsed.kid().expect("a kid"))
            .expect("lookup")
            .expect("the kid names a key this tenant holds");
        assert_eq!(verifying.algorithm(), algorithm);
        let payload = parsed.verify(&verifying).expect("verify");
        let claims: Value = serde_json::from_slice(&payload).expect("json");

        // OIDC Core §3.1.3.6: the hash the *client* will recompute — from the
        // algorithm it registered, which the assertion above has just proved is
        // also the one in the header. Both readings have to give one answer,
        // and `the_at_hash_is_the_one_the_tokens_own_header_implies` checks the
        // other reading on its own.
        assert_eq!(
            claims["at_hash"],
            json!(token_hash(algorithm, ACCESS_TOKEN)),
            "at_hash for {algorithm} is not the one that algorithm implies"
        );
        assert_eq!(
            claims["at_hash"],
            json!(token_hash(header_alg, ACCESS_TOKEN))
        );
        assert_eq!(claims["aud"], json!(CLIENT));
        assert_eq!(claims["iss"], json!(ISSUER));
    }
}

/// The check a conforming client actually performs, done the way it does it.
///
/// This one reads *nothing* from the registration. It takes the token, reads
/// the `alg` out of its own JOSE header, derives the hash from that — which is
/// what OIDC Core §3.1.3.6 says to do, word for word — and compares. That is
/// the sharpest statement of the bug: the builder computed a correct `at_hash`
/// for ES256 and the signer then wrote `EdDSA` above it, so the claim and the
/// header disagreed and every client checking `at_hash` rejected the token
/// while the server logged a success.
///
/// A test that compared `at_hash` against the *registered* algorithm cannot
/// see that, because the builder used the registered algorithm and got it
/// right; only the header can betray the signer.
#[tokio::test]
async fn the_at_hash_is_the_one_the_tokens_own_header_implies() {
    let store = keys_for_every_algorithm();

    for algorithm in SigningAlgorithm::ALL {
        let jwt = issue(&store, &unsigned_for(algorithm)).await;
        let parsed = jws::parse(&jwt).expect("parse");

        // Everything below comes from the token, as it would at a client.
        let header_alg = SigningAlgorithm::parse(parsed.claimed_alg())
            .expect("the header names an allow-listed algorithm");
        let verifying = store
            .verifying_key(&tenant(), &parsed.kid().expect("a kid"))
            .expect("lookup")
            .expect("present");
        let claims: Value =
            serde_json::from_slice(&parsed.verify(&verifying).expect("verify")).expect("json");

        assert_eq!(
            claims["at_hash"],
            json!(token_hash(header_alg, ACCESS_TOKEN)),
            "the at_hash does not match the alg in the token's own header ({header_alg})"
        );

        // And it is not merely self-consistent under some other algorithm: the
        // 43-character SHA-512 half and the 22-character SHA-256 half are not
        // interchangeable, so a token that swapped them is caught here too.
        for other in SigningAlgorithm::ALL {
            if token_hash(other, ACCESS_TOKEN) != token_hash(header_alg, ACCESS_TOKEN) {
                assert_ne!(claims["at_hash"], json!(token_hash(other, ACCESS_TOKEN)));
            }
        }
    }
}

/// The two tokens of one response are signed independently.
///
/// An access token is verified by a resource server, which resolves the key
/// from the published JWKS by `kid` and cares only that the `alg` is on the
/// allow-list. An ID token is verified by one client, against one registered
/// algorithm. Nothing requires them to agree, and coupling them would mean
/// either dragging the access token onto whatever the client registered or
/// dragging the ID token back onto the tenant default — which is this bug.
#[tokio::test]
async fn an_access_token_does_not_borrow_the_clients_id_token_algorithm() {
    let store = keys_for_every_algorithm();

    // The unconstrained call is what an access token makes: `None`, because
    // `AccessToken::build` sets no `required_algorithm`.
    let access = store
        .sign(&tenant(), None, "at+jwt", &json!({"sub": "SUBJECT-1"}))
        .await
        .expect("sign");
    assert_eq!(
        jws::parse(access.as_str()).expect("parse").claimed_alg(),
        SigningAlgorithm::DEFAULT.as_str()
    );

    for algorithm in SigningAlgorithm::ALL {
        let id = issue(&store, &unsigned_for(algorithm)).await;
        assert_eq!(
            jws::parse(&id).expect("parse").claimed_alg(),
            algorithm.as_str(),
            "the ID token followed the access token instead of the registration"
        );
    }
}

/// A tenant with no key for the algorithm a client registered.
///
/// This is an ordinary operational state, not a corrupt one: the key schedule
/// stages the tenant's default algorithm, so a tenant that has never been asked
/// for an ES256 key does not have one, and a client can register ES256 at any
/// moment. Three answers were available and two are wrong.
///
/// *Falling back* to another key recreates `ast-a05.12` exactly — the client
/// gets a token it rejects, and the server logs a success. *Generating* a key
/// inside the request is worse: `KeyState::Pending` exists so that verifiers
/// can fetch a key before anything is signed with it, so a key minted here
/// would publish a `kid` no cached JWKS has seen, and RSA generation on an
/// unauthenticated-reachable path is a denial-of-service lever besides.
///
/// So the request is refused, with an error a caller can act on:
/// `DomainError::NoSigningKey` names the algorithm and is distinct from
/// `DomainError::Storage`, because retrying will not fix it — an operator has
/// to add the key or stop accepting that registration. `ast-a05.13` moves the
/// refusal to registration time, where the client can be told about it.
#[tokio::test]
async fn a_tenant_without_the_clients_algorithm_refuses_rather_than_signing_with_another() {
    let store = LocalKeyStore::new();
    store
        .generate(&tenant(), SigningAlgorithm::DEFAULT)
        .expect("generate");

    for algorithm in SigningAlgorithm::ALL {
        let unsigned = unsigned_for(algorithm);
        let result = store
            .sign(
                &tenant(),
                unsigned.required_algorithm(),
                unsigned.typ(),
                unsigned.claims(),
            )
            .await;

        if algorithm == SigningAlgorithm::DEFAULT {
            let jwt = result.expect("the tenant has this key");
            assert_eq!(
                jws::parse(jwt.as_str()).expect("parse").claimed_alg(),
                algorithm.as_str()
            );
            continue;
        }

        let error = result.expect_err("must refuse, not substitute a key");
        assert!(
            matches!(
                error,
                DomainError::NoSigningKey { algorithm: named } if named == Some(algorithm)
            ),
            "expected NoSigningKey for {algorithm}, got {error}"
        );
    }
}
