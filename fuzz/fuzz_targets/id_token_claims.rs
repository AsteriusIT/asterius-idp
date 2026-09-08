//! `IdToken::build` — the claims set of an ID token, and `token_hash`.
//!
//! An ID token is an identity assertion, and the thing a relying party does
//! with it is *believe it*: the `sub` it carries becomes the user's account at
//! that RP, and the `nonce` it echoes is what ties the sign-in to the browser
//! that started it. Almost everything in it is computed by the authorization
//! server, and the one part that is not — the claims released by
//! `claims::resolve` — is a map whose keys came, ultimately, from a user record
//! and a `claims` request parameter.
//!
//! So the properties asserted here are the ones an RP's security depends on:
//!
//! * **Nothing released can take the place of a claim the server issues.**
//!   `sub`, `aud`, `acr`, `cnf`, `sid`, `nonce`, `at_hash` — the whole of
//!   `ClaimName::SERVER_ISSUED`. A released `sub` is a stored user attribute
//!   naming somebody else, and an RP has no way to tell.
//! * **`aud` is one client, as a string.** OIDC Core §3.1.3.7 makes a client
//!   reject a token carrying audiences it does not trust; a token audible to
//!   two clients is one that either can replay at the other.
//! * **`nonce` appears exactly when one was supplied, byte for byte.** OIDC
//!   Core §2: "The value is passed through unmodified". A rewritten nonce fails
//!   the client's comparison; a nonce that appears when none was sent is one
//!   the client never stored.
//! * **`at_hash` is the left-most half of the right hash.** Recomputed here
//!   from `sha2` directly, so the oracle and the code under test cannot share
//!   a mistake — in particular the "half of the digest, not 128 bits" one,
//!   which only shows up under EdDSA's SHA-512.
//! * **An ID token carries no authorisation.** No `cnf`, no `scope`, no
//!   `client_id`, no `authorization_details`. It must never be usable, or
//!   mistakable, as an access token (RFC 9068 §2.1).
//! * **Building is a pure function**, so two replicas answering one token
//!   request cannot hand a client two different identities.
#![no_main]

use arbitrary::Arbitrary;
use asterius_domain::{
    ClaimName, ClientId, Grant, GrantId, Issuer, SigningAlgorithm, SubjectId, TenantId,
};
use asterius_oidc::tokens::{Authentication, IdToken, IssuanceError, Session, token_hash};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256, Sha512};
use time::{Duration, OffsetDateTime};

/// Claim names worth spending the budget on: every reserved one, the ordinary
/// ones, and the near-misses. Random bytes are almost never any of these.
const NAMES: [&str; 18] = [
    "sub",
    "aud",
    "acr",
    "amr",
    "azp",
    "cnf",
    "sid",
    "nonce",
    "at_hash",
    "iss",
    "exp",
    "iat",
    "auth_time",
    "given_name",
    "name#ja-Kana-JP",
    "email",
    "",
    "\u{202e}given_name",
];

/// Access token spellings, including the ones that are not ASCII at all — the
/// hash is over bytes, and a caller could hand this anything.
const TOKENS: [&str; 5] = [
    "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
    "",
    "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhIn0.c2ln",
    "foobar",
    "\u{e9}\u{4e2d}\u{1f600}",
];

const ALGORITHMS: [SigningAlgorithm; 3] = [
    SigningAlgorithm::EdDsa,
    SigningAlgorithm::Es256,
    SigningAlgorithm::Ps256,
];

#[derive(Arbitrary, Debug)]
struct Input {
    released: Vec<(u8, u8)>,
    free_name: String,
    algorithm: u8,
    access_token: u8,
    free_token: String,
    nonce: Option<String>,
    session: Option<String>,
    acr: Option<String>,
    amr: Vec<String>,
    lifetime_seconds: i32,
    subject: String,
    client_id: String,
    issued_at: i32,
    authenticated_at: i32,
}

/// The oracle: OIDC Core §3.1.3.6 recomputed from primitives.
fn expected_hash(algorithm: SigningAlgorithm, token: &str) -> String {
    let digest: Vec<u8> = match algorithm {
        SigningAlgorithm::EdDsa => Sha512::digest(token.as_bytes()).to_vec(),
        SigningAlgorithm::Es256 | SigningAlgorithm::Ps256 => {
            Sha256::digest(token.as_bytes()).to_vec()
        }
    };
    B64.encode(&digest[..digest.len() / 2])
}

fn instant(seconds: i32) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::seconds(i64::from(seconds))
}

fuzz_target!(|input: Input| {
    let issuer = Issuer::parse("https://as.example/t/demo").expect("a fixed issuer");
    let algorithm = ALGORITHMS[usize::from(input.algorithm) % ALGORITHMS.len()];
    let access_token = if usize::from(input.access_token) == TOKENS.len() {
        input.free_token.as_str()
    } else {
        TOKENS[usize::from(input.access_token) % TOKENS.len()]
    };

    // `token_hash` is total and pure, whatever it is handed.
    let hash = token_hash(algorithm, access_token);
    assert_eq!(
        hash,
        expected_hash(algorithm, access_token),
        "at_hash disagrees with SHA-{} over {access_token:?}",
        if algorithm == SigningAlgorithm::EdDsa {
            512
        } else {
            256
        }
    );
    assert_eq!(
        hash.len(),
        if algorithm == SigningAlgorithm::EdDsa {
            43
        } else {
            22
        },
        "at_hash is not half a digest"
    );
    assert_eq!(hash, token_hash(algorithm, access_token), "at_hash is not pure");

    let client_id = if input.client_id.is_empty() {
        "billing".to_owned()
    } else {
        input.client_id.clone()
    };
    let issued_at = instant(input.issued_at);

    let mut grant = Grant::new(
        TenantId::new("demo"),
        ClientId::new(client_id.clone()),
        OffsetDateTime::UNIX_EPOCH,
    );
    grant.id = GrantId::new("2c1d4b1e-0000-4000-8000-000000000001");
    // An empty subject would be a grant no authorization flow can produce; the
    // `None` case is the client-credentials one, and it is covered below.
    grant.subject = (!input.subject.is_empty()).then(|| SubjectId::new(input.subject.clone()));

    let Ok(claimed) = grant.claim(issued_at) else {
        return;
    };

    let mut released = Map::new();
    for (name, value) in input.released.iter().take(32) {
        let name = if usize::from(*name) == NAMES.len() {
            input.free_name.clone()
        } else {
            NAMES[usize::from(*name) % NAMES.len()].to_owned()
        };
        released.insert(name, Value::from(i64::from(*value)));
    }

    let session = input
        .session
        .as_ref()
        .map(|raw| Session::new(&asterius_domain::SessionId::new(raw.clone())));

    let build = || {
        let mut token = IdToken::new(
            &issuer,
            &claimed,
            algorithm,
            Authentication {
                authenticated_at: instant(input.authenticated_at),
                acr: input.acr.clone(),
                amr: input.amr.iter().take(8).cloned().collect(),
            },
            access_token,
            issued_at,
        )
        .for_lifetime(Duration::seconds(i64::from(input.lifetime_seconds)))
        .releasing(released.clone());
        if let Some(nonce) = &input.nonce {
            token = token.with_nonce(nonce.clone());
        }
        if let Some(Ok(session)) = session.clone() {
            token = token.for_session(session);
        }
        token.build()
    };

    let first = build();
    assert_eq!(first, build(), "building an ID token is not deterministic");

    let Ok(unsigned) = first else {
        // A grant with no resource owner has no ID token to build, and that is
        // the only refusal that does not depend on the inputs above.
        if grant.subject.is_none() {
            // That it refuses, not which refusal wins. `IdToken::build`
            // checks the lifetime before the subject, so a grant that has
            // neither a resource owner nor a usable lifetime answers
            // `Lifetime` — and the order those two are tested in is an
            // implementation detail no caller can depend on.
            assert!(
                matches!(
                    build(),
                    Err(IssuanceError::NoSubject | IssuanceError::Lifetime)
                ),
                "a grant with no resource owner built an ID token"
            );
        }
        return;
    };

    // --- explicit typing and the algorithm the claims are correct under ----

    assert_eq!(unsigned.typ(), "JWT");
    assert_eq!(
        unsigned.required_algorithm(),
        Some(algorithm),
        "an ID token did not pin the algorithm its at_hash was computed for"
    );

    let claims = unsigned.into_claims();
    let object = claims.as_object().expect("a claims set is a JSON object");

    // --- everything OIDC Core §2 makes REQUIRED ----------------------------

    for required in ["iss", "sub", "aud", "exp", "iat"] {
        assert!(
            object.contains_key(required),
            "OIDC Core §2 requires {required}"
        );
    }
    assert_eq!(object["iss"], Value::String(issuer.as_str().to_owned()));
    assert_eq!(
        object["sub"],
        Value::String(input.subject.clone()),
        "the sub is not the one the grant recorded"
    );
    assert_eq!(
        object["aud"],
        Value::String(client_id.clone()),
        "an ID token was audienced somewhere other than its client"
    );
    assert!(
        object["aud"].is_string(),
        "an ID token carried more than one audience"
    );
    assert_eq!(object["azp"], Value::String(client_id.clone()));

    // --- auth_time is the authentication, always ---------------------------

    assert_eq!(
        object["auth_time"],
        Value::from(instant(input.authenticated_at).unix_timestamp()),
        "auth_time was not the time of the authentication"
    );

    // --- nonce (OIDC Core §2) ----------------------------------------------

    match &input.nonce {
        Some(nonce) => assert_eq!(
            object["nonce"],
            Value::String(nonce.clone()),
            "a nonce was rewritten on the way into an ID token"
        ),
        None => assert!(
            !object.contains_key("nonce"),
            "an ID token carried a nonce nobody sent"
        ),
    }

    // --- at_hash (OIDC Core §3.1.3.6) --------------------------------------

    assert_eq!(
        object["at_hash"],
        Value::String(expected_hash(algorithm, access_token)),
        "the at_hash claim is not the hash of the token that was issued"
    );

    // --- sid (Back-Channel Logout 1.0 §2.1) --------------------------------

    match session {
        Some(Ok(_)) => {
            let sid = object["sid"].as_str().expect("sid is a string");
            assert!(
                !sid.is_empty()
                    && sid.len() <= Session::MAX_LEN
                    && sid.bytes().all(|b| (0x21..=0x7e).contains(&b)),
                "a sid an RP cannot store round-tripped: {sid:?}"
            );
        }
        _ => assert!(
            !object.contains_key("sid"),
            "an ID token reported a session that was never given"
        ),
    }

    // --- nothing released displaced a claim the server issues --------------

    for name in released.keys() {
        assert!(
            !ClaimName::SERVER_ISSUED.contains(&name.as_str()),
            "a released {name} reached a built ID token"
        );
    }
    // And every server-issued claim in the token still holds the server's
    // value, not a released one: `released` only ever holds numbers.
    for name in ClaimName::SERVER_ISSUED {
        if let Some(value) = object.get(*name) {
            assert!(
                !value.is_number() || *name == "exp" || *name == "iat" || *name == "auth_time",
                "the server-issued claim {name} holds a released value"
            );
        }
    }

    // --- an ID token carries no authorisation (RFC 9068 §2.1) --------------

    for forbidden in ["cnf", "scope", "client_id", "authorization_details", "act"] {
        assert!(
            !object.contains_key(forbidden),
            "an ID token carried the access token claim {forbidden}"
        );
    }

    // --- lifetime and size --------------------------------------------------

    let iat = object["iat"].as_i64().expect("iat is a number");
    let exp = object["exp"].as_i64().expect("exp is a number");
    assert_eq!(iat, issued_at.unix_timestamp());
    let lifetime = exp - iat;
    assert!(
        lifetime > 0 && lifetime <= IdToken::MAX_LIFETIME.whole_seconds(),
        "an ID token lived for {lifetime}s"
    );
    assert!(
        claims.to_string().len() <= 8 * 1024,
        "a claims set past the guard was minted"
    );
});
