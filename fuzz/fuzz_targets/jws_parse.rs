//! The JWS compact-serialisation parser (RFC 7515 §7.1).
//!
//! This is the parser closest to an attacker: a JWT arrives from a client on
//! every token request, every DPoP proof and every client assertion, and it is
//! parsed *before* anything about it has been verified. The invariants asserted
//! here are the ones the rest of the server relies on:
//!
//! * a parsed token never carries an algorithm outside the allow-list, so a
//!   caller cannot be handed an `alg: none` token and forget to look;
//! * a token that parses does not verify under a key that did not sign it,
//!   whatever its header claims.
#![no_main]

use asterius_domain::SigningAlgorithm;
use asterius_jose::{SigningKey, jws};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// One key per algorithm, generated once: key generation is far slower than
/// parsing, and regenerating per iteration would fuzz aws-lc-rs instead of the
/// parser.
fn keys() -> &'static [SigningKey; 3] {
    static KEYS: OnceLock<[SigningKey; 3]> = OnceLock::new();
    KEYS.get_or_init(|| {
        [
            SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate"),
            SigningKey::generate(SigningAlgorithm::Es256).expect("generate"),
            SigningKey::generate(SigningAlgorithm::Ps256).expect("generate"),
        ]
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(unverified) = jws::parse(text) else {
        return;
    };

    // Whatever parsed, its algorithm is one we permit. RFC 8725 §3.1–3.2.
    assert!(
        SigningAlgorithm::parse(unverified.claimed_alg()).is_some(),
        "parse accepted an algorithm outside the allow-list: {:?}",
        unverified.claimed_alg()
    );

    // Whatever `typ` the token claims, reporting it must not invent one. The
    // *judgement* moved to `verify::Policy`, which is where the type rules are
    // now tested; what is left for this target is that the header is reported
    // faithfully, so the oracle is the header segment decoded here rather than
    // the parser's own answer — comparing the parser to itself would assert
    // nothing.
    let header = text
        .split('.')
        .next()
        .and_then(|segment| URL_SAFE_NO_PAD.decode(segment).ok())
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .expect("a token that parsed has a base64url JSON header");
    assert_eq!(
        unverified.claimed_typ(),
        header.get("typ").and_then(serde_json::Value::as_str),
        "claimed_typ does not match the header the token actually carries"
    );

    // No key here signed this input, so nothing may verify against one. A pass
    // would mean a forged token had been accepted.
    for key in keys() {
        let verifying = key.verifying_key().expect("public key");
        let Ok(parsed) = jws::parse(text) else { return };
        assert!(
            parsed.verify(&verifying).is_err(),
            "a token this key never signed verified against it"
        );
    }
});
