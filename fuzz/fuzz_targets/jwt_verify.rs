//! The JWT verifier, over arbitrary input.
//!
//! This is the function every attacker-supplied JWT goes through — a client
//! assertion, a DPoP proof, a request object. The invariant is blunt and is the
//! only one that matters: **nothing verifies**. The resolver here offers keys
//! that signed none of the fuzzer's input, so a success would mean a forged
//! token was accepted.
#![no_main]

use asterius_domain::{Kid, SigningAlgorithm};
use asterius_jose::{Policy, SigningKey, TypRule, VerifyingKey, verify};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use time::OffsetDateTime;

/// Keys generated once: generating per iteration would fuzz aws-lc-rs rather
/// than the verifier.
fn keys() -> &'static Vec<VerifyingKey> {
    static KEYS: OnceLock<Vec<VerifyingKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        SigningAlgorithm::ALL
            .into_iter()
            .map(|alg| {
                SigningKey::generate(alg)
                    .expect("generate")
                    .verifying_key()
                    .expect("public key")
            })
            .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };

    let resolver = |_: Option<&Kid>| keys().clone();
    let now = OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("fixed instant");

    // Every typ rule and every algorithm combination a caller might ask for, so
    // the policy checks are exercised rather than only the parser. The
    // `OptionalOneOf` rules matter most here: they are the ones that accept a
    // token with no `typ` at all, so they are where a parser that mishandles an
    // absent header would show up.
    for typ in [
        TypRule::Exactly("at+jwt"),
        TypRule::Exactly("dpop+jwt"),
        TypRule::Exactly("oauth-authz-req+jwt"),
        TypRule::Exactly("logout+jwt"),
        TypRule::OptionalOneOf(&["JWT"]),
        TypRule::OptionalOneOf(&[]),
    ] {
        for algorithms in [
            SigningAlgorithm::ALL.to_vec(),
            vec![SigningAlgorithm::EdDsa],
            Vec::new(),
        ] {
            let policy = Policy::new(typ.clone(), algorithms)
                .issued_by("https://client.example")
                .for_audience("https://as.example/t/demo");

            assert!(
                verify(token, &policy, &resolver, now).is_err(),
                "a token no offered key signed was accepted as {typ:?}"
            );
        }
    }
});
