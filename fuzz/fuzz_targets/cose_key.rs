#![no_main]
//! `asterius_webauthn::cose::parse` over arbitrary bytes.
//!
//! The credential public key is CBOR chosen by whoever can reach the
//! registration endpoint. What is asserted is not that any particular byte
//! string parses, but that the parser is total: it answers, and what it
//! answers is stable.

use asterius_webauthn::cose;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(key) = cose::parse(data) else {
        return;
    };

    // An accepted key is one of the three this server can verify with, and it
    // kept the bytes it was given: verifying an assertion later means handing
    // *these* to aws-lc-rs, so a parser that rewrote them would be changing
    // what the key is.
    assert!(
        cose::CoseAlgorithm::ALL.contains(&key.algorithm()),
        "accepted an algorithm outside the allow-list"
    );
    assert_eq!(
        key.encoded(),
        data,
        "the parser did not keep the bytes it was given"
    );

    // Deterministic. A parser whose answer depends on anything but its input
    // cannot be reasoned about from a crash artefact.
    let again = cose::parse(data).expect("a key that parsed once parses again");
    assert_eq!(again, key);
});
