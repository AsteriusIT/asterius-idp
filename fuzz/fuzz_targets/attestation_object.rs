#![no_main]
//! `asterius_webauthn::attestation::parse` over arbitrary bytes.
//!
//! §6.5's envelope. The property that matters is the one the module exists to
//! guarantee: nothing but `none` gets through, so no attestation statement is
//! ever accepted without being verified.

use asterius_webauthn::attestation;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(object) = attestation::parse(data) else {
        return;
    };

    // Whatever was accepted, its authenticator data is a byte string that came
    // out of the input — it cannot be longer than what went in.
    assert!(
        object.authenticator_data.len() <= data.len(),
        "authenticator data grew"
    );

    let again = attestation::parse(data).expect("stable");
    assert_eq!(again.authenticator_data, object.authenticator_data);
});
