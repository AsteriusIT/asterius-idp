#![no_main]
//! `asterius_webauthn::authenticator_data`, both ceremonies.
//!
//! Packed binary with two attacker-chosen lengths in it — a credential id
//! length and, implicitly, where the COSE key starts. This is the target for
//! the slice arithmetic: a panic here is a denial of service anyone who can
//! reach registration can trigger.
//!
//! `verify_assertion` reads the same 37-byte header and stops there, so it is
//! fuzzed here rather than in a target of its own: the two entry points share
//! every bound this looks for, and one corpus that reaches both is worth more
//! than two that each reach half.

use asterius_webauthn::authenticator_data::{self, UserVerification};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // A fixed hash, so the RP-ID check is a real gate rather than something
    // the fuzzer has to guess its way past. The interesting inputs are the
    // ones that get past it, so the corpus is seeded toward them by making
    // the first 32 bytes matter in exactly one way.
    let rp_id_hash = asterius_domain::sha256(b"as.example");

    for uv in [UserVerification::Required, UserVerification::Discouraged] {
        let Ok(credential) = authenticator_data::verify_registration(data, &rp_id_hash, uv) else {
            continue;
        };

        // §6.5.2's ceiling.
        assert!(
            credential.credential_id.len() <= 1023,
            "a credential id over the specification's limit was accepted"
        );
        // §6.1: BS may not be set without BE.
        assert!(
            credential.backup_eligible || !credential.backup_state,
            "accepted a backed-up credential that cannot be backed up"
        );
        // §7.1 step 15.
        if uv == UserVerification::Required {
            assert!(credential.user_verified, "UV was required and not proved");
        }
        // Everything accepted came out of the input.
        assert!(credential.credential_id.len() <= data.len());
    }

    for uv in [UserVerification::Required, UserVerification::Discouraged] {
        let Ok(asserted) = authenticator_data::verify_assertion(data, &rp_id_hash, uv) else {
            continue;
        };

        // §6.1, on the ceremony that reports flags without attesting anything.
        assert!(
            asserted.backup_eligible || !asserted.backup_state,
            "accepted a backed-up credential that cannot be backed up"
        );
        if uv == UserVerification::Required {
            assert!(asserted.user_verified, "UV was required and not proved");
        }
        // The header is fixed-width, so anything shorter cannot have been
        // parsed into one.
        assert!(data.len() >= 37);

        // The two entry points must agree about the header they share: a
        // registration that succeeded and an assertion that succeeded on the
        // same bytes cannot disagree about the counter or the flags.
        if let Ok(credential) = authenticator_data::verify_registration(data, &rp_id_hash, uv) {
            assert_eq!(credential.sign_count, asserted.sign_count);
            assert_eq!(credential.user_verified, asserted.user_verified);
            assert_eq!(credential.backup_state, asserted.backup_state);
        }
    }
});
