//! Opening a private key that came out of a database row.
//!
//! Everything `LocalKek::open` reads — ciphertext, nonce, the `kek_id` — is a
//! column of `signing_keys`, which is precisely what an attacker with SQL
//! access edits. The AEAD is the whole defence, so the invariants asserted here
//! are the ones that make a tampered row useless rather than dangerous:
//!
//! * arbitrary bytes never open into a private key;
//! * a genuine ciphertext opens to exactly what was sealed, and to nothing else
//!   under any other binding — a row moved to another tenant, relabelled to the
//!   other purpose, or paired with a different `kid` must fail;
//! * nothing panics, whatever the row holds. A row that crashes the process on
//!   read is a denial of service that survives every restart.
#![no_main]

use asterius_domain::keys::{KeyPurpose, SigningAlgorithm};
use asterius_domain::{Kid, TenantId};
use asterius_jose::{KeyBinding, LocalKek, WrappedKey};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// One KEK, built once. Regenerating it per iteration would fuzz AES key
/// scheduling rather than the envelope.
fn kek() -> &'static LocalKek {
    static KEK: OnceLock<LocalKek> = OnceLock::new();
    KEK.get_or_init(|| LocalKek::from_bytes(&[0x5a; 32]).expect("a 32-byte KEK"))
}

fuzz_target!(|data: &[u8]| {
    let tenant = TenantId::new("demo");
    let kid = Kid::new("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    let binding = KeyBinding::new(&tenant, &kid, KeyPurpose::Signing, SigningAlgorithm::EdDsa);

    // The row as the fuzzer wrote it. Split so that both the nonce and the
    // ciphertext are attacker-chosen, which is what an `UPDATE` gives them.
    if data.len() > 12 {
        let (nonce, ciphertext) = data.split_at(12);
        if let Ok(forged) = WrappedKey::from_parts(kek().id(), nonce.to_vec(), ciphertext.to_vec())
        {
            assert!(
                kek().open(binding, &forged).is_err(),
                "arbitrary bytes opened as a private key"
            );
        }
    }

    // A genuine sealing of the same bytes, to check the other direction: it
    // opens, it opens to what went in, and it opens under nothing else.
    let sealed = kek().seal(binding, data).expect("seal");
    let opened = kek()
        .open(binding, &sealed)
        .expect("a sealed key must open");
    assert_eq!(
        opened.as_slice(),
        data,
        "the plaintext changed in the envelope"
    );
    assert!(
        !sealed.ciphertext().is_empty() && sealed.ciphertext() != data,
        "the ciphertext is the plaintext"
    );

    let elsewhere = TenantId::new("other");
    let other_kid = Kid::new("a-different-thumbprint");
    for wrong in [
        KeyBinding::new(
            &elsewhere,
            &kid,
            KeyPurpose::Signing,
            SigningAlgorithm::EdDsa,
        ),
        KeyBinding::new(
            &tenant,
            &other_kid,
            KeyPurpose::Signing,
            SigningAlgorithm::EdDsa,
        ),
        KeyBinding::new(
            &tenant,
            &kid,
            KeyPurpose::Encryption,
            SigningAlgorithm::EdDsa,
        ),
        KeyBinding::new(&tenant, &kid, KeyPurpose::Signing, SigningAlgorithm::Es256),
    ] {
        assert!(
            kek().open(wrong, &sealed).is_err(),
            "a private key opened under a binding it was not sealed with"
        );
    }
});
