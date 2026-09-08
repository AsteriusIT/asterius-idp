//! `request_uri` references — RFC 9126 §2.2, §7.1.
//!
//! A `request_uri` is a bearer reference: whoever holds one can begin an
//! authorization flow as the client it was issued to. `digest_of` is the
//! gatekeeper, and the properties that matter are narrow:
//!
//! * **A value this server could not have minted never yields a digest.** The
//!   shape check runs before the database is touched, so a flood of guesses
//!   costs a comparison rather than a query — most of what §7.1 asks for.
//! * **Accepting is deterministic and total.** The same input always gives the
//!   same digest, and no input panics.
//! * **The digest is never the reference.** A leaked row must not be usable.
#![no_main]

use asterius_oidc::par::{MintedRequestUri, REQUEST_URI_PREFIX, digest_of};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // The raw input, and the same input dressed as one of ours — so the target
    // spends its budget on the reference rather than on the constant prefix.
    for candidate in [text.to_owned(), format!("{REQUEST_URI_PREFIX}{text}")] {
        let Ok(digest) = digest_of(&candidate) else {
            continue;
        };

        // A hex SHA-256, always.
        assert_eq!(digest.len(), 64, "accepted {candidate:?} -> {digest}");
        assert!(
            digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "digest is not lower-case hex: {digest}"
        );

        // Deterministic: a lookup key that varied per call would make every
        // reference single-use by accident and none of them findable.
        assert_eq!(digest_of(&candidate).as_deref(), Ok(digest.as_str()));

        // Accepting implies the shape this server issues.
        let reference = candidate
            .strip_prefix(REQUEST_URI_PREFIX)
            .expect("accepted a value without the prefix");
        assert!(
            reference
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "accepted a reference outside base64url: {reference:?}"
        );

        // The stored form must not contain the credential.
        assert!(
            !digest.contains(reference),
            "the digest contains the reference"
        );
    }

    // A freshly minted reference always round-trips. If this ever fails, every
    // client is holding a `request_uri` this server cannot look up.
    let minted = MintedRequestUri::generate();
    assert_eq!(digest_of(minted.uri()).as_deref(), Ok(minted.digest()));
});
