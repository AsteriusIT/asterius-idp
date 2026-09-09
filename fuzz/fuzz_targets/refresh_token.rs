//! `refresh::digest_of` — the shape check standing in front of the one query
//! that can turn a string somebody sent into a live authorization.
//!
//! A refresh token is the longest-lived credential this server issues, it is
//! presented by a machine with no user watching, and the value arrives in a
//! form field. So three properties are worth a fuzzer rather than a unit test:
//!
//! * **It never panics.** The token endpoint calls this before it calls
//!   anything else; a panic here is a 500 on a request an attacker composes.
//! * **What it returns is a lookup key and nothing else.** Sixty-four hex
//!   characters, deterministic, and never the value itself. A digest that
//!   could carry a byte from the input into a query is the injection this
//!   layer exists to make impossible.
//! * **It agrees with the minter.** Any value `MintedRefreshToken` produces
//!   must pass, and must digest to what the minter stored. A drift between the
//!   two is a server that cannot redeem what it just issued — which shows up
//!   as every refresh failing, weeks after the change that caused it.
#![no_main]

use asterius_oidc::refresh::{MintedRefreshToken, REFRESH_TOKEN_LEN, digest_of};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|presented: String| {
    if let Ok(digest) = digest_of(&presented) {
        // A lookup key, not a value spliced into anything.
        assert_eq!(digest.len(), 64, "not a SHA-256 digest: {digest:?}");
        assert!(
            digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "a digest outside hex: {digest:?}"
        );
        assert_ne!(digest, presented, "the digest is the value it digested");
        assert_eq!(
            digest,
            digest_of(&presented).expect("accepted once, accepted twice"),
            "digesting is not deterministic"
        );
        // Accepted means it had the shape a minted token has. Anything else
        // reaching the database is a query paid for on somebody's guess.
        assert_eq!(
            presented.len(),
            REFRESH_TOKEN_LEN,
            "a value of the wrong length was accepted: {presented:?}"
        );
        assert!(
            presented
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "a value outside base64url was accepted: {presented:?}"
        );
    }

    // The minter and the check are two halves of one credential.
    let minted = MintedRefreshToken::generate();
    assert_eq!(
        digest_of(minted.expose()).expect("a minted refresh token must be accepted"),
        minted.digest()
    );
    assert_ne!(minted.expose(), minted.digest());
    // And the redacting `Debug` is what keeps the value out of a log line.
    assert!(!format!("{minted:?}").contains(minted.expose()));
});
