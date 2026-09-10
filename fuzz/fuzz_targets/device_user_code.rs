//! `UserCode::parse` — the one thing a person types into the device
//! verification page, and therefore the one thing an attacker types into it a
//! few thousand times.
//!
//! RFC 8628 §6.1 makes the code case-insensitive and displayed with a
//! separator, which means the parser has *tolerance*, and tolerance is where a
//! lookup key stops being canonical. Every property below is one a later stage
//! trusts without re-checking:
//!
//! * **An accepted code is canonical.** Eight characters, all from the
//!   alphabet, upper case, no separator — because the digest of that string is
//!   the primary lookup key, and two spellings that digested differently would
//!   be one authorization nobody could find.
//! * **The digest is a digest.** Sixty-four hex characters, deterministic, and
//!   never the code itself: it is interpolated into no SQL, but it *is* handed
//!   to a query, and a value that could be anything else has no business
//!   getting that far.
//! * **Case and separators do not change the answer.** A code, its lower-case
//!   spelling, and its hyphenated display form are the same code — that is
//!   §6.1's requirement, and the fuzzer states it rather than trusting the
//!   three lines that implement it.
//! * **A minted code parses.** A generator and a parser that disagree is a
//!   server that shows a code nobody can type back in, and no test that only
//!   feeds the parser hostile input would ever notice.
//! * **Nothing panics.** The field is a text input on an unauthenticated
//!   page's successor, and a panic there is a denial of service reachable with
//!   a form post.
#![no_main]

use asterius_oidc::device::{USER_CODE_ALPHABET, USER_CODE_LENGTH, UserCode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|presented: String| {
    if let Ok(code) = UserCode::parse(&presented) {
        let canonical = code.as_str();
        assert_eq!(
            canonical.len(),
            USER_CODE_LENGTH,
            "an accepted code of the wrong length: {canonical:?}"
        );
        assert!(
            canonical.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)),
            "an accepted code outside the alphabet: {canonical:?}"
        );

        let digest = code.digest();
        assert_eq!(digest.len(), 64, "not a SHA-256 digest: {digest:?}");
        assert!(
            digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "a digest outside hex: {digest:?}"
        );
        assert_ne!(digest, canonical, "the code is its own lookup key");

        // §6.1's case-insensitivity, and the separator the display adds.
        for spelling in [
            canonical.to_ascii_lowercase(),
            code.formatted(),
            code.formatted().to_ascii_lowercase(),
            format!(" {canonical} "),
        ] {
            let again = UserCode::parse(&spelling).unwrap_or_else(|_| {
                panic!("a spelling of an accepted code was refused: {spelling:?}")
            });
            assert_eq!(
                again.digest(),
                digest,
                "two spellings of one code do not look the same up: {spelling:?}"
            );
        }

        // The displayed form is the canonical one with one separator in it,
        // and nothing else: a device shows this string and a person copies it.
        let formatted = code.formatted();
        assert_eq!(formatted.len(), USER_CODE_LENGTH + 1, "{formatted:?}");
        assert_eq!(formatted.matches('-').count(), 1, "{formatted:?}");
    }

    // A minted code always passes its own parser and survives its own display
    // form. A drift between the two is unreachable from hostile input alone,
    // which is exactly why it is asserted here.
    let minted = UserCode::generate();
    let typed = UserCode::parse(&minted.formatted()).expect("a minted code must be accepted");
    assert_eq!(typed.as_str(), minted.as_str());
    assert_eq!(typed.digest(), minted.digest());
});
