//! The account-recovery token parser — NIST SP 800-63B §6.1.2.3.
//!
//! This is the parser a reset link's token goes through, and it is reached by
//! an unauthenticated stranger twice: once as a query parameter on the mailed
//! link, once as a hidden form field on the page that link opens. Both are
//! arbitrary attacker-chosen bytes until this function says otherwise, and it
//! runs before any database work — so a request carrying a megabyte of junk
//! must cost a length check rather than an index probe.
//!
//! Properties:
//!
//! * **Total.** Arbitrary bytes, including invalid UTF-8 boundaries and
//!   multi-byte characters that make `len()` and character count disagree,
//!   must not panic.
//! * **Exact shape only.** Accepting anything but the 43 unpadded `base64url`
//!   characters this server issues would widen the lookup surface for no
//!   benefit; the token has no other spelling.
//! * **No repair.** Whatever comes back is byte-for-byte what went in. A
//!   parser that trimmed, padded or case-folded would make two different
//!   strings name one token — and single use is a property of a row, not of a
//!   spelling, so a second spelling is a second use.
//! * **The digest is a function of the token and nothing else.** Two readings
//!   of one token produce one digest, and an accepted token's digest is never
//!   the token.
#![no_main]

use asterius_domain::RecoveryToken;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(presented) = std::str::from_utf8(data) else {
        return;
    };

    // The raw input, plus the fuzzer's bytes spliced into a real token, so the
    // budget goes on the boundary between accept and refuse rather than on
    // inputs that are obviously the wrong length.
    let issued = RecoveryToken::generate();
    let wire = issued.expose();
    let mut spliced = String::from(wire);
    if !presented.is_empty() {
        // Replace the first character, keeping the length a real token's.
        spliced.replace_range(
            0..1,
            &presented[..presented
                .char_indices()
                .nth(1)
                .map_or(presented.len(), |(index, _)| index)],
        );
    }

    for candidate in [presented, spliced.as_str(), wire] {
        let Ok(parsed) = RecoveryToken::parse(candidate) else {
            continue;
        };

        // No repair: what came back is what went in.
        assert_eq!(
            parsed.expose(),
            candidate,
            "the parser rewrote its input: {candidate:?}"
        );

        // The exact shape this server issues, and nothing else. 43 characters
        // of unpadded base64url — the encoding of 256 bits.
        assert_eq!(candidate.len(), wire.len(), "accepted a wrong length");
        assert!(
            candidate
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
            "accepted a character outside base64url: {candidate:?}"
        );

        // Deterministic, and not the token.
        let digest = parsed.digest();
        assert_eq!(
            digest,
            RecoveryToken::parse(candidate)
                .expect("parsed once, must parse twice")
                .digest()
        );
        assert_ne!(digest, candidate, "the digest is the token");
        assert!(!digest.is_empty());
    }

    // What this server issues is always accepted. A generator and a parser
    // that disagree is a reset link nobody can use.
    assert!(
        RecoveryToken::parse(wire).is_ok(),
        "refused a token this server issued"
    );
});
