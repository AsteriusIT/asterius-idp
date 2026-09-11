//! The email-verification token parser — OIDC Core §5.1's `email_verified`.
//!
//! The sibling of `recovery_token`, and fuzzed separately rather than folded
//! into it because they are two parsers over two token spaces: one says "reset
//! this credential", one says "this mailbox was readable at this moment", and
//! a change that made either accept the other's spelling would be a
//! confirmation link presented where a reset link is expected.
//!
//! It is reached by an unauthenticated stranger as a query parameter on a
//! mailed link, before any database work, so arbitrary bytes must cost a
//! length check rather than an index probe.
//!
//! Properties:
//!
//! * **Total.** Arbitrary bytes, including invalid UTF-8 boundaries and
//!   multi-byte characters that make `len()` and character count disagree,
//!   must not panic.
//! * **Exact shape only.** The 43 unpadded `base64url` characters this server
//!   issues, and nothing else.
//! * **No repair.** Whatever comes back is byte-for-byte what went in: a
//!   parser that trimmed, padded or case-folded would make two spellings name
//!   one token, and single use is a property of a row rather than of a
//!   spelling.
//! * **The digest is a function of the token and nothing else**, and is never
//!   the token.
#![no_main]

use asterius_domain::EmailVerificationToken;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(presented) = std::str::from_utf8(data) else {
        return;
    };

    // The raw input, plus the fuzzer's bytes spliced into a real token, so the
    // budget goes on the boundary between accept and refuse rather than on
    // inputs that are obviously the wrong length.
    let issued = EmailVerificationToken::generate();
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
        let Ok(parsed) = EmailVerificationToken::parse(candidate) else {
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
            EmailVerificationToken::parse(candidate)
                .expect("parsed once, must parse twice")
                .digest()
        );
        assert_ne!(digest, candidate, "the digest is the token");
        assert!(!digest.is_empty());
    }

    // What this server issues is always accepted. A generator and a parser
    // that disagree is a confirmation link nobody can use.
    assert!(
        EmailVerificationToken::parse(wire).is_ok(),
        "refused a token this server issued"
    );
});
