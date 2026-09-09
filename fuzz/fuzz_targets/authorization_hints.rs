//! The four hint parameters of OIDC Core §3.1.2.1 (`ast-gxh.8`).
//!
//! `prompt`, `max_age`, `login_hint` and `id_token_hint` are small parsers with
//! large consequences: between them they decide whether a user is shown
//! anything at all, how old an authentication may be, what text a relying party
//! can put on this server's sign-in page, and which string is handed to a JWS
//! parser afterwards. Each is fuzzed for the property that makes it worth
//! having rather than merely for the absence of a panic.
//!
//! * `prompt` — an accepted list round-trips to itself value for value, and
//!   `none` never survives alongside another value. That combination rule is
//!   the one OIDC Core states as a MUST, and it is the one a client can send by
//!   accident.
//! * `max_age` — accepted input is exactly a run of ASCII digits, and the value
//!   is the number those digits spell. Nothing else may be coerced into a
//!   duration, because a coerced `max_age` is an authentication age nobody
//!   asked for.
//! * `login_hint` — accepted input carries no control character and no
//!   bidirectional formatting character, and is returned unchanged. It is
//!   *displayed*, so a parser that sanitised rather than refused would be one
//!   whose output nobody has seen.
//! * `id_token_hint` — accepted input is three non-empty base64url segments,
//!   which is the whole of JWS Compact Serialization's shape.
#![no_main]

use asterius_oidc::authorize::{
    AuthorizationPolicy, MAX_ID_TOKEN_HINT_LEN, MAX_LOGIN_HINT_LEN, Prompt, parse_id_token_hint,
    parse_login_hint, parse_max_age,
};
use libfuzzer_sys::fuzz_target;

/// The characters no accepted `login_hint` may contain, rewritten here rather
/// than imported: the oracle and the code under test must not share a list.
fn is_forbidden_in_a_hint(character: char) -> bool {
    let code = character as u32;
    let control = code < 0x20 || (0x7F..=0x9F).contains(&code);
    let bidirectional = matches!(
        code,
        0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069
    );
    control || bidirectional
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    for policy in [
        AuthorizationPolicy::new(false),
        AuthorizationPolicy::new(true),
    ] {
        if let Ok(prompts) = Prompt::parse_list(Some(text), policy) {
            // Every accepted value is one the tenant offers, and it is spelled
            // the way the input spelled it.
            for prompt in &prompts {
                assert!(policy.offers(*prompt), "accepted {prompt:?}");
                assert!(
                    text.split_whitespace()
                        .any(|token| token == prompt.as_str()),
                    "invented a prompt: {prompt:?}"
                );
            }
            // The combination rule, from the other side: `none` is alone or it
            // is not there.
            if prompts.contains(&Prompt::None) {
                assert_eq!(prompts.len(), 1, "none survived a combination");
            }
            // And the whole input was understood: nothing was dropped.
            assert_eq!(
                prompts.len(),
                text.split_whitespace()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                "a value was ignored rather than refused"
            );
        }
    }

    match parse_max_age(Some(text)) {
        Ok(Some(seconds)) => {
            assert!(!text.is_empty());
            assert!(
                text.bytes().all(|byte| byte.is_ascii_digit()),
                "accepted a non-digit max_age: {text:?}"
            );
            // The value is the number the digits spell, computed by something
            // other than the parser under test.
            assert_eq!(text.parse::<u64>().ok(), Some(u64::from(seconds)));
        }
        Ok(None) => unreachable!("a present parameter parsed as absent"),
        Err(_) => {}
    }

    if let Ok(Some(hint)) = parse_login_hint(Some(text)) {
        assert_eq!(hint, text, "a login_hint was rewritten");
        assert!(!hint.is_empty());
        assert!(hint.len() <= MAX_LOGIN_HINT_LEN);
        assert!(
            !hint.chars().any(is_forbidden_in_a_hint),
            "accepted a hint that can rewrite a page: {hint:?}"
        );
    }

    if let Ok(Some(hint)) = parse_id_token_hint(Some(text)) {
        assert_eq!(hint, text, "an id_token_hint was rewritten");
        assert!(hint.len() <= MAX_ID_TOKEN_HINT_LEN);
        let segments: Vec<&str> = hint.split('.').collect();
        assert_eq!(segments.len(), 3, "accepted a non-compact JWS: {hint:?}");
        for segment in segments {
            assert!(!segment.is_empty(), "accepted an empty segment: {hint:?}");
            assert!(
                segment.bytes().all(is_base64url),
                "accepted a non-base64url segment: {hint:?}"
            );
        }
    }
});
