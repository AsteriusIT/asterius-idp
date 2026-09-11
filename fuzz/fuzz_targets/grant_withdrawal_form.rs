//! The body of `POST /account/grants/revoke` — the grants dashboard's
//! withdrawal form (Grant Management ID1 §3, `ast-uwv.6`).
//!
//! A submission here destroys an authorization and everything minted from it:
//! the grant, its refresh tokens, and every access token issued before the
//! cutoff the revocation writes. That is why a form of two fields has a target
//! of its own — it is the last parser in front of an irreversible write, and
//! the properties below are the ones nothing downstream re-checks.
//!
//! * **One grant, from this body.** A parameter that appears twice is refused
//!   outright rather than resolved to the first or the last (RFC 6749 §3.1's
//!   rule about repeated parameters, applied to this server's own form).
//!   Resolving it either way is a choice an attacker can exploit the moment
//!   anything else makes the other one.
//! * **An identifier is the spelling this server writes.** Thirty-six
//!   characters of lower-case hex with hyphens where RFC 9562 §4 puts them.
//!   Braces, a `urn:uuid:` prefix and upper case are all things
//!   `Uuid::parse_str` would accept and this server never emits, so they are
//!   bodies it did not write and will not act on.
//! * **Ownership is not decided here.** The parser sees no session, so
//!   whatever it accepts is still a *claim* about which row is meant; the
//!   handler re-reads the grant and compares its account against the
//!   signed-in one. This target asserts the shape, which is what keeps a
//!   guessed identifier from ever reaching a query.
//!
//! And nothing panics, on any byte sequence, including invalid UTF-8 — which
//! is why the input is bytes: the page refuses a body that is not text before
//! it parses anything, so a target that fed the parser lossy text would be
//! fuzzing a decoder this server does not have.

#![no_main]

use asterius_server::http::account_grants::{MAX_BODY, withdrawal};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| {
    let Some(form) = withdrawal(body) else {
        return;
    };

    // Accepted, so the body was text and within the bound. Both are properties
    // of the *input*, restated here rather than taken from the parser.
    assert!(body.len() <= MAX_BODY, "an over-long body was accepted");
    let text = std::str::from_utf8(body).expect("a withdrawal was read out of non-UTF-8 bytes");
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();

    // The identifier is a hyphenated lower-case UUID and nothing else. A store
    // asked to match anything else would be a store asked a question about a
    // row that cannot exist.
    assert_eq!(
        form.grant.len(),
        36,
        "a grant id that is not a hyphenated UUID: {:?}",
        form.grant
    );
    for (index, byte) in form.grant.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            assert_eq!(byte, b'-', "a hyphen moved in {:?}", form.grant);
        } else {
            assert!(
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
                "a grant id outside lower-case hex: {:?}",
                form.grant
            );
        }
    }

    // Every accepted value came from this body, under its own name.
    for (name, value) in [("csrf", form.csrf.clone()), ("grant", form.grant.clone())] {
        assert!(
            pairs
                .iter()
                .any(|(key, carried)| key == name && *carried == value),
            "{name} was accepted with a value the form did not carry"
        );
    }

    // RFC 6749 §3.1: nothing this parser reads may have been sent twice.
    for name in ["csrf", "grant"] {
        let seen = pairs.iter().filter(|(key, _)| key == name).count();
        assert_eq!(seen, 1, "{name} was accepted {seen} times");
    }

    // A synchroniser token is compared in constant time against a derived
    // value; an empty one would compare equal to nothing and is refused
    // earlier, and an unbounded one is a body that was bounded anyway.
    assert!(!form.csrf.is_empty(), "an empty token was accepted");
    assert!(
        form.csrf.chars().count() <= 256,
        "an over-long token was accepted"
    );

    // The same input twice is the same answer: a parser whose result depended
    // on anything but its argument could not be reasoned about at all.
    assert_eq!(
        withdrawal(body),
        Some(form),
        "the same body parsed differently twice"
    );
});
