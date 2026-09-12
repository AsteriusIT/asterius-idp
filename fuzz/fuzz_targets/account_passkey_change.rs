//! The body of `POST /account/passkeys` — the self-service passkey form
//! (`ast-1xd`).
//!
//! A submission here removes a way of signing in. For the last usable
//! credential on an account it is the credential its owner would use to come
//! back, which is why a form of five fields has a target of its own: it is the
//! last parser in front of an irreversible write, and the properties below are
//! the ones nothing downstream re-checks.
//!
//! * **One credential and one verb, from this body.** A parameter that appears
//!   twice is refused outright rather than resolved to the first or the last
//!   (RFC 6749 §3.1's rule about repeated parameters, applied to this server's
//!   own form). Here that matters twice over: one repeated field decides
//!   *which* credential is acted on, and another decides whether it is renamed
//!   or removed.
//! * **An identifier is the spelling this server writes.** Thirty-six
//!   characters of lower-case hex with hyphens where RFC 9562 §4 puts them.
//!   Braces, a `urn:uuid:` prefix and upper case are all things
//!   `Uuid::parse_str` would accept and this server never emits.
//! * **A label is bounded and otherwise untouched.** The column is unbounded
//!   `text`, so the bound is the parser's; the *content* is a person's own
//!   words, escaped by the template like every other value. A parser that
//!   stripped characters from it would be the one place a reviewer later
//!   believed the escaping had already happened.
//! * **Ownership is not decided here.** The parser sees no session, so what it
//!   accepts is a *claim* about which row is meant; the handler checks the
//!   account before anything is written, and answers a guessed id exactly as
//!   an id that does not exist.
//!
//! And nothing panics, on any byte sequence, including invalid UTF-8 — which
//! is why the input is bytes: the page refuses a body that is not text before
//! it parses anything.

#![no_main]

use asterius_server::http::account::{MAX_BODY, MAX_CSRF_CHARS};
use asterius_server::http::account_passkeys::{MAX_LABEL_CHARS, Verb, change};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| {
    let Some(form) = change(body) else {
        return;
    };

    // Accepted, so the body was text and within the bound. Both are properties
    // of the *input*, restated here rather than taken from the parser.
    assert!(body.len() <= MAX_BODY, "an over-long body was accepted");
    let text = std::str::from_utf8(body).expect("a change was read out of non-UTF-8 bytes");
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();

    // The identifier is a hyphenated lower-case UUID and nothing else. A store
    // asked to match anything else would be a store asked a question about a
    // row that cannot exist.
    assert_eq!(
        form.credential.len(),
        36,
        "a credential id that is not a hyphenated UUID: {:?}",
        form.credential
    );
    for (index, byte) in form.credential.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            assert_eq!(byte, b'-', "a hyphen moved in {:?}", form.credential);
        } else {
            assert!(
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
                "a credential id outside lower-case hex: {:?}",
                form.credential
            );
        }
    }

    // The verb is one of the two this page has, and it is the one the body
    // named: a parser that defaulted to either would be choosing between
    // renaming somebody's credential and destroying it.
    let named = pairs
        .iter()
        .find(|(key, _)| key == "do")
        .map(|(_, value)| value.clone())
        .expect("a verb was accepted that the body did not carry");
    match form.verb {
        Verb::Rename => assert_eq!(named, "rename"),
        Verb::Remove => assert_eq!(named, "remove"),
    }

    // Every accepted value came from this body, under its own name. The label
    // is exempt only in the sense that an absent field reads as empty, which
    // is the same thing a submitted empty field means: take the name away.
    for (name, value) in [
        ("csrf", Some(form.csrf.clone())),
        ("credential", Some(form.credential.clone())),
        ("password", form.password.clone()),
    ] {
        let Some(value) = value else {
            assert!(
                !pairs.iter().any(|(key, _)| key == name),
                "{name} was dropped from a body that carried it"
            );
            continue;
        };
        assert!(
            pairs
                .iter()
                .any(|(key, carried)| key == name && *carried == value),
            "{name} was accepted with a value the form did not carry"
        );
    }
    if !form.label.is_empty() {
        assert!(
            pairs
                .iter()
                .any(|(key, carried)| key == "label" && *carried == form.label),
            "a label was accepted that the form did not carry"
        );
    }

    // RFC 6749 §3.1: nothing this parser reads may have been sent twice.
    for name in ["csrf", "credential", "label", "password", "do"] {
        let seen = pairs.iter().filter(|(key, _)| key == name).count();
        assert!(seen <= 1, "{name} was accepted {seen} times");
    }

    // The bounds, restated: a synchroniser token is compared in constant time
    // against a derived value, and the label reaches an unbounded `text`
    // column.
    assert!(!form.csrf.is_empty(), "an empty token was accepted");
    assert!(
        form.csrf.chars().count() <= MAX_CSRF_CHARS,
        "an over-long token was accepted"
    );
    assert!(
        form.label.chars().count() <= MAX_LABEL_CHARS,
        "an over-long label was accepted"
    );

    // The same input twice is the same answer: a parser whose result depended
    // on anything but its argument could not be reasoned about at all.
    assert_eq!(
        change(body),
        Some(form),
        "the same body parsed differently twice"
    );
});
