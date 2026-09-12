//! The body of `POST /account/sessions` — the self-service session list
//! (`ast-1xd`).
//!
//! A submission here ends a session and tells every relying party that took an
//! ID token in it. Two properties are the whole reason this is a target:
//!
//! * **"Close this one" names exactly one session, and "close the others"
//!   names none.** The second verb takes no argument by construction: the
//!   server works out which rows those are from the cookie it is holding, so a
//!   body that carried a `sid` anyway cannot aim it. A parser that let the
//!   argument through would turn the one button a person presses when they
//!   believe somebody else is signed in into a button an attacker can point.
//! * **A revocation with no session is refused rather than resolved.** The
//!   newest, the current, the first in the list — every way of guessing is
//!   this server choosing a session to end on somebody's behalf.
//!
//! The `sid` itself is opaque (OIDC Session Management §5 says nothing about
//! its shape) so what is checked is that it is non-empty and bounded; whether
//! it names one of *this* account's sessions is the handler's question, and it
//! answers somebody else's exactly as one that does not exist.
//!
//! And nothing panics, on any byte sequence, including invalid UTF-8.

#![no_main]

use asterius_server::http::account::{MAX_BODY, MAX_CSRF_CHARS};
use asterius_server::http::account_sessions::{Verb, revocation};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| {
    let Some(form) = revocation(body) else {
        return;
    };

    assert!(body.len() <= MAX_BODY, "an over-long body was accepted");
    let text = std::str::from_utf8(body).expect("a revocation was read out of non-UTF-8 bytes");
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();

    let named = pairs
        .iter()
        .find(|(key, _)| key == "do")
        .map(|(_, value)| value.clone())
        .expect("a verb was accepted that the body did not carry");
    match form.verb {
        Verb::Revoke => {
            assert_eq!(named, "revoke");
            let session = form
                .session
                .as_ref()
                .expect("a revocation was accepted without a session");
            assert!(!session.is_empty(), "an empty session id was accepted");
            assert!(
                session.chars().count() <= 256,
                "an over-long session id was accepted"
            );
            assert!(
                pairs
                    .iter()
                    .any(|(key, carried)| key == "session" && carried == session),
                "a session was accepted that the form did not carry"
            );
        }
        Verb::Others => {
            assert_eq!(named, "others");
            assert_eq!(
                form.session, None,
                "closing the other sessions carried an argument, which it must never do"
            );
        }
    }

    // RFC 6749 §3.1: nothing this parser reads may have been sent twice.
    for name in ["csrf", "session", "do"] {
        let seen = pairs.iter().filter(|(key, _)| key == name).count();
        assert!(seen <= 1, "{name} was accepted {seen} times");
    }

    assert!(!form.csrf.is_empty(), "an empty token was accepted");
    assert!(
        form.csrf.chars().count() <= MAX_CSRF_CHARS,
        "an over-long token was accepted"
    );
    assert!(
        pairs
            .iter()
            .any(|(key, carried)| key == "csrf" && *carried == form.csrf),
        "a token was accepted that the form did not carry"
    );

    assert_eq!(
        revocation(body),
        Some(form),
        "the same body parsed differently twice"
    );
});
