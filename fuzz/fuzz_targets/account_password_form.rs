//! The body of `POST /account/password` — setting or changing a password from
//! a signed-in session (`ast-1xd`).
//!
//! This parser stands in front of the write that replaces an account's
//! password, and it carries the one value that is checked against a stored
//! hash. Three properties:
//!
//! * **One new password, from this body.** RFC 6749 §3.1's rule about repeated
//!   parameters, applied where it matters most: a body naming `password`
//!   twice is a body where which one is stored depends on which the parser
//!   preferred, and the same for `current_password`, which decides whether the
//!   change is allowed at all.
//! * **Both halves are present.** A password nobody can see is a password that
//!   gets typed wrong, so a submission with no confirmation is not one this
//!   page makes. Whether the two *match* is the handler's question.
//! * **No policy here.** `AcceptedPassword::accept_locally` owns the NIST SP
//!   800-63B §5.1.1.2 floor and the deny list; a parser that refused short
//!   passwords would be a second copy of a rule that has to move as one. What
//!   is bounded here is what the function allocates.
//!
//! The password is never compared, hashed or logged by this target: it is read
//! for its length and its provenance and nothing else.
//!
//! And nothing panics, on any byte sequence, including invalid UTF-8.

#![no_main]

use asterius_server::http::account::{MAX_BODY, MAX_CSRF_CHARS};
use asterius_server::http::account_password::new_password;
use libfuzzer_sys::fuzz_target;

/// The policy's ceiling, which is also this parser's bound.
const MAX_PASSWORD_CHARS: usize = 128;

fuzz_target!(|body: &[u8]| {
    let Some(form) = new_password(body) else {
        return;
    };

    assert!(body.len() <= MAX_BODY, "an over-long body was accepted");
    let text = std::str::from_utf8(body).expect("a form was read out of non-UTF-8 bytes");
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();

    // Every accepted value came from this body, under its own name.
    for (name, value) in [
        ("csrf", Some(form.csrf.clone())),
        ("password", Some(form.password.clone())),
        ("password_confirmation", Some(form.confirmation.clone())),
        ("current_password", form.current.clone()),
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

    // The checkbox is present or absent, and nothing else: a body with no
    // `sign_out_others` must never close somebody's other sessions.
    assert_eq!(
        form.sign_out_others,
        pairs.iter().any(|(key, _)| key == "sign_out_others"),
        "the sign-out box was read differently from how the body carried it"
    );

    // RFC 6749 §3.1: nothing this parser reads may have been sent twice.
    for name in [
        "csrf",
        "password",
        "password_confirmation",
        "current_password",
    ] {
        let seen = pairs.iter().filter(|(key, _)| key == name).count();
        assert!(seen <= 1, "{name} was accepted {seen} times");
    }

    assert!(!form.csrf.is_empty(), "an empty token was accepted");
    assert!(
        form.csrf.chars().count() <= MAX_CSRF_CHARS,
        "an over-long token was accepted"
    );
    for field in [
        Some(&form.password),
        Some(&form.confirmation),
        form.current.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        assert!(
            field.chars().count() <= MAX_PASSWORD_CHARS,
            "an over-long password was accepted"
        );
    }

    assert_eq!(
        new_password(body),
        Some(form),
        "the same body parsed differently twice"
    );
});
