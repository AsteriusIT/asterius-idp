//! The body of `POST /account/approvals/decide` — the approvals inbox's
//! decision form (CIBA Core 1.0 §8, `ast-lh3.6`).
//!
//! An acceptance here is a *credential on somebody's account*: the form says
//! which pending backchannel request is being answered and whether the answer
//! is yes. That is why a form this small has a target of its own — it is the
//! last parser in front of an authorization decision, and the three properties
//! below are the ones nothing downstream re-checks.
//!
//! * **One answer, from this body.** A parameter that appears twice is refused
//!   outright rather than resolved to the first or the last (RFC 6749 §3.1's
//!   rule about repeated parameters, applied to this server's own form). Both
//!   resolutions are a choice an attacker can exploit the moment anything else
//!   makes the other one — a proxy, a log, a future rewrite.
//! * **A reference is a digest.** Sixty-four lower-case hex characters, which
//!   is what `sha256_hex` produces and the only shape the store could match.
//!   Anything else never reaches a query.
//! * **A verdict is one of two words.** `approve` or `deny`; a third word is
//!   not a quieter `deny`, it is a body this server will not act on.
//!
//! And nothing panics, on any byte sequence, including invalid UTF-8 — which
//! is why the input is bytes: the endpoint refuses a body that is not text
//! before it parses anything, so a target that fed the parser lossy text would
//! be fuzzing a decoder this server does not have.

#![no_main]

use asterius_server::http::approvals::{MAX_BODY, Verdict, decision};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|body: &[u8]| {
    let Some(decision) = decision(body) else {
        return;
    };

    // Accepted, so the body was text and within the bound. Both are properties
    // of the *input*, restated here rather than taken from the parser.
    assert!(body.len() <= MAX_BODY, "an over-long body was accepted");
    let text = std::str::from_utf8(body).expect("a decision was read out of non-UTF-8 bytes");
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();

    // The reference is a digest and nothing else. A store asked to match
    // anything else would be a store asked a question about a row that cannot
    // exist.
    assert_eq!(
        decision.approval.len(),
        64,
        "an approval reference that is not a digest: {:?}",
        decision.approval
    );
    assert!(
        decision
            .approval
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "an approval reference outside lower-case hex: {:?}",
        decision.approval
    );

    // Every accepted value came from this body, under its own name.
    for (name, value) in [
        ("csrf", decision.csrf.clone()),
        ("approval", decision.approval.clone()),
    ] {
        assert!(
            pairs
                .iter()
                .any(|(key, carried)| key == name && *carried == value),
            "{name} was accepted with a value the form did not carry"
        );
    }
    let spelling = match decision.verdict {
        Verdict::Approve => "approve",
        Verdict::Deny => "deny",
    };
    assert!(
        pairs
            .iter()
            .any(|(key, value)| key == "decision" && value == spelling),
        "a verdict was accepted that the form did not carry"
    );

    // RFC 6749 §3.1: nothing this parser reads may have been sent twice.
    for name in ["csrf", "approval", "decision"] {
        let seen = pairs.iter().filter(|(key, _)| key == name).count();
        assert_eq!(seen, 1, "{name} was accepted {seen} times");
    }

    // A synchroniser token is compared in constant time against a derived
    // value; an empty one would compare equal to nothing and is refused
    // earlier, and an unbounded one is a body that was bounded anyway.
    assert!(!decision.csrf.is_empty(), "an empty token was accepted");
    assert!(
        decision.csrf.chars().count() <= 256,
        "an over-long token was accepted"
    );

    // The same input twice is the same answer: a parser whose result depended
    // on anything but its argument could not be reasoned about at all.
    assert_eq!(
        self::decision(body),
        Some(decision),
        "the same body parsed differently twice"
    );
});
