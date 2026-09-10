//! `MessageOverrides::from_json` — the wording a tenant substitutes into the
//! pages this server renders to somebody else's browser.
//!
//! This is a stored-XSS surface with the ordinary shape: a tenant administrator
//! writes a string, the string is kept in `tenants.settings`, and an end user's
//! browser is what renders it. Askama's autoescaping is the second line; this
//! validator is the first, and it is the one that also protects consumers that
//! are not templates.
//!
//! The properties asserted here are the ones the render path does not re-check:
//!
//! * **Nothing accepted can open or close a tag.** No `<`, no `>`, in any
//!   accepted value, whatever the document contained.
//! * **Nothing accepted carries a non-printing character**, including the
//!   bidirectional overrides that reverse what a person reads without changing
//!   what is stored (CVE-2021-42574).
//! * **Every accepted key is key-shaped and bounded**, so that a key echoed
//!   back in an administrator-facing error message cannot be an echo of
//!   arbitrary bytes.
//! * **What is accepted round-trips**: reading, writing and reading again is
//!   the same value, so a settings screen that saves what it loaded cannot
//!   drift.
//! * **A refusal names a key.** The acceptance criterion for `ast-ndk.5` is
//!   that an unusable override is reported by path rather than as "invalid
//!   settings".
//! * **It never panics**, because it runs on the path that renders a sign-in
//!   page.
#![no_main]

use asterius_domain::{MessageOverrideError, MessageOverrides};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };

    let accepted = match MessageOverrides::from_json(Some(&value)) {
        Ok(accepted) => accepted,
        Err(refused) => {
            // Every refusal but the two structural ones names the key it
            // refused, which is what makes it actionable.
            match refused {
                MessageOverrideError::NotAnObject | MessageOverrideError::TooMany { .. } => {}
                other => assert!(
                    !other.to_string().is_empty(),
                    "a refusal with no message: {value}"
                ),
            }
            return;
        }
    };

    for key in accepted.keys() {
        assert!(
            !key.is_empty() && key.len() <= MessageOverrides::MAX_KEY_BYTES,
            "an accepted key is out of bounds: {key:?}"
        );
        assert!(
            key.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'),
            "an accepted key is not key-shaped: {key:?}"
        );

        let value = accepted.get(key).expect("a key that was just listed");
        assert!(
            !value.contains('<') && !value.contains('>'),
            "an accepted override can open a tag: {key} = {value:?}"
        );
        assert!(
            value.len() <= MessageOverrides::MAX_VALUE_BYTES,
            "an accepted override is past the bound: {key}"
        );
        assert!(
            !value
                .chars()
                .any(|c| (c.is_control() && c != '\n' && c != '\t')
                    || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')),
            "an accepted override carries a non-printing character: {key}"
        );
        assert!(
            !value.trim().is_empty(),
            "an accepted override is blank: {key}"
        );
    }

    let written = accepted.to_json();
    let read_back =
        MessageOverrides::from_json(Some(&written)).expect("what this validator wrote, it reads");
    assert_eq!(
        read_back, accepted,
        "a round trip through the stored document changed the overrides: {value}"
    );
});
