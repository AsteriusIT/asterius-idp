//! `RoleName::parse` — the alphabet of every application role this server puts
//! in a token.
//!
//! The input is an administrator's string, and the output is copied verbatim
//! into the `roles` and `resource_access.<client_id>.roles` claims of an access
//! token that third-party resource servers authorise against. So the properties
//! asserted here are the ones nothing downstream re-checks:
//!
//! * **An accepted name cannot split.** No whitespace of any kind, so a name
//!   cannot become two roles at a resource server that splits on space — the
//!   same escalation the `scope` claim guards against.
//! * **An accepted name is ASCII, lowercase, and in the stated alphabet.** No
//!   control character, no bidirectional formatting character, no confusable
//!   uppercase twin, nothing that would need escaping in JSON or in a URL path
//!   segment. A console rendering a name that is not the name authorises the
//!   wrong thing.
//! * **Parsing does not change its input.** `parse(x).as_str() == x` for every
//!   accepted `x`, so the name an administrator typed, the name in the database
//!   key and the name in the token are one string. A parser that lowercased
//!   would merge two catalogue entries into one role.
//! * **It is idempotent and total.** Re-parsing an accepted name accepts it
//!   again, and no input panics.
//! * **The bound holds.** Never longer than `RoleName::MAX_LEN`.
#![no_main]

use asterius_domain::{RoleName, RoleNameError};
use libfuzzer_sys::fuzz_target;

/// Fragments a name is assembled from: the ones that must pass, and the ones
/// that must not, spelled the ways somebody would type them into a console.
const FRAGMENTS: [&str; 20] = [
    "admin",
    "payments",
    ".settlement",
    ":approve",
    "-2",
    "_x",
    "9",
    "Admin",
    "ADMIN",
    " ",
    "\t",
    "\n",
    "\u{202e}",
    "rôle",
    "\"",
    "/",
    "*",
    "",
    "\u{0}",
    "..",
];

fuzz_target!(|input: (Vec<u8>, String)| {
    let (picks, free) = input;

    let mut candidate = String::new();
    for index in picks.iter().take(64) {
        candidate.push_str(FRAGMENTS[usize::from(*index) % FRAGMENTS.len()]);
    }
    candidate.push_str(&free);

    for raw in [candidate.as_str(), free.as_str()] {
        let Ok(parsed) = RoleName::parse(raw) else {
            // A refusal is always the right outcome for something outside the
            // alphabet; what must not happen is a refusal of a name the
            // alphabet admits, which the accepted branch below checks by
            // reconstructing the rule from primitives.
            let admissible = !raw.is_empty()
                && raw.len() <= RoleName::MAX_LEN
                && raw
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.:".contains(c))
                && raw
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric());
            assert!(
                !admissible,
                "a name inside the alphabet was refused: {raw:?}"
            );
            continue;
        };

        // Nothing was rewritten on the way through.
        assert_eq!(
            parsed.as_str(),
            raw,
            "parsing changed the name it was given"
        );

        // The bound, and the alphabet, re-derived here rather than read off the
        // implementation.
        assert!(!parsed.as_str().is_empty(), "an empty role name");
        assert!(
            parsed.as_str().len() <= RoleName::MAX_LEN,
            "a role name past the bound: {raw:?}"
        );
        for character in parsed.as_str().chars() {
            assert!(
                character.is_ascii(),
                "a non-ASCII character reached a role name: {character:?}"
            );
            assert!(
                !character.is_whitespace(),
                "a role name that splits at a resource server: {raw:?}"
            );
            assert!(
                !character.is_control(),
                "a control character reached a role name: {raw:?}"
            );
            assert!(
                !character.is_ascii_uppercase(),
                "an uppercase character reached a role name: {raw:?}"
            );
            assert!(
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || "-_.:".contains(character),
                "a character outside the alphabet reached a role name: {character:?}"
            );
        }
        assert!(
            parsed
                .as_str()
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric()),
            "a role name starting with punctuation: {raw:?}"
        );

        // A name this server minted is a name it accepts again.
        assert_eq!(
            RoleName::parse(parsed.as_str()).as_ref(),
            Ok(&parsed),
            "parsing is not idempotent"
        );

        // And the JSON spelling of an accepted name needs no escaping, which is
        // what makes it safe to concatenate into a claims set by hand in a
        // resource server.
        let encoded = serde_json::to_string(parsed.as_str()).expect("a string encodes");
        assert_eq!(
            encoded,
            format!("\"{raw}\""),
            "an accepted role name needed JSON escaping"
        );
    }

    // The error type is inspected so that a variant added without a rule here
    // is at least constructed under the fuzzer.
    if let Err(error) = RoleName::parse(&free) {
        match error {
            RoleNameError::Length { found } => assert!(found == 0 || found > RoleName::MAX_LEN),
            RoleNameError::Character(_) | RoleNameError::Start => {}
            _ => {}
        }
    }
});
