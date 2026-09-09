//! Claim names — OIDC Core §5.1 (standard claims), §5.2 (claims languages and
//! scripts).
//!
//! A claim name arrives from an administrator, from a bulk import and from
//! another issuer's assertion, and it ends up as a JSON member name in an ID
//! Token, in a UserInfo response, in a JSONB key and in a log line. So the
//! properties asserted here are the ones the rest of the server never
//! re-checks:
//!
//! * **A name the server issues is never a user claim.** The reserved set is
//!   restated in this file rather than imported, because the point of the rule
//!   is that a bag able to hold a `sub` is a bag able to name another person —
//!   and an oracle that shares the subject's list would agree with it even when
//!   the list is wrong.
//! * **Nothing is rewritten.** What `parse` accepts is byte-identical to what
//!   it was given, so the key written to JSONB is the key that was asked for.
//! * **The §5.2 split is exact.** `base` and `language_tag` reassemble into the
//!   original name, and a suffix that is not a language tag is an error rather
//!   than a name silently read as carrying one.
//! * **A name cannot reorder what a human reads.** No control, whitespace or
//!   bidirectional formatting character survives, because escaping does not
//!   help against a right-to-left override on a consent screen.
//! * **An accepted name survives its column.** Every accepted name round-trips
//!   through the JSON the claim bag is stored as.
#![no_main]

use asterius_domain::{Claim, ClaimName, ClaimSet, ClaimSource};
use libfuzzer_sys::fuzz_target;

/// Claims the authorization server issues about the exchange, restated from
/// OIDC Core §2, RFC 7519 §4.1, RFC 7800 §3.1 and RFC 8693 §4.1.
const SERVER_ISSUED: &[&str] = &[
    "acr",
    "act",
    "amr",
    "at_hash",
    "aud",
    "auth_time",
    "azp",
    "c_hash",
    "client_id",
    "cnf",
    "exp",
    "iat",
    "iss",
    "jti",
    "may_act",
    "nbf",
    "nonce",
    "s_hash",
    "scope",
    "sid",
    "sub",
];

/// Claims the `users` row already carries in a column of its own.
const HELD_IN_A_COLUMN: &[&str] = &["email", "email_verified", "updated_at"];

/// RFC 5646 §2.1's basic shape, restated: alphabetic primary subtag, then
/// alphanumeric subtags, each 1 to 8 characters.
fn is_a_language_tag(tag: &str) -> bool {
    let mut subtags = tag.split('-');
    let Some(primary) = subtags.next() else {
        return false;
    };
    (1..=8).contains(&primary.len())
        && primary.bytes().all(|b| b.is_ascii_alphabetic())
        && subtags.all(|subtag| {
            (1..=8).contains(&subtag.len()) && subtag.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

/// A near-miss generator: a base name from a small set, sometimes a suffix,
/// sometimes raw bytes.
///
/// Random strings are almost never claim names, and never two names a rule
/// would have to tell apart. Half of these are exactly the names that must be
/// refused, spelled the ways somebody would try.
fn name(data: &[u8]) -> String {
    const BASES: [&str; 14] = [
        "name",
        "given_name",
        "family_name",
        "preferred_username",
        "sub",
        "SUB",
        "email",
        "email_verified",
        "updated_at",
        "acr",
        "https://claims.example/roles",
        "",
        "sub ",
        "subject",
    ];
    const SUFFIXES: [&str; 12] = [
        "",
        "#en",
        "#ja-Kana-JP",
        "#",
        "#-en",
        "#en-",
        "#123",
        "#toolongsubtag",
        "#en#fr",
        "\u{202e}x",
        "\u{2066}x",
        "\n",
    ];

    if data.is_empty() {
        return String::new();
    }
    match data[0] % 4 {
        0 => String::from_utf8_lossy(&data[1..]).into_owned(),
        _ => {
            let base = BASES[usize::from(data[0]) % BASES.len()];
            let suffix = SUFFIXES[usize::from(*data.last().unwrap_or(&0)) % SUFFIXES.len()];
            let filler = String::from_utf8_lossy(&data[1..data.len().min(9)]).into_owned();
            match data[0] % 3 {
                0 => format!("{base}{suffix}"),
                1 => format!("{base}{filler}{suffix}"),
                _ => format!("{filler}{suffix}"),
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let raw = name(data);

    // A rule that only holds sometimes is not a rule: the write path and the
    // read path have to reach the same answer for one name.
    let first = ClaimName::parse(&raw);
    assert_eq!(
        first.as_ref().err(),
        ClaimName::parse(&raw).as_ref().err(),
        "parsing a claim name is not deterministic: {raw:?}"
    );

    let Ok(parsed) = first else { return };

    // --- what an accepted name is -------------------------------------------

    assert_eq!(
        parsed.as_str(),
        raw,
        "a claim name was rewritten on the way in"
    );
    assert!(
        !parsed.base().is_empty(),
        "a name that names nothing: {raw:?}"
    );
    assert!(
        !parsed
            .as_str()
            .chars()
            .any(|c| c.is_control() || c.is_whitespace()),
        "a claim name kept a character that cannot be read safely: {raw:?}"
    );
    assert!(
        !parsed.as_str().chars().any(|c| matches!(
            c,
            '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )),
        "a claim name kept a bidirectional formatting character: {raw:?}"
    );

    // --- what it may not be --------------------------------------------------

    assert!(
        !SERVER_ISSUED.contains(&parsed.base()),
        "a user record was allowed to assert {:?}, which the server issues",
        parsed.base()
    );
    assert!(
        !HELD_IN_A_COLUMN.contains(&parsed.base()),
        "a user record was allowed to assert {:?}, which has a column",
        parsed.base()
    );

    // --- the OIDC Core §5.2 split -------------------------------------------

    match parsed.language_tag() {
        Some(tag) => {
            assert!(
                is_a_language_tag(tag),
                "{tag:?} was accepted as a language tag"
            );
            assert_eq!(
                format!("{}#{tag}", parsed.base()),
                raw,
                "the base and the tag do not reassemble into the name"
            );
        }
        None => assert_eq!(parsed.base(), raw, "an untagged name split anyway"),
    }

    // --- the column it is about to live in ----------------------------------

    let mut claims = ClaimSet::new();
    claims.insert(
        parsed,
        Claim::new(serde_json::json!("value"), ClaimSource::Local).expect("a non-null claim"),
    );
    let encoded = serde_json::to_value(&claims).expect("a claim set serialises");
    let decoded: ClaimSet =
        serde_json::from_value(encoded).expect("an accepted claim set must load again");
    assert_eq!(decoded, claims, "a claim set did not survive its column");
});
