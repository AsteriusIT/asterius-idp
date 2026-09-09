//! The member names `serde_json` reserves for itself.
//!
//! This lives in the domain crate rather than next to its first caller because
//! it is one rule, not one per module. Every layer above serialises a map some
//! other layer parses back — a claim bag into JSONB, a claims request onto a
//! grant, a client's metadata into a registration response — and the rule that
//! a member may not be named after `serde_json`'s private types has to be the
//! same rule in all of them. A second hand-copied list is a second rule, and it
//! drifts the first time one of them is corrected.

use serde_json::Value;

/// The member names `serde_json` reserves for its own use.
///
/// These are not JSON syntax and not names anything asks for: they are the
/// struct names `serde_json` uses to smuggle its `RawValue` and its
/// arbitrary-precision `Number` through `serde`. When the matching feature is
/// on — and features are unified across a whole binary, so a dependency several
/// crates away decides this, not us — the *deserialiser* recognises an object
/// whose **first** member carries one of these names and demands the shape that
/// feature expects, failing the parse of the entire document otherwise.
///
/// Two consequences, both of which every caller has to refuse:
///
/// * Parsing stops being a function of the document alone. `{"a":{},"$…":{}}`
///   parses and `{"$…":{},"a":{}}` does not, so the same data is accepted where
///   it is written and refused once storage has handed it back in sorted order.
/// * Anything written with such a member and read back with `serde_json` is a
///   document that cannot be read at all. Where that document is a database
///   row, the row is *durably* unreadable by the normal paths.
///
/// Both names are listed, not only the one whose feature happens to be enabled
/// today: the crate that enables it can change under us with a `cargo update`.
pub const SERDE_JSON_SENTINELS: [&str; 2] = [
    "$serde_json::private::RawValue",
    "$serde_json::private::Number",
];

/// The sentinel `name` is, if it is one.
///
/// Returns the entry of [`SERDE_JSON_SENTINELS`] rather than a bare `bool` so
/// that a caller reporting the refusal can name the constant it collided with
/// without echoing attacker-chosen text back.
#[must_use]
pub fn serde_json_sentinel(name: &str) -> Option<&'static str> {
    SERDE_JSON_SENTINELS
        .into_iter()
        .find(|sentinel| *sentinel == name)
}

/// Whether a member name is one `serde_json` reserves.
#[must_use]
pub fn is_serde_json_sentinel(name: &str) -> bool {
    serde_json_sentinel(name).is_some()
}

/// Whether any object anywhere in `value` has a member `serde_json` reserves.
///
/// Recursive, and safe to be: `serde_json` refuses input nested past its own
/// recursion limit before any of this runs, so the depth here is bounded by
/// whatever produced the `Value`.
#[must_use]
pub fn names_a_serde_json_sentinel(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(names_a_serde_json_sentinel),
        Value::Object(members) => members.iter().any(|(name, member)| {
            is_serde_json_sentinel(name) || names_a_serde_json_sentinel(member)
        }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The list is the rule; a caller that walks it must see both entries.
    #[test]
    fn both_sentinels_are_recognised() {
        for name in SERDE_JSON_SENTINELS {
            assert!(is_serde_json_sentinel(name), "{name} was not recognised");
            assert_eq!(serde_json_sentinel(name), Some(name));
        }
    }

    #[test]
    fn an_ordinary_member_name_is_not_a_sentinel() {
        assert!(!is_serde_json_sentinel("given_name"));
        assert!(!is_serde_json_sentinel("$serde_json::private"));
        assert_eq!(serde_json_sentinel("given_name"), None);
    }

    /// Nesting is where this hides: the corrupting member is rarely at the top.
    #[test]
    fn a_sentinel_nested_in_a_value_is_found() {
        let buried = json!({"a": [{"b": {"$serde_json::private::RawValue": "x"}}]});

        assert!(names_a_serde_json_sentinel(&buried));
    }

    #[test]
    fn a_document_without_a_sentinel_is_accepted() {
        let ordinary = json!({"a": [{"b": {"c": "$serde_json"}}], "d": 1});

        assert!(!names_a_serde_json_sentinel(&ordinary));
    }
}
