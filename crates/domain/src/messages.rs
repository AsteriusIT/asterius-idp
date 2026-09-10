//! A tenant's replacement wording for the pages a person sees.
//!
//! The product rule this type exists to hold is the one `crates/web` states:
//! **a tenant supplies no markup**. It supplies design tokens, and it supplies
//! strings — and a string that reaches a page is text a tenant administrator
//! wrote which this server then renders to somebody else's browser. That is an
//! injection surface with an ordinary name: stored cross-site scripting.
//!
//! There are two defences and they are deliberately independent.
//!
//! 1. Askama autoescapes every `{{ … }}` in an `.html` template, and
//!    `crates/web/src/source_audit.rs` fails the build if a second `|safe`
//!    appears in the tree. An override is therefore escaped at render time
//!    whatever it contains.
//! 2. This type refuses `<` and `>` at the point the value is *accepted*, so a
//!    string shaped like markup never reaches a row in the first place.
//!
//! Either one alone would stop `<script>`. Both are here because the first is a
//! property of a template engine's configuration — one `|safe` away from being
//! untrue on one page — and the second is a property of the data, which holds
//! for a consumer that is not a template at all: an email body, a JSON API
//! answer, an admin console that renders the current settings back to an
//! operator. The threat-model note is `docs/threat-model.md`, "Tenant string
//! overrides".
//!
//! # What this module does not know
//!
//! Which keys exist. The catalogue lives in `crates/web`, which is above this
//! crate, so the shape checks here are about the *bytes* — is it an object, is
//! the key key-shaped, is the value text rather than markup — and
//! `asterius_web::i18n` is what refuses a key no page has. Splitting it that
//! way is what lets the settings row be validated by the domain and the key
//! space be owned by the crate that renders it.

use std::collections::BTreeMap;

/// Wording a tenant has substituted, by message key.
///
/// A `BTreeMap` because the stored document is compared in tests and read by
/// operators: a settings blob whose member order changed between two writes
/// looks like a change nobody made.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageOverrides(BTreeMap<String, String>);

impl MessageOverrides {
    /// The most strings one tenant may override.
    ///
    /// Every one of them is read on the way to rendering a page and written
    /// into a settings document that is loaded per request. The catalogue is
    /// smaller than this today; the bound is here so that the size of the
    /// document is a property of this type rather than of whatever an admin API
    /// happened to accept.
    pub const MAX_ENTRIES: usize = 64;

    /// The longest key accepted, in bytes.
    pub const MAX_KEY_BYTES: usize = 64;

    /// The longest replacement accepted, in bytes.
    ///
    /// These are labels, buttons and a sentence or two of explanation. A value
    /// past this is not a translation of anything on these pages.
    pub const MAX_VALUE_BYTES: usize = 512;

    /// Reads the overrides out of a tenant's settings document.
    ///
    /// An absent or `null` member is a tenant that has overridden nothing. A
    /// member that is present and wrong is refused rather than dropped, for the
    /// reason `TenantSettings::from_json` gives: settings rows get edited by
    /// hand during incidents, and a value that quietly fell back to the built-in
    /// wording is a setting an operator believes is in force and is not.
    ///
    /// # Errors
    ///
    /// [`MessageOverrideError`], always naming the key it refused, so that an
    /// administrator is told which of sixty strings is the problem rather than
    /// that "the overrides are invalid".
    // fuzz-target: tenant_message_overrides
    pub fn from_json(value: Option<&serde_json::Value>) -> Result<Self, MessageOverrideError> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        if value.is_null() {
            return Ok(Self::default());
        }
        let object = value.as_object().ok_or(MessageOverrideError::NotAnObject)?;
        if object.len() > Self::MAX_ENTRIES {
            return Err(MessageOverrideError::TooMany {
                count: object.len(),
                maximum: Self::MAX_ENTRIES,
            });
        }

        let mut overrides = BTreeMap::new();
        for (key, entry) in object {
            check_key(key)?;
            let text = entry
                .as_str()
                .ok_or_else(|| MessageOverrideError::NotAString { key: key.clone() })?;
            check_text(key, text)?;
            overrides.insert(key.clone(), text.to_owned());
        }
        Ok(Self(overrides))
    }

    /// The overrides as they are stored.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.0
                .iter()
                .map(|(key, text)| (key.clone(), serde_json::Value::String(text.clone())))
                .collect(),
        )
    }

    /// The replacement for a key, if there is one.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Every key that was overridden.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.0.keys().map(String::as_str)
    }

    /// Whether the tenant overrode nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Builds a set from pairs, applying the same checks as [`Self::from_json`].
    ///
    /// The route an admin API takes. It exists so that a caller holding typed
    /// values does not have to build a `serde_json::Value` to be validated, and
    /// so that there is exactly one implementation of the checks.
    ///
    /// # Errors
    ///
    /// As [`Self::from_json`].
    pub fn from_pairs<I, K, V>(pairs: I) -> Result<Self, MessageOverrideError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut overrides = BTreeMap::new();
        for (key, text) in pairs {
            let (key, text) = (key.as_ref(), text.as_ref());
            check_key(key)?;
            check_text(key, text)?;
            overrides.insert(key.to_owned(), text.to_owned());
        }
        if overrides.len() > Self::MAX_ENTRIES {
            return Err(MessageOverrideError::TooMany {
                count: overrides.len(),
                maximum: Self::MAX_ENTRIES,
            });
        }
        Ok(Self(overrides))
    }
}

/// A key is `[a-z0-9]` separated by `-` and `.`: `consent.allow`,
/// `login.sign-in`.
///
/// Narrow on purpose. The key is a *path into a catalogue*, it is echoed back
/// in error messages an administrator reads, and it is the one part of an
/// override that this server compares rather than renders. Nothing is lost by
/// refusing anything else, and a key space that admits arbitrary bytes is one
/// where "unknown key" reports become an echo of whatever was sent.
fn check_key(key: &str) -> Result<(), MessageOverrideError> {
    if key.is_empty() || key.len() > MessageOverrides::MAX_KEY_BYTES {
        return Err(MessageOverrideError::KeyLength {
            key: key.chars().take(32).collect(),
            maximum: MessageOverrides::MAX_KEY_BYTES,
        });
    }
    let shaped = key
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !key.starts_with(['.', '-'])
        && !key.ends_with(['.', '-'])
        && !key.contains("..");
    if !shaped {
        return Err(MessageOverrideError::KeyShape {
            key: key.chars().take(32).collect(),
        });
    }
    Ok(())
}

/// The value checks: not empty, not too long, not markup, not control bytes.
fn check_text(key: &str, text: &str) -> Result<(), MessageOverrideError> {
    if text.trim().is_empty() {
        return Err(MessageOverrideError::Empty {
            key: key.to_owned(),
        });
    }
    if text.len() > MessageOverrides::MAX_VALUE_BYTES {
        return Err(MessageOverrideError::TooLong {
            key: key.to_owned(),
            bytes: text.len(),
            maximum: MessageOverrides::MAX_VALUE_BYTES,
        });
    }
    if let Some(character) = text.chars().find(|c| matches!(c, '<' | '>')) {
        return Err(MessageOverrideError::Markup {
            key: key.to_owned(),
            character,
        });
    }
    // Newlines are text; everything else in the C0 range, plus DEL and the
    // bidirectional overrides, is not. `U+202E RIGHT-TO-LEFT OVERRIDE` in a
    // consent sentence reverses what a person reads without changing what is
    // stored, which is the Trojan Source trick (CVE-2021-42574) pointed at a
    // human decision rather than at a compiler.
    if let Some(character) = text.chars().find(|c| {
        (c.is_control() && *c != '\n' && *c != '\t')
            || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    }) {
        return Err(MessageOverrideError::ControlCharacter {
            key: key.to_owned(),
            codepoint: character as u32,
        });
    }
    Ok(())
}

/// Why an override was refused.
///
/// Every variant names its key. An administrator told "invalid overrides" edits
/// at random; one told `consent.allow contains '<'` fixes the string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MessageOverrideError {
    /// The stored member is not a JSON object.
    #[error("the tenant's message overrides are not an object")]
    NotAnObject,
    /// More overrides than one tenant may hold.
    #[error("{count} message overrides exceeds the maximum of {maximum}")]
    TooMany {
        /// How many arrived.
        count: usize,
        /// How many are allowed.
        maximum: usize,
    },
    /// The key is empty or longer than the bound.
    #[error("the message key '{key}' is empty or longer than {maximum} bytes")]
    KeyLength {
        /// The key, truncated for the message.
        key: String,
        /// The bound.
        maximum: usize,
    },
    /// The key uses characters a message key may not.
    #[error("the message key '{key}' is not a dotted lower-case key such as 'consent.allow'")]
    KeyShape {
        /// The key, truncated for the message.
        key: String,
    },
    /// The value is not a JSON string.
    #[error("the message override for '{key}' is not a string")]
    NotAString {
        /// Which key.
        key: String,
    },
    /// The value is blank.
    #[error("the message override for '{key}' is blank; remove the key instead")]
    Empty {
        /// Which key.
        key: String,
    },
    /// The value is longer than the bound.
    #[error("the message override for '{key}' is {bytes} bytes, past the maximum of {maximum}")]
    TooLong {
        /// Which key.
        key: String,
        /// How long it was.
        bytes: usize,
        /// The bound.
        maximum: usize,
    },
    /// The value contains `<` or `>`.
    #[error(
        "the message override for '{key}' contains '{character}': overrides are text, and a \
         tenant supplies no markup"
    )]
    Markup {
        /// Which key.
        key: String,
        /// Which character was found.
        character: char,
    },
    /// The value contains a control or bidirectional-override character.
    #[error(
        "the message override for '{key}' contains the non-printing character U+{codepoint:04X}"
    )]
    ControlCharacter {
        /// Which key.
        key: String,
        /// What was found.
        codepoint: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_absent_member_is_a_tenant_that_overrode_nothing() {
        let overrides = MessageOverrides::from_json(None).expect("absent is not an error");

        assert!(overrides.is_empty());
    }

    #[test]
    fn a_plain_string_replaces_the_built_in_wording() {
        let stored = json!({ "consent.allow": "Autoriser" });

        let overrides = MessageOverrides::from_json(Some(&stored)).expect("a plain string");

        assert_eq!(overrides.get("consent.allow"), Some("Autoriser"));
    }

    /// The acceptance criterion, at the layer that accepts the value.
    #[test]
    fn a_script_tag_is_refused_at_the_door() {
        let stored = json!({ "consent.allow": "<script>alert(1)</script>" });

        let refused = MessageOverrides::from_json(Some(&stored)).expect_err("markup is refused");

        assert_eq!(
            refused,
            MessageOverrideError::Markup {
                key: "consent.allow".to_owned(),
                character: '<',
            }
        );
    }

    #[test]
    fn a_bare_angle_bracket_is_refused_too() {
        let stored = json!({ "consent.allow": "a > b" });

        assert!(matches!(
            MessageOverrides::from_json(Some(&stored)),
            Err(MessageOverrideError::Markup { .. })
        ));
    }

    #[test]
    fn a_bidirectional_override_is_refused() {
        let stored = json!({ "consent.allow": "Allow \u{202e}yned" });

        assert!(matches!(
            MessageOverrides::from_json(Some(&stored)),
            Err(MessageOverrideError::ControlCharacter { .. })
        ));
    }

    #[test]
    fn a_refusal_names_the_key_it_refused() {
        let stored = json!({ "consent.deny": 7 });

        let refused = MessageOverrides::from_json(Some(&stored)).expect_err("not a string");

        assert!(refused.to_string().contains("consent.deny"), "{refused}");
    }

    #[test]
    fn a_key_that_is_not_key_shaped_is_refused() {
        let stored = json!({ "Consent Allow": "x" });

        assert!(matches!(
            MessageOverrides::from_json(Some(&stored)),
            Err(MessageOverrideError::KeyShape { .. })
        ));
    }

    #[test]
    fn an_oversized_value_is_refused() {
        let long = "a".repeat(MessageOverrides::MAX_VALUE_BYTES + 1);
        let stored = json!({ "consent.allow": long });

        assert!(matches!(
            MessageOverrides::from_json(Some(&stored)),
            Err(MessageOverrideError::TooLong { .. })
        ));
    }

    #[test]
    fn a_blank_value_is_refused_rather_than_rendered_as_an_empty_button() {
        let stored = json!({ "consent.allow": "   " });

        assert!(matches!(
            MessageOverrides::from_json(Some(&stored)),
            Err(MessageOverrideError::Empty { .. })
        ));
    }

    #[test]
    fn what_is_written_reads_back_the_same() {
        let stored = json!({ "consent.allow": "Autoriser", "consent.deny": "Refuser" });

        let overrides = MessageOverrides::from_json(Some(&stored)).expect("valid");

        assert_eq!(overrides.to_json(), stored);
    }

    #[test]
    fn the_pairs_constructor_applies_the_same_checks() {
        assert!(matches!(
            MessageOverrides::from_pairs([("consent.allow", "<b>")]),
            Err(MessageOverrideError::Markup { .. })
        ));
    }
}
