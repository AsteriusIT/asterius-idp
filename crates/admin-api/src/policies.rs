//! The tenant's authorization policy, as an administrator edits it
//! (`ast-pj0.4`).
//!
//! Three routes over one document: read it, replace it, remove it. There is no
//! route that edits a single rule, and that is the model rather than a missing
//! feature — deny precedence is a property of the *set* ([ADR-0011]), so a
//! partial write would leave a tenant authorised by half of two policies.
//!
//! # The document is data, and this module is where that is enforced
//!
//! Everything a tenant sends goes through
//! [`asterius_domain::policy::RuleSet::parse`], the fuzzed parser, before it
//! reaches the store — and the port's write side takes a `RuleSet`, so there is
//! no way to store a document that was not parsed. A tenant therefore cannot
//! supply *code*: the closed condition set is the whole vocabulary, and a
//! member this build does not know is a 400 naming the path rather than
//! something stored for a later build to interpret.
//!
//! # What a refusal says
//!
//! The path the parser reports — `rules[3].when.attribute.of` — and the reason,
//! both of which are members of this server's own schema. Never the value the
//! administrator typed: an error body is the easiest thing in an API to end up
//! in a screenshot, and a rule's literals are the attribute values a tenant
//! reasons about.
//!
//! [ADR-0011]: https://github.com/AsteriusIT/asterius-idp/blob/main/docs/adr/0011-a-declarative-rule-model-for-the-built-in-pdp.md

use asterius_domain::policy::{RuleSet, StoredPolicy};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;

use crate::error::AdminError;

/// The largest policy document this API reads, before the shared body limit.
///
/// The same bound the parser applies to a stored row
/// ([`asterius_domain::policy::document::MAX_DOCUMENT_BYTES`]), so a document
/// that is accepted here is one that can be read back.
pub const MAX_BODY_BYTES: usize = asterius_domain::policy::document::MAX_DOCUMENT_BYTES;

/// Parses a `PUT /policies` body.
///
/// # Errors
///
/// [`AdminError::Invalid`] with the parser's path and reason.
pub fn parse_document(body: &[u8]) -> Result<RuleSet, AdminError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(AdminError::Invalid(
            "the policy document is larger than this API accepts".to_owned(),
        ));
    }
    let raw = std::str::from_utf8(body)
        .map_err(|_| AdminError::Invalid("the policy document is not UTF-8".to_owned()))?;
    RuleSet::parse(raw).map_err(|error| AdminError::Invalid(error.to_string()))
}

/// The document as `GET /policies` renders it.
///
/// `document` is exactly what [`RuleSet::to_json`] writes, so the console can
/// fetch it, edit it and `PUT` it back unchanged. `updated_at` is beside it and
/// not inside it, because it is this server's stamp and not part of the policy:
/// a document round-tripped through the editor must not grow a member the
/// parser would then have to ignore.
#[must_use]
pub fn document(policy: Option<&StoredPolicy>) -> Value {
    match policy {
        Some(policy) => json!({
            "document": policy.rules.to_json(),
            "rule_count": policy.rules.rules().len(),
            "updated_at": policy
                .updated_at
                .format(&Rfc3339)
                .unwrap_or_else(|_| String::new()),
        }),
        // A tenant that has never written one. `document` is the empty policy
        // rather than `null`, so that the editor opens on something valid and
        // a `PUT` of what was fetched is a no-op rather than a 400.
        None => json!({
            "document": RuleSet::deny_all().to_json(),
            "rule_count": 0,
            "updated_at": Value::Null,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[test]
    fn a_valid_document_is_accepted() {
        // Arrange
        let body = br#"{"version": 1, "rules": [{"id": "r", "effect": "deny"}]}"#;

        // Act
        let parsed = parse_document(body).expect("a valid document");

        // Assert
        assert_eq!(parsed.rules().len(), 1);
    }

    #[test]
    fn a_refusal_names_the_path_in_the_document() {
        // Arrange
        let body = br#"{"version": 1, "rules": [{"id": "r", "effect": "permit",
                        "when": {"eval": "1 + 1"}}]}"#;

        // Act
        let refused = parse_document(body).expect_err("an unknown condition");

        // Assert
        let AdminError::Invalid(message) = refused else {
            panic!("expected an invalid-request refusal");
        };
        assert!(message.contains("rules[0].when"), "{message}");
    }

    /// A tenant cannot supply code: the condition set is closed, and a member
    /// this build does not know is refused rather than stored for a later
    /// build to interpret.
    #[test]
    fn a_document_this_build_does_not_understand_is_not_stored() {
        // Arrange
        let body = br#"{"version": 2, "rules": []}"#;

        // Act / Assert
        assert!(parse_document(body).is_err());
    }

    #[test]
    fn a_body_that_is_not_utf8_is_refused() {
        assert!(parse_document(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn a_tenant_with_no_policy_renders_an_empty_document() {
        // Arrange / Act
        let rendered = document(None);

        // Assert
        assert_eq!(rendered["rule_count"], json!(0));
        assert_eq!(rendered["updated_at"], Value::Null);
        assert!(RuleSet::from_json(&rendered["document"]).is_ok());
    }

    /// What the editor fetched is what it may `PUT` back.
    #[test]
    fn a_rendered_document_parses_as_the_policy_it_came_from() {
        // Arrange
        let rules = RuleSet::parse(r#"{"version": 1, "rules": [{"id": "r", "effect": "deny"}]}"#)
            .expect("a valid document");
        let stored = StoredPolicy {
            rules: rules.clone(),
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };

        // Act
        let rendered = document(Some(&stored));

        // Assert
        assert_eq!(RuleSet::from_json(&rendered["document"]), Ok(rules));
        assert_eq!(rendered["updated_at"], json!("1970-01-01T00:00:00Z"));
    }
}
