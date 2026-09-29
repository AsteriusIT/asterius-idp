//! Validation and rendering for RFC 9396 authorization-details type administration.

use asterius_domain::{AuthorizationDetailsType, JsonSchema};
use serde::Deserialize;

use crate::AdminError;

/// The editable document for one registered type.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub schema: serde_json::Value,
    pub consent_template: Option<String>,
}

/// Validates a type name, schema, and user-facing consent sentence.
pub fn parse(name: &str, document: Document) -> Result<AuthorizationDetailsType, AdminError> {
    if !asterius_domain::entities::authorization_details::is_type_name(name) {
        return Err(AdminError::Invalid(
            "type must be 1 to 128 printable ASCII characters without quotes or backslashes"
                .to_owned(),
        ));
    }
    if document
        .consent_template
        .as_ref()
        .is_some_and(|template| template.chars().count() > 512)
    {
        return Err(AdminError::Invalid(
            "consent_template must be at most 512 characters".to_owned(),
        ));
    }
    let schema = JsonSchema::parse(&document.schema)
        .map_err(|failure| AdminError::Invalid(format!("schema: {failure}")))?;
    Ok(AuthorizationDetailsType {
        name: name.to_owned(),
        schema,
        consent_template: document.consent_template,
    })
}

#[must_use]
pub fn render(kind: &AuthorizationDetailsType) -> serde_json::Value {
    serde_json::json!({
        "type": kind.name,
        "schema": kind.schema.document(),
        "consent_template": kind.consent_template,
    })
}

/// A bounded request evaluated by the same schema implementation as authorization.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleDocument {
    pub schema: serde_json::Value,
    pub sample: serde_json::Value,
}

pub fn validate_sample(document: &SampleDocument) -> Result<serde_json::Value, AdminError> {
    let schema = JsonSchema::parse(&document.schema)
        .map_err(|failure| AdminError::Invalid(format!("schema: {failure}")))?;
    Ok(match schema.validate(&document.sample) {
        Ok(()) => serde_json::json!({"valid": true}),
        Err(error) => serde_json::json!({"valid": false, "message": error.to_string()}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn samples_use_the_authorization_validator_without_reflecting_values() {
        let result = validate_sample(&SampleDocument {
            schema: json!({"type":"object","properties":{"amount":{"type":"string","maxLength":3}}}),
            sample: json!({"amount":"private-value"}),
        }).expect("valid schema");
        assert_eq!(result["valid"], false);
        assert!(
            result["message"]
                .as_str()
                .expect("message")
                .contains("amount")
        );
        assert!(!result.to_string().contains("private-value"));
        assert_eq!(
            validate_sample(&SampleDocument {
                schema: json!({"type":"object"}),
                sample: json!({})
            })
            .expect("valid sample")["valid"],
            true
        );
    }

    #[test]
    fn unsupported_schema_keywords_are_explained() {
        let error = parse(
            "payment",
            Document {
                schema: json!({"pattern": "secret"}),
                consent_template: None,
            },
        )
        .expect_err("pattern is outside the supported schema subset");
        assert!(error.to_string().contains("pattern"));
    }

    #[test]
    fn valid_documents_round_trip() {
        let kind = parse(
            "payment",
            Document {
                schema: json!({"type": "object", "required": ["amount"]}),
                consent_template: Some("Make this payment".to_owned()),
            },
        )
        .expect("a supported schema");
        assert_eq!(render(&kind)["schema"]["required"], json!(["amount"]));
    }
}
