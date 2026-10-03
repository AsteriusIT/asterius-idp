//! Classification is an explicit administrative CAS operation, never DCR input.
use asterius_domain::policy::conditional::Sensitivity;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedSettings {
    pub sensitivity: Option<Sensitivity>,
    pub expected_revision: Option<Uuid>,
}

impl RequestedSettings {
    // fuzz-target: conditional_client_settings
    pub fn parse(value: &Value) -> Result<Self, crate::AdminError> {
        let invalid = || crate::AdminError::Invalid("conditional classification requires sensitivity and expected_revision".to_owned());
        if !value.as_object().is_some_and(|object| object.len() == 2 && object.contains_key("sensitivity") && object.contains_key("expected_revision")) {
            return Err(invalid());
        }
        serde_json::from_value(value.clone()).map_err(|_| invalid())
    }
}
