//! Closed temporary-entitlement administrative documents.
use asterius_domain::temporary_entitlements::EntitlementConfiguration;
use serde::Deserialize;
use uuid::Uuid;
#[derive(Debug)]
pub struct ReplaceConfiguration {
    pub expected_revision: Uuid,
    pub configuration: EntitlementConfiguration,
}
impl ReplaceConfiguration {
    pub fn parse(mut value: serde_json::Value) -> Result<Self, crate::AdminError> {
        let invalid = || {
            crate::AdminError::Invalid(
                "configuration and exact expected_revision UUID required".into(),
            )
        };
        let object = value.as_object_mut().ok_or_else(invalid)?;
        let revision = object.remove("expected_revision").ok_or_else(invalid)?;
        let expected_revision = serde_json::from_value(revision).map_err(|_| invalid())?;
        let configuration = serde_json::from_value(value).map_err(|_| invalid())?;
        Ok(Self {
            expected_revision,
            configuration,
        })
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoveEligibility {
    pub expected_revision: Uuid,
}
