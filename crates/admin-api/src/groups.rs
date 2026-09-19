//! Wire documents for tenant-scoped managed groups.

use asterius_domain::{Group, GroupMetadata};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AdminError;

/// A create or full metadata replacement.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedGroup {
    /// Stable machine-facing name, unique within the tenant.
    pub name: String,
    /// Human-facing label.
    pub display_name: String,
}

impl RequestedGroup {
    /// Validates the document with the domain's one metadata parser.
    pub fn metadata(&self) -> Result<GroupMetadata, AdminError> {
        GroupMetadata::parse(&self.name, &self.display_name)
            .map_err(|error| AdminError::Invalid(error.to_string()))
    }
}

/// Optimistic-concurrency token for a replacement or deletion.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedRevision {
    /// The revision returned by the last read.
    pub revision: i64,
}

/// Renders all non-secret persisted group fields.
#[must_use]
pub fn document(group: &Group) -> Value {
    json!({
        "id": group.id.as_uuid().to_string(),
        "name": group.metadata.name().as_str(),
        "display_name": group.metadata.display_name(),
        "revision": group.revision,
        "created_at": group.created_at,
        "updated_at": group.updated_at,
    })
}
