//! Wire validation and rendering for the resource-server administration routes.

use asterius_domain::{ClientId, ResourceIdentifier, ResourceServer};
use serde::Deserialize;
use std::collections::BTreeSet;
use time::Duration;

use crate::AdminError;

/// The editable part of a resource server. Its identifier stays in the path,
/// so a replacement cannot accidentally rename the row it was opened from.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Document {
    /// `null` means the resource accepts every granted scope; an empty array
    /// deliberately means it accepts none.
    pub scopes: Option<Vec<String>>,
    pub default_token_lifetime_seconds: Option<i64>,
    #[serde(default)]
    pub introspection_clients: Vec<String>,
}

pub fn parse(identifier: &str, document: Document) -> Result<ResourceServer, AdminError> {
    let identifier = ResourceIdentifier::parse(identifier).map_err(|_| {
        AdminError::Invalid("identifier must be an absolute, fragment-free URL".to_owned())
    })?;
    let scopes = document
        .scopes
        .map(|values| {
            values
                .into_iter()
                .map(|scope| validate_scope(&scope).map(|()| scope))
                .collect::<Result<BTreeSet<_>, _>>()
        })
        .transpose()?;
    let default_token_lifetime = document
        .default_token_lifetime_seconds
        .map(|seconds| {
            (seconds > 0 && seconds <= 86_400)
                .then(|| Duration::seconds(seconds))
                .ok_or_else(|| {
                    AdminError::Invalid(
                        "default_token_lifetime_seconds must be between 1 and 86400".to_owned(),
                    )
                })
        })
        .transpose()?;
    Ok(ResourceServer {
        identifier,
        scopes,
        default_token_lifetime,
        introspection_clients: document
            .introspection_clients
            .into_iter()
            .map(ClientId::new)
            .collect(),
    })
}

fn validate_scope(scope: &str) -> Result<(), AdminError> {
    let valid = !scope.is_empty()
        && scope.len() <= 128
        && scope.bytes().all(|byte| {
            byte == b'!' || (b'#'..=b'[').contains(&byte) || (b']'..=b'~').contains(&byte)
        });
    valid
        .then_some(())
        .ok_or_else(|| AdminError::Invalid(format!("scope '{scope}' is not an OAuth scope token")))
}

#[must_use]
pub fn render(server: &ResourceServer) -> serde_json::Value {
    serde_json::json!({
        "identifier": server.identifier.as_str(),
        "scopes": server.scopes.as_ref().map(|values| values.iter().collect::<Vec<_>>()),
        "default_token_lifetime_seconds": server.default_token_lifetime.map(time::Duration::whole_seconds),
        "introspection_clients": server.introspection_clients.iter().map(ClientId::as_str).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_are_deduplicated_and_sorted() {
        let server = parse(
            "https://api.example/",
            Document {
                scopes: Some(vec![
                    "write".to_owned(),
                    "read".to_owned(),
                    "read".to_owned(),
                ]),
                default_token_lifetime_seconds: None,
                introspection_clients: vec![],
            },
        )
        .expect("a resource server");
        assert_eq!(
            server
                .scopes
                .expect("scopes")
                .into_iter()
                .collect::<Vec<_>>(),
            ["read", "write"]
        );
    }

    #[test]
    fn whitespace_is_not_a_scope_token() {
        let result = parse(
            "https://api.example/",
            Document {
                scopes: Some(vec!["account read".to_owned()]),
                default_token_lifetime_seconds: None,
                introspection_clients: vec![],
            },
        );
        assert!(result.is_err());
    }
}
