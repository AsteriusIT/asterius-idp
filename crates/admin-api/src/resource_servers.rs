//! Wire validation and rendering for the resource-server administration routes.

use asterius_domain::{ClientId, ResourceIdentifier, ResourceServer};
use serde::Deserialize;
use std::collections::BTreeSet;
use time::Duration;

use crate::AdminError;

/// Resource-server callers are names, not credentials, but still arrive in an
/// administrator-controlled JSON array. Bound each one before it becomes a
/// value retained in the registry. The server-minted ids are much shorter;
/// this ceiling leaves room for imported deployments without admitting an
/// unbounded row.
const MAX_INTROSPECTION_CLIENT_ID_LEN: usize = 512;

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
            .map(|client| validate_introspection_client(&client).map(|()| ClientId::new(client)))
            .collect::<Result<_, _>>()?,
    })
}

fn validate_introspection_client(client: &str) -> Result<(), AdminError> {
    let valid = !client.is_empty()
        && client.len() <= MAX_INTROSPECTION_CLIENT_ID_LEN
        && !client.chars().any(char::is_control);
    valid.then_some(()).ok_or_else(|| {
        AdminError::Invalid(format!(
            "introspection client ids must be 1 to {MAX_INTROSPECTION_CLIENT_ID_LEN} characters and contain no control characters"
        ))
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

    #[test]
    fn the_complete_registration_round_trips_without_widening_it() {
        let server = parse(
            "https://api.example/accounts",
            Document {
                scopes: Some(vec![
                    "accounts:write".to_owned(),
                    "accounts:read".to_owned(),
                ]),
                default_token_lifetime_seconds: Some(300),
                introspection_clients: vec![
                    "c.reports".to_owned(),
                    "c.gateway".to_owned(),
                    "c.gateway".to_owned(),
                ],
            },
        )
        .expect("a complete resource server");

        assert_eq!(
            render(&server),
            serde_json::json!({
                "identifier": "https://api.example/accounts",
                "scopes": ["accounts:read", "accounts:write"],
                "default_token_lifetime_seconds": 300,
                "introspection_clients": ["c.gateway", "c.reports"],
            })
        );
    }

    #[test]
    fn invalid_lifetimes_and_introspection_clients_are_refused() {
        for lifetime in [0, 86_401] {
            let result = parse(
                "https://api.example/",
                Document {
                    scopes: None,
                    default_token_lifetime_seconds: Some(lifetime),
                    introspection_clients: vec![],
                },
            );
            assert!(result.is_err());
        }

        for client in [String::new(), "line\nbreak".to_owned(), "x".repeat(513)] {
            let result = parse(
                "https://api.example/",
                Document {
                    scopes: None,
                    default_token_lifetime_seconds: None,
                    introspection_clients: vec![client],
                },
            );
            assert!(result.is_err());
        }
    }
}
