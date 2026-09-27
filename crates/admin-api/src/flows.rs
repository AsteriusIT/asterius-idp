//! Versioned architecture graph documents and connection rules.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AdminError;

#[derive(Debug, Clone)]
pub struct LinkIntent {
    pub node: String,
    pub kind: String,
    pub resource: String,
    pub relation: String,
}

#[derive(Debug, Clone)]
pub struct ApplyStep {
    pub flow: uuid::Uuid,
    pub token: uuid::Uuid,
    pub revision: i64,
    pub node: String,
    pub now: time::OffsetDateTime,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionRequest {
    pub revision: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyRequest {
    pub revision: i64,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanStep {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub action: String,
    pub scope: String,
    pub resource_id: Option<String>,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub flow_id: String,
    pub revision: i64,
    pub digest: String,
    pub applicable: bool,
    pub steps: Vec<PlanStep>,
}

#[must_use]
pub fn scope_for(kind: NodeKind, write: bool) -> &'static str {
    match (kind, write) {
        (NodeKind::Application | NodeKind::IdentityProvider, false) => "admin.clients:read",
        (NodeKind::Application | NodeKind::IdentityProvider, true) => "admin.clients:write",
        (NodeKind::Api, false) => "admin.resource_servers:read",
        (NodeKind::Api, true) => "admin.resource_servers:write",
        (NodeKind::Group, false) => "admin.groups:read",
        (NodeKind::Group, true) => "admin.groups:write",
        (NodeKind::Role, false) => "admin.app_roles:read",
        (NodeKind::Role, true) => "admin.app_roles:write",
        (NodeKind::Stream, false) => "admin.ssf:read",
        (NodeKind::Stream, true) => "admin.ssf:write",
    }
}

/// Only public registration parameters are allowed in a flow. A private key
/// or client secret has no place in a saved diagram.
pub fn application_registration(node: &Node) -> Result<Value, AdminError> {
    let redirects = node
        .settings
        .get("redirect_uris")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AdminError::Invalid(format!("{}: add at least one redirect URI", node.label))
        })?;
    let jwks_uri = node
        .settings
        .get("jwks_uri")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AdminError::Invalid(format!("{}: add a public JWKS URI", node.label)))?;
    if redirects.is_empty() || !redirects.iter().all(Value::is_string) {
        return Err(AdminError::Invalid(format!(
            "{}: redirect URIs must be non-empty strings",
            node.label
        )));
    }
    Ok(serde_json::json!({
        "client_name": node.label,
        "redirect_uris": redirects,
        "grant_types": ["authorization_code"],
        "scope": "openid",
        "jwks_uri": jwks_uri,
        "token_endpoint_auth_method": "private_key_jwt",
        "id_token_signed_response_alg": "EdDSA",
        "dpop_bound_access_tokens": true,
        "require_pushed_authorization_requests": true,
        "compliance_profile": "fapi",
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowInput {
    pub name: String,
    pub graph: Graph,
    #[serde(default)]
    pub revision: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Graph {
    pub schema_version: u8,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    pub identifier: String,
    pub mode: NodeMode,
    pub x: f64,
    pub y: f64,
    #[serde(default)]
    pub settings: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Application,
    Api,
    Group,
    Role,
    Stream,
    IdentityProvider,
}

impl NodeKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Api => "api",
            Self::Group => "group",
            Self::Role => "role",
            Self::Stream => "stream",
            Self::IdentityProvider => "identity_provider",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeMode {
    Managed,
    Reference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edge {
    pub id: String,
    pub source: String,
    pub target: String,
}

#[must_use]
pub fn permits(source: NodeKind, target: NodeKind) -> bool {
    matches!(
        (source, target),
        (
            NodeKind::Application,
            NodeKind::Api | NodeKind::Role | NodeKind::Stream
        ) | (NodeKind::Group, NodeKind::Role)
            | (NodeKind::IdentityProvider, NodeKind::Application)
    )
}

impl FlowInput {
    // Graph-wide ID, connection, and secret-field checks share one pass so
    // every saved revision is accepted or refused as one document.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), AdminError> {
        if self.name.trim().is_empty() || self.name.len() > 120 {
            return Err(AdminError::Invalid(
                "flow name must be 1–120 characters".into(),
            ));
        }
        if self.graph.schema_version != 1 {
            return Err(AdminError::Invalid(
                "unsupported graph schema version".into(),
            ));
        }
        if self.graph.nodes.len() > 100 || self.graph.edges.len() > 200 {
            return Err(AdminError::Invalid(
                "flow exceeds 100 nodes or 200 connections".into(),
            ));
        }
        let mut ids = HashSet::new();
        for node in &self.graph.nodes {
            if !ids.insert(node.id.as_str()) || node.id.is_empty() || node.id.len() > 80 {
                return Err(AdminError::Invalid(
                    "node IDs must be unique and 1–80 characters".into(),
                ));
            }
            if node.label.trim().is_empty() || node.label.len() > 120 || node.identifier.len() > 255
            {
                return Err(AdminError::Invalid(
                    "node label or identifier is invalid".into(),
                ));
            }
            if !node.x.is_finite()
                || !node.y.is_finite()
                || node.x.abs() > 100_000.0
                || node.y.abs() > 100_000.0
            {
                return Err(AdminError::Invalid("node position is out of range".into()));
            }
            if !node.settings.is_null() && !node.settings.is_object() {
                return Err(AdminError::Invalid(
                    "node settings must be an object".into(),
                ));
            }
            if let Some(settings) = node.settings.as_object() {
                let allowed: &[&str] = match node.kind {
                    NodeKind::Application => &["redirect_uris", "jwks_uri"],
                    NodeKind::Api => &[
                        "scopes",
                        "default_token_lifetime_seconds",
                        "introspection_clients",
                    ],
                    NodeKind::Role => &["description"],
                    NodeKind::Group | NodeKind::Stream | NodeKind::IdentityProvider => &[],
                };
                if settings.keys().any(|key| !allowed.contains(&key.as_str())) {
                    return Err(AdminError::Invalid(
                        "unsupported or secret node setting".into(),
                    ));
                }
                if settings
                    .get("jwks_uri")
                    .is_some_and(|value| value.as_str().is_none_or(|value| value.len() > 2048))
                    || settings
                        .get("description")
                        .is_some_and(|value| value.as_str().is_none_or(|value| value.len() > 400))
                    || ["redirect_uris", "scopes", "introspection_clients"]
                        .iter()
                        .any(|key| {
                            settings.get(*key).is_some_and(|value| {
                                value.as_array().is_none_or(|values| {
                                    values.len() > 100
                                        || values.iter().any(|value| {
                                            value.as_str().is_none_or(|value| value.len() > 2048)
                                        })
                                })
                            })
                        })
                    || settings
                        .get("default_token_lifetime_seconds")
                        .is_some_and(|value| {
                            value
                                .as_i64()
                                .is_none_or(|value| !(1..=86_400).contains(&value))
                        })
                {
                    return Err(AdminError::Invalid("node settings are out of range".into()));
                }
            }
        }
        let mut edge_ids = HashSet::new();
        let mut pairs = HashSet::new();
        for edge in &self.graph.edges {
            let source = self.graph.nodes.iter().find(|node| node.id == edge.source);
            let target = self.graph.nodes.iter().find(|node| node.id == edge.target);
            if edge.id.is_empty()
                || edge.id.len() > 80
                || ids.contains(edge.id.as_str())
                || !edge_ids.insert(edge.id.as_str())
                || !pairs.insert((&edge.source, &edge.target))
            {
                return Err(AdminError::Invalid(
                    "connections must have unique IDs and endpoints".into(),
                ));
            }
            if !source
                .zip(target)
                .is_some_and(|(source, target)| permits(source.kind, target.kind))
            {
                return Err(AdminError::Invalid(
                    "connection is not valid for these node types".into(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_cross_type_and_dangling_connections() {
        let mut input = FlowInput {
            name: "Example".into(),
            revision: None,
            graph: Graph {
                schema_version: 1,
                nodes: vec![
                    Node {
                        id: "a".into(),
                        kind: NodeKind::Application,
                        label: "App".into(),
                        identifier: "app".into(),
                        mode: NodeMode::Managed,
                        x: 0.0,
                        y: 0.0,
                        settings: Value::Null,
                    },
                    Node {
                        id: "b".into(),
                        kind: NodeKind::Api,
                        label: "API".into(),
                        identifier: "api".into(),
                        mode: NodeMode::Managed,
                        x: 1.0,
                        y: 1.0,
                        settings: Value::Null,
                    },
                ],
                edges: vec![Edge {
                    id: "e".into(),
                    source: "b".into(),
                    target: "a".into(),
                }],
            },
        };
        assert!(input.validate().is_err());
        input.graph.edges[0].source = "a".into();
        input.graph.edges[0].target = "b".into();
        assert!(input.validate().is_ok());
        input.graph.edges[0].target = "missing".into();
        assert!(input.validate().is_err());
    }

    #[test]
    fn saved_graph_rejects_credentials() {
        let input = FlowInput {
            name: "Secret".into(),
            revision: None,
            graph: Graph {
                schema_version: 1,
                nodes: vec![Node {
                    id: "app".into(),
                    kind: NodeKind::Application,
                    label: "App".into(),
                    identifier: String::new(),
                    mode: NodeMode::Managed,
                    x: 0.0,
                    y: 0.0,
                    settings: serde_json::json!({ "client_secret": "must-not-persist" }),
                }],
                edges: vec![],
            },
        };
        assert!(input.validate().is_err());
    }
}
