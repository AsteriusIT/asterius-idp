//! Versioned architecture graph documents and connection rules.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::AdminError;

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
        }
        let mut edge_ids = HashSet::new();
        let mut pairs = HashSet::new();
        for edge in &self.graph.edges {
            let source = self.graph.nodes.iter().find(|node| node.id == edge.source);
            let target = self.graph.nodes.iter().find(|node| node.id == edge.target);
            if edge.id.is_empty()
                || edge.id.len() > 80
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
}
