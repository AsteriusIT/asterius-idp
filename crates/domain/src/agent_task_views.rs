//! Read-only task provenance. These snapshots never authorize token issuance.
use crate::agent_tasks::Permissions;
use crate::{ClientId, DomainError, TenantId};
use serde::Serialize;
use std::collections::BTreeSet;
use uuid::Uuid;

pub const MAX_TASK_PAGE: usize = 50;
pub const MAX_LINEAGE_ROWS: usize = 10;

/// Closed pagination/filter grammar, shared by the administration API and store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub cursor: Option<Uuid>,
    pub owner: Option<Uuid>,
    pub agent: Option<ClientId>,
    pub limit: usize,
}
impl Default for Query {
    fn default() -> Self {
        Self {
            cursor: None,
            owner: None,
            agent: None,
            limit: 25,
        }
    }
}
impl Query {
    // fuzz-target: agent_task_view_query
    pub fn parse(raw: Option<&str>) -> Result<Self, DomainError> {
        let raw = raw.unwrap_or_default();
        if raw.len() > 2048 {
            return Err(invalid());
        }
        let mut query = Self::default();
        let mut seen = BTreeSet::new();
        for (name, value) in url::form_urlencoded::parse(raw.as_bytes()) {
            if !seen.insert(name.to_string()) {
                return Err(invalid());
            }
            match name.as_ref() {
                "cursor" => query.cursor = Some(identity(&value)?),
                "owner" => query.owner = Some(identity(&value)?),
                "agent"
                    if !value.is_empty()
                        && value.len() <= 256
                        && !value.chars().any(char::is_control) =>
                {
                    query.agent = Some(ClientId::new(value.into_owned()));
                }
                "limit" => {
                    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(invalid());
                    }
                    query.limit = value.parse().map_err(|_| invalid())?;
                    if !(1..=MAX_TASK_PAGE).contains(&query.limit) {
                        return Err(invalid());
                    }
                }
                _ => return Err(invalid()),
            }
        }
        Ok(query)
    }
}

// fuzz-target: agent_task_view_query
pub fn identity(raw: &str) -> Result<Uuid, DomainError> {
    let id = Uuid::parse_str(raw).map_err(|_| invalid())?;
    if id.hyphenated().to_string() != raw {
        return Err(invalid());
    }
    Ok(id)
}
fn invalid() -> DomainError {
    DomainError::invalid("task_view", "invalid bounded task query")
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Active,
    Expired,
    Withdrawn,
    PrincipalUnavailable,
    AncestorUnavailable,
}

/// Only tenant-local provenance identifiers, never user names or credentials.
#[derive(Debug, Clone, Serialize)]
pub struct Task {
    pub task_id: Uuid,
    pub root_grant_id: Uuid,
    pub owner_user_id: Uuid,
    pub initiating_client_id: ClientId,
    pub approval_revision: i64,
    pub label: String,
    pub approved_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub state: State,
}

#[derive(Debug, Clone, Serialize)]
pub struct Page {
    pub items: Vec<Task>,
    pub next_cursor: Option<Uuid>,
    pub observed_at: String,
}

/// Explicit v1 action comparator, separate from the accepted approval type.
/// Empty results represent no currently available permission, not an error.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ActionCeiling {
    pub resource: String,
    pub actions: BTreeSet<String>,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ResourceCeiling {
    pub resource: String,
    pub scopes: BTreeSet<String>,
    pub maximum_token_ttl_seconds: i64,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Ceiling {
    pub scopes: BTreeSet<String>,
    pub resources: BTreeSet<String>,
    pub actions: Vec<ActionCeiling>,
    pub resource_ceilings: Vec<ResourceCeiling>,
    pub max_delegation_depth: u8,
}
impl Ceiling {
    /// Input is immutable validated approval data. Unknown stored shapes fail
    /// rather than presenting an invented authorization comparator.
    pub fn approved(permissions: &Permissions) -> Result<Self, DomainError> {
        permissions.validate()?;
        let mut actions = Vec::new();
        for detail in &permissions.authorization_details {
            let resource = detail
                .get("locations")
                .and_then(serde_json::Value::as_array)
                .and_then(|values| values.first())
                .and_then(serde_json::Value::as_str)
                .ok_or_else(invalid)?;
            let values = detail
                .get("actions")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(invalid)?;
            actions.push(ActionCeiling {
                resource: resource.to_owned(),
                actions: values
                    .iter()
                    .map(|value| value.as_str().map(str::to_owned).ok_or_else(invalid))
                    .collect::<Result<_, _>>()?,
            });
        }
        Ok(Self {
            resource_ceilings: permissions
                .resources
                .iter()
                .map(|resource| ResourceCeiling {
                    resource: resource.clone(),
                    scopes: permissions.scopes.clone(),
                    maximum_token_ttl_seconds: 300,
                })
                .collect(),
            scopes: permissions.scopes.clone(),
            resources: permissions.resources.clone(),
            actions,
            max_delegation_depth: permissions.max_delegation_depth,
        })
    }
    /// AND, never union: later constraints cannot enlarge human approval.
    pub fn narrow(&mut self, scopes: &BTreeSet<String>, resources: &BTreeSet<String>, depth: u8) {
        self.scopes.retain(|scope| scopes.contains(scope));
        self.resources
            .retain(|resource| resources.contains(resource));
        self.actions
            .retain(|action| self.resources.contains(&action.resource));
        self.resource_ceilings
            .retain(|resource| self.resources.contains(&resource.resource));
        for resource in &mut self.resource_ceilings {
            resource.scopes.retain(|scope| self.scopes.contains(scope));
        }
        self.max_delegation_depth = self.max_delegation_depth.min(depth);
    }
    pub fn cap_lifetime(&mut self, seconds: i64) {
        for resource in &mut self.resource_ceilings {
            resource.maximum_token_ttl_seconds =
                resource.maximum_token_ttl_seconds.min(seconds.max(0));
        }
    }
    pub fn resource_policy(
        &mut self,
        resource: &str,
        scopes: Option<&BTreeSet<String>>,
        lifetime: Option<i64>,
    ) {
        if let Some(current) = self
            .resource_ceilings
            .iter_mut()
            .find(|current| current.resource == resource)
        {
            if let Some(scopes) = scopes {
                current.scopes.retain(|scope| scopes.contains(scope));
            }
            if let Some(seconds) = lifetime {
                current.maximum_token_ttl_seconds =
                    current.maximum_token_ttl_seconds.min(seconds.max(0));
            }
        }
    }
    pub fn narrow_actions(&mut self, details: &[serde_json::Value]) {
        for current in &mut self.actions {
            let allowed: BTreeSet<&str> = details
                .iter()
                .filter(|detail| {
                    detail.get("type").and_then(serde_json::Value::as_str)
                        == Some("urn:asterius:workload-actions")
                })
                .filter(|detail| {
                    detail
                        .get("locations")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|locations| {
                            locations.iter().any(|location| {
                                location.as_str() == Some(current.resource.as_str())
                            })
                        })
                })
                .filter_map(|detail| detail.get("actions").and_then(serde_json::Value::as_array))
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .collect();
            current
                .actions
                .retain(|action| allowed.contains(action.as_str()));
        }
        self.actions.retain(|action| !action.actions.is_empty());
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantNode {
    pub grant_id: Uuid,
    pub parent_grant_id: Option<Uuid>,
    pub client_id: ClientId,
    pub depth: usize,
    pub ancestry: Vec<Uuid>,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub state: State,
    pub recorded_ceiling: Ceiling,
    pub current_issuance_ceiling: Ceiling,
}
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub task: Task,
    pub approved_ceiling: Ceiling,
    pub current_issuance_ceiling: Ceiling,
    pub current_grant_types: BTreeSet<String>,
    pub maximum_new_token_ttl_seconds: i64,
    pub observed_at: String,
    pub lineage: Vec<GrantNode>,
    pub next_cursor: Option<Uuid>,
    /// This port reports lifecycle/ceilings, not a request-specific PDP grant.
    pub conditional_decision: &'static str,
}

#[async_trait::async_trait]
pub trait Administration: std::fmt::Debug + Send + Sync {
    async fn list(&self, tenant: &TenantId, query: &Query) -> Result<Page, DomainError>;
    async fn read(
        &self,
        tenant: &TenantId,
        task: Uuid,
        query: &Query,
    ) -> Result<Snapshot, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn agent_task_view_query_is_bounded_canonical_and_closed() {
        let id = Uuid::new_v4();
        assert_eq!(
            Query::parse(Some(&format!("cursor={id}&limit=50")))
                .expect("bounded cursor")
                .cursor,
            Some(id)
        );
        for raw in [
            "limit=0",
            "limit=51",
            "limit=-1",
            "limit=1&limit=2",
            "unknown=1",
            "owner=garbage",
            "agent=",
            "cursor={00000000-0000-0000-0000-000000000000}",
        ] {
            assert!(Query::parse(Some(raw)).is_err(), "{raw}");
        }
        assert!(Query::parse(Some(&"x".repeat(2049))).is_err());
    }
    #[test]
    fn agent_task_current_ceiling_intersects_scopes_audiences_and_exact_actions() {
        let permissions = Permissions {
            scopes: BTreeSet::from(["read".into(), "write".into()]),
            resources: BTreeSet::from(["https://api.example/".into()]),
            authorization_details: vec![
                json!({"type":"urn:asterius:workload-actions","locations":["https://api.example/"],"actions":["read","write"]}),
            ],
            max_delegation_depth: 8,
        };
        let mut ceiling = Ceiling::approved(&permissions).expect("approved exact comparator");
        ceiling.narrow(
            &BTreeSet::from(["read".into(), "unapproved".into()]),
            &permissions.resources,
            2,
        );
        ceiling.narrow_actions(&[json!({"type":"urn:asterius:workload-actions","locations":["https://api.example/"],"actions":["read","delete"]})]);
        assert_eq!(ceiling.scopes, BTreeSet::from(["read".into()]));
        assert_eq!(ceiling.actions[0].actions, BTreeSet::from(["read".into()]));
        assert_eq!(ceiling.max_delegation_depth, 2);
        ceiling.narrow(&ceiling.scopes.clone(), &BTreeSet::new(), 2);
        assert!(ceiling.resources.is_empty() && ceiling.actions.is_empty());
    }
    #[test]
    fn agent_task_resource_scope_and_lifetime_caps_do_not_bleed_between_audiences() {
        let permissions = Permissions {
            scopes: BTreeSet::from(["read".into(), "write".into()]),
            resources: BTreeSet::from([
                "https://read.example/".into(),
                "https://write.example/".into(),
            ]),
            authorization_details: Vec::new(),
            max_delegation_depth: 2,
        };
        let mut ceiling = Ceiling::approved(&permissions).expect("approved scopes");
        ceiling.resource_policy(
            "https://read.example/",
            Some(&BTreeSet::from(["read".into()])),
            Some(30),
        );
        ceiling.resource_policy(
            "https://write.example/",
            Some(&BTreeSet::from(["write".into()])),
            Some(90),
        );
        ceiling.cap_lifetime(60);
        let read = ceiling
            .resource_ceilings
            .iter()
            .find(|entry| entry.resource == "https://read.example/")
            .expect("read resource");
        let write = ceiling
            .resource_ceilings
            .iter()
            .find(|entry| entry.resource == "https://write.example/")
            .expect("write resource");
        assert_eq!(read.scopes, BTreeSet::from(["read".into()]));
        assert_eq!(write.scopes, BTreeSet::from(["write".into()]));
        assert_eq!(read.maximum_token_ttl_seconds, 30);
        assert_eq!(write.maximum_token_ttl_seconds, 60);
    }
}
