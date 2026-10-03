//! Immutable task approvals over existing human grant authorization.
use crate::{DomainError, Grant};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const MAX_TASK_LIFETIME: Duration = Duration::hours(1);
pub const MAX_TASK_TOKEN_LIFETIME: Duration = Duration::seconds(300);

/// Exact approved ceilings. Empty sets confer no authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    pub scopes: BTreeSet<String>,
    pub resources: BTreeSet<String>,
    #[serde(with = "strict_details")]
    pub authorization_details: Vec<Value>,
    pub max_delegation_depth: u8,
}

impl Permissions {
    // fuzz-target: agent_task_permissions
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.scopes.contains("device_sso")
            || self.scopes.is_empty()
            || self.resources.is_empty()
            || self.scopes.len() > 64
            || self.resources.len() > 64
            || self.authorization_details.len() > 32
            || !(1..=8).contains(&self.max_delegation_depth)
        {
            return Err(invalid());
        }
        // Existing scope/resource parsers are the authorization grammar.
        for scope in &self.scopes {
            if scope.len() > 256 || !crate::entities::grant::is_scope_token(scope) {
                return Err(invalid());
            }
        }
        for resource in &self.resources {
            if resource.len() > 2048
                || crate::entities::resource_server::ResourceIdentifier::parse(resource).is_err()
            {
                return Err(invalid());
            }
        }
        self.permits_details(&self.authorization_details, &self.resources)
    }

    // fuzz-target: agent_task_permissions
    pub fn permits(&self, grant: &Grant) -> Result<(), DomainError> {
        if !grant.scopes.is_subset(&self.scopes)
            || !grant.resources.is_subset(&self.resources)
            || grant.actor_chain.len() > usize::from(self.max_delegation_depth)
        {
            return Err(invalid());
        }
        self.permits_details(&grant.authorization_details, &grant.resources)
    }

    fn permits_details(
        &self,
        details: &[Value],
        resources: &BTreeSet<String>,
    ) -> Result<(), DomainError> {
        // v1 recognizes the registered workload-actions comparator. A schema
        // alone does not define narrowing for arbitrary RFC9396 extensions.
        let mut actions = BTreeSet::new();
        for detail in &self.authorization_details {
            let object = detail.as_object().ok_or_else(invalid)?;
            if object.get("type").and_then(Value::as_str) != Some("urn:asterius:workload-actions")
                || object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "type" | "actions" | "locations"))
            {
                return Err(invalid());
            }
            for action in object
                .get("actions")
                .and_then(Value::as_array)
                .ok_or_else(invalid)?
            {
                actions.insert(action.as_str().ok_or_else(invalid)?.to_owned());
            }
        }
        crate::workload::validate_actions(details, &actions, resources).map_err(|_| invalid())?;
        for detail in details {
            let requested = detail.as_object().ok_or_else(invalid)?;
            let covered = self.authorization_details.iter().any(|approved| {
                let Some(approved) = approved.as_object() else {
                    return false;
                };
                ["actions", "locations"].iter().all(|key| {
                    let (Some(requested), Some(approved)) = (
                        requested.get(*key).and_then(Value::as_array),
                        approved.get(*key).and_then(Value::as_array),
                    ) else {
                        return false;
                    };
                    requested.iter().all(|value| approved.contains(value))
                })
            });
            if !covered {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

/// Public correlators, never credentials or owner identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Binding {
    pub task_id: Uuid,
    pub root_grant_id: Uuid,
    pub approval_revision: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[must_use]
pub fn invalid() -> DomainError {
    DomainError::invalid(
        "agent_task",
        "task authority is not active or does not cover this request",
    )
}

/// Bounded typed RFC9396 task dialect; duplicates and unknown members fail.
// fuzz-target: agent_task_permissions
pub fn parse_details(raw: &str) -> Result<Vec<Value>, DomainError> {
    if raw.len() > 32768 {
        return Err(invalid());
    }
    strict_details::parse(raw).map_err(|_| invalid())
}

mod strict_details {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_json::Value;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Detail {
        #[serde(rename = "type")]
        kind: String,
        actions: Vec<String>,
        locations: Vec<String>,
    }
    pub fn serialize<S: Serializer>(values: &[Value], serializer: S) -> Result<S::Ok, S::Error> {
        values.serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Value>, D::Error> {
        Vec::<Detail>::deserialize(deserializer).map(|values| values.into_iter().map(|value|
            serde_json::json!({"type":value.kind,"actions":value.actions,"locations":value.locations})).collect())
    }
    pub fn parse(raw: &str) -> Result<Vec<Value>, serde_json::Error> {
        serde_json::from_str::<Vec<Detail>>(raw).map(|values| values.into_iter().map(|value|
            serde_json::json!({"type":value.kind,"actions":value.actions,"locations":value.locations})).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn permissions() -> Permissions {
        Permissions {
            scopes: BTreeSet::from(["read".to_owned(), "write".to_owned()]),
            resources: BTreeSet::from([
                "https://api.example.test".to_owned(),
                "https://other.example.test".to_owned(),
            ]),
            authorization_details: vec![
                json!({"type":"urn:asterius:workload-actions","actions":["read"],"locations":["https://api.example.test"]}),
                json!({"type":"urn:asterius:workload-actions","actions":["write"],"locations":["https://other.example.test"]}),
            ],
            max_delegation_depth: 2,
        }
    }
    fn grant() -> Grant {
        let mut grant = Grant::new(
            crate::TenantId::new("tenant"),
            crate::ClientId::new("agent"),
            OffsetDateTime::UNIX_EPOCH,
        );
        grant.scopes.insert("read".to_owned());
        grant
            .resources
            .insert("https://api.example.test".to_owned());
        grant.authorization_details = vec![
            json!({"type":"urn:asterius:workload-actions","actions":["read"],"locations":["https://api.example.test"]}),
        ];
        grant
    }
    #[test]
    fn task_permissions_accept_narrowing_and_refuse_expansion() {
        let ceiling = permissions();
        ceiling.validate().expect("known task dialect");
        let mut grant = grant();
        ceiling.permits(&grant).expect("exact narrowing");
        grant.scopes.insert("admin".to_owned());
        assert!(ceiling.permits(&grant).is_err());
        grant.scopes.remove("admin");
        grant
            .resources
            .insert("https://unapproved.example.test".to_owned());
        assert!(ceiling.permits(&grant).is_err());
    }
    #[test]
    fn task_permissions_action_refusals_keep_the_task_error_boundary() {
        let ceiling = permissions();
        let mut grant = grant();
        grant.authorization_details[0]["actions"] = json!(["admin"]);
        assert!(matches!(
            ceiling.permits(&grant),
            Err(DomainError::Invalid {
                field: "agent_task",
                ..
            })
        ));
    }
    #[test]
    fn task_permissions_do_not_union_actions_across_locations() {
        let ceiling = permissions();
        let mut grant = grant();
        grant.authorization_details[0]["actions"] = json!(["write"]);
        assert!(ceiling.permits(&grant).is_err());
    }
    #[test]
    fn task_permissions_reject_unknown_dialect_and_members() {
        let mut ceiling = permissions();
        ceiling.authorization_details[0]["type"] = json!("unknown");
        assert!(ceiling.validate().is_err());
        let mut ceiling = permissions();
        ceiling.authorization_details[0]["privileged"] = json!(true);
        assert!(ceiling.validate().is_err());
        assert!(parse_details(r#"[{"type":"urn:asterius:workload-actions","actions":["read"],"locations":["https://api.example.test"],"privileged":true}]"#).is_err());
    }
    #[test]
    fn task_permissions_parser_rejects_duplicate_and_mistyped_fields() {
        assert!(parse_details(r#"[{"type":"urn:asterius:workload-actions","actions":["read"],"actions":["write"],"locations":["https://api.example.test"]}]"#).is_err());
        assert!(
            parse_details(
                r#"[{"type":"urn:asterius:workload-actions","actions":"read","locations":[]}]"#
            )
            .is_err()
        );
        assert!(parse_details(&" ".repeat(32769)).is_err());
        let mut document = serde_json::to_value(permissions()).expect("serializable ceiling");
        document["owner_user_id"] = json!("forged");
        assert!(serde_json::from_value::<Permissions>(document).is_err());
    }
    #[test]
    fn task_permissions_require_bounded_nonempty_authority() {
        for depth in [0, 9] {
            let mut ceiling = permissions();
            ceiling.max_delegation_depth = depth;
            assert!(ceiling.validate().is_err());
        }
        let mut ceiling = permissions();
        ceiling.scopes.clear();
        assert!(ceiling.validate().is_err());
        let mut ceiling = permissions();
        ceiling.resources.clear();
        assert!(ceiling.validate().is_err());
        let mut ceiling = permissions();
        ceiling.scopes.insert("device_sso".to_owned());
        assert!(ceiling.validate().is_err());
    }
}
