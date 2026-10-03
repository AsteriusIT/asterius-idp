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

/// Public signed token linkage, parsed only after signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenQuery {
    pub jti: String,
    pub client: crate::ClientId,
    pub approval: Option<SignedApproval>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedApproval {
    pub task_id: Uuid,
    pub revision: i64,
}

impl TokenQuery {
    /// This parser provides no authentication; callers first verify the JWT
    /// signature, issuer, audience, expiry and required sender constraint.
    // fuzz-target: agent_task_token_linkage
    pub fn from_claims(claims: &Value) -> Result<Self, DomainError> {
        let jti = claims
            .get("jti")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .ok_or_else(invalid)?;
        let client = claims
            .get("client_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .ok_or_else(invalid)?;
        let approval = match (claims.get("task_id"), claims.get("task_approval_revision")) {
            (None, None) => None,
            (Some(task), Some(revision)) => {
                let task = task.as_str().ok_or_else(invalid)?;
                let task_id = Uuid::parse_str(task).map_err(|_| invalid())?;
                if task_id.hyphenated().to_string() != task {
                    return Err(invalid());
                }
                let revision = revision
                    .as_i64()
                    .filter(|value| *value > 0)
                    .ok_or_else(invalid)?;
                Some(SignedApproval { task_id, revision })
            }
            _ => return Err(invalid()),
        };
        Ok(Self {
            jti: jti.to_owned(),
            client: crate::ClientId::new(client.to_owned()),
            approval,
        })
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

    #[test]
    fn agent_task_token_linkage_refuses_partial_untyped_or_unbounded_claims() {
        let id = Uuid::new_v4();
        let base = json!({"jti":"private-correlation","client_id":"recipient"});
        assert!(
            TokenQuery::from_claims(&base)
                .expect("legacy facts")
                .approval
                .is_none()
        );
        let claims = json!({"jti":"private-correlation","client_id":"recipient","task_id":id.to_string(),"task_approval_revision":7,"grant_id":"ignored-public-correlator"});
        let query = TokenQuery::from_claims(&claims).expect("signed task facts");
        assert_eq!(
            query.approval,
            Some(SignedApproval {
                task_id: id,
                revision: 7
            })
        );
        for (field, value) in [
            ("task_id", Value::Null),
            ("task_id", json!(id.to_string().to_uppercase())),
            ("task_id", json!(id.simple().to_string())),
            ("task_approval_revision", json!("7")),
            ("task_approval_revision", json!(0)),
            ("task_approval_revision", json!(-1)),
            ("task_approval_revision", json!(7.5)),
            ("jti", json!("")),
            ("jti", json!("j".repeat(257))),
            ("client_id", json!("")),
            ("client_id", json!("c".repeat(257))),
        ] {
            let mut refused = claims.clone();
            refused[field] = value;
            assert!(TokenQuery::from_claims(&refused).is_err(), "field {field}");
        }
        for field in ["task_id", "task_approval_revision", "jti", "client_id"] {
            let mut refused = claims.clone();
            refused.as_object_mut().expect("object").remove(field);
            assert!(
                TokenQuery::from_claims(&refused).is_err(),
                "missing {field}"
            );
        }
    }

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
