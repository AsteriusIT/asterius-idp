//! Bounded first-target SCIM documents. Location and member references are never followed.

use super::{Projection, ResourceKind, canonical_uuid};
use crate::DomainError;
use serde_json::Value;
use uuid::Uuid;

pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

#[derive(Clone, PartialEq, Eq)]
pub struct RemoteDocument {
    pub target: Uuid,
    pub etag: String,
    pub active: Option<bool>,
    pub work_email: Option<String>,
    pub members: Vec<Uuid>,
}

impl std::fmt::Debug for RemoteDocument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteDocument")
            .field("target", &self.target)
            .field("member_count", &self.members.len())
            .finish_non_exhaustive()
    }
}

fn invalid() -> DomainError {
    DomainError::invalid("target_response", "invalid bounded owned SCIM document")
}

/// The precise conditional version must agree with both response channels.
pub fn target_etag(input: &str) -> Result<(), DomainError> {
    let digits = input
        .strip_prefix("W/\"")
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(invalid)?;
    let revision = digits.parse::<i64>().map_err(|_| invalid())?;
    if revision < 1 || revision.to_string() != digits || input.len() > 128 {
        return Err(invalid());
    }
    Ok(())
}

/// Verify the immutable incarnation before accepting a target UUID or state.
// fuzz-target: outbound_scim_document
pub fn parse_document(
    body: &[u8],
    etag: &str,
    projection: &Projection,
) -> Result<RemoteDocument, DomainError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(invalid());
    }
    target_etag(etag)?;
    let document: Value = serde_json::from_slice(body).map_err(|_| invalid())?;
    let (kind, alias, external) = match projection {
        Projection::User(user) => (
            ResourceKind::User,
            user.immutable_alias.as_str(),
            user.external_id.as_str(),
        ),
        Projection::Group(group) => (
            ResourceKind::Group,
            group.immutable_alias.as_str(),
            group.external_id.as_str(),
        ),
    };
    let (schema, alias_key, resource_type) = match kind {
        ResourceKind::User => (USER_SCHEMA, "userName", "User"),
        ResourceKind::Group => (GROUP_SCHEMA, "displayName", "Group"),
    };
    if document.get("schemas") != Some(&serde_json::json!([schema]))
        || document.get(alias_key).and_then(Value::as_str) != Some(alias)
        || document.get("externalId").and_then(Value::as_str) != Some(external)
        || document.pointer("/meta/version").and_then(Value::as_str) != Some(etag)
        || document
            .pointer("/meta/resourceType")
            .and_then(Value::as_str)
            != Some(resource_type)
    {
        return Err(invalid());
    }
    let target = canonical_uuid(
        document
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?,
    )?;
    let mut result = RemoteDocument {
        target,
        etag: etag.to_owned(),
        active: None,
        work_email: None,
        members: Vec::new(),
    };
    match kind {
        ResourceKind::User => {
            result.active = Some(
                document
                    .get("active")
                    .and_then(Value::as_bool)
                    .ok_or_else(invalid)?,
            );
            if let Some(emails) = document.get("emails") {
                let emails = emails.as_array().ok_or_else(invalid)?;
                if emails.len() > 1 {
                    return Err(invalid());
                }
                if let Some(email) = emails.first() {
                    let value = email
                        .get("value")
                        .and_then(Value::as_str)
                        .ok_or_else(invalid)?;
                    if value.len() > 320
                        || email.get("type").and_then(Value::as_str) != Some("work")
                        || email.get("primary").and_then(Value::as_bool) != Some(true)
                    {
                        return Err(invalid());
                    }
                    result.work_email = Some(value.to_owned());
                }
            }
        }
        ResourceKind::Group => {
            let members = document
                .get("members")
                .and_then(Value::as_array)
                .ok_or_else(invalid)?;
            if members.len() > 100 {
                return Err(invalid());
            }
            for member in members {
                if member.get("type").and_then(Value::as_str) != Some("User") {
                    return Err(invalid());
                }
                let id = canonical_uuid(
                    member
                        .get("value")
                        .and_then(Value::as_str)
                        .ok_or_else(invalid)?,
                )?;
                if result.members.contains(&id) {
                    return Err(invalid());
                }
                result.members.push(id);
            }
            result.members.sort_unstable();
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound_scim::UserProjection;

    fn projection() -> Projection {
        Projection::User(UserProjection {
            immutable_alias: "immutable".into(),
            external_id: "owned".into(),
            work_email: None,
            active: true,
        })
    }
    fn body() -> Value {
        serde_json::json!({"schemas":[USER_SCHEMA],"id":Uuid::from_u128(1).to_string(),"userName":"immutable","externalId":"owned","active":true,"meta":{"resourceType":"User","version":"W/\"1\"","location":"https://untrusted.example/never-follow"}})
    }
    #[test]
    fn owned_incarnation_accepts_only_its_canonical_uuid_and_bound_version() {
        let bytes = serde_json::to_vec(&body()).expect("JSON");
        assert_eq!(
            parse_document(&bytes, "W/\"1\"", &projection())
                .expect("owned")
                .target,
            Uuid::from_u128(1)
        );
        assert!(parse_document(&bytes, "W/\"2\"", &projection()).is_err());
        let mut changed = body();
        changed["externalId"] = serde_json::json!("other-incarnation");
        assert!(
            parse_document(
                &serde_json::to_vec(&changed).expect("JSON"),
                "W/\"1\"",
                &projection()
            )
            .is_err()
        );
    }
    #[test]
    fn unsupported_or_unbounded_documents_never_become_mappings() {
        let mut changed = body();
        changed["schemas"] = serde_json::json!([GROUP_SCHEMA]);
        assert!(
            parse_document(
                &serde_json::to_vec(&changed).expect("JSON"),
                "W/\"1\"",
                &projection()
            )
            .is_err()
        );
        assert!(
            parse_document(
                &vec![b' '; MAX_RESPONSE_BYTES + 1],
                "W/\"1\"",
                &projection()
            )
            .is_err()
        );
        for bad in [
            "*",
            "W/\"0\"",
            "W/\"01\"",
            "W/\"-1\"",
            "\"1\"",
            "W/\"9223372036854775808\"",
        ] {
            assert!(target_etag(bad).is_err());
        }
    }
}
