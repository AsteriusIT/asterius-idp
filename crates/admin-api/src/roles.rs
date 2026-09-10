//! The application-role screens' documents and their validation (`ast-095`).
//!
//! Two catalogues — the tenant's and each client's — and the assignment of
//! their entries to accounts. What is *not* here is
//! [`asterius_domain::Role`]: the authority to administer this server is not
//! editable through any route, and there is no type in this module that could
//! name one.
//!
//! # Nothing on this path invents a name
//!
//! Every request goes through [`asterius_domain::RoleName::parse`], which is
//! the fuzzed parser, before it reaches a port. The reason is that a role name
//! is copied verbatim into an access token that third-party resource servers
//! authorise against: a name carrying a space would become two roles at any of
//! them that splits on whitespace. The admin API is the only place a name can
//! enter the system — dynamic client registration cannot declare one, because
//! there is no field for it in a registration document and no code path from
//! `POST /register` to this module.

use asterius_domain::{
    ApplicationRole, ApplicationRoleError, ClientId, RoleName, RoleOwner, TenantId,
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::error::AdminError;

/// A role a caller asks to create.
///
/// `name` and an optional `description`, and nothing else. In particular there
/// is no "assign to" field: creating a role and giving it to somebody are two
/// audited acts, and one request that did both would be one record for two
/// changes of authority.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedRole {
    /// The name, as it will appear in tokens.
    pub name: String,
    /// What it is for, for whoever assigns it. Never issued.
    #[serde(default)]
    pub description: Option<String>,
}

/// A role a caller asks to give somebody.
///
/// `client_id` absent means the tenant's shared catalogue, which is the same
/// distinction [`RoleOwner`] carries; it is turned into that enum here, at the
/// edge, so nothing below this module reasons about an `Option`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedAssignment {
    /// The role.
    pub name: String,
    /// The client whose catalogue it comes from, or absent for the tenant's.
    #[serde(default)]
    pub client_id: Option<String>,
}

/// Turns a create request into a catalogue entry.
///
/// # Errors
///
/// [`AdminError::Invalid`] for a name outside the alphabet or a description
/// that is too long or carries a control character. The message names the
/// rule, because an operator typing `Payments Approver` needs to be told which
/// half of it was refused.
pub fn accept_role(
    requested: &RequestedRole,
    tenant: &TenantId,
    owner: RoleOwner,
    now: OffsetDateTime,
) -> Result<ApplicationRole, AdminError> {
    ApplicationRole::new(
        tenant.clone(),
        owner,
        &requested.name,
        requested.description.as_deref(),
        now,
    )
    .map_err(|error: ApplicationRoleError| AdminError::Invalid(error.to_string()))
}

/// Parses a role name from a path segment or a request body.
///
/// # Errors
///
/// [`AdminError::Invalid`] for anything outside the alphabet. Deliberately not
/// a 404: "that is not a name a role can have" is a statement about the
/// request, and answering 404 would leave a caller retrying a spelling that
/// can never exist.
pub fn accept_name(raw: &str) -> Result<RoleName, AdminError> {
    RoleName::parse(raw).map_err(|error| AdminError::Invalid(error.to_string()))
}

/// Which catalogue an assignment request names.
///
/// # Errors
///
/// [`AdminError::Invalid`] if the `client_id` is empty, which names no client
/// and would otherwise become a foreign-key refusal reported as a conflict.
pub fn accept_owner(client_id: Option<&str>) -> Result<RoleOwner, AdminError> {
    match client_id {
        None => Ok(RoleOwner::Tenant),
        Some("") => Err(AdminError::Invalid(
            "client_id must not be empty; omit it for a tenant role".to_owned(),
        )),
        Some(client) => Ok(RoleOwner::Client(ClientId::new(client.to_owned()))),
    }
}

/// One catalogue entry, as the API renders it.
#[must_use]
pub fn document(role: &ApplicationRole) -> Value {
    json!({
        "name": role.name.as_str(),
        "description": role.description,
        "client_id": role.owner.client().map(ClientId::as_str),
        "created_at": role.created_at.unix_timestamp(),
    })
}

/// What one account holds, as the API renders it.
///
/// The same two shapes a token carries — a flat list for the tenant's roles
/// and one object per client — so that an administrator reading this screen
/// and a developer reading a token are looking at the same structure.
#[must_use]
pub fn held_document(held: &asterius_domain::HeldRoles) -> Value {
    json!({
        "roles": held
            .tenant
            .iter()
            .map(RoleName::as_str)
            .collect::<Vec<_>>(),
        "resource_access": held
            .clients
            .iter()
            .map(|(client, roles)| {
                (
                    client.as_str().to_owned(),
                    json!({
                        "roles": roles.iter().map(RoleName::as_str).collect::<Vec<_>>(),
                    }),
                )
            })
            .collect::<serde_json::Map<String, Value>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    #[test]
    fn a_name_outside_the_alphabet_is_a_bad_request_not_a_404() {
        let error = accept_name("Payments Approver").expect_err("a refusal");

        assert!(matches!(error, AdminError::Invalid(_)));
    }

    #[test]
    fn a_created_tenant_role_carries_no_client() {
        let requested = RequestedRole {
            name: "auditor".to_owned(),
            description: Some("Reads the ledger".to_owned()),
        };

        let role = accept_role(
            &requested,
            &TenantId::new("demo"),
            RoleOwner::Tenant,
            epoch(),
        )
        .expect("a role");

        assert_eq!(role.owner, RoleOwner::Tenant);
        assert_eq!(document(&role)["client_id"], Value::Null);
    }

    #[test]
    fn an_empty_client_id_is_refused_rather_than_read_as_a_tenant_role() {
        let error = accept_owner(Some("")).expect_err("a refusal");

        assert!(matches!(error, AdminError::Invalid(_)));
    }

    #[test]
    fn an_absent_client_id_names_the_tenants_catalogue() {
        assert_eq!(accept_owner(None).expect("an owner"), RoleOwner::Tenant);
    }

    /// The document a console renders must not lose the distinction between
    /// "holds nothing" and "holds something in some client".
    #[test]
    fn the_held_document_carries_both_shapes() {
        let mut held = asterius_domain::HeldRoles::default();
        held.tenant
            .insert(RoleName::parse("auditor").expect("a name"));
        held.clients.insert(
            ClientId::new("billing"),
            [RoleName::parse("refund").expect("a name")]
                .into_iter()
                .collect(),
        );

        let rendered = held_document(&held);

        assert_eq!(rendered["roles"], json!(["auditor"]));
        assert_eq!(
            rendered["resource_access"]["billing"]["roles"],
            json!(["refund"])
        );
    }
}
