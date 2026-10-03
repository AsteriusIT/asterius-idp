//! Same-realm human administration; posted IDs never confer credential authority.

use super::{AdminError, Handling, Principal, Response, StatusCode, json_no_store};
use asterius_domain::outbound_scim::{
    ConfigureConnector, canonical_uuid, parse_lifecycle, parse_selection,
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigureBody {
    expected_revision: Option<Uuid>,
    target_issuer: String,
    target_client: String,
    credential_ref: String,
    credential_generation: Uuid,
    enabled: bool,
    allow_reviewed_delete: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionBody {
    expected_revision: Uuid,
}

fn error(error: asterius_domain::DomainError) -> AdminError {
    match error {
        asterius_domain::DomainError::NotFound => AdminError::NotFound,
        asterius_domain::DomainError::Conflict(code) => AdminError::Conflict(code),
        asterius_domain::DomainError::Invalid { field, reason } => {
            AdminError::Invalid(format!("{field}: {reason}"))
        }
        other => AdminError::from_storage("outbound_scim", &other),
    }
}
fn id(value: &str) -> Result<Uuid, AdminError> {
    let id = canonical_uuid(value).map_err(|_| AdminError::NotFound)?;
    if id.is_nil() {
        return Err(AdminError::NotFound);
    }
    Ok(id)
}
fn page(query: &str) -> Result<(Option<Uuid>, u16), AdminError> {
    let after = super::query_value(query, "after")
        .map(|value| id(&value))
        .transpose()?;
    let limit = super::query_value(query, "limit")
        .map(|value| {
            value
                .parse::<u16>()
                .map_err(|_| AdminError::Invalid("invalid page bound".into()))
        })
        .transpose()?
        .unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(AdminError::Invalid("page bound must be 1..100".into()));
    }
    Ok((after, limit))
}

impl Handling<'_> {
    pub(super) async fn outbound_scim(
        &self,
        operation: &str,
        body: axum::body::Body,
    ) -> Result<Response, AdminError> {
        let Principal::Console { tenant, user, .. } = self.principal else {
            return Err(AdminError::Forbidden);
        };
        if tenant != &self.tenant.id {
            return Err(AdminError::Forbidden);
        }
        let catalogue = self
            .state
            .backend
            .outbound_scim()
            .ok_or(AdminError::Unavailable)?;
        let write = !matches!(
            operation,
            "outbound_scim.lifecycle_read"
                | "outbound_scim.list"
                | "outbound_scim.read"
                | "outbound_scim.credentials"
                | "outbound_scim.assignments"
        );
        if write {
            self.require_fresh_totp_recovery_admin().await?;
        }
        let (after, limit) = page(&self.query)?;
        let segments: Vec<_> = self
            .path
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        let connector = || {
            segments
                .iter()
                .position(|part| *part == "connectors")
                .and_then(|offset| segments.get(offset + 1))
                .ok_or(AdminError::NotFound)
                .and_then(|value| id(value))
        };
        let document = match operation {
            "outbound_scim.read" => serde_json::json!(
                catalogue
                    .read(&self.tenant.id, connector()?)
                    .await
                    .map_err(error)?
            ),
            "outbound_scim.list" => {
                serde_json::json!({"items":catalogue.list(&self.tenant.id,after,limit).await.map_err(error)?})
            }
            "outbound_scim.credentials" => {
                let credentials = self
                    .state
                    .backend
                    .outbound_scim_credentials()
                    .ok_or(AdminError::Unavailable)?;
                serde_json::json!({"items":credentials.descriptors(&self.tenant.id)})
            }
            "outbound_scim.assignments" => {
                serde_json::json!({"items":catalogue.assignments(&self.tenant.id,connector()?,after,limit).await.map_err(error)?})
            }
            "outbound_scim.create" | "outbound_scim.configure" => {
                let bytes = self.body_bytes(body).await?;
                if bytes.len() > 8192 {
                    return Err(AdminError::Invalid("command too large".into()));
                }
                let request: ConfigureBody = serde_json::from_slice(&bytes)
                    .map_err(|_| AdminError::Invalid("invalid connector command".into()))?;
                let creating = operation == "outbound_scim.create";
                if creating && (request.expected_revision.is_some() || request.enabled)
                    || !creating && request.expected_revision.is_none()
                {
                    return Err(AdminError::Invalid(
                        "create must be disabled; configure requires a revision".into(),
                    ));
                }
                let command = ConfigureConnector {
                    id: if creating {
                        Uuid::new_v4()
                    } else {
                        connector()?
                    },
                    expected_revision: request.expected_revision,
                    target_issuer: request.target_issuer,
                    target_client: request.target_client,
                    credential_ref: request.credential_ref,
                    credential_generation: request.credential_generation,
                    enabled: request.enabled,
                    allow_reviewed_delete: request.allow_reviewed_delete,
                };
                serde_json::json!(
                    catalogue
                        .configure(&self.tenant.id, *user, command)
                        .await
                        .map_err(error)?
                )
            }
            "outbound_scim.select" => {
                let command = parse_selection(&self.body_bytes(body).await?).map_err(error)?;
                serde_json::json!({"items":catalogue.select(&self.tenant.id,*user,connector()?,command).await.map_err(error)?})
            }
            "outbound_scim.lifecycle_read" => {
                let assignment = segments
                    .iter()
                    .position(|part| *part == "assignments")
                    .and_then(|offset| segments.get(offset + 1))
                    .ok_or(AdminError::NotFound)
                    .and_then(|value| id(value))?;
                let lifecycle = self
                    .state
                    .backend
                    .outbound_scim_lifecycle()
                    .ok_or(AdminError::Unavailable)?;
                serde_json::json!({"items":lifecycle.recent(&self.tenant.id,connector()?,assignment).await.map_err(error)?})
            }
            "outbound_scim.lifecycle" => {
                let command = parse_lifecycle(&self.body_bytes(body).await?).map_err(error)?;
                let assignment = segments
                    .iter()
                    .position(|part| *part == "assignments")
                    .and_then(|offset| segments.get(offset + 1))
                    .ok_or(AdminError::NotFound)
                    .and_then(|value| id(value))?;
                let lifecycle = self
                    .state
                    .backend
                    .outbound_scim_lifecycle()
                    .ok_or(AdminError::Unavailable)?;
                serde_json::json!(
                    lifecycle
                        .enqueue(&self.tenant.id, *user, connector()?, assignment, command)
                        .await
                        .map_err(error)?
                )
            }
            "outbound_scim.dry_run" => {
                let bytes = self.body_bytes(body).await?;
                if bytes.len() > 1024 {
                    return Err(AdminError::Invalid("command too large".into()));
                }
                let command: RevisionBody = serde_json::from_slice(&bytes)
                    .map_err(|_| AdminError::Invalid("invalid dry-run command".into()))?;
                let assignment = segments
                    .iter()
                    .position(|part| *part == "assignments")
                    .and_then(|offset| segments.get(offset + 1))
                    .ok_or(AdminError::NotFound)
                    .and_then(|value| id(value))?;
                let inspection = self
                    .state
                    .backend
                    .outbound_scim_inspection()
                    .ok_or(AdminError::Unavailable)?;
                serde_json::json!(
                    inspection
                        .dry_run(
                            &self.tenant.id,
                            connector()?,
                            assignment,
                            command.expected_revision
                        )
                        .await
                        .map_err(error)?
                )
            }
            "outbound_scim.preview" => {
                let bytes = self.body_bytes(body).await?;
                if bytes.len() > 1024 {
                    return Err(AdminError::Invalid("command too large".into()));
                }
                let command: RevisionBody = serde_json::from_slice(&bytes)
                    .map_err(|_| AdminError::Invalid("invalid preview command".into()))?;
                let inspection = self
                    .state
                    .backend
                    .outbound_scim_inspection()
                    .ok_or(AdminError::Unavailable)?;
                serde_json::json!(
                    inspection
                        .preview(
                            &self.tenant.id,
                            *user,
                            connector()?,
                            command.expected_revision
                        )
                        .await
                        .map_err(error)?
                )
            }
            "outbound_scim.unselect" | "outbound_scim.reconcile" => {
                let bytes = self.body_bytes(body).await?;
                if bytes.len() > 1024 {
                    return Err(AdminError::Invalid("command too large".into()));
                }
                let command: RevisionBody = serde_json::from_slice(&bytes)
                    .map_err(|_| AdminError::Invalid("invalid revision command".into()))?;
                if operation == "outbound_scim.reconcile" {
                    serde_json::json!({"after":catalogue.reconcile(&self.tenant.id,*user,connector()?,command.expected_revision,after).await.map_err(error)?})
                } else {
                    let assignment = segments
                        .iter()
                        .position(|part| *part == "assignments")
                        .and_then(|offset| segments.get(offset + 1))
                        .ok_or(AdminError::NotFound)
                        .and_then(|value| id(value))?;
                    catalogue
                        .unselect(
                            &self.tenant.id,
                            *user,
                            connector()?,
                            assignment,
                            command.expected_revision,
                        )
                        .await
                        .map_err(error)?;
                    serde_json::json!({"accepted":true})
                }
            }
            _ => return Err(AdminError::NotFound),
        };
        Ok(json_no_store(StatusCode::OK, &document))
    }
}
