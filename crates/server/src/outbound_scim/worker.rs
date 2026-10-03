//! Ordered, owned reconciliation. A remote UUID is accepted only after its
//! immutable alias/externalId and the response version have been verified.

use super::OutboundScimClient;
use super::client::{DeliveryAdmission, RequestAdmission, ScimRequest};
use crate::outbound::PostResponse;
use crate::outbox::{Delivered, Deliverer, Undelivered};
use asterius_domain::outbound_scim::{
    FailureCode, GROUP_SCHEMA, MappingReceipt, OutboundScimJobs, PreparedDelivery, Projection,
    RemoteDocument, ResourceKind, USER_SCHEMA, canonical_uuid, parse_document,
};
use asterius_domain::{DomainError, outbox::OutboxEvent};
use hyper::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug)]
pub struct OutboundScimDeliverer {
    jobs: Arc<dyn OutboundScimJobs>,
    client: Arc<OutboundScimClient>,
}
impl OutboundScimDeliverer {
    #[must_use]
    pub fn new(jobs: Arc<dyn OutboundScimJobs>, client: Arc<OutboundScimClient>) -> Self {
        Self { jobs, client }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Locator {
    assignment: String,
    generation: String,
}

fn refused(code: FailureCode) -> Undelivered {
    Undelivered {
        detail: code.as_str().to_owned(),
        permanent: !matches!(
            code,
            FailureCode::Paused
                | FailureCode::TargetUnavailable
                | FailureCode::UserDependenciesPending
                | FailureCode::LeaseSuperseded
        ),
    }
}
fn domain_code(error: &DomainError) -> FailureCode {
    match error {
        DomainError::Conflict(code) => match code.as_str() {
            "paused" => FailureCode::Paused,
            "source_protected" => FailureCode::SourceProtected,
            "source_projection_invalid" => FailureCode::SourceProjectionInvalid,
            "snapshot_bound_exceeded" => FailureCode::SnapshotBoundExceeded,
            "user_dependencies_pending" => FailureCode::UserDependenciesPending,
            "credential_binding_mismatch" => FailureCode::CredentialBindingMismatch,
            "ownership_mismatch" => FailureCode::OwnershipMismatch,
            _ => FailureCode::LeaseSuperseded,
        },
        DomainError::Storage(_) => FailureCode::TargetUnavailable,
        _ => FailureCode::SourceProjectionInvalid,
    }
}
fn status(response: &PostResponse) -> Result<(), FailureCode> {
    match response.status {
        200..=299 if !response.truncated => Ok(()),
        401 | 403 => Err(FailureCode::AuthenticationRefused),
        404 => Err(FailureCode::TargetAbsent),
        409 | 412 => Err(FailureCode::TargetVersionChanged),
        429 | 500..=599 => Err(FailureCode::TargetUnavailable),
        _ => Err(FailureCode::SourceProjectionInvalid),
    }
}
fn parsed(response: &PostResponse, projection: &Projection) -> Result<RemoteDocument, FailureCode> {
    status(response)?;
    if !response.content_type.as_deref().is_some_and(|media| {
        media
            .split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/scim+json"))
    }) {
        return Err(FailureCode::SourceProjectionInvalid);
    }
    parse_document(
        &response.body,
        response
            .etag
            .as_deref()
            .ok_or(FailureCode::SourceProjectionInvalid)?,
        projection,
    )
    .map_err(|_| FailureCode::OwnershipMismatch)
}
fn collection(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::User => "Users",
        ResourceKind::Group => "Groups",
    }
}
fn desired(projection: &Projection, id: Option<Uuid>) -> Value {
    let mut document = match projection {
        Projection::User(user) => {
            json!({"schemas":[USER_SCHEMA],"userName":user.immutable_alias,"externalId":user.external_id,"active":user.active,"emails":user.work_email.as_ref().map_or_else(Vec::new,|email| vec![json!({"value":email,"type":"work","primary":true})])})
        }
        Projection::Group(group) => {
            json!({"schemas":[GROUP_SCHEMA],"displayName":group.immutable_alias,"externalId":group.external_id,"members":group.target_members.iter().map(|member| json!({"value":member.to_string(),"type":"User"})).collect::<Vec<_>>()})
        }
    };
    if let Some(id) = id {
        document["id"] = json!(id.to_string());
    }
    document
}
fn equal(remote: &RemoteDocument, projection: &Projection) -> bool {
    match projection {
        Projection::User(user) => {
            remote.active == Some(user.active) && remote.work_email == user.work_email
        }
        Projection::Group(group) => {
            let mut expected = group.target_members.clone();
            expected.sort_unstable();
            remote.members == expected
        }
    }
}

impl OutboundScimDeliverer {
    async fn fetch(
        &self,
        prepared: &PreparedDelivery,
        id: Uuid,
    ) -> Result<RemoteDocument, FailureCode> {
        let path = format!("{}/{}", collection(prepared.assignment.kind), id);
        let response = self
            .client
            .request(
                &prepared.connector.credential,
                ScimRequest {
                    method: Method::GET,
                    path: &path,
                    query: None,
                    etag: None,
                    body: &[],
                    admission: RequestAdmission::Delivery(DeliveryAdmission {
                        jobs: self.jobs.as_ref(),
                        prepared,
                    }),
                },
            )
            .await?;
        let remote = parsed(&response, &prepared.projection)?;
        if remote.target != id {
            return Err(FailureCode::OwnershipMismatch);
        }
        Ok(remote)
    }

    /// Recover an uncertain POST by exact immutable alias, then GET only the
    /// canonical returned UUID. List Location/$ref values never influence URLs.
    async fn locate(
        &self,
        prepared: &PreparedDelivery,
    ) -> Result<Option<RemoteDocument>, FailureCode> {
        let (attribute, alias) = match &prepared.projection {
            Projection::User(user) => ("userName", &user.immutable_alias),
            Projection::Group(group) => ("displayName", &group.immutable_alias),
        };
        let literal =
            serde_json::to_string(alias).map_err(|_| FailureCode::SourceProjectionInvalid)?;
        let filter = format!("{attribute} eq {literal}");
        let response = self
            .client
            .request(
                &prepared.connector.credential,
                ScimRequest {
                    method: Method::GET,
                    path: collection(prepared.assignment.kind),
                    query: Some(("filter", &filter)),
                    etag: None,
                    body: &[],
                    admission: RequestAdmission::Delivery(DeliveryAdmission {
                        jobs: self.jobs.as_ref(),
                        prepared,
                    }),
                },
            )
            .await?;
        status(&response)?;
        let document: Value = serde_json::from_slice(&response.body)
            .map_err(|_| FailureCode::SourceProjectionInvalid)?;
        if document.get("schemas")
            != Some(&json!([
                "urn:ietf:params:scim:api:messages:2.0:ListResponse"
            ]))
        {
            return Err(FailureCode::SourceProjectionInvalid);
        }
        let total = document
            .get("totalResults")
            .and_then(Value::as_u64)
            .ok_or(FailureCode::SourceProjectionInvalid)?;
        let resources = document
            .get("Resources")
            .and_then(Value::as_array)
            .ok_or(FailureCode::SourceProjectionInvalid)?;
        if total > 1 || resources.len() > 1 || total != resources.len() as u64 {
            return Err(FailureCode::OwnershipMismatch);
        }
        let Some(resource) = resources.first() else {
            return Ok(None);
        };
        let etag = resource
            .pointer("/meta/version")
            .and_then(Value::as_str)
            .ok_or(FailureCode::OwnershipMismatch)?;
        let bytes =
            serde_json::to_vec(resource).map_err(|_| FailureCode::SourceProjectionInvalid)?;
        let located = parse_document(&bytes, etag, &prepared.projection)
            .map_err(|_| FailureCode::OwnershipMismatch)?;
        self.fetch(prepared, located.target).await.map(Some)
    }

    async fn apply_existing(
        &self,
        prepared: &PreparedDelivery,
        remote: RemoteDocument,
    ) -> Result<RemoteDocument, FailureCode> {
        if equal(&remote, &prepared.projection) {
            return Ok(remote);
        }
        let path = format!("{}/{}", collection(prepared.assignment.kind), remote.target);
        let body = serde_json::to_vec(&desired(&prepared.projection, Some(remote.target)))
            .map_err(|_| FailureCode::SourceProjectionInvalid)?;
        let response = self
            .client
            .request(
                &prepared.connector.credential,
                ScimRequest {
                    method: Method::PUT,
                    path: &path,
                    query: None,
                    etag: Some(&remote.etag),
                    body: &body,
                    admission: RequestAdmission::Delivery(DeliveryAdmission {
                        jobs: self.jobs.as_ref(),
                        prepared,
                    }),
                },
            )
            .await?;
        let applied = parsed(&response, &prepared.projection)?;
        if applied.target != remote.target || !equal(&applied, &prepared.projection) {
            return Err(FailureCode::OwnershipMismatch);
        }
        Ok(applied)
    }

    async fn reconcile(
        &self,
        prepared: &PreparedDelivery,
    ) -> Result<Option<RemoteDocument>, FailureCode> {
        let remote = if let Some(target) = prepared.assignment.target {
            Some(self.fetch(prepared, target).await?)
        } else {
            self.locate(prepared).await?
        };
        if let Some(remote) = remote {
            return self.apply_existing(prepared, remote).await.map(Some);
        }
        // Deprovisioning an assignment never creates a previously absent remote
        // object merely to disable/empty it. An already-admitted uncertain POST
        // must instead establish this SAME incarnation disabled/empty, so a late
        // duplicate create cannot orphan an active object after retirement.
        let source_exists = match &prepared.projection {
            Projection::User(user) => user.source_exists,
            Projection::Group(group) => group.source_exists,
        };
        if (!prepared.assignment.selected || !source_exists)
            && !prepared.assignment.creation_admitted
        {
            return Ok(None);
        }
        let body = serde_json::to_vec(&desired(&prepared.projection, None))
            .map_err(|_| FailureCode::SourceProjectionInvalid)?;
        let response = self
            .client
            .request(
                &prepared.connector.credential,
                ScimRequest {
                    method: Method::POST,
                    path: collection(prepared.assignment.kind),
                    query: None,
                    etag: None,
                    body: &body,
                    admission: RequestAdmission::Delivery(DeliveryAdmission {
                        jobs: self.jobs.as_ref(),
                        prepared,
                    }),
                },
            )
            .await?;
        if response.status == 409 {
            let remote = self
                .locate(prepared)
                .await?
                .ok_or(FailureCode::OwnershipMismatch)?;
            return self.apply_existing(prepared, remote).await.map(Some);
        }
        let applied = parsed(&response, &prepared.projection)?;
        if !equal(&applied, &prepared.projection) {
            return Err(FailureCode::OwnershipMismatch);
        }
        Ok(Some(applied))
    }
}

#[async_trait::async_trait]
impl Deliverer for OutboundScimDeliverer {
    fn family(&self) -> &'static str {
        "outbound_scim"
    }
    async fn deliver(&self, event: &OutboxEvent) -> Result<Delivered, Undelivered> {
        if event.kind != "outbound_scim.reconcile" {
            return Err(refused(FailureCode::SourceProjectionInvalid));
        }
        let locator: Locator = serde_json::from_value(event.payload.clone())
            .map_err(|_| refused(FailureCode::SourceProjectionInvalid))?;
        let assignment = canonical_uuid(&locator.assignment)
            .map_err(|_| refused(FailureCode::SourceProjectionInvalid))?;
        let generation = canonical_uuid(&locator.generation)
            .map_err(|_| refused(FailureCode::SourceProjectionInvalid))?;
        let prepared = self
            .jobs
            .prepare(&event.tenant, event.id, event.attempt, assignment)
            .await
            .map_err(|error| refused(domain_code(&error)))?;
        if prepared.assignment.generation != generation {
            return Err(refused(FailureCode::LeaseSuperseded));
        }
        let remaining = prepared.fence.deadline - OffsetDateTime::now_utc();
        let timeout = std::time::Duration::try_from(remaining)
            .map_err(|_| refused(FailureCode::LeaseSuperseded))?;
        let outcome = tokio::time::timeout(timeout, self.reconcile(&prepared))
            .await
            .unwrap_or(Err(FailureCode::LeaseSuperseded));
        match outcome {
            Ok(remote) => {
                let receipt = MappingReceipt {
                    target: remote.as_ref().map(|document| document.target),
                    etag: remote.as_ref().map(|document| document.etag.clone()),
                    observed_at: OffsetDateTime::now_utc(),
                };
                self.jobs
                    .complete(&event.tenant, assignment, &prepared.fence, &receipt)
                    .await
                    .map_err(|error| refused(domain_code(&error)))?;
                Ok(if remote.is_some() {
                    Delivered::Sent
                } else {
                    Delivered::Journalled
                })
            }
            Err(code) => {
                self.jobs
                    .fail(&event.tenant, assignment, &prepared.fence, code)
                    .await
                    .map_err(|error| refused(domain_code(&error)))?;
                Err(refused(code))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::outbound_scim::UserProjection;
    #[test]
    fn source_deprovision_body_never_carries_credentials_or_authorization_roles() {
        let projection = Projection::User(UserProjection {
            source_exists: true,
            immutable_alias: "fixed".into(),
            external_id: "owned".into(),
            work_email: None,
            active: false,
        });
        let document = desired(&projection, Some(Uuid::from_u128(1)));
        assert_eq!(document["active"], false);
        assert_eq!(document["emails"], json!([]));
        for forbidden in ["password", "roles", "groups", "claims", "credentials"] {
            assert!(document.get(forbidden).is_none());
        }
    }
    #[test]
    fn diagnostics_are_fixed_codes_and_version_conflicts_are_permanent() {
        assert_eq!(
            refused(FailureCode::TargetVersionChanged).detail,
            "target_version_changed"
        );
        assert!(refused(FailureCode::TargetVersionChanged).permanent);
        assert!(!refused(FailureCode::TargetUnavailable).permanent);
        assert!(!refused(FailureCode::Paused).permanent);
    }
}
