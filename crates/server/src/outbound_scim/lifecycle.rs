//! Explicit lifecycle delivery shares the same ownership parser and HTTP guard.

use super::OutboundScimClient;
use super::client::{RequestAdmission, ScimRequest};
use super::inspection::OwnerReader;
use super::worker::{collection, desired, domain_code, equal, parsed, refused, status};
use crate::outbox::{Delivered, Undelivered};
use asterius_domain::outbound_scim::{
    FailureCode, LifecycleKind, LifecyclePreparation, LifecycleReceipt, OutboundScimLifecycle,
    PreparedLifecycle, Projection, RemoteDocument, canonical_uuid,
};
use asterius_domain::outbox::OutboxEvent;
use hyper::Method;
use serde::Deserialize;
use std::sync::Arc;
use time::OffsetDateTime;

#[derive(Debug)]
pub(super) struct LifecycleDeliverer {
    pub jobs: Arc<dyn OutboundScimLifecycle>,
    pub client: Arc<OutboundScimClient>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Locator {
    request: String,
    assignment: String,
    generation: String,
}
fn quiescent(remote: &RemoteDocument, projection: &Projection) -> bool {
    match projection {
        Projection::User(_) => remote.active == Some(false),
        Projection::Group(_) => remote.members.is_empty(),
    }
}
fn disabled(projection: &Projection) -> Projection {
    let mut projection = projection.clone();
    match &mut projection {
        Projection::User(user) => user.active = false,
        Projection::Group(group) => group.target_members.clear(),
    }
    projection
}
impl LifecycleDeliverer {
    fn admission<'a>(&'a self, prepared: &'a PreparedLifecycle) -> RequestAdmission<'a> {
        RequestAdmission::Lifecycle {
            jobs: self.jobs.as_ref(),
            prepared,
        }
    }
    async fn remote(
        &self,
        prepared: &PreparedLifecycle,
    ) -> Result<Option<RemoteDocument>, FailureCode> {
        let delivery = &prepared.delivery;
        let reader = OwnerReader {
            client: &self.client,
            credential: &delivery.connector.credential,
            kind: delivery.assignment.kind,
            projection: &delivery.projection,
            admission: self.admission(prepared),
        };
        match prepared.request.target {
            Some(target) => match reader.fetch(target).await {
                Ok(remote) => Ok(Some(remote)),
                Err(FailureCode::TargetAbsent)
                    if prepared.request.kind == LifecycleKind::Recreate
                        || prepared.request.kind == LifecycleKind::Delete
                            && prepared.request.delete_admitted =>
                {
                    Ok(None)
                }
                Err(code) => Err(code),
            },
            None => reader.locate().await,
        }
    }
    async fn perform(&self, prepared: &PreparedLifecycle) -> Result<LifecycleReceipt, FailureCode> {
        let Some(remote) = self.remote(prepared).await? else {
            return match prepared.request.kind {
                LifecycleKind::Archive
                    if prepared.request.target.is_none()
                        && !prepared.delivery.assignment.creation_admitted =>
                {
                    Ok(LifecycleReceipt {
                        absent: true,
                        etag: None,
                    })
                }
                LifecycleKind::Delete if prepared.request.delete_admitted => Ok(LifecycleReceipt {
                    absent: true,
                    etag: None,
                }),
                LifecycleKind::Recreate => Ok(LifecycleReceipt {
                    absent: true,
                    etag: None,
                }),
                _ => Err(FailureCode::TargetAbsent),
            };
        };
        if prepared.request.target != Some(remote.target)
            || prepared.request.etag.as_deref() != Some(&remote.etag)
            || !quiescent(&remote, &prepared.delivery.projection)
        {
            return Err(FailureCode::TargetVersionChanged);
        }
        let path = format!(
            "{}/{}",
            collection(prepared.delivery.assignment.kind),
            remote.target
        );
        if prepared.request.kind == LifecycleKind::Delete {
            let response = self
                .client
                .request(
                    &prepared.delivery.connector.credential,
                    ScimRequest {
                        method: Method::DELETE,
                        path: &path,
                        query: None,
                        etag: Some(&remote.etag),
                        body: &[],
                        admission: self.admission(prepared),
                    },
                )
                .await?;
            if response.status == 404 {
                return Ok(LifecycleReceipt {
                    absent: true,
                    etag: None,
                });
            }
            status(&response)?;
            if response.status != 204 {
                return Err(FailureCode::SourceProjectionInvalid);
            }
            return Ok(LifecycleReceipt {
                absent: true,
                etag: None,
            });
        }
        // Even a matching inactive/empty resource is conditionally rewritten:
        // its new ETag prevents an older admitted PUT undoing retirement.
        let projection = disabled(&prepared.delivery.projection);
        let body = serde_json::to_vec(&desired(&projection, Some(remote.target)))
            .map_err(|_| FailureCode::SourceProjectionInvalid)?;
        let response = self
            .client
            .request(
                &prepared.delivery.connector.credential,
                ScimRequest {
                    method: Method::PUT,
                    path: &path,
                    query: None,
                    etag: Some(&remote.etag),
                    body: &body,
                    admission: self.admission(prepared),
                },
            )
            .await?;
        let applied = parsed(&response, &projection)?;
        if applied.target != remote.target
            || !equal(&applied, &projection)
            || applied.etag == remote.etag
        {
            return Err(FailureCode::OwnershipMismatch);
        }
        Ok(LifecycleReceipt {
            absent: false,
            etag: Some(applied.etag),
        })
    }
    pub async fn deliver(&self, event: &OutboxEvent) -> Result<Delivered, Undelivered> {
        let locator: Locator = serde_json::from_value(event.payload.clone())
            .map_err(|_| refused(FailureCode::SourceProjectionInvalid))?;
        let id = canonical_uuid(&locator.request)
            .map_err(|_| refused(FailureCode::SourceProjectionInvalid))?;
        let assignment = canonical_uuid(&locator.assignment)
            .map_err(|_| refused(FailureCode::SourceProjectionInvalid))?;
        let generation = canonical_uuid(&locator.generation)
            .map_err(|_| refused(FailureCode::SourceProjectionInvalid))?;
        let prepared = match self
            .jobs
            .prepare(&event.tenant, event.id, event.attempt, id)
            .await
            .map_err(|error| refused(domain_code(&error)))?
        {
            LifecyclePreparation::Completed => return Ok(Delivered::Journalled),
            LifecyclePreparation::Pending(prepared) => prepared,
        };
        if prepared.delivery.assignment.id != assignment
            || prepared.delivery.assignment.generation != generation
        {
            return Err(refused(FailureCode::LeaseSuperseded));
        }
        let timeout = std::time::Duration::try_from(
            prepared.delivery.fence.deadline - OffsetDateTime::now_utc(),
        )
        .map_err(|_| refused(FailureCode::LeaseSuperseded))?;
        match tokio::time::timeout(timeout, self.perform(&prepared))
            .await
            .unwrap_or(Err(FailureCode::LeaseSuperseded))
        {
            Ok(receipt) => {
                self.jobs
                    .complete(&event.tenant, id, &prepared.delivery.fence, &receipt)
                    .await
                    .map_err(|error| refused(domain_code(&error)))?;
                Ok(Delivered::Sent)
            }
            Err(code) => {
                self.jobs
                    .fail(&event.tenant, id, &prepared.delivery.fence, code)
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
    fn recreation_fencing_body_cannot_reactivate_an_old_incarnation() {
        let current = Projection::User(UserProjection {
            source_exists: true,
            immutable_alias: "pinned".into(),
            external_id: "owned".into(),
            work_email: None,
            active: true,
        });
        let projection = disabled(&current);
        assert!(matches!(&projection,Projection::User(user) if !user.active));
        assert!(matches!(&current,Projection::User(user) if user.active));
    }
}
