//! Recoverable lifecycle approvals; all remote effects occur outside transactions.

use super::{administration as admin, jobs};
use crate::error::to_domain_error;
use asterius_domain::audit::EventType;
use asterius_domain::outbound_scim::{
    Assignment, Connector, DeliveryFence, FailureCode, LifecycleCommand, LifecycleKind,
    LifecyclePreparation, LifecycleReceipt, LifecycleRequest, LifecycleView, OutboundScimLifecycle,
    PreparedDelivery, PreparedLifecycle, Projection, ResourceKind, resource_identity,
};
use asterius_domain::{DomainError, TenantId, UserId};
use sqlx::{PgConnection, PgPool, Row};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PgOutboundScimLifecycle {
    pool: PgPool,
}
impl PgOutboundScimLifecycle {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
struct StoredRequest {
    approval: LifecycleRequest,
    assignment: Uuid,
    generation: Uuid,
    connector_revision: Uuid,
    credential_generation: Uuid,
    desired_revision: Uuid,
    completed: bool,
    cancelled: bool,
}
fn conflict(code: &str) -> DomainError {
    DomainError::Conflict(code.into())
}
async fn request_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
) -> Result<(Connector, Assignment, StoredRequest), DomainError> {
    let assignment:Uuid=sqlx::query_scalar("select assignment_id from outbound_scim_lifecycle_requests where tenant_id=$1 and request_id=$2")
        .bind(tenant.as_str()).bind(id).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
    // Current human authority locks precede connector/assignment locks, just
    // like administration and source writers. Avoid parent -> user inversion.
    let actor_row=sqlx::query("select reviewed_by,completed_at from outbound_scim_lifecycle_requests where tenant_id=$1 and request_id=$2")
        .bind(tenant.as_str()).bind(id).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
    if actor_row
        .try_get::<Option<OffsetDateTime>, _>("completed_at")
        .map_err(to_domain_error)?
        .is_none()
    {
        admin::actor_on(
            connection,
            tenant,
            UserId::new(actor_row.try_get("reviewed_by").map_err(to_domain_error)?),
        )
        .await?;
    }
    let (connector, assignment) = jobs::load_history(connection, tenant, assignment, true).await?;
    let row=sqlx::query("select * from outbound_scim_lifecycle_requests where tenant_id=$1 and request_id=$2 for update")
        .bind(tenant.as_str()).bind(id).fetch_one(connection).await.map_err(to_domain_error)?;
    let kind: String = row.try_get("kind").map_err(to_domain_error)?;
    let kind = match kind.as_str() {
        "archive" => LifecycleKind::Archive,
        "delete" => LifecycleKind::Delete,
        "recreate" => LifecycleKind::Recreate,
        _ => return Err(conflict("source_projection_invalid")),
    };
    let stored = StoredRequest {
        approval: LifecycleRequest {
            id,
            kind,
            reviewer: UserId::new(row.try_get("reviewed_by").map_err(to_domain_error)?),
            target: row.try_get("target_id").map_err(to_domain_error)?,
            etag: row.try_get("expected_etag").map_err(to_domain_error)?,
            expires_at: row.try_get("expires_at").map_err(to_domain_error)?,
            delete_admitted: row.try_get("delete_admitted").map_err(to_domain_error)?,
        },
        assignment: assignment.id,
        generation: row
            .try_get("assignment_generation")
            .map_err(to_domain_error)?,
        connector_revision: row.try_get("connector_revision").map_err(to_domain_error)?,
        credential_generation: row
            .try_get("credential_generation")
            .map_err(to_domain_error)?,
        desired_revision: row.try_get("desired_revision").map_err(to_domain_error)?,
        completed: row
            .try_get::<Option<OffsetDateTime>, _>("completed_at")
            .map_err(to_domain_error)?
            .is_some(),
        cancelled: row
            .try_get::<Option<OffsetDateTime>, _>("cancelled_at")
            .map_err(to_domain_error)?
            .is_some(),
    };
    Ok((connector, assignment, stored))
}
fn check(
    request: &StoredRequest,
    connector: &Connector,
    assignment: &Assignment,
    fence: &DeliveryFence,
    now: OffsetDateTime,
    mutation: bool,
) -> Result<(), DomainError> {
    jobs::check_fence(connector, assignment, fence, now)?;
    if request.cancelled
        || request.completed
        || request.assignment != assignment.id
        || request.generation != assignment.generation
        || request.connector_revision != connector.revision
        || request.credential_generation != connector.credential.generation
        || request.desired_revision != assignment.desired_revision
        || fence.desired_revision != assignment.desired_revision
        || request.approval.target != assignment.target
        || assignment.retired_at.is_some() && request.approval.kind != LifecycleKind::Recreate
        || (request.approval.kind == LifecycleKind::Delete && !connector.allow_reviewed_delete)
        || (now >= request.approval.expires_at && (mutation || !request.approval.delete_admitted))
    {
        return Err(conflict("lease_superseded"));
    }
    Ok(())
}
fn quiescent(projection: &Projection) -> bool {
    match projection {
        Projection::User(user) => !user.active,
        Projection::Group(group) => group.target_members.is_empty(),
    }
}
async fn lease(
    connection: &mut PgConnection,
    tenant: &TenantId,
    request: &StoredRequest,
    assignment: &Assignment,
    outbox: i64,
    attempt: u32,
) -> Result<(OffsetDateTime, OffsetDateTime), DomainError> {
    let times = jobs::lease_on(
        connection,
        tenant,
        outbox,
        attempt,
        assignment,
        "outbound_scim.lifecycle",
    )
    .await?;
    let matches: bool = sqlx::query_scalar(
        "select payload->>'request'=$3 from outbox where tenant_id=$1 and outbox_id=$2",
    )
    .bind(tenant.as_str())
    .bind(outbox)
    .bind(request.approval.id.to_string())
    .fetch_one(connection)
    .await
    .map_err(to_domain_error)?;
    if !matches {
        return Err(conflict("lease_superseded"));
    }
    Ok(times)
}

// Archive a completed same-incarnation deletion without admitting remote work.
// The caller retains its actor, connector and assignment locks through commit.
async fn archive_deleted_receipt(
    connection: &mut PgConnection,
    tenant: &TenantId,
    actor: UserId,
    connector: &Connector,
    assignment: &Assignment,
) -> Result<LifecycleView, DomainError> {
    // A prior completed same-incarnation DELETE is a durable absence
    // receipt. Archiving it grants no new target effect or replacement.
    let deleted:bool=sqlx::query_scalar("select exists(select 1 from outbound_scim_lifecycle_requests where tenant_id=$1 and assignment_id=$2 and assignment_generation=$3 and target_id=$4 and kind='delete' and delete_admitted and completed_at is not null)")
        .bind(tenant.as_str()).bind(assignment.id).bind(assignment.generation).bind(assignment.target).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
    if !deleted {
        return Err(conflict("ownership_mismatch"));
    }
    let now = admin::clock(connection).await?;
    let id = Uuid::new_v4();
    sqlx::query("insert into outbound_scim_lifecycle_requests(tenant_id,request_id,assignment_id,assignment_generation,connector_revision,credential_generation,desired_revision,kind,target_id,expected_etag,reviewed_by,reviewed_at,expires_at,completed_at) values($1,$2,$3,$4,$5,$6,$7,'archive',$8,$9,$10,$11,$11::timestamptz+interval '5 minutes',$11)")
        .bind(tenant.as_str()).bind(id).bind(assignment.id).bind(assignment.generation).bind(connector.revision).bind(connector.credential.generation).bind(assignment.desired_revision).bind(assignment.target).bind(&assignment.observed_etag).bind(actor.as_uuid()).bind(now).execute(&mut *connection).await.map_err(to_domain_error)?;
    sqlx::query("update outbound_scim_assignments set retired_at=$3 where tenant_id=$1 and assignment_id=$2")
        .bind(tenant.as_str()).bind(assignment.id).bind(now).execute(&mut *connection).await.map_err(to_domain_error)?;
    admin::evidence(
        connection,
        tenant,
        actor,
        id,
        "outbound_scim_deleted_receipt_archived",
    )
    .await?;
    Ok(LifecycleView {
        id,
        kind: LifecycleKind::Archive,
        completed: true,
        replacement: None,
        failure_code: None,
        cancelled: false,
    })
}

#[async_trait::async_trait]
impl OutboundScimLifecycle for PgOutboundScimLifecycle {
    async fn recent(
        &self,
        tenant: &TenantId,
        connector: Uuid,
        assignment: Uuid,
    ) -> Result<Vec<LifecycleView>, DomainError> {
        let rows=sqlx::query("select r.request_id,r.kind,r.completed_at,r.cancelled_at,r.replacement_id,r.failure_code from outbound_scim_lifecycle_requests r join outbound_scim_assignments a using(tenant_id,assignment_id) where r.tenant_id=$1 and a.connector_id=$2 and r.assignment_id=$3 order by r.reviewed_at desc,r.request_id desc limit 25")
            .bind(tenant.as_str()).bind(connector).bind(assignment).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        rows.iter()
            .map(|row| {
                let kind: String = row.try_get("kind").map_err(to_domain_error)?;
                Ok(LifecycleView {
                    id: row.try_get("request_id").map_err(to_domain_error)?,
                    kind: match kind.as_str() {
                        "archive" => LifecycleKind::Archive,
                        "delete" => LifecycleKind::Delete,
                        "recreate" => LifecycleKind::Recreate,
                        _ => return Err(conflict("source_projection_invalid")),
                    },
                    completed: row
                        .try_get::<Option<OffsetDateTime>, _>("completed_at")
                        .map_err(to_domain_error)?
                        .is_some(),
                    cancelled: row
                        .try_get::<Option<OffsetDateTime>, _>("cancelled_at")
                        .map_err(to_domain_error)?
                        .is_some(),
                    replacement: row.try_get("replacement_id").map_err(to_domain_error)?,
                    failure_code: row.try_get("failure_code").map_err(to_domain_error)?,
                })
            })
            .collect()
    }

    async fn enqueue(
        &self,
        tenant: &TenantId,
        actor: UserId,
        connector_id: Uuid,
        assignment_id: Uuid,
        command: LifecycleCommand,
    ) -> Result<LifecycleView, DomainError> {
        command.validate()?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        admin::actor_on(&mut tx, tenant, actor).await?;
        let (connector, assignment) =
            jobs::load_history(&mut tx, tenant, assignment_id, true).await?;
        if connector.id != connector_id
            || connector.revision != command.expected_revision
            || assignment.generation != command.expected_generation
            || assignment.retired_at.is_some() && command.kind != LifecycleKind::Recreate
            || assignment.target != command.target
            || assignment.observed_etag != command.etag
        {
            return Err(conflict("ownership_mismatch"));
        }
        let state: String = sqlx::query_scalar(
            "select state from outbound_scim_assignments where tenant_id=$1 and assignment_id=$2",
        )
        .bind(tenant.as_str())
        .bind(assignment_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if state == "deleted" && command.kind == LifecycleKind::Archive {
            let receipt =
                archive_deleted_receipt(&mut tx, tenant, actor, &connector, &assignment).await?;
            tx.commit().await.map_err(to_domain_error)?;
            return Ok(receipt);
        }
        if !connector.enabled || state == "deleted" && command.kind != LifecycleKind::Recreate {
            return Err(conflict("paused"));
        }
        if command.kind == LifecycleKind::Recreate {
            let other:bool=sqlx::query_scalar("select exists(select 1 from outbound_scim_assignments where tenant_id=$1 and connector_id=$2 and kind=$3 and source_id=$4 and retired_at is null and assignment_id<>$5)")
                .bind(tenant.as_str()).bind(connector.id).bind(match assignment.kind{ResourceKind::User=>"user",ResourceKind::Group=>"group"}).bind(assignment.source).bind(assignment.id).fetch_one(&mut *tx).await.map_err(to_domain_error)?;
            if other {
                return Err(conflict("ownership_mismatch"));
            }
        }
        let projection = jobs::projection_on(&mut tx, tenant, &assignment).await?;
        if command.kind != LifecycleKind::Recreate
            && (!quiescent(&projection)
                || assignment.selected
                    && match &projection {
                        Projection::User(user) => user.source_exists,
                        Projection::Group(group) => group.source_exists,
                    })
        {
            return Err(conflict("source_projection_invalid"));
        }
        if command.kind == LifecycleKind::Delete && !connector.allow_reviewed_delete {
            return Err(conflict("source_projection_invalid"));
        }
        // Uncertain POSTs must first resolve the same incarnation through the
        // normal deprovision job. A point-in-time absence is insufficient.
        if assignment.target.is_none() && assignment.creation_admitted {
            return Err(conflict("ownership_mismatch"));
        }
        if command.kind == LifecycleKind::Recreate && assignment.target.is_none() {
            return Err(conflict("target_absent"));
        }
        let now = admin::clock(&mut tx).await?;
        sqlx::query("update outbound_scim_lifecycle_requests set cancelled_at=$2 where tenant_id=$1 and assignment_id in (select assignment_id from outbound_scim_assignments where tenant_id=$1 and connector_id=$3 and kind=$4 and source_id=$5) and completed_at is null and cancelled_at is null and expires_at<=$2")
            .bind(tenant.as_str()).bind(now).bind(connector.id).bind(match assignment.kind{ResourceKind::User=>"user",ResourceKind::Group=>"group"}).bind(assignment.source).execute(&mut *tx).await.map_err(to_domain_error)?;
        let open:bool=sqlx::query_scalar("select exists(select 1 from outbound_scim_lifecycle_requests r join outbound_scim_assignments a using(tenant_id,assignment_id) where r.tenant_id=$1 and a.connector_id=$2 and a.kind=$3 and a.source_id=$4 and r.completed_at is null and r.cancelled_at is null)")
            .bind(tenant.as_str()).bind(connector.id).bind(match assignment.kind{ResourceKind::User=>"user",ResourceKind::Group=>"group"}).bind(assignment.source).fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        if open {
            return Err(conflict("lifecycle approval is already pending"));
        }
        let inherited_delete: bool = if command.kind == LifecycleKind::Delete {
            sqlx::query_scalar("select exists(select 1 from outbound_scim_lifecycle_requests where tenant_id=$1 and assignment_id=$2 and assignment_generation=$3 and target_id=$4 and kind='delete' and delete_admitted)")
                .bind(tenant.as_str()).bind(assignment_id).bind(assignment.generation).bind(assignment.target).fetch_one(&mut *tx).await.map_err(to_domain_error)?
        } else {
            false
        };
        let id = Uuid::new_v4();
        let desired = Uuid::new_v4();
        // Supersede all pre-approval admission snapshots before queueing the
        // same ordered assignment stream. Current remote ownership stays pinned.
        sqlx::query("update outbound_scim_assignments set desired_revision=$3,dirty=true where tenant_id=$1 and assignment_id=$2")
            .bind(tenant.as_str()).bind(assignment_id).bind(desired).execute(&mut *tx).await.map_err(to_domain_error)?;
        sqlx::query("insert into outbound_scim_lifecycle_requests(tenant_id,request_id,assignment_id,assignment_generation,connector_revision,credential_generation,desired_revision,kind,target_id,expected_etag,reviewed_by,reviewed_at,expires_at,delete_admitted) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12::timestamptz+interval '5 minutes',$13)")
            .bind(tenant.as_str()).bind(id).bind(assignment_id).bind(assignment.generation).bind(connector.revision).bind(connector.credential.generation).bind(desired).bind(command.kind.as_str()).bind(command.target).bind(&command.etag).bind(actor.as_uuid()).bind(now).bind(inherited_delete).execute(&mut *tx).await.map_err(to_domain_error)?;
        sqlx::query("insert into outbox(tenant_id,kind,destination,payload,ordering_key) values($1,'outbound_scim.lifecycle',$2,$3,$4)")
            .bind(tenant.as_str()).bind(connector_id.to_string()).bind(serde_json::json!({"assignment":assignment_id.to_string(),"generation":assignment.generation.to_string(),"request":id.to_string()})).bind(format!("outbound_scim:{assignment_id}")).execute(&mut *tx).await.map_err(to_domain_error)?;
        admin::evidence(
            &mut tx,
            tenant,
            actor,
            id,
            "outbound_scim_lifecycle_approved",
        )
        .await?;
        if admin::clock(&mut tx).await? >= now + Duration::minutes(5) {
            return Err(conflict("lease_superseded"));
        }
        tx.commit().await.map_err(to_domain_error)?;
        Ok(LifecycleView {
            id,
            kind: command.kind,
            completed: false,
            replacement: None,
            failure_code: None,
            cancelled: false,
        })
    }
    async fn prepare(
        &self,
        tenant: &TenantId,
        outbox_id: i64,
        attempt: u32,
        id: Uuid,
    ) -> Result<LifecyclePreparation, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let (connector, assignment, request) = request_on(&mut tx, tenant, id).await?;
        let (now, expiry) =
            lease(&mut tx, tenant, &request, &assignment, outbox_id, attempt).await?;
        if request.completed {
            tx.commit().await.map_err(to_domain_error)?;
            return Ok(LifecyclePreparation::Completed);
        }
        let fence = DeliveryFence {
            outbox_id,
            attempt,
            connector_revision: request.connector_revision,
            credential_generation: request.credential_generation,
            assignment_generation: request.generation,
            desired_revision: request.desired_revision,
            deadline: expiry.min(now + Duration::seconds(45)),
        };
        check(&request, &connector, &assignment, &fence, now, false)?;
        let projection = jobs::projection_on(&mut tx, tenant, &assignment).await?;
        if request.approval.kind != LifecycleKind::Recreate && !quiescent(&projection) {
            return Err(conflict("source_projection_invalid"));
        }
        jobs::recheck_deadline(&mut tx, &fence).await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(LifecyclePreparation::Pending(Box::new(PreparedLifecycle {
            delivery: PreparedDelivery {
                connector,
                assignment,
                fence,
                projection,
            },
            request: request.approval,
        })))
    }
    async fn admit(
        &self,
        tenant: &TenantId,
        id: Uuid,
        fence: &DeliveryFence,
        mutating: bool,
        deleting: bool,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let (connector, assignment, request) = request_on(&mut tx, tenant, id).await?;
        let (now, _) = lease(
            &mut tx,
            tenant,
            &request,
            &assignment,
            fence.outbox_id,
            fence.attempt,
        )
        .await?;
        check(&request, &connector, &assignment, fence, now, mutating)?;
        jobs::projection_on(&mut tx, tenant, &assignment).await?;
        if deleting {
            if request.approval.kind != LifecycleKind::Delete {
                return Err(conflict("source_projection_invalid"));
            }
            sqlx::query("update outbound_scim_lifecycle_requests set delete_admitted=true where tenant_id=$1 and request_id=$2")
                .bind(tenant.as_str()).bind(id).execute(&mut *tx).await.map_err(to_domain_error)?;
        }
        check(
            &request,
            &connector,
            &assignment,
            fence,
            admin::clock(&mut tx).await?,
            mutating,
        )?;
        tx.commit().await.map_err(to_domain_error)
    }
    async fn complete(
        &self,
        tenant: &TenantId,
        id: Uuid,
        fence: &DeliveryFence,
        receipt: &LifecycleReceipt,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let (connector, assignment, request) = request_on(&mut tx, tenant, id).await?;
        let (now, _) = lease(
            &mut tx,
            tenant,
            &request,
            &assignment,
            fence.outbox_id,
            fence.attempt,
        )
        .await?;
        if request.completed {
            tx.commit().await.map_err(to_domain_error)?;
            return Ok(());
        }
        check(&request, &connector, &assignment, fence, now, false)?;
        if receipt.absent == receipt.etag.is_some() {
            return Err(conflict("ownership_mismatch"));
        }
        if let Some(etag) = &receipt.etag {
            asterius_domain::outbound_scim::target_etag(etag)?;
        }
        if request.approval.kind == LifecycleKind::Delete
            && (!receipt.absent || !request.approval.delete_admitted)
        {
            return Err(conflict("ownership_mismatch"));
        }
        if request.approval.kind == LifecycleKind::Archive
            && receipt.absent
            && (assignment.target.is_some() || assignment.creation_admitted)
        {
            return Err(conflict("ownership_mismatch"));
        }
        let current = jobs::projection_on(&mut tx, tenant, &assignment).await?;
        if request.approval.kind != LifecycleKind::Recreate && !quiescent(&current) {
            return Err(conflict("source_projection_invalid"));
        }
        let replacement = if request.approval.kind == LifecycleKind::Recreate {
            sqlx::query("update outbound_scim_assignments set selected=false,retired_at=coalesce(retired_at,$3),dirty=false,observed_etag=coalesce($4,observed_etag),observed_at=$3 where tenant_id=$1 and assignment_id=$2")
                .bind(tenant.as_str()).bind(assignment.id).bind(now).bind(&receipt.etag).execute(&mut *tx).await.map_err(to_domain_error)?;
            let new_id = Uuid::new_v4();
            let generation = Uuid::new_v4();
            let (alias, external) = resource_identity(
                tenant,
                connector.id,
                assignment.kind,
                assignment.source,
                generation,
            );
            sqlx::query("insert into outbound_scim_assignments(tenant_id,connector_id,assignment_id,kind,source_id,generation,immutable_alias,external_id) values($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(tenant.as_str()).bind(connector.id).bind(new_id).bind(match assignment.kind{ResourceKind::User=>"user",ResourceKind::Group=>"group"}).bind(assignment.source).bind(generation).bind(alias).bind(external).execute(&mut *tx).await.map_err(to_domain_error)?;
            admin::queue(&mut tx, tenant, new_id).await?;
            if assignment.kind == ResourceKind::User {
                admin::queue_user_groups(&mut tx, tenant, connector.id, &[assignment.source])
                    .await?;
            }
            Some(new_id)
        } else {
            sqlx::query("update outbound_scim_assignments set selected=false,retired_at=case when $4='archive' then $3 else retired_at end,state=case when $4='delete' then 'deleted' else 'applied' end,dirty=false,failure_code=null,observed_at=$3,observed_etag=coalesce($5,observed_etag),delivered_revision=desired_revision where tenant_id=$1 and assignment_id=$2")
                .bind(tenant.as_str()).bind(assignment.id).bind(now).bind(request.approval.kind.as_str()).bind(&receipt.etag).execute(&mut *tx).await.map_err(to_domain_error)?;
            None
        };
        sqlx::query("update outbound_scim_lifecycle_requests set completed_at=$3,replacement_id=$4,failure_code=null where tenant_id=$1 and request_id=$2")
            .bind(tenant.as_str()).bind(id).bind(now).bind(replacement).execute(&mut *tx).await.map_err(to_domain_error)?;
        jobs::audit_delivery(
            &mut tx,
            tenant,
            assignment.id,
            now,
            EventType::OUTBOUND_SCIM_DELIVERED,
            request.approval.kind.as_str(),
        )
        .await?;
        jobs::recheck_deadline(&mut tx, fence).await?;
        if !request.approval.delete_admitted
            && admin::clock(&mut tx).await? >= request.approval.expires_at
        {
            return Err(conflict("lease_superseded"));
        }
        tx.commit().await.map_err(to_domain_error)
    }
    async fn fail(
        &self,
        tenant: &TenantId,
        id: Uuid,
        fence: &DeliveryFence,
        code: FailureCode,
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let (connector, assignment, request) = request_on(&mut tx, tenant, id).await?;
        let (now, _) = lease(
            &mut tx,
            tenant,
            &request,
            &assignment,
            fence.outbox_id,
            fence.attempt,
        )
        .await?;
        check(&request, &connector, &assignment, fence, now, false)?;
        sqlx::query("update outbound_scim_lifecycle_requests set failure_code=$3 where tenant_id=$1 and request_id=$2")
            .bind(tenant.as_str()).bind(id).bind(code.as_str()).execute(&mut *tx).await.map_err(to_domain_error)?;
        jobs::audit_delivery(
            &mut tx,
            tenant,
            assignment.id,
            now,
            EventType::OUTBOUND_SCIM_REFUSED,
            code.as_str(),
        )
        .await?;
        jobs::recheck_deadline(&mut tx, fence).await?;
        tx.commit().await.map_err(to_domain_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::ClientId;
    use asterius_domain::outbound_scim::CredentialBinding;
    fn context() -> (
        Connector,
        Assignment,
        StoredRequest,
        DeliveryFence,
        OffsetDateTime,
    ) {
        let now = OffsetDateTime::UNIX_EPOCH + Duration::hours(1);
        let id = Uuid::from_u128(1);
        let generation = Uuid::from_u128(2);
        let revision = Uuid::from_u128(3);
        let target = Uuid::from_u128(4);
        let desired = Uuid::from_u128(5);
        let credential = Uuid::from_u128(6);
        let connector = Connector {
            tenant: TenantId::new("source"),
            id,
            revision,
            target_issuer: "https://target.example/t/target".into(),
            target_client: ClientId::new("provisioner"),
            enabled: true,
            allow_reviewed_delete: true,
            credential: CredentialBinding {
                reference: "key".into(),
                generation: credential,
                source_tenant: TenantId::new("source"),
                target_admin_resource: "https://target.example/t/target/admin/api/v1".into(),
                scim_origin: "https://target.example".into(),
                target_issuer: "https://target.example/t/target".into(),
                target_client: ClientId::new("provisioner"),
            },
        };
        let assignment = Assignment {
            id,
            connector: id,
            kind: ResourceKind::User,
            source: Uuid::from_u128(7),
            generation,
            desired_revision: desired,
            immutable_alias: "owned".into(),
            external_id: "owned".into(),
            selected: false,
            target: Some(target),
            observed_etag: Some("W/\"1\"".into()),
            creation_admitted: true,
            retired_at: None,
        };
        let request = StoredRequest {
            approval: LifecycleRequest {
                id: Uuid::from_u128(8),
                kind: LifecycleKind::Delete,
                reviewer: UserId::new(Uuid::from_u128(9)),
                target: Some(target),
                etag: Some("W/\"1\"".into()),
                expires_at: now + Duration::minutes(5),
                delete_admitted: false,
            },
            assignment: id,
            generation,
            connector_revision: revision,
            credential_generation: credential,
            desired_revision: desired,
            completed: false,
            cancelled: false,
        };
        let fence = DeliveryFence {
            outbox_id: 1,
            attempt: 1,
            connector_revision: revision,
            credential_generation: credential,
            assignment_generation: generation,
            desired_revision: desired,
            deadline: now + Duration::seconds(45),
        };
        (connector, assignment, request, fence, now)
    }
    #[test]
    fn expired_approval_cannot_dispatch_a_new_effect() {
        let (connector, assignment, mut request, fence, now) = context();
        request.approval.expires_at = now;
        assert!(check(&request, &connector, &assignment, &fence, now, true).is_err());
        assert!(check(&request, &connector, &assignment, &fence, now, false).is_err());
    }
    #[test]
    fn admitted_same_resource_deletion_can_recover_only_a_read_receipt_after_expiry() {
        let (connector, assignment, mut request, fence, now) = context();
        request.approval.expires_at = now;
        request.approval.delete_admitted = true;
        assert!(check(&request, &connector, &assignment, &fence, now, false).is_ok());
        assert!(check(&request, &connector, &assignment, &fence, now, true).is_err());
        request.approval.target = Some(Uuid::from_u128(99));
        assert!(check(&request, &connector, &assignment, &fence, now, false).is_err());
    }
    #[test]
    fn changed_source_revision_or_paused_connector_fences_lifecycle_admission() {
        let (mut connector, mut assignment, request, fence, now) = context();
        assert!(check(&request, &connector, &assignment, &fence, now, true).is_ok());
        assignment.desired_revision = Uuid::from_u128(98);
        assert!(check(&request, &connector, &assignment, &fence, now, true).is_err());
        assignment.desired_revision = request.desired_revision;
        connector.enabled = false;
        assert!(check(&request, &connector, &assignment, &fence, now, false).is_err());
    }
}
