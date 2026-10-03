//! Current-source projections and receipts fenced by the current claimed attempt.

use crate::error::to_domain_error;
use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::outbound_scim::{
    Assignment, Connector, CredentialBinding, DeliveryFence, FailureCode, GroupProjection,
    MappingReceipt, OutboundScimJobs, PreparedDelivery, Projection, ResourceKind, UserProjection,
    canonical_issuer,
};
use asterius_domain::{ClientId, DomainError, TenantId};
use sqlx::{PgConnection, PgPool, Row};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PgOutboundScimJobs {
    pool: PgPool,
}

impl PgOutboundScimJobs {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

async fn load(
    connection: &mut PgConnection,
    tenant: &TenantId,
    assignment_id: Uuid,
) -> Result<(Connector, Assignment), DomainError> {
    // Locate first without locking the child; every mutation locks its parent
    // before the assignment, including source-side transactional producers.
    let connector_id: Uuid = sqlx::query_scalar("select connector_id from outbound_scim_assignments where tenant_id=$1 and assignment_id=$2")
        .bind(tenant.as_str()).bind(assignment_id).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
    let row = sqlx::query("select * from outbound_scim_connectors where tenant_id=$1 and connector_id=$2 and removed_at is null for update")
        .bind(tenant.as_str()).bind(connector_id).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
    let target_issuer: String = row.try_get("target_issuer").map_err(to_domain_error)?;
    let issuer = canonical_issuer(&target_issuer)?;
    let target_client = ClientId::new(
        row.try_get::<String, _>("target_client")
            .map_err(to_domain_error)?,
    );
    let connector = Connector {
        tenant: tenant.clone(),
        id: connector_id,
        revision: row.try_get("revision").map_err(to_domain_error)?,
        target_issuer: target_issuer.clone(),
        target_client: target_client.clone(),
        enabled: row.try_get("enabled").map_err(to_domain_error)?,
        allow_reviewed_delete: row
            .try_get("allow_reviewed_delete")
            .map_err(to_domain_error)?,
        credential: CredentialBinding {
            reference: row.try_get("credential_ref").map_err(to_domain_error)?,
            generation: row
                .try_get("credential_generation")
                .map_err(to_domain_error)?,
            source_tenant: tenant.clone(),
            target_issuer: target_issuer.clone(),
            target_client,
            target_admin_resource: format!("{target_issuer}/admin/api/v1"),
            scim_origin: issuer.origin().ascii_serialization(),
        },
    };
    let row = sqlx::query("select * from outbound_scim_assignments where tenant_id=$1 and assignment_id=$2 and retired_at is null and state<>'deleted' for update")
        .bind(tenant.as_str()).bind(assignment_id).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
    let kind: String = row.try_get("kind").map_err(to_domain_error)?;
    let kind = match kind.as_str() {
        "user" => ResourceKind::User,
        "group" => ResourceKind::Group,
        _ => return Err(DomainError::Conflict("source_projection_invalid".into())),
    };
    let assignment = Assignment {
        id: assignment_id,
        connector: connector_id,
        kind,
        source: row.try_get("source_id").map_err(to_domain_error)?,
        generation: row.try_get("generation").map_err(to_domain_error)?,
        desired_revision: row.try_get("desired_revision").map_err(to_domain_error)?,
        immutable_alias: row.try_get("immutable_alias").map_err(to_domain_error)?,
        external_id: row.try_get("external_id").map_err(to_domain_error)?,
        selected: row.try_get("selected").map_err(to_domain_error)?,
        target: row.try_get("target_id").map_err(to_domain_error)?,
        observed_etag: row.try_get("observed_etag").map_err(to_domain_error)?,
        retired_at: row.try_get("retired_at").map_err(to_domain_error)?,
    };
    Ok((connector, assignment))
}

async fn lease_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    outbox_id: i64,
    attempt: u32,
    assignment: &Assignment,
) -> Result<(OffsetDateTime, OffsetDateTime), DomainError> {
    let row = sqlx::query("select claim_expires_at from outbox where tenant_id=$1 and outbox_id=$2 and attempts::bigint=$3 and status='claimed' and kind='outbound_scim.reconcile' and destination=$4 and payload->>'assignment'=$5 and payload->>'generation'=$6 for share")
        .bind(tenant.as_str()).bind(outbox_id).bind(i64::from(attempt))
        .bind(assignment.connector.to_string()).bind(assignment.id.to_string()).bind(assignment.generation.to_string())
        .fetch_optional(&mut *connection).await.map_err(to_domain_error)?
        .ok_or_else(|| DomainError::Conflict("lease_superseded".into()))?;
    let lease: Option<OffsetDateTime> = row.try_get("claim_expires_at").map_err(to_domain_error)?;
    // Separate statement AFTER row locking: a lock wait must not preserve a
    // pre-wait time and let a stale worker cross the receipt boundary.
    let now = sqlx::query_scalar::<_, OffsetDateTime>("select clock_timestamp()")
        .fetch_one(&mut *connection)
        .await
        .map_err(to_domain_error)?;
    let lease = lease
        .filter(|expiry| *expiry > now)
        .ok_or_else(|| DomainError::Conflict("lease_superseded".into()))?;
    Ok((now, lease))
}

async fn projection_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    assignment: &Assignment,
) -> Result<Projection, DomainError> {
    match assignment.kind {
        ResourceKind::User => {
            let protected: bool = sqlx::query_scalar("select exists(select 1 from scim_user_external_ids where tenant_id=$1 and user_id=$2)")
                .bind(tenant.as_str()).bind(assignment.source).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
            if protected {
                return Err(DomainError::Conflict("source_protected".into()));
            }
            let row =
                sqlx::query("select email,status from users where tenant_id=$1 and user_id=$2")
                    .bind(tenant.as_str())
                    .bind(assignment.source)
                    .fetch_optional(&mut *connection)
                    .await
                    .map_err(to_domain_error)?;
            let (work_email, active) = if let Some(row) = row {
                (
                    row.try_get("email").map_err(to_domain_error)?,
                    assignment.selected
                        && row
                            .try_get::<String, _>("status")
                            .map_err(to_domain_error)?
                            == "active",
                )
            } else {
                (None, false)
            };
            Ok(Projection::User(UserProjection {
                immutable_alias: assignment.immutable_alias.clone(),
                external_id: assignment.external_id.clone(),
                work_email,
                active,
            }))
        }
        ResourceKind::Group => {
            let protected: bool = sqlx::query_scalar(
                "select exists(select 1 from scim_group_owners where tenant_id=$1 and group_id=$2)",
            )
            .bind(tenant.as_str())
            .bind(assignment.source)
            .fetch_one(&mut *connection)
            .await
            .map_err(to_domain_error)?;
            if protected {
                return Err(DomainError::Conflict("source_protected".into()));
            }
            let rows = sqlx::query("select a.target_id from group_memberships m join users u using(tenant_id,user_id) join outbound_scim_assignments a on a.tenant_id=m.tenant_id and a.source_id=m.user_id and a.kind='user' and a.connector_id=$3 and a.selected and a.retired_at is null where m.tenant_id=$1 and m.group_id=$2 and u.status='active' and $4 order by m.user_id limit 101")
                .bind(tenant.as_str()).bind(assignment.source).bind(assignment.connector).bind(assignment.selected)
                .fetch_all(&mut *connection).await.map_err(to_domain_error)?;
            if rows.len() > 100 {
                return Err(DomainError::Conflict("snapshot_bound_exceeded".into()));
            }
            let mut target_members = Vec::with_capacity(rows.len());
            for row in rows {
                let target: Option<Uuid> = row.try_get("target_id").map_err(to_domain_error)?;
                target_members
                    .push(target.ok_or_else(|| {
                        DomainError::Conflict("user_dependencies_pending".into())
                    })?);
            }
            Ok(Projection::Group(GroupProjection {
                immutable_alias: assignment.immutable_alias.clone(),
                external_id: assignment.external_id.clone(),
                target_members,
            }))
        }
    }
}

#[async_trait::async_trait]
impl OutboundScimJobs for PgOutboundScimJobs {
    async fn prepare(
        &self,
        tenant: &TenantId,
        outbox_id: i64,
        attempt: u32,
        assignment_id: Uuid,
    ) -> Result<PreparedDelivery, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let (connector, assignment) = load(&mut transaction, tenant, assignment_id).await?;
        if !connector.enabled {
            return Err(DomainError::Conflict("paused".into()));
        }
        let (now, lease) =
            lease_on(&mut transaction, tenant, outbox_id, attempt, &assignment).await?;
        if lease - now < Duration::seconds(5) {
            return Err(DomainError::Conflict("lease_superseded".into()));
        }
        let projection = projection_on(&mut transaction, tenant, &assignment).await?;
        let fence = DeliveryFence {
            outbox_id,
            attempt,
            connector_revision: connector.revision,
            credential_generation: connector.credential.generation,
            assignment_generation: assignment.generation,
            desired_revision: assignment.desired_revision,
            deadline: lease.min(now + Duration::seconds(45)),
        };
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(PreparedDelivery {
            connector,
            assignment,
            fence,
            projection,
        })
    }

    async fn complete(
        &self,
        tenant: &TenantId,
        assignment_id: Uuid,
        fence: &DeliveryFence,
        receipt: &MappingReceipt,
    ) -> Result<(), DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let (connector, assignment) = load(&mut transaction, tenant, assignment_id).await?;
        let (now, _) = lease_on(
            &mut transaction,
            tenant,
            fence.outbox_id,
            fence.attempt,
            &assignment,
        )
        .await?;
        check_fence(&connector, &assignment, fence, now)?;
        if assignment
            .target
            .is_some_and(|target| target != receipt.target)
        {
            return Err(DomainError::Conflict("ownership_mismatch".into()));
        }
        if receipt.etag.is_empty() || receipt.etag.len() > 128 {
            return Err(DomainError::invalid(
                "etag",
                "invalid bounded target version",
            ));
        }
        sqlx::query("update outbound_scim_assignments set target_id=$3,observed_etag=$4,observed_at=$5,delivered_revision=case when desired_revision=$6 then $6 else delivered_revision end,dirty=desired_revision<>$6,state=case when desired_revision=$6 then 'applied' else 'pending' end,failure_code=null where tenant_id=$1 and assignment_id=$2")
            .bind(tenant.as_str()).bind(assignment_id).bind(receipt.target).bind(&receipt.etag).bind(now).bind(fence.desired_revision)
            .execute(&mut *transaction).await.map_err(to_domain_error)?;
        audit_delivery(
            &mut transaction,
            tenant,
            assignment_id,
            now,
            EventType::OUTBOUND_SCIM_DELIVERED,
            "applied",
        )
        .await?;
        recheck_deadline(&mut transaction, fence).await?;
        transaction.commit().await.map_err(to_domain_error)
    }

    async fn fail(
        &self,
        tenant: &TenantId,
        assignment_id: Uuid,
        fence: &DeliveryFence,
        code: FailureCode,
    ) -> Result<(), DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let (connector, assignment) = load(&mut transaction, tenant, assignment_id).await?;
        let (now, _) = lease_on(
            &mut transaction,
            tenant,
            fence.outbox_id,
            fence.attempt,
            &assignment,
        )
        .await?;
        check_fence(&connector, &assignment, fence, now)?;
        sqlx::query("update outbound_scim_assignments set failure_code=$3,state='conflict',dirty=true where tenant_id=$1 and assignment_id=$2")
            .bind(tenant.as_str()).bind(assignment_id).bind(code.as_str())
            .execute(&mut *transaction).await.map_err(to_domain_error)?;
        audit_delivery(
            &mut transaction,
            tenant,
            assignment_id,
            now,
            EventType::OUTBOUND_SCIM_REFUSED,
            code.as_str(),
        )
        .await?;
        recheck_deadline(&mut transaction, fence).await?;
        transaction.commit().await.map_err(to_domain_error)
    }
}

async fn recheck_deadline(
    connection: &mut PgConnection,
    fence: &DeliveryFence,
) -> Result<(), DomainError> {
    let now = sqlx::query_scalar::<_, OffsetDateTime>("select clock_timestamp()")
        .fetch_one(connection)
        .await
        .map_err(to_domain_error)?;
    if now >= fence.deadline {
        return Err(DomainError::Conflict("lease_superseded".into()));
    }
    Ok(())
}

async fn audit_delivery(
    connection: &mut PgConnection,
    tenant: &TenantId,
    assignment: Uuid,
    now: OffsetDateTime,
    event_type: EventType,
    result: &'static str,
) -> Result<(), DomainError> {
    crate::audit::append(
        connection,
        AuditEvent::new(
            tenant.clone(),
            event_type,
            Outcome::Success,
            Actor::System,
            now,
        )
        .subject(assignment.to_string())
        .detail(Detail::new().label("result", result)),
    )
    .await
}

fn check_fence(
    connector: &Connector,
    assignment: &Assignment,
    fence: &DeliveryFence,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    if !connector.enabled
        || connector.revision != fence.connector_revision
        || connector.credential.generation != fence.credential_generation
        || assignment.generation != fence.assignment_generation
        || now >= fence.deadline
    {
        return Err(DomainError::Conflict("lease_superseded".into()));
    }
    Ok(())
}
