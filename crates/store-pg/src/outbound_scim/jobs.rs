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

pub(super) async fn load(
    connection: &mut PgConnection,
    tenant: &TenantId,
    assignment_id: Uuid,
) -> Result<(Connector, Assignment), DomainError> {
    load_history(connection, tenant, assignment_id, false).await
}

pub(super) async fn load_history(
    connection: &mut PgConnection,
    tenant: &TenantId,
    assignment_id: Uuid,
    historical: bool,
) -> Result<(Connector, Assignment), DomainError> {
    sqlx::query("select tenant_id from tenants where tenant_id=$1 for share")
        .bind(tenant.as_str())
        .fetch_one(&mut *connection)
        .await
        .map_err(to_domain_error)?;
    // Locate first without locking the child; every mutation locks its parent
    // before the assignment, including source-side transactional producers.
    let connector_id: Uuid = sqlx::query_scalar("select connector_id from outbound_scim_assignments where tenant_id=$1 and assignment_id=$2")
        .bind(tenant.as_str()).bind(assignment_id).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
    let row = sqlx::query("select * from outbound_scim_connectors where tenant_id=$1 and connector_id=$2 and removed_at is null for update")
        .bind(tenant.as_str()).bind(connector_id).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
    let target_issuer: String = row.try_get("target_issuer").map_err(to_domain_error)?;
    let issuer = canonical_issuer(&target_issuer)?;
    let source_issuer: String = sqlx::query_scalar("select issuer from tenants where tenant_id=$1")
        .bind(tenant.as_str())
        .fetch_one(&mut *connection)
        .await
        .map_err(to_domain_error)?;
    if source_issuer == target_issuer {
        return Err(DomainError::Conflict("source_projection_invalid".into()));
    }
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
    let row = sqlx::query("select * from outbound_scim_assignments where tenant_id=$1 and assignment_id=$2 and ($3 or (retired_at is null and state<>'deleted')) for update")
        .bind(tenant.as_str()).bind(assignment_id).bind(historical).fetch_one(&mut *connection).await.map_err(to_domain_error)?;
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
        creation_admitted: row.try_get("creation_admitted").map_err(to_domain_error)?,
        retired_at: row.try_get("retired_at").map_err(to_domain_error)?,
    };
    Ok((connector, assignment))
}

pub(super) async fn lease_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    outbox_id: i64,
    attempt: u32,
    assignment: &Assignment,
    kind: &str,
) -> Result<(OffsetDateTime, OffsetDateTime), DomainError> {
    let row = sqlx::query("select claim_expires_at from outbox where tenant_id=$1 and outbox_id=$2 and attempts::bigint=$3 and status='claimed' and kind=$7 and destination=$4 and payload->>'assignment'=$5 and payload->>'generation'=$6 for share")
        .bind(tenant.as_str()).bind(outbox_id).bind(i64::from(attempt))
        .bind(assignment.connector.to_string()).bind(assignment.id.to_string()).bind(assignment.generation.to_string()).bind(kind)
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

pub(super) async fn projection_on(
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
            let source_exists = row.is_some();
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
                source_exists,
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
            let source_exists: bool = sqlx::query_scalar(
                "select exists(select 1 from managed_groups where tenant_id=$1 and group_id=$2)",
            )
            .bind(tenant.as_str())
            .bind(assignment.source)
            .fetch_one(&mut *connection)
            .await
            .map_err(to_domain_error)?;
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
                source_exists,
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
        let (now, lease) = lease_on(
            &mut transaction,
            tenant,
            outbox_id,
            attempt,
            &assignment,
            "outbound_scim.reconcile",
        )
        .await?;
        if lease - now < Duration::seconds(5) {
            return Err(DomainError::Conflict("lease_superseded".into()));
        }
        let fence = DeliveryFence {
            outbox_id,
            attempt,
            connector_revision: connector.revision,
            credential_generation: connector.credential.generation,
            assignment_generation: assignment.generation,
            desired_revision: assignment.desired_revision,
            deadline: lease.min(now + Duration::seconds(45)),
        };
        let projection = match projection_on(&mut transaction, tenant, &assignment).await {
            Ok(projection) => projection,
            Err(DomainError::Conflict(code)) if code == "user_dependencies_pending" => {
                let dependencies = sqlx::query_scalar::<_,Uuid>("select a.assignment_id from group_memberships m join users u using(tenant_id,user_id) join outbound_scim_assignments a on a.tenant_id=m.tenant_id and a.source_id=m.user_id and a.kind='user' and a.connector_id=$3 and a.selected and a.retired_at is null where m.tenant_id=$1 and m.group_id=$2 and u.status='active' and a.target_id is null order by a.assignment_id limit 101")
                    .bind(tenant.as_str()).bind(assignment.source).bind(assignment.connector)
                    .fetch_all(&mut *transaction).await.map_err(to_domain_error)?;
                if dependencies.len() > 100 {
                    return Err(DomainError::Conflict("snapshot_bound_exceeded".into()));
                }
                for dependency in dependencies {
                    sqlx::query("select outbound_scim_enqueue_assignment($1,$2)")
                        .bind(tenant.as_str())
                        .bind(dependency)
                        .execute(&mut *transaction)
                        .await
                        .map_err(to_domain_error)?;
                }
                sqlx::query("update outbound_scim_assignments set state='waiting_dependencies',failure_code='user_dependencies_pending',dirty=true where tenant_id=$1 and assignment_id=$2")
                    .bind(tenant.as_str()).bind(assignment_id).execute(&mut *transaction).await.map_err(to_domain_error)?;
                audit_delivery(
                    &mut transaction,
                    tenant,
                    assignment_id,
                    now,
                    EventType::OUTBOUND_SCIM_REFUSED,
                    "user_dependencies_pending",
                )
                .await?;
                recheck_deadline(&mut transaction, &fence).await?;
                transaction.commit().await.map_err(to_domain_error)?;
                return Err(DomainError::Conflict(code));
            }
            Err(error) => return Err(error),
        };
        recheck_deadline(&mut transaction, &fence).await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(PreparedDelivery {
            connector,
            assignment,
            fence,
            projection,
        })
    }

    async fn admit(
        &self,
        tenant: &TenantId,
        assignment_id: Uuid,
        fence: &DeliveryFence,
        creating: bool,
    ) -> Result<(), DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let (connector, assignment) = load(&mut transaction, tenant, assignment_id).await?;
        let (now, _) = lease_on(
            &mut transaction,
            tenant,
            fence.outbox_id,
            fence.attempt,
            &assignment,
            "outbound_scim.reconcile",
        )
        .await?;
        check_fence(&connector, &assignment, fence, now)?;
        if assignment.desired_revision != fence.desired_revision {
            return Err(DomainError::Conflict("lease_superseded".into()));
        }
        if creating {
            sqlx::query("update outbound_scim_assignments set creation_admitted=true where tenant_id=$1 and assignment_id=$2")
                .bind(tenant.as_str()).bind(assignment_id).execute(&mut *transaction).await.map_err(to_domain_error)?;
        }
        // Revalidate protected provenance as well as the producer revision.
        projection_on(&mut transaction, tenant, &assignment).await?;
        let now: OffsetDateTime = sqlx::query_scalar("select clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(to_domain_error)?;
        check_fence(&connector, &assignment, fence, now)?;
        transaction.commit().await.map_err(to_domain_error)
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
            "outbound_scim.reconcile",
        )
        .await?;
        check_fence(&connector, &assignment, fence, now)?;
        if assignment
            .target
            .is_some_and(|target| Some(target) != receipt.target)
        {
            return Err(DomainError::Conflict("ownership_mismatch".into()));
        }
        if receipt.target.is_some() != receipt.etag.is_some() {
            return Err(DomainError::invalid(
                "receipt",
                "target and version must agree",
            ));
        }
        if let Some(etag) = &receipt.etag {
            asterius_domain::outbound_scim::target_etag(etag)?;
        }
        if receipt.target.is_none() {
            if assignment.creation_admitted {
                return Err(DomainError::Conflict("lease_superseded".into()));
            }
            let current = projection_on(&mut transaction, tenant, &assignment).await?;
            let source_exists = match current {
                Projection::User(user) => user.source_exists,
                Projection::Group(group) => group.source_exists,
            };
            if assignment.selected && source_exists {
                return Err(DomainError::Conflict("source_projection_invalid".into()));
            }
        }
        if receipt
            .etag
            .as_ref()
            .is_some_and(|etag| etag.is_empty() || etag.len() > 128)
        {
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
            if receipt.target.is_some() {
                "applied"
            } else {
                "absent"
            },
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
            "outbound_scim.reconcile",
        )
        .await?;
        check_fence(&connector, &assignment, fence, now)?;
        sqlx::query("update outbound_scim_assignments set failure_code=$3,state=case when $3='paused' then 'paused' when $3='user_dependencies_pending' then 'waiting_dependencies' when $3 in ('target_unavailable','lease_superseded') then 'pending' else 'conflict' end,dirty=true where tenant_id=$1 and assignment_id=$2")
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

pub(super) async fn recheck_deadline(
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

pub(super) async fn audit_delivery(
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

pub(super) fn check_fence(
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
