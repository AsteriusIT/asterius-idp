//! Current human authority, connector revision CAS, durable selections and previews.

use crate::error::to_domain_error;
use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::outbound_scim::{
    AssignmentView, ConfigureConnector, Connector, ConnectorView, CredentialBinding,
    OutboundScimAdministration, OutboundScimCredentialCatalogue, PreviewSelection, ResourceKind,
    SelectSources, canonical_issuer, resource_identity,
};
use asterius_domain::{ClientId, DomainError, TenantId, UserId};
use sqlx::{PgConnection, PgPool, Row};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PgOutboundScimAdministration {
    pool: PgPool,
    credentials: Arc<dyn OutboundScimCredentialCatalogue>,
}
impl PgOutboundScimAdministration {
    #[must_use]
    pub fn new(pool: PgPool, credentials: Arc<dyn OutboundScimCredentialCatalogue>) -> Self {
        Self { pool, credentials }
    }
}
fn page(limit: u16) -> Result<i64, DomainError> {
    if limit == 0 || limit > 100 {
        return Err(DomainError::invalid(
            "limit",
            "one to one hundred is required",
        ));
    }
    Ok(i64::from(limit))
}
async fn clock(connection: &mut PgConnection) -> Result<OffsetDateTime, DomainError> {
    sqlx::query_scalar("select clock_timestamp()")
        .fetch_one(connection)
        .await
        .map_err(to_domain_error)
}
async fn actor_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    actor: UserId,
) -> Result<(), DomainError> {
    let held:Option<Uuid>=sqlx::query_scalar("select u.user_id from tenants t join users u using(tenant_id) join user_roles r using(tenant_id,user_id) where t.tenant_id=$1 and t.status='active' and u.user_id=$2 and u.status='active' and r.role='tenant_admin' for share of t,u,r")
        .bind(tenant.as_str()).bind(actor.as_uuid()).fetch_optional(connection).await.map_err(to_domain_error)?;
    if held.is_none() {
        return Err(DomainError::Conflict(
            "current active tenant administrator is required".into(),
        ));
    }
    Ok(())
}
async fn evidence(
    connection: &mut PgConnection,
    tenant: &TenantId,
    actor: UserId,
    id: Uuid,
    operation: &'static str,
) -> Result<(), DomainError> {
    let now = clock(connection).await?;
    crate::audit::append(
        connection,
        AuditEvent::new(
            tenant.clone(),
            EventType::ADMIN_CHANGED,
            Outcome::Success,
            Actor::Admin(actor.to_string()),
            now,
        )
        .subject(id.to_string())
        .detail(Detail::new().label("operation", operation)),
    )
    .await
}
async fn connector_on(
    connection: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
) -> Result<Connector, DomainError> {
    let row=sqlx::query("select * from outbound_scim_connectors where tenant_id=$1 and connector_id=$2 and removed_at is null for update")
        .bind(tenant.as_str()).bind(id).fetch_one(connection).await.map_err(to_domain_error)?;
    let issuer: String = row.try_get("target_issuer").map_err(to_domain_error)?;
    let parsed = canonical_issuer(&issuer)?;
    let client = ClientId::new(
        row.try_get::<String, _>("target_client")
            .map_err(to_domain_error)?,
    );
    Ok(Connector {
        tenant: tenant.clone(),
        id,
        revision: row.try_get("revision").map_err(to_domain_error)?,
        target_issuer: issuer.clone(),
        target_client: client.clone(),
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
            target_admin_resource: format!("{issuer}/admin/api/v1"),
            scim_origin: parsed.origin().ascii_serialization(),
            target_issuer: issuer,
            target_client: client,
        },
    })
}
fn assignment_view(row: &sqlx::postgres::PgRow) -> Result<AssignmentView, DomainError> {
    Ok(AssignmentView {
        id: row.try_get("assignment_id").map_err(to_domain_error)?,
        kind: row.try_get("kind").map_err(to_domain_error)?,
        source: row.try_get("source_id").map_err(to_domain_error)?,
        generation: row.try_get("generation").map_err(to_domain_error)?,
        selected: row.try_get("selected").map_err(to_domain_error)?,
        target: row.try_get("target_id").map_err(to_domain_error)?,
        state: row.try_get("state").map_err(to_domain_error)?,
        failure_code: row.try_get("failure_code").map_err(to_domain_error)?,
        dirty: row.try_get("dirty").map_err(to_domain_error)?,
    })
}
async fn expected(
    connection: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
    revision: Uuid,
) -> Result<Connector, DomainError> {
    let connector = connector_on(connection, tenant, id).await?;
    if connector.revision != revision {
        return Err(DomainError::Conflict("connector revision changed".into()));
    }
    Ok(connector)
}
async fn advance(
    connection: &mut PgConnection,
    tenant: &TenantId,
    id: Uuid,
) -> Result<(), DomainError> {
    sqlx::query("update outbound_scim_connectors set updated_at=clock_timestamp() where tenant_id=$1 and connector_id=$2")
        .bind(tenant.as_str()).bind(id).execute(connection).await.map_err(to_domain_error)?;
    Ok(())
}
async fn queue(
    connection: &mut PgConnection,
    tenant: &TenantId,
    assignment: Uuid,
) -> Result<(), DomainError> {
    sqlx::query("select outbound_scim_enqueue_assignment($1,$2)")
        .bind(tenant.as_str())
        .bind(assignment)
        .execute(connection)
        .await
        .map_err(to_domain_error)?;
    Ok(())
}

#[async_trait::async_trait]
impl OutboundScimAdministration for PgOutboundScimAdministration {
    async fn list(
        &self,
        tenant: &TenantId,
        after: Option<Uuid>,
        limit: u16,
    ) -> Result<Vec<ConnectorView>, DomainError> {
        let ids=sqlx::query_scalar::<_,Uuid>("select connector_id from outbound_scim_connectors where tenant_id=$1 and removed_at is null and ($2::uuid is null or connector_id>$2) order by connector_id limit $3")
            .bind(tenant.as_str()).bind(after).bind(page(limit)?).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let mut items = Vec::with_capacity(ids.len());
        for id in ids {
            items.push(connector_on(&mut transaction, tenant, id).await?.into());
        }
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(items)
    }
    async fn configure(
        &self,
        tenant: &TenantId,
        actor: UserId,
        command: ConfigureConnector,
    ) -> Result<ConnectorView, DomainError> {
        let binding = command.binding(tenant)?;
        if !self.credentials.available(&binding) {
            return Err(DomainError::Conflict("credential_binding_mismatch".into()));
        }
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        actor_on(&mut transaction, tenant, actor).await?;
        let source: String = sqlx::query_scalar("select issuer from tenants where tenant_id=$1")
            .bind(tenant.as_str())
            .fetch_one(&mut *transaction)
            .await
            .map_err(to_domain_error)?;
        if source == command.target_issuer {
            return Err(DomainError::invalid(
                "target_issuer",
                "source and target issuers must differ",
            ));
        }
        let mut activation_deadline = None;
        if let Some(revision) = command.expected_revision {
            let current = expected(&mut transaction, tenant, command.id, revision).await?;
            if command.enabled && (!current.enabled || binding != current.credential) {
                let preview:Option<OffsetDateTime>=sqlx::query_scalar("select expires_at from outbound_scim_previews where tenant_id=$1 and connector_id=$2 and connector_revision=$3 and credential_generation=$4 and expires_at>clock_timestamp()")
                    .bind(tenant.as_str()).bind(command.id).bind(revision).bind(binding.generation).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
                if preview.is_none() || binding != current.credential {
                    return Err(DomainError::Conflict(
                        "fresh read-only preview of this configuration is required".into(),
                    ));
                }
                activation_deadline = preview;
            }
            sqlx::query("update outbound_scim_connectors set target_issuer=$3,target_client=$4,credential_ref=$5,credential_generation=$6,enabled=$7,allow_reviewed_delete=$8 where tenant_id=$1 and connector_id=$2")
                .bind(tenant.as_str()).bind(command.id).bind(&command.target_issuer).bind(&command.target_client).bind(&command.credential_ref).bind(command.credential_generation).bind(command.enabled).bind(command.allow_reviewed_delete)
                .execute(&mut *transaction).await.map_err(to_domain_error)?;
        } else {
            if command.enabled {
                return Err(DomainError::invalid(
                    "enabled",
                    "create disabled, preview, then enable",
                ));
            }
            sqlx::query("insert into outbound_scim_connectors(tenant_id,connector_id,target_issuer,target_client,credential_ref,credential_generation,enabled,allow_reviewed_delete) values($1,$2,$3,$4,$5,$6,false,$7)")
                .bind(tenant.as_str()).bind(command.id).bind(&command.target_issuer).bind(&command.target_client).bind(&command.credential_ref).bind(command.credential_generation).bind(command.allow_reviewed_delete)
                .execute(&mut *transaction).await.map_err(to_domain_error)?;
        }
        // Resuming/rotating invalidates claimed context and creates fresh work
        // for every current selection, bounded by the catalogue's two limits.
        if command.enabled {
            let ids=sqlx::query_scalar::<_,Uuid>("select assignment_id from outbound_scim_assignments where tenant_id=$1 and connector_id=$2 and retired_at is null and state<>'deleted' order by assignment_id limit 201")
                .bind(tenant.as_str()).bind(command.id).fetch_all(&mut *transaction).await.map_err(to_domain_error)?;
            if ids.len() > 200 {
                return Err(DomainError::Conflict("snapshot_bound_exceeded".into()));
            }
            for id in ids {
                queue(&mut transaction, tenant, id).await?;
            }
        }
        evidence(
            &mut transaction,
            tenant,
            actor,
            command.id,
            "outbound_scim.configure",
        )
        .await?;
        if let Some(deadline) = activation_deadline {
            if clock(&mut transaction).await? >= deadline {
                return Err(DomainError::Conflict(
                    "read-only preview expired before activation".into(),
                ));
            }
        }
        let result = connector_on(&mut transaction, tenant, command.id)
            .await?
            .into();
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
    async fn assignments(
        &self,
        tenant: &TenantId,
        connector: Uuid,
        after: Option<Uuid>,
        limit: u16,
    ) -> Result<Vec<AssignmentView>, DomainError> {
        let rows=sqlx::query("select * from outbound_scim_assignments where tenant_id=$1 and connector_id=$2 and ($3::uuid is null or assignment_id>$3) order by assignment_id limit $4")
            .bind(tenant.as_str()).bind(connector).bind(after).bind(page(limit)?).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        rows.iter().map(assignment_view).collect()
    }
    async fn select(
        &self,
        tenant: &TenantId,
        actor: UserId,
        connector: Uuid,
        command: SelectSources,
    ) -> Result<Vec<AssignmentView>, DomainError> {
        let kind = command.kind()?;
        let kind = match kind {
            ResourceKind::User => "user",
            ResourceKind::Group => "group",
        };
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        actor_on(&mut transaction, tenant, actor).await?;
        expected(
            &mut transaction,
            tenant,
            connector,
            command.expected_revision,
        )
        .await?;
        let mut sources = command.sources;
        sources.sort_unstable();
        let mut result = Vec::with_capacity(sources.len());
        for source in sources {
            let local:bool=if kind=="user" { sqlx::query_scalar("select exists(select 1 from users where tenant_id=$1 and user_id=$2) and not exists(select 1 from scim_user_external_ids where tenant_id=$1 and user_id=$2)") }
                else { sqlx::query_scalar("select exists(select 1 from managed_groups where tenant_id=$1 and group_id=$2) and not exists(select 1 from scim_group_owners where tenant_id=$1 and group_id=$2)") }
                .bind(tenant.as_str()).bind(source).fetch_one(&mut *transaction).await.map_err(to_domain_error)?;
            if !local {
                return Err(DomainError::Conflict("source_protected".into()));
            }
            let existing=sqlx::query_scalar::<_,Uuid>("select assignment_id from outbound_scim_assignments where tenant_id=$1 and connector_id=$2 and kind=$3 and source_id=$4 and retired_at is null for update")
                .bind(tenant.as_str()).bind(connector).bind(kind).bind(source).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
            let id = if let Some(id) = existing {
                sqlx::query("update outbound_scim_assignments set selected=true where tenant_id=$1 and assignment_id=$2 and state<>'deleted'").bind(tenant.as_str()).bind(id).execute(&mut *transaction).await.map_err(to_domain_error)?;
                id
            } else {
                let retained:bool=sqlx::query_scalar("select exists(select 1 from outbound_scim_assignments where tenant_id=$1 and connector_id=$2 and kind=$3 and source_id=$4)")
                    .bind(tenant.as_str()).bind(connector).bind(kind).bind(source).fetch_one(&mut *transaction).await.map_err(to_domain_error)?;
                if retained {
                    return Err(DomainError::Conflict(
                        "explicit recreate is required for a retained incarnation".into(),
                    ));
                }
                let id = Uuid::new_v4();
                let generation = Uuid::new_v4();
                let (alias, external) = resource_identity(tenant, connector, source, generation);
                sqlx::query("insert into outbound_scim_assignments(tenant_id,connector_id,assignment_id,kind,source_id,generation,immutable_alias,external_id) values($1,$2,$3,$4,$5,$6,$7,$8)")
                    .bind(tenant.as_str()).bind(connector).bind(id).bind(kind).bind(source).bind(generation).bind(alias).bind(external).execute(&mut *transaction).await.map_err(to_domain_error)?;
                id
            };
            queue(&mut transaction, tenant, id).await?;
            let row = sqlx::query(
                "select * from outbound_scim_assignments where tenant_id=$1 and assignment_id=$2",
            )
            .bind(tenant.as_str())
            .bind(id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(to_domain_error)?;
            result.push(assignment_view(&row)?);
        }
        advance(&mut transaction, tenant, connector).await?;
        evidence(
            &mut transaction,
            tenant,
            actor,
            connector,
            "outbound_scim.select",
        )
        .await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
    async fn unselect(
        &self,
        tenant: &TenantId,
        actor: UserId,
        connector: Uuid,
        assignment: Uuid,
        revision: Uuid,
    ) -> Result<(), DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        actor_on(&mut transaction, tenant, actor).await?;
        expected(&mut transaction, tenant, connector, revision).await?;
        let changed=sqlx::query("update outbound_scim_assignments set selected=false where tenant_id=$1 and connector_id=$2 and assignment_id=$3 and retired_at is null and state<>'deleted'")
            .bind(tenant.as_str()).bind(connector).bind(assignment).execute(&mut *transaction).await.map_err(to_domain_error)?;
        if changed.rows_affected() != 1 {
            return Err(DomainError::NotFound);
        }
        queue(&mut transaction, tenant, assignment).await?;
        advance(&mut transaction, tenant, connector).await?;
        evidence(
            &mut transaction,
            tenant,
            actor,
            assignment,
            "outbound_scim.unselect",
        )
        .await?;
        transaction.commit().await.map_err(to_domain_error)
    }
    async fn reconcile(
        &self,
        tenant: &TenantId,
        actor: UserId,
        connector: Uuid,
        revision: Uuid,
        after: Option<Uuid>,
    ) -> Result<Option<Uuid>, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        actor_on(&mut transaction, tenant, actor).await?;
        let current = expected(&mut transaction, tenant, connector, revision).await?;
        if !current.enabled {
            return Err(DomainError::Conflict("paused".into()));
        }
        let mut ids=sqlx::query_scalar::<_,Uuid>("select assignment_id from outbound_scim_assignments where tenant_id=$1 and connector_id=$2 and retired_at is null and state<>'deleted' and ($3::uuid is null or assignment_id>$3) order by assignment_id limit 26")
            .bind(tenant.as_str()).bind(connector).bind(after).fetch_all(&mut *transaction).await.map_err(to_domain_error)?;
        let more = ids.len() > 25;
        ids.truncate(25);
        let next = more.then(|| ids.last().copied()).flatten();
        for id in ids {
            queue(&mut transaction, tenant, id).await?;
        }
        evidence(
            &mut transaction,
            tenant,
            actor,
            connector,
            "outbound_scim.reconcile",
        )
        .await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(next)
    }
    async fn preview_connector(
        &self,
        tenant: &TenantId,
        connector: Uuid,
        revision: Uuid,
    ) -> Result<Connector, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let result = expected(&mut transaction, tenant, connector, revision).await?;
        if !self.credentials.available(&result.credential) {
            return Err(DomainError::Conflict("credential_binding_mismatch".into()));
        }
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(result)
    }
    async fn preview_selection(
        &self,
        tenant: &TenantId,
        connector: Uuid,
        assignment: Uuid,
        revision: Uuid,
    ) -> Result<PreviewSelection, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let (current, assignment) = super::jobs::load(&mut transaction, tenant, assignment).await?;
        if current.id != connector || current.revision != revision {
            return Err(DomainError::Conflict("connector revision changed".into()));
        }
        let projection = super::jobs::projection_on(&mut transaction, tenant, &assignment).await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(PreviewSelection {
            connector: current,
            assignment,
            projection,
        })
    }
    async fn record_preview(
        &self,
        tenant: &TenantId,
        actor: UserId,
        connector: Uuid,
        revision: Uuid,
    ) -> Result<(), DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        actor_on(&mut transaction, tenant, actor).await?;
        let current = expected(&mut transaction, tenant, connector, revision).await?;
        if !self.credentials.available(&current.credential) {
            return Err(DomainError::Conflict("credential_binding_mismatch".into()));
        }
        let now = clock(&mut transaction).await?;
        sqlx::query("insert into outbound_scim_previews(tenant_id,connector_id,connector_revision,credential_generation,previewed_by,previewed_at,expires_at) values($1,$2,$3,$4,$5,$6,$6+interval '5 minutes') on conflict(tenant_id,connector_id,connector_revision,credential_generation) do update set previewed_by=excluded.previewed_by,previewed_at=excluded.previewed_at,expires_at=excluded.expires_at")
            .bind(tenant.as_str()).bind(connector).bind(revision).bind(current.credential.generation).bind(actor.as_uuid()).bind(now).execute(&mut *transaction).await.map_err(to_domain_error)?;
        evidence(
            &mut transaction,
            tenant,
            actor,
            connector,
            "outbound_scim.preview",
        )
        .await?;
        transaction.commit().await.map_err(to_domain_error)
    }
}
