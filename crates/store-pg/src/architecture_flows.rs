//! Tenant-bound persistence for architecture drafts.

use asterius_domain::{DomainError, TenantId};
use serde_json::{Value, json};
use sqlx::{FromRow, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::to_domain_error;

#[derive(Debug, Clone)]
pub struct PgArchitectureFlows {
    pool: PgPool,
}

#[derive(FromRow)]
struct FlowRow {
    flow_id: Uuid,
    name: String,
    graph: Value,
    revision: i64,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl FlowRow {
    fn document(self) -> Value {
        json!({
            "id": self.flow_id,
            "name": self.name,
            "graph": self.graph,
            "revision": self.revision,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
    }
}

impl PgArchitectureFlows {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list(&self, tenant: &TenantId) -> Result<Vec<Value>, DomainError> {
        let rows: Vec<FlowRow> = sqlx::query_as(
            "select flow_id, name, graph, revision, created_at, updated_at from architecture_flows
             where tenant_id = $1 order by updated_at desc, flow_id limit 100",
        )
        .bind(tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(rows.into_iter().map(FlowRow::document).collect())
    }

    pub async fn read(&self, tenant: &TenantId, id: Uuid) -> Result<Value, DomainError> {
        let row: FlowRow = sqlx::query_as(
            "select flow_id, name, graph, revision, created_at, updated_at from architecture_flows
             where tenant_id = $1 and flow_id = $2",
        )
        .bind(tenant.as_str())
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(row.document())
    }

    pub async fn create(
        &self,
        tenant: &TenantId,
        id: Uuid,
        name: &str,
        graph: Value,
        now: OffsetDateTime,
    ) -> Result<Value, DomainError> {
        let row: FlowRow = sqlx::query_as(
            "insert into architecture_flows (tenant_id, flow_id, name, graph, created_at, updated_at)
             values ($1, $2, $3, $4, $5, $5)
             returning flow_id, name, graph, revision, created_at, updated_at"
        ).bind(tenant.as_str()).bind(id).bind(name).bind(graph).bind(now)
            .fetch_one(&self.pool).await.map_err(to_domain_error)?;
        Ok(row.document())
    }

    pub async fn update(
        &self,
        tenant: &TenantId,
        id: Uuid,
        revision: i64,
        name: &str,
        graph: Value,
        now: OffsetDateTime,
    ) -> Result<Value, DomainError> {
        let row: Option<FlowRow> = sqlx::query_as(
            "update architecture_flows set name = $4, graph = $5, revision = revision + 1, updated_at = $6
             where tenant_id = $1 and flow_id = $2 and revision = $3
             returning flow_id, name, graph, revision, created_at, updated_at"
        ).bind(tenant.as_str()).bind(id).bind(revision).bind(name).bind(graph).bind(now)
            .fetch_optional(&self.pool).await.map_err(to_domain_error)?;
        match row {
            Some(row) => Ok(row.document()),
            None => match self.read(tenant, id).await {
                Ok(_) => Err(DomainError::Conflict(
                    "flow revision changed; reload before saving".into(),
                )),
                Err(error) => Err(error),
            },
        }
    }
}
