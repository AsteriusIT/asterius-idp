//! Exact tenant/application classification with an incarnation-safe CAS revision.
use asterius_domain::policy::conditional::{ClientSettings, ConditionalSettings, Sensitivity};
use asterius_domain::{ClientId, DomainError, TenantId};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PgConditionalSettings {
    pool: PgPool,
}

impl PgConditionalSettings {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn settings(row: (Option<String>, Uuid)) -> Result<ClientSettings, DomainError> {
    let sensitivity = row
        .0
        .map(|value| {
            serde_json::from_value(serde_json::Value::String(value)).map_err(|_| {
                DomainError::invalid(
                    "conditional.sensitivity",
                    "stored classification is invalid",
                )
            })
        })
        .transpose()?;
    Ok(ClientSettings {
        sensitivity,
        revision: row.1,
    })
}

#[async_trait::async_trait]
impl ConditionalSettings for PgConditionalSettings {
    async fn read(
        &self,
        tenant: &TenantId,
        client: &ClientId,
    ) -> Result<Option<ClientSettings>, DomainError> {
        let row: Option<(Option<String>, Uuid)> = sqlx::query_as("select sensitivity, revision from conditional_client_settings where tenant_id = $1 and client_id = $2")
            .bind(tenant.as_str()).bind(client.as_str()).fetch_optional(&self.pool).await.map_err(crate::error::to_domain_error)?;
        row.map(settings).transpose()
    }

    async fn replace(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        sensitivity: Option<Sensitivity>,
        expected: Option<Uuid>,
    ) -> Result<ClientSettings, DomainError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(crate::error::to_domain_error)?;
        let exists: Option<(String,)> = sqlx::query_as(
            "select client_id from clients where tenant_id = $1 and client_id = $2 for update",
        )
        .bind(tenant.as_str())
        .bind(client.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(crate::error::to_domain_error)?;
        if exists.is_none() {
            return Err(DomainError::Conflict("no such client".to_owned()));
        }
        let revision = Uuid::new_v4();
        let row: Option<(Option<String>, Uuid)> = if let Some(expected) = expected {
            sqlx::query_as("update conditional_client_settings set sensitivity = $3, revision = $4 where tenant_id = $1 and client_id = $2 and revision = $5 returning sensitivity, revision")
                .bind(tenant.as_str()).bind(client.as_str()).bind(sensitivity.map(Sensitivity::as_str)).bind(revision).bind(expected).fetch_optional(&mut *tx).await.map_err(crate::error::to_domain_error)?
        } else {
            sqlx::query_as("insert into conditional_client_settings(tenant_id, client_id, sensitivity, revision) values ($1,$2,$3,$4) on conflict(tenant_id,client_id) do nothing returning sensitivity, revision")
                .bind(tenant.as_str()).bind(client.as_str()).bind(sensitivity.map(Sensitivity::as_str)).bind(revision).fetch_optional(&mut *tx).await.map_err(crate::error::to_domain_error)?
        };
        let row = row.ok_or_else(|| {
            DomainError::Conflict("conditional classification revision changed".to_owned())
        })?;
        tx.commit().await.map_err(crate::error::to_domain_error)?;
        settings(row)
    }
}
