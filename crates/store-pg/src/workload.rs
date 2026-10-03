//! Authoritative tenant workload trust and issuance fences.
use crate::error::to_domain_error;
use asterius_domain::workload::{
    Config, Keys, MAX_TRUSTS, Registry, Summary, Trust, Verified, valid_id,
};
use asterius_domain::{Actor, AuditEvent, Detail, DomainError, EventType, Outcome, TenantId};
use sqlx::{PgConnection, PgPool, Row as _};
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct PgWorkloadTrusts {
    pool: PgPool,
}
impl PgWorkloadTrusts {
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}
fn invalid() -> DomainError {
    DomainError::invalid("workload_trust", "invalid workload trust")
}
fn validated(
    tenant: &TenantId,
    id: &str,
    version: i64,
    value: serde_json::Value,
) -> Result<Trust, DomainError> {
    let config: Config = serde_json::from_value(value).map_err(|_| invalid())?;
    config.validate(tenant, id)?;
    if version <= 0 {
        return Err(invalid());
    }
    Ok(Trust {
        tenant: tenant.clone(),
        id: id.to_owned(),
        version,
        config,
    })
}
fn summary(trust: &Trust) -> Result<Summary, DomainError> {
    let fingerprints = match &trust.config.keys {
        Keys::Inline { jwks } => asterius_jose::workload::KeySet::parse(
            &serde_json::to_vec(jwks).map_err(|_| invalid())?,
            &trust.config.algorithms,
        )
        .map_err(|_| invalid())?
        .fingerprints()
        .to_vec(),
        Keys::Remote { .. } => Vec::new(),
    };
    Ok(trust.config.summary(&trust.id, trust.version, fingerprints))
}
async fn tenant_lock(connection: &mut PgConnection, tenant: &TenantId) -> Result<(), DomainError> {
    sqlx::query("select pg_advisory_xact_lock(hashtext($1),hashtext('workload-trusts'))")
        .bind(tenant.as_str())
        .execute(connection)
        .await
        .map_err(to_domain_error)?;
    Ok(())
}

#[async_trait::async_trait]
impl Registry for PgWorkloadTrusts {
    async fn candidates(&self, tenant: &TenantId, issuer: &str) -> Result<Vec<Trust>, DomainError> {
        let rows=sqlx::query("select trust_id,version,config from workload_trusts where tenant_id=$1 and config->>'issuer'=$2 order by trust_id limit 65")
            .bind(tenant.as_str()).bind(issuer).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        if rows.len() > MAX_TRUSTS {
            return Err(invalid());
        }
        rows.into_iter()
            .map(|row| {
                validated(
                    tenant,
                    &row.try_get::<String, _>("trust_id")
                        .map_err(to_domain_error)?,
                    row.try_get("version").map_err(to_domain_error)?,
                    row.try_get("config").map_err(to_domain_error)?,
                )
            })
            .collect()
    }
    async fn list(&self, tenant: &TenantId) -> Result<Vec<Summary>, DomainError> {
        let rows=sqlx::query("select trust_id,version,config from workload_trusts where tenant_id=$1 order by trust_id limit 65")
            .bind(tenant.as_str()).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        if rows.len() > MAX_TRUSTS {
            return Err(invalid());
        }
        rows.into_iter()
            .map(|row| {
                summary(&validated(
                    tenant,
                    &row.try_get::<String, _>("trust_id")
                        .map_err(to_domain_error)?,
                    row.try_get("version").map_err(to_domain_error)?,
                    row.try_get("config").map_err(to_domain_error)?,
                )?)
            })
            .collect()
    }
    async fn find(&self, tenant: &TenantId, id: &str) -> Result<Option<Summary>, DomainError> {
        if !valid_id(id) {
            return Err(invalid());
        }
        let row = sqlx::query(
            "select version,config from workload_trusts where tenant_id=$1 and trust_id=$2",
        )
        .bind(tenant.as_str())
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(|row| {
            summary(&validated(
                tenant,
                id,
                row.try_get("version").map_err(to_domain_error)?,
                row.try_get("config").map_err(to_domain_error)?,
            )?)
        })
        .transpose()
    }
    async fn put(
        &self,
        tenant: &TenantId,
        id: &str,
        config: &Config,
        expected: Option<i64>,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<Summary, DomainError> {
        config.validate(tenant, id)?;
        let value = serde_json::to_value(config).map_err(|_| invalid())?;
        // Revalidate public inline material before any live mutation.
        summary(&Trust {
            tenant: tenant.clone(),
            id: id.to_owned(),
            version: 1,
            config: config.clone(),
        })?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        tenant_lock(&mut tx, tenant).await?;
        let current: Option<i64> = sqlx::query_scalar(
            "select version from workload_trusts where tenant_id=$1 and trust_id=$2 for update",
        )
        .bind(tenant.as_str())
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if current != expected {
            return Err(DomainError::Conflict(
                "workload trust revision changed".to_owned(),
            ));
        }
        if current.is_none() {
            let count: i64 =
                sqlx::query_scalar("select count(*) from workload_trusts where tenant_id=$1")
                    .bind(tenant.as_str())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(to_domain_error)?;
            if usize::try_from(count).map_err(|_| invalid())? >= MAX_TRUSTS {
                return Err(invalid());
            }
        }
        let version:i64=sqlx::query_scalar("insert into workload_trusts(tenant_id,trust_id,config,created_at,updated_at) values($1,$2,$3,$4,$4) on conflict(tenant_id,trust_id) do update set config=excluded.config,version=nextval('workload_trust_versions'),updated_at=excluded.updated_at returning version")
            .bind(tenant.as_str()).bind(id).bind(value).bind(now).fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        let event = AuditEvent::new(
            tenant.clone(),
            EventType::WORKLOAD_TRUST_SAVED,
            Outcome::Success,
            actor,
            now,
        )
        .detail(
            Detail::new()
                .text("trust_id", id)
                .number("version", version)
                .label("enabled", if config.enabled { "true" } else { "false" }),
        );
        crate::audit::append(&mut tx, event).await?;
        tx.commit().await.map_err(to_domain_error)?;
        summary(&Trust {
            tenant: tenant.clone(),
            id: id.to_owned(),
            version,
            config: config.clone(),
        })
    }
    async fn delete(
        &self,
        tenant: &TenantId,
        id: &str,
        expected: i64,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if !valid_id(id) || expected <= 0 {
            return Err(invalid());
        }
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        tenant_lock(&mut tx, tenant).await?;
        let changed = sqlx::query(
            "delete from workload_trusts where tenant_id=$1 and trust_id=$2 and version=$3",
        )
        .bind(tenant.as_str())
        .bind(id)
        .bind(expected)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if changed.rows_affected() != 1 {
            return Err(DomainError::Conflict(
                "workload trust revision changed".to_owned(),
            ));
        }
        crate::audit::append(
            &mut tx,
            AuditEvent::new(
                tenant.clone(),
                EventType::WORKLOAD_TRUST_DELETED,
                Outcome::Success,
                actor,
                now,
            )
            .detail(
                Detail::new()
                    .text("trust_id", id)
                    .number("version", expected),
            ),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)
    }
}

/// This fence must be called within the same transaction that creates the child
/// grant. Verification alone cannot serialize issuance against trust disable.
pub async fn consume_on_connection(
    connection: &mut PgConnection,
    verified: &Verified,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    if verified.expires_at <= now {
        return Err(invalid());
    }
    let row = sqlx::query(
        "select version,config from workload_trusts where tenant_id=$1 and trust_id=$2 for update",
    )
    .bind(verified.tenant.as_str())
    .bind(&verified.trust_id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(to_domain_error)?
    .ok_or_else(invalid)?;
    let trust = validated(
        &verified.tenant,
        &verified.trust_id,
        row.try_get("version").map_err(to_domain_error)?,
        row.try_get("config").map_err(to_domain_error)?,
    )?;
    if !trust.config.enabled || trust.version != verified.trust_version {
        return Err(invalid());
    }
    let inserted=sqlx::query("insert into workload_assertion_consumptions(tenant_id,trust_id,digest,expires_at,consumed_at) values($1,$2,$3,$4,$5) on conflict do nothing")
        .bind(verified.tenant.as_str()).bind(&verified.trust_id).bind(verified.digest.as_slice()).bind(verified.expires_at).bind(now)
        .execute(connection).await.map_err(to_domain_error)?;
    if inserted.rows_affected() != 1 {
        return Err(invalid());
    }
    Ok(())
}
