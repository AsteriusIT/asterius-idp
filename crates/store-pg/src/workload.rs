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
impl PgWorkloadTrusts {
    /// Consume the assertion, persist its child and provenance, and append
    /// issuance audit atomically. A signing failure requires a fresh assertion.
    pub async fn issue(
        &self,
        verified: &Verified,
        grant: &asterius_domain::Grant,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.issue_with_audit(
            verified,
            grant,
            now,
            &crate::PgAuditSink::new(self.pool.clone()),
        )
        .await
    }

    /// Preserve the request's trusted audit metadata inside the issuance transaction.
    pub async fn issue_with_audit(
        &self,
        verified: &Verified,
        grant: &asterius_domain::Grant,
        now: OffsetDateTime,
        audit: &dyn asterius_domain::AuditSink,
    ) -> Result<(), DomainError> {
        let expires = grant.expires_at.ok_or_else(invalid)?;
        if grant.client != verified.client
            || grant.tenant != verified.tenant
            || grant.user.is_some()
            || grant.session.is_some()
            || grant.parent.is_some()
            || grant
                .subject
                .as_ref()
                .map(asterius_domain::SubjectId::as_str)
                != Some(verified.principal.as_str())
            || !grant.scopes.is_subset(&verified.scopes)
            || !grant.resources.is_subset(&verified.resources)
            || grant.resources.len() != 1
            || grant.claimed_at != Some(now)
            || expires <= now
            || expires > verified.expires_at
            || expires > now + time::Duration::seconds(300)
        {
            return Err(invalid());
        }
        asterius_domain::workload::validate_actions(
            &grant.authorization_details,
            &verified.actions,
            &grant.resources,
        )?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        consume_on_connection(&mut tx, verified, now).await?;
        crate::grants::PgGrantRepository::insert_on(&mut tx, &verified.tenant, grant).await?;
        sqlx::query("insert into workload_grant_bindings(tenant_id,grant_id,trust_id,trust_version,provider,principal,assertion_digest,assertion_expires_at,source_subject,trust_domain) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(verified.tenant.as_str()).bind(uuid::Uuid::parse_str(grant.id.as_str()).map_err(|_| invalid())?).bind(&verified.trust_id).bind(verified.trust_version)
            .bind(match verified.provider { asterius_domain::workload::Provider::Kubernetes => "kubernetes", asterius_domain::workload::Provider::Github => "github", asterius_domain::workload::Provider::Spiffe => "spiffe" })
            .bind(&verified.principal).bind(verified.digest.as_slice()).bind(verified.expires_at).bind(&verified.source_subject).bind(&verified.trust_domain)
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        let event = AuditEvent::new(
            verified.tenant.clone(),
            EventType::TOKEN_EXCHANGED,
            Outcome::Success,
            Actor::Client(grant.client.clone()),
            now,
        )
        .client(grant.client.clone())
        .grant(grant.id.clone())
        .subject(verified.principal.clone())
        .detail(
            Detail::new()
                .text("trust_id", &verified.trust_id)
                .text("source_subject", &verified.source_subject)
                .text(
                    "trust_domain",
                    verified.trust_domain.as_deref().unwrap_or(""),
                )
                .label(
                    "provider",
                    match verified.provider {
                        asterius_domain::workload::Provider::Kubernetes => "kubernetes",
                        asterius_domain::workload::Provider::Github => "github",
                        asterius_domain::workload::Provider::Spiffe => "spiffe",
                    },
                )
                .number("trust_version", verified.trust_version),
        );
        crate::audit::append(&mut tx, audit.prepare(event)).await?;
        tx.commit().await.map_err(to_domain_error)
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
        Keys::Inline { .. } | Keys::SpiffeBundle { .. } => {
            asterius_jose::workload::KeySet::for_config(&trust.config)
                .map_err(|_| invalid())?
                .fingerprints()
                .to_vec()
        }
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
        if let Keys::SpiffeBundle {
            trust_domain,
            bundle,
        } = &config.keys
        {
            let next =
                asterius_jose::workload::SpiffeBundle::parse(bundle.as_bytes(), &config.algorithms)
                    .map_err(|_| invalid())?;
            // Keep upstream ordering across trust deletion/recreation. The
            // tenant advisory lock also serializes first ledger insertion.
            let previous: Option<serde_json::Value> = sqlx::query_scalar(
                "select snapshot from workload_spiffe_bundle_history where tenant_id=$1 and trust_id=$2 and trust_domain=$3 for update"
            ).bind(tenant.as_str()).bind(id).bind(trust_domain).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
            if let Some(previous) = previous {
                next.follows(
                    previous
                        .get("spiffe_sequence")
                        .and_then(serde_json::Value::as_u64),
                    &serde_json::to_vec(&previous).map_err(|_| invalid())?,
                )
                .map_err(|_| invalid())?;
            }
            let snapshot: serde_json::Value =
                serde_json::from_slice(&next.canonical).map_err(|_| invalid())?;
            sqlx::query("insert into workload_spiffe_bundle_history(tenant_id,trust_id,trust_domain,snapshot) values($1,$2,$3,$4) on conflict(tenant_id,trust_id,trust_domain) do update set snapshot=excluded.snapshot")
                .bind(tenant.as_str()).bind(id).bind(trust_domain).bind(snapshot).execute(&mut *tx).await.map_err(to_domain_error)?;
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
    if !trust.config.enabled
        || trust.version != verified.trust_version
        || trust.config.provider != verified.provider
        || trust.config.principal != verified.principal
        || trust.config.subject != verified.source_subject
        || match &trust.config.keys {
            Keys::SpiffeBundle { trust_domain, .. } => {
                verified.trust_domain.as_ref() != Some(trust_domain)
            }
            _ => verified.trust_domain.is_some(),
        }
        || !trust.config.clients.contains(verified.client.as_str())
        || trust.config.scopes != verified.scopes
        || trust.config.resources != verified.resources
        || trust.config.actions != verified.actions
    {
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
