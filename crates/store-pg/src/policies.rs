//! One tenant's authorization policy (`ast-pj0.4`).
//!
//! `0038_tenant_policies.sql` says why the document has a table of its own;
//! what this file adds is the read and write rules.
//!
//! # A stored document this build refuses fails the read
//!
//! The same rule [`crate::themes`] and [`crate::tenant_settings`] follow, with
//! the sharpest consequence of the three. A policy that silently parsed as
//! "the rules this build understood" would be a policy whose *deny* rules can
//! disappear in an upgrade, and the failure would look exactly like a
//! deployment working: requests would be permitted. So a document that does
//! not parse is [`DomainError::Invalid`], the endpoint fails closed on it
//! (Authorization API 1.0 §10.1.2), and an operator is told which path in the
//! document is wrong.
//!
//! A tenant with **no row** is a different case and is not an error: it has
//! never written a policy, [`PolicyStore::load`] answers `None`, and the engine
//! denies everything with a decision context that says so.

use crate::error::to_domain_error;
use asterius_domain::policy::{RuleSet, StoredPolicy};
use asterius_domain::ports::PolicyStore;
use asterius_domain::{DomainError, TenantId};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// [`PolicyStore`] over `PostgreSQL`.
#[derive(Debug, Clone)]
pub struct PgPolicies {
    pool: PgPool,
}

/// A publication lock held until a prepared signature has been produced.
#[derive(Debug)]
pub struct PolicyPublicationFence {
    transaction: sqlx::Transaction<'static, sqlx::Postgres>,
}
impl PolicyPublicationFence {
    /// Release only after the downstream signing decorator committed its work.
    pub async fn commit(self) -> Result<(), DomainError> { self.transaction.commit().await.map_err(to_domain_error) }
}

impl PgPolicies {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    /// Fence every SQL publication path, including first publication/deletion.
    /// The key must already be prepared before this method acquires a lock.
    pub async fn signing_fence(&self, tenant: &TenantId, issuer: &asterius_domain::Issuer) -> Result<PolicyPublicationFence, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let current: Option<String> = sqlx::query_scalar("select issuer from tenants where tenant_id=$1 and status='active' for share").bind(tenant.as_str()).fetch_optional(&mut *transaction).await.map_err(to_domain_error)?;
        if current.as_deref() != Some(issuer.as_str()) { return Err(DomainError::NotFound); }
        Ok(PolicyPublicationFence { transaction })
    }

    async fn publish(&self, tenant: &TenantId, rules: &RuleSet, expected: Option<Option<&str>>, now: OffsetDateTime) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        // Also serializes the first publication, for which no policy row exists.
        let exists: Option<String> = sqlx::query_scalar("select tenant_id from tenants where tenant_id=$1 for update").bind(tenant.as_str()).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if exists.is_none() { return Err(DomainError::Conflict("no such tenant".to_owned())); }
        let old: Option<serde_json::Value> = sqlx::query_scalar("select document from tenant_policies where tenant_id=$1 for update").bind(tenant.as_str()).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        let old = old.as_ref().map(RuleSet::from_json).transpose().map_err(|error| DomainError::invalid("tenant_policies.document", error.to_string()))?;
        let revision = old.as_ref().map(asterius_domain::policy::explanation::revision);
        match expected {
            Some(expected) if revision.as_deref() != expected => return Err(DomainError::Conflict("policy revision changed".to_owned())),
            None if !rules.conditional_scopes().is_empty() || old.as_ref().is_some_and(|rules| !rules.conditional_scopes().is_empty()) => return Err(DomainError::Conflict("conditional publication requires an expected policy revision".to_owned())),
            _ => {},
        }
        if !rules.conditional_scopes().is_empty() {
            use asterius_domain::ports::TenantSettingsRepository as _;
            let settings = crate::PgTenantSettings::new(self.pool.clone()).settings(tenant).await?;
            for scope in rules.conditional_scopes() {
                if scope.assurance_remedy.as_ref().is_some_and(|target| !settings.acr_policy().can_produce(target)) {
                    return Err(DomainError::invalid("conditional_scopes.assurance_remedy", "authentication requirement unavailable"));
                }
            }
        }
        sqlx::query("insert into tenant_policies(tenant_id,document,created_at,updated_at) values($1,$2,$3,$3) on conflict(tenant_id) do update set document=excluded.document,updated_at=excluded.updated_at").bind(tenant.as_str()).bind(rules.to_json()).bind(now).execute(&mut *tx).await.map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)
    }

}

#[async_trait::async_trait]
impl PolicyStore for PgPolicies {
    async fn history(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<asterius_domain::policy::PolicyRevision>, DomainError> {
        let rows: Vec<(i64, serde_json::Value, OffsetDateTime)> = sqlx::query_as(
            "select id, document, published_at from tenant_policy_revisions where tenant_id = $1 order by id desc limit 100"
        ).bind(tenant.as_str()).fetch_all(&self.pool).await.map_err(to_domain_error)?;
        rows.into_iter()
            .map(|(id, document, updated_at)| {
                let rules = RuleSet::from_json(&document).map_err(|error| {
                    DomainError::invalid("tenant_policy_revisions.document", error.to_string())
                })?;
                Ok(asterius_domain::policy::PolicyRevision {
                    id,
                    policy: StoredPolicy { rules, updated_at },
                })
            })
            .collect()
    }

    async fn load(&self, tenant: &TenantId) -> Result<Option<StoredPolicy>, DomainError> {
        let row = sqlx::query!(
            "select document, updated_at from tenant_policies where tenant_id = $1",
            tenant.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let Some(row) = row else {
            return Ok(None);
        };

        // The reason carries the parser's path — `rules[3].when.group` — which
        // names a member of this server's own schema and never a value the
        // administrator typed, so it is safe in an error an operator reads.
        let rules = RuleSet::from_json(&row.document)
            .map_err(|error| DomainError::invalid("tenant_policies.document", error.to_string()))?;

        Ok(Some(StoredPolicy {
            rules,
            updated_at: row.updated_at,
        }))
    }

    async fn replace(
        &self,
        tenant: &TenantId,
        rules: &RuleSet,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.publish(tenant, rules, None, now).await
    }

    async fn replace_if_revision(&self, tenant: &TenantId, rules: &RuleSet, expected: Option<&str>, now: OffsetDateTime) -> Result<(), DomainError> {
        self.publish(tenant, rules, Some(expected), now).await
    }

    async fn clear(&self, tenant: &TenantId) -> Result<bool, DomainError> {
        let conditional: bool = sqlx::query_scalar("select exists(select 1 from tenant_policies where tenant_id=$1 and coalesce(jsonb_array_length(document->'conditional_scopes'),0)>0)").bind(tenant.as_str()).fetch_one(&self.pool).await.map_err(to_domain_error)?;
        if conditional { return Err(DomainError::Conflict("remove conditional scopes using revision-checked publication".to_owned())); }
        let affected = sqlx::query("delete from tenant_policies where tenant_id=$1 and coalesce(jsonb_array_length(document->'conditional_scopes'),0)=0").bind(tenant.as_str())
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();

        Ok(affected > 0)
    }
}
