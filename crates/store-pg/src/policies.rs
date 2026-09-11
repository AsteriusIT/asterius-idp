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

impl PgPolicies {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl PolicyStore for PgPolicies {
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
        // `insert … on conflict`, like the theme: a tenant that has never had a
        // policy has no row to update, and the caller should not have to know
        // which case it is in. The `where exists` turns an unknown tenant into
        // a `Conflict` rather than a foreign-key violation surfacing as a
        // storage failure.
        let affected = sqlx::query!(
            "insert into tenant_policies (tenant_id, document, created_at, updated_at)
             select $1, $2::jsonb, $3, $3
              where exists (select 1 from tenants where tenant_id = $1)
             on conflict (tenant_id)
             do update set document = excluded.document, updated_at = excluded.updated_at",
            tenant.as_str(),
            rules.to_json(),
            now
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();

        if affected == 0 {
            return Err(DomainError::Conflict("no such tenant".to_owned()));
        }
        Ok(())
    }

    async fn clear(&self, tenant: &TenantId) -> Result<bool, DomainError> {
        let affected = sqlx::query!(
            "delete from tenant_policies where tenant_id = $1",
            tenant.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();

        Ok(affected > 0)
    }
}
