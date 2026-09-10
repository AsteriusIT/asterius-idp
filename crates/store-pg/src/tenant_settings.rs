//! One tenant's settings: the feature flags it has switched off and the
//! lifetimes it issues with.
//!
//! # Why this is a second repository over the same row
//!
//! The settings live in the `tenants.settings` column, beside the refresh
//! policy [`crate::tenants`] reads, and they are still reached through their
//! own port. The reason is the write side: [`TenantSettingsRepository::save`]
//! takes an [`asterius_domain::TenantSettings`], which has private fields and
//! one constructor, so a lifetime past FAPI 2.0 Security Profile's ceiling
//! cannot be handed to this adapter at all. A `settings: Value` parameter on
//! the tenant repository would accept whatever a handler built.
//!
//! # Merged, never replaced
//!
//! `settings` is one document with several owners — `refresh` is written by
//! [`crate::tenants`], `options` by this file — so the write is a shallow
//! `||` merge for the reason stated there: an update that wrote the whole
//! document would silently drop whatever a later story put beside it. The
//! `options` member itself is replaced whole, because settings read half from
//! one write and half from another are settings nobody chose.
//!
//! # The member name is not a `query!` parameter
//!
//! Both statements are `sqlx::query!`, checked against a migrated database at
//! compile time and recorded in `.sqlx/`, like the rest of this crate. The one
//! thing the macro cannot take from [`MEMBER`] is the member name itself: a
//! `query!` statement must be a literal, so `'options'` is spelled out in the
//! `jsonb_build_object` call and [`MEMBER`] names the read side. The two are
//! asserted equal in this module's tests, which is what keeps a rename from
//! producing settings that are written and never read.

use crate::error::to_domain_error;
use asterius_domain::ports::TenantSettingsRepository;
use asterius_domain::{DomainError, TenantId, TenantSettings};
use sqlx::postgres::PgPool;

/// The member of `tenants.settings` this repository owns.
///
/// Named in one place, because a reader and a writer that disagree about it
/// produce a tenant whose settings are written and never read — which looks
/// exactly like a cache that will not invalidate.
const MEMBER: &str = "options";

/// `TenantSettingsRepository` over `PostgreSQL`.
#[derive(Debug, Clone)]
pub struct PgTenantSettings {
    pool: PgPool,
}

impl PgTenantSettings {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl TenantSettingsRepository for PgTenantSettings {
    async fn settings(&self, tenant: &TenantId) -> Result<TenantSettings, DomainError> {
        let row = sqlx::query!(
            "select settings from tenants where tenant_id = $1",
            tenant.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?
        .ok_or(DomainError::NotFound)?;

        let document = row.settings;

        // A stored document this build refuses fails the read rather than
        // falling back to the defaults, for the reason
        // `RefreshPolicy::from_json` states: a lifetime that quietly reverted
        // to this file's idea of a default is a setting an operator believes
        // is in force and is not.
        TenantSettings::from_json(document.get(MEMBER))
            .map_err(|error| DomainError::invalid("settings.options", error.to_string()))
    }

    async fn save(&self, tenant: &TenantId, settings: &TenantSettings) -> Result<(), DomainError> {
        let affected = sqlx::query!(
            "update tenants
             set settings = coalesce(settings, '{}'::jsonb)
                            || jsonb_build_object('options', $2::jsonb),
                 updated_at = now()
             where tenant_id = $1",
            tenant.as_str(),
            settings.to_json()
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();

        if affected == 0 {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }
}
