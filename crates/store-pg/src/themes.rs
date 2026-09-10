//! One tenant's design tokens, and the images they name (`ast-ndk.1`).
//!
//! Two tables, one port. `0016_tenant_themes.sql` says why they are not a
//! member of `tenants.settings`; what this file adds is the read and write
//! rules.
//!
//! # A stored document that this build refuses fails the read
//!
//! Same rule as [`crate::tenant_settings`], and for a stronger reason. A theme
//! that quietly fell back to the shipped palette because its document no
//! longer parses is a tenant whose brand disappeared without anything saying
//! so, and — since the contrast check runs on the way in — it is also the only
//! way an unvalidated palette could ever render. A tenant that has never set a
//! theme is a different case and is not an error: no row means
//! [`Theme::default`].
//!
//! # The asset write is idempotent by construction
//!
//! The primary key is `(tenant_id, digest)` and the digest is over the stored
//! bytes, so `on conflict do nothing` is not a convenience: two administrators
//! uploading the same logo have written the same bytes, and the second write
//! has nothing to change. It is also what makes a retried request safe.

use crate::error::to_domain_error;
use asterius_domain::entities::theme::ImageFormat;
use asterius_domain::ports::{StoredAsset, ThemeRepository};
use asterius_domain::{DomainError, TenantId, Theme};
use sqlx::postgres::PgPool;

/// `ThemeRepository` over `PostgreSQL`.
#[derive(Debug, Clone)]
pub struct PgThemes {
    pool: PgPool,
}

impl PgThemes {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ThemeRepository for PgThemes {
    async fn theme(&self, tenant: &TenantId) -> Result<Theme, DomainError> {
        let row = sqlx::query!(
            "select document from tenant_themes where tenant_id = $1",
            tenant.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        // No row is a tenant that has never expressed an opinion, which is the
        // shipped palette and not an error.
        let Some(row) = row else {
            return Ok(Theme::default());
        };

        // The field is the column and the reason carries the JSON pointer:
        // the pointer names a member of this server's own schema, never a
        // value the tenant typed, so it is safe in an error an operator reads.
        Theme::from_json(&row.document)
            .map_err(|error| DomainError::invalid("tenant_themes.document", error.to_string()))
    }

    async fn save_theme(&self, tenant: &TenantId, theme: &Theme) -> Result<(), DomainError> {
        // `insert … on conflict` rather than an update, because a tenant that
        // has never had a theme has no row to update and the caller should not
        // have to know which case it is in.
        let affected = sqlx::query!(
            "insert into tenant_themes (tenant_id, document)
             select $1, $2::jsonb
              where exists (select 1 from tenants where tenant_id = $1)
             on conflict (tenant_id)
             do update set document = excluded.document, updated_at = now()",
            tenant.as_str(),
            theme.to_json()
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();

        // The `where exists` is what turns an unknown tenant into `NotFound`
        // rather than a foreign key violation surfacing as a storage error:
        // the caller asked about a tenant, and "no such tenant" is an answer.
        if affected == 0 {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }

    async fn store_asset(&self, tenant: &TenantId, asset: &StoredAsset) -> Result<(), DomainError> {
        let affected = sqlx::query!(
            "insert into tenant_theme_assets (tenant_id, digest, content_type, bytes)
             select $1, $2, $3, $4
              where exists (select 1 from tenants where tenant_id = $1)
             on conflict (tenant_id, digest) do nothing",
            tenant.as_str(),
            asset.digest,
            asset.format.content_type(),
            asset.bytes
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();

        if affected == 0 {
            // Either the tenant does not exist or the same bytes are already
            // stored. The second is the common case and is a success, so the
            // two are told apart rather than guessed at.
            let known = sqlx::query!(
                "select 1 as present from tenant_theme_assets
                  where tenant_id = $1 and digest = $2",
                tenant.as_str(),
                asset.digest
            )
            .fetch_optional(&self.pool)
            .await
            .map_err(to_domain_error)?;
            if known.is_none() {
                return Err(DomainError::NotFound);
            }
        }
        Ok(())
    }

    async fn asset(
        &self,
        tenant: &TenantId,
        digest: &str,
    ) -> Result<Option<StoredAsset>, DomainError> {
        let row = sqlx::query!(
            "select digest, content_type, bytes from tenant_theme_assets
              where tenant_id = $1 and digest = $2",
            tenant.as_str(),
            digest
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let Some(row) = row else {
            return Ok(None);
        };
        // A `content_type` outside the three is impossible while the column's
        // check constraint holds; if it ever did happen, serving the bytes
        // under a type nobody validated is the one outcome worth refusing.
        let format = ImageFormat::from_content_type(&row.content_type).ok_or_else(|| {
            DomainError::invalid(
                "content_type",
                "a stored asset has a media type this build does not serve",
            )
        })?;
        Ok(Some(StoredAsset {
            digest: row.digest,
            format,
            bytes: row.bytes,
        }))
    }
}
