//! One tenant's registered authorization details types, over `PostgreSQL`
//! (RFC 9396 §2.1).
//!
//! # Checked against the schema, not just against the tests
//!
//! Every statement here is `sqlx::query!`, like [`crate::resource_servers`]
//! beside it: the column list and the bind types are checked against a
//! migrated database at compile time and recorded in `.sqlx/`. The `schema`
//! column is the reason it earns its keep — it is `jsonb`, and a bind that
//! drifted to `text` would store a registered type nothing could ever read
//! back.

use crate::error::to_domain_error;
use asterius_domain::ports::AuthorizationDetailsTypeRepository;
use asterius_domain::{AuthorizationDetailsType, DomainError, JsonSchema, TenantId};
use sqlx::postgres::PgPool;

/// [`AuthorizationDetailsTypeRepository`] over `PostgreSQL`, scoped to one
/// tenant.
#[derive(Debug, Clone)]
pub struct PgAuthorizationDetailsTypes {
    pool: PgPool,
    tenant: TenantId,
}

impl PgAuthorizationDetailsTypes {
    /// Scopes a repository to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Registers a type, or replaces the one already registered under this
    /// name.
    ///
    /// The schema is checked *here*, before the write, rather than only on the
    /// way out: an operator who pastes a schema using a keyword this server
    /// does not understand finds out at registration, which is the moment they
    /// can fix it, rather than at the moment a client's pushed request is
    /// refused for a reason neither of them can see.
    ///
    /// The administrative API for this is follow-up work; until it exists an
    /// operator registers a type through this, which is what provisioning and
    /// the tests use so that the shape of the row is decided in one place.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] if the schema is not one this server can
    /// validate against, or [`DomainError::Storage`] if the write fails —
    /// which includes the schema's own refusal of a type name that is not
    /// printable ASCII.
    pub async fn register(
        &self,
        kind: &AuthorizationDetailsType,
        schema: &serde_json::Value,
    ) -> Result<(), DomainError> {
        JsonSchema::parse(schema).map_err(|failure| {
            DomainError::invalid("authorization_details_types.schema", failure.to_string())
        })?;
        sqlx::query!(
            "insert into authorization_details_types
                 (tenant_id, type_name, schema, consent_template)
             values ($1, $2, $3, $4)
             on conflict (tenant_id, type_name) do update
             set schema = excluded.schema,
                 consent_template = excluded.consent_template",
            self.tenant.as_str(),
            kind.name,
            schema,
            kind.consent_template.as_deref()
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    /// Withdraws a type.
    ///
    /// Returns whether a row was there to withdraw. A withdrawn type stops
    /// being a legal `authorization_details` element immediately; grants
    /// already carrying one keep it, because a grant records a decision that
    /// was taken.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the delete fails.
    pub async fn withdraw(&self, name: &str) -> Result<bool, DomainError> {
        let affected = sqlx::query!(
            "delete from authorization_details_types
              where tenant_id = $1 and type_name = $2",
            self.tenant.as_str(),
            name
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        Ok(affected > 0)
    }
}

#[async_trait::async_trait]
impl AuthorizationDetailsTypeRepository for PgAuthorizationDetailsTypes {
    async fn list(&self) -> Result<Vec<AuthorizationDetailsType>, DomainError> {
        let rows = sqlx::query!(
            "select type_name, schema, consent_template
               from authorization_details_types
              where tenant_id = $1
              order by type_name",
            self.tenant.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let mut types = Vec::with_capacity(rows.len());
        for row in rows {
            let name = row.type_name;
            let schema = row.schema;
            let consent_template = row.consent_template;
            // A stored schema this server cannot validate against fails the
            // read rather than being replaced by an empty one: an unparseable
            // schema silently read as `{}` would admit every element it was
            // written to refuse, and the operator has no way to notice. The
            // same reasoning as `PgResourceServers::list` refusing a stored
            // identifier that is not a resource indicator.
            let schema = JsonSchema::parse(&schema).map_err(|failure| {
                DomainError::invalid(
                    "authorization_details_types.schema",
                    format!("a registered type has an unusable schema: {failure}"),
                )
            })?;
            types.push(AuthorizationDetailsType {
                name,
                schema,
                consent_template,
            });
        }
        Ok(types)
    }
}
