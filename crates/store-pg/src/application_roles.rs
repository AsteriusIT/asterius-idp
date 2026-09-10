//! The application-role catalogues and their assignments, over `PostgreSQL`
//! (`ast-095`).
//!
//! Four tables, two of them catalogues and two of them assignments; see
//! `0023_application_roles.sql` for why it is four and not one with a nullable
//! `client_id`.
//!
//! # Nothing here invents a name
//!
//! Every write binds a [`RoleName`], which has already been through the
//! fuzzed parser, and every read parses what came back. A row this build's
//! parser refuses is [`DomainError::Invalid`] and not a skipped element: a
//! token minted from a *subset* of somebody's roles would be an authorization
//! decision taken by a parse failure, and a catalogue listing rendered with a
//! row missing is a screen an administrator would act on.
//!
//! # Deleting a held role is the database's refusal, not this adapter's
//!
//! The `delete` below is a plain statement. The `on delete restrict` on the
//! assignment tables is what turns "somebody still holds it" into an error,
//! which [`crate::error::to_domain_error`] renders as
//! [`DomainError::Conflict`]. Checking here instead would be a read followed
//! by a write with a race between them, and the race is exactly the case that
//! matters: an assignment made while the deletion was being considered.

use crate::error::to_domain_error;
use asterius_domain::ports::ApplicationRoleDirectory;
use asterius_domain::{
    ApplicationRole, ClientId, DomainError, HeldRoles, RoleName, RoleOwner, TenantId, UserId,
};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// [`ApplicationRoleDirectory`] over `PostgreSQL`.
///
/// Deployment-wide, with the tenant on every call: the same shape
/// [`crate::PgUserRepository`]'s administrative port has, and for the same
/// reason — the admin API holds one handle and names the tenant the request
/// resolved to.
#[derive(Debug, Clone)]
pub struct PgApplicationRoles {
    pool: PgPool,
}

impl PgApplicationRoles {
    /// Binds a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Turns a stored name back into a [`RoleName`].
///
/// The schema carries the same alphabet as a check constraint, so a failure
/// here means a row written by something that bypassed both — which is worth
/// an error rather than a silent omission.
fn parse_stored(name: &str) -> Result<RoleName, DomainError> {
    RoleName::parse(name).map_err(|error| {
        DomainError::invalid(
            "role.name",
            format!("a stored role name is not one this build accepts: {error}"),
        )
    })
}

#[async_trait::async_trait]
impl ApplicationRoleDirectory for PgApplicationRoles {
    async fn define(&self, role: &ApplicationRole) -> Result<bool, DomainError> {
        let affected = match &role.owner {
            RoleOwner::Tenant => sqlx::query!(
                "insert into tenant_roles (tenant_id, name, description, created_at)
                 values ($1, $2, $3, $4)
                 on conflict (tenant_id, name) do nothing",
                role.tenant.as_str(),
                role.name.as_str(),
                role.description.as_deref(),
                role.created_at
            )
            .execute(&self.pool)
            .await
            .map_err(to_domain_error)?
            .rows_affected(),
            RoleOwner::Client(client) => sqlx::query!(
                "insert into client_roles (tenant_id, client_id, name, description, created_at)
                 values ($1, $2, $3, $4, $5)
                 on conflict (tenant_id, client_id, name) do nothing",
                role.tenant.as_str(),
                client.as_str(),
                role.name.as_str(),
                role.description.as_deref(),
                role.created_at
            )
            .execute(&self.pool)
            .await
            .map_err(to_domain_error)?
            .rows_affected(),
        };
        Ok(affected > 0)
    }

    async fn catalogue(
        &self,
        tenant: &TenantId,
        owner: &RoleOwner,
    ) -> Result<Vec<ApplicationRole>, DomainError> {
        let rows: Vec<(String, Option<String>, OffsetDateTime)> = match owner {
            RoleOwner::Tenant => sqlx::query!(
                "select name, description, created_at
                   from tenant_roles
                  where tenant_id = $1
                  order by name",
                tenant.as_str()
            )
            .fetch_all(&self.pool)
            .await
            .map_err(to_domain_error)?
            .into_iter()
            .map(|row| (row.name, row.description, row.created_at))
            .collect(),
            RoleOwner::Client(client) => sqlx::query!(
                "select name, description, created_at
                   from client_roles
                  where tenant_id = $1 and client_id = $2
                  order by name",
                tenant.as_str(),
                client.as_str()
            )
            .fetch_all(&self.pool)
            .await
            .map_err(to_domain_error)?
            .into_iter()
            .map(|row| (row.name, row.description, row.created_at))
            .collect(),
        };

        let mut catalogue = Vec::with_capacity(rows.len());
        for (name, description, created_at) in rows {
            catalogue.push(ApplicationRole {
                tenant: tenant.clone(),
                owner: owner.clone(),
                name: parse_stored(&name)?,
                description,
                created_at,
            });
        }
        Ok(catalogue)
    }

    async fn remove(
        &self,
        tenant: &TenantId,
        owner: &RoleOwner,
        name: &RoleName,
    ) -> Result<bool, DomainError> {
        let affected = match owner {
            RoleOwner::Tenant => sqlx::query!(
                "delete from tenant_roles where tenant_id = $1 and name = $2",
                tenant.as_str(),
                name.as_str()
            )
            .execute(&self.pool)
            .await
            .map_err(to_domain_error)?
            .rows_affected(),
            RoleOwner::Client(client) => sqlx::query!(
                "delete from client_roles
                  where tenant_id = $1 and client_id = $2 and name = $3",
                tenant.as_str(),
                client.as_str(),
                name.as_str()
            )
            .execute(&self.pool)
            .await
            .map_err(to_domain_error)?
            .rows_affected(),
        };
        Ok(affected > 0)
    }

    async fn assign(
        &self,
        tenant: &TenantId,
        user: UserId,
        owner: &RoleOwner,
        name: &RoleName,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let affected = match owner {
            RoleOwner::Tenant => sqlx::query!(
                "insert into user_tenant_roles (tenant_id, user_id, name, granted_at)
                 values ($1, $2, $3, $4)
                 on conflict (tenant_id, user_id, name) do nothing",
                tenant.as_str(),
                user.as_uuid(),
                name.as_str(),
                now
            )
            .execute(&self.pool)
            .await
            .map_err(to_domain_error)?
            .rows_affected(),
            RoleOwner::Client(client) => sqlx::query!(
                "insert into user_client_roles (tenant_id, client_id, user_id, name, granted_at)
                 values ($1, $2, $3, $4, $5)
                 on conflict (tenant_id, client_id, user_id, name) do nothing",
                tenant.as_str(),
                client.as_str(),
                user.as_uuid(),
                name.as_str(),
                now
            )
            .execute(&self.pool)
            .await
            .map_err(to_domain_error)?
            .rows_affected(),
        };
        Ok(affected > 0)
    }

    async fn withdraw(
        &self,
        tenant: &TenantId,
        user: UserId,
        owner: &RoleOwner,
        name: &RoleName,
    ) -> Result<bool, DomainError> {
        let affected = match owner {
            RoleOwner::Tenant => sqlx::query!(
                "delete from user_tenant_roles
                  where tenant_id = $1 and user_id = $2 and name = $3",
                tenant.as_str(),
                user.as_uuid(),
                name.as_str()
            )
            .execute(&self.pool)
            .await
            .map_err(to_domain_error)?
            .rows_affected(),
            RoleOwner::Client(client) => sqlx::query!(
                "delete from user_client_roles
                  where tenant_id = $1 and client_id = $2 and user_id = $3 and name = $4",
                tenant.as_str(),
                client.as_str(),
                user.as_uuid(),
                name.as_str()
            )
            .execute(&self.pool)
            .await
            .map_err(to_domain_error)?
            .rows_affected(),
        };
        Ok(affected > 0)
    }

    async fn held_by(&self, tenant: &TenantId, user: UserId) -> Result<HeldRoles, DomainError> {
        let mut held = HeldRoles::default();

        let tenant_rows = sqlx::query!(
            "select name from user_tenant_roles
              where tenant_id = $1 and user_id = $2
              order by name",
            tenant.as_str(),
            user.as_uuid()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        for row in tenant_rows {
            held.tenant.insert(parse_stored(&row.name)?);
        }

        let client_rows = sqlx::query!(
            "select client_id, name from user_client_roles
              where tenant_id = $1 and user_id = $2
              order by client_id, name",
            tenant.as_str(),
            user.as_uuid()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        for row in client_rows {
            held.clients
                .entry(ClientId::new(row.client_id))
                .or_default()
                .insert(parse_stored(&row.name)?);
        }

        Ok(held)
    }
}
