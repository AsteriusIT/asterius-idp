//! Administrative roles: who may administer a tenant, and who the deployment.
//!
//! ADR-0010. A role is a row on a user, and its scope is a property of the role
//! name rather than a column — see [`asterius_domain::Role`].
//!
//! **`tenant_is_reserved` is never an argument.** The insert below reads it out
//! of `tenants` in the same statement, and the composite foreign key on
//! `user_roles` refuses the row if the pair does not exist. That is what makes
//! "a deployment-scoped role only inside the reserved tenant" a fact about the
//! database rather than a rule this adapter is trusted to apply: a caller
//! cannot pass the flag, and a second adapter written later cannot pass a wrong
//! one either.

use crate::error::to_domain_error;
use asterius_domain::ports::TenantScoped;
use asterius_domain::{DomainError, Role, TenantId, UserId, UserRole};
use sqlx::postgres::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// The check constraint that refuses a deployment-scoped role outside the
/// reserved tenant. Named here so the error a caller sees says which rule it
/// broke rather than "23514".
const OUTSIDE_THE_RESERVED_TENANT: &str = "user_roles_deployment_scope_needs_the_reserved_tenant";

/// The role repository for one tenant.
#[derive(Debug, Clone)]
pub struct PgRoleRepository {
    pool: PgPool,
    tenant: TenantId,
}

impl TenantScoped for PgRoleRepository {
    fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}

impl PgRoleRepository {
    /// Binds a pool to one tenant.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Grants `role` to `user`, or does nothing if they already hold it.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] when the grant is refused: the user or the
    /// tenant does not exist, or the role is deployment-scoped and this tenant
    /// is not the reserved one. All three come from the schema, not from a
    /// check performed here.
    pub async fn grant(&self, user: UserId, role: Role) -> Result<(), DomainError> {
        let inserted = sqlx::query!(
            "insert into user_roles (tenant_id, user_id, role, tenant_is_reserved)
             select $1, $2, $3, t.is_reserved
               from tenants t
              where t.tenant_id = $1
             on conflict (tenant_id, user_id, role) do nothing",
            self.tenant.as_str(),
            user.as_uuid(),
            role.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(check_violation_is_a_conflict)?;

        if inserted.rows_affected() == 0 && !self.holds(user, role).await? {
            // The `select` found no tenant, so there was nothing to insert and
            // no constraint to break. Reported rather than swallowed: a grant
            // that wrote nothing looks exactly like a grant that worked.
            return Err(DomainError::Conflict(format!(
                "no tenant {} to grant {role} in",
                self.tenant
            )));
        }
        Ok(())
    }

    /// Takes `role` away from `user`.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if they did not hold it, or a storage error.
    pub async fn revoke(&self, user: UserId, role: Role) -> Result<(), DomainError> {
        let deleted = sqlx::query!(
            "delete from user_roles
              where tenant_id = $1 and user_id = $2 and role = $3",
            self.tenant.as_str(),
            user.as_uuid(),
            role.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        if deleted.rows_affected() == 0 {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }

    /// Whether `user` holds `role` in this tenant.
    ///
    /// # Errors
    ///
    /// A storage error.
    pub async fn holds(&self, user: UserId, role: Role) -> Result<bool, DomainError> {
        let held: Option<bool> = sqlx::query_scalar!(
            "select true from user_roles
              where tenant_id = $1 and user_id = $2 and role = $3",
            self.tenant.as_str(),
            user.as_uuid(),
            role.as_str(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?
        .flatten();
        Ok(held.unwrap_or(false))
    }

    /// Every role `user` holds in this tenant.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] if a stored role is one this build does not
    /// know — a row from a newer schema, which must not be read as a weaker
    /// authority than it is — or a storage error.
    pub async fn roles_of(&self, user: UserId) -> Result<Vec<UserRole>, DomainError> {
        let rows = sqlx::query!(
            "select role, granted_at from user_roles
              where tenant_id = $1 and user_id = $2
              order by role",
            self.tenant.as_str(),
            user.as_uuid(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        rows.into_iter()
            .map(|row| self.entity(user, &row.role, row.granted_at))
            .collect()
    }

    /// The users in this tenant holding `role`.
    ///
    /// # Errors
    ///
    /// A storage error.
    pub async fn holders_of(&self, role: Role) -> Result<Vec<UserId>, DomainError> {
        let rows: Vec<Uuid> = sqlx::query_scalar!(
            "select user_id from user_roles
              where tenant_id = $1 and role = $2
              order by granted_at, user_id",
            self.tenant.as_str(),
            role.as_str(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(rows.into_iter().map(UserId::new).collect())
    }

    fn entity(
        &self,
        user: UserId,
        role: &str,
        granted_at: OffsetDateTime,
    ) -> Result<UserRole, DomainError> {
        let role = Role::parse(role)
            .ok_or_else(|| DomainError::invalid("role", format!("unknown: {role}")))?;
        Ok(UserRole {
            tenant: self.tenant.clone(),
            user,
            role,
            granted_at,
        })
    }
}

/// Turns the schema's refusal into a domain outcome a caller can read.
///
/// A check violation is `Storage` under the general mapping, which is right for
/// a constraint the application already enforces. This one it does not: the
/// rule that deployment authority lives in the reserved tenant is the schema's
/// alone, so breaking it is an outcome and not an outage.
fn check_violation_is_a_conflict(error: sqlx::Error) -> DomainError {
    if let sqlx::Error::Database(db) = &error
        && db.constraint() == Some(OUTSIDE_THE_RESERVED_TENANT)
    {
        return DomainError::Conflict(format!(
            "{OUTSIDE_THE_RESERVED_TENANT}: a deployment-scoped role may only be granted \
             to a user of the reserved tenant (ADR-0010)"
        ));
    }
    to_domain_error(error)
}
