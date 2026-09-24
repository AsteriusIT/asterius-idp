//! Tenant-bound, single-use invitations. The mailbox token is never stored.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, OpaqueToken, TenantId, UserId};
use serde_json::json;
use sqlx::{PgPool, Row};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// The maximum lifetime an administrator can grant to an invitation.
pub const MAX_INVITATION_LIFETIME: Duration = Duration::days(1);

/// Metadata safe for the administrator to read. No token or password is here.
#[derive(Debug, Clone)]
pub struct Invitation {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub role: Option<String>,
    pub group_ids: Vec<Uuid>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

/// The address proved by a still-live invitation.
#[derive(Debug, Clone)]
pub struct InvitationPreview {
    pub email: String,
    pub username: String,
    pub expires_at: OffsetDateTime,
}

/// The committed activation and the assignments it applied.
#[derive(Debug, Clone)]
pub struct ActivatedInvitation {
    pub user: UserId,
    pub invitation_id: Uuid,
    pub invited_by: String,
    pub role: Option<String>,
    pub group_ids: Vec<Uuid>,
}

/// An administrator's approved invitation before a row or mail is written.
#[derive(Debug, Clone, Copy)]
pub struct NewInvitation<'a> {
    pub email: &'a str,
    pub username: &'a str,
    pub inviter: &'a str,
    pub role: Option<&'a str>,
    pub group_ids: &'a [Uuid],
    pub expires_at: OffsetDateTime,
    pub link_base: &'a str,
    pub now: OffsetDateTime,
}

/// All invitation writes bind the tenant before executing any statement.
#[derive(Debug, Clone)]
pub struct PgInvitations {
    pool: PgPool,
    tenant: TenantId,
}

impl PgInvitations {
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Creates an invitation and its queued mail in one transaction.
    pub async fn invite(&self, request: NewInvitation<'_>) -> Result<Invitation, DomainError> {
        let NewInvitation {
            email,
            username,
            inviter,
            role,
            group_ids,
            expires_at,
            link_base,
            now,
        } = request;
        let email = email.trim();
        let username = username.trim();
        validate_invitation(email, username, role, expires_at, now)?;

        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let existing = sqlx::query_scalar::<_, i64>(
            "select count(*) from users where tenant_id = $1 and (lower(email) = lower($2) or username = $3)",
        )
        .bind(self.tenant.as_str()).bind(email).bind(username)
        .fetch_one(&mut *tx).await.map_err(to_domain_error)?;
        if existing != 0 {
            return Err(DomainError::Conflict("account already exists".to_owned()));
        }
        let pending_username = sqlx::query_scalar::<_, i64>(
            "select count(*) from invitations where tenant_id = $1 and username = $2 and lower(email) <> lower($3) and consumed_at is null and revoked_at is null",
        )
        .bind(self.tenant.as_str())
        .bind(username)
        .bind(email)
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if pending_username != 0 {
            return Err(DomainError::Conflict("username already invited".to_owned()));
        }
        for group in group_ids {
            let present = sqlx::query_scalar::<_, i64>(
                "select count(*) from managed_groups where tenant_id = $1 and group_id = $2",
            )
            .bind(self.tenant.as_str())
            .bind(group)
            .fetch_one(&mut *tx)
            .await
            .map_err(to_domain_error)?;
            if present == 0 {
                return Err(DomainError::invalid(
                    "group_ids",
                    "group is not in this tenant",
                ));
            }
        }

        // A second invitation to the same mailbox rotates the old bearer link.
        sqlx::query("update invitations set revoked_at = $3 where tenant_id = $1 and lower(email) = lower($2) and consumed_at is null and revoked_at is null")
            .bind(self.tenant.as_str()).bind(email).bind(now)
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        let token = OpaqueToken::generate();
        let id = Uuid::new_v4();
        sqlx::query("insert into invitations (tenant_id, invitation_id, email, username, token_hash, invited_by, role, group_ids, created_at, expires_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(self.tenant.as_str()).bind(id).bind(email).bind(username).bind(token.digest())
            .bind(inviter).bind(role).bind(group_ids).bind(now).bind(expires_at)
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        self.queue_mail(&mut tx, email, link_base, &token, expires_at, now)
            .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(Invitation {
            id,
            email: email.to_owned(),
            username: username.to_owned(),
            role: role.map(str::to_owned),
            group_ids: group_ids.to_vec(),
            created_at: now,
            expires_at,
            consumed_at: None,
            revoked_at: None,
        })
    }

    /// Rotates a live invitation's token and queues a fresh link.
    pub async fn resend(
        &self,
        id: Uuid,
        expires_at: OffsetDateTime,
        link_base: &str,
        now: OffsetDateTime,
    ) -> Result<Invitation, DomainError> {
        if expires_at - now < Duration::minutes(1) || expires_at - now > MAX_INVITATION_LIFETIME {
            return Err(DomainError::invalid(
                "expires_at",
                "invitation expiry must be within twenty-four hours",
            ));
        }
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let token = OpaqueToken::generate();
        let row = sqlx::query("update invitations set token_hash = $3, expires_at = $4 where tenant_id = $1 and invitation_id = $2 and consumed_at is null and revoked_at is null returning email, username, role, group_ids, created_at")
            .bind(self.tenant.as_str()).bind(id).bind(token.digest()).bind(expires_at)
            .fetch_optional(&mut *tx).await.map_err(to_domain_error)?
            .ok_or(DomainError::NotFound)?;
        let email: String = row.get("email");
        self.queue_mail(&mut tx, &email, link_base, &token, expires_at, now)
            .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(Invitation {
            id,
            email,
            username: row.get("username"),
            role: row.get("role"),
            group_ids: row.get("group_ids"),
            created_at: row.get("created_at"),
            expires_at,
            consumed_at: None,
            revoked_at: None,
        })
    }

    async fn queue_mail(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        email: &str,
        link_base: &str,
        token: &OpaqueToken,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let link = format!("{link_base}?token={}", token.expose());
        let minutes = (expires_at - now).whole_minutes();
        sqlx::query("insert into outbox (tenant_id, kind, destination, payload, created_at) values ($1, 'notification.invitation', $2, $3, $4)")
            .bind(self.tenant.as_str()).bind(email)
            .bind(json!({"link": link, "valid_for_minutes": minutes, "expires_at": expires_at.unix_timestamp()}))
            .bind(now).execute(&mut **tx).await.map_err(to_domain_error)?;
        Ok(())
    }

    /// Revokes an outstanding link; repeat calls reveal no extra state.
    pub async fn revoke(&self, id: Uuid, now: OffsetDateTime) -> Result<bool, DomainError> {
        let changed = sqlx::query("update invitations set revoked_at = $3 where tenant_id = $1 and invitation_id = $2 and consumed_at is null and revoked_at is null")
            .bind(self.tenant.as_str()).bind(id).bind(now)
            .execute(&self.pool).await.map_err(to_domain_error)?;
        Ok(changed.rows_affected() == 1)
    }

    /// Resolves a link for a form without spending it.
    pub async fn preview(
        &self,
        token: &OpaqueToken,
        now: OffsetDateTime,
    ) -> Result<Option<InvitationPreview>, DomainError> {
        let row = sqlx::query("select email, username, expires_at from invitations where tenant_id = $1 and token_hash = $2 and consumed_at is null and revoked_at is null and expires_at > $3")
            .bind(self.tenant.as_str()).bind(token.digest()).bind(now)
            .fetch_optional(&self.pool).await.map_err(to_domain_error)?;
        Ok(row.map(|row| InvitationPreview {
            email: row.get("email"),
            username: row.get("username"),
            expires_at: row.get("expires_at"),
        }))
    }

    /// Claims the link, creates the verified account and its credential, and
    /// applies preapproved assignments atomically. A failed insert rolls back
    /// token consumption, so the recipient can ask an admin to repair it.
    pub async fn activate(
        &self,
        token: &OpaqueToken,
        password_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Option<ActivatedInvitation>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let row = sqlx::query("update invitations set consumed_at = $3 where tenant_id = $1 and token_hash = $2 and consumed_at is null and revoked_at is null and expires_at > $3 returning invitation_id, invited_by, email, username, role, group_ids")
            .bind(self.tenant.as_str()).bind(token.digest()).bind(now)
            .fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        let Some(row) = row else { return Ok(None) };
        let email: String = row.get("email");
        let username: String = row.get("username");
        let role: Option<String> = row.get("role");
        let groups: Vec<Uuid> = row.get("group_ids");
        let user = UserId::generate();
        sqlx::query("insert into users (tenant_id, user_id, username, email, email_verified, status, created_at, updated_at) values ($1,$2,$3,$4,true,'active',$5,$5)")
            .bind(self.tenant.as_str()).bind(user.as_uuid()).bind(username).bind(email).bind(now)
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        sqlx::query("insert into credentials (tenant_id, credential_id, user_id, kind, password_hash) values ($1,$2,$3,'password',$4)")
            .bind(self.tenant.as_str()).bind(Uuid::new_v4()).bind(user.as_uuid()).bind(password_hash)
            .execute(&mut *tx).await.map_err(to_domain_error)?;
        if let Some(ref role) = role {
            sqlx::query("insert into user_roles (tenant_id, user_id, role, tenant_is_reserved) select $1,$2,$3,is_reserved from tenants where tenant_id = $1")
                .bind(self.tenant.as_str()).bind(user.as_uuid()).bind(role)
                .execute(&mut *tx).await.map_err(to_domain_error)?;
        }
        for group in &groups {
            sqlx::query("insert into group_memberships (tenant_id, group_id, user_id, created_at) values ($1,$2,$3,$4)")
                .bind(self.tenant.as_str()).bind(group).bind(user.as_uuid()).bind(now)
                .execute(&mut *tx).await.map_err(to_domain_error)?;
        }
        tx.commit().await.map_err(to_domain_error)?;
        Ok(Some(ActivatedInvitation {
            user,
            invitation_id: row.get("invitation_id"),
            invited_by: row.get("invited_by"),
            role,
            group_ids: groups,
        }))
    }
}

fn validate_invitation(
    email: &str,
    username: &str,
    role: Option<&str>,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    if email.is_empty()
        || email.len() > 320
        || email.chars().any(|c| c.is_whitespace() || c.is_control())
        || !email.rsplit_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.')
        })
        || username.is_empty()
        || username.chars().count() > 320
        || username.chars().any(char::is_control)
    {
        return Err(DomainError::invalid(
            "invitation",
            "a valid email and username are required",
        ));
    }
    if expires_at - now < Duration::minutes(1) || expires_at - now > MAX_INVITATION_LIFETIME {
        return Err(DomainError::invalid(
            "expires_at",
            "invitation expiry must be within twenty-four hours",
        ));
    }
    if role
        .is_some_and(|role| !matches!(role, "tenant_admin" | "user_support" | "security_auditor"))
    {
        return Err(DomainError::invalid(
            "role",
            "role cannot be assigned by invitation",
        ));
    }
    Ok(())
}
