//! Exact upstream OIDC identity bindings. Email is never a lookup key here.

use crate::{audit, error::to_domain_error};
use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::{DomainError, TenantId, UserId};
use sqlx::{Acquire as _, PgPool, Row as _};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcRefusal {
    ProviderUnavailable,
    Unlinked,
    DisabledUser,
    UsernameUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OidcResolution {
    User(UserId),
    Refused(OidcRefusal),
}

#[derive(Debug, Clone)]
pub struct OidcBinding {
    pub provider_id: String,
    pub issuer: String,
    pub upstream_subject: String,
    pub user_id: UserId,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct PgOidcBindings {
    pool: PgPool,
    tenant: TenantId,
}

impl PgOidcBindings {
    pub(crate) const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Resolve a verified ID token subject. The caller must verify the token
    /// signature and claims first. Unknown identities can create accounts only
    /// when the tenant provider explicitly enables registration. The generated
    /// account has no email, so an upstream email claim cannot seize one.
    /// A configured signed username claim is required and synchronised after
    /// exact issuer/subject binding resolution; it never selects an account.
    pub async fn resolve_or_create(
        &self,
        provider_id: &str,
        exact_issuer: &str,
        verified_subject: &str,
        expected_username_claim: Option<&str>,
        verified_username: Option<&str>,
    ) -> Result<OidcResolution, DomainError> {
        validate_identity(exact_issuer, verified_subject)?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        // Serialize first-login creation for the same provider. The provider
        // row lock also fences concurrent disable and issuer replacement.
        let policy: Option<(bool, Option<String>)> = sqlx::query_as(
            "select allow_registration, username_claim from oidc_identity_providers
             where tenant_id = $1 and provider_id = $2 and issuer = $3 and enabled
             for update",
        )
        .bind(self.tenant.as_str())
        .bind(provider_id)
        .bind(exact_issuer)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let Some((allow_registration, username_claim)) = policy else {
            return Ok(OidcResolution::Refused(OidcRefusal::ProviderUnavailable));
        };
        if username_claim.as_deref() != expected_username_claim {
            return Ok(OidcResolution::Refused(OidcRefusal::ProviderUnavailable));
        }
        let requested_username = if username_claim.is_some() {
            let Some(username) = verified_username.filter(|name| valid_username(name)) else {
                return Ok(OidcResolution::Refused(OidcRefusal::UsernameUnavailable));
            };
            Some(username)
        } else {
            None
        };
        let status: Option<(Uuid, String, String)> = sqlx::query_as(
            "select u.user_id, u.status, u.username from oidc_identity_bindings b
             join users u on u.tenant_id = b.tenant_id and u.user_id = b.user_id
             where b.tenant_id = $1 and b.provider_id = $2
               and b.issuer = $3 and b.upstream_subject = $4
             for update of u",
        )
        .bind(self.tenant.as_str())
        .bind(provider_id)
        .bind(exact_issuer)
        .bind(verified_subject)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if let Some((user, status, current_username)) = status {
            if status != "active" {
                return Ok(OidcResolution::Refused(OidcRefusal::DisabledUser));
            }
            if let Some(username) = requested_username.filter(|name| *name != current_username) {
                let renamed = sqlx::query(
                    "update users set username = $3 where tenant_id = $1 and user_id = $2",
                )
                .bind(self.tenant.as_str())
                .bind(user)
                .bind(username)
                .execute(&mut *tx)
                .await;
                if let Err(error) = renamed {
                    if matches!(&error, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")) {
                        return Ok(OidcResolution::Refused(OidcRefusal::UsernameUnavailable));
                    }
                    return Err(to_domain_error(error));
                }
                audit::append(
                    tx.acquire().await.map_err(to_domain_error)?,
                    AuditEvent::new(
                        self.tenant.clone(),
                        EventType::OIDC_USERNAME_SYNCED,
                        Outcome::Success,
                        Actor::System,
                        OffsetDateTime::now_utc(),
                    )
                    .subject(user.to_string())
                    .detail(Detail::new().text("provider_id", provider_id)),
                )
                .await?;
            }
            tx.commit().await.map_err(to_domain_error)?;
            return Ok(OidcResolution::User(UserId::new(user)));
        }
        if !allow_registration {
            return Ok(OidcResolution::Refused(OidcRefusal::Unlinked));
        }
        let id = Uuid::new_v4();
        let username = requested_username
            .map(str::to_owned)
            .unwrap_or_else(|| format!("oidc-{}", id.simple()));
        let inserted = sqlx::query(
            "insert into users (tenant_id, user_id, username, status)
             values ($1, $2, $3, 'active')
             on conflict (tenant_id, username) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(id)
        .bind(username)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if inserted.rows_affected() == 0 {
            return Ok(OidcResolution::Refused(OidcRefusal::UsernameUnavailable));
        }
        sqlx::query(
            "insert into oidc_identity_bindings
             (tenant_id, provider_id, issuer, upstream_subject, user_id)
             values ($1,$2,$3,$4,$5)",
        )
        .bind(self.tenant.as_str())
        .bind(provider_id)
        .bind(exact_issuer)
        .bind(verified_subject)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        audit::append(
            tx.acquire().await.map_err(to_domain_error)?,
            AuditEvent::new(
                self.tenant.clone(),
                EventType::OIDC_IDENTITY_CREATED,
                Outcome::Success,
                Actor::System,
                OffsetDateTime::now_utc(),
            )
            .subject(id.to_string())
            .detail(Detail::new().text("provider_id", provider_id)),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(OidcResolution::User(UserId::new(id)))
    }

    /// Explicit linking requires a separately authenticated local user or
    /// operator. This method never infers the target from upstream claims.
    pub async fn link(
        &self,
        provider_id: &str,
        exact_issuer: &str,
        verified_subject: &str,
        user: UserId,
        actor: Actor,
    ) -> Result<(), DomainError> {
        validate_identity(exact_issuer, verified_subject)?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        // Hold the provider row through the insert so a concurrent disable or
        // issuer change cannot slip between the policy check and the binding.
        let provider: Option<bool> = sqlx::query_scalar(
            "select enabled from oidc_identity_providers
             where tenant_id = $1 and provider_id = $2 and issuer = $3
             for update",
        )
        .bind(self.tenant.as_str())
        .bind(provider_id)
        .bind(exact_issuer)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if provider != Some(true) {
            return Err(DomainError::NotFound);
        }
        let status: Option<String> = sqlx::query_scalar(
            "select status from users where tenant_id = $1 and user_id = $2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if status.as_deref() != Some("active") {
            return Err(DomainError::invalid(
                "oidc_binding",
                "target user is not active",
            ));
        }
        sqlx::query(
            "insert into oidc_identity_bindings
             (tenant_id, provider_id, issuer, upstream_subject, user_id)
             values ($1,$2,$3,$4,$5)",
        )
        .bind(self.tenant.as_str())
        .bind(provider_id)
        .bind(exact_issuer)
        .bind(verified_subject)
        .bind(user.as_uuid())
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        audit::append(
            tx.acquire().await.map_err(to_domain_error)?,
            AuditEvent::new(
                self.tenant.clone(),
                EventType::OIDC_IDENTITY_LINKED,
                Outcome::Success,
                actor,
                OffsetDateTime::now_utc(),
            )
            .subject(user.as_uuid().to_string())
            .detail(Detail::new().text("provider_id", provider_id)),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)
    }

    pub async fn list_for_user(&self, user: UserId) -> Result<Vec<OidcBinding>, DomainError> {
        let rows = sqlx::query(
            "select provider_id, issuer, upstream_subject, user_id, created_at
             from oidc_identity_bindings where tenant_id = $1 and user_id = $2
             order by provider_id, issuer, upstream_subject",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        rows.into_iter()
            .map(|row| {
                Ok(OidcBinding {
                    provider_id: row.try_get("provider_id").map_err(to_domain_error)?,
                    issuer: row.try_get("issuer").map_err(to_domain_error)?,
                    upstream_subject: row.try_get("upstream_subject").map_err(to_domain_error)?,
                    user_id: UserId::new(row.try_get("user_id").map_err(to_domain_error)?),
                    created_at: row.try_get("created_at").map_err(to_domain_error)?,
                })
            })
            .collect()
    }

    pub async fn unlink(
        &self,
        provider_id: &str,
        exact_issuer: &str,
        verified_subject: &str,
        user: UserId,
        actor: Actor,
    ) -> Result<bool, DomainError> {
        validate_identity(exact_issuer, verified_subject)?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let result = sqlx::query(
            "delete from oidc_identity_bindings where tenant_id = $1
             and provider_id = $2 and issuer = $3 and upstream_subject = $4 and user_id = $5",
        )
        .bind(self.tenant.as_str())
        .bind(provider_id)
        .bind(exact_issuer)
        .bind(verified_subject)
        .bind(user.as_uuid())
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if result.rows_affected() == 0 {
            return Ok(false);
        }
        audit::append(
            tx.acquire().await.map_err(to_domain_error)?,
            AuditEvent::new(
                self.tenant.clone(),
                EventType::OIDC_IDENTITY_UNLINKED,
                Outcome::Success,
                actor,
                OffsetDateTime::now_utc(),
            )
            .subject(user.as_uuid().to_string())
            .detail(Detail::new().text("provider_id", provider_id)),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(true)
    }
}

fn validate_identity(issuer: &str, subject: &str) -> Result<(), DomainError> {
    if issuer.is_empty()
        || issuer.len() > 2048
        || subject.is_empty()
        || subject.len() > 1024
        || issuer.chars().any(char::is_control)
        || subject.chars().any(char::is_control)
    {
        return Err(DomainError::invalid("oidc_binding", "invalid identity"));
    }
    Ok(())
}

fn valid_username(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.chars().count() <= 320
        && !value.chars().any(|ch| {
            ch.is_control()
                || matches!(ch, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}

#[cfg(test)]
mod tests {
    use super::valid_username;

    #[test]
    fn configured_usernames_reject_empty_hidden_and_oversized_values() {
        assert!(valid_username("alice@example.test"));
        for invalid in ["", " alice", "alice\n", "a\u{202e}b"] {
            assert!(!valid_username(invalid));
        }
        assert!(!valid_username(&"a".repeat(321)));
    }
}
