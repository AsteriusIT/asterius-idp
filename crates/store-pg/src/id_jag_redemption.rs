//! Exact ID-JAG subject resolution, consent gate and one-use replay claim.
//!
//! This is a storage primitive, not a grant handler. The caller must first
//! verify the ID-JAG with issuer-pinned keys and the request's DPoP proof.
//! A token cannot establish its own trust or create its own subject binding.
//! Consent is written only for the authenticated account owner, through a
//! tenant-scoped account page that checks fresh authentication and CSRF.

use crate::error::to_domain_error;
use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::{DomainError, Grant, SessionId, TenantId, sha256};
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// One tenant's external subject bindings and authorized replay claims.
#[derive(Debug, Clone)]
pub struct PgIdJagRedemption {
    pool: PgPool,
    tenant: TenantId,
}

fn validate_consent_inputs(
    issuer: &str,
    actor_client_id: &str,
    client_id: &str,
    resource: &str,
    scopes: &[String],
) -> Result<(), DomainError> {
    if issuer.is_empty()
        || issuer.len() > 2048
        || actor_client_id.is_empty()
        || actor_client_id.len() > 512
        || client_id.is_empty()
        || client_id.len() > 512
        || resource.is_empty()
        || resource.len() > 2048
        || scopes.is_empty()
        || scopes.len() > 32
        || scopes
            .iter()
            .any(|scope| scope.is_empty() || scope.len() > 255)
    {
        return Err(DomainError::invalid(
            "id_jag_consent",
            "invalid authorization tuple",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Audit records the same exact authorization tuple as the row.
async fn consent_audit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &TenantId,
    user_id: Uuid,
    session_digest: &str,
    issuer: &str,
    actor_client_id: &str,
    client_id: &str,
    resource: &str,
    scopes: &[String],
    event_type: EventType,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    crate::audit::append(
        transaction,
        AuditEvent::new(
            tenant.clone(),
            event_type,
            Outcome::Success,
            Actor::User(user_id.to_string()),
            now,
        )
        .session(SessionId::new(session_digest.to_owned()))
        .subject(user_id.to_string())
        .detail(
            Detail::new()
                .label("grant_type", "id_jag")
                .text("issuer", issuer)
                .text("actor_client_id", actor_client_id)
                .text("client_id", client_id)
                .text("resource", resource)
                .text("scopes", scopes.join(" ")),
        ),
    )
    .await
}

/// An active, exact downstream authorization chosen by the account owner.
#[derive(Debug, Clone)]
pub struct IdJagConsent {
    pub issuer: String,
    pub actor_client_id: String,
    pub client_id: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub expires_at: OffsetDateTime,
}

/// Maximum life of an owner approval. Redemption still requires a fresh,
/// verified ID-JAG and a current operator trust pin at the time of use.
pub const MAX_CONSENT_LIFETIME: Duration = Duration::days(30);

impl PgIdJagRedemption {
    pub(crate) const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Issuers with an operator-provisioned subject binding for this owner.
    /// The owner cannot create or alter these bindings from the account page.
    pub async fn bound_issuers(&self, user_id: Uuid) -> Result<Vec<String>, DomainError> {
        sqlx::query_scalar(
            "select distinct issuer from id_jag_subject_bindings
             where tenant_id = $1 and user_id = $2 order by issuer",
        )
        .bind(self.tenant.as_str())
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)
    }

    /// Live authorizations owned by this exact account, excluding revoked and
    /// expired rows. No upstream subject is exposed on this page.
    pub async fn consents_for_owner(
        &self,
        user_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<Vec<IdJagConsent>, DomainError> {
        let rows: Vec<(String, String, String, String, Vec<String>, OffsetDateTime)> =
            sqlx::query_as(
                "select issuer, actor_client_id, client_id, resource, scopes, expires_at
                 from id_jag_consents
                 where tenant_id = $1 and user_id = $2
                   and revoked_at is null and expires_at > $3
                 order by issuer, actor_client_id, client_id, resource",
            )
            .bind(self.tenant.as_str())
            .bind(user_id)
            .bind(now)
            .fetch_all(&self.pool)
            .await
            .map_err(to_domain_error)?;
        Ok(rows
            .into_iter()
            .map(
                |(issuer, actor_client_id, client_id, resource, scopes, expires_at)| IdJagConsent {
                    issuer,
                    actor_client_id,
                    client_id,
                    resource,
                    scopes,
                    expires_at,
                },
            )
            .collect())
    }

    /// Grants an exact actor/client/resource/scope tuple to this account only
    /// while a current operator subject binding and active local client exist.
    /// The consent row and audit chain record commit together.
    #[allow(clippy::too_many_arguments)] // The authorization tuple stays explicit at the write boundary.
    pub async fn grant_consent(
        &self,
        user_id: Uuid,
        session_digest: &str,
        issuer: &str,
        actor_client_id: &str,
        client_id: &str,
        resource: &str,
        scopes: &[String],
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        validate_consent_inputs(issuer, actor_client_id, client_id, resource, scopes)?;
        if expires_at <= now || expires_at > now + MAX_CONSENT_LIFETIME {
            return Err(DomainError::invalid("id_jag_consent", "invalid expiry"));
        }
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let written: Option<Uuid> = sqlx::query_scalar(
            "insert into id_jag_consents
                (tenant_id, user_id, issuer, actor_client_id, client_id, resource,
                 scopes, granted_at, expires_at, revoked_at)
             select $1, $2, $3, $4, $5, $6, $7, $8, $9, null
               from users u join clients c on c.tenant_id = u.tenant_id
                 and c.client_id = $5
              where u.tenant_id = $1 and u.user_id = $2 and u.status = 'active'
                and c.status = 'active'
                and exists (
                  select 1 from id_jag_subject_bindings b
                   where b.tenant_id = $1 and b.user_id = $2 and b.issuer = $3
                   for share
                )
              for share of u, c
             on conflict (tenant_id, user_id, issuer, actor_client_id, client_id, resource)
             do update set scopes = excluded.scopes,
                           granted_at = excluded.granted_at,
                           expires_at = excluded.expires_at,
                           revoked_at = null
             returning user_id",
        )
        .bind(self.tenant.as_str())
        .bind(user_id)
        .bind(issuer)
        .bind(actor_client_id)
        .bind(client_id)
        .bind(resource)
        .bind(scopes)
        .bind(now)
        .bind(expires_at)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if written.is_none() {
            transaction.rollback().await.map_err(to_domain_error)?;
            return Ok(false);
        }
        consent_audit(
            &mut transaction,
            &self.tenant,
            user_id,
            session_digest,
            issuer,
            actor_client_id,
            client_id,
            resource,
            scopes,
            EventType::CONSENT_GRANTED,
            now,
        )
        .await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(true)
    }

    /// Revokes one exact row only if it belongs to this account. A missing or
    /// previously revoked row is one indistinguishable `false` result.
    #[allow(clippy::too_many_arguments)] // The primary key is intentionally explicit.
    pub async fn revoke_consent(
        &self,
        user_id: Uuid,
        session_digest: &str,
        issuer: &str,
        actor_client_id: &str,
        client_id: &str,
        resource: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let revoked: Option<Vec<String>> = sqlx::query_scalar(
            "update id_jag_consents set revoked_at = $7
             where tenant_id = $1 and user_id = $2 and issuer = $3
               and actor_client_id = $4 and client_id = $5 and resource = $6
               and revoked_at is null
             returning scopes",
        )
        .bind(self.tenant.as_str())
        .bind(user_id)
        .bind(issuer)
        .bind(actor_client_id)
        .bind(client_id)
        .bind(resource)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        let Some(scopes) = revoked else {
            transaction.rollback().await.map_err(to_domain_error)?;
            return Ok(false);
        };
        consent_audit(
            &mut transaction,
            &self.tenant,
            user_id,
            session_digest,
            issuer,
            actor_client_id,
            client_id,
            resource,
            &scopes,
            EventType::GRANT_REVOKED,
            now,
        )
        .await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(true)
    }

    /// Binds one trusted issuer's exact `sub` to a local user. The caller must
    /// be an authenticated operator; this operation does not grant consent.
    /// An existing binding to another user is refused, never silently moved.
    ///
    /// # Errors
    /// Returns a storage error if the user or binding cannot be written.
    pub async fn bind_subject(
        &self,
        issuer: &str,
        upstream_subject: &str,
        user_id: Uuid,
    ) -> Result<(), DomainError> {
        if issuer.is_empty()
            || issuer.len() > 2048
            || upstream_subject.is_empty()
            || upstream_subject.len() > 512
        {
            return Err(DomainError::invalid("id_jag_subject", "invalid binding"));
        }
        let bound = sqlx::query_scalar::<_, Uuid>(
            "insert into id_jag_subject_bindings
                (tenant_id, issuer, upstream_subject, user_id)
             select $1, $2, $3, $4 from users
              where tenant_id = $1 and user_id = $4 and status = 'active'
             on conflict (tenant_id, issuer, upstream_subject)
             do update set user_id = id_jag_subject_bindings.user_id
               where id_jag_subject_bindings.user_id = excluded.user_id
             returning user_id",
        )
        .bind(self.tenant.as_str())
        .bind(issuer)
        .bind(upstream_subject)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        bound
            .map(|_| ())
            .ok_or_else(|| DomainError::invalid("id_jag_subject", "binding already exists"))
    }

    /// Removes one binding only while it still names the expected local user.
    ///
    /// # Errors
    /// Returns a storage error if the delete fails.
    pub async fn remove_subject(
        &self,
        issuer: &str,
        upstream_subject: &str,
        user_id: Uuid,
    ) -> Result<bool, DomainError> {
        let result = sqlx::query(
            "delete from id_jag_subject_bindings
             where tenant_id = $1 and issuer = $2 and upstream_subject = $3
               and user_id = $4",
        )
        .bind(self.tenant.as_str())
        .bind(issuer)
        .bind(upstream_subject)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Atomically reserves a verified issuer-scoped `jti` only when its exact
    /// subject maps to an active user with current consent for the pinned
    /// actor/client/resource and all requested scopes. `None` deliberately
    /// hides whether mapping, consent or replay failed. A caller must still
    /// check the operator allow-list and issue a DPoP-bound token.
    ///
    /// No handler invokes this yet. A future issuer should keep the resulting
    /// grant and audit write in the same transaction; claiming a one-use ID-JAG
    /// before those writes is safe against replay but can consume a grant on a
    /// later failure.
    ///
    /// # Errors
    /// Returns a storage error if the claim cannot be evaluated or written.
    #[allow(clippy::too_many_arguments)]
    pub async fn reserve_authorized(
        &self,
        issuer: &str,
        upstream_subject: &str,
        actor_client_id: &str,
        client_id: &str,
        resource: &str,
        scopes: &[String],
        jti: &str,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, DomainError> {
        if issuer.is_empty()
            || issuer.len() > 2048
            || upstream_subject.is_empty()
            || upstream_subject.len() > 512
            || jti.is_empty()
            || jti.len() > 255
            || scopes.is_empty()
            || scopes.len() > 32
            || expires_at <= now
        {
            return Err(DomainError::invalid("id_jag", "invalid redemption inputs"));
        }
        let jti_hash = sha256(jti.as_bytes());
        let user_id = sqlx::query_scalar::<_, Uuid>(
            "with eligible as (
                 select b.user_id
                   from id_jag_subject_bindings b
                   join users u on u.tenant_id = b.tenant_id
                               and u.user_id = b.user_id
                   join id_jag_consents c on c.tenant_id = b.tenant_id
                                         and c.user_id = b.user_id
                                         and c.issuer = b.issuer
                  where b.tenant_id = $1 and b.issuer = $2
                    and b.upstream_subject = $3
                    and u.status = 'active'
                    and c.actor_client_id = $4 and c.client_id = $5
                    and c.resource = $6 and c.scopes @> $7::text[]
                    and c.granted_at <= $8 and c.expires_at > $8
                    and c.revoked_at is null
                  for share of b, u, c
             )
             insert into id_jag_replays
                 (tenant_id, issuer, jti_hash, user_id, expires_at)
             select $1, $2, $9, eligible.user_id, $10 from eligible where true
             on conflict (tenant_id, issuer, jti_hash) do nothing
             returning user_id",
        )
        .bind(self.tenant.as_str())
        .bind(issuer)
        .bind(upstream_subject)
        .bind(actor_client_id)
        .bind(client_id)
        .bind(resource)
        .bind(scopes)
        .bind(now)
        .bind(&jti_hash[..])
        .bind(expires_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(user_id)
    }

    /// Resolves a pinned upstream subject for grant preparation. This is only
    /// a hint: `commit_issued` repeats the binding and consent predicates under
    /// row locks before it commits any authority.
    ///
    /// # Errors
    /// Returns a storage error if lookup fails.
    pub async fn resolve_subject(
        &self,
        issuer: &str,
        upstream_subject: &str,
    ) -> Result<Option<Uuid>, DomainError> {
        sqlx::query_scalar::<_, Uuid>(
            "select b.user_id from id_jag_subject_bindings b
             join users u on u.tenant_id = b.tenant_id and u.user_id = b.user_id
             where b.tenant_id = $1 and b.issuer = $2
               and b.upstream_subject = $3 and u.status = 'active'",
        )
        .bind(self.tenant.as_str())
        .bind(issuer)
        .bind(upstream_subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)
    }

    /// Commits one verified ID-JAG redemption after the caller has prepared
    /// and signed a DPoP-bound access token. The signed bytes must remain
    /// private until this returns `true`. The replay claim, current consent,
    /// grant, and audit chain append either all commit or all roll back.
    /// `false` deliberately conflates absent binding, absent/revoked consent,
    /// changed local user, and replay.
    ///
    /// # Errors
    /// Returns a storage error if any write or commit fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_issued(
        &self,
        issuer: &str,
        upstream_subject: &str,
        actor_client_id: &str,
        client_id: &str,
        resource: &str,
        scopes: &[String],
        jti: &str,
        assertion_expires_at: OffsetDateTime,
        now: OffsetDateTime,
        grant: &Grant,
        event: AuditEvent,
    ) -> Result<bool, DomainError> {
        if grant.tenant != self.tenant
            || grant.client.as_str() != client_id
            || grant.user.is_none()
            || grant.claimed_at != Some(now)
            || grant.expires_at.is_none_or(|expiry| expiry <= now)
            || grant.resources.len() != 1
            || !grant.resources.contains(resource)
            || grant.scopes.len() != scopes.len()
            || !scopes.iter().all(|scope| grant.scopes.contains(scope))
            || event.tenant != self.tenant
            || event.grant.as_ref() != Some(&grant.id)
            || event.client.as_ref() != Some(&grant.client)
            || event.subject.as_deref() != grant.subject.as_ref().map(|s| s.as_str())
        {
            return Err(DomainError::invalid("id_jag", "grant or audit mismatch"));
        }
        if issuer.is_empty()
            || issuer.len() > 2048
            || upstream_subject.is_empty()
            || upstream_subject.len() > 512
            || jti.is_empty()
            || jti.len() > 255
            || scopes.is_empty()
            || scopes.len() > 32
            || assertion_expires_at <= now
        {
            return Err(DomainError::invalid("id_jag", "invalid redemption inputs"));
        }

        let jti_hash = sha256(jti.as_bytes());
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let user = sqlx::query_scalar::<_, Uuid>(
            "with eligible as (
                 select b.user_id
                   from id_jag_subject_bindings b
                   join users u on u.tenant_id = b.tenant_id and u.user_id = b.user_id
                   join id_jag_consents c on c.tenant_id = b.tenant_id
                                         and c.user_id = b.user_id and c.issuer = b.issuer
                  where b.tenant_id = $1 and b.issuer = $2
                    and b.upstream_subject = $3 and u.status = 'active'
                    and c.actor_client_id = $4 and c.client_id = $5
                    and c.resource = $6 and c.scopes @> $7::text[]
                    and c.granted_at <= $8 and c.expires_at > $8
                    and c.expires_at > clock_timestamp()
                    and c.revoked_at is null
                    and $10 > clock_timestamp()
                    and $11 > clock_timestamp()
                  for share of b, u, c
             )
             insert into id_jag_replays
                 (tenant_id, issuer, jti_hash, user_id, expires_at)
             select $1, $2, $9, eligible.user_id, $10 from eligible where true
             on conflict (tenant_id, issuer, jti_hash) do nothing
             returning user_id",
        )
        .bind(self.tenant.as_str())
        .bind(issuer)
        .bind(upstream_subject)
        .bind(actor_client_id)
        .bind(client_id)
        .bind(resource)
        .bind(scopes)
        .bind(now)
        .bind(&jti_hash[..])
        .bind(assertion_expires_at)
        .bind(grant.expires_at)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if user != grant.user.map(|id| *id.as_uuid()) {
            return Ok(false);
        }
        crate::grants::PgGrantRepository::insert_on(&mut transaction, &self.tenant, grant).await?;
        crate::audit::append(&mut transaction, event).await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(true)
    }

    /// Removes expired replay entries for this tenant after their assertions
    /// can no longer pass `exp` validation. The ID-JAG verifier uses JOSE's
    /// zero-leeway `exp` check, so exact expiry is the first safe purge time.
    ///
    /// # Errors
    /// Returns a storage error if deletion fails.
    pub async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64, DomainError> {
        let result =
            sqlx::query("delete from id_jag_replays where tenant_id = $1 and expires_at <= $2")
                .bind(self.tenant.as_str())
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(to_domain_error)?;
        Ok(result.rows_affected())
    }
}
