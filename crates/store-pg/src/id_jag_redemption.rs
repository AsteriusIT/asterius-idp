//! Exact ID-JAG subject resolution, consent gate and one-use replay claim.
//!
//! This is a storage primitive, not a grant handler. The caller must first
//! verify the ID-JAG with issuer-pinned keys and the request's DPoP proof.
//! A token cannot establish its own trust or create its own subject binding.
//! No consent writer is exposed here: an authenticated owner-approval flow
//! must exist before any redemption can pass the consent predicate.

use crate::error::to_domain_error;
use asterius_domain::audit::AuditEvent;
use asterius_domain::{DomainError, Grant, TenantId, sha256};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// One tenant's external subject bindings and authorized replay claims.
#[derive(Debug, Clone)]
pub struct PgIdJagRedemption {
    pool: PgPool,
    tenant: TenantId,
}

impl PgIdJagRedemption {
    pub(crate) const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
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
