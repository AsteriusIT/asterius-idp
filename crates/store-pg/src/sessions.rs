//! Sessions, over PostgreSQL.
//!
//! Two statements carry the security properties. [`PgSessionRepository::rotate`]
//! is one `update` that changes the id, so there is never an instant where both
//! the old and the new one work — that is the session-fixation defence, and two
//! statements would open exactly the window it exists to close.
//! [`PgSessionRepository::revoke`] uses `coalesce` so the *first* reason
//! survives: the first answer to "why was I signed out" is the true one, and a
//! later sweep overwriting it with `expired` would lose the interesting fact.

use crate::error::to_domain_error;
use asterius_domain::{
    AuthenticationMethod, ClientId, DomainError, Participant, Session, SessionRepository,
    SessionRevocation, TenantId,
};
use sqlx::postgres::PgPool;
use time::{Duration, OffsetDateTime};

/// [`SessionRepository`] over PostgreSQL, scoped to one tenant.
#[derive(Debug, Clone)]
pub struct PgSessionRepository {
    pool: PgPool,
    tenant: TenantId,
}

impl PgSessionRepository {
    /// Scopes a repository to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Drops this tenant's sessions that are past their absolute deadline.
    ///
    /// Only the absolute clock: an idle session may still be revived by use,
    /// and deleting it would sign somebody out who was about to come back.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the delete fails.
    pub async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64, DomainError> {
        let result = sqlx::query!(
            "delete from sessions where tenant_id = $1 and expires_at <= $2",
            self.tenant.as_str(),
            now
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected())
    }

    fn methods(stored: &[String]) -> Vec<AuthenticationMethod> {
        // An unrecognised `amr` is dropped rather than failing the load. It was
        // written by some version of this server, and refusing to read a
        // session because one label is unfamiliar would sign a user out during
        // a rolling deployment.
        stored
            .iter()
            .filter_map(|value| AuthenticationMethod::parse(value))
            .collect()
    }
}

impl PgSessionRepository {
    /// Every session this account has, newest first (`ast-f7m.6`).
    ///
    /// Revoked and expired ones included: an operator asking "why is this
    /// person still signed in somewhere" needs to see the sessions that ended
    /// as well as the ones that have not, and a list that hid them would make
    /// a revocation that already happened look like one that did not.
    ///
    /// Answers [`asterius_domain::SessionSummary`] and not [`Session`],
    /// because the caller is the admin API and `session_id` is the lookup key
    /// — see `asterius_domain::administration` for why it is not on that side
    /// of the port.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the query fails.
    pub async fn summaries_for_user(
        &self,
        user: uuid::Uuid,
    ) -> Result<Vec<asterius_domain::SessionSummary>, DomainError> {
        let rows = sqlx::query!(
            "select public_sid, created_at, authenticated_at, last_seen_at, expires_at,
                    acr, amr, revoked_at, revocation_reason
             from sessions
             where tenant_id = $1 and user_id = $2
             order by created_at desc",
            self.tenant.as_str(),
            user
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(rows
            .into_iter()
            .map(|row| asterius_domain::SessionSummary {
                public_sid: row.public_sid,
                created_at: row.created_at,
                authenticated_at: row.authenticated_at,
                last_seen_at: row.last_seen_at,
                expires_at: row.expires_at,
                amr: row
                    .amr
                    .iter()
                    .filter_map(|method| AuthenticationMethod::parse(method))
                    .collect(),
                acr: row.acr,
                // The stored spelling, through the enum and back out again:
                // a reason the database holds and this build does not know is
                // rendered as nothing rather than as a word a screen would
                // present as meaningful.
                revoked: row.revoked_at.and_then(|at| {
                    row.revocation_reason
                        .as_deref()
                        .and_then(SessionRevocation::parse)
                        .map(|reason| (at, reason.as_str()))
                }),
            })
            .collect())
    }

    /// The session a `sid` names, whatever state it is in.
    ///
    /// The `sid` is what a relying party and the console both hold; the
    /// digest is what this table is keyed by. One index resolves the first to
    /// the second (`unique (tenant_id, public_sid)`), and this is the only
    /// place that does it for an administrative caller.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the query fails.
    pub async fn digest_of_sid(&self, public_sid: &str) -> Result<Option<String>, DomainError> {
        sqlx::query_scalar!(
            "select session_id from sessions where tenant_id = $1 and public_sid = $2",
            self.tenant.as_str(),
            public_sid
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)
    }

    /// Every live session of an account, by digest, newest first.
    ///
    /// The digests and not the rows: the caller revokes each one and reads its
    /// participant list, and both take a digest.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the query fails.
    pub async fn live_digests_for_user(
        &self,
        user: uuid::Uuid,
        now: OffsetDateTime,
    ) -> Result<Vec<String>, DomainError> {
        sqlx::query_scalar!(
            "select session_id from sessions
             where tenant_id = $1 and user_id = $2
               and revoked_at is null and expires_at > $3
             order by created_at desc",
            self.tenant.as_str(),
            user,
            now
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)
    }
}

#[async_trait::async_trait]
impl SessionRepository for PgSessionRepository {
    async fn begin(&self, session: &Session) -> Result<(), DomainError> {
        let amr: Vec<String> = session.amr.iter().map(|m| m.as_str().to_owned()).collect();
        sqlx::query!(
            "insert into sessions
                 (tenant_id, session_id, public_sid, user_id, created_at,
                  authenticated_at, last_seen_at, expires_at, idle_expires_at,
                  acr, amr)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            self.tenant.as_str(),
            session.id_digest,
            session.public_sid,
            session.user,
            session.created_at,
            session.authenticated_at,
            session.last_seen_at,
            session.expires_at,
            session.idle_expires_at,
            session.acr.as_deref(),
            &amr,
        )
        .execute(&self.pool)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("session id already exists".to_owned())
            }
            _ => to_domain_error(error),
        })?;
        Ok(())
    }

    async fn find(&self, id_digest: &str) -> Result<Option<Session>, DomainError> {
        let row = sqlx::query!(
            "select session_id, public_sid, user_id, created_at, authenticated_at,
                    last_seen_at, expires_at, idle_expires_at, acr, amr,
                    revoked_at, revocation_reason
               from sessions
              where tenant_id = $1 and session_id = $2",
            self.tenant.as_str(),
            id_digest,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(row.map(|row| Session {
            tenant: self.tenant.clone(),
            id_digest: row.session_id,
            public_sid: row.public_sid,
            user: row.user_id,
            created_at: row.created_at,
            authenticated_at: row.authenticated_at,
            last_seen_at: row.last_seen_at,
            expires_at: row.expires_at,
            idle_expires_at: row.idle_expires_at,
            acr: row.acr,
            amr: Self::methods(&row.amr),
            revoked: row.revoked_at.map(|at| {
                (
                    at,
                    row.revocation_reason
                        .as_deref()
                        .and_then(SessionRevocation::parse)
                        // A row revoked with a reason this binary does not know
                        // is still revoked. Losing the label is survivable;
                        // treating it as live is not.
                        .unwrap_or(SessionRevocation::Administrative),
                )
            }),
        }))
    }

    async fn touch(
        &self,
        id_digest: &str,
        now: OffsetDateTime,
        idle: Duration,
    ) -> Result<(), DomainError> {
        // The new deadline is computed here rather than as `$3 + interval`,
        // so the arithmetic is the same one `Session::status` does and there
        // is no chance of PostgreSQL and Rust disagreeing about it.
        let idle_expires_at = now + idle;
        let updated = sqlx::query!(
            "update sessions
                set last_seen_at = $3, idle_expires_at = $4
              where tenant_id = $1
                and session_id = $2
                and revoked_at is null
                and expires_at > $3
                and idle_expires_at > $3",
            self.tenant.as_str(),
            id_digest,
            now,
            idle_expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        if updated.rows_affected() == 1 {
            Ok(())
        } else {
            Err(DomainError::NotFound)
        }
    }

    async fn rotate(
        &self,
        old_digest: &str,
        new_digest: &str,
        methods: &[AuthenticationMethod],
        acr: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let amr: Vec<String> = methods.iter().map(|m| m.as_str().to_owned()).collect();

        // One statement. The old id stops resolving at the same instant the new
        // one starts, which is what makes this a fixation defence rather than a
        // window. The `where` also refuses to rotate something already revoked
        // or expired — a rotation is not a way to revive a session.
        let updated = sqlx::query!(
            "update sessions
                set session_id = $3,
                    authenticated_at = $4,
                    last_seen_at = $4,
                    amr = $5,
                    acr = $6
              where tenant_id = $1
                and session_id = $2
                and revoked_at is null
                and expires_at > $4",
            self.tenant.as_str(),
            old_digest,
            new_digest,
            now,
            &amr,
            acr,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        if updated.rows_affected() == 1 {
            Ok(())
        } else {
            Err(DomainError::NotFound)
        }
    }

    async fn revoke(
        &self,
        id_digest: &str,
        reason: SessionRevocation,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        // `coalesce` keeps the first reason. Revoking twice is ordinary — a
        // user signs out of a session an administrator had already ended — and
        // the first reason is the one that explains it.
        sqlx::query!(
            "update sessions
                set revoked_at = coalesce(revoked_at, $3),
                    revocation_reason = coalesce(revocation_reason, $4)
              where tenant_id = $1 and session_id = $2",
            self.tenant.as_str(),
            id_digest,
            now,
            reason.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    async fn revoke_all_for_user(
        &self,
        user: uuid::Uuid,
        reason: SessionRevocation,
        now: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let result = sqlx::query!(
            "update sessions
                set revoked_at = coalesce(revoked_at, $3),
                    revocation_reason = coalesce(revocation_reason, $4)
              where tenant_id = $1 and user_id = $2 and revoked_at is null",
            self.tenant.as_str(),
            user,
            now,
            reason.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected())
    }

    async fn record_participant(
        &self,
        id_digest: &str,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        sqlx::query!(
            "insert into session_clients (tenant_id, session_id, client_id, first_seen_at, last_seen_at)
             values ($1, $2, $3, $4, $4)
             on conflict (tenant_id, session_id, client_id)
             do update set last_seen_at = $4",
            self.tenant.as_str(),
            id_digest,
            client.as_str(),
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    async fn participants(&self, id_digest: &str) -> Result<Vec<Participant>, DomainError> {
        let rows = sqlx::query!(
            "select client_id, first_seen_at, last_seen_at
               from session_clients
              where tenant_id = $1 and session_id = $2
              order by first_seen_at",
            self.tenant.as_str(),
            id_digest,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(rows
            .into_iter()
            .map(|row| Participant {
                client: ClientId::new(row.client_id),
                first_seen_at: row.first_seen_at,
                last_seen_at: row.last_seen_at,
            })
            .collect())
    }
}
