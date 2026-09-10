//! Pushed authorization requests, over PostgreSQL.
//!
//! The interesting statement is `consume`: one `update ... where consumed_at
//! is null and expires_at > now returning ...`, so the check and the spend are
//! the same statement. FAPI 2.0 SP §5.3.2.2 Note 3 puts one-time use at the
//! completion of authorization rather than at page load, which means two tabs
//! may both *render* the consent screen — and exactly one may submit it.
//! Reading and then writing would let both submit, which is the race the
//! requirement exists to close.

use crate::error::to_domain_error;
use asterius_domain::{
    AuthRequestRepository, ClientId, Consumed, Continuation, DomainError, FirstPartyDestination,
    InteractionRecord, PushedRequest, TenantId,
};
use serde_json::Value;
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// [`AuthRequestRepository`] over PostgreSQL, scoped to one tenant.
#[derive(Debug, Clone)]
pub struct PgAuthRequestRepository {
    pool: PgPool,
    tenant: TenantId,
}

impl PgAuthRequestRepository {
    /// Scopes a repository to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Drops this tenant's expired and consumed rows.
    ///
    /// Per tenant, because `sql_audit` requires every statement over a
    /// tenant-scoped table to name `tenant_id` and that invariant has no
    /// exceptions.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the delete fails.
    pub async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64, DomainError> {
        let result = sqlx::query!(
            "delete from auth_requests where tenant_id = $1 and expires_at <= $2",
            self.tenant.as_str(),
            now
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected())
    }

    /// Turns a hex digest into the bytes the column holds.
    fn digest_bytes(digest: &str) -> Result<Vec<u8>, DomainError> {
        hex::decode(digest).map_err(|e| DomainError::invalid("request_uri", e.to_string()))
    }
}

#[async_trait::async_trait]
impl AuthRequestRepository for PgAuthRequestRepository {
    async fn push(&self, request: &PushedRequest) -> Result<(), DomainError> {
        let digest = Self::digest_bytes(&request.request_uri_digest)?;
        sqlx::query!(
            "insert into auth_requests
                 (tenant_id, request_uri_hash, client_id, parameters,
                  pushed_at, expires_at)
             values ($1, $2, $3, $4, $5, $6)",
            self.tenant.as_str(),
            digest,
            request.client.as_str(),
            request.parameters,
            request.pushed_at,
            request.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|error| match &error {
            // At 256 bits, a collision means the generator is broken, not that
            // we were unlucky. Surfacing it as a conflict rather than a generic
            // storage failure is what makes that visible.
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("request_uri already exists".to_owned())
            }
            _ => to_domain_error(error),
        })?;
        Ok(())
    }

    async fn consume(&self, digest: &str, now: OffsetDateTime) -> Result<Consumed, DomainError> {
        let digest = Self::digest_bytes(digest)?;

        // The spend. `consumed_at is null` in the predicate is what makes this
        // single-use: a second concurrent update matches no row.
        let spent = sqlx::query!(
            "update auth_requests
                set consumed_at = $3
              where tenant_id = $1
                and request_uri_hash = $2
                and consumed_at is null
                and expires_at > $3
             returning client_id, parameters, pushed_at, expires_at",
            self.tenant.as_str(),
            digest,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        if let Some(row) = spent {
            return Ok(Consumed::Request(Box::new(PushedRequest {
                tenant: self.tenant.clone(),
                request_uri_digest: hex::encode(&digest),
                client: ClientId::new(row.client_id),
                parameters: row.parameters,
                pushed_at: row.pushed_at,
                expires_at: row.expires_at,
            })));
        }

        // Nothing was spent. Which of the three reasons is a fact for the log,
        // not for the client: all three render the same error page, or an
        // enumeration oracle is exactly what the reference's entropy was for.
        let existing = sqlx::query!(
            "select consumed_at, expires_at from auth_requests
              where tenant_id = $1 and request_uri_hash = $2",
            self.tenant.as_str(),
            digest,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(match existing {
            None => Consumed::NotFound,
            Some(row) if row.consumed_at.is_some() => Consumed::AlreadyUsed,
            Some(_) => Consumed::Expired,
        })
    }

    async fn peek(
        &self,
        digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<PushedRequest>, DomainError> {
        let digest = Self::digest_bytes(digest)?;
        let row = sqlx::query!(
            "select client_id, parameters, pushed_at, expires_at
               from auth_requests
              where tenant_id = $1
                and request_uri_hash = $2
                and consumed_at is null
                and expires_at > $3",
            self.tenant.as_str(),
            digest,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(row.map(|row| PushedRequest {
            tenant: self.tenant.clone(),
            request_uri_digest: hex::encode(&digest),
            client: ClientId::new(row.client_id),
            parameters: row.parameters,
            pushed_at: row.pushed_at,
            expires_at: row.expires_at,
        }))
    }
}

#[async_trait::async_trait]
impl asterius_domain::InteractionRepository for PgAuthRequestRepository {
    async fn begin_interaction(
        &self,
        request_uri_digest: &str,
        interaction_digest: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let request = Self::digest_bytes(request_uri_digest)?;
        let interaction = Self::digest_bytes(interaction_digest)?;

        // `interaction_id_hash is null` in the predicate is what makes a second
        // `/authorize` on one `request_uri` a conflict rather than a re-key. A
        // read-then-write here would let two browsers race for one flow, and
        // the loser would be holding a cookie for a request the winner owns.
        let updated = sqlx::query!(
            "update auth_requests
                set interaction_id_hash = $3
              where tenant_id = $1
                and request_uri_hash = $2
                and interaction_id_hash is null
                and consumed_at is null
                and expires_at > $4",
            self.tenant.as_str(),
            request,
            interaction,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("interaction id already in use".to_owned())
            }
            _ => to_domain_error(error),
        })?;

        if updated.rows_affected() == 1 {
            return Ok(());
        }

        // Nothing matched. Distinguish "no such request" from "already has an
        // interaction" for the log; the caller renders one page for both.
        let existing = sqlx::query!(
            "select interaction_id_hash from auth_requests
              where tenant_id = $1 and request_uri_hash = $2",
            self.tenant.as_str(),
            request,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Err(match existing {
            Some(row) if row.interaction_id_hash.is_some() => {
                DomainError::Conflict("the request already has an interaction".to_owned())
            }
            _ => DomainError::NotFound,
        })
    }

    async fn by_interaction(
        &self,
        interaction_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<InteractionRecord>, DomainError> {
        let interaction = Self::digest_bytes(interaction_digest)?;
        let row = sqlx::query!(
            "select client_id, parameters, interaction_state, session_id, expires_at
               from auth_requests
              where tenant_id = $1
                and interaction_id_hash = $2
                and consumed_at is null
                and expires_at > $3",
            self.tenant.as_str(),
            interaction,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        if let Some(row) = row {
            return Ok(Some(InteractionRecord {
                tenant: self.tenant.clone(),
                continuation: Continuation::for_client(
                    ClientId::new(row.client_id),
                    row.parameters,
                ),
                state: row.interaction_state,
                session: row.session_id,
                expires_at: row.expires_at,
            }));
        }

        // The other table. An interaction is one of two things (ADR-0009) and
        // the browser's credential does not say which, so a miss here is a
        // question for the first-party rows rather than an answer.
        self.first_party_by_interaction(&interaction, now).await
    }

    async fn save_interaction_state(
        &self,
        interaction_digest: &str,
        state: &Value,
        session: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let interaction = Self::digest_bytes(interaction_digest)?;
        let updated = sqlx::query!(
            "update auth_requests
                set interaction_state = $3, session_id = coalesce($4, session_id)
              where tenant_id = $1
                and interaction_id_hash = $2
                and consumed_at is null
                and expires_at > $5",
            self.tenant.as_str(),
            interaction,
            state,
            session,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        if updated.rows_affected() == 1 {
            return Ok(());
        }

        let updated = sqlx::query!(
            "update first_party_interactions
                set interaction_state = $3, session_id = coalesce($4, session_id)
              where tenant_id = $1
                and interaction_id_hash = $2
                and consumed_at is null
                and expires_at > $5",
            self.tenant.as_str(),
            interaction,
            state,
            session,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        if updated.rows_affected() == 1 {
            Ok(())
        } else {
            // Expired or consumed mid-interaction. Progress must not
            // resurrect a request whose window has closed.
            Err(DomainError::NotFound)
        }
    }

    async fn complete_interaction(
        &self,
        interaction_digest: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let interaction = Self::digest_bytes(interaction_digest)?;
        // The same shape as `consume`, reached by the other credential:
        // `consumed_at is null` in the predicate is what makes exactly one of
        // two racing submissions win. Whichever loses gets zero rows and must
        // not send an authorization response.
        let spent = sqlx::query!(
            "update auth_requests
                set consumed_at = $3
              where tenant_id = $1
                and interaction_id_hash = $2
                and consumed_at is null
                and expires_at > $3",
            self.tenant.as_str(),
            interaction,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        if spent.rows_affected() == 1 {
            return Ok(());
        }

        let spent = sqlx::query!(
            "update first_party_interactions
                set consumed_at = $3
              where tenant_id = $1
                and interaction_id_hash = $2
                and consumed_at is null
                and expires_at > $3",
            self.tenant.as_str(),
            interaction,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        if spent.rows_affected() == 1 {
            Ok(())
        } else {
            Err(DomainError::NotFound)
        }
    }

    async fn destroy_interaction(&self, interaction_digest: &str) -> Result<(), DomainError> {
        let interaction = Self::digest_bytes(interaction_digest)?;
        sqlx::query!(
            "delete from auth_requests where tenant_id = $1 and interaction_id_hash = $2",
            self.tenant.as_str(),
            interaction,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        // Both tables, unconditionally. A destroy is what a browser mismatch
        // produces (FAPI 2.0 SP §6.5), and it must not depend on this
        // repository first working out which kind of interaction the id names:
        // the case where that lookup is wrong is exactly the case somebody is
        // being deceived in.
        sqlx::query!(
            "delete from first_party_interactions
              where tenant_id = $1 and interaction_id_hash = $2",
            self.tenant.as_str(),
            interaction,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        // Absent is success: destroying something already gone is the outcome
        // that was wanted.
        Ok(())
    }

    async fn begin_first_party_interaction(
        &self,
        interaction_digest: &str,
        destination: FirstPartyDestination,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let interaction = Self::digest_bytes(interaction_digest)?;
        sqlx::query!(
            "insert into first_party_interactions
                 (tenant_id, interaction_id_hash, destination, started_at, expires_at)
             values ($1, $2, $3, $4, $5)",
            self.tenant.as_str(),
            interaction,
            destination.as_str(),
            now,
            expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(|error| match &error {
            // At 256 bits this is a broken generator, not bad luck, and it is
            // worth being told apart from a storage failure.
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("interaction id already in use".to_owned())
            }
            _ => to_domain_error(error),
        })?;
        Ok(())
    }
}

impl PgAuthRequestRepository {
    /// The first-party half of [`by_interaction`](InteractionRepository::by_interaction).
    ///
    /// A row whose `destination` this binary cannot name is treated as no row
    /// at all: it was written by a newer binary, and the honest answer to "what
    /// is this interaction for" is that this process does not know. Sending the
    /// user somewhere of this binary's choosing would be answering a question
    /// nobody asked it.
    async fn first_party_by_interaction(
        &self,
        interaction: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<InteractionRecord>, DomainError> {
        let row = sqlx::query!(
            "select destination, interaction_state, session_id, expires_at
               from first_party_interactions
              where tenant_id = $1
                and interaction_id_hash = $2
                and consumed_at is null
                and expires_at > $3",
            self.tenant.as_str(),
            interaction,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let Some(row) = row else { return Ok(None) };
        let Some(destination) = FirstPartyDestination::parse(&row.destination) else {
            tracing::error!(
                tenant = %self.tenant,
                "an interaction names a first-party destination this build does not have"
            );
            return Ok(None);
        };

        Ok(Some(InteractionRecord {
            tenant: self.tenant.clone(),
            continuation: Continuation::FirstParty(destination),
            state: row.interaction_state,
            session: row.session_id,
            expires_at: row.expires_at,
        }))
    }
}
