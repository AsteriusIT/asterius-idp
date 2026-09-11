//! The SETs one stream is holding for a receiver that polls (RFC 8936).
//!
//! `0030_ssf_poll_queue.sql` says why these rows are not outbox rows. What
//! this module adds is the three statements the polling endpoint makes, and
//! one property worth stating in Rust as well as in SQL: **nothing here
//! removes a row except the receiver**. A poll hands SETs over and counts the
//! handing over; it does not delete, it does not hide, it does not lease. A
//! receiver that crashes between reading a response and processing it polls
//! again and is handed the same SETs (§2.4), which is the behaviour every
//! at-least-once delivery in this server has and the only one that does not
//! lose a security signal to a restart.
//!
//! Every statement carries the tenant *and* the stream. The receiver is one
//! step further out — [`crate::PgSsfStreams::find`] is what decides that this
//! receiver may poll this stream, and the endpoint calls it first — so a
//! stream identifier that reached here has already been matched against the
//! caller's `client_id`.

use crate::error::to_domain_error;
use crate::outbox::PgTransaction;
use asterius_domain::{DomainError, TenantId};
use asterius_ssf::stream::StreamId;
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// One queued SET, as the polling endpoint renders it (§2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedSet {
    /// RFC 8417 §2's `jti`, which is the member name in the response.
    pub jti: String,
    /// The compact serialisation, as it was signed.
    pub jws: String,
}

/// What one batch of a poll returned, and whether there is more (§2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollBatch {
    /// The SETs, oldest first.
    pub sets: Vec<QueuedSet>,
    /// §2.3's `moreAvailable`: the stream is still holding SETs this batch did
    /// not carry.
    pub more_available: bool,
}

/// One tenant's poll queues.
#[derive(Debug, Clone)]
pub struct PgSsfPoll {
    pool: PgPool,
    tenant: TenantId,
}

impl PgSsfPoll {
    /// Scopes a queue to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Queues one SET for a stream, inside the caller's transaction.
    ///
    /// A `&mut` transaction and not the pool, for the reason
    /// [`crate::outbox::enqueue`] gives: the SET commits with the change it
    /// reports, so there is no window in which a session is revoked and the
    /// signal that says so was lost. The emitters of `ast-0ju.8` are the
    /// callers.
    ///
    /// A `jti` already queued for this stream is left alone rather than
    /// written twice: the identifier is the response's member name (§2.3), so
    /// a duplicate is not something a receiver could tell apart anyway.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the insert fails — including when the
    /// stream does not exist, which the foreign key refuses. The caller's
    /// transaction is left for the caller to roll back.
    pub async fn enqueue(
        &self,
        transaction: &mut PgTransaction<'_>,
        stream: &StreamId,
        jti: &str,
        jws: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        sqlx::query!(
            "insert into ssf_poll_queue (tenant_id, stream_id, jti, set_jws, queued_at)
             values ($1, $2, $3, $4, $5)
             on conflict (tenant_id, stream_id, jti) do nothing",
            self.tenant.as_str(),
            stream.as_str(),
            jti,
            jws,
            now,
        )
        .execute(&mut **transaction)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    /// The oldest `limit` SETs this stream is holding, and whether there are
    /// more (§2.3).
    ///
    /// Oldest first, because a stream's events only mean anything in order: a
    /// `session-revoked` that arrives before the sign-in it invalidates says
    /// the opposite of what happened. The same argument the outbox makes with
    /// its ordering key, made here by the `order by` — a poll queue has one
    /// ordering group per stream and needs no key to name it.
    ///
    /// The rows are *not* removed and *not* hidden: §2.4 has the receiver
    /// remove them by acknowledging them. What this does write is the count
    /// and the instant, so an operator can see a receiver that is being handed
    /// the same SET over and over.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the transaction fails.
    pub async fn deliver(
        &self,
        stream: &StreamId,
        limit: usize,
        now: OffsetDateTime,
    ) -> Result<PollBatch, DomainError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        let rows = sqlx::query!(
            "with taken as (
                 select jti
                   from ssf_poll_queue
                  where tenant_id = $1 and stream_id = $2
                  order by queued_at, jti
                  limit $3
             )
             update ssf_poll_queue queued
                set deliveries = queued.deliveries + 1,
                    delivered_at = $4
               from taken
              where queued.tenant_id = $1
                and queued.stream_id = $2
                and queued.jti = taken.jti
             returning queued.jti as \"jti!\",
                       queued.set_jws as \"set_jws!\",
                       queued.queued_at as \"queued_at!\"",
            self.tenant.as_str(),
            stream.as_str(),
            limit,
            now,
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        let held = count(&mut transaction, &self.tenant, stream).await?;
        transaction.commit().await.map_err(to_domain_error)?;

        let mut rows = rows;
        rows.sort_by(|left, right| (left.queued_at, &left.jti).cmp(&(right.queued_at, &right.jti)));
        let sets: Vec<QueuedSet> = rows
            .into_iter()
            .map(|row| QueuedSet {
                jti: row.jti,
                jws: row.set_jws,
            })
            .collect();
        let more_available = held > i64::try_from(sets.len()).unwrap_or(i64::MAX);
        Ok(PollBatch {
            sets,
            more_available,
        })
    }

    /// Removes the SETs a receiver acknowledged (§2.4).
    ///
    /// Returns how many rows went, which is not the same as how many
    /// identifiers were named: a receiver may acknowledge a `jti` twice, or
    /// one it invented, and neither is an error — §2.4 makes an
    /// acknowledgement a statement about the receiver's own state, not a
    /// request this transmitter can refuse.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the delete fails, in which case nothing was
    /// removed and the SETs are delivered again.
    pub async fn acknowledge(
        &self,
        stream: &StreamId,
        acknowledged: &[String],
    ) -> Result<u64, DomainError> {
        self.remove(stream, acknowledged).await
    }

    /// Retires the SETs a receiver reported an error for (§2.4).
    ///
    /// The same delete, under a different name and for a different reason: the
    /// receiver is saying it *cannot* process these, so handing them over
    /// again is a loop rather than a retry. The report itself — which SET,
    /// which `err` code, which description — is the endpoint's audit entry,
    /// and that entry is the only record left once the row is gone. See
    /// `0030_ssf_poll_queue.sql`.
    ///
    /// # Errors
    ///
    /// As [`Self::acknowledge`].
    pub async fn reject(&self, stream: &StreamId, rejected: &[String]) -> Result<u64, DomainError> {
        self.remove(stream, rejected).await
    }

    /// The delete both of the above make.
    async fn remove(&self, stream: &StreamId, jtis: &[String]) -> Result<u64, DomainError> {
        if jtis.is_empty() {
            return Ok(0);
        }
        let affected = sqlx::query!(
            "delete from ssf_poll_queue
              where tenant_id = $1 and stream_id = $2 and jti = any($3)",
            self.tenant.as_str(),
            stream.as_str(),
            jtis,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        Ok(affected)
    }

    /// Whether this stream is holding anything at all.
    ///
    /// What a long poll (§2.1's `returnImmediately: false`) waits on.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails.
    pub async fn has_pending(&self, stream: &StreamId) -> Result<bool, DomainError> {
        let held = sqlx::query_scalar!(
            "select count(*) from ssf_poll_queue
              where tenant_id = $1 and stream_id = $2",
            self.tenant.as_str(),
            stream.as_str(),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)?
        .unwrap_or(0);
        Ok(held > 0)
    }
}

/// How many SETs the stream is holding right now.
async fn count(
    transaction: &mut PgTransaction<'_>,
    tenant: &TenantId,
    stream: &StreamId,
) -> Result<i64, DomainError> {
    let held = sqlx::query_scalar!(
        "select count(*) from ssf_poll_queue
          where tenant_id = $1 and stream_id = $2",
        tenant.as_str(),
        stream.as_str(),
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(to_domain_error)?
    .unwrap_or(0);
    Ok(held)
}
