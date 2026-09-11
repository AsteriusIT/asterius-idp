//! The subjects one stream carries events about (SSF 1.0 §8.1.3).
//!
//! # `default_subjects` is `NONE`, so this table is the whole permission
//!
//! This transmitter advertises `default_subjects: NONE` (§7.1,
//! `asterius_ssf::metadata`): a new stream carries events about nobody until a
//! receiver adds a subject with §8.1.3.2. So a row here is the only thing that
//! lets a subject identifier leave this server for a given receiver, and an
//! empty table for a stream is a stream that delivers nothing. That is the
//! safe default and it is the one that cannot be reached by forgetting to
//! write something.
//!
//! # The receiver is in every statement, as it is for the stream itself
//!
//! §8 makes management authorization "an association between the receiver and
//! the stream identifiers it may act on". Here the association is one step
//! removed — this table is keyed by stream, not by client — so every statement
//! that a receiver can reach goes through an `exists` against `ssf_streams`
//! carrying its `client_id`. Another receiver's stream is not a stream whose
//! subjects this repository returns and then refuses: it is a stream for which
//! nothing is written and nothing comes back, which is what §9.1's "answer the
//! same way whether or not it exists" needs underneath it.
//!
//! # Why a bound on how many subjects a stream may hold
//!
//! §8.1.3.2 puts no ceiling on a receiver's additions, and an endpoint one
//! access token reaches must have one: without it a receiver adds subject
//! identifiers until a tenant's database is full, and every added row also
//! costs an emitter one more §8.1.3.1 comparison per event. [`MAX_SUBJECTS`]
//! is that ceiling, and reaching it is a refusal a receiver can read rather
//! than a silent drop — §9.1's advice not to reveal whether a subject exists
//! is about *subjects*, not about the receiver's own quota.

use crate::error::to_domain_error;
use asterius_domain::{ClientId, DomainError, TenantId};
use asterius_ssf::stream::StreamId;
use asterius_ssf::subject::Subject;
use sqlx::postgres::PgPool;
use time::OffsetDateTime;

/// How many subjects one stream may carry events about.
///
/// Ten thousand. Large enough that a receiver watching a department never
/// meets it, small enough that a receiver that meets it is doing something an
/// operator should hear about — and bounded at all, which is the point: see
/// the module documentation.
pub const MAX_SUBJECTS: usize = 10_000;

/// One tenant's stream subject memberships.
#[derive(Debug, Clone)]
pub struct PgSsfSubjects {
    pool: PgPool,
    tenant: TenantId,
}

/// What an add did (§8.1.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    /// The subject is a member of the stream now. Also the answer when it
    /// already was: §8.1.3.2 describes a membership, not a counter, and a
    /// receiver repeating a request it is unsure about must not be punished
    /// for it.
    Member,
    /// No such stream for this receiver.
    NoSuchStream,
    /// The stream already holds [`MAX_SUBJECTS`] subjects.
    Full,
}

impl PgSsfSubjects {
    /// Scopes a repository to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Adds one subject to a stream (§8.1.3.2).
    ///
    /// Idempotent: the canonical key is the primary key, so adding a subject
    /// twice is one row and the second call reports [`Added::Member`] like the
    /// first. `verified` is recorded as the receiver asserted it and grants
    /// nothing — see [`asterius_ssf::management::SubjectRequest`].
    ///
    /// The count and the insert are one transaction, so two concurrent adds
    /// cannot both find room for the last slot.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the transaction fails, in which case
    /// nothing was written.
    pub async fn add(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
        subject: &Subject,
        verified: Option<bool>,
        now: OffsetDateTime,
    ) -> Result<Added, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        let owned = sqlx::query_scalar!(
            "select exists (select 1 from ssf_streams
                             where tenant_id = $1 and client_id = $2 and stream_id = $3)
                 as \"owned!\"",
            self.tenant.as_str(),
            receiver.as_str(),
            stream.as_str(),
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if !owned {
            return Ok(Added::NoSuchStream);
        }

        let key = subject.key();
        let held = sqlx::query_scalar!(
            "select count(*) as \"held!\"
               from ssf_stream_subjects
              where tenant_id = $1 and stream_id = $2 and subject_key <> $3",
            self.tenant.as_str(),
            stream.as_str(),
            &key,
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        // The subject being added is excluded from the count above, so a
        // re-add of a subject the stream already holds is never refused for
        // want of room it does not need.
        if held >= i64::try_from(MAX_SUBJECTS).unwrap_or(i64::MAX) {
            return Ok(Added::Full);
        }

        sqlx::query!(
            "insert into ssf_stream_subjects
                 (tenant_id, stream_id, subject_key, subject, verified, added_at)
             values ($1, $2, $3, $4, $5, $6)
             on conflict (tenant_id, stream_id, subject_key)
                 do update set verified = excluded.verified",
            self.tenant.as_str(),
            stream.as_str(),
            &key,
            subject.to_json(),
            verified,
            now,
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        transaction.commit().await.map_err(to_domain_error)?;
        Ok(Added::Member)
    }

    /// Removes one subject from a stream (§8.1.3.3).
    ///
    /// `true` is "this receiver's stream exists", not "a row went": §8.1.3.3
    /// answers 204 whether or not the subject was a member, and §9.1 requires
    /// that the two be indistinguishable. The caller therefore never learns
    /// how many rows were removed, because it has nothing it may do with the
    /// number.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the transaction fails, in which case the
    /// subject may still be a member and the caller must not answer 204.
    pub async fn remove(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
        subject: &Subject,
    ) -> Result<bool, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        let owned = sqlx::query_scalar!(
            "select exists (select 1 from ssf_streams
                             where tenant_id = $1 and client_id = $2 and stream_id = $3)
                 as \"owned!\"",
            self.tenant.as_str(),
            receiver.as_str(),
            stream.as_str(),
        )
        .fetch_one(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if !owned {
            return Ok(false);
        }

        sqlx::query!(
            "delete from ssf_stream_subjects
              where tenant_id = $1 and stream_id = $2 and subject_key = $3",
            self.tenant.as_str(),
            stream.as_str(),
            subject.key(),
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        transaction.commit().await.map_err(to_domain_error)?;
        Ok(true)
    }

    /// Every subject one stream carries events about (§8.1.3.1's left-hand
    /// side).
    ///
    /// Not scoped to a receiver: the caller is an emitter deciding where an
    /// event goes, and it reaches a stream by walking this tenant's streams
    /// rather than by answering a request. The receiver-scoped statements are
    /// the two above.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails, or [`DomainError::Invalid`]
    /// if a stored identifier is not one the model reads back — a membership
    /// this server cannot interpret is a failure, never a subject silently
    /// skipped, because skipping it means an event that should have been
    /// delivered quietly is not.
    pub async fn list(&self, stream: &StreamId) -> Result<Vec<Subject>, DomainError> {
        let rows = sqlx::query!(
            "select subject
               from ssf_stream_subjects
              where tenant_id = $1 and stream_id = $2
              order by subject_key",
            self.tenant.as_str(),
            stream.as_str(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        rows.into_iter()
            .map(|row| {
                Subject::from_json(&row.subject).map_err(|error| DomainError::Invalid {
                    field: "subject",
                    reason: error.to_string(),
                })
            })
            .collect()
    }

    /// Whether this stream carries events about `subject`, under §8.1.3.1's
    /// matching rules.
    ///
    /// The comparison is in Rust and not in SQL, because §8.1.3.1 is not
    /// equality: a complex subject matches one whose members are undefined on
    /// either side, which no index over a canonical key can answer.
    ///
    /// # Errors
    ///
    /// As [`Self::list`].
    pub async fn delivers_to(
        &self,
        stream: &StreamId,
        subject: &Subject,
    ) -> Result<bool, DomainError> {
        Ok(self
            .list(stream)
            .await?
            .iter()
            .any(|member| member.matches(subject)))
    }
}
