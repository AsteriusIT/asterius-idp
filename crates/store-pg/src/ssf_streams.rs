//! One receiver's SSF streams, over `PostgreSQL` (SSF 1.0 §8.1.1).
//!
//! # Every statement carries the receiver, not only the tenant
//!
//! §8 makes authorization at the management API "an association between the
//! receiver and the stream identifiers it may act on". That association is the
//! `client_id` column, and it is in the `WHERE` clause of every statement
//! here — including the read that a `PATCH` or a `DELETE` starts from. So
//! another receiver's stream is not a row this repository can return and then
//! have to refuse: it is a row that does not exist, which is exactly the 404
//! §8.1.1.2 asks for and the frontier `docs/threat-model.md` records.
//!
//! The tenant is the outer half of the same argument and comes from
//! [`crate::TenantScope`], as everywhere else in this crate.
//!
//! # What a delete has to take with it
//!
//! §8.1.1.5: a deleted stream delivers nothing more. A SET that is already
//! queued is therefore abandoned in the same transaction that removes the
//! row — not deleted, because the outbox is the delivery trail and an
//! operator asking "what happened to that signal" must find "the stream was
//! deleted" rather than nothing at all.

use crate::error::to_domain_error;
use asterius_domain::{ClientId, DomainError, TenantId};
use asterius_ssf::stream::{Delivery, StreamConfiguration, StreamId};
use sqlx::postgres::PgPool;

/// The outbox `kind` a queued SET is written under.
///
/// Named here because this is where it is read: `delete` abandons the rows a
/// stream still owes, and the delivery stories (`ast-0ju.6`, `ast-0ju.7`)
/// queue under the same constant, with `destination` set to the `stream_id`.
pub const SET_OUTBOX_KIND: &str = "ssf.set";

/// One tenant's SSF streams.
#[derive(Debug, Clone)]
pub struct PgSsfStreams {
    pool: PgPool,
    tenant: TenantId,
}

impl PgSsfStreams {
    /// Scopes a repository to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Stores a newly created stream (§8.1.1.1).
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] when this receiver already has a stream for
    /// this audience, which is the 409 §8.1.1.1 describes — raised by the
    /// unique index rather than by a count this method took first, so two
    /// concurrent creations cannot both find "no stream yet".
    ///
    /// [`DomainError::Storage`] for anything else the write refuses.
    pub async fn create(
        &self,
        receiver: &ClientId,
        stream: &StreamConfiguration,
    ) -> Result<(), DomainError> {
        let audience = sorted(&stream.audience);
        let timeout = timeout_seconds(stream)?;
        sqlx::query!(
            "insert into ssf_streams
                 (tenant_id, stream_id, client_id, audience, events_requested,
                  delivery_method, delivery_endpoint_url, description,
                  inactivity_timeout_seconds)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            self.tenant.as_str(),
            stream.stream_id.as_str(),
            receiver.as_str(),
            &audience,
            &stream.events_requested,
            stream.delivery.method(),
            stream.delivery.endpoint_url(),
            stream.description.as_deref(),
            timeout,
        )
        .execute(&self.pool)
        .await
        .map_err(conflict_or_storage)?;
        Ok(())
    }

    /// The stream this receiver's `stream_id` names (§8.1.1.2).
    ///
    /// `None` covers "no such stream" and "not this receiver's" in one
    /// answer, because the receiver is in the `WHERE` clause.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails, or
    /// [`DomainError::Invalid`] if the stored row is not one the model
    /// accepts — a row this server cannot render is a failure, never a stream
    /// silently skipped.
    pub async fn find(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
    ) -> Result<Option<StreamConfiguration>, DomainError> {
        let row = sqlx::query!(
            "select stream_id, audience, events_requested, delivery_method,
                    delivery_endpoint_url, description, inactivity_timeout_seconds
               from ssf_streams
              where tenant_id = $1 and client_id = $2 and stream_id = $3",
            self.tenant.as_str(),
            receiver.as_str(),
            stream.as_str(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        row.map(|row| {
            configuration(
                &row.stream_id,
                row.audience,
                row.events_requested,
                &row.delivery_method,
                row.delivery_endpoint_url,
                row.description,
                row.inactivity_timeout_seconds,
            )
        })
        .transpose()
    }

    /// Every stream this receiver holds (§8.1.1.2's `GET` with no
    /// `stream_id`).
    ///
    /// Ordered by creation, so a receiver reading the list twice sees the same
    /// order.
    ///
    /// # Errors
    ///
    /// As [`Self::find`].
    pub async fn list(&self, receiver: &ClientId) -> Result<Vec<StreamConfiguration>, DomainError> {
        let rows = sqlx::query!(
            "select stream_id, audience, events_requested, delivery_method,
                    delivery_endpoint_url, description, inactivity_timeout_seconds
               from ssf_streams
              where tenant_id = $1 and client_id = $2
              order by created_at, stream_id",
            self.tenant.as_str(),
            receiver.as_str(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        rows.into_iter()
            .map(|row| {
                configuration(
                    &row.stream_id,
                    row.audience,
                    row.events_requested,
                    &row.delivery_method,
                    row.delivery_endpoint_url,
                    row.description,
                    row.inactivity_timeout_seconds,
                )
            })
            .collect()
    }

    /// Writes an updated stream (§8.1.1.3 and §8.1.1.4).
    ///
    /// Only the receiver-supplied columns are in the `SET` list: `audience` is
    /// immutable and `stream_id` addresses the row, so an update cannot move a
    /// stream between receivers or audiences however wrong the caller is.
    ///
    /// `false` is "no such stream for this receiver", which is the 404 the
    /// caller answers.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    pub async fn save(
        &self,
        receiver: &ClientId,
        stream: &StreamConfiguration,
    ) -> Result<bool, DomainError> {
        let timeout = timeout_seconds(stream)?;
        let affected = sqlx::query!(
            "update ssf_streams
                set events_requested = $4,
                    delivery_method = $5,
                    delivery_endpoint_url = $6,
                    description = $7,
                    inactivity_timeout_seconds = $8
              where tenant_id = $1 and client_id = $2 and stream_id = $3",
            self.tenant.as_str(),
            receiver.as_str(),
            stream.stream_id.as_str(),
            &stream.events_requested,
            stream.delivery.method(),
            stream.delivery.endpoint_url(),
            stream.description.as_deref(),
            timeout,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        Ok(affected > 0)
    }

    /// Removes a stream and abandons what it still owed (§8.1.1.5).
    ///
    /// One transaction: the queued SETs are abandoned first and the row is
    /// removed last, so a crash between the two leaves a stream whose events
    /// are already stopped rather than a deleted stream whose events are still
    /// being delivered.
    ///
    /// `false` is "no such stream for this receiver".
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the transaction fails, in which case
    /// nothing was deleted and the caller must not answer 204.
    pub async fn delete(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
    ) -> Result<bool, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        // Abandoned rather than deleted: the outbox is the delivery trail, and
        // "this signal was never sent because the stream was deleted" is the
        // answer an operator needs during an incident.
        sqlx::query!(
            "update outbox
                set status = 'abandoned',
                    last_error = 'the stream was deleted (SSF 1.0 §8.1.1.5)'
              where tenant_id = $1
                and kind = $2
                and destination = $3
                and status in ('pending', 'failed', 'claimed')
                and exists (select 1 from ssf_streams
                             where tenant_id = $1
                               and client_id = $4
                               and stream_id = $3)",
            self.tenant.as_str(),
            SET_OUTBOX_KIND,
            stream.as_str(),
            receiver.as_str(),
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        let affected = sqlx::query!(
            "delete from ssf_streams
              where tenant_id = $1 and client_id = $2 and stream_id = $3",
            self.tenant.as_str(),
            receiver.as_str(),
            stream.as_str(),
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?
        .rows_affected();

        transaction.commit().await.map_err(to_domain_error)?;
        Ok(affected > 0)
    }
}

/// The audience as it is stored: sorted, because the unique index compares
/// whole arrays and the order of an audience carries no meaning.
fn sorted(audience: &[String]) -> Vec<String> {
    let mut sorted = audience.to_vec();
    sorted.sort();
    sorted.dedup();
    sorted
}

/// §8.1.1's `inactivity_timeout` as the column's type.
///
/// An `Err` rather than a silent clamp: the endpoint bounds the value long
/// before it reaches here, so a number that does not fit is this server
/// holding a stream it could not have accepted.
fn timeout_seconds(stream: &StreamConfiguration) -> Result<Option<i32>, DomainError> {
    stream
        .inactivity_timeout
        .map(|seconds| {
            i32::try_from(seconds).map_err(|_| {
                DomainError::invalid(
                    "inactivity_timeout",
                    "the inactivity timeout does not fit the column",
                )
            })
        })
        .transpose()
}

/// One row, as the model.
fn configuration(
    stream_id: &str,
    audience: Vec<String>,
    events_requested: Vec<String>,
    delivery_method: &str,
    delivery_endpoint_url: Option<String>,
    description: Option<String>,
    inactivity_timeout_seconds: Option<i32>,
) -> Result<StreamConfiguration, DomainError> {
    let stream_id = StreamId::parse(stream_id).ok_or_else(|| {
        DomainError::invalid(
            "ssf_streams.stream_id",
            "a stored stream identifier is not one this server issues",
        )
    })?;
    let delivery = match (delivery_method, delivery_endpoint_url) {
        (asterius_ssf::stream::DELIVERY_POLL, None) => Delivery::Poll,
        (asterius_ssf::stream::DELIVERY_PUSH, Some(endpoint_url)) => {
            Delivery::Push { endpoint_url }
        }
        // The schema's own check refuses both halves of this, so reaching it
        // means the row was written by something other than this repository.
        _ => {
            return Err(DomainError::invalid(
                "ssf_streams.delivery_method",
                "a stored delivery method has no endpoint this server can use",
            ));
        }
    };
    // The column's check keeps this positive; a negative one would be a row
    // written around the schema, and it fails the read for the reason the
    // module gives — a stream this server cannot render is not one it hides.
    let inactivity_timeout = inactivity_timeout_seconds
        .map(|seconds| {
            u64::try_from(seconds).map_err(|_| {
                DomainError::invalid(
                    "ssf_streams.inactivity_timeout_seconds",
                    "a stored inactivity timeout is not a positive number of seconds",
                )
            })
        })
        .transpose()?;
    Ok(StreamConfiguration {
        stream_id,
        audience,
        events_requested,
        delivery,
        description,
        inactivity_timeout,
    })
}

/// A unique violation is §8.1.1.1's 409; everything else is a storage
/// failure.
///
/// The code is `23505`, and it can only be the one unique index on this table:
/// the primary key is a freshly drawn 128-bit identifier, so a collision there
/// is not an event this maps for.
fn conflict_or_storage(error: sqlx::Error) -> DomainError {
    if let sqlx::Error::Database(database) = &error
        && database.code().as_deref() == Some("23505")
    {
        return DomainError::Conflict(
            "this receiver already has a stream for this audience".to_owned(),
        );
    }
    to_domain_error(error)
}
