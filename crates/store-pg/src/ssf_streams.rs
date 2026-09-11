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
use asterius_jose::{Kek, KeyBinding, RowSecret, WrappedKey};
use asterius_ssf::push::AuthorizationHeader;
use asterius_ssf::stream::{Delivery, StreamConfiguration, StreamId, StreamStatus};
use sqlx::postgres::PgPool;
use std::sync::Arc;
use time::OffsetDateTime;

/// The outbox `kind` a queued SET is written under.
///
/// Named here because this is where it is read: `delete` abandons the rows a
/// stream still owes, and the delivery stories (`ast-0ju.6`, `ast-0ju.7`)
/// queue under the same constant, with `destination` set to the `stream_id`.
pub const SET_OUTBOX_KIND: &str = "ssf.set";

/// What a push delivery needs to know about a stream, and nothing more.
///
/// Read by the delivery worker, which holds an outbox row naming a
/// `stream_id` and no receiver. It carries the credential, so it does not
/// derive `Debug`: see [`AuthorizationHeader`], which does not render itself
/// either — belt and braces, because this type is the one that ends up in a
/// `tracing` field by accident.
#[derive(Clone)]
pub struct PushTarget {
    /// The receiver's endpoint (RFC 8935 §2.2).
    pub endpoint_url: String,
    /// What to present on every request (SSF 1.0 §6.1.1).
    pub authorization_header: Option<AuthorizationHeader>,
    /// Whether the stream is delivering (SSF 1.0 §8.1.2).
    pub status: StreamStatus,
}

impl std::fmt::Debug for PushTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushTarget")
            .field("status", &self.status)
            .field(
                "authorization_header",
                &self.authorization_header.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

/// What one stream has delivered, failed and still owes.
///
/// The per-stream half of "metrics per stream": the Prometheus counters are
/// per-family, because a stream identifier is a label a caller chooses and
/// `crate::observability` in the server crate keeps those out of the metric
/// store. See `0031_ssf_push_delivery.sql`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamStats {
    /// Whether the stream is delivering.
    pub status: StreamStatus,
    /// Why it is not delivering, where this server stopped it.
    ///
    /// This server's own words: a receiver's response body reaches it only
    /// through [`asterius_ssf::push::ReceiverError`], which has already reduced
    /// the code to a closed set and bounded the free text.
    pub reason: Option<String>,
    /// SETs the receiver has accepted, since the stream was created.
    pub delivered: i64,
    /// Deliveries that failed, retries included.
    pub failed: i64,
    /// SETs still owed: queued, being retried, or claimed by a worker.
    pub queue_depth: i64,
}

/// One stream as the console lists it (`ast-f7m.8`): who it belongs to,
/// how it delivers, and how it is doing.
///
/// The management API's `StreamConfiguration` is a receiver's view and
/// carries the push endpoint and the sealed credential; this is an
/// operator's view and carries neither. The endpoint URL is left out on
/// purpose — a receiver may put a token in its query string, and
/// `crates/server/src/outbox/ssf.rs` keeps it out of logs for that reason —
/// so what an operator sees is the receiver's `client_id`, the delivery
/// method and the counters, which is what "is this receiver taking anything"
/// needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOverview {
    /// The stream.
    pub stream_id: StreamId,
    /// The receiver the stream belongs to.
    pub receiver: ClientId,
    /// RFC 8935 or RFC 8936.
    pub delivery: DeliveryMethod,
    /// §8.1.1's `events_requested`, as the receiver asked for it.
    pub events_requested: Vec<String>,
    /// §8.1.1's `description`.
    pub description: Option<String>,
    /// When the receiver created it.
    pub created_at: OffsetDateTime,
    /// When the status last changed, or `None` for a stream that has been
    /// enabled since creation.
    pub status_changed_at: Option<OffsetDateTime>,
    /// Status, reason and counters.
    pub stats: StreamStats,
}

/// How a subscribed stream takes delivery, as an emitter needs to know it.
///
/// Two variants and nothing else: the emitter's only decision is *which
/// queue* — the poll table (`ast-0ju.7`) or the outbox (`ast-0ju.6`). The
/// receiver's endpoint and credential are read by the push deliverer at
/// delivery time, never carried on the SET's way in, so a stream that changes
/// its endpoint between the two is posted to the new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMethod {
    /// RFC 8936: the receiver polls, so the SET waits in `ssf_poll_queue`.
    Poll,
    /// RFC 8935: this server posts, so the SET goes through the outbox.
    Push,
}

/// A stream that asked for one event type (`ast-0ju.8`).
///
/// What an emitter reads before it signs anything: the stream to queue on,
/// the receiver whose `sub` the SET is about (OIDC Core §8.1 — the subject
/// is derived under *this* receiver's sector), the `aud` to write, and which
/// queue takes it. Nothing here is the receiver's credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    /// The stream.
    pub stream_id: StreamId,
    /// The receiver the stream belongs to.
    pub receiver: ClientId,
    /// §8.1.1's `aud`, as it was settled at creation.
    pub audience: Vec<String>,
    /// Which queue the SET goes to.
    pub delivery: DeliveryMethod,
}

/// What §8.1.4.2's interval check decided.
///
/// Three answers rather than an `Option`, because "no such stream for this
/// receiver" is §8.1.4.2's 404 and "not yet" is its 429, and an endpoint that
/// could not tell them apart would answer one of them wrongly — either
/// telling a receiver that somebody else's stream exists, or hiding a real
/// stream behind a rate limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationClaim {
    /// The interval has elapsed and the instant has been written: the caller
    /// owes this stream one verification event.
    Granted(Box<Subscription>),
    /// Verified too recently. How long until the next one is admitted, never
    /// less than a second so that a `Retry-After` of `0` cannot invite an
    /// immediate retry.
    TooSoon {
        /// Seconds to wait.
        retry_after: i64,
    },
    /// No such stream for this receiver.
    NoSuchStream,
}

/// One tenant's SSF streams.
#[derive(Clone)]
pub struct PgSsfStreams {
    pool: PgPool,
    tenant: TenantId,
    kek: Arc<dyn Kek>,
}

impl std::fmt::Debug for PgSsfStreams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgSsfStreams")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgSsfStreams {
    /// Scopes a repository to `tenant`.
    ///
    /// `kek` is what seals and opens a push stream's `authorization_header`;
    /// see [`asterius_jose::RowSecret::SsfPushAuthorization`].
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId, kek: Arc<dyn Kek>) -> Self {
        Self { pool, tenant, kek }
    }

    /// Seals a receiver's credential for one stream, or nothing.
    ///
    /// The stream identifier is bound into the ciphertext, so a row copied
    /// over another stream's row stops decrypting rather than presenting one
    /// receiver's credential to another's endpoint.
    async fn seal(
        &self,
        stream: &StreamId,
        delivery: &Delivery,
    ) -> Result<Option<WrappedKey>, DomainError> {
        let Delivery::Push {
            authorization_header: Some(header),
            ..
        } = delivery
        else {
            return Ok(None);
        };
        let binding = KeyBinding::row_secret(
            &self.tenant,
            RowSecret::SsfPushAuthorization,
            stream.as_str(),
        );
        self.kek
            .wrap(binding, header.expose().as_bytes())
            .await
            .map(Some)
            .map_err(|e| DomainError::Storage(Box::new(e)))
    }

    /// Opens a stored credential.
    ///
    /// A row that does not open is an error and never a stream delivered
    /// without its `Authorization`: SSF 1.0 §6.1.1 makes presenting it
    /// mandatory, so a delivery that silently dropped it would be refused by
    /// the receiver with `authentication_failed` and look like the receiver's
    /// fault.
    async fn open(
        &self,
        stream: &StreamId,
        sealed: Option<WrappedKey>,
    ) -> Result<Option<AuthorizationHeader>, DomainError> {
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        let binding = KeyBinding::row_secret(
            &self.tenant,
            RowSecret::SsfPushAuthorization,
            stream.as_str(),
        );
        let plaintext = self
            .kek
            .unwrap(binding, &sealed)
            .await
            .map_err(|e| DomainError::Storage(Box::new(e)))?;
        let text = std::str::from_utf8(&plaintext).map_err(|_| {
            DomainError::invalid(
                "ssf_streams.authorization_header_ciphertext",
                "a stored push credential is not text",
            )
        })?;
        AuthorizationHeader::from_storage(text)
            .map(Some)
            .map_err(|_| {
                DomainError::invalid(
                    "ssf_streams.authorization_header_ciphertext",
                    "a stored push credential is not a header value this server can send",
                )
            })
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
        let sealed = self.seal(&stream.stream_id, &stream.delivery).await?;
        sqlx::query!(
            "insert into ssf_streams
                 (tenant_id, stream_id, client_id, audience, events_requested,
                  delivery_method, delivery_endpoint_url, description,
                  inactivity_timeout_seconds,
                  authorization_header_ciphertext, authorization_header_nonce,
                  authorization_header_kek_id)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            self.tenant.as_str(),
            stream.stream_id.as_str(),
            receiver.as_str(),
            &audience,
            &stream.events_requested,
            stream.delivery.method(),
            stream.delivery.endpoint_url(),
            stream.description.as_deref(),
            timeout,
            sealed.as_ref().map(WrappedKey::ciphertext),
            sealed.as_ref().map(WrappedKey::nonce),
            sealed.as_ref().map(WrappedKey::kek_id),
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
                    delivery_endpoint_url, description, inactivity_timeout_seconds,
                    authorization_header_ciphertext, authorization_header_nonce,
                    authorization_header_kek_id
               from ssf_streams
              where tenant_id = $1 and client_id = $2 and stream_id = $3",
            self.tenant.as_str(),
            receiver.as_str(),
            stream.as_str(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let Some(row) = row else {
            return Ok(None);
        };
        let sealed = wrapped(
            row.authorization_header_kek_id,
            row.authorization_header_nonce,
            row.authorization_header_ciphertext,
        )?;
        let header = self.open(stream, sealed).await?;
        configuration(
            &row.stream_id,
            row.audience,
            row.events_requested,
            delivery(&row.delivery_method, row.delivery_endpoint_url, header)?,
            row.description,
            row.inactivity_timeout_seconds,
        )
        .map(Some)
    }

    /// What a push delivery needs, by stream identifier alone (`ast-0ju.6`).
    ///
    /// The one read here with no `client_id` in its `WHERE` clause, and the
    /// module's opening argument says why that is not a hole: the caller is
    /// the delivery worker, holding an outbox row this server wrote, and the
    /// receiver is not a party to the call — it is whoever the stream says it
    /// is. A `client_id` argument here would have to come from the outbox row,
    /// which is to say from this same server, so it would check a value
    /// against itself.
    ///
    /// `None` covers "no such stream" and "not a push stream" in one answer:
    /// a poll stream has nothing for a pusher to do, and a stream deleted
    /// between the queueing and the delivery must not be delivered to
    /// (§8.1.1.5).
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails or the credential does not
    /// open, and [`DomainError::Invalid`] if the row holds a status this build
    /// does not know.
    pub async fn for_delivery(&self, stream: &StreamId) -> Result<Option<PushTarget>, DomainError> {
        let row = sqlx::query!(
            "select delivery_endpoint_url, status,
                    authorization_header_ciphertext, authorization_header_nonce,
                    authorization_header_kek_id
               from ssf_streams
              where tenant_id = $1 and stream_id = $2
                and delivery_method = $3",
            self.tenant.as_str(),
            stream.as_str(),
            asterius_ssf::stream::DELIVERY_PUSH,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let Some(row) = row else {
            return Ok(None);
        };
        let Some(endpoint_url) = row.delivery_endpoint_url else {
            // The schema's own check makes a push stream without an endpoint
            // impossible, so this is a row written around it.
            return Err(DomainError::invalid(
                "ssf_streams.delivery_endpoint_url",
                "a stored push stream has no endpoint",
            ));
        };
        let status = StreamStatus::parse(&row.status).ok_or_else(|| {
            DomainError::invalid(
                "ssf_streams.status",
                "a stored stream status is not one SSF 1.0 §8.1.2 defines",
            )
        })?;
        let sealed = wrapped(
            row.authorization_header_kek_id,
            row.authorization_header_nonce,
            row.authorization_header_ciphertext,
        )?;
        Ok(Some(PushTarget {
            endpoint_url,
            authorization_header: self.open(stream, sealed).await?,
            status,
        }))
    }

    /// Stops delivering on a stream, and says why (SSF 1.0 §8.1.2).
    ///
    /// Written by the delivery worker when a SET has exhausted RFC 8935
    /// §2.4's retries: the SET itself is a dead letter either way, and pausing
    /// is what stops the next hundred from becoming dead letters too.
    ///
    /// Idempotent, and it never *un*-pauses: `status = 'enabled'` is the only
    /// row this touches, so a stream an operator disabled stays disabled and a
    /// second failing delivery does not overwrite the first one's reason —
    /// the reason an operator wants is the one that stopped the stream.
    ///
    /// `reason` is this server's own words. A receiver's response body reaches
    /// it only through [`asterius_ssf::push::ReceiverError`], which reduces it
    /// to a code and bounded text.
    ///
    /// `false` means the stream was already not enabled, or is gone.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    pub async fn pause(
        &self,
        stream: &StreamId,
        reason: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let affected = sqlx::query!(
            "update ssf_streams
                set status = 'paused', status_reason = $3, status_changed_at = $4
              where tenant_id = $1 and stream_id = $2 and status = 'enabled'",
            self.tenant.as_str(),
            stream.as_str(),
            reason,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        Ok(affected > 0)
    }

    /// Counts one delivery attempt against its stream.
    ///
    /// Two counters rather than one signed number, because "nothing has ever
    /// been delivered and forty have failed" and "forty have been delivered
    /// and forty have failed" are different receivers and a difference would
    /// render them the same.
    ///
    /// A stream that has been deleted counts nothing and is not an error: the
    /// delivery that was in flight is the caller's to record in the outbox,
    /// and §8.1.1.5 already says a deleted stream delivers nothing more.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    pub async fn count_attempt(
        &self,
        stream: &StreamId,
        delivered: bool,
    ) -> Result<(), DomainError> {
        sqlx::query!(
            "update ssf_streams
                set delivered_count = delivered_count + case when $3 then 1 else 0 end,
                    failed_count = failed_count + case when $3 then 0 else 1 end
              where tenant_id = $1 and stream_id = $2",
            self.tenant.as_str(),
            stream.as_str(),
            delivered,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    /// One receiver's view of how its stream is doing.
    ///
    /// The receiver is in the `WHERE` clause, as everywhere else in the
    /// management direction: a stream's delivery history says how often this
    /// server has reached that receiver, which is not another receiver's to
    /// read.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails, [`DomainError::Invalid`]
    /// for a status this build does not know.
    pub async fn stats(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
    ) -> Result<Option<StreamStats>, DomainError> {
        let row = sqlx::query!(
            "select s.status, s.status_reason, s.delivered_count, s.failed_count,
                    (select count(*) from outbox o
                      where o.tenant_id = s.tenant_id
                        and o.kind = $4
                        and o.destination = s.stream_id
                        and o.status in ('pending', 'failed', 'claimed')) as \"queued!\"
               from ssf_streams s
              where s.tenant_id = $1 and s.client_id = $2 and s.stream_id = $3",
            self.tenant.as_str(),
            receiver.as_str(),
            stream.as_str(),
            SET_OUTBOX_KIND,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        row.map(|row| {
            Ok(StreamStats {
                status: StreamStatus::parse(&row.status).ok_or_else(|| {
                    DomainError::invalid(
                        "ssf_streams.status",
                        "a stored stream status is not one SSF 1.0 §8.1.2 defines",
                    )
                })?,
                reason: row.status_reason,
                delivered: row.delivered_count,
                failed: row.failed_count,
                queue_depth: row.queued,
            })
        })
        .transpose()
    }

    /// Every stream of the tenant, whoever holds it, with its delivery
    /// figures (`ast-f7m.8`).
    ///
    /// The one listing with no `client_id` in its `WHERE` clause, and the
    /// module's opening argument says why that is not a hole: the caller is
    /// the admin API, acting for an operator of the *tenant*, whose authority
    /// (`admin.ssf:read`) is over every receiver's arrangement to be told
    /// about the tenant's users. It renders no credential and no endpoint —
    /// see [`StreamOverview`].
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails, [`DomainError::Invalid`]
    /// for a stored row this build cannot read back.
    pub async fn overview(&self) -> Result<Vec<StreamOverview>, DomainError> {
        let rows = sqlx::query!(
            "select s.stream_id, s.client_id, s.delivery_method, s.events_requested,
                    s.description, s.created_at, s.status, s.status_reason,
                    s.status_changed_at, s.delivered_count, s.failed_count,
                    (select count(*) from outbox o
                      where o.tenant_id = s.tenant_id
                        and o.kind = $2
                        and o.destination = s.stream_id
                        and o.status in ('pending', 'failed', 'claimed')) as \"queued!\"
               from ssf_streams s
              where s.tenant_id = $1
              order by s.created_at, s.stream_id",
            self.tenant.as_str(),
            SET_OUTBOX_KIND,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        rows.into_iter()
            .map(|row| {
                Ok(StreamOverview {
                    stream_id: parse_stream_id(&row.stream_id)?,
                    receiver: ClientId::new(&row.client_id),
                    delivery: parse_delivery_method(&row.delivery_method)?,
                    events_requested: row.events_requested,
                    description: row.description,
                    created_at: row.created_at,
                    status_changed_at: row.status_changed_at,
                    stats: StreamStats {
                        status: parse_status(&row.status)?,
                        reason: row.status_reason,
                        delivered: row.delivered_count,
                        failed: row.failed_count,
                        queue_depth: row.queued,
                    },
                })
            })
            .collect()
    }

    /// One stream by identifier alone, as an emitter sees it (`ast-f7m.8`).
    ///
    /// What the verification event needs: the receiver, the audience and the
    /// queue. No `client_id` predicate, for the reason [`Self::overview`]
    /// gives — the caller is an operator of the tenant, not a receiver — and
    /// a `disabled` stream is returned like any other, because §8.1.4's
    /// verification is precisely the thing one sends to find out whether a
    /// stream that is not delivering could.
    ///
    /// # Errors
    ///
    /// As [`Self::overview`].
    pub async fn subscription(
        &self,
        stream: &StreamId,
    ) -> Result<Option<Subscription>, DomainError> {
        let row = sqlx::query!(
            "select stream_id, client_id, audience, delivery_method
               from ssf_streams
              where tenant_id = $1 and stream_id = $2",
            self.tenant.as_str(),
            stream.as_str(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        row.map(|row| {
            Ok(Subscription {
                stream_id: parse_stream_id(&row.stream_id)?,
                receiver: ClientId::new(&row.client_id),
                audience: row.audience,
                delivery: parse_delivery_method(&row.delivery_method)?,
            })
        })
        .transpose()
    }

    /// An operator's change of status (SSF 1.0 §8.1.2, `ast-f7m.8`).
    ///
    /// The counterpart of [`Self::pause`], which is the worker's and only
    /// ever goes one way. This one goes both ways and overwrites the reason
    /// — an operator re-enabling a stream is stating that the worker's
    /// reason no longer holds, and a stream paused by hand carries the hand's
    /// reason. `enabled` clears the reason: a delivering stream with a stale
    /// "the receiver answered 400" beside it is a screen that lies.
    ///
    /// `false` is "no such stream in this tenant".
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    pub async fn set_status(
        &self,
        stream: &StreamId,
        status: StreamStatus,
        reason: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let reason = match status {
            StreamStatus::Enabled => None,
            StreamStatus::Paused | StreamStatus::Disabled => reason,
        };
        let affected = sqlx::query!(
            "update ssf_streams
                set status = $3, status_reason = $4, status_changed_at = $5
              where tenant_id = $1 and stream_id = $2",
            self.tenant.as_str(),
            stream.as_str(),
            status.as_str(),
            reason,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        Ok(affected > 0)
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
                    delivery_endpoint_url, description, inactivity_timeout_seconds,
                    authorization_header_ciphertext, authorization_header_nonce,
                    authorization_header_kek_id
               from ssf_streams
              where tenant_id = $1 and client_id = $2
              order by created_at, stream_id",
            self.tenant.as_str(),
            receiver.as_str(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let mut streams = Vec::with_capacity(rows.len());
        for row in rows {
            let stream_id = StreamId::parse(&row.stream_id).ok_or_else(|| {
                DomainError::invalid(
                    "ssf_streams.stream_id",
                    "a stored stream identifier is not one this server issues",
                )
            })?;
            let sealed = wrapped(
                row.authorization_header_kek_id,
                row.authorization_header_nonce,
                row.authorization_header_ciphertext,
            )?;
            let header = self.open(&stream_id, sealed).await?;
            streams.push(configuration(
                &row.stream_id,
                row.audience,
                row.events_requested,
                delivery(&row.delivery_method, row.delivery_endpoint_url, header)?,
                row.description,
                row.inactivity_timeout_seconds,
            )?);
        }
        Ok(streams)
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
        // Re-sealed rather than left alone: an update carries the whole
        // `delivery` object (§8.1.1.3 and §8.1.1.4), so a stream that now has
        // no credential must stop holding its old one — a secret nothing
        // presents any more is a secret kept for no reason.
        let sealed = self.seal(&stream.stream_id, &stream.delivery).await?;
        let affected = sqlx::query!(
            "update ssf_streams
                set events_requested = $4,
                    delivery_method = $5,
                    delivery_endpoint_url = $6,
                    description = $7,
                    inactivity_timeout_seconds = $8,
                    authorization_header_ciphertext = $9,
                    authorization_header_nonce = $10,
                    authorization_header_kek_id = $11
              where tenant_id = $1 and client_id = $2 and stream_id = $3",
            self.tenant.as_str(),
            receiver.as_str(),
            stream.stream_id.as_str(),
            &stream.events_requested,
            stream.delivery.method(),
            stream.delivery.endpoint_url(),
            stream.description.as_deref(),
            timeout,
            sealed.as_ref().map(WrappedKey::ciphertext),
            sealed.as_ref().map(WrappedKey::nonce),
            sealed.as_ref().map(WrappedKey::kek_id),
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        Ok(affected > 0)
    }

    /// This stream's status and the reason it was last given (§8.1.2.1).
    ///
    /// `None` is "no such stream for this receiver", for the reason
    /// [`Self::find`] gives: the receiver is in the `WHERE` clause, so another
    /// receiver's stream is a row that does not come back rather than one this
    /// method has to refuse.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails, or [`DomainError::Invalid`]
    /// if the stored status is not one §8.1.2 defines — a row this server
    /// cannot interpret is a failure, never a stream silently treated as
    /// enabled.
    pub async fn status(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
    ) -> Result<Option<(StreamStatus, Option<String>)>, DomainError> {
        let row = sqlx::query!(
            "select status, status_reason
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
            let status = StreamStatus::parse(&row.status).ok_or_else(|| DomainError::Invalid {
                field: "status",
                reason: "a stored stream status is not one SSF 1.0 §8.1.2 defines".to_owned(),
            })?;
            Ok((status, row.status_reason))
        })
        .transpose()
    }

    /// Writes a stream's status *for the receiver that owns it* (§8.1.2.2).
    /// `false` is "no such stream for this receiver".
    ///
    /// The counterpart of [`Self::set_status`], which is the console's: that
    /// one is tenant-scoped because an operator acts on any stream of the
    /// tenant, and it clears the reason when a stream is re-enabled. This one
    /// carries the `client_id` — §8 makes the management API "an association
    /// between the receiver and the stream identifiers it may act on", so
    /// another receiver's stream must not be a row this statement can reach —
    /// and it keeps the reason the receiver gave, whichever status it asked
    /// for: §8.1.2.2 makes `reason` the receiver's own sentence, and
    /// §8.1.2.1 reads it back.
    ///
    /// Nothing is flushed here and nothing is dropped here. Re-enabling a
    /// stream releases what it held by making the queue readable again — the
    /// held rows were never removed — and disabling one stops events at the
    /// point they are enqueued. Both are [`crate::PgSsfPoll`]'s doing, which
    /// is what keeps "what `paused` means" a single decision rather than one
    /// this method and that one could come to disagree about.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails, in which case the status
    /// is unchanged and the caller must not report the new one.
    pub async fn set_status_for(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
        status: StreamStatus,
        reason: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let affected = sqlx::query!(
            "update ssf_streams
                set status = $4, status_reason = $5, status_changed_at = $6
              where tenant_id = $1 and client_id = $2 and stream_id = $3",
            self.tenant.as_str(),
            receiver.as_str(),
            stream.as_str(),
            status.as_str(),
            reason,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        Ok(affected > 0)
    }

    /// Claims one receiver-requested verification (SSF 1.0 §8.1.4.2).
    ///
    /// One statement, and that is the point: the interval check and the
    /// instant it is measured from next time are the same `UPDATE`, so two
    /// requests arriving together cannot both read "last verified long ago"
    /// and both be admitted. A read followed by a write would make
    /// `min_verification_interval` advisory under concurrency, which is the
    /// one condition a receiver can create on purpose.
    ///
    /// The `client_id` is in the predicate for the reason the module
    /// documentation gives: another receiver's stream is not a row this
    /// statement can reach, so §8.1.4.2's 404 falls out rather than being
    /// enforced above.
    ///
    /// A `paused` or `disabled` stream is claimed like any other: §8.1.4 is
    /// how a receiver finds out whether a stream that is not delivering
    /// could, and the queue decides what happens to the SET afterwards
    /// (§8.1.2 holds it while paused).
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the statement fails, in which case nothing
    /// was written and no verification is owed.
    pub async fn claim_verification(
        &self,
        receiver: &ClientId,
        stream: &StreamId,
        min_interval: time::Duration,
        now: OffsetDateTime,
    ) -> Result<VerificationClaim, DomainError> {
        let earliest = now - min_interval;
        let claimed = sqlx::query!(
            "update ssf_streams
                set last_verification_at = $4
              where tenant_id = $1 and client_id = $2 and stream_id = $3
                and (last_verification_at is null or last_verification_at <= $5)
          returning stream_id, client_id, audience, delivery_method",
            self.tenant.as_str(),
            receiver.as_str(),
            stream.as_str(),
            now,
            earliest,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        if let Some(row) = claimed {
            return Ok(VerificationClaim::Granted(Box::new(Subscription {
                stream_id: parse_stream_id(&row.stream_id)?,
                receiver: ClientId::new(&row.client_id),
                audience: row.audience,
                delivery: parse_delivery_method(&row.delivery_method)?,
            })));
        }

        // Nothing was updated: either the stream is not this receiver's, or
        // the interval has not elapsed. The second read is what tells them
        // apart, and it runs only on the path that is already refusing.
        let existing = sqlx::query!(
            "select last_verification_at
               from ssf_streams
              where tenant_id = $1 and client_id = $2 and stream_id = $3",
            self.tenant.as_str(),
            receiver.as_str(),
            stream.as_str(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let Some(row) = existing else {
            return Ok(VerificationClaim::NoSuchStream);
        };
        let last = row.last_verification_at.unwrap_or(now);
        let wait = (last + min_interval) - now;
        Ok(VerificationClaim::TooSoon {
            retry_after: wait.whole_seconds().max(1),
        })
    }

    /// The streams that asked for `event`, across every receiver of the tenant.
    ///
    /// The one read in this repository with no receiver in its `WHERE`
    /// clause, and the reason is the same as [`Self::for_delivery`]'s: an
    /// emitter holds a cause — a session ended, a passkey was added — and no
    /// caller. Which receivers hear of it is what the streams say, and every
    /// stream that says so is read here.
    ///
    /// `events_requested` is matched as the receiver wrote it (§8.1.1), so a
    /// stream that asked for a type before this build could emit it starts
    /// receiving it now, without asking again — which is why the column keeps
    /// the whole request rather than the intersection. A `disabled` stream
    /// (§8.1.2) is not returned: nothing is delivered on it and nothing is
    /// held for it. A `paused` one *is*: §8.1.2 makes paused a state a stream
    /// leaves, and what was queued while it was paused is what it gets when
    /// it does.
    ///
    /// Ordered by creation, so the SETs of one cause are queued in a stable
    /// order and two runs of an emitter over the same streams produce the
    /// same trail.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails, or if a stored row is not
    /// one this server would have written.
    pub async fn subscribed(&self, event: &str) -> Result<Vec<Subscription>, DomainError> {
        let rows = sqlx::query!(
            "select stream_id, client_id, audience, delivery_method
               from ssf_streams
              where tenant_id = $1
                and $2 = any(events_requested)
                and status <> $3
              order by created_at, stream_id",
            self.tenant.as_str(),
            event,
            StreamStatus::Disabled.as_str(),
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        rows.into_iter()
            .map(|row| {
                Ok(Subscription {
                    stream_id: parse_stream_id(&row.stream_id)?,
                    receiver: ClientId::new(&row.client_id),
                    audience: row.audience,
                    delivery: parse_delivery_method(&row.delivery_method)?,
                })
            })
            .collect()
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

/// A stored `stream_id`, or the refusal every reader gives a row this server
/// would not have written.
fn parse_stream_id(raw: &str) -> Result<StreamId, DomainError> {
    StreamId::parse(raw).ok_or_else(|| {
        DomainError::invalid(
            "ssf_streams.stream_id",
            "a stored stream identifier is not one this server issues",
        )
    })
}

/// A stored `delivery_method`, as an emitter reads it.
fn parse_delivery_method(raw: &str) -> Result<DeliveryMethod, DomainError> {
    match raw {
        asterius_ssf::stream::DELIVERY_POLL => Ok(DeliveryMethod::Poll),
        asterius_ssf::stream::DELIVERY_PUSH => Ok(DeliveryMethod::Push),
        _ => Err(DomainError::invalid(
            "ssf_streams.delivery_method",
            "a stored delivery method is not one SSF 1.0 defines",
        )),
    }
}

/// A stored `status` (§8.1.2).
fn parse_status(raw: &str) -> Result<StreamStatus, DomainError> {
    StreamStatus::parse(raw).ok_or_else(|| {
        DomainError::invalid(
            "ssf_streams.status",
            "a stored stream status is not one SSF 1.0 §8.1.2 defines",
        )
    })
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

/// §8.1.1's `delivery`, out of the three columns that carry it.
///
/// Its own function rather than three more arguments to [`configuration`]: the
/// method, the endpoint and the credential are one member of §8.1.1 and are
/// only ever read together.
fn delivery(
    delivery_method: &str,
    delivery_endpoint_url: Option<String>,
    authorization_header: Option<AuthorizationHeader>,
) -> Result<Delivery, DomainError> {
    match (delivery_method, delivery_endpoint_url) {
        (asterius_ssf::stream::DELIVERY_POLL, None) => Ok(Delivery::Poll),
        (asterius_ssf::stream::DELIVERY_PUSH, Some(endpoint_url)) => Ok(Delivery::Push {
            endpoint_url,
            authorization_header,
        }),
        // The schema's own check refuses both halves of this, so reaching it
        // means the row was written by something other than this repository.
        _ => Err(DomainError::invalid(
            "ssf_streams.delivery_method",
            "a stored delivery method has no endpoint this server can use",
        )),
    }
}

/// One row, as the model.
fn configuration(
    stream_id: &str,
    audience: Vec<String>,
    events_requested: Vec<String>,
    delivery: Delivery,
    description: Option<String>,
    inactivity_timeout_seconds: Option<i32>,
) -> Result<StreamConfiguration, DomainError> {
    let stream_id = StreamId::parse(stream_id).ok_or_else(|| {
        DomainError::invalid(
            "ssf_streams.stream_id",
            "a stored stream identifier is not one this server issues",
        )
    })?;
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

/// The three sealed columns as one envelope, or none of them.
///
/// The schema's `ssf_streams_authorization_header_is_whole` check makes the
/// mixed case impossible, so reaching it means a row was written around the
/// schema — which fails the read rather than delivering without the header.
fn wrapped(
    kek_id: Option<String>,
    nonce: Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
) -> Result<Option<WrappedKey>, DomainError> {
    match (kek_id, nonce, ciphertext) {
        (None, None, None) => Ok(None),
        (Some(kek_id), Some(nonce), Some(ciphertext)) => {
            WrappedKey::from_parts(kek_id, nonce, ciphertext)
                .map(Some)
                .map_err(|e| DomainError::Storage(Box::new(e)))
        }
        _ => Err(DomainError::invalid(
            "ssf_streams.authorization_header_ciphertext",
            "a stored push credential is missing part of its envelope",
        )),
    }
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
