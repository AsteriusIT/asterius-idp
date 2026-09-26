//! Durable receiver-side stream identity. No OAuth credential is stored here.
//!
//! Only an explicitly managed upstream setup may write a row. Inbound push
//! reception does not create one and cannot infer a stream from a signed SET.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId};
use sqlx::PgPool;
use time::OffsetDateTime;

/// A stream established with one operator-registered SSF transmitter.
#[derive(Debug, Clone)]
pub struct UpstreamStream {
    pub peer_client_id: String,
    pub issuer: String,
    pub jwks_uri: String,
    pub configuration_endpoint: String,
    pub status_endpoint: String,
    pub stream_id: String,
    pub delivery_method: String,
    pub poll_endpoint: Option<String>,
    pub audience: String,
    pub events_requested: Vec<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub last_polled_at: Option<OffsetDateTime>,
}

/// Durable outbound create intent. Its immutable fields are the trust and
/// request pins that a later authenticated list response must still match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSetupIntent {
    pub peer_client_id: String,
    pub issuer: String,
    pub jwks_uri: String,
    pub configuration_endpoint: String,
    pub status_endpoint: String,
    pub audience: String,
    pub events_requested: Vec<String>,
    pub delivery_method: String,
    pub started_at: OffsetDateTime,
}

/// One tenant's upstream stream records, scoped before any query is written.
#[derive(Debug, Clone)]
pub struct PgSsfUpstreamStreams {
    pool: PgPool,
    tenant: TenantId,
}

impl PgSsfUpstreamStreams {
    pub(crate) const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Commits a one-use setup intent before any remote POST. `false` means
    /// another call already reserved this peer, or a stream already exists;
    /// the caller must reconcile or stop, never send a second create request.
    pub async fn begin_setup(&self, intent: &UpstreamSetupIntent) -> Result<bool, DomainError> {
        if intent.peer_client_id != intent.issuer
            || intent.events_requested.is_empty()
            || intent.events_requested.len() > 16
            || intent.delivery_method != asterius_ssf::stream::DELIVERY_POLL
        {
            return Err(DomainError::invalid(
                "ssf.upstream_setup",
                "invalid setup intent",
            ));
        }
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let locked: Option<String> = sqlx::query_scalar(
            "select client_id from clients where tenant_id = $1 and client_id = $2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(&intent.peer_client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if locked.is_none() {
            tx.rollback().await.map_err(to_domain_error)?;
            return Ok(false);
        }
        let result = sqlx::query(
            "insert into ssf_receiver_upstream_setup_intents
                (tenant_id, peer_client_id, issuer, jwks_uri,
                 configuration_endpoint, status_endpoint, audience,
                 events_requested, delivery_method, started_at)
             select $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
              where not exists (
                  select 1 from ssf_receiver_upstream_streams
                   where tenant_id = $1 and peer_client_id = $2
              )
             on conflict (tenant_id, peer_client_id) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(&intent.peer_client_id)
        .bind(&intent.issuer)
        .bind(&intent.jwks_uri)
        .bind(&intent.configuration_endpoint)
        .bind(&intent.status_endpoint)
        .bind(&intent.audience)
        .bind(&intent.events_requested)
        .bind(&intent.delivery_method)
        .bind(intent.started_at)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Reads the exact pending intent that blocks another remote creation.
    pub async fn pending_setup(
        &self,
        peer_client_id: &str,
    ) -> Result<Option<UpstreamSetupIntent>, DomainError> {
        let row: Option<(
            String,
            String,
            String,
            String,
            String,
            String,
            Vec<String>,
            String,
            OffsetDateTime,
        )> = sqlx::query_as(
            "select peer_client_id, issuer, jwks_uri, configuration_endpoint,
                    status_endpoint, audience, events_requested,
                    delivery_method, started_at
               from ssf_receiver_upstream_setup_intents
              where tenant_id = $1 and peer_client_id = $2",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(row.map(|row| UpstreamSetupIntent {
            peer_client_id: row.0,
            issuer: row.1,
            jwks_uri: row.2,
            configuration_endpoint: row.3,
            status_endpoint: row.4,
            audience: row.5,
            events_requested: row.6,
            delivery_method: row.7,
            started_at: row.8,
        }))
    }

    /// Atomically records the verified remote stream and consumes only its
    /// matching pending intent. A stale metadata pin or competing completion
    /// cannot silently replace the stream identity.
    pub async fn finish_setup(
        &self,
        intent: &UpstreamSetupIntent,
        stream: &UpstreamStream,
    ) -> Result<bool, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let locked: Option<String> = sqlx::query_scalar(
            "select client_id from clients where tenant_id = $1 and client_id = $2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(&intent.peer_client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if locked.is_none() {
            tx.rollback().await.map_err(to_domain_error)?;
            return Ok(false);
        }
        let current: Option<(
            String,
            String,
            String,
            String,
            String,
            String,
            Vec<String>,
            String,
            OffsetDateTime,
        )> = sqlx::query_as(
            "select peer_client_id, issuer, jwks_uri, configuration_endpoint,
                    status_endpoint, audience, events_requested,
                    delivery_method, started_at
               from ssf_receiver_upstream_setup_intents
              where tenant_id = $1 and peer_client_id = $2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(&intent.peer_client_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let same = current.is_some_and(|row| {
            row.0 == intent.peer_client_id
                && row.1 == intent.issuer
                && row.2 == intent.jwks_uri
                && row.3 == intent.configuration_endpoint
                && row.4 == intent.status_endpoint
                && row.5 == intent.audience
                && row.6 == intent.events_requested
                && row.7 == intent.delivery_method
                && row.8 == intent.started_at
        });
        if !same
            || stream.peer_client_id != intent.peer_client_id
            || stream.issuer != intent.issuer
            || stream.jwks_uri != intent.jwks_uri
            || stream.configuration_endpoint != intent.configuration_endpoint
            || stream.status_endpoint != intent.status_endpoint
            || stream.audience != intent.audience
            || stream.events_requested != intent.events_requested
            || stream.delivery_method != intent.delivery_method
            || stream.stream_id.is_empty()
            || stream.stream_id.len() > 255
            || stream.poll_endpoint.is_none()
        {
            tx.rollback().await.map_err(to_domain_error)?;
            return Ok(false);
        }
        let inserted = sqlx::query(
            "insert into ssf_receiver_upstream_streams
                (tenant_id, peer_client_id, issuer, jwks_uri,
                 configuration_endpoint, status_endpoint, stream_id,
                 delivery_method, poll_endpoint, audience, events_requested,
                 created_at, updated_at, last_polled_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             on conflict (tenant_id, peer_client_id) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(&stream.peer_client_id)
        .bind(&stream.issuer)
        .bind(&stream.jwks_uri)
        .bind(&stream.configuration_endpoint)
        .bind(&stream.status_endpoint)
        .bind(&stream.stream_id)
        .bind(&stream.delivery_method)
        .bind(&stream.poll_endpoint)
        .bind(&stream.audience)
        .bind(&stream.events_requested)
        .bind(stream.created_at)
        .bind(stream.updated_at)
        .bind(stream.last_polled_at)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if inserted.rows_affected() != 1 {
            tx.rollback().await.map_err(to_domain_error)?;
            return Ok(false);
        }
        sqlx::query("delete from ssf_receiver_upstream_setup_intents where tenant_id = $1 and peer_client_id = $2")
            .bind(self.tenant.as_str())
            .bind(&intent.peer_client_id)
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(true)
    }

    /// Returns the configured peer's persisted stream, if any.
    ///
    /// # Errors
    /// Storage errors fail closed.
    pub async fn find(&self, peer_client_id: &str) -> Result<Option<UpstreamStream>, DomainError> {
        let row: Option<(
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
            Vec<String>,
            OffsetDateTime,
            OffsetDateTime,
            Option<OffsetDateTime>,
        )> = sqlx::query_as(
            "select peer_client_id, issuer, jwks_uri, configuration_endpoint,
                    status_endpoint, stream_id, delivery_method, poll_endpoint,
                    audience, events_requested, created_at, updated_at, last_polled_at
               from ssf_receiver_upstream_streams
              where tenant_id = $1 and peer_client_id = $2",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(row.map(|row| UpstreamStream {
            peer_client_id: row.0,
            issuer: row.1,
            jwks_uri: row.2,
            configuration_endpoint: row.3,
            status_endpoint: row.4,
            stream_id: row.5,
            delivery_method: row.6,
            poll_endpoint: row.7,
            audience: row.8,
            events_requested: row.9,
            created_at: row.10,
            updated_at: row.11,
            last_polled_at: row.12,
        }))
    }

    /// Advances the health timestamp only for the exact stream still stored.
    /// A stale poll worker cannot update a replacement stream.
    ///
    /// # Errors
    /// Returns a storage error if the update fails.
    pub async fn mark_polled(
        &self,
        peer_client_id: &str,
        stream_id: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let result = sqlx::query(
            "update ssf_receiver_upstream_streams
                set last_polled_at = $4, updated_at = $4
              where tenant_id = $1 and peer_client_id = $2 and stream_id = $3
                and delivery_method = 'urn:ietf:rfc:8936'",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(stream_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }
}
