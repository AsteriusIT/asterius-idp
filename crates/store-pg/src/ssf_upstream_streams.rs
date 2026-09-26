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

    /// Records a successfully established stream exactly once. A retry or a
    /// competing setup cannot replace the stream identity or pinned endpoints.
    /// The caller must have authenticated to the upstream management API with
    /// a separate OAuth credential and validated its response first.
    ///
    /// # Errors
    /// Returns a storage error if persistence fails.
    pub async fn record_established(&self, stream: &UpstreamStream) -> Result<bool, DomainError> {
        if stream.peer_client_id != stream.issuer
            || stream.events_requested.is_empty()
            || stream.events_requested.len() > 16
            || stream.stream_id.is_empty()
            || stream.stream_id.len() > 255
            || (stream.delivery_method == asterius_ssf::stream::DELIVERY_POLL)
                != stream.poll_endpoint.is_some()
            || !matches!(
                stream.delivery_method.as_str(),
                asterius_ssf::stream::DELIVERY_POLL | asterius_ssf::stream::DELIVERY_PUSH
            )
        {
            return Err(DomainError::invalid(
                "ssf.upstream_stream",
                "invalid stream identity",
            ));
        }
        let result = sqlx::query(
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
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
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
