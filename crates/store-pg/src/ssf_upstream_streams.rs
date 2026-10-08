//! Durable receiver-side stream identity. No OAuth credential is stored here.
//!
//! Only an explicitly managed upstream setup may write a row. Inbound push
//! reception does not create one and cannot infer a stream from a signed SET.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId, ct_eq};
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
    /// A durable remote DELETE intent; polling stops until readback proves
    /// the exact stream was removed and this row can be deleted.
    pub deletion_started_at: Option<OffsetDateTime>,
    pub last_verified_at: Option<OffsetDateTime>,
    pub last_challenge_verified_at: Option<OffsetDateTime>,
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

type SetupIntentRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Vec<String>,
    String,
    OffsetDateTime,
);

type UpstreamStreamRow = (
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
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
);

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
        self.begin_setup_owned(intent, None).await
    }
    pub async fn begin_setup_for_flow(&self, intent: &UpstreamSetupIntent, step: &crate::FlowApplyStep<'_>) -> Result<bool, DomainError> {
        self.begin_setup_owned(intent, Some(step)).await
    }
    // Peer row serialization, active flow reservation and durable intent ownership
    // must be checked before any caller can send an external create request.
    #[allow(clippy::too_many_lines)]
    async fn begin_setup_owned(&self, intent: &UpstreamSetupIntent, owner: Option<&crate::FlowApplyStep<'_>>) -> Result<bool, DomainError> {
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
        let reservation: Option<(uuid::Uuid,String,String)> = sqlx::query_as("select flow_id,node_id,state from flow_resource_links where tenant_id=$1 and resource_kind='stream' and resource_id=$2 and relation='managed'")
            .bind(self.tenant.as_str()).bind(&intent.peer_client_id).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        let owner_identity = owner.map(|step| (step.flow, step.node.to_owned()));
        if let Some(step) = owner {
            let active: bool = sqlx::query_scalar("select exists(select 1 from architecture_flows where tenant_id=$1 and flow_id=$2 and revision=$3 and apply_token=$4 and apply_deadline>clock_timestamp())")
                .bind(self.tenant.as_str()).bind(step.flow).bind(step.revision).bind(step.token).fetch_one(&mut *tx).await.map_err(to_domain_error)?;
            if !active || reservation.as_ref().map(|row| (row.0,row.1.clone())) != owner_identity {
                return Err(DomainError::Conflict("exact active flow stream reservation required".into()));
            }
        } else if reservation.as_ref().is_some_and(|row| row.2 == "pending") {
            return Err(DomainError::Conflict("stream setup belongs to an active architecture reservation".into()));
        }
        let existing_owner: Option<(Option<uuid::Uuid>,Option<String>)> = sqlx::query_as("select origin_flow,origin_node from ssf_receiver_upstream_setup_intents where tenant_id=$1 and peer_client_id=$2")
            .bind(self.tenant.as_str()).bind(&intent.peer_client_id).fetch_optional(&mut *tx).await.map_err(to_domain_error)?;
        if existing_owner.is_some_and(|existing| existing != (owner.map(|step| step.flow),owner.map(|step| step.node.to_owned()))) {
            return Err(DomainError::Conflict("uncertain stream setup has another origin; reconcile it with its owner".into()));
        }
        let result = sqlx::query(
            "insert into ssf_receiver_upstream_setup_intents
                (tenant_id, peer_client_id, issuer, jwks_uri,
                 configuration_endpoint, status_endpoint, audience,
                 events_requested, delivery_method, started_at, origin_flow, origin_node)
             select $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
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
        .bind(owner.map(|step| step.flow)).bind(owner.map(|step| step.node))
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn flow_origin(&self, peer: &str) -> Result<Option<(uuid::Uuid,String)>, DomainError> {
        sqlx::query_as("select origin_flow,origin_node from ssf_receiver_upstream_streams where tenant_id=$1 and peer_client_id=$2 and origin_flow is not null union all select origin_flow,origin_node from ssf_receiver_upstream_setup_intents where tenant_id=$1 and peer_client_id=$2 and origin_flow is not null")
            .bind(self.tenant.as_str()).bind(peer).fetch_optional(&self.pool).await.map_err(to_domain_error)
    }

    /// Reads the exact pending intent that blocks another remote creation.
    pub async fn pending_setup(
        &self,
        peer_client_id: &str,
    ) -> Result<Option<UpstreamSetupIntent>, DomainError> {
        let row: Option<SetupIntentRow> = sqlx::query_as(
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
    // The peer lock, intent comparison, stream insert, and intent removal form one transaction.
    #[allow(clippy::too_many_lines)]
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
        let current: Option<SetupIntentRow> = sqlx::query_as(
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
                 created_at, updated_at, last_polled_at, origin_flow, origin_node)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
               (select origin_flow from ssf_receiver_upstream_setup_intents where tenant_id=$1 and peer_client_id=$2),
               (select origin_node from ssf_receiver_upstream_setup_intents where tenant_id=$1 and peer_client_id=$2))
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
        let row: Option<UpstreamStreamRow> = sqlx::query_as(
            "select peer_client_id, issuer, jwks_uri, configuration_endpoint,
                    status_endpoint, stream_id, delivery_method, poll_endpoint,
                    audience, events_requested, created_at, updated_at, last_polled_at,
                    deletion_started_at, last_verified_at,
                    last_challenge_verified_at
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
            deletion_started_at: row.13,
            last_verified_at: row.14,
            last_challenge_verified_at: row.15,
        }))
    }

    /// Persist a one-way delete intent before making an outbound request.
    /// Repeated calls retain the original marker for crash reconciliation.
    pub async fn begin_delete(
        &self,
        peer_client_id: &str,
        stream_id: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let result = sqlx::query(
            "update ssf_receiver_upstream_streams
                set deletion_started_at = coalesce(deletion_started_at, $4)
              where tenant_id = $1 and peer_client_id = $2 and stream_id = $3",
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

    /// Remove only the stream whose pending remote deletion was read back as
    /// absent. Another stream or a non-deleting row cannot be removed here.
    pub async fn finish_delete(
        &self,
        peer_client_id: &str,
        stream_id: &str,
    ) -> Result<bool, DomainError> {
        let result = sqlx::query(
            "delete from ssf_receiver_upstream_streams
              where tenant_id = $1 and peer_client_id = $2 and stream_id = $3
                and deletion_started_at is not null",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(stream_id)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Reserve one verification challenge before calling the transmitter.
    /// A lost response leaves the challenge pending until its bounded expiry.
    pub async fn begin_verification(
        &self,
        peer_client_id: &str,
        stream_id: &str,
        state_hash: &[u8],
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        if state_hash.len() != 32 || expires_at <= now {
            return Err(DomainError::invalid(
                "ssf.verification",
                "invalid challenge",
            ));
        }
        let result = sqlx::query(
            "update ssf_receiver_upstream_streams
                set verification_state_hash = $4, verification_expires_at = $5
              where tenant_id = $1 and peer_client_id = $2 and stream_id = $3
                and deletion_started_at is null
                and (verification_expires_at is null or verification_expires_at <= $6)",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(stream_id)
        .bind(state_hash)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() == 1)
    }

    /// Accept one verified stream-scoped SET, recording its JTI before ACK.
    /// A duplicate is accepted without consuming a later challenge. `false`
    /// means the returned state was absent from the pending challenge window.
    pub async fn complete_verification(
        &self,
        peer_client_id: &str,
        stream_id: &str,
        jti: &str,
        state_hash: Option<&[u8]>,
        replay_until: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        let pending: Option<(Option<Vec<u8>>, Option<OffsetDateTime>)> = sqlx::query_as(
            "select verification_state_hash, verification_expires_at
               from ssf_receiver_upstream_streams
              where tenant_id = $1 and peer_client_id = $2 and stream_id = $3
                and deletion_started_at is null for update",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(stream_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let Some((pending_hash, pending_until)) = pending else {
            return Ok(false);
        };
        let duplicate: bool = sqlx::query_scalar(
            "select exists(select 1 from ssf_receiver_upstream_verification_events
              where tenant_id = $1 and peer_client_id = $2 and jti = $3
                and stream_id = $4 and replay_until > $5)",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(jti)
        .bind(stream_id)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if duplicate {
            return Ok(true);
        }
        if let Some(state_hash) = state_hash {
            let matches = pending_hash
                .as_deref()
                .is_some_and(|expected| ct_eq(expected, state_hash));
            if !matches || pending_until.is_none_or(|until| until <= now) {
                return Ok(false);
            }
        }
        sqlx::query(
            "delete from ssf_receiver_upstream_verification_events
              where tenant_id = $1 and peer_client_id = $2 and replay_until <= $3",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let inserted = sqlx::query(
            "insert into ssf_receiver_upstream_verification_events
                (tenant_id, peer_client_id, jti, stream_id, replay_until, processed_at)
             values ($1, $2, $3, $4, $5, $6)
             on conflict (tenant_id, peer_client_id, jti) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(jti)
        .bind(stream_id)
        .bind(replay_until)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if inserted.rows_affected() != 1 {
            return Ok(false);
        }
        sqlx::query(
            "update ssf_receiver_upstream_streams
                set last_verified_at = $4,
                    last_challenge_verified_at = case when $5 then $4 else last_challenge_verified_at end,
                    verification_state_hash = case when $5 then null else verification_state_hash end,
                    verification_expires_at = case when $5 then null else verification_expires_at end
              where tenant_id = $1 and peer_client_id = $2 and stream_id = $3",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(stream_id)
        .bind(now)
        .bind(state_hash.is_some())
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok(true)
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
                and delivery_method = 'urn:ietf:rfc:8936'
                and deletion_started_at is null",
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
