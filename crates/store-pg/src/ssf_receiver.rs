//! Tenant-scoped identity bindings and atomic, replay-safe inbound SET effects.

use crate::error::to_domain_error;
use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::outbox::QueuedEvent;
use asterius_domain::{ClientId, DomainError, SessionRevocation, TenantId};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// A lifecycle action the configured peer is permitted to request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverAction {
    /// Revoke all active sessions belonging to the mapped user.
    SessionRevoked,
    /// Disable the mapped account and revoke its active sessions.
    AccountDisabled,
    /// Revoke current sessions after an upstream credential revocation/removal.
    CredentialCompromised,
    /// Record a creation/update event without changing local credentials.
    ObserveOnly,
}

impl ReceiverAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SessionRevoked => "session-revoked",
            Self::AccountDisabled => "account-disabled",
            Self::CredentialCompromised => "credential-compromised",
            Self::ObserveOnly => "credential-observed",
        }
    }
}

/// Outcome of processing one valid inbound SET.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverOutcome {
    /// The subject's local action was applied and recorded.
    Applied,
    /// This peer's `jti` was already processed; no action was repeated.
    Duplicate,
    /// The verified event was older than the last event for this subject.
    Stale,
}

/// A session whose revocation must be announced to its participating clients.
#[derive(Debug, Clone)]
pub struct ReceiverSession {
    pub public_sid: String,
    pub participants: Vec<ClientId>,
}

/// Signed notices prepared for the transaction that accepts an inbound SET.
#[derive(Debug, Default)]
pub struct ReceiverNotifications {
    pub outbox: Vec<QueuedEvent>,
    pub poll: Vec<ReceiverPollSet>,
    pub subjects: Vec<ReceiverSubjectReservation>,
}

/// A pairwise identifier used by a prepared notice. It is reserved before the
/// notice commits, preserving the issuer's never-reassign guarantee.
#[derive(Debug)]
pub struct ReceiverSubjectReservation {
    pub sector_identifier: String,
    pub subject: String,
}

/// A signed SET for one polling stream.
#[derive(Debug)]
pub struct ReceiverPollSet {
    pub stream_id: String,
    pub jti: String,
    pub jws: String,
}

/// Prepares notifications without committing them. The receiver invokes this
/// while its user and session rows are locked; any failure aborts the SET.
#[async_trait::async_trait]
pub trait ReceiverNotificationPreparer: Send + Sync {
    async fn prepare(
        &self,
        peer_client_id: &str,
        user_id: Uuid,
        sessions: &[ReceiverSession],
        action: ReceiverAction,
        account_was_active: bool,
        now: OffsetDateTime,
    ) -> Result<ReceiverNotifications, DomainError>;
}

/// The durable receiver store for one tenant.
#[derive(Clone)]
pub struct PgSsfReceiver {
    pool: PgPool,
    tenant: TenantId,
}

impl std::fmt::Debug for PgSsfReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgSsfReceiver")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgSsfReceiver {
    pub(crate) const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// Adds or replaces an operator-provisioned binding from one peer subject
    /// to one local account. `subject_key` must be the canonical output of
    /// `asterius_ssf::Subject::key`; raw email or username matching is not used.
    pub async fn bind_subject(
        &self,
        peer_client_id: &str,
        subject_key: &str,
        user_id: Uuid,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "insert into ssf_receiver_subject_mappings
                (tenant_id, peer_client_id, subject_key, user_id)
             values ($1, $2, $3, $4)
             on conflict (tenant_id, peer_client_id, subject_key)
             do update set user_id = excluded.user_id",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(subject_key)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    /// Removes one exact subject-to-user binding, returning false when it is
    /// absent or now names a different local user.
    pub async fn remove_subject(
        &self,
        peer_client_id: &str,
        subject_key: &str,
        user_id: Uuid,
    ) -> Result<bool, DomainError> {
        let result = sqlx::query(
            "delete from ssf_receiver_subject_mappings
             where tenant_id = $1 and peer_client_id = $2 and subject_key = $3 and user_id = $4",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(subject_key)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() > 0)
    }

    /// Atomically resolves an explicitly bound subject, claims the peer's
    /// `jti`, and applies its authorized lifecycle action. A failed identity
    /// lookup rolls back; a duplicate returns successfully without repeating
    /// the effect.
    // The verified SET fields stay explicit so no caller can omit the replay
    // bound, event time, or notification preparer at this security boundary.
    // Replay claim, lifecycle action, notifications, and audit must commit atomically.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn process(
        &self,
        peer_client_id: &str,
        subject_key: &str,
        jti: &str,
        replay_until: OffsetDateTime,
        action: ReceiverAction,
        event_at: OffsetDateTime,
        now: OffsetDateTime,
        notifications: &dyn ReceiverNotificationPreparer,
    ) -> Result<ReceiverOutcome, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let duplicate: bool = sqlx::query_scalar(
            "select exists(
                 select 1 from ssf_receiver_events
                  where tenant_id = $1 and peer_client_id = $2 and jti = $3
             )",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(jti)
        .fetch_one(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if duplicate {
            transaction.rollback().await.map_err(to_domain_error)?;
            return Ok(ReceiverOutcome::Duplicate);
        }
        let user_id: Option<Uuid> = sqlx::query_scalar(
            "select user_id from ssf_receiver_subject_mappings
             where tenant_id = $1 and peer_client_id = $2 and subject_key = $3
             for update",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(subject_key)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        let Some(user_id) = user_id else {
            return Err(DomainError::invalid(
                "sub_id",
                "the event subject is not configured for this peer",
            ));
        };
        // Serialize lifecycle effects across mappings for the same account.
        // Event ordering itself is scoped to the locked peer/subject mapping.
        let status: Option<String> = sqlx::query_scalar(
            "select status from users where tenant_id = $1 and user_id = $2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        let account_was_active = status.as_deref() == Some("active");
        let latest: Option<OffsetDateTime> = sqlx::query_scalar(
            "select latest_event_timestamp from ssf_receiver_subject_order
             where tenant_id = $1 and peer_client_id = $2 and subject_key = $3
               and user_id = $4
             for update",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(subject_key)
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        let stale = latest.is_some_and(|latest| event_at <= latest);
        let inserted = sqlx::query(
            "insert into ssf_receiver_events
                (tenant_id, peer_client_id, jti, replay_until, user_id, event_type, event_timestamp, outcome, processed_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             on conflict (tenant_id, peer_client_id, jti) do nothing",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(jti)
        .bind(replay_until)
        .bind(user_id)
        .bind(action.as_str())
        .bind(event_at)
        .bind(if stale { "stale" } else { "applied" })
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        if inserted == 0 {
            transaction.rollback().await.map_err(to_domain_error)?;
            return Ok(ReceiverOutcome::Duplicate);
        }

        let (event_type, outcome) = match action {
            ReceiverAction::AccountDisabled => (EventType::ACCOUNT_DISABLED, Outcome::Success),
            ReceiverAction::CredentialCompromised | ReceiverAction::ObserveOnly => {
                (EventType::CREDENTIAL_CHANGED, Outcome::Success)
            }
            ReceiverAction::SessionRevoked => (EventType::SESSION_REVOKED, Outcome::Success),
        };
        let audit = AuditEvent::new(
            self.tenant.clone(),
            event_type,
            if stale { Outcome::Failure } else { outcome },
            Actor::Client(ClientId::new(peer_client_id)),
            now,
        )
        .subject(user_id.to_string())
        .detail(
            Detail::new()
                .label("source", "ssf.receiver")
                .label("action", action.as_str())
                .label("result", if stale { "stale" } else { "accepted" }),
        );

        if stale {
            crate::audit::append(&mut transaction, audit).await?;
            transaction.commit().await.map_err(to_domain_error)?;
            return Ok(ReceiverOutcome::Stale);
        }

        // The user lock prevents new sessions (their FK needs KEY SHARE),
        // and the session locks prevent new participants. Lock existing
        // participant rows too so removal cannot change the fan-out between
        // preparation and the lifecycle update. A failed preparation rolls
        // back these locks and the inbox claim; audit follows preparation so
        // the subject collision audit can use its own transaction safely.
        let sessions = if action == ReceiverAction::ObserveOnly {
            Vec::new()
        } else {
            let rows: Vec<(String, String)> = sqlx::query_as(
                "select session_id, public_sid from sessions
                 where tenant_id = $1 and user_id = $2 and revoked_at is null
                 for update",
            )
            .bind(self.tenant.as_str())
            .bind(user_id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(to_domain_error)?;
            let mut sessions = Vec::with_capacity(rows.len());
            for (session_id, public_sid) in rows {
                let participants: Vec<String> = sqlx::query_scalar(
                    "select client_id from session_clients
                     where tenant_id = $1 and session_id = $2 order by client_id for update",
                )
                .bind(self.tenant.as_str())
                .bind(&session_id)
                .fetch_all(&mut *transaction)
                .await
                .map_err(to_domain_error)?;
                sessions.push(ReceiverSession {
                    public_sid,
                    participants: participants.into_iter().map(ClientId::new).collect(),
                });
            }
            sessions
        };
        let prepared = notifications
            .prepare(
                peer_client_id,
                user_id,
                &sessions,
                action,
                account_was_active,
                now,
            )
            .await
            .map_err(|error| DomainError::Storage(Box::new(error)))?;

        for subject in &prepared.subjects {
            sqlx::query(
                "insert into subject_identifiers
                    (tenant_id, user_id, sector_identifier, subject)
                 values ($1, $2, $3, $4)
                 on conflict (tenant_id, user_id, sector_identifier) do nothing",
            )
            .bind(self.tenant.as_str())
            .bind(user_id)
            .bind(&subject.sector_identifier)
            .bind(&subject.subject)
            .execute(&mut *transaction)
            .await
            .map_err(to_domain_error)?;
            let reserved: Option<String> = sqlx::query_scalar(
                "select subject from subject_identifiers
                 where tenant_id = $1 and user_id = $2 and sector_identifier = $3",
            )
            .bind(self.tenant.as_str())
            .bind(user_id)
            .bind(&subject.sector_identifier)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(to_domain_error)?;
            if reserved.as_deref() != Some(subject.subject.as_str()) {
                return Err(DomainError::Conflict(
                    "subject reservation changed during notification preparation".to_owned(),
                ));
            }
        }

        crate::audit::append(&mut transaction, audit).await?;

        match action {
            ReceiverAction::SessionRevoked | ReceiverAction::CredentialCompromised => {
                revoke_sessions(&mut transaction, &self.tenant, user_id, now).await?;
            }
            ReceiverAction::AccountDisabled => {
                sqlx::query(
                    "update users set status = 'disabled', updated_at = $3
                     where tenant_id = $1 and user_id = $2 and status = 'active'",
                )
                .bind(self.tenant.as_str())
                .bind(user_id)
                .bind(now)
                .execute(&mut *transaction)
                .await
                .map_err(to_domain_error)?;
                revoke_sessions(&mut transaction, &self.tenant, user_id, now).await?;
            }
            ReceiverAction::ObserveOnly => {}
        }
        for notice in &prepared.outbox {
            let mut entry = crate::outbox::NewOutboxEntry::new(
                &notice.kind,
                &notice.destination,
                notice.payload.clone(),
            );
            entry.ordering_key = notice.ordering_key.as_deref();
            crate::outbox::enqueue(&mut transaction, &self.tenant, &entry, now).await?;
        }
        let poll = crate::ssf_poll::PgSsfPoll::new(self.pool.clone(), self.tenant.clone());
        for set in &prepared.poll {
            let stream =
                asterius_ssf::stream::StreamId::parse(&set.stream_id).ok_or_else(|| {
                    DomainError::Conflict("invalid prepared stream identifier".to_owned())
                })?;
            poll.enqueue(&mut transaction, &stream, &set.jti, &set.jws, now)
                .await?;
        }
        // Only an applied event advances ordering. The mapping row was locked
        // before the comparison, so a concurrent rebind/remove cannot race
        // this update. Rebinding to a new user resets the old user's mark.
        sqlx::query(
            "insert into ssf_receiver_subject_order
                (tenant_id, peer_client_id, subject_key, user_id, latest_event_timestamp)
             values ($1, $2, $3, $4, $5)
             on conflict (tenant_id, peer_client_id, subject_key)
             do update set user_id = excluded.user_id,
                           latest_event_timestamp = excluded.latest_event_timestamp",
        )
        .bind(self.tenant.as_str())
        .bind(peer_client_id)
        .bind(subject_key)
        .bind(user_id)
        .bind(event_at)
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(ReceiverOutcome::Applied)
    }
}

async fn revoke_sessions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &TenantId,
    user_id: Uuid,
    now: OffsetDateTime,
) -> Result<(), DomainError> {
    sqlx::query(
        "update sessions
         set revoked_at = coalesce(revoked_at, $3),
             revocation_reason = coalesce(revocation_reason, $4)
         where tenant_id = $1 and user_id = $2 and revoked_at is null",
    )
    .bind(tenant.as_str())
    .bind(user_id)
    .bind(now)
    .bind(SessionRevocation::Administrative.as_str())
    .execute(&mut **transaction)
    .await
    .map_err(to_domain_error)?;
    Ok(())
}
