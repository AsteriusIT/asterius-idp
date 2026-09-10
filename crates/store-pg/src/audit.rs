//! The audit sink, and the jobs that verify and trim the trail.

use crate::error::to_domain_error;
use asterius_domain::audit::chain::{self, Content, EventHash, Link};
use asterius_domain::audit::record::{self, AuditRecord, StoredEvent};
use asterius_domain::audit::{AuditEvent, AuditSink};
use asterius_domain::{ClientId, DomainError, SessionId, TenantId};
use sqlx::postgres::PgPool;
use sqlx::{Acquire as _, Row as _};
use time::OffsetDateTime;

/// `AuditSink` over PostgreSQL, with a per-tenant hash chain.
#[derive(Debug, Clone)]
pub struct PgAuditSink {
    pool: PgPool,
}

impl PgAuditSink {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Verifies a tenant's chain from the oldest retained record forward.
    ///
    /// Retention trims the front of the chain, so the first retained record no
    /// longer follows genesis. Verification therefore starts from whatever that
    /// record claims its predecessor was, and checks every link after it — the
    /// links between what remains are exactly what tampering would break.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invalid`] describing which record failed, or a
    /// storage error if the trail cannot be read.
    pub async fn verify_chain(&self, tenant: &TenantId) -> Result<VerifiedChain, DomainError> {
        let stored = self.read_stored(tenant).await?;

        let links: Vec<Link<'_>> = stored
            .iter()
            .map(|record| Link {
                content: match &record.record {
                    AuditRecord::Event(event) => Content::Event(event),
                    AuditRecord::Opaque { .. } => Content::Opaque,
                },
                previous: record.previous,
                current: record.current,
            })
            .collect();

        let start = stored
            .first()
            .map_or(EventHash::GENESIS, |record| record.previous);
        let tip = chain::verify(&links, start)
            .map_err(|e| DomainError::invalid("audit_events", e.to_string()))?;

        Ok(VerifiedChain {
            records: links.len(),
            start,
            opaque: stored.iter().filter(|r| r.record.is_opaque()).count(),
            tip,
        })
    }

    /// Reads a tenant's trail, oldest first.
    ///
    /// Total by construction: a record this build cannot deserialise comes
    /// back as [`AuditRecord::Opaque`] carrying its hash, its position and why,
    /// and the records around it are read normally. Failing the read instead
    /// would let one unreadable row — a row the database will not let anything
    /// repair, by policy (`ast-1p1`) — cost the readability of the whole trail.
    ///
    /// Nothing here writes.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the trail cannot be read at all.
    pub async fn read_trail(&self, tenant: &TenantId) -> Result<Vec<AuditRecord>, DomainError> {
        Ok(self
            .read_stored(tenant)
            .await?
            .into_iter()
            .map(|stored| stored.record)
            .collect())
    }

    /// The trail with the hashes each record was stored with.
    async fn read_stored(&self, tenant: &TenantId) -> Result<Vec<StoredRecord>, DomainError> {
        // The JSON columns are cast to text rather than decoded as JSON by the
        // driver: a document the driver cannot parse would otherwise fail the
        // whole query, which is precisely the outcome an opaque record exists
        // to avoid.
        let rows = sqlx::query(
            "select event_id, occurred_at, event_type, outcome,
                    actor::text as actor, actor_chain::text as actor_chain, subject,
                    client_id, session_id, grant_id::text as grant_id, request_id,
                    detail::text as detail, previous_hash, event_hash
             from audit_events
             where tenant_id = $1
             order by event_id",
        )
        .bind(tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let mut stored = Vec::with_capacity(rows.len());
        for (position, row) in rows.iter().enumerate() {
            let previous = EventHash::from_slice(row.get::<Vec<u8>, _>("previous_hash").as_slice())
                .map_err(|e| DomainError::invalid("previous_hash", e.to_string()))?;
            let current = EventHash::from_slice(row.get::<Vec<u8>, _>("event_hash").as_slice())
                .map_err(|e| DomainError::invalid("event_hash", e.to_string()))?;

            let record = match read_row(tenant, row) {
                Ok(event) => AuditRecord::Event(Box::new(event)),
                Err(reason) => AuditRecord::Opaque {
                    hash: current,
                    position,
                    reason,
                },
            };
            stored.push(StoredRecord {
                record,
                previous,
                current,
            });
        }
        Ok(stored)
    }

    /// Deletes records older than `cutoff` for one tenant.
    ///
    /// This is the only path allowed to remove audit records: it announces
    /// itself with `asterius.retention` for the duration of its transaction,
    /// which the append-only trigger checks. Idempotent — running it twice with
    /// the same cutoff removes nothing the second time.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the deletion fails.
    pub async fn purge_older_than(
        &self,
        tenant: &TenantId,
        cutoff: OffsetDateTime,
    ) -> Result<u64, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        // `set local` is scoped to this transaction, so the escape hatch closes
        // when it commits — there is no window in which some other query on a
        // pooled connection inherits permission to delete.
        sqlx::query("set local asterius.retention = 'on'")
            .execute(&mut *transaction)
            .await
            .map_err(to_domain_error)?;

        let deleted =
            sqlx::query("delete from audit_events where tenant_id = $1 and occurred_at < $2")
                .bind(tenant.as_str())
                .bind(cutoff)
                .execute(&mut *transaction)
                .await
                .map_err(to_domain_error)?
                .rows_affected();

        transaction.commit().await.map_err(to_domain_error)?;
        Ok(deleted)
    }
}

/// The result of verifying a tenant's trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedChain {
    /// How many records were checked.
    pub records: usize,
    /// How many of them this build could not deserialise. Their linkage was
    /// checked; their contents could not be re-hashed, because canonicalising
    /// a record requires reading it. See
    /// [`asterius_domain::audit::chain::Content`].
    pub opaque: usize,
    /// The hash the first retained record follows. [`EventHash::GENESIS`]
    /// unless retention has trimmed the front.
    pub start: EventHash,
    /// The hash of the newest record.
    pub tip: EventHash,
}

#[async_trait::async_trait]
impl AuditSink for PgAuditSink {
    async fn record(&self, event: AuditEvent) -> Result<(), DomainError> {
        // Hash what will actually be stored, not what was handed to us. See
        // `as_stored`.
        let event = as_stored(event);
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let connection = transaction.acquire().await.map_err(to_domain_error)?;

        // Appending to a chain is a read-then-write, so two concurrent writers
        // for one tenant would both read the same tip and produce a fork. The
        // lock is per tenant and held for the transaction, so tenants do not
        // queue behind each other.
        sqlx::query("select pg_advisory_xact_lock(hashtext($1))")
            .bind(event.tenant.as_str())
            .execute(&mut *connection)
            .await
            .map_err(to_domain_error)?;

        let previous = sqlx::query(
            "select event_hash from audit_events
             where tenant_id = $1
             order by event_id desc
             limit 1",
        )
        .bind(event.tenant.as_str())
        .fetch_optional(&mut *connection)
        .await
        .map_err(to_domain_error)?
        .map(|row| EventHash::from_slice(row.get::<Vec<u8>, _>("event_hash").as_slice()))
        .transpose()
        .map_err(|e| DomainError::invalid("event_hash", e.to_string()))?
        .unwrap_or(EventHash::GENESIS);

        let current = chain::hash(previous, &event);

        sqlx::query(
            "insert into audit_events
                 (tenant_id, occurred_at, event_type, outcome, actor, actor_chain, subject,
                  client_id, session_id, grant_id, request_id, detail,
                  previous_hash, event_hash)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(event.tenant.as_str())
        .bind(event.occurred_at)
        .bind(event.event_type.as_str())
        .bind(event.outcome.as_str())
        .bind(record::actor_json(&event.actor))
        .bind(record::actor_chain_json(&event.actor_chain))
        .bind(event.subject.as_deref())
        .bind(event.client.as_ref().map(ClientId::as_str))
        .bind(event.session.as_ref().map(SessionId::as_str))
        .bind(event.grant.as_ref().and_then(|g| uuid_or_none(g.as_str())))
        .bind(event.request_id.as_deref())
        .bind(record::detail_json(&event.detail))
        .bind(previous.as_bytes().as_slice())
        .bind(current.as_bytes().as_slice())
        .execute(&mut *connection)
        .await
        .map_err(to_domain_error)?;

        transaction.commit().await.map_err(to_domain_error)?;
        Ok(())
    }
}

/// Normalises an event into exactly the form storage will hold.
///
/// The hash must cover the stored bytes, or verification compares a recomputed
/// hash of one value against a stored hash of another and reports tampering
/// that never happened. Two things differ between an in-memory event and its
/// row:
///
/// * **Timestamp precision.** `OffsetDateTime::now_utc` is nanosecond
///   resolution; PostgreSQL `timestamptz` is microsecond. The nanoseconds are
///   silently dropped on the way in, so they are dropped here first.
/// * **Grant ids.** The column is `uuid`. A grant id that is not a UUID cannot
///   be stored, so it is cleared rather than allowed to disagree.
fn as_stored(mut event: AuditEvent) -> AuditEvent {
    let nanoseconds = event.occurred_at.nanosecond();
    event.occurred_at = event
        .occurred_at
        .replace_nanosecond(nanoseconds / 1_000 * 1_000)
        .unwrap_or(event.occurred_at);

    if event
        .grant
        .as_ref()
        .is_some_and(|g| uuid_or_none(g.as_str()).is_none())
    {
        event.grant = None;
    }
    event
}

/// Grant ids are UUIDs in the schema; anything else is recorded as absent
/// rather than failing the audit write.
fn uuid_or_none(value: &str) -> Option<uuid::Uuid> {
    value.parse().ok()
}

/// One stored record and the hashes it was stored with.
struct StoredRecord {
    record: AuditRecord,
    previous: EventHash,
    current: EventHash,
}

/// Rebuilds an event from a row, or says why it cannot be rebuilt.
///
/// Every column is read as a type PostgreSQL always produces — text, and bytes
/// for the hashes — so that the judgment about whether a record is readable is
/// made by the domain's reader and not by the driver's decoder.
fn read_row(
    tenant: &TenantId,
    row: &sqlx::postgres::PgRow,
) -> Result<AuditEvent, asterius_domain::audit::OpaqueReason> {
    let event_type: String = row.get("event_type");
    let outcome: String = row.get("outcome");
    let actor: String = row.get("actor");
    let actor_chain: Option<String> = row.get("actor_chain");
    let subject: Option<String> = row.get("subject");
    let client: Option<String> = row.get("client_id");
    let session: Option<String> = row.get("session_id");
    let grant: Option<String> = row.get("grant_id");
    let request_id: Option<String> = row.get("request_id");
    let detail: Option<String> = row.get("detail");

    record::read_event(&StoredEvent {
        tenant,
        occurred_at: row.get::<OffsetDateTime, _>("occurred_at"),
        event_type: &event_type,
        outcome: &outcome,
        actor: actor.as_bytes(),
        actor_chain: actor_chain.as_deref().unwrap_or("[]").as_bytes(),
        subject: subject.as_deref(),
        client: client.as_deref(),
        session: session.as_deref(),
        grant: grant.as_deref(),
        request_id: request_id.as_deref(),
        detail: detail.as_deref().unwrap_or("{}").as_bytes(),
    })
}
