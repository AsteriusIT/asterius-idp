//! The audit sink, and the jobs that verify and trim the trail.

use crate::error::to_domain_error;
use asterius_domain::audit::chain::{self, EventHash, Link};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, DetailValue, EventType, Outcome};
use asterius_domain::{ClientId, DomainError, GrantId, SessionId, TenantId};
use serde_json::{Map, Value};
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
        let rows = sqlx::query(
            "select event_id, occurred_at, event_type, outcome, actor, actor_chain, subject,
                    client_id, session_id, grant_id, request_id, detail,
                    previous_hash, event_hash
             from audit_events
             where tenant_id = $1
             order by event_id",
        )
        .bind(tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let mut events = Vec::with_capacity(rows.len());
        let mut hashes = Vec::with_capacity(rows.len());
        for row in &rows {
            events.push(row_to_event(tenant, row)?);
            hashes.push((
                EventHash::from_slice(row.get::<Vec<u8>, _>("previous_hash").as_slice())
                    .map_err(|e| DomainError::invalid("previous_hash", e.to_string()))?,
                EventHash::from_slice(row.get::<Vec<u8>, _>("event_hash").as_slice())
                    .map_err(|e| DomainError::invalid("event_hash", e.to_string()))?,
            ));
        }

        let links: Vec<Link<'_>> = events
            .iter()
            .zip(&hashes)
            .map(|(event, (previous, current))| Link {
                event,
                previous: *previous,
                current: *current,
            })
            .collect();

        let start = hashes
            .first()
            .map_or(EventHash::GENESIS, |(previous, _)| *previous);
        let tip = chain::verify(&links, start)
            .map_err(|e| DomainError::invalid("audit_events", e.to_string()))?;

        Ok(VerifiedChain {
            records: links.len(),
            start,
            tip,
        })
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
        .bind(actor_to_json(&event.actor))
        .bind(Value::Array(
            event.actor_chain.iter().map(actor_to_json).collect(),
        ))
        .bind(event.subject.as_deref())
        .bind(event.client.as_ref().map(ClientId::as_str))
        .bind(event.session.as_ref().map(SessionId::as_str))
        .bind(event.grant.as_ref().and_then(|g| uuid_or_none(g.as_str())))
        .bind(event.request_id.as_deref())
        .bind(detail_to_json(&event))
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

fn actor_to_json(actor: &Actor) -> Value {
    let mut object = Map::new();
    object.insert("type".to_owned(), Value::String(actor.kind().to_owned()));
    object.insert("id".to_owned(), Value::String(actor.id().to_owned()));
    if let Actor::Agent { on_behalf_of, .. } = actor {
        object.insert(
            "on_behalf_of".to_owned(),
            Value::String(on_behalf_of.clone()),
        );
    }
    Value::Object(object)
}

fn detail_to_json(event: &AuditEvent) -> Value {
    let mut object = Map::new();
    for (key, value) in event.detail.iter() {
        let encoded = match value {
            DetailValue::Text(text) => Value::String(text.clone()),
            DetailValue::Number(number) => Value::Number((*number).into()),
            DetailValue::Flag(flag) => Value::Bool(*flag),
            // Prefixed so a reader can tell a digest from a value that merely
            // looks like one.
            DetailValue::Fingerprint(digest) => Value::String(format!("sha256:{digest}")),
        };
        object.insert(key.clone(), encoded);
    }
    Value::Object(object)
}

/// Rebuilds an event from a row, so that its hash can be recomputed.
fn row_to_event(tenant: &TenantId, row: &sqlx::postgres::PgRow) -> Result<AuditEvent, DomainError> {
    let event_type = EventType::ALL
        .into_iter()
        .find(|candidate| candidate.as_str() == row.get::<String, _>("event_type"))
        .ok_or_else(|| {
            DomainError::invalid(
                "event_type",
                format!("unknown: {}", row.get::<String, _>("event_type")),
            )
        })?;

    let outcome = match row.get::<String, _>("outcome").as_str() {
        "success" => Outcome::Success,
        "failure" => Outcome::Failure,
        other => return Err(DomainError::invalid("outcome", format!("unknown: {other}"))),
    };

    let mut event = AuditEvent::new(
        tenant.clone(),
        event_type,
        outcome,
        actor_from_json(&row.get::<Value, _>("actor"))?,
        row.get::<OffsetDateTime, _>("occurred_at"),
    );

    event.actor_chain = row
        .get::<Value, _>("actor_chain")
        .as_array()
        .map(|links| {
            links
                .iter()
                .map(actor_from_json)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    event.subject = row.get::<Option<String>, _>("subject");
    event.client = row.get::<Option<String>, _>("client_id").map(ClientId::new);
    event.session = row
        .get::<Option<String>, _>("session_id")
        .map(SessionId::new);
    event.grant = row
        .get::<Option<uuid::Uuid>, _>("grant_id")
        .map(|g| GrantId::new(g.to_string()));
    event.request_id = row.get::<Option<String>, _>("request_id");
    event.detail = detail_from_json(&row.get::<Value, _>("detail"))?;
    Ok(event)
}

fn actor_from_json(value: &Value) -> Result<Actor, DomainError> {
    let object = value
        .as_object()
        .ok_or_else(|| DomainError::invalid("actor", "not an object"))?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(match kind {
        "user" => Actor::User(id),
        "client" => Actor::Client(ClientId::new(id)),
        "agent" => Actor::Agent {
            client: ClientId::new(id),
            on_behalf_of: object
                .get("on_behalf_of")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        },
        "admin" => Actor::Admin(id),
        "system" => Actor::System,
        other => {
            return Err(DomainError::invalid(
                "actor.type",
                format!("unknown: {other}"),
            ));
        }
    })
}

fn detail_from_json(value: &Value) -> Result<asterius_domain::Detail, DomainError> {
    let object = value
        .as_object()
        .ok_or_else(|| DomainError::invalid("detail", "not an object"))?;
    let mut detail = asterius_domain::Detail::new();
    for (key, encoded) in object {
        detail = match encoded {
            Value::String(text) => match text.strip_prefix("sha256:") {
                // Reconstructed as the digest it already is, not re-hashed.
                Some(digest) => detail.raw_fingerprint(key, digest),
                None => detail.raw_text(key, text),
            },
            Value::Number(number) => detail.number(
                key,
                number.as_i64().ok_or_else(|| {
                    DomainError::invalid("detail", format!("{key} is not an integer"))
                })?,
            ),
            Value::Bool(flag) => detail.flag(key, *flag),
            other => {
                return Err(DomainError::invalid(
                    "detail",
                    format!("{key} has type {other:?}"),
                ));
            }
        };
    }
    Ok(detail)
}
