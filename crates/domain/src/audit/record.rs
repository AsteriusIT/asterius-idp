//! The stored form of a record, and what a reader does with one it cannot
//! read.
//!
//! A record in `audit_events` is never rewritten (`ast-1p1`): the database
//! refuses `UPDATE` and `DELETE`, and a row whose JSON this binary cannot turn
//! back into an [`AuditEvent`] is *unreadable*, not *tampered* — its hash is
//! correct and the chain through it verifies. A reader that failed on such a
//! row would lose the whole trail around it to one bad row, which is the
//! outcome an attacker who can write one row would most like.
//!
//! So reading is total. [`read_event`] takes the columns as stored and either
//! returns the event or says, in a type the console and an export can render,
//! why it could not; the caller wraps that in [`AuditRecord::Opaque`] with the
//! record's hash and its position and carries on.
//!
//! Both directions of the JSON encoding live here, next to each other. They
//! are one format: the writer's `actor` object is the reader's, and a change
//! to one that misses the other turns every subsequent record opaque. Keeping
//! them in the storage adapter would put a crate boundary between the two
//! halves of one rule.

use super::{Actor, AuditEvent, Detail, DetailValue, EventType, Outcome};
use crate::audit::chain::EventHash;
use crate::{ClientId, GrantId, SessionId, TenantId};
use serde_json::{Map, Value};
use time::OffsetDateTime;

/// The `actor` column.
pub const ACTOR: &str = "actor";
/// The `actor_chain` column.
pub const ACTOR_CHAIN: &str = "actor_chain";
/// The `detail` column.
pub const DETAIL: &str = "detail";
/// The `event_type` column.
pub const EVENT_TYPE: &str = "event_type";
/// The `outcome` column.
pub const OUTCOME: &str = "outcome";

/// Why a stored record could not be turned back into an event.
///
/// Deliberately a closed vocabulary naming a *column*, and not the
/// deserialiser's message: the message would carry text from the row, and a
/// row is the one place an attacker who reached the database can choose what
/// an operator's console renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OpaqueReason {
    /// The column does not parse as JSON at all. This is where a member name
    /// `serde_json` reserves for itself lands (see [`crate::json_sentinel`])
    /// once the feature that recognises it is enabled anywhere in the binary.
    #[error("the {column} column is not JSON this reader can parse")]
    Unparseable {
        /// Which column.
        column: &'static str,
    },
    /// The column is JSON, but not a shape the trail defines: an event type
    /// this build does not know, an actor kind it does not know, a detail
    /// value that is not text, a number or a flag.
    #[error("the {column} column is JSON, but not a shape this trail defines")]
    Unrepresentable {
        /// Which column.
        column: &'static str,
    },
}

impl OpaqueReason {
    /// Which column the reader stopped at.
    ///
    /// Which of the two reasons applies to a given row is not stable across
    /// builds — a `serde_json` feature unified in from anywhere turns a
    /// document that merely holds an undefined shape into one that does not
    /// parse at all — but the column does not move. A caller reporting a row,
    /// or a test asserting on one, wants this rather than the variant.
    #[must_use]
    pub const fn column(&self) -> &'static str {
        match self {
            Self::Unparseable { column } | Self::Unrepresentable { column } => column,
        }
    }
}

/// One record as the trail hands it back.
///
/// The readable event is boxed because it is an order of magnitude larger than
/// the opaque variant, and a trail is read a page at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditRecord {
    /// A record this build understood.
    Event(Box<AuditEvent>),
    /// A record this build could not read, reported rather than skipped and
    /// never rewritten.
    ///
    /// It carries what is true about it regardless of its contents: the hash
    /// stored with it, and where it sits in the range that was read. That is
    /// enough for an operator to find the row and for an export to name it.
    Opaque {
        /// The hash stored with the record.
        hash: EventHash,
        /// Zero-based position in the range that was read.
        position: usize,
        /// Why it could not be read.
        reason: OpaqueReason,
    },
}

impl AuditRecord {
    /// The event, if this record was readable.
    #[must_use]
    pub fn event(&self) -> Option<&AuditEvent> {
        match self {
            Self::Event(event) => Some(event),
            Self::Opaque { .. } => None,
        }
    }

    /// Whether this record is one the reader could not read.
    #[must_use]
    pub const fn is_opaque(&self) -> bool {
        matches!(self, Self::Opaque { .. })
    }
}

/// One record's columns, exactly as storage holds them.
///
/// The JSON columns are bytes rather than parsed values: a row whose JSON this
/// build cannot parse has to reach the reader, or the failure happens in the
/// storage driver where there is nothing left to report but an error for the
/// whole query.
#[derive(Debug, Clone, Copy)]
pub struct StoredEvent<'a> {
    /// The tenant the trail belongs to.
    pub tenant: &'a TenantId,
    /// When the event happened.
    pub occurred_at: OffsetDateTime,
    /// The `event_type` column.
    pub event_type: &'a str,
    /// The `outcome` column.
    pub outcome: &'a str,
    /// The `actor` column, as stored.
    pub actor: &'a [u8],
    /// The `actor_chain` column, as stored.
    pub actor_chain: &'a [u8],
    /// The `subject` column.
    pub subject: Option<&'a str>,
    /// The `client_id` column.
    pub client: Option<&'a str>,
    /// The `session_id` column.
    pub session: Option<&'a str>,
    /// The `grant_id` column.
    pub grant: Option<&'a str>,
    /// The `request_id` column.
    pub request_id: Option<&'a str>,
    /// The `detail` column, as stored.
    pub detail: &'a [u8],
}

/// Rebuilds an event from its stored columns.
///
/// # Errors
///
/// Returns the [`OpaqueReason`] the caller should report the record with. It
/// is never a reason to fail the read: the record is authentic, and the rest
/// of the trail is still readable.
// fuzz-target: audit_record
pub fn read_event(stored: &StoredEvent<'_>) -> Result<AuditEvent, OpaqueReason> {
    let event_type = EventType::ALL
        .into_iter()
        .find(|candidate| candidate.as_str() == stored.event_type)
        .ok_or(OpaqueReason::Unrepresentable { column: EVENT_TYPE })?;

    let outcome = match stored.outcome {
        "success" => Outcome::Success,
        "failure" => Outcome::Failure,
        _ => return Err(OpaqueReason::Unrepresentable { column: OUTCOME }),
    };

    let mut event = AuditEvent::new(
        stored.tenant.clone(),
        event_type,
        outcome,
        actor_from_json(&parse(stored.actor, ACTOR)?, ACTOR)?,
        stored.occurred_at,
    );

    event.actor_chain = parse(stored.actor_chain, ACTOR_CHAIN)?
        .as_array()
        .ok_or(OpaqueReason::Unrepresentable {
            column: ACTOR_CHAIN,
        })?
        .iter()
        .map(|link| actor_from_json(link, ACTOR_CHAIN))
        .collect::<Result<Vec<_>, _>>()?;
    event.subject = stored.subject.map(ToOwned::to_owned);
    event.client = stored.client.map(ClientId::new);
    event.session = stored.session.map(SessionId::new);
    event.grant = stored.grant.map(GrantId::new);
    event.request_id = stored.request_id.map(ToOwned::to_owned);
    event.detail = detail_from_json(&parse(stored.detail, DETAIL)?)?;
    Ok(event)
}

/// The `actor` column for an actor.
#[must_use]
pub fn actor_json(actor: &Actor) -> Value {
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

/// The `actor_chain` column for a delegation chain.
#[must_use]
pub fn actor_chain_json(chain: &[Actor]) -> Value {
    Value::Array(chain.iter().map(actor_json).collect())
}

/// The `detail` column for a detail map.
#[must_use]
pub fn detail_json(detail: &Detail) -> Value {
    let mut object = Map::new();
    for (key, value) in detail.iter() {
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

fn parse(bytes: &[u8], column: &'static str) -> Result<Value, OpaqueReason> {
    serde_json::from_slice(bytes).map_err(|_| OpaqueReason::Unparseable { column })
}

fn actor_from_json(value: &Value, column: &'static str) -> Result<Actor, OpaqueReason> {
    let object = value
        .as_object()
        .ok_or(OpaqueReason::Unrepresentable { column })?;
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
        _ => return Err(OpaqueReason::Unrepresentable { column }),
    })
}

fn detail_from_json(value: &Value) -> Result<Detail, OpaqueReason> {
    let object = value
        .as_object()
        .ok_or(OpaqueReason::Unrepresentable { column: DETAIL })?;
    let mut detail = Detail::new();
    for (key, encoded) in object {
        detail = match encoded {
            Value::String(text) => match text.strip_prefix("sha256:") {
                // Reconstructed as the digest it already is, not re-hashed.
                Some(digest) => detail.raw_fingerprint(key, digest),
                None => detail.raw_text(key, text),
            },
            Value::Number(number) => detail.number(
                key,
                number
                    .as_i64()
                    .ok_or(OpaqueReason::Unrepresentable { column: DETAIL })?,
            ),
            Value::Bool(flag) => detail.flag(key, *flag),
            _ => return Err(OpaqueReason::Unrepresentable { column: DETAIL }),
        };
    }
    Ok(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_sentinel::SERDE_JSON_SENTINELS;

    fn event() -> AuditEvent {
        AuditEvent::new(
            TenantId::new("demo"),
            EventType::TOKEN_ISSUED,
            Outcome::Success,
            Actor::Client(ClientId::new("billing")),
            OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("timestamp"),
        )
        .subject("alice")
        .request_id("req-1")
        .actor_chain(vec![
            Actor::User("alice".to_owned()),
            Actor::Agent {
                client: ClientId::new("scheduler-bot"),
                on_behalf_of: "alice".to_owned(),
            },
        ])
        .detail(
            Detail::new()
                .text("scope", "openid profile")
                .number("expires_in", 300)
                .flag("consent_reused", true)
                .credential("code", "Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5uV-eW_iO2nQ"),
        )
    }

    /// Renders an event the way a writer does, then reads it back.
    fn round_trip(event: &AuditEvent) -> Result<AuditEvent, OpaqueReason> {
        let actor = actor_json(&event.actor).to_string();
        let chain = actor_chain_json(&event.actor_chain).to_string();
        let detail = detail_json(&event.detail).to_string();
        read_event(&StoredEvent {
            tenant: &event.tenant,
            occurred_at: event.occurred_at,
            event_type: event.event_type.as_str(),
            outcome: event.outcome.as_str(),
            actor: actor.as_bytes(),
            actor_chain: chain.as_bytes(),
            subject: event.subject.as_deref(),
            client: event.client.as_ref().map(ClientId::as_str),
            session: event.session.as_ref().map(SessionId::as_str),
            grant: event.grant.as_ref().map(GrantId::as_str),
            request_id: event.request_id.as_deref(),
            detail: detail.as_bytes(),
        })
    }

    /// The columns of a readable record, with `detail` replaced.
    fn with_detail(detail: &str) -> Result<AuditEvent, OpaqueReason> {
        let event = event();
        let actor = actor_json(&event.actor).to_string();
        let chain = actor_chain_json(&event.actor_chain).to_string();
        read_event(&StoredEvent {
            tenant: &event.tenant,
            occurred_at: event.occurred_at,
            event_type: event.event_type.as_str(),
            outcome: event.outcome.as_str(),
            actor: actor.as_bytes(),
            actor_chain: chain.as_bytes(),
            subject: None,
            client: None,
            session: None,
            grant: None,
            request_id: None,
            detail: detail.as_bytes(),
        })
    }

    #[test]
    fn an_event_survives_the_round_trip_through_its_stored_columns() {
        let original = event();

        let read = round_trip(&original).expect("a written event must read back");

        assert_eq!(read, original);
    }

    #[test]
    fn a_detail_column_that_is_not_json_is_unparseable() {
        let read = with_detail("{not json");

        assert_eq!(read, Err(OpaqueReason::Unparseable { column: DETAIL }));
    }

    #[test]
    fn a_detail_value_the_trail_does_not_define_is_unrepresentable() {
        // A nested object: the trail's values are text, numbers and flags, and
        // nothing that writes a record can produce this.
        let read = with_detail(r#"{"nested": {"value": "1"}}"#);

        assert_eq!(read, Err(OpaqueReason::Unrepresentable { column: DETAIL }));
    }

    #[test]
    fn a_sentinel_member_in_a_detail_column_never_fails_the_whole_read() {
        for sentinel in SERDE_JSON_SENTINELS {
            let read = with_detail(&format!(r#"{{"{sentinel}": {{"value": "{{}}"}}}}"#));

            // Which reason applies depends on which `serde_json` features are
            // unified into the build: with `raw_value` or `arbitrary_precision`
            // on, the document does not parse at all; without them it parses
            // and the nested object is refused. Both are the same answer to
            // the caller — this column, this row, opaque — and neither is a
            // failure of the read.
            let reason = read.expect_err("a sentinel-bearing detail is not readable");
            assert_eq!(reason.column(), DETAIL, "{sentinel} produced {reason}");
        }
    }

    #[test]
    fn an_unknown_event_type_is_reported_against_its_own_column() {
        let event = event();
        let actor = actor_json(&event.actor).to_string();

        let read = read_event(&StoredEvent {
            tenant: &event.tenant,
            occurred_at: event.occurred_at,
            event_type: "token.teleported",
            outcome: "success",
            actor: actor.as_bytes(),
            actor_chain: b"[]",
            subject: None,
            client: None,
            session: None,
            grant: None,
            request_id: None,
            detail: b"{}",
        });

        assert_eq!(
            read,
            Err(OpaqueReason::Unrepresentable { column: EVENT_TYPE })
        );
    }

    #[test]
    fn an_unknown_actor_kind_is_reported_against_the_actor_column() {
        let event = event();

        let read = read_event(&StoredEvent {
            tenant: &event.tenant,
            occurred_at: event.occurred_at,
            event_type: EventType::AUTH_LOGIN.as_str(),
            outcome: "success",
            actor: br#"{"type": "poltergeist", "id": "x"}"#,
            actor_chain: b"[]",
            subject: None,
            client: None,
            session: None,
            grant: None,
            request_id: None,
            detail: b"{}",
        });

        assert_eq!(read, Err(OpaqueReason::Unrepresentable { column: ACTOR }));
    }

    #[test]
    fn an_opaque_record_yields_no_event() {
        let record = AuditRecord::Opaque {
            hash: EventHash::GENESIS,
            position: 3,
            reason: OpaqueReason::Unparseable { column: DETAIL },
        };

        assert!(record.is_opaque());
        assert!(record.event().is_none());
    }
}
