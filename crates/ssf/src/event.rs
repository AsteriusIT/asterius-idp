//! The one event a SET carries.
//!
//! RFC 8417 §2 makes `events` a JSON object keyed by an event type URI, and
//! SSF 1.0 §4.2.1 says it SHOULD hold exactly one member. Asterius emits one,
//! always, and the type in this module is why: a [`SecurityEvent`] is a single
//! URI and a single payload, and [`crate::Set`] takes one of them. There is no
//! `add_event`, so "two events, two types, one SET" is not a state a caller can
//! reach — see [`crate::Set`] for the argument.

use crate::subject::Subject;
use serde_json::{Map, Value};
use thiserror::Error;
use time::OffsetDateTime;

/// The longest event type URI this server will emit.
pub const MAX_EVENT_URI_LEN: usize = 512;

/// Why an event type URI was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum EventError {
    /// Empty, or longer than [`MAX_EVENT_URI_LEN`].
    #[error("an event type URI must be 1 to {max} characters, found {found}", max = MAX_EVENT_URI_LEN)]
    Length {
        /// How long it was.
        found: usize,
    },
    /// Not an absolute URI.
    ///
    /// RFC 8417 §2 keys `events` by a URI, and a receiver dispatches on the
    /// exact string. A relative reference resolves against nothing at the far
    /// end and would be dispatched as its own, unknown, type.
    #[error("an event type URI must be absolute")]
    NotAbsolute,
    /// Carries a fragment.
    ///
    /// Two URIs differing only in a fragment are two keys in `events` and one
    /// event type to a human reader. Refusing the fragment removes the
    /// difference rather than leaving a receiver to notice it.
    #[error("an event type URI must not contain a fragment")]
    HasFragment,
}

/// An event type URI: the key an event appears under in `events`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventUri(String);

impl EventUri {
    /// Validates an event type URI.
    ///
    /// # Errors
    ///
    /// [`EventError`] if the value is empty, oversized, relative, or carries a
    /// fragment.
    // fuzz-target: ssf_event_uri
    pub fn parse(raw: &str) -> Result<Self, EventError> {
        let found = raw.chars().count();
        if raw.is_empty() || found > MAX_EVENT_URI_LEN {
            return Err(EventError::Length { found });
        }
        let url = url::Url::parse(raw).map_err(|_| EventError::NotAbsolute)?;
        if url.fragment().is_some() {
            return Err(EventError::HasFragment);
        }
        // The parsed form is *not* what is kept. A receiver dispatches on the
        // exact bytes of the key, and `Url` normalises — a trailing slash
        // appears, a default port disappears — so re-rendering here would emit
        // a key that is not the one the event type was registered under.
        Ok(Self(raw.to_owned()))
    }

    /// The URI, as it appears as the `events` key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EventUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One security event: a type and the payload that belongs to that type.
///
/// The payload is deliberately a free map. What a CAEP `session-revoked` or a
/// RISC `account-disabled` may say is defined by the event's own
/// specification, not by SSF, and this crate's job is the *envelope*. The one
/// payload member with a rule that reaches here is `subject`: SSF 1.0 §3.1
/// lets an existing CAEP or RISC event keep it, and requires the top-level
/// `sub_id` all the same — which [`crate::Set`] makes structural.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    uri: EventUri,
    payload: Map<String, Value>,
}

impl SecurityEvent {
    /// An event of `uri` with an empty payload.
    #[must_use]
    pub fn new(uri: EventUri) -> Self {
        Self {
            uri,
            payload: Map::new(),
        }
    }

    /// Sets the event's own `subject` member (SSF 1.0 §3.1).
    ///
    /// Optional, and never a substitute for the SET's `sub_id`: the two are
    /// emitted together when this is used, because §3.1 requires `sub_id` to
    /// describe the primary subject whatever the event body also says.
    #[must_use]
    pub fn about(mut self, subject: &Subject) -> Self {
        self.payload.insert("subject".to_owned(), subject.to_json());
        self
    }

    /// Sets the CAEP `event_timestamp`: when the event happened, in seconds.
    ///
    /// Distinct from the SET's `iat`, which is when the token was *issued*. An
    /// outbox that retries, or a stream that is resumed after an outage, makes
    /// the two differ by however long the delay was.
    #[must_use]
    pub fn at(mut self, when: OffsetDateTime) -> Self {
        self.payload.insert(
            "event_timestamp".to_owned(),
            Value::from(when.unix_timestamp()),
        );
        self
    }

    /// Sets an event-specific payload member.
    #[must_use]
    pub fn with(mut self, name: &str, value: Value) -> Self {
        self.payload.insert(name.to_owned(), value);
        self
    }

    /// The event type URI.
    #[must_use]
    pub const fn uri(&self) -> &EventUri {
        &self.uri
    }

    /// The `events` claim holding this event, and only this one.
    #[must_use]
    pub(crate) fn to_events_claim(&self) -> Value {
        let mut events = Map::new();
        events.insert(
            self.uri.as_str().to_owned(),
            Value::Object(self.payload.clone()),
        );
        Value::Object(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subject::SimpleSubject;
    use serde_json::json;

    fn uri() -> EventUri {
        EventUri::parse("https://schemas.openid.net/secevent/caep/event-type/session-revoked")
            .expect("an event type")
    }

    #[test]
    fn an_event_renders_under_its_own_uri() {
        let event = SecurityEvent::new(uri()).with("initiating_entity", Value::from("policy"));

        assert_eq!(
            event.to_events_claim(),
            json!({
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
                    "initiating_entity": "policy",
                },
            })
        );
    }

    /// SSF 1.0 §3.1: an event may carry its own `subject`.
    #[test]
    fn an_event_can_carry_its_own_subject_member() {
        let subject = Subject::from(SimpleSubject::opaque("u-1").expect("a subject"));
        let event = SecurityEvent::new(uri()).about(&subject);

        assert_eq!(
            event.to_events_claim()[uri().as_str()]["subject"],
            json!({"format": "opaque", "id": "u-1"})
        );
    }

    #[test]
    fn the_event_timestamp_is_seconds_since_the_epoch() {
        let when = OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("a time");
        let event = SecurityEvent::new(uri()).at(when);

        assert_eq!(
            event.to_events_claim()[uri().as_str()]["event_timestamp"],
            json!(1_760_000_000_i64)
        );
    }

    #[test]
    fn a_relative_or_fragmented_event_type_is_refused() {
        assert_eq!(
            EventUri::parse("session-revoked"),
            Err(EventError::NotAbsolute)
        );
        assert_eq!(
            EventUri::parse("https://schemas.example/e#frag"),
            Err(EventError::HasFragment)
        );
        assert_eq!(EventUri::parse(""), Err(EventError::Length { found: 0 }));
        assert_eq!(
            EventUri::parse(&"h".repeat(MAX_EVENT_URI_LEN + 1)),
            Err(EventError::Length {
                found: MAX_EVENT_URI_LEN + 1,
            })
        );
    }

    /// A receiver dispatches on the exact key, so normalisation would emit an
    /// event type nobody registered.
    #[test]
    fn the_uri_is_kept_exactly_as_written() {
        for raw in [
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
            "https://Schemas.Example/Event",
            "urn:example:event:one",
        ] {
            assert_eq!(EventUri::parse(raw).expect("a uri").as_str(), raw);
        }
    }
}
