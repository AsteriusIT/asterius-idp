//! The poll-based delivery method's request and response (RFC 8936 §2).
//!
//! A poll is one `POST` carrying a JSON object that does three things at once
//! (§2.1): it acknowledges the SETs the receiver has already processed, it
//! reports the ones it could not, and it asks for more. The response (§2.3)
//! is a map from `jti` to the compact serialisation of a SET, plus a flag
//! saying whether the transmitter is holding any back.
//!
//! Everything here is the *shape* of those two objects. What is queued, what
//! an acknowledgement removes and how long a long poll waits belong to the
//! transmitter's storage and to its endpoint; this module has no database, no
//! clock and no HTTP, for the same reason [`crate::stream`] has none.
//!
//! # Why this is a parser and is treated as one
//!
//! The poll request is the only SSF document a *receiver* writes and this
//! transmitter reads. It arrives with an access token, and its members steer
//! two destructive operations — an acknowledgement deletes queued SETs, an
//! error report retires them — so a member read loosely is a signal a
//! receiver silently stops getting. Hence: a bound on every member before it
//! is kept ([`MAX_ACK`], [`MAX_SET_ERRS`], [`MAX_JTI_LEN`],
//! [`MAX_ERR_CODE_LEN`], [`MAX_ERR_DESCRIPTION_LEN`]), a refusal for a known
//! member of the wrong type, and `fuzz/fuzz_targets/ssf_poll_request.rs` over
//! [`PollRequest::parse`].
//!
//! Unknown members are ignored, as in [`crate::stream`]: RFC 8936 is extended
//! by profiles, and a receiver built against a later one must not be refused
//! for sending a member this transmitter has not heard of.
//!
//! # Two defaults worth stating out loud
//!
//! **`returnImmediately` defaults to `false`** — §2.1 makes long polling the
//! default behaviour of a poll request that does not say otherwise, so a
//! receiver that sends `{}` is asking the transmitter to hold the request open
//! until an event is available. [`MAX_LONG_POLL`] bounds that wait, because
//! the alternative is a receiver holding a connection of this server open for
//! as long as it likes.
//!
//! **`maxEvents` is advisory and capped.** §2.1 lets the receiver name the
//! most SETs it wants; it does not oblige the transmitter to send that many.
//! [`MAX_EVENTS`] is the cap, and `moreAvailable` (§2.3) is how the receiver
//! learns that the rest are still waiting — so a cap costs a receiver another
//! round trip and never costs it an event.

use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use thiserror::Error;

/// The most SETs one poll returns, whatever `maxEvents` asks for.
///
/// A hundred SETs is already a response of a few hundred kibibytes, and a
/// receiver that is behind clears its backlog in as many round trips as it
/// takes — each of which it acknowledges, so the queue shrinks as it goes.
/// An unbounded `maxEvents` would let one request ask this server to read and
/// render a tenant's whole backlog into memory at once.
pub const MAX_EVENTS: usize = 100;

/// The most `jti` values one poll may acknowledge.
///
/// Ten batches' worth: a receiver that polled ten times without acknowledging
/// can still catch up in one request, and a request naming a million
/// identifiers is not a receiver catching up.
pub const MAX_ACK: usize = 10 * MAX_EVENTS;

/// The most entries `setErrs` may carry. One batch: a receiver reports errors
/// about SETs it was just handed.
pub const MAX_SET_ERRS: usize = MAX_EVENTS;

/// The longest `jti` this transmitter will look for.
///
/// Its own SETs carry [`crate::SetId`], which is well inside this; the bound
/// is here because the value is a receiver's string and reaches a `WHERE`
/// clause.
pub const MAX_JTI_LEN: usize = 128;

/// The longest `err` code kept from a `setErrs` entry (§2.4).
pub const MAX_ERR_CODE_LEN: usize = 64;

/// The longest `description` kept from a `setErrs` entry (§2.4).
///
/// Receiver-supplied free text that lands in this transmitter's audit trail,
/// so it is bounded before it is stored and never echoed in an error message.
pub const MAX_ERR_DESCRIPTION_LEN: usize = 256;

/// The longest a poll request is held open when `returnImmediately` is false
/// (§2.1), in seconds.
///
/// Thirty seconds is the value SSF deployments converge on: long enough that
/// an idle receiver is not re-authenticating every second, short enough that
/// a proxy in front of this server does not time the request out first — and
/// short enough that a shutdown is not waiting on it.
pub const MAX_LONG_POLL: u64 = 30;

/// Why a poll request was refused (§2.1). A 400 in every case.
///
/// No variant carries a value the request supplied: an `err` code and a
/// `description` are receiver text, a `jti` names a SET, and these messages
/// reach both the response body and the logs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PollError {
    /// The body is not a JSON object.
    #[error("a poll request must be a JSON object")]
    NotAnObject,
    /// A member is present with the wrong JSON type.
    #[error("`{member}` is not of the type RFC 8936 §2.1 gives it")]
    WrongType {
        /// The member's name. A constant from this module, never a value.
        member: &'static str,
    },
    /// A member is present but too long, or holds too many entries.
    #[error("`{member}` is longer than this transmitter accepts")]
    TooLong {
        /// The member's name.
        member: &'static str,
    },
    /// A `setErrs` entry without the `err` code §2.4 requires.
    #[error("a `setErrs` entry must carry an `err` code")]
    MissingErrorCode,
}

/// One `setErrs` entry: a SET the receiver rejected, and why (§2.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedSet {
    /// The `jti` of the SET that was rejected.
    pub jti: String,
    /// §2.4's `err`: a code from the SET error registry. Kept as the receiver
    /// spelled it — this transmitter does not act on the code, it records it,
    /// and a code it does not recognise is exactly the one an operator needs
    /// to see.
    pub err: String,
    /// §2.4's `description`, if the receiver sent one.
    pub description: Option<String>,
}

/// A poll request (§2.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PollRequest {
    /// `maxEvents` as the receiver asked for it, before [`MAX_EVENTS`] is
    /// applied. Kept unclamped so [`Self::batch_size`] is the one place the
    /// cap lives.
    pub max_events: Option<u64>,
    /// `returnImmediately`. See the module documentation for the default.
    pub return_immediately: bool,
    /// `ack`: the SETs the receiver has processed and this transmitter may
    /// stop holding (§2.4).
    pub ack: Vec<String>,
    /// `setErrs`: the SETs the receiver could not process (§2.4).
    pub set_errs: Vec<RejectedSet>,
}

impl PollRequest {
    /// Reads one poll request (§2.1).
    ///
    /// # Errors
    ///
    /// [`PollError`] for anything §2.1's 400 covers: a body that is not an
    /// object, a known member of the wrong type, or a member past one of this
    /// module's bounds.
    // fuzz-target: ssf_poll_request
    pub fn parse(body: &Value) -> Result<Self, PollError> {
        let object = body.as_object().ok_or(PollError::NotAnObject)?;
        let mut request = Self::default();

        if let Some(value) = object.get("maxEvents") {
            // `as_u64` is the whole check: §2.1 makes this a non-negative
            // integer, so a negative number and a fraction are both a member
            // whose meaning this transmitter would have to invent.
            request.max_events = Some(value.as_u64().ok_or(PollError::WrongType {
                member: "maxEvents",
            })?);
        }
        if let Some(value) = object.get("returnImmediately") {
            request.return_immediately = value.as_bool().ok_or(PollError::WrongType {
                member: "returnImmediately",
            })?;
        }
        if let Some(value) = object.get("ack") {
            request.ack = parse_ack(value)?;
        }
        if let Some(value) = object.get("setErrs") {
            request.set_errs = parse_set_errs(value)?;
        }
        Ok(request)
    }

    /// How many SETs this poll may be answered with: `maxEvents` bounded by
    /// [`MAX_EVENTS`], or [`MAX_EVENTS`] when the receiver did not ask.
    ///
    /// Zero is a real answer, not a missing one: §2.1's `maxEvents: 0` is how
    /// a receiver acknowledges without asking for more, and returning a SET to
    /// it would be handing over an event it is not ready to process.
    #[must_use]
    pub fn batch_size(&self) -> usize {
        let asked = self.max_events.map_or(MAX_EVENTS, |events| {
            usize::try_from(events).unwrap_or(MAX_EVENTS)
        });
        asked.min(MAX_EVENTS)
    }

    /// Whether this request asks the transmitter to wait for an event (§2.1).
    ///
    /// A poll that wants no events never waits, whichever way
    /// `returnImmediately` was sent: there is nothing for the wait to end on.
    #[must_use]
    pub fn waits(&self) -> bool {
        !self.return_immediately && self.batch_size() > 0
    }
}

/// §2.1's `ack`: an array of `jti` strings.
fn parse_ack(value: &Value) -> Result<Vec<String>, PollError> {
    let entries = value
        .as_array()
        .ok_or(PollError::WrongType { member: "ack" })?;
    if entries.len() > MAX_ACK {
        return Err(PollError::TooLong { member: "ack" });
    }
    entries
        .iter()
        .map(|entry| {
            let jti = entry
                .as_str()
                .ok_or(PollError::WrongType { member: "ack" })?;
            bounded(jti, MAX_JTI_LEN, "ack")
        })
        .collect()
}

/// §2.4's `setErrs`: an object keyed by `jti`, whose values carry `err` and an
/// optional `description`.
fn parse_set_errs(value: &Value) -> Result<Vec<RejectedSet>, PollError> {
    let entries = value
        .as_object()
        .ok_or(PollError::WrongType { member: "setErrs" })?;
    if entries.len() > MAX_SET_ERRS {
        return Err(PollError::TooLong { member: "setErrs" });
    }
    entries
        .iter()
        .map(|(jti, detail)| parse_set_err(jti, detail))
        .collect()
}

/// One `setErrs` member.
fn parse_set_err(jti: &str, detail: &Value) -> Result<RejectedSet, PollError> {
    let jti = bounded(jti, MAX_JTI_LEN, "setErrs")?;
    let detail = detail
        .as_object()
        .ok_or(PollError::WrongType { member: "setErrs" })?;
    let err = detail
        .get("err")
        .ok_or(PollError::MissingErrorCode)?
        .as_str()
        .ok_or(PollError::WrongType { member: "err" })?;
    let err = bounded(err, MAX_ERR_CODE_LEN, "err")?;
    let description = detail
        .get("description")
        .map(|value| {
            let text = value.as_str().ok_or(PollError::WrongType {
                member: "description",
            })?;
            bounded(text, MAX_ERR_DESCRIPTION_LEN, "description")
        })
        .transpose()?;
    Ok(RejectedSet {
        jti,
        err,
        description,
    })
}

/// A receiver string, kept only if it is inside its bound.
///
/// Characters rather than bytes, as [`crate::stream`] counts them: the bound
/// is about how much text a receiver may hand over, and a multi-byte code
/// point is one piece of text.
fn bounded(value: &str, max: usize, member: &'static str) -> Result<String, PollError> {
    if value.chars().count() > max {
        return Err(PollError::TooLong { member });
    }
    Ok(value.to_owned())
}

/// A poll response (§2.3).
///
/// `sets` is a map and not an array because that is §2.3's shape: the `jti` is
/// the member name, so a receiver reading the response has the identifier it
/// must acknowledge without parsing the token first. A [`BTreeMap`] keeps the
/// rendering deterministic, which is what lets a test assert on a whole body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PollResponse {
    /// §2.3's `sets`: `jti` to the compact serialisation of the SET.
    pub sets: BTreeMap<String, String>,
    /// §2.3's `moreAvailable`: the transmitter is holding SETs this response
    /// did not carry.
    pub more_available: bool,
}

impl PollResponse {
    /// An empty response, which is what a long poll that timed out returns.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Adds one SET to the response.
    #[must_use]
    pub fn with(mut self, jti: impl Into<String>, jws: impl Into<String>) -> Self {
        self.sets.insert(jti.into(), jws.into());
        self
    }

    /// Says the transmitter is holding more (§2.3).
    #[must_use]
    pub const fn holding_more(mut self, more: bool) -> Self {
        self.more_available = more;
        self
    }

    /// §2.3's object.
    ///
    /// Both members are always rendered. §2.3 makes `moreAvailable` optional
    /// with a default of `false`, and sending it anyway costs nothing and
    /// spares a receiver the default.
    #[must_use]
    pub fn render(&self) -> Map<String, Value> {
        let sets: Map<String, Value> = self
            .sets
            .iter()
            .map(|(jti, jws)| (jti.clone(), json!(jws)))
            .collect();
        let mut object = Map::new();
        object.insert("sets".to_owned(), Value::Object(sets));
        object.insert("moreAvailable".to_owned(), json!(self.more_available));
        object
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_poll_request_asks_for_a_full_batch_and_waits() {
        // Arrange: `{}` — §2.1's smallest request.
        let body = json!({});

        // Act.
        let request = PollRequest::parse(&body).expect("an empty object is a poll request");

        // Assert: the defaults of §2.1, including long polling.
        assert_eq!(request.batch_size(), MAX_EVENTS);
        assert!(request.waits(), "returnImmediately defaults to false");
    }

    #[test]
    fn return_immediately_stops_the_request_from_waiting() {
        // Arrange.
        let body = json!({"returnImmediately": true});

        // Act.
        let request = PollRequest::parse(&body).expect("a poll request");

        // Assert.
        assert!(!request.waits());
    }

    #[test]
    fn max_events_is_capped_at_a_hundred() {
        // Arrange: a receiver asking for far more than the cap.
        let body = json!({"maxEvents": 10_000});

        // Act.
        let request = PollRequest::parse(&body).expect("a poll request");

        // Assert: what it asked for is kept, and what it gets is the cap.
        assert_eq!(request.max_events, Some(10_000));
        assert_eq!(request.batch_size(), MAX_EVENTS);
    }

    #[test]
    fn max_events_zero_asks_for_nothing_and_does_not_wait() {
        // Arrange: §2.1's acknowledge-only poll.
        let body = json!({"maxEvents": 0, "ack": ["set-1"]});

        // Act.
        let request = PollRequest::parse(&body).expect("a poll request");

        // Assert.
        assert_eq!(request.batch_size(), 0);
        assert!(!request.waits(), "a poll that wants no events cannot wait");
    }

    #[test]
    fn a_negative_max_events_is_refused() {
        // Arrange.
        let body = json!({"maxEvents": -1});

        // Act.
        let error = PollRequest::parse(&body).expect_err("a negative maxEvents");

        // Assert.
        assert_eq!(
            error,
            PollError::WrongType {
                member: "maxEvents"
            }
        );
    }

    #[test]
    fn ack_is_read_as_a_list_of_identifiers() {
        // Arrange.
        let body = json!({"ack": ["set-1", "set-2"]});

        // Act.
        let request = PollRequest::parse(&body).expect("a poll request");

        // Assert.
        assert_eq!(request.ack, vec!["set-1".to_owned(), "set-2".to_owned()]);
    }

    #[test]
    fn an_ack_entry_that_is_not_a_string_is_refused() {
        // Arrange.
        let body = json!({"ack": [42]});

        // Act.
        let error = PollRequest::parse(&body).expect_err("a numeric ack entry");

        // Assert.
        assert_eq!(error, PollError::WrongType { member: "ack" });
    }

    #[test]
    fn an_ack_longer_than_the_bound_is_refused() {
        // Arrange.
        let entries: Vec<Value> = (0..=MAX_ACK)
            .map(|index| json!(index.to_string()))
            .collect();
        let body = json!({"ack": entries});

        // Act.
        let error = PollRequest::parse(&body).expect_err("an oversized ack");

        // Assert.
        assert_eq!(error, PollError::TooLong { member: "ack" });
    }

    #[test]
    fn an_ack_identifier_longer_than_the_bound_is_refused() {
        // Arrange.
        let body = json!({"ack": ["x".repeat(MAX_JTI_LEN + 1)]});

        // Act.
        let error = PollRequest::parse(&body).expect_err("an oversized identifier");

        // Assert.
        assert_eq!(error, PollError::TooLong { member: "ack" });
    }

    #[test]
    fn set_errs_carries_the_code_and_the_description() {
        // Arrange: §2.4's error report.
        let body = json!({
            "setErrs": {
                "set-1": {"err": "invalid_issuer", "description": "not our issuer"}
            }
        });

        // Act.
        let request = PollRequest::parse(&body).expect("a poll request");

        // Assert.
        assert_eq!(
            request.set_errs,
            vec![RejectedSet {
                jti: "set-1".to_owned(),
                err: "invalid_issuer".to_owned(),
                description: Some("not our issuer".to_owned()),
            }]
        );
    }

    #[test]
    fn a_set_errs_entry_without_a_code_is_refused() {
        // Arrange: §2.4 makes `err` required.
        let body = json!({"setErrs": {"set-1": {"description": "no code"}}});

        // Act.
        let error = PollRequest::parse(&body).expect_err("a setErrs entry with no err");

        // Assert.
        assert_eq!(error, PollError::MissingErrorCode);
    }

    #[test]
    fn a_set_errs_entry_that_is_not_an_object_is_refused() {
        // Arrange.
        let body = json!({"setErrs": {"set-1": "invalid_issuer"}});

        // Act.
        let error = PollRequest::parse(&body).expect_err("a string setErrs entry");

        // Assert.
        assert_eq!(error, PollError::WrongType { member: "setErrs" });
    }

    #[test]
    fn a_set_errs_description_longer_than_the_bound_is_refused() {
        // Arrange.
        let body = json!({
            "setErrs": {
                "set-1": {"err": "invalid_issuer", "description": "x".repeat(MAX_ERR_DESCRIPTION_LEN + 1)}
            }
        });

        // Act.
        let error = PollRequest::parse(&body).expect_err("an oversized description");

        // Assert.
        assert_eq!(
            error,
            PollError::TooLong {
                member: "description"
            }
        );
    }

    #[test]
    fn a_member_this_transmitter_has_not_heard_of_is_ignored() {
        // Arrange: a receiver built against a later profile.
        let body = json!({"maxEvents": 1, "somethingLater": {"nested": true}});

        // Act.
        let request = PollRequest::parse(&body).expect("a poll request");

        // Assert.
        assert_eq!(request.batch_size(), 1);
    }

    #[test]
    fn a_body_that_is_not_an_object_is_refused() {
        // Arrange.
        let body = json!(["ack"]);

        // Act.
        let error = PollRequest::parse(&body).expect_err("an array body");

        // Assert.
        assert_eq!(error, PollError::NotAnObject);
    }

    #[test]
    fn an_empty_response_still_carries_both_members() {
        // Arrange: the response a long poll that timed out returns.
        let response = PollResponse::empty();

        // Act.
        let rendered = Value::Object(response.render());

        // Assert: §2.3's shape, with nothing in it.
        assert_eq!(rendered, json!({"sets": {}, "moreAvailable": false}));
    }

    #[test]
    fn a_response_maps_each_identifier_to_its_token() {
        // Arrange.
        let response = PollResponse::empty()
            .with("set-1", "a.b.c")
            .with("set-2", "d.e.f")
            .holding_more(true);

        // Act.
        let rendered = Value::Object(response.render());

        // Assert.
        assert_eq!(
            rendered,
            json!({
                "sets": {"set-1": "a.b.c", "set-2": "d.e.f"},
                "moreAvailable": true
            })
        );
    }
}
