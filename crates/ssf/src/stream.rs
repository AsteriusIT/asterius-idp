//! Stream configuration: the object SSF 1.0 §8.1.1 defines, and the rules
//! §8.1.1.1 to §8.1.1.5 apply to it.
//!
//! This module holds the *protocol*, and nothing else. It parses a receiver's
//! request, decides what a stream looks like after a `POST`, a `PATCH` or a
//! `PUT`, and renders the object a receiver reads back. It reaches no
//! database, authenticates nobody and makes no HTTP decision: which receiver
//! is calling, whether it may have a second stream, and what status code a
//! refusal becomes all live in `asterius_server::http::ssf`.
//!
//! # The one distinction the whole section turns on
//!
//! §8.1.1 splits the members in two.
//!
//! * **Receiver-supplied**: `events_requested`, `delivery`, `description`,
//!   `inactivity_timeout`. These are what a receiver is configuring.
//! * **Transmitter-supplied**: `stream_id`, `iss`, `aud`, `events_supported`,
//!   `events_delivered`, `min_verification_interval`. These describe what the
//!   transmitter decided, and §8.1.1.3 says a request that carries one with a
//!   value that is *not* the current one is an error rather than a change.
//!
//! [`StreamRequest::parse`] therefore keeps the echoed transmitter-supplied
//! members verbatim rather than dropping them, and
//! [`StreamConfiguration::refuse_transmitter_edits`] is the comparison. The
//! alternative — ignoring them — would let a receiver believe it had changed
//! its own `aud`, which is the one member that decides whose signals reach it.
//!
//! # `aud` is settled once, at creation
//!
//! §8.1.1 makes `aud` immutable. A receiver may name it on the `POST` (it is
//! what its own SET verifier will check the `aud` claim against); once the
//! stream exists it is transmitter-supplied like `iss`, and a `PATCH` or `PUT`
//! naming a different one is refused. A `POST` that names none gets the
//! receiver's own client identifier, which is the only audience the
//! transmitter can be sure the receiver recognises.
//!
//! # The one member that is a credential
//!
//! `delivery.authorization_header` (RFC 8935 §2.2; SSF 1.0 §6.1.1) is a
//! credential the receiver hands the transmitter to present on every push. It
//! is accepted, validated as an HTTP field value
//! ([`crate::push::AuthorizationHeader`]) and stored sealed under the tenant's
//! key-encryption key, inside the sweep `asterius_store_pg::rewrap` re-seals —
//! the condition `ast-0ju.3` set for accepting it at all.
//!
//! It is **never rendered back**. §8.1.1 lists it among `delivery`'s members,
//! and a stream read (§8.1.1.2) is authorized by a token rather than by
//! holding the credential: echoing it would turn every read into a second copy
//! of a secret, in a response body and in whatever log captures one, for a
//! caller that already had it. A receiver that has lost it registers a new
//! one. That also settles §8.1.1.3 for this member: one this transmitter does
//! not render is not one a request can be refused for echoing differently.

use crate::event::EventUri;
use crate::push::{AuthorizationHeader, AuthorizationHeaderError};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// RFC 8936, the poll-based delivery method, as SSF 1.0 §8.1.1 names it.
pub const DELIVERY_POLL: &str = "urn:ietf:rfc:8936";

/// RFC 8935, the push-based delivery method.
pub const DELIVERY_PUSH: &str = "urn:ietf:rfc:8935";

/// The scope a receiver's access token must carry to reach the management API
/// (SSF 1.0 §7.1's `authorization_schemes`, RFC 6749 §3.3).
///
/// One scope and not one per verb: §8 describes a single management API over
/// one stream, and a receiver that may create a stream may already delete the
/// one it created. The separation that matters here is the *audience* — a
/// token for the business API cannot reach this endpoint — and that is what
/// `aud` does.
pub const SCOPE_MANAGE: &str = "ssf.manage";

/// The scope a receiver's access token must carry to poll for its SETs
/// (RFC 8936; SSF 1.0 §7.1.1, which SHOULD protect the polling endpoint).
///
/// Its own scope, separate from [`SCOPE_MANAGE`], because the two are
/// different powers held by different parts of a receiver: configuring a
/// stream is an administrative act done once, and polling it is what the
/// component that consumes signals does all day. A deployment that hands its
/// event consumer a token which can also delete the stream has given a
/// long-lived credential more than it needs — and §7.1.1's point is that these
/// endpoints are protected, not that one token opens both.
pub const SCOPE_POLL: &str = "ssf.poll";

/// How many event type URIs a receiver may request on one stream.
///
/// Not a specification limit. `events_requested` is stored, echoed and
/// intersected on every request; a bound turns an unbounded write into a
/// refusal a receiver can read.
pub const MAX_EVENTS_REQUESTED: usize = 64;

/// The longest `description` this transmitter keeps (§8.1.1).
pub const MAX_DESCRIPTION_LEN: usize = 256;

/// How many audience values one stream may carry.
pub const MAX_AUDIENCE: usize = 8;

/// The longest audience value, and the longest delivery URL.
pub const MAX_URL_LEN: usize = 512;

/// The narrowest `inactivity_timeout` a receiver may ask for, in seconds.
pub const MIN_INACTIVITY_TIMEOUT: u64 = 60;

/// The widest `inactivity_timeout` a receiver may ask for: one year.
pub const MAX_INACTIVITY_TIMEOUT: u64 = 365 * 24 * 60 * 60;

/// How often a receiver may ask for a verification event (§8.1.1,
/// §8.1.4.2's 429).
///
/// Transmitter-supplied, so it is a constant here rather than a request
/// member. Sixty seconds: long enough that a receiver polling for liveness
/// cannot turn verification into a signal flood, short enough that a receiver
/// diagnosing a silent stream is not waiting on this server.
pub const MIN_VERIFICATION_INTERVAL: u64 = 60;

/// The event types a stream of this transmitter can deliver.
///
/// Empty, and that is a claim rather than a placeholder: an event type belongs
/// here the day something emits it. The emitters are `ast-0ju.5` (verification
/// and stream-updated) and `ast-0ju.8` (the CAEP and RISC types), and each of
/// them adds its own URI to this list as it lands.
///
/// The consequence is visible and intended: a receiver that requests
/// `session-revoked` today is told, in `events_delivered`, that it will
/// receive nothing. §8.1.1 makes `events_delivered` the member "the receiver
/// relies on", so the honest empty list is what stops a receiver believing it
/// has continuous access coverage it has not got — the same argument
/// [`crate::metadata`] makes for advertising no endpoint it does not route.
pub const SUPPORTED_EVENTS: &[&str] = &[];

/// How many bytes of entropy a stream identifier carries. 128 bits.
const STREAM_ID_BYTES: usize = 16;

/// Why a stream configuration request was refused.
///
/// Every variant is a client error — §8.1.1.1's and §8.1.1.3's 400 — except
/// where the caller maps it otherwise. No variant carries a value the request
/// supplied: these messages reach logs and a `description` is receiver text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum StreamError {
    /// The body is not a JSON object.
    #[error("a stream configuration request must be a JSON object")]
    NotAnObject,
    /// A member is present with the wrong JSON type.
    #[error("`{member}` is not of the type §8.1.1 gives it")]
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
    /// `delivery.method` names something this transmitter does not do
    /// (§8.1.1.1: an unsupported delivery method is a 400).
    #[error("the requested delivery method is not one this transmitter supports")]
    UnsupportedDeliveryMethod,
    /// A push delivery whose `endpoint_url` is not https (RFC 8935 §2.2).
    #[error("a push delivery endpoint must be an https URL")]
    InsecureEndpoint,
    /// A push delivery whose `authorization_header` is not a value HTTP can
    /// carry (SSF 1.0 §6.1.1).
    #[error("`authorization_header` is not a header value this transmitter can send")]
    BadAuthorizationHeader(
        /// Which rule it broke. Names no part of the value: it is a
        /// credential, and these messages reach logs.
        #[from]
        AuthorizationHeaderError,
    ),
    /// A transmitter-supplied member was echoed with a value that is not the
    /// current one (§8.1.1.3).
    #[error("`{member}` is transmitter-supplied and was sent with a different value")]
    TransmitterSupplied {
        /// The member's name.
        member: &'static str,
    },
    /// `stream_id` is missing where §8.1.1.3 and §8.1.1.4 require it.
    #[error("`stream_id` is required on this request")]
    MissingStreamId,
    /// An `events_requested` entry is not a usable event type URI.
    #[error("an entry of `events_requested` is not an event type URI")]
    BadEventUri,
}

/// A stream's status (SSF 1.0 §8.1.2).
///
/// Three states and no fourth. The transmitter writes this as well as the
/// receiver: RFC 8935 §2.4 bounds the retries of *one* SET and says nothing
/// about a receiver that has refused every SET for a day, so a push delivery
/// that exhausts its budget pauses the stream with a reason
/// (`asterius_store_pg::PgSsfStreams::pause`).
///
/// [`Self::Paused`] rather than [`Self::Disabled`] for that, deliberately:
/// §8.1.2 makes paused a state a stream is expected to leave, and events go on
/// being queued while it lasts. Disabling is an act of the receiver's or of an
/// operator's, and this server never does it on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StreamStatus {
    /// Events are delivered as they are generated.
    #[default]
    Enabled,
    /// Events are queued but not delivered.
    Paused,
    /// Events are neither queued nor delivered.
    Disabled,
}

impl StreamStatus {
    /// Every status, so a test can be exhaustive.
    pub const ALL: [Self; 3] = [Self::Enabled, Self::Paused, Self::Disabled];

    /// The value as §8.1.2 spells it, and as the column stores it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Paused => "paused",
            Self::Disabled => "disabled",
        }
    }

    /// The status `raw` names, or `None` for anything else.
    ///
    /// `None` rather than a default: a stored value this build does not
    /// recognise is a row it must not guess about, and guessing `enabled`
    /// would resume delivery to a stream somebody stopped.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|status| status.as_str() == raw)
    }

    /// Whether a SET may go out on a stream in this state.
    #[must_use]
    pub const fn delivers(self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Whether an event this stream cannot transmit is *kept* for later
    /// (§8.1.2).
    ///
    /// > `paused`: […] The Transmitter SHOULD hold any events it would have
    /// > transmitted while paused, and transmit them when the stream becomes
    /// > enabled.
    /// > `disabled`: […] will not hold any events.
    ///
    /// True for [`Self::Paused`] and false for [`Self::Disabled`], which is
    /// the whole difference between the two: both stop delivery, and only one
    /// of them promises the receiver will eventually hear what it missed.
    /// False for [`Self::Enabled`] as well, which transmits rather than holds
    /// — so a caller asking both questions gets one yes at most.
    #[must_use]
    pub const fn holds(self) -> bool {
        matches!(self, Self::Paused)
    }
}

/// A stream identifier: 128 bits of entropy, base64url-encoded.
///
/// Transmitter-supplied (§8.1.1) and unguessable on purpose. It names a stream
/// in a URL a receiver holds, it is the `sub_id` of a verification event
/// (§8.1.4), and — while the endpoint answers 404 for another receiver's
/// stream — a guessable one would still turn a `DELETE` into something worth
/// trying. There is no constructor taking a caller's string except
/// [`StreamId::parse`], which is for reading one back.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(String);

impl StreamId {
    /// The longest identifier this server will read back.
    ///
    /// Its own generated form is 22 characters; the ceiling is what stops a
    /// URL segment of arbitrary length reaching a query.
    pub const MAX_LEN: usize = 64;

    /// Draws a fresh identifier from the operating system CSPRNG.
    ///
    /// # Panics
    ///
    /// If the OS CSPRNG is unavailable, for the reason
    /// [`crate::SetId::generate`] gives: a predictable identifier is worse
    /// than no identifier.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0_u8; STREAM_ID_BYTES];
        getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
        Self(B64.encode(bytes))
    }

    /// Reads an identifier back, from a URL or a stored row.
    ///
    /// Shape only — unreserved characters, bounded length — so that a lookup
    /// is never made with something that was never one of ours. `None` is "no
    /// such stream", which is what the caller answers 404 to.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.is_empty() || raw.len() > Self::MAX_LEN {
            return None;
        }
        raw.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            .then(|| Self(raw.to_owned()))
    }

    /// The identifier, as it appears in `stream_id`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How a stream's events reach the receiver (§8.1.1's `delivery`).
///
/// Two variants and no third: RFC 8935 and RFC 8936 are the two methods SSF
/// 1.0 defines, and an unrecognised URN is
/// [`StreamError::UnsupportedDeliveryMethod`] rather than a stream nobody can
/// deliver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// RFC 8936. `endpoint_url` is the transmitter's polling endpoint, which
    /// is why it is not in this variant: it is derived from the tenant's
    /// issuer by [`StreamConfiguration::render`] and never stored.
    Poll,
    /// RFC 8935. `endpoint_url` is the receiver's, and must be https.
    Push {
        /// Where the transmitter POSTs each SET.
        endpoint_url: String,
        /// What the transmitter presents on every push (SSF 1.0 §6.1.1), if
        /// the receiver registered one.
        authorization_header: Option<AuthorizationHeader>,
    },
}

impl Delivery {
    /// The method URN, as §8.1.1 spells it.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Poll => DELIVERY_POLL,
            Self::Push { .. } => DELIVERY_PUSH,
        }
    }

    /// The receiver's endpoint, for a push stream.
    ///
    /// `None` for a poll stream, where the endpoint belongs to the
    /// transmitter and is rendered rather than stored.
    #[must_use]
    pub fn endpoint_url(&self) -> Option<&str> {
        match self {
            Self::Poll => None,
            Self::Push { endpoint_url, .. } => Some(endpoint_url),
        }
    }
}

/// A `delivery` as it arrived, before the transmitter's own URL is known.
///
/// The poll variant keeps whatever `endpoint_url` the request carried, because
/// §8.1.1 makes that member transmitter-supplied for poll delivery: echoing
/// the current one is allowed and naming a different one is §8.1.1.3's error,
/// and telling the two apart needs the transmitter. [`DeliveryRequest::resolve`]
/// is where that happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryRequest {
    /// RFC 8936.
    Poll {
        /// The polling URL the request echoed, if it carried one.
        echoed_endpoint_url: Option<String>,
    },
    /// RFC 8935.
    Push {
        /// The receiver's endpoint, already checked against RFC 8935 §2.2.
        endpoint_url: String,
        /// The credential it registered, already checked as a field value.
        authorization_header: Option<AuthorizationHeader>,
    },
}

impl DeliveryRequest {
    /// The delivery this request asks for, given what the transmitter offers.
    ///
    /// `current` is the stream being updated, where there is one: a receiver
    /// that read its stream back echoes the *per-stream* polling URL
    /// (SSF 1.0 §6.1.2), and only a creation — which has no identifier yet —
    /// may echo the transmitter's base polling endpoint.
    ///
    /// # Errors
    ///
    /// [`StreamError::TransmitterSupplied`] when a poll `endpoint_url` is not
    /// the transmitter's own — §8.1.1.3's rule, applied to the one
    /// receiver-supplied member that has a transmitter-supplied half.
    pub fn resolve(
        &self,
        transmitter: &Transmitter<'_>,
        current: Option<&StreamId>,
    ) -> Result<Delivery, StreamError> {
        match self {
            Self::Poll {
                echoed_endpoint_url: None,
            } => Ok(Delivery::Poll),
            Self::Poll {
                echoed_endpoint_url: Some(echoed),
            } => {
                let ours = echoed == transmitter.poll_endpoint
                    || current.is_some_and(|stream| {
                        *echoed == poll_endpoint_for(transmitter.poll_endpoint, stream)
                    });
                if ours {
                    Ok(Delivery::Poll)
                } else {
                    Err(StreamError::TransmitterSupplied {
                        member: "endpoint_url",
                    })
                }
            }
            Self::Push {
                endpoint_url,
                authorization_header,
            } => Ok(Delivery::Push {
                endpoint_url: endpoint_url.clone(),
                authorization_header: authorization_header.clone(),
            }),
        }
    }
}

/// The receiver-supplied members of one request (§8.1.1), plus whatever
/// transmitter-supplied members it echoed.
///
/// Every field is an [`Option`], and the distinction is the whole of §8.1.1.3
/// versus §8.1.1.4: `None` means "the member was absent", which a `PATCH`
/// reads as "leave it alone" and a `PUT` reads as "remove it".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamRequest {
    /// The stream this request addresses. REQUIRED by §8.1.1.3 and §8.1.1.4,
    /// meaningless on a `POST`.
    pub stream_id: Option<StreamId>,
    /// §8.1.1's `aud`, which only a `POST` may settle.
    pub audience: Option<Vec<String>>,
    /// §8.1.1's `events_requested`. Entries that are not event type URIs are
    /// a refusal; entries this transmitter does not support are *ignored*,
    /// which happens in [`events_delivered`].
    pub events_requested: Option<Vec<String>>,
    /// §8.1.1's `delivery`, as it arrived.
    pub delivery: Option<DeliveryRequest>,
    /// §8.1.1's `description`.
    pub description: Option<String>,
    /// §8.1.1's `inactivity_timeout`, in seconds.
    pub inactivity_timeout: Option<u64>,
    /// The transmitter-supplied members the request carried, verbatim, for
    /// §8.1.1.3's comparison.
    pub echoed: BTreeMap<&'static str, Value>,
}

/// The transmitter-supplied members a request may echo, by name (§8.1.1).
///
/// `stream_id` is not among them: it addresses the request rather than
/// describing the stream, and §8.1.1.3 requires it. `aud` is not among them
/// either, because it is compared as a set rather than as a rendered value —
/// see [`StreamConfiguration::refuse_transmitter_edits`].
const TRANSMITTER_SUPPLIED: [&str; 4] = [
    "iss",
    "events_supported",
    "events_delivered",
    "min_verification_interval",
];

impl StreamRequest {
    /// Parses one request body.
    ///
    /// Unknown members are ignored: §8.1.1 is an extensible object and a
    /// receiver built against a later revision must not be refused for
    /// sending a member this transmitter has not heard of. A *known* member of
    /// the wrong type is not ignored — that is a receiver that means something
    /// this transmitter would get wrong.
    ///
    /// # Errors
    ///
    /// [`StreamError`] for anything §8.1.1.1's or §8.1.1.3's 400 covers.
    // fuzz-target: ssf_stream_configuration
    pub fn parse(body: &Value) -> Result<Self, StreamError> {
        let object = body.as_object().ok_or(StreamError::NotAnObject)?;
        let mut request = Self::default();

        if let Some(value) = object.get("stream_id") {
            let raw = value.as_str().ok_or(StreamError::WrongType {
                member: "stream_id",
            })?;
            request.stream_id = Some(StreamId::parse(raw).ok_or(StreamError::TooLong {
                member: "stream_id",
            })?);
        }
        if let Some(value) = object.get("aud") {
            request.audience = Some(parse_audience(value)?);
        }
        if let Some(value) = object.get("events_requested") {
            request.events_requested = Some(parse_events(value)?);
        }
        if let Some(value) = object.get("delivery") {
            request.delivery = Some(parse_delivery(value)?);
        }
        if let Some(value) = object.get("description") {
            let text = value.as_str().ok_or(StreamError::WrongType {
                member: "description",
            })?;
            if text.chars().count() > MAX_DESCRIPTION_LEN {
                return Err(StreamError::TooLong {
                    member: "description",
                });
            }
            request.description = Some(text.to_owned());
        }
        if let Some(value) = object.get("inactivity_timeout") {
            request.inactivity_timeout = Some(parse_inactivity_timeout(value)?);
        }

        for member in TRANSMITTER_SUPPLIED {
            if let Some(value) = object.get(member) {
                request.echoed.insert(member, value.clone());
            }
        }
        Ok(request)
    }

    /// The stream this request addresses, where one is required.
    ///
    /// # Errors
    ///
    /// [`StreamError::MissingStreamId`] — §8.1.1.3 and §8.1.1.4 both make the
    /// member REQUIRED, and a request without it addresses no stream at all.
    pub fn addressed_stream(&self) -> Result<&StreamId, StreamError> {
        self.stream_id.as_ref().ok_or(StreamError::MissingStreamId)
    }
}

/// §8.1.1's `aud`: a string, or an array of strings.
fn parse_audience(value: &Value) -> Result<Vec<String>, StreamError> {
    let values = match value {
        Value::String(one) => vec![one.clone()],
        Value::Array(many) => many
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(StreamError::WrongType { member: "aud" })
            })
            .collect::<Result<Vec<String>, StreamError>>()?,
        _ => return Err(StreamError::WrongType { member: "aud" }),
    };
    if values.is_empty() || values.len() > MAX_AUDIENCE {
        return Err(StreamError::TooLong { member: "aud" });
    }
    if values
        .iter()
        .any(|entry| entry.is_empty() || entry.chars().count() > MAX_URL_LEN)
    {
        return Err(StreamError::TooLong { member: "aud" });
    }
    Ok(values)
}

/// §8.1.1's `events_requested`: an array of event type URIs.
fn parse_events(value: &Value) -> Result<Vec<String>, StreamError> {
    let entries = value.as_array().ok_or(StreamError::WrongType {
        member: "events_requested",
    })?;
    if entries.len() > MAX_EVENTS_REQUESTED {
        return Err(StreamError::TooLong {
            member: "events_requested",
        });
    }
    let mut events: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let uri = entry.as_str().ok_or(StreamError::WrongType {
            member: "events_requested",
        })?;
        // Validated as a URI here rather than silently ignored: an unknown
        // *event* is ignored by §8.1.1, but a value that is not an event type
        // URI at all is a receiver sending something else entirely.
        EventUri::parse(uri).map_err(|_| StreamError::BadEventUri)?;
        if !events.iter().any(|seen| seen == uri) {
            events.push(uri.to_owned());
        }
    }
    Ok(events)
}

/// §8.1.1's `delivery`.
fn parse_delivery(value: &Value) -> Result<DeliveryRequest, StreamError> {
    let object = value
        .as_object()
        .ok_or(StreamError::WrongType { member: "delivery" })?;
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or(StreamError::UnsupportedDeliveryMethod)?;
    let endpoint = object.get("endpoint_url");
    match method {
        DELIVERY_POLL => match endpoint {
            // §8.1.1: the polling endpoint is the transmitter's, so an
            // `endpoint_url` here is *echoed* rather than chosen. It is kept
            // and compared in `DeliveryRequest::resolve`, where the
            // transmitter's own URL is known: refusing it outright would
            // refuse the natural round-trip — read the stream, change one
            // member, send it back — which §8.1.1.3 explicitly allows.
            None | Some(Value::Null) => Ok(DeliveryRequest::Poll {
                echoed_endpoint_url: None,
            }),
            Some(url) => Ok(DeliveryRequest::Poll {
                echoed_endpoint_url: Some(
                    url.as_str()
                        .ok_or(StreamError::WrongType {
                            member: "endpoint_url",
                        })?
                        .to_owned(),
                ),
            }),
        },
        DELIVERY_PUSH => {
            let url = endpoint
                .and_then(Value::as_str)
                .ok_or(StreamError::WrongType {
                    member: "endpoint_url",
                })?;
            // Absent and null are "no credential"; anything else has to be a
            // string, because a receiver that meant to register one and sent a
            // number must be told rather than quietly pushed to without it.
            let authorization_header = match object.get("authorization_header") {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let raw = value.as_str().ok_or(StreamError::WrongType {
                        member: "authorization_header",
                    })?;
                    Some(AuthorizationHeader::parse(raw)?)
                }
            };
            Ok(DeliveryRequest::Push {
                endpoint_url: push_endpoint(url)?,
                authorization_header,
            })
        }
        _ => Err(StreamError::UnsupportedDeliveryMethod),
    }
}

/// RFC 8935 §2.2's endpoint: an absolute https URL, and nothing that would
/// make it ambiguous.
///
/// https because a SET is a signed statement about a person's security state
/// and the delivery is a back channel nobody is watching; `http` would put a
/// subject identifier on the wire in clear. Userinfo and fragments are refused
/// because both would be carried into an outbound request built from this
/// string — a fragment is not sent, and userinfo is a credential in a URL.
///
/// Where the request may be *sent* is not decided here: ADR-0006 puts every
/// outbound fetch of a client-supplied URL through one guarded path, and push
/// delivery (`ast-0ju.6`) goes through it like the rest.
fn push_endpoint(raw: &str) -> Result<String, StreamError> {
    if raw.chars().count() > MAX_URL_LEN {
        return Err(StreamError::TooLong {
            member: "endpoint_url",
        });
    }
    let url = url::Url::parse(raw).map_err(|_| StreamError::InsecureEndpoint)?;
    if url.scheme() != "https"
        || !url.has_host()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(StreamError::InsecureEndpoint);
    }
    Ok(raw.to_owned())
}

/// §8.1.1's `inactivity_timeout`: a positive number of seconds, bounded.
fn parse_inactivity_timeout(value: &Value) -> Result<u64, StreamError> {
    let seconds = value.as_u64().ok_or(StreamError::WrongType {
        member: "inactivity_timeout",
    })?;
    if !(MIN_INACTIVITY_TIMEOUT..=MAX_INACTIVITY_TIMEOUT).contains(&seconds) {
        return Err(StreamError::TooLong {
            member: "inactivity_timeout",
        });
    }
    Ok(seconds)
}

/// What this transmitter will deliver on a stream: supported ∩ requested
/// (§8.1.1).
///
/// > `events_delivered`: ... the events that the Transmitter will deliver,
/// > which is the intersection of `events_supported` and `events_requested`.
///
/// A requested event this transmitter does not support is **ignored** and not
/// an error: §8.1.1 makes `events_delivered` the answer, so a receiver that
/// asked for six types and reads three back has been told exactly what it will
/// get. Refusing the whole stream instead would make a receiver's support for
/// a newer event type a reason it cannot configure anything at all.
#[must_use]
pub fn events_delivered(supported: &BTreeSet<String>, requested: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|event| supported.contains(*event))
        .cloned()
        .collect()
}

/// One configured stream, as §8.1.1 defines it.
///
/// The transmitter-supplied members that are constants of the deployment —
/// `iss`, `events_supported`, `min_verification_interval` — are not fields:
/// they are arguments to [`StreamConfiguration::render`], which is what stops
/// a stored row from carrying a stale copy of the tenant's issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamConfiguration {
    /// §8.1.1's `stream_id`.
    pub stream_id: StreamId,
    /// §8.1.1's `aud`. Settled at creation and immutable thereafter.
    pub audience: Vec<String>,
    /// §8.1.1's `events_requested`, as the receiver asked for it — including
    /// types this transmitter does not support, so that a type gaining an
    /// emitter starts being delivered without the receiver asking again.
    pub events_requested: Vec<String>,
    /// §8.1.1's `delivery`.
    pub delivery: Delivery,
    /// §8.1.1's `description`.
    pub description: Option<String>,
    /// §8.1.1's `inactivity_timeout`, in seconds.
    pub inactivity_timeout: Option<u64>,
}

impl StreamConfiguration {
    /// §8.1.1.1: a stream from a `POST` body.
    ///
    /// `default_audience` is what a receiver that named no `aud` gets — its
    /// own client identifier, the one audience the transmitter knows it
    /// recognises — and a `POST` that echoed a transmitter-supplied member is
    /// refused before anything is created, because there is no current value
    /// for it to have matched.
    ///
    /// A body with no `delivery` is a poll stream (§8.1.1.1: where the
    /// delivery method is not specified, the transmitter selects one), which
    /// is the method that needs nothing of the receiver.
    ///
    /// # Errors
    ///
    /// [`StreamError`] for a request §8.1.1.1 answers 400 to.
    pub fn create(
        request: &StreamRequest,
        default_audience: &str,
        transmitter: &Transmitter<'_>,
    ) -> Result<Self, StreamError> {
        if let Some(member) = request.echoed.keys().next() {
            return Err(StreamError::TransmitterSupplied { member });
        }
        Ok(Self {
            stream_id: StreamId::generate(),
            audience: request
                .audience
                .clone()
                .unwrap_or_else(|| vec![default_audience.to_owned()]),
            events_requested: request.events_requested.clone().unwrap_or_default(),
            delivery: resolve_delivery(request, transmitter, None)?,
            description: request.description.clone(),
            inactivity_timeout: request.inactivity_timeout,
        })
    }

    /// §8.1.1.3: the members the request carries are changed, the rest are
    /// left alone.
    ///
    /// # Errors
    ///
    /// [`StreamError::TransmitterSupplied`] if the request carried a
    /// transmitter-supplied member with a value that is not the current one.
    pub fn patch(
        &self,
        request: &StreamRequest,
        transmitter: &Transmitter<'_>,
    ) -> Result<Self, StreamError> {
        self.refuse_transmitter_edits(request, transmitter)?;
        let mut updated = self.clone();
        if let Some(events) = request.events_requested.clone() {
            updated.events_requested = events;
        }
        if let Some(delivery) = &request.delivery {
            updated.delivery = delivery.resolve(transmitter, Some(&self.stream_id))?;
        }
        if let Some(description) = request.description.clone() {
            updated.description = Some(description);
        }
        if let Some(timeout) = request.inactivity_timeout {
            updated.inactivity_timeout = Some(timeout);
        }
        Ok(updated)
    }

    /// §8.1.1.4: the request is the complete set of receiver-supplied
    /// members, so one it does not carry is removed.
    ///
    /// > Properties that are not included in the request body are deleted.
    ///
    /// "Deleted" for `delivery` means back to the transmitter's default rather
    /// than absent: a stream has to have a delivery method to be a stream, and
    /// §8.1.1.1's rule for a `POST` with no `delivery` is the same choice.
    ///
    /// # Errors
    ///
    /// [`StreamError::TransmitterSupplied`], as [`Self::patch`].
    pub fn replace(
        &self,
        request: &StreamRequest,
        transmitter: &Transmitter<'_>,
    ) -> Result<Self, StreamError> {
        self.refuse_transmitter_edits(request, transmitter)?;
        Ok(Self {
            stream_id: self.stream_id.clone(),
            audience: self.audience.clone(),
            events_requested: request.events_requested.clone().unwrap_or_default(),
            delivery: resolve_delivery(request, transmitter, Some(&self.stream_id))?,
            description: request.description.clone(),
            inactivity_timeout: request.inactivity_timeout,
        })
    }

    /// §8.1.1.3: a transmitter-supplied member may be echoed, and only with
    /// the value it already has.
    ///
    /// > Properties that are not receiver-supplied MUST match the current
    /// > values, otherwise the request is an error.
    ///
    /// `aud` is checked here too, and not as a receiver-supplied member: it is
    /// settled at creation and §8.1.1 makes it immutable. The order of an
    /// array carries no meaning — a receiver echoing its own audiences in a
    /// different order means the same set — so the comparison is over sets.
    ///
    /// # Errors
    ///
    /// [`StreamError::TransmitterSupplied`], naming the member.
    pub fn refuse_transmitter_edits(
        &self,
        request: &StreamRequest,
        transmitter: &Transmitter<'_>,
    ) -> Result<(), StreamError> {
        if let Some(audience) = &request.audience
            && audience.iter().collect::<BTreeSet<_>>()
                != self.audience.iter().collect::<BTreeSet<_>>()
        {
            return Err(StreamError::TransmitterSupplied { member: "aud" });
        }
        let current = self.render(transmitter);
        for (member, echoed) in &request.echoed {
            let ours = current.get(*member).unwrap_or(&Value::Null);
            if !same_member(echoed, ours) {
                return Err(StreamError::TransmitterSupplied { member });
            }
        }
        Ok(())
    }

    /// The §8.1.1 object a receiver reads back.
    ///
    /// Every member §8.1.1 defines is present, including the ones that are
    /// this deployment's constants, because a receiver reads its stream to
    /// learn them: `min_verification_interval` is how often it may verify, and
    /// `events_delivered` is what it will actually get.
    #[must_use]
    pub fn render(&self, transmitter: &Transmitter<'_>) -> Map<String, Value> {
        let mut object = Map::new();
        object.insert("stream_id".to_owned(), json!(self.stream_id.as_str()));
        object.insert("iss".to_owned(), json!(transmitter.issuer));
        object.insert("aud".to_owned(), render_audience(&self.audience));
        object.insert(
            "events_supported".to_owned(),
            json!(transmitter.events_supported),
        );
        object.insert("events_requested".to_owned(), json!(self.events_requested));
        object.insert(
            "events_delivered".to_owned(),
            json!(events_delivered(
                transmitter.events_supported,
                &self.events_requested
            )),
        );
        object.insert("delivery".to_owned(), self.render_delivery(transmitter));
        object.insert(
            "min_verification_interval".to_owned(),
            json!(MIN_VERIFICATION_INTERVAL),
        );
        if let Some(description) = &self.description {
            object.insert("description".to_owned(), json!(description));
        }
        if let Some(timeout) = self.inactivity_timeout {
            object.insert("inactivity_timeout".to_owned(), json!(timeout));
        }
        object
    }

    /// §8.1.1's `delivery`, with the poll endpoint filled in.
    ///
    /// The URL is the transmitter's and is rendered rather than stored, so a
    /// tenant whose issuer changes does not hand out an address that no longer
    /// exists. Delivering from it is `ast-0ju.7`; naming it is what §8.1.1.1
    /// requires of the creation response, and a receiver that starts polling
    /// before then gets a 404 rather than silence.
    fn render_delivery(&self, transmitter: &Transmitter<'_>) -> Value {
        match &self.delivery {
            Delivery::Poll => json!({
                "method": DELIVERY_POLL,
                "endpoint_url": poll_endpoint_for(transmitter.poll_endpoint, &self.stream_id),
            }),
            // `authorization_header` is deliberately absent; see the module
            // documentation.
            Delivery::Push { endpoint_url, .. } => json!({
                "method": DELIVERY_PUSH,
                "endpoint_url": endpoint_url,
            }),
        }
    }
}

/// The delivery a request settles on where an absent `delivery` means the
/// transmitter's default (§8.1.1.1 for a `POST`, §8.1.1.4 for a `PUT`).
///
/// Poll, because it is the method that asks nothing of the receiver: a stream
/// has to have a delivery method to be a stream, and the alternative — no
/// method — is a stream whose events have nowhere to go.
fn resolve_delivery(
    request: &StreamRequest,
    transmitter: &Transmitter<'_>,
    current: Option<&StreamId>,
) -> Result<Delivery, StreamError> {
    match &request.delivery {
        None => Ok(Delivery::Poll),
        Some(delivery) => delivery.resolve(transmitter, current),
    }
}

/// The polling URL of one stream (RFC 8936; SSF 1.0 §6.1.2).
///
/// > The URL ... is unique per stream and per receiver.
///
/// One URL per stream rather than one per transmitter, because a poll request
/// (RFC 8936 §2.1) carries no stream identifier: the *address* is what says
/// which stream is being polled, and a shared address would leave a receiver
/// holding two streams unable to say which one it means. The identifier is
/// already 128 unguessable bits ([`StreamId`]), so the URL a receiver holds is
/// not a handle another receiver stumbles on — the endpoint checks the
/// receiver anyway, and the shape of the URL is not what does that work.
#[must_use]
pub fn poll_endpoint_for(base: &str, stream: &StreamId) -> String {
    format!("{base}/{}", stream.as_str())
}

/// What the transmitter contributes to a rendered stream: the members §8.1.1
/// makes transmitter-supplied and this deployment decides.
///
/// Borrowed rather than owned, and passed to every render, so that a stored
/// stream never carries a copy of the tenant's issuer.
#[derive(Debug, Clone, Copy)]
pub struct Transmitter<'a> {
    /// The tenant's issuer: §8.1.1's `iss`, and the `iss` of every SET the
    /// stream carries.
    pub issuer: &'a str,
    /// This tenant's polling endpoint (RFC 8936), for a poll stream.
    pub poll_endpoint: &'a str,
    /// The event types this deployment can deliver. See [`SUPPORTED_EVENTS`].
    pub events_supported: &'a BTreeSet<String>,
}

/// §8.1.1's `aud`: rendered as a string when there is one, an array otherwise.
///
/// RFC 7519 §4.1.3's rule, and the shape [`crate::StreamAudience`] renders a
/// SET's `aud` in — so a receiver comparing the two sees the same spelling.
fn render_audience(audience: &[String]) -> Value {
    match audience {
        [one] => json!(one),
        many => json!(many),
    }
}

/// Whether an echoed member is the value the transmitter holds.
///
/// Arrays are compared as sets, for `events_supported` and `events_delivered`:
/// §8.1.1 gives them no order, and a receiver that sorted them differently
/// means the same thing.
fn same_member(echoed: &Value, ours: &Value) -> bool {
    match (echoed, ours) {
        // `Value` is not `Ord`, so the sets are compared by containment both
        // ways rather than by sorting. The arrays here are `events_supported`
        // and `events_delivered`, both bounded by `MAX_EVENTS_REQUESTED`.
        (Value::Array(left), Value::Array(right)) => {
            left.iter().all(|entry| right.contains(entry))
                && right.iter().all(|entry| left.contains(entry))
        }
        (left, right) => left == right,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECEIVER: &str = "https://receiver.example/events";
    const SESSION_REVOKED: &str =
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    const ACCOUNT_DISABLED: &str =
        "https://schemas.openid.net/secevent/risc/event-type/account-disabled";

    fn supported(events: &[&str]) -> BTreeSet<String> {
        events.iter().map(|event| (*event).to_owned()).collect()
    }

    fn transmitter(events: &BTreeSet<String>) -> Transmitter<'_> {
        Transmitter {
            issuer: "https://as.example/t/demo",
            poll_endpoint: "https://as.example/t/demo/ssf/poll",
            events_supported: events,
        }
    }

    fn request(body: &Value) -> StreamRequest {
        StreamRequest::parse(body).expect("a valid request")
    }

    fn stream(body: &Value) -> StreamConfiguration {
        let events = supported(&[]);
        StreamConfiguration::create(&request(body), RECEIVER, &transmitter(&events))
            .expect("a creatable stream")
    }

    // -----------------------------------------------------------------------
    // §8.1.1.1 — creation
    // -----------------------------------------------------------------------

    /// §8.1.1.1: a `POST` with no `delivery` is a poll stream, and the poll
    /// endpoint is the transmitter's.
    #[test]
    fn a_creation_without_a_delivery_method_is_a_poll_stream() {
        // Arrange
        let events = supported(&[]);
        let stream = stream(&json!({}));

        // Act
        let rendered = stream.render(&transmitter(&events));

        // Assert
        assert_eq!(rendered["delivery"]["method"], json!(DELIVERY_POLL));
        assert_eq!(
            rendered["delivery"]["endpoint_url"],
            json!(format!(
                "https://as.example/t/demo/ssf/poll/{}",
                stream.stream_id.as_str()
            )),
            "SSF 1.0 §6.1.2: the polling URL is unique per stream"
        );
    }

    /// §6.1.2 again, from the other side: two streams of one receiver are
    /// polled at two different URLs, because a poll request (RFC 8936 §2.1)
    /// carries nothing else that could say which stream it means.
    #[test]
    fn two_streams_are_polled_at_two_different_urls() {
        // Arrange
        let events = supported(&[]);
        let one = stream(&json!({}));
        let other = stream(&json!({}));

        // Act
        let rendered = one.render(&transmitter(&events));
        let rendered_other = other.render(&transmitter(&events));

        // Assert
        assert_ne!(
            rendered["delivery"]["endpoint_url"],
            rendered_other["delivery"]["endpoint_url"]
        );
    }

    /// A receiver that read its stream back and echoed the per-stream polling
    /// URL on a `PATCH` has changed nothing (§8.1.1.3).
    #[test]
    fn a_receiver_may_echo_the_per_stream_poll_endpoint() {
        // Arrange
        let events = supported(&[]);
        let current = stream(&json!({}));
        let url = poll_endpoint_for("https://as.example/t/demo/ssf/poll", &current.stream_id);
        let parsed = request(&json!({
            "stream_id": current.stream_id.as_str(),
            "delivery": {"method": DELIVERY_POLL, "endpoint_url": url},
        }));

        // Act
        let patched = current.patch(&parsed, &transmitter(&events));

        // Assert
        assert_eq!(patched.map(|stream| stream.delivery), Ok(Delivery::Poll));
    }

    /// And the receiver next door cannot: §6.1.2's URL names a stream, so
    /// echoing another one's is the §8.1.1.3 error rather than a change.
    #[test]
    fn a_receiver_may_not_echo_another_streams_poll_endpoint() {
        // Arrange
        let events = supported(&[]);
        let current = stream(&json!({}));
        let other = stream(&json!({}));
        let url = poll_endpoint_for("https://as.example/t/demo/ssf/poll", &other.stream_id);
        let parsed = request(&json!({
            "stream_id": current.stream_id.as_str(),
            "delivery": {"method": DELIVERY_POLL, "endpoint_url": url},
        }));

        // Act
        let refused = current.patch(&parsed, &transmitter(&events));

        // Assert
        assert_eq!(
            refused,
            Err(StreamError::TransmitterSupplied {
                member: "endpoint_url"
            })
        );
    }

    /// §8.1.1.1: an unsupported delivery method is refused rather than
    /// silently turned into one this transmitter does do.
    #[test]
    fn an_unknown_delivery_method_is_refused() {
        // Arrange
        let body = json!({"delivery": {"method": "urn:example:carrier-pigeon"}});

        // Act
        let refused = StreamRequest::parse(&body);

        // Assert
        assert_eq!(refused, Err(StreamError::UnsupportedDeliveryMethod));
    }

    /// RFC 8935 §2.2: a push endpoint is an https URL.
    #[test]
    fn a_push_delivery_over_plain_http_is_refused() {
        // Arrange
        let body = json!({"delivery": {
            "method": DELIVERY_PUSH,
            "endpoint_url": "http://receiver.example/events",
        }});

        // Act
        let refused = StreamRequest::parse(&body);

        // Assert
        assert_eq!(refused, Err(StreamError::InsecureEndpoint));
    }

    #[test]
    fn a_push_delivery_over_https_is_kept_verbatim() {
        // Arrange
        let body = json!({"delivery": {
            "method": DELIVERY_PUSH,
            "endpoint_url": "https://receiver.example/events",
        }});

        // Act
        let parsed = request(&body);

        // Assert
        assert_eq!(
            parsed.delivery,
            Some(DeliveryRequest::Push {
                endpoint_url: "https://receiver.example/events".to_owned(),
                authorization_header: None,
            })
        );
    }

    /// SSF 1.0 §6.1.1: the receiver's credential is kept, so that every push
    /// can present it.
    #[test]
    fn a_push_authorization_header_is_kept() {
        // Arrange
        let body = json!({"delivery": {
            "method": DELIVERY_PUSH,
            "endpoint_url": "https://receiver.example/events",
            "authorization_header": "Bearer secret",
        }});

        // Act
        let parsed = request(&body);

        // Assert
        let Some(DeliveryRequest::Push {
            authorization_header: Some(header),
            ..
        }) = parsed.delivery
        else {
            panic!("the credential was dropped");
        };
        assert_eq!(header.expose(), "Bearer secret");
    }

    /// A credential that HTTP cannot carry is refused where it is registered.
    /// The alternative is a stream that exists, looks configured, and fails
    /// every delivery at the socket.
    #[test]
    fn an_authorization_header_that_is_not_a_field_value_is_refused() {
        // Arrange
        let body = json!({"delivery": {
            "method": DELIVERY_PUSH,
            "endpoint_url": "https://receiver.example/events",
            "authorization_header": "Bearer t\r\nX-Admin: 1",
        }});

        // Act
        let refused = StreamRequest::parse(&body);

        // Assert
        assert_eq!(
            refused,
            Err(StreamError::BadAuthorizationHeader(
                AuthorizationHeaderError::NotAFieldValue
            ))
        );
    }

    /// A refusal names the member and never any part of the value: these
    /// strings reach logs, and this one is a credential.
    #[test]
    fn a_refused_credential_is_not_echoed_in_the_error() {
        // Arrange
        let body = json!({"delivery": {
            "method": DELIVERY_PUSH,
            "endpoint_url": "https://receiver.example/events",
            "authorization_header": "Bearer hunter2\nX: 1",
        }});

        // Act
        let rendered = StreamRequest::parse(&body)
            .expect_err("a header with a line break is refused")
            .to_string();

        // Assert
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    /// §8.1.1.2: a stream read is authorized by a token, not by holding the
    /// credential, so the credential is not in what comes back.
    #[test]
    fn a_rendered_stream_does_not_echo_the_credential() {
        // Arrange
        let stream = StreamConfiguration {
            stream_id: StreamId::generate(),
            audience: vec!["https://receiver.example".to_owned()],
            events_requested: Vec::new(),
            delivery: Delivery::Push {
                endpoint_url: "https://receiver.example/events".to_owned(),
                authorization_header: Some(
                    AuthorizationHeader::parse("Bearer secret-value").expect("a field value"),
                ),
            },
            description: None,
            inactivity_timeout: None,
        };

        // Act
        let events = supported(&[]);
        let rendered =
            serde_json::to_string(&stream.render(&transmitter(&events))).expect("serialises");

        // Assert
        assert!(!rendered.contains("secret-value"), "{rendered}");
        assert!(!rendered.contains("authorization_header"), "{rendered}");
    }

    /// §8.1.1: the poll endpoint is transmitter-supplied, so a receiver
    /// naming a different one is told rather than quietly given the
    /// transmitter's — it would otherwise poll an address that answers
    /// nothing and read the difference as a quiet stream.
    #[test]
    fn a_receiver_may_not_choose_the_poll_endpoint() {
        // Arrange
        let events = supported(&[]);
        let parsed = request(&json!({"delivery": {
            "method": DELIVERY_POLL,
            "endpoint_url": "https://receiver.example/poll",
        }}));

        // Act
        let refused = StreamConfiguration::create(&parsed, RECEIVER, &transmitter(&events));

        // Assert
        assert_eq!(
            refused,
            Err(StreamError::TransmitterSupplied {
                member: "endpoint_url"
            })
        );
    }

    /// The other half of the same rule: a receiver that read its stream and
    /// sent the poll endpoint back unchanged has changed nothing (§8.1.1.3).
    #[test]
    fn a_receiver_may_echo_the_poll_endpoint_it_was_given() {
        // Arrange
        let events = supported(&[]);
        let parsed = request(&json!({"delivery": {
            "method": DELIVERY_POLL,
            "endpoint_url": "https://as.example/t/demo/ssf/poll",
        }}));

        // Act
        let created = StreamConfiguration::create(&parsed, RECEIVER, &transmitter(&events));

        // Assert
        assert_eq!(created.map(|stream| stream.delivery), Ok(Delivery::Poll));
    }

    /// §8.1.1: a `POST` with no `aud` gets the receiver's own identifier.
    #[test]
    fn a_creation_without_an_audience_is_audienced_at_the_receiver() {
        // Arrange, act
        let events = supported(&[]);
        let rendered = stream(&json!({})).render(&transmitter(&events));

        // Assert
        assert_eq!(rendered["aud"], json!(RECEIVER));
    }

    /// A `POST` cannot pre-empt a transmitter-supplied member: there is no
    /// current value it could have matched.
    #[test]
    fn a_creation_that_dictates_a_transmitter_supplied_member_is_refused() {
        // Arrange
        let events = supported(&[]);
        let parsed = request(&json!({"iss": "https://not.us.example"}));

        // Act
        let refused = StreamConfiguration::create(&parsed, RECEIVER, &transmitter(&events));

        // Assert
        assert_eq!(
            refused,
            Err(StreamError::TransmitterSupplied { member: "iss" })
        );
    }

    // -----------------------------------------------------------------------
    // §8.1.1 — the object
    // -----------------------------------------------------------------------

    /// §8.1.1: every member the section defines is in the response.
    #[test]
    fn the_rendered_stream_carries_every_member_the_section_defines() {
        // Arrange
        let events = supported(&[SESSION_REVOKED]);
        let stream = stream(&json!({
            "events_requested": [SESSION_REVOKED],
            "description": "prod",
            "inactivity_timeout": 3600,
        }));

        // Act
        let rendered = stream.render(&transmitter(&events));

        // Assert
        for member in [
            "stream_id",
            "iss",
            "aud",
            "events_supported",
            "events_requested",
            "events_delivered",
            "delivery",
            "min_verification_interval",
            "description",
            "inactivity_timeout",
        ] {
            assert!(rendered.contains_key(member), "{member} is missing");
        }
    }

    /// §8.1.1: `events_delivered` is the intersection, and an event this
    /// transmitter does not support is ignored rather than refused.
    #[test]
    fn events_delivered_is_the_intersection_and_unknown_events_are_ignored() {
        // Arrange
        let events = supported(&[SESSION_REVOKED]);
        let stream = stream(&json!({
            "events_requested": [SESSION_REVOKED, ACCOUNT_DISABLED],
        }));

        // Act
        let rendered = stream.render(&transmitter(&events));

        // Assert
        assert_eq!(rendered["events_delivered"], json!([SESSION_REVOKED]));
        assert_eq!(
            rendered["events_requested"],
            json!([SESSION_REVOKED, ACCOUNT_DISABLED]),
            "what the receiver asked for is kept, so a later emitter starts delivering it"
        );
    }

    /// An entry that is not an event type URI at all is a different mistake
    /// from an unsupported event, and is answered rather than ignored.
    #[test]
    fn an_events_requested_entry_that_is_not_a_uri_is_refused() {
        // Arrange
        let body = json!({"events_requested": ["not a uri"]});

        // Act
        let refused = StreamRequest::parse(&body);

        // Assert
        assert_eq!(refused, Err(StreamError::BadEventUri));
    }

    // -----------------------------------------------------------------------
    // §8.1.1.3 — PATCH
    // -----------------------------------------------------------------------

    /// §8.1.1.3: a member the request does not carry is unchanged.
    #[test]
    fn a_patch_leaves_a_member_it_does_not_carry_alone() {
        // Arrange
        let events = supported(&[SESSION_REVOKED]);
        let before = stream(&json!({
            "description": "prod",
            "events_requested": [SESSION_REVOKED],
        }));

        // Act
        let after = before
            .patch(
                &request(&json!({"description": "staging"})),
                &transmitter(&events),
            )
            .expect("a valid patch");

        // Assert
        assert_eq!(after.description.as_deref(), Some("staging"));
        assert_eq!(after.events_requested, vec![SESSION_REVOKED.to_owned()]);
    }

    /// §8.1.1.3: a transmitter-supplied member echoed with the wrong value is
    /// an error, not a change.
    #[test]
    fn a_patch_that_rewrites_a_transmitter_supplied_member_is_refused() {
        // Arrange
        let events = supported(&[]);
        let before = stream(&json!({}));

        // Act
        let refused = before.patch(
            &request(&json!({"iss": "https://attacker.example"})),
            &transmitter(&events),
        );

        // Assert
        assert_eq!(
            refused,
            Err(StreamError::TransmitterSupplied { member: "iss" })
        );
    }

    /// The same rule, the other way: echoing the current value is allowed,
    /// because a receiver that read the stream and sent it back has changed
    /// nothing.
    #[test]
    fn a_patch_that_echoes_the_current_values_is_accepted() {
        // Arrange
        let events = supported(&[SESSION_REVOKED]);
        let transmitter = transmitter(&events);
        let before = stream(&json!({"events_requested": [SESSION_REVOKED]}));
        let echoed = Value::Object(before.render(&transmitter));

        // Act
        let after = before.patch(&request(&echoed), &transmitter);

        // Assert
        assert_eq!(
            after.map(|stream| stream.events_requested),
            Ok(vec![SESSION_REVOKED.to_owned()])
        );
    }

    /// §8.1.1: `aud` is immutable, and a receiver that asks for a different
    /// one is asking for another receiver's signals.
    #[test]
    fn a_patch_that_changes_the_audience_is_refused() {
        // Arrange
        let events = supported(&[]);
        let before = stream(&json!({}));

        // Act
        let refused = before.patch(
            &request(&json!({"aud": "https://elsewhere.example/events"})),
            &transmitter(&events),
        );

        // Assert
        assert_eq!(
            refused,
            Err(StreamError::TransmitterSupplied { member: "aud" })
        );
    }

    /// §8.1.1.3: `stream_id` is REQUIRED, and a request without one addresses
    /// nothing.
    #[test]
    fn an_update_without_a_stream_id_addresses_no_stream() {
        // Arrange
        let parsed = request(&json!({"description": "prod"}));

        // Act
        let refused = parsed.addressed_stream();

        // Assert
        assert_eq!(refused.err(), Some(StreamError::MissingStreamId));
    }

    // -----------------------------------------------------------------------
    // §8.1.1.4 — PUT
    // -----------------------------------------------------------------------

    /// §8.1.1.4: a receiver-supplied member the request does not carry is
    /// deleted.
    #[test]
    fn a_replace_deletes_the_members_it_does_not_carry() {
        // Arrange
        let events = supported(&[SESSION_REVOKED]);
        let before = stream(&json!({
            "description": "prod",
            "inactivity_timeout": 3600,
            "events_requested": [SESSION_REVOKED],
        }));

        // Act
        let after = before
            .replace(
                &request(&json!({"description": "staging"})),
                &transmitter(&events),
            )
            .expect("a valid replacement");

        // Assert
        assert_eq!(after.description.as_deref(), Some("staging"));
        assert_eq!(after.inactivity_timeout, None);
        assert!(after.events_requested.is_empty());
    }

    /// A `PUT` that removes `delivery` leaves the stream deliverable, by the
    /// same default a `POST` with no delivery gets.
    #[test]
    fn a_replace_without_a_delivery_falls_back_to_the_default_method() {
        // Arrange
        let events = supported(&[]);
        let before = stream(&json!({"delivery": {
            "method": DELIVERY_PUSH,
            "endpoint_url": "https://receiver.example/events",
        }}));

        // Act
        let after = before
            .replace(&request(&json!({})), &transmitter(&events))
            .expect("a valid replacement");

        // Assert
        assert_eq!(after.delivery, Delivery::Poll);
    }

    /// §8.1.1: the identifier and the audience survive a full replacement.
    #[test]
    fn a_replace_keeps_the_identifier_and_the_audience() {
        // Arrange
        let events = supported(&[]);
        let before = stream(&json!({}));

        // Act
        let after = before
            .replace(&request(&json!({})), &transmitter(&events))
            .expect("a valid replacement");

        // Assert
        assert_eq!(after.stream_id, before.stream_id);
        assert_eq!(after.audience, before.audience);
    }

    // -----------------------------------------------------------------------
    // Shapes and bounds
    // -----------------------------------------------------------------------

    #[test]
    fn a_body_that_is_not_an_object_is_refused() {
        assert_eq!(
            StreamRequest::parse(&json!(["a stream?"])),
            Err(StreamError::NotAnObject)
        );
    }

    #[test]
    fn a_known_member_of_the_wrong_type_is_refused() {
        assert_eq!(
            StreamRequest::parse(&json!({"description": 7})),
            Err(StreamError::WrongType {
                member: "description"
            })
        );
    }

    /// §8.1.1 is extensible, and a receiver built against a later revision is
    /// not refused for knowing more than this transmitter.
    #[test]
    fn an_unknown_member_is_ignored() {
        // Arrange, act
        let parsed = StreamRequest::parse(&json!({"future_member": {"nested": true}}));

        // Assert
        assert_eq!(parsed, Ok(StreamRequest::default()));
    }

    #[test]
    fn an_oversized_description_is_refused() {
        // Arrange
        let body = json!({"description": "x".repeat(MAX_DESCRIPTION_LEN + 1)});

        // Act, assert
        assert_eq!(
            StreamRequest::parse(&body),
            Err(StreamError::TooLong {
                member: "description"
            })
        );
    }

    #[test]
    fn too_many_requested_events_are_refused() {
        // Arrange
        let events: Vec<String> = (0..=MAX_EVENTS_REQUESTED)
            .map(|n| format!("https://events.example/{n}"))
            .collect();

        // Act, assert
        assert_eq!(
            StreamRequest::parse(&json!({"events_requested": events})),
            Err(StreamError::TooLong {
                member: "events_requested"
            })
        );
    }

    #[test]
    fn an_inactivity_timeout_outside_the_bounds_is_refused() {
        for value in [json!(1), json!(MAX_INACTIVITY_TIMEOUT + 1), json!(-5)] {
            assert!(
                StreamRequest::parse(&json!({"inactivity_timeout": value})).is_err(),
                "{value} was accepted as an inactivity timeout"
            );
        }
    }

    /// A stream identifier is drawn, not chosen, and two of them differ.
    #[test]
    fn stream_identifiers_are_unguessable_and_distinct() {
        // Arrange, act
        let one = StreamId::generate();
        let two = StreamId::generate();

        // Assert
        assert_ne!(one, two);
        assert!(
            one.as_str().len() >= 22,
            "128 bits of base64url is 22 characters"
        );
        assert_eq!(StreamId::parse(one.as_str()), Some(one));
    }

    #[test]
    fn a_stream_identifier_with_a_path_in_it_is_not_one_of_ours() {
        for raw in ["", "../etc", "a/b", &"x".repeat(StreamId::MAX_LEN + 1)] {
            assert_eq!(StreamId::parse(raw), None, "{raw} was accepted");
        }
    }
}
