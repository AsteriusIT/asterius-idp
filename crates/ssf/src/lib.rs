//! Security Event Token issuance for the Shared Signals Framework.
//!
//! This crate builds and signs the tokens a transmitter sends: SSF 1.0 §3
//! (subject identifiers), §4 (the SET profile), RFC 8417 (the SET itself) and
//! RFC 9493 (subject identifier formats). It does **not** receive, parse or
//! verify a SET, does not know what a stream is (`ast-0ju.3`), and does not
//! deliver anything (`ast-0ju.9`): what it produces is a [`SignedSet`], which
//! an outbox takes and puts on the wire.
//!
//! ```no_run
//! # use asterius_ssf::*;
//! # use asterius_domain::{Issuer, Signer, TenantId};
//! # async fn issue(signer: &dyn Signer) -> Result<(), Box<dyn std::error::Error>> {
//! # let issuer = Issuer::parse("https://as.example/t/demo")?;
//! # let tenant = TenantId::parse("demo")?;
//! let audience = StreamAudience::single("https://receiver.example/events")?;
//! let cause = Txn::generate(); // once per underlying event, shared by every SET
//!
//! let signed = Set::about(SimpleSubject::opaque("u-1")?)
//!     .reporting(SecurityEvent::new(EventUri::parse(
//!         "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
//!     )?))
//!     .caused_by(cause)
//!     .issue(&issuer, &audience, time::OffsetDateTime::now_utc())?
//!     .sign(signer, &tenant)
//!     .await?;
//!
//! let _on_the_wire = signed.jws();
//! # Ok(())
//! # }
//! ```
//!
//! # Why a crate of its own
//!
//! The obvious home was `asterius-oidc`, and the layering is what ruled it
//! out. `scripts/check-layering.sh` forbids `asterius-oidc` from reaching
//! `tokio` — through a dev-dependency as much as a real one, because it walks
//! the resolved graph — and SSF issuance has to be tested through the signing
//! port, which is `async`, against the tenant's real `KeyStore`. Keeping the
//! module in `asterius-oidc` would have meant either weakening that gate or
//! testing the profile without ever signing anything.
//!
//! The dependency list is what a protocol crate's should be: this crate
//! reaches no database, no HTTP framework and no runtime of its own. It signs
//! through [`asterius_domain::Signer`] — the same port, and the same key, that
//! signs an ID token — and only the tests bring in `asterius-jose` to stand a
//! signer up.
//!
//! # Threat model note: a SET carries a subject identifier to a third party
//!
//! Every other token this server issues is handed to the party that asked for
//! it, in a flow the user started. A SET is not: it is *pushed*, out of band,
//! to a receiver, about a user who is not present and did not ask. Three
//! consequences shape this crate.
//!
//! **The identifier must be the one the receiver already holds, and no more.**
//! A receiver is a client, so OIDC Core §8.1's pairwise `sub` applies to it:
//! [`SimpleSubject::pairwise_iss_sub`] derives under the *receiver's* sector,
//! which is both the only identifier it can act on and the only one that does
//! not hand it a correlation handle it was never given at sign-in. Sending a
//! public `sub`, an email address or a phone number to a pairwise receiver
//! would undo, in a back channel, the unlinkability the front channel spent
//! effort establishing. The choice of format is therefore a privacy decision
//! and not a convenience: `email` and `phone_number` exist here because some
//! receivers are provisioned that way, and using them for a receiver that was
//! not is a leak.
//!
//! **`aud` is the only thing that keeps a signal in its lane.** A SET is a
//! bearer object about a user; a receiver that is handed another receiver's
//! SET learns that user's identifier and their security state. Hence
//! [`StreamAudience`], validated and never empty.
//!
//! **The token says as little as the event allows.** No `sub` (§4.1.2), one
//! event (§4.2.1), a bounded payload, and error messages in this crate that
//! name a member without echoing its value — a subject identifier is personal
//! data and these strings reach logs.
//!
//! What this crate does **not** decide: whether a given receiver is entitled
//! to hear about a given user at all. That is stream configuration, it belongs
//! to `ast-0ju.3`, and until it exists the caller is responsible for it.
#![forbid(unsafe_code)]

pub mod event;
pub mod metadata;
pub mod poll;
pub mod set;
pub mod stream;
pub mod subject;

pub use event::{EventError, EventUri, MAX_EVENT_URI_LEN, SecurityEvent};
pub use metadata::{SPEC_VERSION, WELL_KNOWN_DOCUMENT, transmitter_metadata};
pub use poll::{MAX_LONG_POLL, PollError, PollRequest, PollResponse, RejectedSet};
pub use set::{
    AudienceError, MAX_SET_CLAIMS_BYTES, ReadySet, SET_TYP, Set, SetError, SetId, SetSubject,
    SignedSet, StreamAudience, Txn, UnsignedSet,
};
pub use subject::{ComplexSubject, MAX_MEMBER_LEN, SimpleSubject, Subject, SubjectError};
