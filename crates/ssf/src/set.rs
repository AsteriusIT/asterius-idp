//! The Security Event Token itself: the issuance profile of SSF 1.0 §4.
//!
//! The whole module is arranged so that the profile's prohibitions are things
//! a caller cannot express, rather than things a reviewer has to notice.
//!
//! | Rule | How it is enforced |
//! |---|---|
//! | §4.1.1 `typ` MUST be `secevent+jwt` | [`SET_TYP`] is the only value handed to [`Signer::sign`] |
//! | §4.1.2 `sub` MUST NOT be present | no API writes claims; the claim set is built here |
//! | §4.1.7 `exp` MUST NOT be used | same |
//! | §3.1 `sub_id` MUST be present | typestate: [`Set::about`] is the only entry point |
//! | §4.2.1 one event | [`SetSubject::reporting`] takes one [`SecurityEvent`] and yields a type with no way to add another |
//! | §4.1.6 `iss` matches the stream | [`ReadySet::issue`] takes the tenant [`Issuer`] and writes it |
//! | §4.1.8 `aud` | [`StreamAudience`], validated at construction |
//! | §4.1.9 `txn` | always emitted; [`Txn`] is shared by construction |
//!
//! ## The typestate
//!
//! ```text
//! Set::about(subject) -> SetSubject::reporting(event) -> Set{Ready}::issue(..)
//! ```
//!
//! Three types, each with one way forward. A SET with no subject has no
//! `issue`; a SET with no event has no `issue`; and after `reporting` there is
//! no second `reporting`, so the "two event types in one `events`" that §4.2.1
//! warns about needs a second SET, which is what the specification wanted.

use crate::event::SecurityEvent;
use crate::subject::Subject;
use asterius_domain::{CompactJws, DomainError, Issuer, Signer, TenantId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Map, Value};
use thiserror::Error;
use time::OffsetDateTime;

/// The explicit type of a SET (RFC 8417 §2.3, SSF 1.0 §4.1.1).
///
/// > The `typ` header MUST be present and MUST be set to `secevent+jwt`.
///
/// Not a parameter anywhere in this crate. A SET signed as `at+jwt` would be a
/// token a resource server might accept, and the point of explicit typing is
/// that the one who signs cannot forget.
pub const SET_TYP: &str = "secevent+jwt";

/// The guard on how large a SET this server will sign.
///
/// Not a specification limit. A SET is pushed to a receiver over HTTP or
/// queued in an outbox row, and an event payload is the one part a caller
/// fills freely; the bound turns "a signal nobody can deliver" into an error
/// at issuance, where the cause is still visible.
pub const MAX_SET_CLAIMS_BYTES: usize = 8 * 1024;

/// How many bytes of entropy go into a `jti` and a `txn`. 128 bits.
const ID_BYTES: usize = 16;

/// Draws `ID_BYTES` of randomness, base64url-encoded.
///
/// # Panics
///
/// If the OS CSPRNG is unavailable. There is nothing to fall back to, and a
/// buffer of zeros would be a `jti` a receiver has already seen — which, for a
/// receiver doing the duplicate detection RFC 8417 §2 expects, is a signal
/// silently dropped.
fn random_id() -> String {
    let mut bytes = [0_u8; ID_BYTES];
    getrandom::fill(&mut bytes).expect("the OS CSPRNG must be available");
    B64.encode(bytes)
}

/// A SET's `jti`: 128 bits of entropy, base64url-encoded.
///
/// A newtype rather than a `String` because the entropy is the requirement. A
/// receiver uses `jti` for duplicate detection, so a guessable one lets an
/// attacker who can predict it pre-empt a genuine signal — the receiver treats
/// the real "this session was revoked" as a replay of something it has seen.
///
/// There is no constructor taking a caller's string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SetId(String);

impl SetId {
    /// Draws a fresh identifier from the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        Self(random_id())
    }

    /// The identifier, as it appears in `jti`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A transaction identifier: SSF 1.0 §4.1.9's `txn`.
///
/// > The `txn` claim SHOULD be included... All SETs that are related to the
/// > same underlying event SHOULD share the same `txn` value.
///
/// One cause — one sign-out, one policy decision, one credential change —
/// produces one SET per stream, and `txn` is what lets an operator (or a
/// receiver correlating with another receiver) see them as one thing. So the
/// type is [`Clone`] and has a `generate` that a caller invokes **once per
/// cause**, then passes to every SET that cause produced. There is no
/// per-SET default that would quietly make each one its own transaction: the
/// only way to get a `txn` is to make one and hand it round.
///
/// It is not a secret, and it is not a `jti`: it is deliberately repeated, so
/// it must never be used for duplicate detection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Txn(String);

impl Txn {
    /// Draws a transaction identifier for one underlying event.
    #[must_use]
    pub fn generate() -> Self {
        Self(random_id())
    }

    /// The identifier, as it appears in `txn`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Txn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a SET could not be issued or signed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SetError {
    /// The claim set is over [`MAX_SET_CLAIMS_BYTES`].
    #[error("a SET of {size} bytes is over the {limit} byte guard")]
    TooLarge {
        /// How large the claims serialised.
        size: usize,
        /// The guard.
        limit: usize,
    },
    /// The tenant's signer refused.
    #[error("cannot sign the security event token")]
    Signing(#[source] DomainError),
}

/// The audience of a stream (SSF 1.0 §4.1.8).
///
/// A typed value rather than a string because `aud` is what stops a SET
/// intended for one receiver being replayed at another: a receiver checks that
/// it is in `aud`, and a transmitter that writes the wrong one has issued a
/// token the wrong party will accept.
///
/// The stream itself does not exist yet (`ast-0ju.3`). Until it does, the
/// caller states the audience, and this type is the thing that will be read
/// off the stream configuration when there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamAudience(Vec<String>);

/// Why a stream audience was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AudienceError {
    /// No audience values, or an empty one among them.
    ///
    /// A SET with no audience is one every receiver may consider its own.
    #[error("a stream audience must be one or more non-empty values")]
    Empty,
    /// More audience values than [`StreamAudience::MAX_VALUES`].
    #[error("a stream audience may name at most {max} receivers", max = StreamAudience::MAX_VALUES)]
    TooMany,
}

impl StreamAudience {
    /// The most receivers one stream may name.
    pub const MAX_VALUES: usize = 8;

    /// The audience of a stream with one receiver, which is the usual case.
    ///
    /// # Errors
    ///
    /// [`AudienceError::Empty`] if the value is empty.
    pub fn single(value: &str) -> Result<Self, AudienceError> {
        Self::new([value])
    }

    /// The audience of a stream naming several receivers.
    ///
    /// # Errors
    ///
    /// [`AudienceError`] if the set is empty, holds an empty value, or names
    /// more than [`StreamAudience::MAX_VALUES`] receivers.
    pub fn new<'a>(values: impl IntoIterator<Item = &'a str>) -> Result<Self, AudienceError> {
        let values: Vec<String> = values.into_iter().map(str::to_owned).collect();
        if values.is_empty() || values.iter().any(String::is_empty) {
            return Err(AudienceError::Empty);
        }
        if values.len() > Self::MAX_VALUES {
            return Err(AudienceError::TooMany);
        }
        Ok(Self(values))
    }

    /// The `aud` claim: a string for one value, an array for several.
    ///
    /// RFC 7519 §4.1.3 permits both, and the single-string form is what every
    /// deployed receiver handles; the array is only rendered when there is
    /// genuinely more than one.
    fn to_claim(&self) -> Value {
        match self.0.as_slice() {
            [one] => Value::from(one.as_str()),
            many => Value::from(many.to_vec()),
        }
    }
}

/// The entry point of the SET typestate. See the [module docs](self).
#[derive(Debug)]
pub struct Set;

impl Set {
    /// Names the primary subject of the SET (SSF 1.0 §3.1).
    ///
    /// > The `sub_id` claim... MUST describe the subject of the event.
    ///
    /// This is the only way into the builder, which is what makes a SET
    /// without a `sub_id` unrepresentable rather than merely tested for.
    #[must_use]
    pub fn about(subject: impl Into<Subject>) -> SetSubject {
        SetSubject {
            sub_id: subject.into(),
        }
    }
}

/// A SET that knows its subject and is waiting for its event.
#[derive(Debug)]
pub struct SetSubject {
    sub_id: Subject,
}

impl SetSubject {
    /// Names the one event this SET reports (SSF 1.0 §4.2.1).
    ///
    /// > While `events` can contain multiple event objects, this profile
    /// > requires that... it SHOULD contain only one.
    ///
    /// The returned type has no method that adds an event, so a second event —
    /// and in particular a second event *type* — needs a second SET.
    #[must_use]
    pub fn reporting(self, event: SecurityEvent) -> ReadySet {
        ReadySet {
            sub_id: self.sub_id,
            event,
            txn: None,
        }
    }
}

/// A SET with a subject and an event: everything the profile needs.
#[derive(Debug)]
pub struct ReadySet {
    sub_id: Subject,
    event: SecurityEvent,
    txn: Option<Txn>,
}

impl ReadySet {
    /// Marks this SET as one of those produced by a single underlying cause.
    ///
    /// Call [`Txn::generate`] once where the cause is handled, then pass the
    /// same value to every SET it produces. Without this, [`ReadySet::issue`]
    /// still emits a `txn` — §4.1.9 says SHOULD, so there is always one — but
    /// it is a fresh one describing a cause of exactly one SET.
    #[must_use]
    pub fn caused_by(mut self, txn: Txn) -> Self {
        self.txn = Some(txn);
        self
    }

    /// Builds the claim set.
    ///
    /// `issuer` is the tenant's issuer identifier, which SSF 1.0 §4.1.6
    /// requires to be the `iss` of the stream this SET will be delivered on. A
    /// receiver resolves the signing key from that issuer's metadata, so an
    /// `iss` from anywhere else is a SET whose key cannot be found.
    ///
    /// # Errors
    ///
    /// [`SetError::TooLarge`] if the claims are over [`MAX_SET_CLAIMS_BYTES`].
    pub fn issue(
        self,
        issuer: &Issuer,
        audience: &StreamAudience,
        now: OffsetDateTime,
    ) -> Result<UnsignedSet, SetError> {
        let jti = SetId::generate();
        let txn = self.txn.unwrap_or_else(Txn::generate);

        let mut claims = Map::new();
        // RFC 8417 §2.2 and SSF 1.0 §4.1.6: the issuer of the stream.
        claims.insert("iss".to_owned(), Value::from(issuer.as_str()));
        // §4.1.8.
        claims.insert("aud".to_owned(), audience.to_claim());
        // RFC 8417 §2.2: `iat` is when the SET was issued, not when the event
        // happened. The event's own timestamp lives in its payload.
        claims.insert("iat".to_owned(), Value::from(now.unix_timestamp()));
        claims.insert("jti".to_owned(), Value::from(jti.as_str()));
        // §4.1.9.
        claims.insert("txn".to_owned(), Value::from(txn.as_str()));
        // §3.1.
        claims.insert("sub_id".to_owned(), self.sub_id.to_json());
        claims.insert("events".to_owned(), self.event.to_events_claim());
        //
        // What is *not* written here is the point of the whole module:
        //   * `sub` — §4.1.2 MUST NOT. A SET is about a subject, and `sub`
        //     would make it look like an assertion *to* one.
        //   * `exp` — §4.1.7 MUST NOT. A SET is a statement about something
        //     that already happened; it does not stop being true, and an
        //     expiry would invite a receiver to discard an event it had not
        //     yet processed.
        // Neither claim is reachable: nothing outside this function writes to
        // `claims`, and this function writes a fixed set of names.

        let claims = Value::Object(claims);
        let size = claims.to_string().len();
        if size > MAX_SET_CLAIMS_BYTES {
            return Err(SetError::TooLarge {
                size,
                limit: MAX_SET_CLAIMS_BYTES,
            });
        }

        Ok(UnsignedSet { claims, jti, txn })
    }
}

/// A complete SET claim set, not yet signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedSet {
    claims: Value,
    jti: SetId,
    txn: Txn,
}

impl UnsignedSet {
    /// The claims, as they will be serialised into the payload.
    #[must_use]
    pub const fn claims(&self) -> &Value {
        &self.claims
    }

    /// The `jti`, which a receiver uses for duplicate detection and a
    /// transmitter's outbox uses as its idempotency key.
    #[must_use]
    pub const fn jti(&self) -> &SetId {
        &self.jti
    }

    /// The `txn` shared with every other SET from the same cause.
    #[must_use]
    pub const fn txn(&self) -> &Txn {
        &self.txn
    }

    /// Signs this SET with the tenant's active key.
    ///
    /// The signer is the domain port — the same one that signs an ID token and
    /// an access token, backed by the same `KeyStore` — and not a second
    /// signing path. That matters more here than it looks: a receiver
    /// validates a SET against the JWKS the tenant publishes, so a SET signed
    /// by a key that is not in that document is a signal the receiver drops,
    /// and the only way to be sure it is in there is to sign with the key the
    /// rest of the server signs with.
    ///
    /// `algorithm` is `None`: the claims commit to nothing about how they were
    /// signed — there is no `at_hash` here — so the tenant's active key is the
    /// right answer, and it is EdDSA or ES256 because that is what ADR-0003
    /// lets a tenant hold. A receiver resolves the key by `kid` from the
    /// published JWKS, exactly as a resource server does for an access token.
    ///
    /// # Errors
    ///
    /// [`SetError::Signing`] if the tenant has no active key or the signer
    /// refuses.
    pub async fn sign(
        &self,
        signer: &dyn Signer,
        tenant: &TenantId,
    ) -> Result<SignedSet, SetError> {
        let jws = signer
            .sign(tenant, None, SET_TYP, &self.claims)
            .await
            .map_err(SetError::Signing)?;
        Ok(SignedSet {
            jws,
            jti: self.jti.clone(),
            txn: self.txn.clone(),
        })
    }
}

/// A signed SET, ready for an outbox to deliver (`ast-0ju.9`).
///
/// The `jti` and `txn` travel beside the compact serialisation rather than
/// being parsed back out of it: an outbox needs them as a key and a
/// correlation handle, and re-reading claims out of a token it just produced
/// would be a parser this crate does not need to own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSet {
    jws: CompactJws,
    jti: SetId,
    txn: Txn,
}

impl SignedSet {
    /// The compact serialisation, which is what goes on the wire.
    #[must_use]
    pub const fn jws(&self) -> &CompactJws {
        &self.jws
    }

    /// The `jti` of the SET inside.
    #[must_use]
    pub const fn jti(&self) -> &SetId {
        &self.jti
    }

    /// The `txn` of the cause this SET reports.
    #[must_use]
    pub const fn txn(&self) -> &Txn {
        &self.txn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventUri;
    use crate::subject::{ComplexSubject, SimpleSubject};
    use serde_json::json;

    fn issuer() -> Issuer {
        Issuer::parse("https://as.example/t/demo").expect("an issuer")
    }

    fn audience() -> StreamAudience {
        StreamAudience::single("https://receiver.example/events").expect("an audience")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("a time")
    }

    fn event() -> SecurityEvent {
        SecurityEvent::new(
            EventUri::parse("https://schemas.openid.net/secevent/caep/event-type/session-revoked")
                .expect("an event type"),
        )
    }

    fn subject() -> SimpleSubject {
        SimpleSubject::opaque("u-1").expect("a subject")
    }

    fn issued() -> UnsignedSet {
        Set::about(subject())
            .reporting(event())
            .issue(&issuer(), &audience(), now())
            .expect("a SET")
    }

    /// SSF 1.0 §4.1.2: `sub` MUST NOT be present. §4.1.7: `exp` MUST NOT be
    /// used. There is no API that writes either; this holds the claim set to
    /// it anyway, because "no caller can" is only true while nobody adds one.
    #[test]
    fn a_set_carries_neither_sub_nor_exp() {
        let set = issued();
        assert!(set.claims().get("sub").is_none(), "§4.1.2");
        assert!(set.claims().get("exp").is_none(), "§4.1.7");
    }

    /// SSF 1.0 §4.1.6: `iss` is the issuer of the stream — the tenant's.
    #[test]
    fn iss_is_the_tenant_issuer() {
        assert_eq!(issued().claims()["iss"], json!(issuer().as_str()));
    }

    /// SSF 1.0 §4.1.8.
    #[test]
    fn aud_is_the_stream_audience() {
        assert_eq!(
            issued().claims()["aud"],
            json!("https://receiver.example/events")
        );

        let many = StreamAudience::new(["https://one.example", "https://two.example"])
            .expect("an audience");
        let set = Set::about(subject())
            .reporting(event())
            .issue(&issuer(), &many, now())
            .expect("a SET");
        assert_eq!(
            set.claims()["aud"],
            json!(["https://one.example", "https://two.example"])
        );
    }

    #[test]
    fn an_empty_or_oversized_audience_is_refused() {
        assert_eq!(StreamAudience::single(""), Err(AudienceError::Empty));
        assert_eq!(
            StreamAudience::new(std::iter::empty()),
            Err(AudienceError::Empty)
        );
        assert_eq!(
            StreamAudience::new(["https://a.example", ""]),
            Err(AudienceError::Empty)
        );
        let too_many = vec!["https://a.example"; StreamAudience::MAX_VALUES + 1];
        assert_eq!(
            StreamAudience::new(too_many),
            Err(AudienceError::TooMany),
            "a stream that names everybody"
        );
    }

    /// RFC 8417 §2.2: `iat` is when the token was issued.
    #[test]
    fn iat_is_the_issuance_time_in_seconds() {
        assert_eq!(issued().claims()["iat"], json!(1_760_000_000_i64));
    }

    /// FAPI 2.0 SP §5.4.1 item 4's entropy floor, applied to a `jti` a
    /// receiver deduplicates on.
    #[test]
    fn the_jti_is_128_bits_of_base64url_and_never_repeats() {
        let first = issued();
        let second = issued();

        // 16 bytes unpadded base64url is 22 characters.
        assert_eq!(first.jti().as_str().len(), 22);
        assert!(
            first
                .jti()
                .as_str()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_ne!(first.jti(), second.jti());
        assert_eq!(first.claims()["jti"], json!(first.jti().as_str()));
    }

    /// SSF 1.0 §4.1.9: SETs from one underlying event share a `txn`.
    #[test]
    fn one_cause_gives_every_set_it_produced_the_same_txn() {
        let cause = Txn::generate();

        let to_first = Set::about(subject())
            .reporting(event())
            .caused_by(cause.clone())
            .issue(&issuer(), &audience(), now())
            .expect("a SET");
        let to_second = Set::about(subject())
            .reporting(event())
            .caused_by(cause.clone())
            .issue(&issuer(), &audience(), now())
            .expect("a SET");

        assert_eq!(to_first.txn(), &cause);
        assert_eq!(to_first.txn(), to_second.txn());
        assert_eq!(to_first.claims()["txn"], json!(cause.as_str()));
        // Two SETs of one cause are still two tokens.
        assert_ne!(to_first.jti(), to_second.jti());
    }

    /// §4.1.9 says SHOULD, so there is always one.
    #[test]
    fn a_set_with_no_stated_cause_still_carries_a_txn() {
        let set = issued();
        assert_eq!(set.claims()["txn"], json!(set.txn().as_str()));
        assert_eq!(set.txn().as_str().len(), 22);
        assert_ne!(issued().txn(), issued().txn());
    }

    /// SSF 1.0 §4.2.1: one event object, under its own type URI.
    #[test]
    fn events_holds_exactly_one_event_keyed_by_its_type() {
        let set = issued();
        let Value::Object(events) = &set.claims()["events"] else {
            panic!("`events` is a JSON object");
        };
        assert_eq!(events.len(), 1);
        assert!(events.contains_key(event().uri().as_str()));
    }

    /// SSF 1.0 §3.1: `sub_id` describes the primary subject — including when
    /// the event body carries a `subject` of its own.
    #[test]
    fn sub_id_is_present_even_when_the_event_carries_its_own_subject() {
        let inner = Subject::from(SimpleSubject::email("alice@example.com").expect("an email"));
        let set = Set::about(subject())
            .reporting(event().about(&inner))
            .issue(&issuer(), &audience(), now())
            .expect("a SET");

        assert_eq!(
            set.claims()["sub_id"],
            json!({"format": "opaque", "id": "u-1"})
        );
        assert_eq!(
            set.claims()["events"][event().uri().as_str()]["subject"],
            json!({"format": "email", "email": "alice@example.com"})
        );
    }

    #[test]
    fn a_complex_subject_is_a_sub_id_like_any_other() {
        let complex = ComplexSubject::of_user(subject())
            .with_session(SimpleSubject::opaque("s-1").expect("a session"));
        let set = Set::about(complex)
            .reporting(event())
            .issue(&issuer(), &audience(), now())
            .expect("a SET");

        assert_eq!(
            set.claims()["sub_id"],
            json!({
                "user": {"format": "opaque", "id": "u-1"},
                "session": {"format": "opaque", "id": "s-1"},
            })
        );
    }

    /// The claim set is exactly the profile's, with nothing else in it.
    #[test]
    fn the_claim_set_is_closed() {
        let set = issued();
        let Value::Object(claims) = set.claims() else {
            panic!("claims are a JSON object");
        };
        let mut names: Vec<&str> = claims.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["aud", "events", "iat", "iss", "jti", "sub_id", "txn"]
        );
    }

    #[test]
    fn a_set_larger_than_the_guard_is_refused() {
        let bulky = event().with("detail", Value::from("x".repeat(MAX_SET_CLAIMS_BYTES)));
        let refusal = Set::about(subject())
            .reporting(bulky)
            .issue(&issuer(), &audience(), now())
            .expect_err("over the guard");

        assert!(
            matches!(refusal, SetError::TooLarge { limit, .. } if limit == MAX_SET_CLAIMS_BYTES)
        );
    }
}
