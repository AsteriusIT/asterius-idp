//! The audit trail.
//!
//! Every security-relevant thing this server does produces one append-only
//! record. The trail has three jobs, and the shape of the types here follows
//! from them:
//!
//! * **Attribution.** Who caused this? For an agent that is not one answer but
//!   a chain — the agent, and the human it is acting for (RFC 8693 `act`) —
//!   so [`AuditEvent::actor_chain`] is a list, not a field.
//! * **Revocation.** FAPI 2.0 SP §6.8 item 4 asks that linked credentials be
//!   recorded so they can be revoked together. Every event therefore carries
//!   the grant, session and client it belongs to where they are known.
//! * **Evidence.** A trail the application can rewrite is not evidence, so the
//!   database refuses `UPDATE` and `DELETE` (see the baseline migration) and
//!   each record is chained to the one before it.
//!
//! And one thing the trail must *not* do: hold credentials. See
//! [`redaction`].

pub mod chain;
pub mod redaction;

use crate::{ClientId, GrantId, SessionId, TenantId};
use std::collections::BTreeMap;
use time::OffsetDateTime;

pub use chain::{ChainError, EventHash};
pub use redaction::{Sensitive, fingerprint};

/// What kind of thing happened.
///
/// A closed vocabulary rather than free text: event types are queried, alerted
/// on and counted, and a trail where `token.issued` and `token_issued` both
/// occur is a trail nobody can query reliably.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventType(&'static str);

impl EventType {
    /// A pushed authorization request was accepted (RFC 9126).
    pub const PAR_ACCEPTED: Self = Self("par.accepted");
    /// A pushed authorization request was rejected.
    pub const PAR_REJECTED: Self = Self("par.rejected");
    /// A user completed authentication.
    pub const AUTH_LOGIN: Self = Self("auth.login");
    /// An authentication attempt failed.
    pub const AUTH_FAILED: Self = Self("auth.failed");
    /// An authentication attempt was refused before any credential was
    /// checked, because the address or the identifier had already failed too
    /// often.
    ///
    /// Separate from [`Self::AUTH_FAILED`] because the two answer different
    /// questions during an incident: a run of failures is somebody guessing,
    /// and a run of throttles is the limiter holding. Conflating them would
    /// hide whichever one is rarer. The record names the *bucket* that was
    /// full, never the identifier that was typed — see
    /// `asterius_domain::rate_limit`.
    pub const AUTH_THROTTLED: Self = Self("auth.throttled");
    /// A credential was registered for a user: a passkey, a password, a
    /// recovery code.
    ///
    /// The event names the user it belongs to and the credential row it
    /// created, so that a credential nobody recognises can be traced back to
    /// the ceremony that produced it. It is also the trail half of the CAEP
    /// `credential-change` (create) signal; the signal itself is emitted
    /// elsewhere.
    pub const CREDENTIAL_CREATED: Self = Self("credential.created");
    /// A user granted consent.
    pub const CONSENT_GRANTED: Self = Self("consent.granted");
    /// A user refused consent.
    pub const CONSENT_DENIED: Self = Self("consent.denied");
    /// An authorization code was issued.
    pub const CODE_ISSUED: Self = Self("code.issued");
    /// An authorization code was redeemed.
    pub const CODE_REDEEMED: Self = Self("code.redeemed");
    /// An authorization code was presented twice (RFC 6749 §10.5).
    pub const CODE_REPLAYED: Self = Self("code.replayed");
    /// A token was issued.
    pub const TOKEN_ISSUED: Self = Self("token.issued");
    /// A token request was refused.
    pub const TOKEN_REFUSED: Self = Self("token.refused");
    /// A token was exchanged for a narrower one (RFC 8693).
    pub const TOKEN_EXCHANGED: Self = Self("token.exchanged");
    /// A grant was revoked.
    pub const GRANT_REVOKED: Self = Self("grant.revoked");
    /// A session was revoked.
    pub const SESSION_REVOKED: Self = Self("session.revoked");
    /// A client authenticated successfully.
    pub const CLIENT_AUTHENTICATED: Self = Self("client.authenticated");
    /// Client authentication failed.
    pub const CLIENT_AUTH_FAILED: Self = Self("client.auth_failed");
    /// A client was registered (RFC 7591).
    pub const CLIENT_REGISTERED: Self = Self("client.registered");
    /// A client read its own registration at the RFC 7592 client
    /// configuration endpoint.
    pub const CLIENT_READ: Self = Self("client.read");
    /// A client replaced its own registration (RFC 7592 §2.2).
    ///
    /// A replacement, not a patch: the recorded event says the whole document
    /// changed, because that is what the specification makes a PUT mean.
    pub const CLIENT_UPDATED: Self = Self("client.updated");
    /// A client deprovisioned itself (RFC 7592 §2.3).
    pub const CLIENT_DELETED: Self = Self("client.deleted");
    /// A signing key was rotated.
    pub const KEY_ROTATED: Self = Self("key.rotated");
    /// An administrator changed configuration.
    pub const ADMIN_CHANGED: Self = Self("admin.changed");
    /// Audit records were removed by the retention policy.
    pub const AUDIT_PURGED: Self = Self("audit.purged");

    /// Every event type, for the admin API's filter list and for the test that
    /// keeps this list honest.
    pub const ALL: [Self; 25] = [
        Self::PAR_ACCEPTED,
        Self::PAR_REJECTED,
        Self::AUTH_LOGIN,
        Self::AUTH_FAILED,
        Self::AUTH_THROTTLED,
        Self::CREDENTIAL_CREATED,
        Self::CONSENT_GRANTED,
        Self::CONSENT_DENIED,
        Self::CODE_ISSUED,
        Self::CODE_REDEEMED,
        Self::CODE_REPLAYED,
        Self::TOKEN_ISSUED,
        Self::TOKEN_REFUSED,
        Self::TOKEN_EXCHANGED,
        Self::GRANT_REVOKED,
        Self::SESSION_REVOKED,
        Self::CLIENT_AUTHENTICATED,
        Self::CLIENT_AUTH_FAILED,
        Self::CLIENT_REGISTERED,
        Self::CLIENT_READ,
        Self::CLIENT_UPDATED,
        Self::CLIENT_DELETED,
        Self::KEY_ROTATED,
        Self::ADMIN_CHANGED,
        Self::AUDIT_PURGED,
    ];

    /// The wire and storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Whether the thing that happened worked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It worked.
    Success,
    /// It did not.
    Failure,
}

impl Outcome {
    /// The storage spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Who did it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    /// An end user, identified by the subject the event concerns.
    User(String),
    /// A confidential client acting for itself.
    Client(ClientId),
    /// An agent client. Always paired with the principal it acts for, which is
    /// what makes an agent's actions attributable to a human.
    Agent {
        /// The agent's client id.
        client: ClientId,
        /// The subject the agent is acting for.
        on_behalf_of: String,
    },
    /// An administrator using the admin API or console.
    Admin(String),
    /// The server itself: a retention job, a key rotation, an outbox worker.
    System,
}

impl Actor {
    /// The actor kind, as stored.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::Client(_) => "client",
            Self::Agent { .. } => "agent",
            Self::Admin(_) => "admin",
            Self::System => "system",
        }
    }

    /// The actor's identifier, as stored. Empty for [`Actor::System`].
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::User(id) | Self::Admin(id) => id,
            Self::Client(id) | Self::Agent { client: id, .. } => id.as_str(),
            Self::System => "",
        }
    }
}

/// A value that may appear in an event's detail map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailValue {
    /// Free text. Scanned for credential shapes on the way in.
    Text(String),
    /// A number: a count, a lifetime, a status code.
    Number(i64),
    /// A flag.
    Flag(bool),
    /// A credential, reduced to a digest. The only way a credential-shaped
    /// thing gets into the trail deliberately.
    Fingerprint(String),
}

/// The free-form part of an event.
///
/// Values are added through [`Detail::text`], [`Detail::number`],
/// [`Detail::flag`] and [`Detail::credential`]; there is no way to insert a
/// value that has not been through one of them, and `text` redacts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detail(BTreeMap<String, DetailValue>);

impl Detail {
    /// An empty detail map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records free text, redacting it if it looks like a credential.
    #[must_use]
    pub fn text(mut self, key: &str, value: impl AsRef<str>) -> Self {
        self.0.insert(
            key.to_owned(),
            DetailValue::Text(redaction::redact(value.as_ref())),
        );
        self
    }

    /// Records a value drawn from a closed set this server owns.
    ///
    /// The `&'static str` bound is the whole point, and it is doing real work:
    /// a value that must live for the program's lifetime cannot have arrived in
    /// a request, so there is nothing here to redact. That makes this the right
    /// home for an OAuth error code, a policy name, a grant type — the closed
    /// vocabularies that are the most useful thing in a trail and the most
    /// annoying thing to lose.
    ///
    /// And they were being lost. [`Self::text`] runs [`redaction::redact`],
    /// whose heuristic is deliberately biased towards false positives: it
    /// classifies any run of 22 or more `base64url` characters using twelve or
    /// more distinct ones as a credential. `temporarily_unavailable` is 23
    /// characters over 15 distinct, so recording it through `text` stored
    /// `[REDACTED:credential:…]` — exactly the outcome `redact`'s own
    /// documentation promises does not happen to "a client name, an error code
    /// or a scope list". Tightening the scanner to spare that one string would
    /// weaken it for every caller; giving a compile-time constant a route that
    /// does not need scanning costs nobody anything.
    ///
    /// Use [`Self::text`] for anything a request could have influenced, even
    /// indirectly. The bound will not stop you — `&'static str` can be leaked
    /// from a `String` — but it makes doing so a deliberate act.
    #[must_use]
    pub fn label(mut self, key: &str, value: &'static str) -> Self {
        self.0
            .insert(key.to_owned(), DetailValue::Text(value.to_owned()));
        self
    }

    /// Records a number.
    #[must_use]
    pub fn number(mut self, key: &str, value: i64) -> Self {
        self.0.insert(key.to_owned(), DetailValue::Number(value));
        self
    }

    /// Records a flag.
    #[must_use]
    pub fn flag(mut self, key: &str, value: bool) -> Self {
        self.0.insert(key.to_owned(), DetailValue::Flag(value));
        self
    }

    /// Records *which* credential an event concerns, without recording it.
    ///
    /// Use this for an authorization code, a refresh token, a `request_uri` or
    /// a `jti`: two events naming the same credential get the same digest, so
    /// the trail can be followed, and the credential cannot be read back out.
    #[must_use]
    pub fn credential(mut self, key: &str, secret: impl AsRef<str>) -> Self {
        self.0.insert(
            key.to_owned(),
            DetailValue::Fingerprint(redaction::fingerprint(secret.as_ref())),
        );
        self
    }

    /// Records *who* an event concerns, without recording their identity.
    ///
    /// For an email address, a username, a phone number, an IP address, a user
    /// agent — the personal data that has no business being legible in a trail
    /// that is deliberately kept for years, copied into a SIEM and read by
    /// whoever is on call (FAPI 2.0 SP §7; GDPR data minimisation).
    ///
    /// [`Self::text`] does not cover this and cannot: the scanner looks for
    /// credential *shapes*, and `alice@example.com` is not one. Recorded
    /// through `text` it is stored verbatim.
    ///
    /// The digest is [`redaction::fingerprint`] — the same function
    /// [`Self::credential`] uses, deliberately, rather than a second hashing
    /// scheme with its own salt and its own bugs. Two consequences, both
    /// intended: the same value fingerprints identically wherever it appears,
    /// so an investigator can follow one person across a trail; and the digest
    /// is unsalted, so somebody holding both the trail and a list of candidate
    /// addresses can confirm a guess. That is the same bargain the log
    /// formatter strikes for `sub` — correlation is most of why the record
    /// exists, and confirming a guess requires already having it.
    ///
    /// Use [`Self::credential`] for a secret and this for a person. They hash
    /// alike; what differs is what a reader may conclude from a match.
    #[must_use]
    pub fn pii(mut self, key: &str, value: impl AsRef<str>) -> Self {
        self.0.insert(
            key.to_owned(),
            DetailValue::Fingerprint(redaction::fingerprint(value.as_ref())),
        );
        self
    }

    /// Rebuilds a text entry read back from storage, without redacting again.
    ///
    /// Redaction happens once, on the way in. Applying it a second time would
    /// be harmless for the value but would make reconstruction depend on the
    /// scanner staying byte-identical forever, and the hash chain cannot
    /// tolerate that. Storage adapters use this; nothing else should.
    #[must_use]
    pub fn raw_text(mut self, key: &str, value: &str) -> Self {
        self.0
            .insert(key.to_owned(), DetailValue::Text(value.to_owned()));
        self
    }

    /// Rebuilds a fingerprint entry read back from storage, without re-hashing
    /// the digest.
    #[must_use]
    pub fn raw_fingerprint(mut self, key: &str, digest: &str) -> Self {
        self.0
            .insert(key.to_owned(), DetailValue::Fingerprint(digest.to_owned()));
        self
    }

    /// The entries, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &DetailValue)> {
        self.0.iter()
    }

    /// Whether anything was recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One record in the trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Which tenant this concerns.
    pub tenant: TenantId,
    /// When it happened.
    pub occurred_at: OffsetDateTime,
    /// What happened.
    pub event_type: EventType,
    /// Whether it worked.
    pub outcome: Outcome,
    /// Who caused it.
    pub actor: Actor,
    /// The delegation chain in force, outermost first. Empty unless an agent
    /// obtained its authority through token exchange.
    pub actor_chain: Vec<Actor>,
    /// The end user the event concerns, when there is one.
    pub subject: Option<String>,
    /// The client involved, when there is one.
    pub client: Option<ClientId>,
    /// The session involved, when there is one.
    pub session: Option<SessionId>,
    /// The grant involved. This is the link FAPI 2.0 SP §6.8 item 4 asks for:
    /// it is what lets everything derived from one authorization be revoked
    /// together.
    pub grant: Option<GrantId>,
    /// The request that caused this, for correlation with logs.
    pub request_id: Option<String>,
    /// Everything else.
    pub detail: Detail,
}

impl AuditEvent {
    /// Starts an event. Everything optional defaults to absent.
    #[must_use]
    pub fn new(
        tenant: TenantId,
        event_type: EventType,
        outcome: Outcome,
        actor: Actor,
        occurred_at: OffsetDateTime,
    ) -> Self {
        Self {
            tenant,
            occurred_at,
            event_type,
            outcome,
            actor,
            actor_chain: Vec::new(),
            subject: None,
            client: None,
            session: None,
            grant: None,
            request_id: None,
            detail: Detail::new(),
        }
    }

    /// Sets the subject.
    #[must_use]
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Sets the client.
    #[must_use]
    pub fn client(mut self, client: ClientId) -> Self {
        self.client = Some(client);
        self
    }

    /// Sets the session.
    #[must_use]
    pub fn session(mut self, session: SessionId) -> Self {
        self.session = Some(session);
        self
    }

    /// Sets the grant.
    #[must_use]
    pub fn grant(mut self, grant: GrantId) -> Self {
        self.grant = Some(grant);
        self
    }

    /// Sets the request id.
    #[must_use]
    pub fn request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = Some(request_id.into());
        self
    }

    /// Sets the delegation chain, outermost actor first.
    #[must_use]
    pub fn actor_chain(mut self, chain: Vec<Actor>) -> Self {
        self.actor_chain = chain;
        self
    }

    /// Sets the detail map.
    #[must_use]
    pub fn detail(mut self, detail: Detail) -> Self {
        self.detail = detail;
        self
    }
}

/// Where audit events go.
///
/// A port, so that protocol code can record an event without knowing whether it
/// lands in PostgreSQL, in a test vector, or nowhere.
#[async_trait::async_trait]
pub trait AuditSink: std::fmt::Debug + Send + Sync {
    /// Appends one event.
    ///
    /// # Errors
    ///
    /// Returns the storage failure. Callers must decide deliberately whether a
    /// failed audit write should fail the operation being audited; for
    /// security-relevant events it should.
    async fn record(&self, event: AuditEvent) -> Result<(), crate::DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_types_are_unique_and_dotted() {
        let mut seen = std::collections::BTreeSet::new();
        for event in EventType::ALL {
            assert!(seen.insert(event.as_str()), "duplicate event type {event}");
            let (category, action) = event
                .as_str()
                .split_once('.')
                .unwrap_or_else(|| panic!("{event} is not category.action"));
            assert!(!category.is_empty() && !action.is_empty(), "{event}");
            assert!(
                event
                    .as_str()
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
                "{event} is not lower snake case"
            );
        }
    }

    /// `EventType::ALL` is what `row_to_event` resolves a stored spelling
    /// through, so a variant missing from it is an event that can be written
    /// and never read back.
    #[test]
    fn a_created_credential_has_an_event_type_that_round_trips_through_all() {
        let stored = EventType::CREDENTIAL_CREATED.as_str();

        let found = EventType::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == stored);

        assert_eq!(found, Some(EventType::CREDENTIAL_CREATED));
    }

    #[test]
    fn an_agent_actor_always_names_the_principal_it_acts_for() {
        let agent = Actor::Agent {
            client: ClientId::new("scheduler-bot"),
            on_behalf_of: "alice".to_owned(),
        };
        assert_eq!(agent.kind(), "agent");
        assert_eq!(agent.id(), "scheduler-bot");
        let Actor::Agent { on_behalf_of, .. } = &agent else {
            panic!("not an agent")
        };
        assert_eq!(on_behalf_of, "alice");
    }

    /// The property the whole module exists for.
    #[test]
    fn a_credential_cannot_be_written_into_the_detail_map() {
        let code = "Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5uV-eW_iO2nQ";
        let detail = Detail::new()
            .text("error_description", "the code has already been redeemed")
            .text("accidentally_pasted", code)
            .credential("code", code)
            .number("lifetime_seconds", 60);

        let rendered = format!("{detail:?}");
        assert!(
            !rendered.contains(code),
            "the credential reached the detail map: {rendered}"
        );
        assert!(rendered.contains("redacted:credential"));
        assert!(
            rendered.contains("already been redeemed"),
            "ordinary text was lost"
        );
    }

    #[test]
    fn the_same_credential_fingerprints_identically_across_events() {
        let code = "Zx9Kq2mNpR7vT4wY1bC8dF3gH6jL0aS5uV-eW_iO2nQ";
        let issued = Detail::new().credential("code", code);
        let redeemed = Detail::new().credential("code", code);
        assert_eq!(issued, redeemed, "a trail cannot be followed across events");
    }

    /// The gap `pii` closes: an email address is not credential-shaped, so the
    /// scanner passes it through and `text` stores it verbatim.
    #[test]
    fn personal_data_is_stored_as_a_digest_rather_than_as_itself() {
        let email = "alice@example.com";
        let careless = Detail::new().text("email", email);
        assert!(
            format!("{careless:?}").contains(email),
            "this test is pointless unless `text` really would have stored it"
        );

        let minimised = Detail::new().pii("email", email);
        let rendered = format!("{minimised:?}");
        assert!(
            !rendered.contains(email),
            "personal data reached the trail: {rendered}"
        );
        assert!(rendered.contains("Fingerprint"));
    }

    /// One hashing scheme, not two: `pii` and `credential` agree, so a value
    /// recorded through either can be matched against the other and there is
    /// only one function to get wrong.
    #[test]
    fn personal_data_and_credentials_share_one_fingerprint_scheme() {
        let value = "alice@example.com";
        assert_eq!(
            Detail::new().pii("who", value),
            Detail::new().credential("who", value)
        );
        assert_ne!(
            Detail::new().pii("who", value),
            Detail::new().pii("who", "bob@example.com")
        );
    }

    #[test]
    fn an_event_defaults_to_nothing_it_was_not_told() {
        let event = AuditEvent::new(
            TenantId::new("demo"),
            EventType::TOKEN_ISSUED,
            Outcome::Success,
            Actor::System,
            OffsetDateTime::UNIX_EPOCH,
        );
        assert!(event.subject.is_none());
        assert!(event.client.is_none());
        assert!(event.grant.is_none());
        assert!(event.actor_chain.is_empty());
        assert!(event.detail.is_empty());
    }
}
