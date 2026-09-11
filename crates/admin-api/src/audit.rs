//! The audit trail's query API: a filtered listing and a streamed export
//! (`ast-lh3.9`).
//!
//! Two reads. `GET /audit/events` answers an operator's question one page at
//! a time; `GET /audit/events/export` answers it as NDJSON, one record per
//! line, for a SIEM or an investigator's notebook. Both take the same filters
//! — agent, owner, user, grant, event type, time window — and the semantics
//! of every filter is [`AuditFilter::matches`] in the domain, which this
//! module only parses into.
//!
//! # The trail is the most sensitive thing a read scope reaches
//!
//! Everything else behind `admin.*:read` describes a deployment. The trail
//! describes its *people*: who signed in when, from which fingerprinted
//! address, which agent acted for whom, and which authorization each token
//! came from. An export of it is exfiltration with a purpose, so the surface
//! is deliberately narrower than "select * with filters":
//!
//! * **Its own scope**, `admin.audit:read`, held by the auditor role and the
//!   administrators and by nobody else. The dead-letter and user screens do
//!   not confer it.
//! * **A ceiling on one export**, [`asterius_domain::audit::query::EXPORT_MAX_RECORDS`]
//!   lines, after which the stream ends. A purpose that needs more has a
//!   database client and a change-control record.
//! * **Nothing is added on the way out.** What is rendered is what was
//!   stored, and what was stored went through `Detail::pii` and
//!   `Detail::credential` on the way in: an address or a user agent is a
//!   `sha256:` digest in the export as it is in the row. The export cannot
//!   un-hash anything because nothing here holds the value.
//! * **Every line names its hash.** An export is evidence, and evidence that
//!   can be checked against the chain later is worth more than evidence that
//!   cannot.
//!
//! See `docs/threat-model.md`, "Audit query API and export".
//!
//! # Why the filter is parsed here and matched there
//!
//! A query string is the one input to a listing that decides which rows an
//! operator is shown, and it is text somebody typed. [`parse_filter`] turns
//! it into an [`AuditFilter`] — a closed set of typed members — and is fuzzed
//! as `admin_audit_filter`; what reaches the database is bound parameters,
//! never a fragment. An unknown parameter is refused rather than ignored:
//! `agnet=c.a` returning the whole trail is the one mistake an export must
//! not make quietly.

use asterius_domain::audit::query::{AuditFilter, AuditQuery, EXPORT_MAX_RECORDS, MAX_PAGE};
use asterius_domain::audit::record::AuditRecord;
use asterius_domain::audit::{Actor, AuditEvent, DetailValue, EventType, TrailEntry};
use asterius_domain::{ClientId, DomainError, GrantId, TenantId};
use serde_json::{Map, Value, json};
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::AdminError;

/// The longest value one filter parameter may carry.
///
/// A `client_id` is under 64 characters, a subject is 43 or 36, a UUID is 36
/// and an RFC 3339 instant is 35. Anything longer is not a filter.
pub const MAX_VALUE_LEN: usize = 256;

/// The most event types one request may name.
///
/// There are fewer distinct types than this, so a list at the cap is a list
/// with repeats, and the bound is what stops a caller sending a megabyte of
/// `type=` to see what happens.
pub const MAX_TYPES: usize = 64;

/// The media type of the export (RFC 7464's cousin, one JSON text per line).
pub const NDJSON: &str = "application/x-ndjson";

/// The filter parameters, with the description the `OpenAPI` document
/// carries for each. The names are the contract; the descriptions are for a
/// person.
pub const PARAMETERS: &[(&str, &str)] = &[
    (
        "agent",
        "A client_id. Records the agent caused, or took part in as a link of the RFC 8693 act chain.",
    ),
    (
        "owner",
        "A subject. Records made by an agent acting on behalf of this person.",
    ),
    (
        "user",
        "A subject. Everything done under this person: records naming them as subject, and records made by agents they own.",
    ),
    (
        "grant",
        "A grant id (UUID). Records naming this authorization.",
    ),
    (
        "type",
        "An event type such as token.exchanged. Repeatable, or comma separated; the result is the union.",
    ),
    ("from", "An RFC 3339 instant. Records at or after it."),
    ("until", "An RFC 3339 instant. Records strictly before it."),
];

/// Reads the filter members out of a query string.
///
/// `cursor` and `limit` are the listing's own and are skipped; every other
/// parameter must be one of [`PARAMETERS`]. Values are percent-decoded the
/// way a browser encodes them (`+` and `%XX`), because `from` carries colons
/// and a console sends them encoded.
///
/// # Errors
///
/// [`AdminError::Invalid`] for an unknown parameter, a single-valued one sent
/// twice, a value over [`MAX_VALUE_LEN`] or carrying a control character, a
/// `grant` that is not a UUID, a `type` this build does not record, an
/// instant that is not RFC 3339, or a window whose `from` is not before its
/// `until`. The message names the parameter and never echoes the value.
// fuzz-target: admin_audit_filter
pub fn parse_filter(query: &str) -> Result<AuditFilter, AdminError> {
    let mut filter = AuditFilter::default();
    let mut seen_types = 0usize;

    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, raw) = pair.split_once('=').unwrap_or((pair, ""));
        if matches!(name, "cursor" | "limit") {
            continue;
        }
        // The name is checked before anything that would put it in a
        // message: every refusal below names a *documented* parameter, so
        // none of them can echo what was typed.
        if !PARAMETERS.iter().any(|(known, _)| *known == name) {
            return Err(AdminError::Invalid(
                "unknown filter parameter; see the OpenAPI document for the list".to_owned(),
            ));
        }
        if raw.len() > MAX_VALUE_LEN {
            return Err(AdminError::Invalid(format!(
                "{name} is longer than {MAX_VALUE_LEN} bytes"
            )));
        }
        let value = crate::clients::search_term(raw);
        if value.is_empty() || value.chars().any(char::is_control) {
            return Err(AdminError::Invalid(format!(
                "{name} must be a non-empty value"
            )));
        }

        match name {
            "agent" => set_once(&mut filter.agent, ClientId::new(value), name)?,
            "owner" => set_once(&mut filter.owner, value, name)?,
            "user" => set_once(&mut filter.user, value, name)?,
            "grant" => {
                let uuid: uuid::Uuid = value
                    .parse()
                    .map_err(|_| AdminError::Invalid("grant must be a UUID".to_owned()))?;
                set_once(&mut filter.grant, GrantId::new(uuid.to_string()), name)?;
            }
            "type" => {
                for spelling in value.split(',').map(str::trim) {
                    seen_types += 1;
                    if seen_types > MAX_TYPES {
                        return Err(AdminError::Invalid(format!(
                            "type may be given at most {MAX_TYPES} times"
                        )));
                    }
                    let event_type = EventType::ALL
                        .into_iter()
                        .find(|candidate| candidate.as_str() == spelling)
                        .ok_or_else(|| {
                            AdminError::Invalid(
                                "type is not an event type this server records".to_owned(),
                            )
                        })?;
                    if !filter.event_types.contains(&event_type) {
                        filter.event_types.push(event_type);
                    }
                }
            }
            "from" => set_once(&mut filter.from, instant(&value, name)?, name)?,
            "until" => set_once(&mut filter.until, instant(&value, name)?, name)?,
            // Unreachable: the name was checked against `PARAMETERS` above.
            // Refused rather than ignored all the same, so that a parameter
            // added to the list and forgotten here is a 400 and not a filter
            // that silently does nothing.
            _ => {
                return Err(AdminError::Invalid(
                    "unknown filter parameter; see the OpenAPI document for the list".to_owned(),
                ));
            }
        }
    }

    if let (Some(from), Some(until)) = (filter.from, filter.until)
        && from >= until
    {
        return Err(AdminError::Invalid("from must be before until".to_owned()));
    }
    Ok(filter)
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), AdminError> {
    if slot.is_some() {
        return Err(AdminError::Invalid(format!("{name} may be given once")));
    }
    *slot = Some(value);
    Ok(())
}

fn instant(value: &str, name: &str) -> Result<OffsetDateTime, AdminError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| AdminError::Invalid(format!("{name} must be an RFC 3339 instant")))
}

/// Renders one entry as the API and the export show it.
///
/// A readable record is the event, flattened: the fields every record has,
/// the agent view ([`AuditEvent::agent_id`], [`AuditEvent::agent_owner`])
/// beside the actor it was read from, and the detail map with fingerprints
/// spelled `sha256:…` as they are stored. An opaque record is its id, its
/// hash and the column the reader stopped at — never the bytes of the row,
/// which are the one thing an attacker who reached the database chose.
#[must_use]
pub fn render(entry: &TrailEntry) -> Value {
    match &entry.record {
        AuditRecord::Event(event) => {
            let mut document = event_document(event);
            document.insert("id".to_owned(), json!(entry.id));
            document.insert("hash".to_owned(), json!(entry.hash.to_hex()));
            Value::Object(document)
        }
        AuditRecord::Opaque { reason, .. } => json!({
            "id": entry.id,
            "hash": entry.hash.to_hex(),
            "opaque": reason.column(),
        }),
    }
}

fn event_document(event: &AuditEvent) -> Map<String, Value> {
    let mut document = Map::new();
    document.insert(
        "occurred_at".to_owned(),
        json!(timestamp(event.occurred_at)),
    );
    document.insert("type".to_owned(), json!(event.event_type.as_str()));
    document.insert("outcome".to_owned(), json!(event.outcome.as_str()));
    document.insert("actor".to_owned(), actor_document(&event.actor));
    document.insert(
        "actor_chain".to_owned(),
        Value::Array(event.actor_chain.iter().map(actor_document).collect()),
    );
    if let Some(agent) = event.agent_id() {
        document.insert("agent_id".to_owned(), json!(agent));
    }
    if let Some(owner) = event.agent_owner() {
        document.insert("agent_owner".to_owned(), json!(owner));
    }
    if let Some(subject) = &event.subject {
        document.insert("subject".to_owned(), json!(subject));
    }
    if let Some(client) = &event.client {
        document.insert("client_id".to_owned(), json!(client.as_str()));
    }
    if let Some(session) = &event.session {
        document.insert("session_id".to_owned(), json!(session.as_str()));
    }
    if let Some(grant) = &event.grant {
        document.insert("grant_id".to_owned(), json!(grant.as_str()));
    }
    if let Some(request_id) = &event.request_id {
        document.insert("request_id".to_owned(), json!(request_id));
    }
    let mut detail = Map::new();
    for (key, value) in event.detail.iter() {
        detail.insert(
            key.clone(),
            match value {
                DetailValue::Text(text) => json!(text),
                DetailValue::Number(number) => json!(number),
                DetailValue::Flag(flag) => json!(flag),
                DetailValue::Fingerprint(digest) => json!(format!("sha256:{digest}")),
            },
        );
    }
    document.insert("detail".to_owned(), Value::Object(detail));
    document
}

fn actor_document(actor: &Actor) -> Value {
    let mut object = Map::new();
    object.insert("type".to_owned(), json!(actor.kind()));
    object.insert("id".to_owned(), json!(actor.id()));
    if let Actor::Agent { on_behalf_of, .. } = actor {
        object.insert("on_behalf_of".to_owned(), json!(on_behalf_of));
    }
    Value::Object(object)
}

/// RFC 3339, or the epoch if the value cannot be formatted — unreachable for
/// a `timestamptz`, and a row that fails a whole export over one odd
/// timestamp is worse than one showing a wrong date beside a real event.
fn timestamp(at: OffsetDateTime) -> String {
    at.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

/// The export: the matching records, newest first, one JSON line each, read
/// from the trail a page at a time as the client drains the body.
///
/// A stream and not a `Vec`, because the ceiling is a hundred thousand lines
/// and a handler that materialised them would hold the whole export in
/// memory per request. Each page is fetched only when the buffer of the
/// previous one has been sent, so a slow reader costs one page of memory and
/// no connection held open across the whole read.
///
/// A storage failure part-way ends the stream with an error: the response
/// headers have gone, so it cannot become a 503, and what the client sees is
/// a body that did not complete rather than one that looks whole and is not.
pub struct Export {
    trail: Arc<dyn AuditQuery>,
    tenant: TenantId,
    filter: AuditFilter,
    before: Option<i64>,
    remaining: usize,
    buffer: VecDeque<Vec<u8>>,
    inflight: Option<PageFuture>,
    exhausted: bool,
}

type PageFuture = Pin<Box<dyn Future<Output = Result<Vec<TrailEntry>, DomainError>> + Send>>;

impl Export {
    /// Starts an export of `tenant`'s records matching `filter`.
    #[must_use]
    pub fn new(trail: Arc<dyn AuditQuery>, tenant: TenantId, filter: AuditFilter) -> Self {
        Self {
            trail,
            tenant,
            filter,
            before: None,
            remaining: EXPORT_MAX_RECORDS,
            buffer: VecDeque::new(),
            inflight: None,
            exhausted: false,
        }
    }

    fn next_page(&self) -> PageFuture {
        let trail = Arc::clone(&self.trail);
        let tenant = self.tenant.clone();
        let filter = self.filter.clone();
        let before = self.before;
        let limit = u32::try_from(self.remaining.min(MAX_PAGE as usize)).unwrap_or(MAX_PAGE);
        Box::pin(async move { trail.query(&tenant, &filter, before, limit).await })
    }
}

impl std::fmt::Debug for Export {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Export")
            .field("tenant", &self.tenant)
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

impl futures_core::Stream for Export {
    type Item = Result<Vec<u8>, DomainError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(line) = self.buffer.pop_front() {
                return Poll::Ready(Some(Ok(line)));
            }
            if self.exhausted || self.remaining == 0 {
                return Poll::Ready(None);
            }
            if self.inflight.is_none() {
                let page = self.next_page();
                self.inflight = Some(page);
            }
            let Some(inflight) = self.inflight.as_mut() else {
                return Poll::Ready(None);
            };
            match inflight.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    self.inflight = None;
                    self.exhausted = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Ok(entries)) => {
                    self.inflight = None;
                    let asked = self.remaining.min(MAX_PAGE as usize);
                    // A short page is the last one. Checked before the
                    // ceiling is applied, so the two conditions stay
                    // distinct: "the trail ended" and "the export is full".
                    if entries.len() < asked {
                        self.exhausted = true;
                    }
                    for entry in entries.iter().take(self.remaining) {
                        let mut line = render(entry).to_string().into_bytes();
                        line.push(b'\n');
                        self.buffer.push_back(line);
                        self.before = Some(entry.id);
                    }
                    self.remaining = self.remaining.saturating_sub(entries.len());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::audit::chain::EventHash;
    use asterius_domain::audit::{Detail, Outcome};
    use futures_core::Stream as _;
    use std::sync::Mutex;

    fn is(actual: &AdminError, message: &str) -> bool {
        matches!(actual, AdminError::Invalid(text) if text.contains(message))
    }

    // ---- the parser --------------------------------------------------------

    #[test]
    fn an_empty_query_is_the_whole_trail() {
        // Arrange / Act
        let filter = parse_filter("").expect("empty is fine");

        // Assert
        assert!(filter.is_empty());
    }

    #[test]
    fn every_member_parses_into_its_typed_slot() {
        // Arrange
        let query = "agent=c.a&owner=alice&user=bob&grant=AAAAAAAA-aaaa-4aaa-8aaa-aaaaaaaaaaaa\
                     &type=token.issued,token.exchanged&type=auth.login\
                     &from=2026-01-01T00%3A00%3A00Z&until=2026-02-01T00:00:00Z&cursor=v1.MQ&limit=5";

        // Act
        let filter = parse_filter(query).expect("a well-formed query");

        // Assert
        assert_eq!(filter.agent, Some(ClientId::new("c.a")));
        assert_eq!(filter.owner.as_deref(), Some("alice"));
        assert_eq!(filter.user.as_deref(), Some("bob"));
        assert_eq!(
            filter.grant.as_ref().map(GrantId::as_str),
            Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            "a UUID is normalised to the spelling the column holds"
        );
        assert_eq!(
            filter.event_types,
            vec![
                EventType::TOKEN_ISSUED,
                EventType::TOKEN_EXCHANGED,
                EventType::AUTH_LOGIN
            ]
        );
        assert_eq!(
            filter.from.map(OffsetDateTime::unix_timestamp),
            Some(1_767_225_600)
        );
        assert!(filter.until > filter.from);
    }

    /// The quiet failure an export must not have: a misspelled parameter
    /// that returns everything.
    #[test]
    fn an_unknown_parameter_is_refused_rather_than_ignored() {
        // Arrange / Act
        let error = parse_filter("agnet=c.a").expect_err("a typo is a bug");

        // Assert
        assert!(is(&error, "unknown filter parameter"), "{error}");
    }

    #[test]
    fn an_event_type_this_build_does_not_record_is_refused() {
        let error = parse_filter("type=token.teleported").expect_err("unknown type");
        assert!(is(&error, "not an event type"), "{error}");
    }

    #[test]
    fn a_grant_must_be_a_uuid() {
        let error = parse_filter("grant=g-1").expect_err("not a uuid");
        assert!(is(&error, "grant must be a UUID"), "{error}");
    }

    #[test]
    fn a_single_valued_parameter_sent_twice_is_refused() {
        let error = parse_filter("agent=c.a&agent=c.b").expect_err("twice");
        assert!(is(&error, "agent may be given once"), "{error}");
    }

    #[test]
    fn an_instant_must_be_rfc_3339_and_the_window_must_be_ordered() {
        let not_an_instant = parse_filter("from=yesterday").expect_err("prose");
        assert!(
            is(&not_an_instant, "from must be an RFC 3339 instant"),
            "{not_an_instant}"
        );

        let inverted = parse_filter("from=2026-02-01T00:00:00Z&until=2026-01-01T00:00:00Z")
            .expect_err("inverted");
        assert!(is(&inverted, "from must be before until"), "{inverted}");

        let empty = parse_filter("from=2026-01-01T00:00:00Z&until=2026-01-01T00:00:00Z")
            .expect_err("empty window");
        assert!(is(&empty, "from must be before until"), "{empty}");
    }

    #[test]
    fn a_value_is_bounded_and_never_carries_a_control_character() {
        let long = format!("agent={}", "a".repeat(MAX_VALUE_LEN + 1));
        assert!(is(
            &parse_filter(&long).expect_err("too long"),
            "longer than"
        ));

        let control = parse_filter("owner=ali%0Ace").expect_err("a newline");
        assert!(is(&control, "owner must be a non-empty value"), "{control}");

        assert!(
            parse_filter("owner=").is_err(),
            "an empty owner is not a filter"
        );
    }

    #[test]
    fn the_error_never_echoes_the_value() {
        let error = parse_filter("type=<script>alert(1)</script>").expect_err("unknown type");
        assert!(!error.to_string().contains("script"), "{error}");
    }

    // ---- rendering ---------------------------------------------------------

    fn entry(event: AuditEvent) -> TrailEntry {
        TrailEntry {
            id: 7,
            hash: EventHash::GENESIS,
            record: AuditRecord::Event(Box::new(event)),
        }
    }

    fn exchange() -> AuditEvent {
        AuditEvent::new(
            TenantId::new("acme"),
            EventType::TOKEN_EXCHANGED,
            Outcome::Success,
            Actor::Agent {
                client: ClientId::new("c.b"),
                on_behalf_of: "bob".to_owned(),
            },
            OffsetDateTime::UNIX_EPOCH,
        )
        .subject("alice")
        .client(ClientId::new("c.b"))
        .grant(GrantId::new("22222222-2222-4222-8222-222222222222"))
        .actor_chain(vec![Actor::Client(ClientId::new("c.a"))])
        .detail(
            Detail::new()
                .label("grant_type", "token_exchange")
                .pii("ip", "203.0.113.5")
                .number("expires_in", 300),
        )
    }

    /// The per-agent view of a record: agent, owner, chain, grant — beside
    /// the fields every record has, and with the id and hash of the entry.
    #[test]
    fn a_rendered_record_carries_the_agent_view_and_its_hash() {
        // Arrange
        let entry = entry(exchange());

        // Act
        let rendered = render(&entry);

        // Assert
        assert_eq!(rendered["id"], 7);
        assert_eq!(rendered["hash"], EventHash::GENESIS.to_hex());
        assert_eq!(rendered["type"], "token.exchanged");
        assert_eq!(rendered["agent_id"], "c.b");
        assert_eq!(rendered["agent_owner"], "bob");
        assert_eq!(rendered["subject"], "alice");
        assert_eq!(rendered["grant_id"], "22222222-2222-4222-8222-222222222222");
        assert_eq!(rendered["actor"]["on_behalf_of"], "bob");
        assert_eq!(rendered["actor_chain"][0]["id"], "c.a");
        assert_eq!(rendered["occurred_at"], "1970-01-01T00:00:00Z");
        assert_eq!(rendered["detail"]["expires_in"], 300);
    }

    /// PII minimisation survives the export: an address recorded through
    /// `Detail::pii` is a digest in the row and a digest on the line.
    #[test]
    fn a_fingerprinted_address_is_rendered_as_its_digest() {
        // Arrange
        let entry = entry(exchange());

        // Act
        let line = render(&entry).to_string();

        // Assert
        assert!(
            !line.contains("203.0.113.5"),
            "an address reached the export: {line}"
        );
        assert!(line.contains("\"ip\":\"sha256:"), "{line}");
    }

    #[test]
    fn an_opaque_record_is_rendered_as_its_hash_and_the_column_and_nothing_else() {
        // Arrange
        let entry = TrailEntry {
            id: 3,
            hash: EventHash::GENESIS,
            record: AuditRecord::Opaque {
                hash: EventHash::GENESIS,
                position: 0,
                reason: asterius_domain::audit::OpaqueReason::Unparseable {
                    column: asterius_domain::audit::record::DETAIL,
                },
            },
        };

        // Act
        let rendered = render(&entry);

        // Assert
        let keys: Vec<_> = rendered.as_object().expect("an object").keys().collect();
        assert_eq!(keys, vec!["hash", "id", "opaque"]);
        assert_eq!(rendered["opaque"], "detail");
    }

    // ---- the export stream -------------------------------------------------

    /// A trail of `n` records that hands out pages the way the port promises
    /// — newest first, ids below `before`, at most `limit` — and counts the
    /// reads.
    #[derive(Debug)]
    struct Trail {
        events: Vec<AuditEvent>,
        reads: Mutex<usize>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl AuditQuery for Trail {
        async fn query(
            &self,
            _tenant: &TenantId,
            filter: &AuditFilter,
            before: Option<i64>,
            limit: u32,
        ) -> Result<Vec<TrailEntry>, DomainError> {
            *self.reads.lock().expect("uncontended") += 1;
            if self.fail {
                return Err(DomainError::Storage("the trail is unreachable".into()));
            }
            Ok(self
                .events
                .iter()
                .enumerate()
                .rev()
                .map(|(index, event)| TrailEntry {
                    id: i64::try_from(index).expect("small") + 1,
                    hash: EventHash::GENESIS,
                    record: AuditRecord::Event(Box::new(event.clone())),
                })
                .filter(|entry| before.is_none_or(|before| entry.id < before))
                .filter(|entry| entry.record.event().is_some_and(|e| filter.matches(e)))
                .take(limit.min(MAX_PAGE) as usize)
                .collect())
        }
    }

    fn trail(n: usize, fail: bool) -> Arc<Trail> {
        Arc::new(Trail {
            events: (0..n).map(|_| exchange()).collect(),
            reads: Mutex::new(0),
            fail,
        })
    }

    /// Drains the stream on the current thread.
    fn drain(mut export: Export) -> (Vec<Vec<u8>>, Option<DomainError>) {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut lines = Vec::new();
        loop {
            match Pin::new(&mut export).poll_next(&mut cx) {
                Poll::Ready(Some(Ok(line))) => lines.push(line),
                Poll::Ready(Some(Err(error))) => return (lines, Some(error)),
                Poll::Ready(None) => return (lines, None),
                Poll::Pending => {}
            }
        }
    }

    #[test]
    fn an_export_is_one_json_line_per_record_newest_first() {
        // Arrange
        let export = Export::new(
            trail(3, false),
            TenantId::new("acme"),
            AuditFilter::default(),
        );

        // Act
        let (lines, error) = drain(export);

        // Assert
        assert!(error.is_none());
        assert_eq!(lines.len(), 3);
        let ids: Vec<i64> = lines
            .iter()
            .map(|line| {
                assert_eq!(line.last(), Some(&b'\n'), "a line ends with a newline");
                serde_json::from_slice::<Value>(line).expect("a JSON text")["id"]
                    .as_i64()
                    .expect("an id")
            })
            .collect();
        assert_eq!(ids, vec![3, 2, 1]);
    }

    /// The export walks the trail a page at a time and stops at a short
    /// page, reading nothing after the last record.
    #[test]
    fn an_export_reads_page_by_page_and_stops_at_a_short_page() {
        // Arrange
        let n = MAX_PAGE as usize + 5;
        let trail = trail(n, false);
        let export = Export::new(
            Arc::clone(&trail) as Arc<dyn AuditQuery>,
            TenantId::new("acme"),
            AuditFilter::default(),
        );

        // Act
        let (lines, error) = drain(export);

        // Assert
        assert!(error.is_none());
        assert_eq!(lines.len(), n);
        assert_eq!(
            *trail.reads.lock().expect("uncontended"),
            2,
            "one full page, one short page"
        );
    }

    /// The ceiling: a trail longer than the export limit is cut at the limit,
    /// and no page past it is read.
    #[test]
    fn an_export_stops_at_the_ceiling() {
        // Arrange
        let trail = trail(EXPORT_MAX_RECORDS + 10, false);
        let export = Export::new(
            Arc::clone(&trail) as Arc<dyn AuditQuery>,
            TenantId::new("acme"),
            AuditFilter::default(),
        );

        // Act
        let (lines, error) = drain(export);

        // Assert
        assert!(error.is_none());
        assert_eq!(lines.len(), EXPORT_MAX_RECORDS);
        assert_eq!(
            *trail.reads.lock().expect("uncontended"),
            EXPORT_MAX_RECORDS / MAX_PAGE as usize,
            "a page was read past the ceiling"
        );
    }

    #[test]
    fn a_storage_failure_ends_the_export_with_an_error_not_a_clean_end() {
        // Arrange
        let export = Export::new(
            trail(3, true),
            TenantId::new("acme"),
            AuditFilter::default(),
        );

        // Act
        let (lines, error) = drain(export);

        // Assert
        assert!(lines.is_empty());
        assert!(error.is_some(), "a failed read looked like an empty trail");
    }
}
