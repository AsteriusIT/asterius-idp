//! The audit trail's reader: stored columns in, a typed record or a reason out.
//!
//! Reading a record has to be *total*. The database refuses `UPDATE` and
//! `DELETE` on `audit_events`, so a row this build cannot parse can never be
//! repaired (`ast-1p1`); a reader that panicked or failed on one would let a
//! single row — one that an import, a restored dump or an older build could
//! have written — cost the readability of the whole trail around it.
//!
//! So this target feeds arbitrary bytes into every column that carries JSON and
//! asserts two things: the reader always answers, and when it answers with an
//! event, that event survives being written back out and read again. The second
//! is what the hash chain depends on — a round trip that loses a field
//! recomputes a different hash and reports tampering that never happened.
#![no_main]

use asterius_domain::audit::record::{self, StoredEvent};
use asterius_domain::audit::{EventType, Outcome};
use asterius_domain::{ClientId, GrantId, SessionId, TenantId};
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

/// The columns a record is made of, as bytes, the way storage holds them.
#[derive(Debug, arbitrary::Arbitrary)]
struct Columns<'a> {
    event_type: &'a str,
    outcome: &'a str,
    actor: &'a [u8],
    actor_chain: &'a [u8],
    subject: Option<&'a str>,
    client: Option<&'a str>,
    session: Option<&'a str>,
    grant: Option<&'a str>,
    request_id: Option<&'a str>,
    detail: &'a [u8],
    /// Which known event type to use when the arbitrary one is not known, so
    /// that the corpus reaches the columns past the first check.
    known_type: bool,
}

fuzz_target!(|columns: Columns<'_>| {
    let tenant = TenantId::new("demo");
    let event_type = if columns.known_type {
        EventType::TOKEN_ISSUED.as_str()
    } else {
        columns.event_type
    };
    let outcome = if columns.known_type {
        Outcome::Success.as_str()
    } else {
        columns.outcome
    };

    let stored = StoredEvent {
        tenant: &tenant,
        occurred_at: OffsetDateTime::UNIX_EPOCH,
        event_type,
        outcome,
        actor: columns.actor,
        actor_chain: columns.actor_chain,
        subject: columns.subject,
        client: columns.client,
        session: columns.session,
        grant: columns.grant,
        request_id: columns.request_id,
        detail: columns.detail,
    };

    // Total: either an event, or a reason the caller reports the record as
    // opaque with. Never a panic, and never a failure of the whole read.
    let Ok(event) = record::read_event(&stored) else {
        return;
    };

    // What was read must be what a writer would store, or the chain would
    // recompute a hash the record was never written with.
    let actor = record::actor_json(&event.actor).to_string();
    let chain = record::actor_chain_json(&event.actor_chain).to_string();
    let detail = record::detail_json(&event.detail).to_string();
    let again = record::read_event(&StoredEvent {
        tenant: &tenant,
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
    .expect("an event this reader produced must read back");

    assert_eq!(again, event, "a record changed on its way through storage");
});
