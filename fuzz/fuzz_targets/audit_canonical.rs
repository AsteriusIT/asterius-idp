//! The audit chain's canonical encoding.
//!
//! The encoding is the security property: if two different events can produce
//! the same bytes, the hash chain can be forged by substituting one for the
//! other. This target drives arbitrary field values through it and asserts the
//! encoding separates them.
#![no_main]

use asterius_domain::audit::chain;
use asterius_domain::audit::{Actor, AuditEvent, Detail, EventType, Outcome};
use asterius_domain::{ClientId, TenantId};
use libfuzzer_sys::fuzz_target;
use time::OffsetDateTime;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if text.len() < 2 {
        return;
    }
    // The split must land on a character boundary — `text.len() / 2` does not,
    // and `split_at` panics there. This crashed on its first run, in the
    // harness rather than in the encoder.
    let midpoint = text.chars().count() / 2;
    let boundary = text
        .char_indices()
        .nth(midpoint)
        .map_or(text.len(), |(index, _)| index);
    let (left, right) = text.split_at(boundary);

    let build = |client: &str, subject: &str| {
        AuditEvent::new(
            TenantId::new("demo"),
            EventType::TOKEN_ISSUED,
            Outcome::Success,
            Actor::Client(ClientId::new(client)),
            OffsetDateTime::UNIX_EPOCH,
        )
        .subject(subject)
        .detail(Detail::new().text("note", text))
    };

    // The boundary-moving attack: `client=ab, subject=c` must not encode the
    // same as `client=a, subject=bc`.
    let split_here = build(left, right);
    let split_there = build(text, "");

    if left != text || !right.is_empty() {
        assert_ne!(
            chain::canonical_bytes(&split_here),
            chain::canonical_bytes(&split_there),
            "two different events share an encoding"
        );
    }

    // Hashing is total and deterministic.
    let hash = chain::hash(chain::EventHash::GENESIS, &split_here);
    assert_eq!(hash, chain::hash(chain::EventHash::GENESIS, &split_here));
});
