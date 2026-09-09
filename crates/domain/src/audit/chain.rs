//! Tamper evidence: chaining each record to the one before it.
//!
//! The database already refuses `UPDATE` and `DELETE` on `audit_events`, which
//! stops the application from rewriting its own history. It does not stop
//! someone with direct database access, and that is the person a trail most
//! needs to be robust against.
//!
//! So each record carries `SHA-256(previous_hash ‖ canonical(event))`. Changing
//! any field of any record changes its hash, which breaks every hash after it,
//! and recomputing the tail requires write access to rows the application never
//! updates. This is *evidence of tampering*, not prevention: an attacker who
//! can rewrite the whole table can rewrite the whole chain. What it removes is
//! the quiet edit — changing one row and hoping nobody recomputes.
//!
//! # A record the reader cannot parse is still an authentic record
//!
//! `ast-ju2` closed the door on claim names that collide with a `serde_json`
//! sentinel, and `ast-dxh` can find rows written before it that carry one.
//! Such a row is *unparseable*, not *tampered*: its hash is correct, the chain
//! through it verifies, and it is exactly what the server wrote.
//!
//! So the record is never rewritten (`ast-1p1`). Repairing it would break a
//! chain that is currently sound, in exchange for readability of one row — and
//! the database refuses `UPDATE` and `DELETE` here precisely so that no code
//! path can make that trade by accident. A reader that meets a record it
//! cannot deserialise reports it as opaque, showing its hash and its position,
//! and carries on: one unreadable row must not cost the readability of the
//! trail around it.
//!
//! # The encoding is the security property
//!
//! A hash is only as good as what goes into it. Serialising to JSON and hashing
//! that would be a bug: two different events can produce the same JSON if key
//! order varies, and worse, concatenating fields without separators lets
//! `("ab", "c")` and `("a", "bc")` hash identically — so an attacker who
//! controls two adjacent fields could move a boundary and keep the hash.
//!
//! [`canonical_bytes`] therefore length-prefixes every field: each is written
//! as an 8-byte big-endian length followed by its bytes. No field can be
//! confused with its neighbour, and the encoding is fully determined by the
//! event, with no map iteration order to depend on.

use super::{Actor, AuditEvent, DetailValue};
use sha2::{Digest as _, Sha256};

/// A chain link: the SHA-256 of the previous link and this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventHash([u8; 32]);

impl EventHash {
    /// The hash every chain starts from: 32 zero bytes.
    pub const GENESIS: Self = Self([0; 32]);

    /// Wraps raw bytes read back from storage.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Reads a hash from a storage slice.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::MalformedHash`] if the slice is not 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ChainError> {
        <[u8; 32]>::try_from(bytes)
            .map(Self)
            .map_err(|_| ChainError::MalformedHash {
                length: bytes.len(),
            })
    }

    /// The raw bytes, for storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex, for display and for error messages.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for EventHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// Why a chain did not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    /// A stored hash was not 32 bytes.
    #[error("stored hash is {length} bytes, expected 32")]
    MalformedHash {
        /// What was actually stored.
        length: usize,
    },
    /// A record's hash does not match its contents: the record was altered
    /// after it was written.
    #[error("record {position} was altered: stored {stored}, recomputed {recomputed}")]
    Altered {
        /// Zero-based position in the verified range.
        position: usize,
        /// The hash stored alongside the record.
        stored: EventHash,
        /// What the record's contents actually hash to.
        recomputed: EventHash,
    },
    /// A record does not point at its predecessor: a record was removed, or
    /// one was inserted out of order.
    #[error("record {position} follows {actual} but the previous record hashes to {expected}")]
    Broken {
        /// Zero-based position in the verified range.
        position: usize,
        /// The predecessor hash the record claims.
        actual: EventHash,
        /// The predecessor's actual hash.
        expected: EventHash,
    },
}

/// Length-prefixed, order-independent encoding of an event.
///
/// See the module docs for why the length prefixes are not decoration.
#[must_use]
// fuzz-target: audit_canonical
pub fn canonical_bytes(event: &AuditEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);

    field(&mut out, event.tenant.as_str().as_bytes());
    field(
        &mut out,
        &event.occurred_at.unix_timestamp_nanos().to_be_bytes(),
    );
    field(&mut out, event.event_type.as_str().as_bytes());
    field(&mut out, event.outcome.as_str().as_bytes());

    actor(&mut out, &event.actor);
    field(&mut out, &(event.actor_chain.len() as u64).to_be_bytes());
    for link in &event.actor_chain {
        actor(&mut out, link);
    }

    optional(&mut out, event.subject.as_deref());
    optional(&mut out, event.client.as_ref().map(crate::ClientId::as_str));
    optional(
        &mut out,
        event.session.as_ref().map(crate::SessionId::as_str),
    );
    optional(&mut out, event.grant.as_ref().map(crate::GrantId::as_str));
    optional(&mut out, event.request_id.as_deref());

    // `Detail` is a BTreeMap, so iteration is already key-ordered; the length
    // prefix makes that independent of how many entries there are.
    let entries: Vec<_> = event.detail.iter().collect();
    field(&mut out, &(entries.len() as u64).to_be_bytes());
    for (key, value) in entries {
        field(&mut out, key.as_bytes());
        match value {
            DetailValue::Text(text) => {
                field(&mut out, b"t");
                field(&mut out, text.as_bytes());
            }
            DetailValue::Number(number) => {
                field(&mut out, b"n");
                field(&mut out, &number.to_be_bytes());
            }
            DetailValue::Flag(flag) => {
                field(&mut out, b"b");
                field(&mut out, &[u8::from(*flag)]);
            }
            DetailValue::Fingerprint(digest) => {
                field(&mut out, b"f");
                field(&mut out, digest.as_bytes());
            }
        }
    }

    out
}

/// The hash of `event` when it follows `previous`.
#[must_use]
pub fn hash(previous: EventHash, event: &AuditEvent) -> EventHash {
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    hasher.update(canonical_bytes(event));
    EventHash(hasher.finalize().into())
}

/// One stored record: what was written, and the two hashes stored with it.
#[derive(Debug, Clone)]
pub struct Link<'e> {
    /// The event as stored.
    pub event: &'e AuditEvent,
    /// The predecessor hash recorded with it.
    pub previous: EventHash,
    /// The hash recorded with it.
    pub current: EventHash,
}

/// Verifies a contiguous run of records.
///
/// `start` is the hash the first record should follow — [`EventHash::GENESIS`]
/// for a whole tenant, or the hash of the last purged record when retention has
/// trimmed the front (retention breaks the link to the beginning of time, not
/// the links between what remains).
///
/// # Errors
///
/// Returns [`ChainError::Altered`] if a record's contents no longer match its
/// stored hash, or [`ChainError::Broken`] if a record does not follow its
/// predecessor — which is what a deletion or an insertion looks like.
pub fn verify(links: &[Link<'_>], start: EventHash) -> Result<EventHash, ChainError> {
    let mut expected = start;
    for (position, link) in links.iter().enumerate() {
        if link.previous != expected {
            return Err(ChainError::Broken {
                position,
                actual: link.previous,
                expected,
            });
        }
        let recomputed = hash(link.previous, link.event);
        if recomputed != link.current {
            return Err(ChainError::Altered {
                position,
                stored: link.current,
                recomputed,
            });
        }
        expected = link.current;
    }
    Ok(expected)
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Encodes an optional value so that absent and empty are distinguishable.
fn optional(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            field(out, b"1");
            field(out, value.as_bytes());
        }
        None => field(out, b"0"),
    }
}

fn actor(out: &mut Vec<u8>, actor: &Actor) {
    field(out, actor.kind().as_bytes());
    field(out, actor.id().as_bytes());
    match actor {
        Actor::Agent { on_behalf_of, .. } => field(out, on_behalf_of.as_bytes()),
        _ => field(out, b""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Detail, EventType, Outcome};
    use crate::{ClientId, GrantId, TenantId};
    use time::OffsetDateTime;

    fn event(event_type: EventType) -> AuditEvent {
        AuditEvent::new(
            TenantId::new("demo"),
            event_type,
            Outcome::Success,
            Actor::Client(ClientId::new("billing")),
            OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("timestamp"),
        )
        .subject("alice")
        .grant(GrantId::new("g-1"))
        .detail(
            Detail::new()
                .text("scope", "openid profile")
                .number("expires_in", 300),
        )
    }

    fn chain(events: &[AuditEvent]) -> Vec<(EventHash, EventHash)> {
        let mut previous = EventHash::GENESIS;
        events
            .iter()
            .map(|e| {
                let current = hash(previous, e);
                let link = (previous, current);
                previous = current;
                link
            })
            .collect()
    }

    fn links<'e>(events: &'e [AuditEvent], hashes: &[(EventHash, EventHash)]) -> Vec<Link<'e>> {
        events
            .iter()
            .zip(hashes)
            .map(|(event, (previous, current))| Link {
                event,
                previous: *previous,
                current: *current,
            })
            .collect()
    }

    #[test]
    fn hashing_is_deterministic() {
        assert_eq!(
            hash(EventHash::GENESIS, &event(EventType::TOKEN_ISSUED)),
            hash(EventHash::GENESIS, &event(EventType::TOKEN_ISSUED))
        );
    }

    #[test]
    fn any_change_to_any_field_changes_the_hash() {
        let base = event(EventType::TOKEN_ISSUED);
        let baseline = hash(EventHash::GENESIS, &base);

        let mutations: Vec<(&str, AuditEvent)> = vec![
            ("event type", event(EventType::TOKEN_REFUSED)),
            ("outcome", {
                let mut e = base.clone();
                e.outcome = Outcome::Failure;
                e
            }),
            ("subject", base.clone().subject("bob")),
            ("tenant", {
                let mut e = base.clone();
                e.tenant = TenantId::new("other");
                e
            }),
            ("timestamp", {
                let mut e = base.clone();
                e.occurred_at =
                    OffsetDateTime::from_unix_timestamp(1_760_000_001).expect("timestamp");
                e
            }),
            ("actor", {
                let mut e = base.clone();
                e.actor = Actor::Client(ClientId::new("other-client"));
                e
            }),
            ("grant", base.clone().grant(GrantId::new("g-2"))),
            (
                "detail value",
                base.clone().detail(Detail::new().text("scope", "openid")),
            ),
            (
                "detail key",
                base.clone()
                    .detail(Detail::new().text("scopes", "openid profile")),
            ),
        ];

        for (what, mutated) in mutations {
            assert_ne!(
                hash(EventHash::GENESIS, &mutated),
                baseline,
                "changing the {what} did not change the hash"
            );
        }
    }

    /// The reason for length prefixes. Without them, an attacker who controls
    /// two adjacent fields could move the boundary between them and keep the
    /// hash — turning "client `ab`, subject `c`" into "client `a`, subject
    /// `bc`" with no evidence.
    #[test]
    fn adjacent_fields_cannot_be_confused_with_each_other() {
        let base = event(EventType::TOKEN_ISSUED);

        let mut ab_c = base.clone();
        ab_c.client = Some(ClientId::new("ab"));
        ab_c.subject = Some("c".to_owned());

        let mut a_bc = base;
        a_bc.client = Some(ClientId::new("a"));
        a_bc.subject = Some("bc".to_owned());

        assert_ne!(
            canonical_bytes(&ab_c),
            canonical_bytes(&a_bc),
            "a field boundary can be moved without changing the encoding"
        );
    }

    /// Absent and empty are different facts and must hash differently.
    #[test]
    fn an_absent_field_differs_from_an_empty_one() {
        let mut absent = event(EventType::AUTH_LOGIN);
        absent.subject = None;
        let mut empty = absent.clone();
        empty.subject = Some(String::new());
        assert_ne!(
            hash(EventHash::GENESIS, &absent),
            hash(EventHash::GENESIS, &empty)
        );
    }

    #[test]
    fn a_delegation_chain_is_part_of_the_hash() {
        let plain = event(EventType::TOKEN_EXCHANGED);
        let delegated = plain.clone().actor_chain(vec![Actor::Agent {
            client: ClientId::new("scheduler-bot"),
            on_behalf_of: "alice".to_owned(),
        }]);
        assert_ne!(
            hash(EventHash::GENESIS, &plain),
            hash(EventHash::GENESIS, &delegated)
        );
    }

    // ---- verification ----------------------------------------------------

    #[test]
    fn an_untouched_chain_verifies() {
        let events = [
            event(EventType::PAR_ACCEPTED),
            event(EventType::AUTH_LOGIN),
            event(EventType::CONSENT_GRANTED),
            event(EventType::CODE_ISSUED),
            event(EventType::TOKEN_ISSUED),
        ];
        let hashes = chain(&events);
        let tip = verify(&links(&events, &hashes), EventHash::GENESIS).expect("should verify");
        assert_eq!(tip, hashes.last().expect("non-empty").1);
    }

    #[test]
    fn an_empty_range_verifies_to_where_it_started() {
        assert_eq!(
            verify(&[], EventHash::GENESIS).expect("empty"),
            EventHash::GENESIS
        );
    }

    /// The point of the whole module: a row edited in the database is caught.
    #[test]
    fn a_mutated_record_is_detected_and_located() {
        let events = [
            event(EventType::CODE_ISSUED),
            event(EventType::TOKEN_ISSUED),
            event(EventType::GRANT_REVOKED),
        ];
        let hashes = chain(&events);

        // Someone edits the middle record to hide who the token was for.
        let mut tampered = events.clone();
        tampered[1] = tampered[1].clone().subject("mallory");

        let error = verify(&links(&tampered, &hashes), EventHash::GENESIS)
            .expect_err("a mutated record must not verify");
        match error {
            ChainError::Altered { position, .. } => assert_eq!(position, 1),
            other => panic!("expected Altered, got {other}"),
        }
    }

    /// Deleting a record is as much a tampering as editing one — often more.
    #[test]
    fn a_removed_record_breaks_the_chain() {
        let events = [
            event(EventType::CODE_ISSUED),
            event(EventType::TOKEN_ISSUED),
            event(EventType::GRANT_REVOKED),
        ];
        let hashes = chain(&events);

        let kept = [events[0].clone(), events[2].clone()];
        let kept_hashes = [hashes[0], hashes[2]];

        let error = verify(&links(&kept, &kept_hashes), EventHash::GENESIS)
            .expect_err("a deletion must not verify");
        match error {
            ChainError::Broken { position, .. } => assert_eq!(position, 1),
            other => panic!("expected Broken, got {other}"),
        }
    }

    /// Retention trims the front of the chain, so verification has to be able
    /// to start from a known point rather than from the beginning of time.
    #[test]
    fn verification_can_start_from_a_point_other_than_genesis() {
        let events = [
            event(EventType::CODE_ISSUED),
            event(EventType::TOKEN_ISSUED),
            event(EventType::GRANT_REVOKED),
        ];
        let hashes = chain(&events);

        let retained = [events[1].clone(), events[2].clone()];
        let retained_hashes = [hashes[1], hashes[2]];

        // Starting from genesis fails, because the first record is missing.
        assert!(verify(&links(&retained, &retained_hashes), EventHash::GENESIS).is_err());
        // Starting from the last purged record's hash succeeds.
        verify(&links(&retained, &retained_hashes), hashes[0].1).expect("should verify");
    }

    #[test]
    fn hashes_round_trip_through_storage() {
        let value = hash(EventHash::GENESIS, &event(EventType::TOKEN_ISSUED));
        assert_eq!(
            EventHash::from_slice(value.as_bytes()).expect("32 bytes"),
            value
        );
        assert_eq!(value.to_hex().len(), 64);
        assert_eq!(
            EventHash::from_slice(&[0_u8; 31]),
            Err(ChainError::MalformedHash { length: 31 })
        );
    }
}
