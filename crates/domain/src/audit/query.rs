//! Reading the trail back, one filtered page at a time (`ast-lh3.9`).
//!
//! The trail is written by every endpoint and read by two things: the chain
//! verifier, which reads all of it in order, and an operator asking a
//! question. This module is the second reader's port. The questions it
//! answers are the ones an incident asks of an agent — *what did agent A do*,
//! *what was done for user U by anybody*, *what came out of grant G* — over a
//! window, by type, newest first, a page at a time.
//!
//! # The filter is the specification
//!
//! [`AuditFilter::matches`] is the reference semantics of every filter. A
//! storage adapter translates it into whatever index it has, and the test
//! that keeps the two honest seeds a trail, queries it through the adapter,
//! and checks the result against a scan through `matches`. An in-memory fake
//! uses `matches` directly, so a handler test and a database test are asking
//! the same question.
//!
//! # What a page is
//!
//! Keyset, on the record's position in the tenant's chain: the storage id is
//! monotonic per tenant, so "the next page" is "ids below the last one seen"
//! and a record written while an operator pages through cannot shift a row
//! out from under them. There is no offset and no count, for the reasons
//! `asterius_admin_api::pagination` gives.

use super::record::AuditRecord;
use super::{AuditEvent, EventHash, EventType};
use crate::{ClientId, DomainError, GrantId, TenantId};
use time::OffsetDateTime;

/// The most records one export may produce.
///
/// A ceiling on what a read scope is worth: an export is exfiltration with
/// a purpose, and a purpose that needs more than this has a database client
/// and a change-control record. See `docs/threat-model.md`, "Audit query
/// API and export".
pub const EXPORT_MAX_RECORDS: usize = 100_000;

/// The most records one storage read returns, whatever the caller asks for.
///
/// An export walks pages of this size; a listing asks for fewer. It is the
/// unit of memory one request can make the server hold, not a suggestion.
pub const MAX_PAGE: u32 = 1_000;

/// What an operator is asking for. Every member is optional and they are
/// conjunctive: a record matches when it satisfies all of the ones set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    /// Records an agent took part in: as the actor, or as any link of the
    /// delegation chain ([`AuditEvent::agents_involved`]).
    pub agent: Option<ClientId>,
    /// Records made by an agent acting for this subject
    /// ([`AuditEvent::agent_owner`]).
    pub owner: Option<String>,
    /// Records made under this subject, as its subject or through an agent
    /// they own ([`AuditEvent::concerns_user`]).
    pub user: Option<String>,
    /// Records naming this grant.
    pub grant: Option<GrantId>,
    /// Records of any of these types. Empty means every type.
    pub event_types: Vec<EventType>,
    /// Records at or after this instant.
    pub from: Option<OffsetDateTime>,
    /// Records strictly before this instant.
    pub until: Option<OffsetDateTime>,
}

impl AuditFilter {
    /// Whether nothing was asked for, which is "the whole trail".
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The reference semantics: whether `event` satisfies every member set.
    #[must_use]
    pub fn matches(&self, event: &AuditEvent) -> bool {
        if let Some(agent) = &self.agent
            && !event.agents_involved().any(|id| id == agent.as_str())
        {
            return false;
        }
        if let Some(owner) = &self.owner
            && event.agent_owner() != Some(owner.as_str())
        {
            return false;
        }
        if let Some(user) = &self.user
            && !event.concerns_user(user)
        {
            return false;
        }
        if let Some(grant) = &self.grant
            && event.grant.as_ref() != Some(grant)
        {
            return false;
        }
        if !self.event_types.is_empty() && !self.event_types.contains(&event.event_type) {
            return false;
        }
        if let Some(from) = self.from
            && event.occurred_at < from
        {
            return false;
        }
        if let Some(until) = self.until
            && event.occurred_at >= until
        {
            return false;
        }
        true
    }
}

/// One record as the query port hands it back: the record, where it sits in
/// the tenant's chain, and the hash it was stored with.
///
/// The hash is on every entry and not only on the opaque ones: an export is
/// evidence, and a line of evidence that names its own hash can be checked
/// against the chain later by whoever holds the export and the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailEntry {
    /// The record's position in the tenant's chain: the storage identity, and
    /// the key a page resumes from.
    pub id: i64,
    /// The hash stored with the record.
    pub hash: EventHash,
    /// The record, readable or opaque.
    pub record: AuditRecord,
}

/// Where the trail is read from.
///
/// Read-only by construction — there is no method on this port that writes —
/// so the admin route that holds it cannot be turned into one that appends.
#[async_trait::async_trait]
pub trait AuditQuery: std::fmt::Debug + Send + Sync {
    /// The records of `tenant` matching `filter`, newest first.
    ///
    /// `before` is the id of the last record already seen, or `None` for the
    /// newest page. At most `limit` records are returned, and never more than
    /// [`MAX_PAGE`] whatever `limit` says.
    ///
    /// A record this build cannot read comes back as
    /// [`AuditRecord::Opaque`] and is counted against the limit like any
    /// other: it is a record, and a page that silently dropped it would be
    /// an export that silently lost evidence.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the trail cannot be read.
    async fn query(
        &self,
        tenant: &TenantId,
        filter: &AuditFilter,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<TrailEntry>, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Actor, Outcome};
    use time::Duration;

    fn at(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(seconds)
    }

    fn agent(id: &str, owner: &str) -> Actor {
        Actor::Agent {
            client: ClientId::new(id),
            on_behalf_of: owner.to_owned(),
        }
    }

    fn event(event_type: EventType, actor: Actor, seconds: i64) -> AuditEvent {
        AuditEvent::new(
            TenantId::new("demo"),
            event_type,
            Outcome::Success,
            actor,
            at(seconds),
        )
    }

    /// The `ast-lh3.9` chain: user alice → agent A → agent B. What each
    /// token endpoint writes, as it writes it.
    fn chain() -> Vec<AuditEvent> {
        vec![
            // A obtains its own token, as alice's agent.
            event(EventType::TOKEN_ISSUED, agent("c.a", "alice"), 10)
                .grant(GrantId::new("11111111-1111-1111-1111-111111111111")),
            // B exchanges A's token: B acts, A is the chain, alice is the subject.
            event(EventType::TOKEN_EXCHANGED, agent("c.b", "bob"), 20)
                .subject("alice")
                .actor_chain(vec![Actor::Client(ClientId::new("c.a"))])
                .grant(GrantId::new("22222222-2222-2222-2222-222222222222")),
            // Somebody else entirely.
            event(EventType::TOKEN_ISSUED, agent("c.c", "carol"), 30),
            event(EventType::AUTH_LOGIN, Actor::User("alice".to_owned()), 40).subject("alice"),
        ]
    }

    fn select(filter: &AuditFilter) -> Vec<EventType> {
        chain()
            .into_iter()
            .filter(|event| filter.matches(event))
            .map(|event| event.event_type)
            .collect()
    }

    #[test]
    fn an_empty_filter_matches_everything() {
        // Arrange
        let filter = AuditFilter::default();

        // Act / Assert
        assert!(filter.is_empty());
        assert_eq!(select(&filter).len(), chain().len());
    }

    /// The acceptance criterion: everything done under alice is the issuance
    /// to A, the exchange by B, and her own login — not carol's agent.
    #[test]
    fn everything_done_under_a_user_spans_the_whole_delegation_chain() {
        // Arrange
        let filter = AuditFilter {
            user: Some("alice".to_owned()),
            ..AuditFilter::default()
        };

        // Act
        let found = select(&filter);

        // Assert
        assert_eq!(
            found,
            vec![
                EventType::TOKEN_ISSUED,
                EventType::TOKEN_EXCHANGED,
                EventType::AUTH_LOGIN
            ]
        );
    }

    /// RFC 8693 §4.1: A is a link in B's exchange, so "what did A take part
    /// in" includes the exchange it did not itself perform.
    #[test]
    fn an_agent_is_found_through_the_act_chain() {
        // Arrange
        let filter = AuditFilter {
            agent: Some(ClientId::new("c.a")),
            ..AuditFilter::default()
        };

        // Act / Assert
        assert_eq!(
            select(&filter),
            vec![EventType::TOKEN_ISSUED, EventType::TOKEN_EXCHANGED]
        );
    }

    #[test]
    fn an_owner_filter_names_the_agents_answerable_to_a_person() {
        // Arrange
        let filter = AuditFilter {
            owner: Some("bob".to_owned()),
            ..AuditFilter::default()
        };

        // Act / Assert
        assert_eq!(select(&filter), vec![EventType::TOKEN_EXCHANGED]);
    }

    #[test]
    fn a_grant_filter_finds_what_came_out_of_one_authorization() {
        // Arrange
        let filter = AuditFilter {
            grant: Some(GrantId::new("22222222-2222-2222-2222-222222222222")),
            ..AuditFilter::default()
        };

        // Act / Assert
        assert_eq!(select(&filter), vec![EventType::TOKEN_EXCHANGED]);
    }

    #[test]
    fn a_type_list_is_a_union_and_an_empty_one_is_every_type() {
        // Arrange
        let two = AuditFilter {
            event_types: vec![EventType::AUTH_LOGIN, EventType::TOKEN_EXCHANGED],
            ..AuditFilter::default()
        };

        // Act / Assert
        assert_eq!(
            select(&two),
            vec![EventType::TOKEN_EXCHANGED, EventType::AUTH_LOGIN]
        );
    }

    /// `from` is inclusive and `until` exclusive, so consecutive windows tile
    /// the trail without a record falling into both or neither.
    #[test]
    fn the_time_window_is_half_open() {
        // Arrange
        let window = AuditFilter {
            from: Some(at(20)),
            until: Some(at(30)),
            ..AuditFilter::default()
        };

        // Act / Assert
        assert_eq!(select(&window), vec![EventType::TOKEN_EXCHANGED]);
    }

    /// Conjunctive: an agent filter and a type filter together narrow to the
    /// intersection.
    #[test]
    fn filters_combine_by_intersection() {
        // Arrange
        let filter = AuditFilter {
            agent: Some(ClientId::new("c.a")),
            event_types: vec![EventType::TOKEN_EXCHANGED],
            ..AuditFilter::default()
        };

        // Act / Assert
        assert_eq!(select(&filter), vec![EventType::TOKEN_EXCHANGED]);
    }
}
