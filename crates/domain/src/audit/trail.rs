//! The per-agent view of a record (`ast-lh3.9`).
//!
//! An agent's actions are attributable only if every record it leaves names
//! the agent *and* the human answerable for it, and links the two to the
//! authorization they were performed under. The trail already carries most of
//! that — [`Actor::Agent`] names both principals, `actor_chain` is the RFC 8693
//! §4.1 `act` chain outermost first, and `grant` is the FAPI 2.0 SP §6.8 item 4
//! link — but it carried it in three different places under three different
//! names, and a query that had to know all three was a query that would get
//! one of them wrong.
//!
//! So this module is the one place the vocabulary is written down:
//!
//! * [`AuditEvent::agent_id`] and [`AuditEvent::agent_owner`] read the agent
//!   and its owner out of whichever field the writer put them in.
//! * The `keys` constants name the detail entries the token endpoints write
//!   for an agent — the resource the token was audienced at, the
//!   `authorization_details` it carried, the CIBA or device approval it was
//!   minted from — so that a writer and the query API spell them identically.
//!
//! None of it changes the stored form or the hash chain. A new *field* on
//! [`AuditEvent`] would change [`super::chain::canonical_bytes`] and turn every
//! record written before it into a tampering report; a detail entry is
//! hashed the day it is written and absent from the records that predate it.

use super::{Actor, AuditEvent, DetailValue};

/// The detail keys the agent trail is read through.
///
/// Every value written under one of these must be *searchable* rather than
/// legible: an identifier, a space-separated set of identifiers, or a
/// fingerprint. Nothing under these keys is prose.
pub mod keys {
    /// The subject the agent acts for, as `client_credentials` and token
    /// exchange record it beside the [`super::Actor::Agent`] that already
    /// carries it. Kept in both places on purpose: the actor is what a query
    /// filters on, the detail is what an export renders without a reader
    /// having to know the actor's shape.
    pub const AGENT_OWNER: &str = "agent_owner";
    /// The RFC 8707 resources the issued token was audienced at, space
    /// separated and sorted. An agent that reached a resource it should not
    /// have is found by this entry.
    pub const RESOURCE: &str = "resource";
    /// The RFC 9396 `authorization_details` the token carried, summarised
    /// by [`super::authorization_details_summary`]: the `type` of each
    /// entry, sorted, unique, space separated — never the entries themselves,
    /// which carry the account numbers and amounts the trail must not.
    pub const AUTHORIZATION_DETAILS: &str = "authorization_details";
    /// The CIBA `auth_req_id` or device `device_code` an issuance was
    /// approved through, as a fingerprint. Two events naming the same
    /// approval get the same digest, and the credential cannot be read back.
    pub const APPROVAL_ID: &str = "approval_id";
    /// `delegation` or `impersonation` (RFC 8693 §5), written by token
    /// exchange for the one case the token itself does not say.
    pub const DELEGATION: &str = "delegation";
}

impl AuditEvent {
    /// The agent this record is about, if an agent caused it.
    ///
    /// `None` for a user, a plain client, an administrator or the server
    /// itself: an agent is a *kind* of actor, and reading a `client_id` out
    /// of a non-agent actor would be the confusion FAPI 2.0 SP §6.7 warns
    /// about.
    #[must_use]
    pub fn agent_id(&self) -> Option<&str> {
        match &self.actor {
            Actor::Agent { client, .. } => Some(client.as_str()),
            _ => None,
        }
    }

    /// The human the agent that caused this record acts for.
    ///
    /// Read from the actor first, and from the [`keys::AGENT_OWNER`] detail
    /// when the actor is not an agent — a record written for an agent by a
    /// path that recorded it as a plain client still names its owner there.
    #[must_use]
    pub fn agent_owner(&self) -> Option<&str> {
        if let Actor::Agent { on_behalf_of, .. } = &self.actor {
            return Some(on_behalf_of);
        }
        self.detail
            .iter()
            .find(|(key, _)| key.as_str() == keys::AGENT_OWNER)
            .and_then(|(_, value)| match value {
                DetailValue::Text(owner) => Some(owner.as_str()),
                _ => None,
            })
    }

    /// Every agent named by this record: the actor when it is one, and each
    /// link of the delegation chain.
    ///
    /// The chain links are recorded as [`Actor::Client`] by token exchange,
    /// because a link is a `client_id` read out of an `act` claim and the
    /// registration behind it may since have changed; a query for "everything
    /// agent A took part in" must still find a record where A is a link, so
    /// the links are included whatever their kind.
    pub fn agents_involved(&self) -> impl Iterator<Item = &str> {
        self.agent_id()
            .into_iter()
            .chain(self.actor_chain.iter().filter_map(|link| match link {
                Actor::Client(id) | Actor::Agent { client: id, .. } => Some(id.as_str()),
                Actor::User(_) | Actor::Admin(_) | Actor::System => None,
            }))
    }

    /// Whether this record was made under `user`: as its subject, or by an
    /// agent acting for them.
    ///
    /// The acceptance question of `ast-lh3.9` — "everything that was done
    /// under U" — has to find the issuance to agent A (no subject; the owner
    /// is U) and the exchange by agent B (subject U; B's owner may be somebody
    /// else) with one predicate, and this is it.
    #[must_use]
    pub fn concerns_user(&self, user: &str) -> bool {
        self.subject.as_deref() == Some(user) || self.agent_owner() == Some(user)
    }
}

/// The [`keys::AUTHORIZATION_DETAILS`] entry for a set of RFC 9396 details.
///
/// The `type` of each entry, sorted and de-duplicated, joined by one space.
/// Nothing else: an `authorization_details` entry carries what the person
/// authorised — an account, an amount, a payee — and that is the content of
/// a payment, not of an audit record kept for years. An entry with no string
/// `type` contributes nothing, and an empty result is `None` so a writer can
/// leave the key out.
#[must_use]
pub fn authorization_details_summary(details: &[serde_json::Value]) -> Option<String> {
    let types: std::collections::BTreeSet<&str> = details
        .iter()
        .filter_map(|entry| entry.get("type").and_then(serde_json::Value::as_str))
        .filter(|kind| !kind.is_empty())
        .collect();
    if types.is_empty() {
        return None;
    }
    Some(types.into_iter().collect::<Vec<_>>().join(" "))
}

/// The [`keys::RESOURCE`] entry for a set of RFC 8707 resources: sorted and
/// joined by one space, or `None` when there are none.
#[must_use]
pub fn resource_summary<'a>(resources: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let sorted: std::collections::BTreeSet<&str> = resources.into_iter().collect();
    if sorted.is_empty() {
        return None;
    }
    Some(sorted.into_iter().collect::<Vec<_>>().join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Detail, EventType, Outcome};
    use crate::{ClientId, TenantId};
    use serde_json::json;
    use time::OffsetDateTime;

    fn event(actor: Actor) -> AuditEvent {
        AuditEvent::new(
            TenantId::new("demo"),
            EventType::TOKEN_ISSUED,
            Outcome::Success,
            actor,
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    fn agent(id: &str, owner: &str) -> Actor {
        Actor::Agent {
            client: ClientId::new(id),
            on_behalf_of: owner.to_owned(),
        }
    }

    #[test]
    fn an_agent_actor_names_the_agent_and_its_owner() {
        // Arrange
        let issued = event(agent("c.a", "alice"));

        // Act / Assert
        assert_eq!(issued.agent_id(), Some("c.a"));
        assert_eq!(issued.agent_owner(), Some("alice"));
    }

    /// FAPI 2.0 SP §6.7: a client id is never read as a person, and a plain
    /// client is never read as an agent.
    #[test]
    fn a_plain_client_is_not_an_agent() {
        // Arrange
        let issued = event(Actor::Client(ClientId::new("billing")));

        // Act / Assert
        assert_eq!(issued.agent_id(), None);
        assert_eq!(issued.agent_owner(), None);
    }

    /// A record written with a plain-client actor but an `agent_owner` detail
    /// still answers "who is answerable", from the detail.
    #[test]
    fn the_owner_falls_back_to_the_detail_entry() {
        // Arrange
        let issued = event(Actor::Client(ClientId::new("c.a")))
            .detail(Detail::new().text(keys::AGENT_OWNER, "alice"));

        // Act / Assert
        assert_eq!(issued.agent_owner(), Some("alice"));
        assert_eq!(issued.agent_id(), None, "a client is still not an agent");
    }

    /// The RFC 8693 §4.1 chain, outermost first: an exchange by B of a token
    /// minted for A involves both, and A is found through the chain even
    /// though the link is recorded as a client.
    #[test]
    fn every_link_of_the_act_chain_is_an_agent_involved() {
        // Arrange
        let exchanged = event(agent("c.b", "bob")).actor_chain(vec![
            Actor::Client(ClientId::new("c.a")),
            Actor::User("alice".to_owned()),
        ]);

        // Act
        let involved: Vec<&str> = exchanged.agents_involved().collect();

        // Assert
        assert_eq!(involved, vec!["c.b", "c.a"]);
    }

    /// The `ast-lh3.9` acceptance question, on the two shapes the token
    /// endpoints write: the issuance to A (owner alice, no subject) and the
    /// exchange by B (subject alice, owner bob) are both "under alice".
    #[test]
    fn everything_done_under_a_user_covers_owner_and_subject() {
        // Arrange
        let issued_to_a = event(agent("c.a", "alice"));
        let exchanged_by_b = event(agent("c.b", "bob")).subject("alice");
        let somebody_else = event(agent("c.c", "carol")).subject("dave");

        // Act / Assert
        assert!(issued_to_a.concerns_user("alice"));
        assert!(exchanged_by_b.concerns_user("alice"));
        assert!(exchanged_by_b.concerns_user("bob"));
        assert!(!somebody_else.concerns_user("alice"));
    }

    /// RFC 9396 §2: the summary is the types and never the content.
    #[test]
    fn an_authorization_details_summary_names_types_and_nothing_else() {
        // Arrange
        let details = vec![
            json!({"type": "payment_initiation", "instructedAmount": {"amount": "250"}, "creditorAccount": {"iban": "DE02100100109307118603"}}),
            json!({"type": "account_information", "actions": ["list_accounts"]}),
            json!({"type": "payment_initiation"}),
            json!({"not_a_type": 1}),
        ];

        // Act
        let summary = authorization_details_summary(&details).expect("a summary");

        // Assert
        assert_eq!(summary, "account_information payment_initiation");
        assert!(
            !summary.contains("DE02"),
            "an account number reached the trail"
        );
    }

    #[test]
    fn no_typed_details_means_no_summary_at_all() {
        assert_eq!(authorization_details_summary(&[]), None);
        assert_eq!(
            authorization_details_summary(&[json!({"type": ""}), json!(7)]),
            None
        );
    }

    #[test]
    fn a_resource_summary_is_sorted_and_deduplicated() {
        // Arrange
        let resources = [
            "https://b.example/",
            "https://a.example/",
            "https://b.example/",
        ];

        // Act / Assert
        assert_eq!(
            resource_summary(resources).as_deref(),
            Some("https://a.example/ https://b.example/")
        );
        assert_eq!(resource_summary([]), None);
    }
}
