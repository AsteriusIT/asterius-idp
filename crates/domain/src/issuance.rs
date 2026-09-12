//! The question asked before an *agent* is minted a token (`ast-lh3.10`).
//!
//! An agent client (`ast-lh3.1`) holds a key and acts for a person who is not
//! there. Its registration already bounds what it may ever ask for — grants,
//! audiences, scopes, `authorization_details` types, delegation depth — and
//! those bounds are static: they were written when the agent was registered and
//! they say nothing about *this* request, *this* audience, or the hour it
//! arrived at. This port is the other half: one policy decision, taken against
//! the tenant's rule document at the instant of issuance, that a token is about
//! to be minted for this agent, for this audience, under this grant.
//!
//! # Why it is a port and not a call into the engine
//!
//! Authorization API 1.0 §2 puts "policy language, architecture, and state
//! management aspects of a PDP" out of scope, and §5 fixes only the shape of
//! the question: a subject, an action, a resource, a context. [`IssuanceQuery`]
//! is that shape, spelled in this server's own vocabulary so that the four
//! issuance paths cannot each invent one, and [`IssuancePolicy`] is the
//! boundary a deployment may put a different decision point behind. The
//! default adapter is this build's own PDP (`ast-pj0.4`), reached through the
//! same decision function the Access Evaluation endpoint and the console's test
//! bench use — a second path to a decision is a second set of answers.
//!
//! # The four parts, and where each one comes from
//!
//! * **Subject** — the agent, named by its `client_id`, with its owner
//!   ([`crate::entities::agent::AgentOwner`]) carried beside it. Both are read
//!   from the registration and neither can be asserted by the request.
//! * **Action** — [`IssuanceAction`]: `obtain_token` for a grant that mints a
//!   fresh token, `exchange_token` for RFC 8693. Two verbs and not four,
//!   because what a rule discriminates on is whether an authority is being
//!   *created* or *passed on*; the grant itself is in the context for a rule
//!   that wants it.
//! * **Resource** — what the token would reach: the audiences it would be
//!   minted at (RFC 8707), the scopes it would carry, and the RFC 9396 §9.2
//!   detail types it would authorize. Taken *after* every static bound has
//!   already narrowed them, so a policy sees what would really be issued and
//!   not what was asked for.
//! * **Context** — the grant type and the delegation chain depth (RFC 8693
//!   §4.1), which is what tells "an agent acting for its owner" from "an agent
//!   acting for an agent acting for its owner".
//!
//! # Fail closed is not this module's decision to take
//!
//! [`IssuancePolicy::permits`] is fallible, for the reason
//! [`crate::ports::PolicyEngine`] is: "the store is unreachable" must not
//! arrive at a caller as "the answer is no", or an operator reading the trail
//! cannot tell a tightened policy from an outage. What to *do* with that error
//! — deny, or issue anyway — is a deployment's posture and lives with the
//! configuration that states it (`[authzen] issuance_fail_open`, default
//! `false`). The port reports; the enforcement point decides and audits.
//!
//! # Threat model
//!
//! A policy that refuses everything blocks every agent in the tenant and no
//! human at all: nothing here is consulted for a client without an
//! [`crate::entities::agent::AgentProfile`], and no user-facing grant reaches
//! it. That asymmetry is deliberate — the failure mode of this feature is
//! "agents stop working", which is visible, recoverable and audited, and never
//! "people cannot sign in".
//!
//! A cached decision is an obsolescence window: a permit taken before an
//! administrator tightened the policy can be reused until it expires. The
//! window is bounded by the adapter's TTL and is the reason the TTL is seconds
//! rather than minutes. Revocation of what was already minted is
//! [`crate::Grant`]'s job and is unaffected.

use crate::entities::agent::AgentOwner;
use crate::entities::client::GrantType;
use crate::error::DomainError;
use crate::ids::{ClientId, TenantId};
use std::collections::BTreeSet;
use std::fmt::Debug;

/// The subject type this server names an agent by, in §5.1's vocabulary.
///
/// Not `user`: an agent is a client, it has no account row, and a rule that
/// matched agents as users would match them against facts (groups, roles,
/// grants) that belong to people.
pub const SUBJECT_TYPE: &str = "agent";

/// The resource type an issuance is about, in §5.4's vocabulary.
///
/// The thing being decided is not the audience and not the scope but the
/// *token that would carry them*, which is why there is one resource type and
/// its attributes are what the token would say.
pub const RESOURCE_TYPE: &str = "token";

/// What an agent is asking to do (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IssuanceAction {
    /// A token is being minted from the agent's own credentials: RFC 6749
    /// §4.4's client credentials, RFC 8628 §3.4's device code, CIBA Core 1.0
    /// §10.1's `auth_req_id`.
    ObtainToken,
    /// An existing token is being exchanged for another (RFC 8693 §2).
    ExchangeToken,
}

impl IssuanceAction {
    /// The §5.2 `name` a rule matches on.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ObtainToken => "obtain_token",
            Self::ExchangeToken => "exchange_token",
        }
    }

    /// Which of the two verbs a grant is.
    ///
    /// Exhaustive on purpose rather than `_ => ObtainToken`: a grant added
    /// later has to be classified by somebody who knows whether it creates an
    /// authority or passes one on.
    #[must_use]
    pub const fn of(grant: GrantType) -> Self {
        match grant {
            GrantType::TokenExchange => Self::ExchangeToken,
            GrantType::AuthorizationCode
            | GrantType::RefreshToken
            | GrantType::ClientCredentials
            | GrantType::DeviceCode
            | GrantType::Ciba => Self::ObtainToken,
        }
    }
}

impl std::fmt::Display for IssuanceAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// One pre-issuance question (§5, §6.1).
///
/// Built once per issuance, from values that have already been narrowed by
/// every static bound: a policy is asked about the token that would actually
/// be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceQuery {
    /// The agent, by the `client_id` it authenticated as.
    pub agent: ClientId,
    /// The principal it acts for.
    pub owner: AgentOwner,
    /// Create an authority, or pass one on.
    pub action: IssuanceAction,
    /// The grant this issuance is (context).
    pub grant: GrantType,
    /// Where the token would be audienced (RFC 8707 §2).
    pub audience: BTreeSet<String>,
    /// What it would carry (RFC 6749 §3.3).
    pub scopes: BTreeSet<String>,
    /// The RFC 9396 §9.2 `type` values it would authorize.
    pub authorization_details_types: BTreeSet<String>,
    /// How many actors deep the delegation would be (RFC 8693 §4.1).
    ///
    /// One for an agent acting for its owner with no `act` chain behind it.
    pub chain_depth: u8,
}

impl IssuanceQuery {
    /// The key a decision may be cached under.
    ///
    /// Every part of the question, not the subject/action/resource triple
    /// alone: the grant and the chain depth are things a rule may match on, so
    /// a key that omitted them would serve a decision taken about a *different*
    /// request. Tenant-scoped by the caller, which holds one cache per process
    /// and many tenants.
    ///
    /// Unambiguous by construction: every part is length-prefixed, so no two
    /// different questions can spell the same key by moving a separator into a
    /// scope name.
    #[must_use]
    pub fn cache_key(&self) -> String {
        let mut key = String::new();
        let mut push = |part: &str| {
            key.push_str(&part.len().to_string());
            key.push(':');
            key.push_str(part);
            key.push('|');
        };
        push(self.agent.as_str());
        push(&self.owner.to_string());
        push(self.action.name());
        push(self.grant.as_str());
        for audience in &self.audience {
            push(audience);
        }
        push("");
        for scope in &self.scopes {
            push(scope);
        }
        push("");
        for kind in &self.authorization_details_types {
            push(kind);
        }
        push("");
        push(&self.chain_depth.to_string());
        key
    }
}

/// What a policy decision point answered about one issuance.
///
/// Deliberately not [`crate::policy::Decision`]: that type is the wire shape of
/// §6.2's response and carries an `acr` ladder and a user-facing reason that an
/// agent's token request has nowhere to put. What an issuance needs is the
/// verdict and the administrator's reason, because the client is told
/// `access_denied` and nothing else (RFC 6749 §5.2) and the whole explanation
/// has to be in the trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceDecision {
    permit: bool,
    reason_admin: Option<String>,
}

impl IssuanceDecision {
    /// A permit, with the reason the decision point gave.
    #[must_use]
    pub const fn permit(reason_admin: Option<String>) -> Self {
        Self {
            permit: true,
            reason_admin,
        }
    }

    /// A deny, with the reason the decision point gave.
    #[must_use]
    pub const fn deny(reason_admin: Option<String>) -> Self {
        Self {
            permit: false,
            reason_admin,
        }
    }

    /// Whether the token may be minted.
    #[must_use]
    pub const fn permitted(&self) -> bool {
        self.permit
    }

    /// Why, in the words the decision point used, for the trail's
    /// `reason_admin`.
    ///
    /// Never rendered to the client: a refusal reason is a statement about the
    /// tenant's rules, and RFC 6749 §5.2's `error_description` reaches whoever
    /// holds the agent's key.
    #[must_use]
    pub fn reason_admin(&self) -> Option<&str> {
        self.reason_admin.as_deref()
    }
}

/// The decision point consulted before an agent's token is minted.
///
/// # Errors
///
/// See [`Self::permits`]. An implementation reports an outage as an error and
/// never as a deny.
#[async_trait::async_trait]
pub trait IssuancePolicy: Debug + Send + Sync {
    /// Decides one issuance.
    ///
    /// # Errors
    ///
    /// [`DomainError`] when the decision could not be *taken* — the policy
    /// could not be loaded, an external decision point did not answer. Never
    /// for an issuance that is simply refused: that is an
    /// [`IssuanceDecision`] whose [`IssuanceDecision::permitted`] is false.
    async fn permits(
        &self,
        tenant: &TenantId,
        query: &IssuanceQuery,
    ) -> Result<IssuanceDecision, DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::user::UserId;

    fn query() -> IssuanceQuery {
        IssuanceQuery {
            agent: ClientId::new("c.agent".to_owned()),
            owner: AgentOwner::User(UserId::new(uuid::Uuid::nil())),
            action: IssuanceAction::ObtainToken,
            grant: GrantType::ClientCredentials,
            audience: BTreeSet::from(["https://api.example".to_owned()]),
            scopes: BTreeSet::from(["read".to_owned()]),
            authorization_details_types: BTreeSet::new(),
            chain_depth: 1,
        }
    }

    #[test]
    fn exchange_is_the_only_grant_that_passes_an_authority_on() {
        assert_eq!(
            IssuanceAction::of(GrantType::TokenExchange),
            IssuanceAction::ExchangeToken
        );
        for grant in [
            GrantType::ClientCredentials,
            GrantType::DeviceCode,
            GrantType::Ciba,
        ] {
            assert_eq!(IssuanceAction::of(grant), IssuanceAction::ObtainToken);
        }
    }

    #[test]
    fn action_names_are_the_two_the_ticket_fixes() {
        assert_eq!(IssuanceAction::ObtainToken.name(), "obtain_token");
        assert_eq!(IssuanceAction::ExchangeToken.name(), "exchange_token");
    }

    #[test]
    fn the_same_question_has_the_same_cache_key() {
        assert_eq!(query().cache_key(), query().cache_key());
    }

    #[test]
    fn a_different_audience_is_a_different_cache_key() {
        let mut other = query();
        other.audience = BTreeSet::from(["https://other.example".to_owned()]);

        assert_ne!(query().cache_key(), other.cache_key());
    }

    #[test]
    fn a_deeper_chain_is_a_different_cache_key() {
        let mut other = query();
        other.chain_depth = 2;

        assert_ne!(query().cache_key(), other.cache_key());
    }

    #[test]
    fn a_scope_that_looks_like_two_is_not_two() {
        let mut one = query();
        one.scopes = BTreeSet::from(["read write".to_owned()]);
        let mut two = query();
        two.scopes = BTreeSet::from(["read".to_owned(), "write".to_owned()]);

        assert_ne!(one.cache_key(), two.cache_key());
    }

    #[test]
    fn a_scope_moved_into_the_audience_is_a_different_question() {
        let mut moved = query();
        moved.audience = BTreeSet::from(["https://api.example".to_owned(), "read".to_owned()]);
        moved.scopes = BTreeSet::new();

        assert_ne!(query().cache_key(), moved.cache_key());
    }

    #[test]
    fn a_decision_carries_the_administrator_s_reason() {
        let denied = IssuanceDecision::deny(Some("rule agents-read denied".to_owned()));

        assert!(!denied.permitted());
        assert_eq!(denied.reason_admin(), Some("rule agents-read denied"));
    }
}
