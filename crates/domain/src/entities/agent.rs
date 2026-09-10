//! Agent clients: a client that acts for a human owner (`E11`, `ast-lh3.1`).
//!
//! An ordinary confidential client acts for itself. An agent acts *for
//! somebody* — a human who provisioned it and who answers for what it does —
//! and that relationship is a new one for this server: RFC 8693 §5 calls it
//! delegation and warns that a delegated credential is only as bounded as the
//! policy attached to it. This module is that policy, as data.
//!
//! # Two halves, on purpose
//!
//! * [`AgentLimits`] is what the *tenant* decided: which grants an agent may
//!   use, which audiences and scopes it may name, which `authorization_details`
//!   types it may ask for, how long its tokens live, how deep a delegation
//!   chain may go, and which scopes a human must approve before an agent may
//!   hold them. It comes from the tenant's registration policy preset
//!   (`ast-m9c.6`), never from the registering client — a client that could
//!   write its own limits has no limits.
//! * [`AgentOwner`] is what the *registration* declared: the account the agent
//!   acts for.
//!
//! [`AgentProfile`] is the pair, and it is what is stored on the client row and
//! read back on every issuance.
//!
//! # The owner is a user, and only a user
//!
//! An owner is a [`UserId`]: a row in `users`, in this tenant. Organisations
//! are not an entity in this server — there is no table, no membership and no
//! administrator of one — so an owner cannot be an org today, and inventing a
//! free-text "org" field would be a delegation to a principal nobody can
//! authenticate or revoke. The identifier is the tenant-local account id and
//! deliberately **not** a `sub`: a pairwise `sub` means something only to the
//! client that received it, so an owner named that way would be a different
//! owner depending on who was reading.
//!
//! An owner that goes away takes the agent with it. The store enforces it (the
//! `clients_disable_ownerless_agent` trigger of migration `0019`) because a
//! deletion is a database event and the domain is not there to see it; what the
//! domain states is the rule: an agent with no owner is nobody's agent.
//!
//! # What is stored and not yet enforced — say so
//!
//! [`AgentLimits::max_delegation_depth`] and the `token-exchange` and `ciba`
//! grants are **stored and validated, and applied to nothing**. Token exchange
//! (`ast-lh3.2`) and CIBA do not exist in this build, so there is no chain to
//! measure and no request to refuse. They are here because they are the
//! contract `ast-lh3.2` will read on the day it lands, and because a profile
//! written now must not have to be rewritten then. A reader who wants to know
//! what is *in force* today should read [`AgentProfile::cap`] (token lifetimes),
//! [`AgentLimits::check`] (registration) and
//! [`AgentProfile::scope_needing_human_approval`] (issuance) — those three, and
//! nothing else.
//!
//! `ast-5c6` and `ast-cu3` both say a setting with no effect is worse than an
//! absent one. The rule stands; the exception is bounded and documented here
//! rather than left for somebody to discover.
//!
//! # Threat model, in short
//!
//! A delegated credential adds three ways to be wrong that a client credential
//! does not have.
//!
//! 1. **Confusion of principals.** A token minted for an agent must never be
//!    mistaken for a token minted for its owner. FAPI 2.0 SP §6.7 names the
//!    concrete form: a `client_id` that could pass for a subject identifier.
//!    [`crate::ClientId::mint`] answers it — the prefix `c.` cannot occur in
//!    either spelling of a `sub` this server issues — and
//!    [`crate::ClientId::MINTED_PREFIX`] is where that argument lives.
//! 2. **Unbounded delegation.** An agent that may mint further delegations is
//!    an agent whose blast radius is whatever the next hop decides.
//!    [`AgentLimits::max_delegation_depth`] is the bound; see above for what it
//!    does today.
//! 3. **Silent escalation.** An agent asking for a scope no human ever agreed
//!    to is the whole risk of the pattern, and it does not announce itself.
//!    [`AgentLimits::human_approval_scopes`] marks those scopes, and a grant
//!    with no human in it — `client_credentials` — is refused them outright.

use crate::entities::client::{ClientMetadataError, ClientRegistration, GrantType};
use crate::entities::tenant_settings::{MAX_ACCESS_TOKEN_LIFETIME, MIN_LIFETIME, TokenLifetimes};
use crate::entities::user::UserId;
use serde_json::Value;
use std::collections::BTreeSet;
use thiserror::Error;
use time::Duration;
use uuid::Uuid;

/// The most entries any one allow-list in an agent profile may hold.
///
/// The same bound [`crate::RegistrationPolicy`] uses, for the same reason: the
/// document is written by an administrator and read on every issuance.
pub const MAX_LIST_ENTRIES: usize = 64;

/// The longest single entry — a scope, an audience, a detail type.
pub const MAX_ENTRY_LEN: usize = 256;

/// The largest stored agent profile this server will read.
pub const MAX_PROFILE_BYTES: usize = 16 * 1024;

/// The deepest delegation chain a tenant may configure.
///
/// Eight is not a considered ergonomic figure, it is a ceiling: nobody has a
/// legitimate chain this long, and the value exists so that a typo in a policy
/// document cannot express "unbounded".
pub const MAX_DELEGATION_DEPTH: u8 = 8;

/// The delegation depth an agent gets when the tenant said nothing: one.
///
/// One hop — the owner to the agent — and no further. A default of anything
/// else would mean a tenant that never thought about delegation had
/// nevertheless permitted it.
pub const DEFAULT_MAX_DELEGATION_DEPTH: u8 = 1;

/// The grants an agent may ever be registered for.
///
/// Everything that reaches the authorization endpoint is absent, and that is
/// the definition rather than a restriction: an agent has no browser and no
/// user at the keyboard, so `authorization_code` is a grant it cannot complete.
/// `refresh_token` is absent too — a refresh token is a long-lived credential
/// held by a process nobody is watching, and an agent that needs a new token
/// can authenticate again with the key it already has.
pub const AGENT_GRANT_TYPES: [GrantType; 4] = [
    GrantType::ClientCredentials,
    GrantType::TokenExchange,
    GrantType::DeviceCode,
    GrantType::Ciba,
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A stored agent profile this server did not write or would not have accepted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AgentProfileError {
    /// The schema in this build does not parse. A bug here, never in the data.
    #[error("the agent profile schema is unusable")]
    SchemaUnusable,
    /// The document is not the shape the schema describes.
    #[error("the stored agent profile does not match its schema")]
    SchemaRejected,
    /// The document is larger than [`MAX_PROFILE_BYTES`].
    #[error("the stored agent profile is too large")]
    TooLarge,
    /// `owner` is absent, or is not a UUID naming a user of this tenant.
    #[error("the stored agent profile does not name a user as its owner")]
    OwnerNotAUser,
    /// A grant type outside [`AGENT_GRANT_TYPES`], or one no build knows.
    #[error("the stored agent profile names a grant type an agent may not use")]
    UnusableGrantType,
    /// `max_delegation_depth` is zero or above [`MAX_DELEGATION_DEPTH`].
    #[error("the stored agent profile names an unusable delegation depth")]
    UnusableDelegationDepth,
    /// A lifetime cap at or below zero, or above the profile's own ceiling.
    #[error("the stored agent profile names an unusable {0}")]
    UnusableLifetime(&'static str),
}

// ---------------------------------------------------------------------------
// The owner
// ---------------------------------------------------------------------------

/// The principal an agent acts for.
///
/// One variant, and a type rather than a bare [`UserId`], because the day an
/// organisation becomes an entity here this is the one place that has to
/// change — and because a function taking an `AgentOwner` cannot be handed the
/// wrong kind of identifier by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgentOwner {
    /// A user account in the same tenant as the agent.
    User(UserId),
}

impl AgentOwner {
    /// The owning account.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        match self {
            Self::User(id) => id,
        }
    }

    /// Reads an owner from the `agent_owner` registration member.
    ///
    /// A UUID and nothing else. A username would be a second spelling of an
    /// account that can be renamed, and a `sub` is meaningless outside the
    /// client that received it (see the module documentation).
    ///
    /// # Errors
    ///
    /// [`ClientMetadataError::Rejected`] — `invalid_client_metadata` — for
    /// anything that is not a UUID. The value is never echoed.
    pub fn parse(raw: &str) -> Result<Self, ClientMetadataError> {
        Uuid::parse_str(raw)
            .map(|id| Self::User(UserId::new(id)))
            .map_err(|_| ClientMetadataError::Rejected {
                field: "agent_owner",
                reason: "must be the UUID of a user account in this tenant".to_owned(),
            })
    }
}

impl std::fmt::Display for AgentOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User(id) => std::fmt::Display::fmt(id, f),
        }
    }
}

// ---------------------------------------------------------------------------
// The limits
// ---------------------------------------------------------------------------

/// What a tenant permits its agents, independent of any one agent.
///
/// `None` on a list means "the tenant said nothing", which is the same shape
/// [`crate::RegistrationPolicy`] uses and means the same thing: no *additional*
/// bound. It never means "everything" — the registration's own allow-lists
/// (`ast-gxh.7` for resources, `ast-gxh.6` for `authorization_details` types)
/// still apply, and this narrows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLimits {
    grant_types: BTreeSet<GrantType>,
    audiences: Option<BTreeSet<String>>,
    scopes: Option<BTreeSet<String>>,
    authorization_details_types: Option<BTreeSet<String>>,
    max_delegation_depth: u8,
    access_token_ttl_cap: Option<Duration>,
    human_approval_scopes: BTreeSet<String>,
    human_approval_authorization_details_types: BTreeSet<String>,
}

impl Default for AgentLimits {
    /// The preset an `agent` tenant policy creates agents with.
    ///
    /// `client_credentials` alone, one hop of delegation, and no additional
    /// allow-list. It is the narrowest profile that still produces a usable
    /// agent: a tenant that wants token exchange or a device-code agent says
    /// so, and says so in a document an operator can read back.
    fn default() -> Self {
        Self {
            grant_types: BTreeSet::from([GrantType::ClientCredentials]),
            audiences: None,
            scopes: None,
            authorization_details_types: None,
            max_delegation_depth: DEFAULT_MAX_DELEGATION_DEPTH,
            access_token_ttl_cap: None,
            human_approval_scopes: BTreeSet::new(),
            human_approval_authorization_details_types: BTreeSet::new(),
        }
    }
}

impl AgentLimits {
    /// The grants an agent under these limits may be registered for.
    #[must_use]
    pub const fn grant_types(&self) -> &BTreeSet<GrantType> {
        &self.grant_types
    }

    /// The audiences (RFC 8707 resource indicators) an agent may name, or
    /// `None` where the tenant added no bound of its own.
    #[must_use]
    pub const fn audiences(&self) -> Option<&BTreeSet<String>> {
        self.audiences.as_ref()
    }

    /// The scopes an agent may hold, or `None` for no additional bound.
    #[must_use]
    pub const fn scopes(&self) -> Option<&BTreeSet<String>> {
        self.scopes.as_ref()
    }

    /// The RFC 9396 §9.2 detail types an agent may use, or `None`.
    #[must_use]
    pub const fn authorization_details_types(&self) -> Option<&BTreeSet<String>> {
        self.authorization_details_types.as_ref()
    }

    /// How deep a delegation chain may go.
    ///
    /// **Stored, not enforced.** See the module documentation: there is no
    /// delegation to measure until `ast-lh3.2` lands.
    #[must_use]
    pub const fn max_delegation_depth(&self) -> u8 {
        self.max_delegation_depth
    }

    /// The ceiling on an agent's access token lifetime, or `None`.
    #[must_use]
    pub const fn access_token_ttl_cap(&self) -> Option<Duration> {
        self.access_token_ttl_cap
    }

    /// Scopes no agent may hold without a human having approved them.
    #[must_use]
    pub const fn human_approval_scopes(&self) -> &BTreeSet<String> {
        &self.human_approval_scopes
    }

    /// Detail types no agent may use without a human having approved them.
    #[must_use]
    pub const fn human_approval_authorization_details_types(&self) -> &BTreeSet<String> {
        &self.human_approval_authorization_details_types
    }

    /// Whether a registration is admissible under these limits.
    ///
    /// Everything here is a set relation on the *validated* document, so it
    /// cannot panic and does not care what order the caller ran its own checks
    /// in. The spec-level rules an agent must satisfy whatever the tenant says
    /// — a key, a non-redirecting grant, an owner — are
    /// [`ClientRegistration`]'s and are applied before this is reached.
    ///
    /// # Errors
    ///
    /// [`ClientMetadataError`], whose code is RFC 7591 §3.2.2's
    /// `invalid_client_metadata`. The field is named; the offending value never
    /// is, for the reason [`ClientMetadataError`] gives.
    pub fn check(&self, registration: &ClientRegistration) -> Result<(), ClientMetadataError> {
        if !registration.grant_types.is_subset(&self.grant_types) {
            return Err(ClientMetadataError::Rejected {
                field: "grant_types",
                reason: "this tenant's agent profile does not permit one of these grants"
                    .to_owned(),
            });
        }
        if let Some(allowed) = &self.scopes
            && !registration.scopes.is_subset(allowed)
        {
            return Err(ClientMetadataError::Rejected {
                field: "scope",
                reason: "this tenant's agent profile does not permit one of these scopes"
                    .to_owned(),
            });
        }
        if let Some(allowed) = &self.authorization_details_types
            && !registration.authorization_details_types.is_subset(allowed)
        {
            return Err(ClientMetadataError::Rejected {
                field: "authorization_details_types",
                reason: "this tenant's agent profile does not permit one of these types".to_owned(),
            });
        }
        if let Some(allowed) = &self.audiences
            && !registration.resources.is_subset(allowed)
        {
            return Err(ClientMetadataError::Rejected {
                field: "resources",
                reason: "this tenant's agent profile does not permit one of these audiences"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// The JSON Schema the stored document is validated against.
    ///
    /// The `ast-gxh.6` subset, the same validator `ast-m9c.6` and `ast-ndk.1`
    /// already read their documents with. A second validator in one binary is a
    /// second opinion about what `"additionalProperties": false` means.
    #[must_use]
    pub fn schema_document() -> Value {
        let list = serde_json::json!({
            "type": "array",
            "maxItems": MAX_LIST_ENTRIES,
            "items": { "type": "string", "maxLength": MAX_ENTRY_LEN }
        });
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "owner": { "type": "string", "maxLength": MAX_ENTRY_LEN },
                "grant_types": list,
                "audiences": list,
                "scopes": list,
                "authorization_details_types": list,
                "max_delegation_depth": { "type": "integer" },
                "access_token_ttl_seconds": { "type": "integer" },
                "human_approval_scopes": list,
                "human_approval_authorization_details_types": list
            }
        })
    }

    /// Reads the limits out of a validated document object.
    ///
    /// Shared by [`AgentLimits::from_json`] and [`AgentProfile::from_json`]:
    /// the two documents are the same document, with and without an `owner`.
    fn read(object: &serde_json::Map<String, Value>) -> Result<Self, AgentProfileError> {
        let mut limits = Self::default();

        if let Some(values) = strings(object.get("grant_types"))? {
            let mut grants = BTreeSet::new();
            for name in values {
                let grant = GrantType::parse(&name).ok_or(AgentProfileError::UnusableGrantType)?;
                if !AGENT_GRANT_TYPES.contains(&grant) {
                    return Err(AgentProfileError::UnusableGrantType);
                }
                grants.insert(grant);
            }
            limits.grant_types = grants;
        }
        if let Some(values) = strings(object.get("audiences"))? {
            limits.audiences = Some(values.into_iter().collect());
        }
        if let Some(values) = strings(object.get("scopes"))? {
            limits.scopes = Some(values.into_iter().collect());
        }
        if let Some(values) = strings(object.get("authorization_details_types"))? {
            limits.authorization_details_types = Some(values.into_iter().collect());
        }
        if let Some(values) = strings(object.get("human_approval_scopes"))? {
            limits.human_approval_scopes = values.into_iter().collect();
        }
        if let Some(values) = strings(object.get("human_approval_authorization_details_types"))? {
            limits.human_approval_authorization_details_types = values.into_iter().collect();
        }

        if let Some(depth) = object.get("max_delegation_depth") {
            let depth = depth
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .filter(|value| *value >= 1 && *value <= MAX_DELEGATION_DEPTH)
                .ok_or(AgentProfileError::UnusableDelegationDepth)?;
            limits.max_delegation_depth = depth;
        }
        if let Some(seconds) = object.get("access_token_ttl_seconds") {
            let cap = seconds
                .as_i64()
                .map(Duration::seconds)
                .filter(|cap| *cap >= MIN_LIFETIME && *cap <= MAX_ACCESS_TOKEN_LIFETIME)
                .ok_or(AgentProfileError::UnusableLifetime(
                    "access_token_ttl_seconds",
                ))?;
            limits.access_token_ttl_cap = Some(cap);
        }

        Ok(limits)
    }

    /// Reads the `agent` object of a tenant's registration policy.
    ///
    /// # Errors
    ///
    /// [`AgentProfileError`] for a document this server would not have written.
    // fuzz-target: agent_profile
    pub fn from_json(value: &Value) -> Result<Self, AgentProfileError> {
        let object = accepted(value)?;
        if object.contains_key("owner") {
            // The tenant's limits are not one agent's profile. An `owner` here
            // would be a tenant-wide document naming a single account, which is
            // either a mistake or an attempt to make every agent somebody's.
            return Err(AgentProfileError::SchemaRejected);
        }
        Self::read(&object)
    }

    /// The limits as they are stored, written out in full.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut document = serde_json::json!({
            "grant_types": self.grant_types.iter().map(|g| g.as_str()).collect::<Vec<_>>(),
            "max_delegation_depth": self.max_delegation_depth,
        });
        let object = document
            .as_object_mut()
            .expect("the document above is a JSON object");
        for (key, list) in [
            ("audiences", self.audiences.as_ref()),
            ("scopes", self.scopes.as_ref()),
            (
                "authorization_details_types",
                self.authorization_details_types.as_ref(),
            ),
        ] {
            if let Some(values) = list {
                object.insert(key.to_owned(), values.iter().map(String::as_str).collect());
            }
        }
        for (key, list) in [
            ("human_approval_scopes", &self.human_approval_scopes),
            (
                "human_approval_authorization_details_types",
                &self.human_approval_authorization_details_types,
            ),
        ] {
            if !list.is_empty() {
                object.insert(key.to_owned(), list.iter().map(String::as_str).collect());
            }
        }
        if let Some(cap) = self.access_token_ttl_cap {
            object.insert(
                "access_token_ttl_seconds".to_owned(),
                Value::from(cap.whole_seconds()),
            );
        }
        document
    }

    /// The limits with a token lifetime ceiling, for tests and for the admin
    /// API's forms.
    #[must_use]
    pub fn with_access_token_ttl_cap(mut self, cap: Duration) -> Self {
        self.access_token_ttl_cap = Some(cap);
        self
    }

    /// The limits with an additional set of permitted grants.
    ///
    /// Entries outside [`AGENT_GRANT_TYPES`] are dropped rather than refused:
    /// this is a constructor for callers that already hold typed values, and
    /// the type system cannot say "a grant an agent may use".
    #[must_use]
    pub fn with_grant_types<I: IntoIterator<Item = GrantType>>(mut self, grants: I) -> Self {
        self.grant_types = grants
            .into_iter()
            .filter(|grant| AGENT_GRANT_TYPES.contains(grant))
            .collect();
        self
    }

    /// The limits with a set of scopes that a human must have approved.
    #[must_use]
    pub fn with_human_approval_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.human_approval_scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// The limits with an allow-list of scopes.
    #[must_use]
    pub fn with_scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = Some(scopes.into_iter().map(Into::into).collect());
        self
    }
}

// ---------------------------------------------------------------------------
// The profile
// ---------------------------------------------------------------------------

/// One agent's profile: its owner, and the limits its tenant put on it.
///
/// Stored on the client row (`clients.agent_policy`) and carried on
/// [`ClientRegistration::agent`], so that every issuance path has the owner and
/// the limits in hand without a second read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProfile {
    owner: AgentOwner,
    limits: AgentLimits,
}

impl AgentProfile {
    /// An agent owned by `owner`, under `limits`.
    #[must_use]
    pub const fn new(owner: AgentOwner, limits: AgentLimits) -> Self {
        Self { owner, limits }
    }

    /// The principal this agent acts for.
    #[must_use]
    pub const fn owner(&self) -> &AgentOwner {
        &self.owner
    }

    /// The limits in force.
    #[must_use]
    pub const fn limits(&self) -> &AgentLimits {
        &self.limits
    }

    /// The same profile under different limits.
    ///
    /// What a registration does: the owner arrives on the document and the
    /// limits arrive from the tenant's policy, and the two meet exactly once.
    #[must_use]
    pub fn under(self, limits: AgentLimits) -> Self {
        Self { limits, ..self }
    }

    /// The tenant's lifetimes, bounded by this agent's ceiling.
    ///
    /// The minimum of the two, never the agent's alone: an agent profile may
    /// shorten a token's life and may not extend it past what the tenant
    /// already validated (`ast-5c6`). The authorization code lifetime is
    /// untouched — an agent never reaches the authorization endpoint, so a cap
    /// on it would be a setting with no effect.
    #[must_use]
    pub fn cap(&self, lifetimes: TokenLifetimes) -> TokenLifetimes {
        match self.limits.access_token_ttl_cap {
            Some(cap) => lifetimes.with_access_token_at_most(cap),
            None => lifetimes,
        }
    }

    /// The first requested scope a human must approve before an agent may hold
    /// it, or `None` when every one of them is unattended-safe.
    ///
    /// Named "first" and not "all" because the caller refuses on one: telling a
    /// client *which* of its scopes needs a person is enough to act on, and
    /// enumerating the rest is a list of the tenant's sensitive scopes handed
    /// to whoever asks.
    #[must_use]
    pub fn scope_needing_human_approval<'a, I>(&self, requested: I) -> Option<&'a str>
    where
        I: IntoIterator<Item = &'a str>,
    {
        requested
            .into_iter()
            .find(|scope| self.limits.human_approval_scopes.contains(*scope))
    }

    /// The first requested `authorization_details` type a human must approve.
    #[must_use]
    pub fn detail_type_needing_human_approval<'a, I>(&self, requested: I) -> Option<&'a str>
    where
        I: IntoIterator<Item = &'a str>,
    {
        requested.into_iter().find(|name| {
            self.limits
                .human_approval_authorization_details_types
                .contains(*name)
        })
    }

    /// Reads the stored `clients.agent_policy` document.
    ///
    /// # Errors
    ///
    /// [`AgentProfileError`] for a document this server did not write, or one
    /// naming no owner: an ownerless agent profile is the one shape that must
    /// never load, because everything above assumes there is somebody to
    /// attribute the agent's actions to.
    // fuzz-target: agent_profile
    pub fn from_json(value: &Value) -> Result<Self, AgentProfileError> {
        let object = accepted(value)?;
        let owner = object
            .get("owner")
            .and_then(Value::as_str)
            .and_then(|raw| Uuid::parse_str(raw).ok())
            .map(|id| AgentOwner::User(UserId::new(id)))
            .ok_or(AgentProfileError::OwnerNotAUser)?;
        Ok(Self {
            owner,
            limits: AgentLimits::read(&object)?,
        })
    }

    /// The profile as it is stored.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut document = self.limits.to_json();
        document
            .as_object_mut()
            .expect("`AgentLimits::to_json` returns a JSON object")
            .insert("owner".to_owned(), Value::from(self.owner.to_string()));
        document
    }
}

// ---------------------------------------------------------------------------
// Shared reading
// ---------------------------------------------------------------------------

/// Checks a document against the schema and hands back its object.
fn accepted(value: &Value) -> Result<serde_json::Map<String, Value>, AgentProfileError> {
    if serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_PROFILE_BYTES) {
        return Err(AgentProfileError::TooLarge);
    }
    let schema = crate::JsonSchema::parse(&AgentLimits::schema_document())
        .map_err(|_| AgentProfileError::SchemaUnusable)?;
    if !schema.accepts(value) {
        return Err(AgentProfileError::SchemaRejected);
    }
    value
        .as_object()
        .cloned()
        .ok_or(AgentProfileError::SchemaRejected)
}

/// Reads a list of strings the schema has already shaped.
fn strings(value: Option<&Value>) -> Result<Option<Vec<String>>, AgentProfileError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let items = value.as_array().ok_or(AgentProfileError::SchemaRejected)?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or(AgentProfileError::SchemaRejected)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn owner() -> AgentOwner {
        AgentOwner::User(UserId::new(
            Uuid::parse_str("6c9f1c4e-9a2e-4a8a-9f0a-0a1b2c3d4e5f").expect("a fixed UUID"),
        ))
    }

    #[test]
    fn an_owner_is_a_user_uuid_and_never_a_subject_identifier() {
        // Arrange: the two spellings a caller might reach for.
        let uuid = "6c9f1c4e-9a2e-4a8a-9f0a-0a1b2c3d4e5f";
        let pairwise_sub = "wD3wVQOR2b7WcZ9m0YkX8s0Zy6c1Q1s3n5r7t9v1x3z";

        // Act.
        let parsed = AgentOwner::parse(uuid);
        let refused = AgentOwner::parse(pairwise_sub);

        // Assert.
        assert_eq!(parsed.expect("a UUID names a user"), owner());
        assert_eq!(
            refused.expect_err("a pairwise sub is not an owner").code(),
            "invalid_client_metadata"
        );
    }

    /// Whether a string is spelled the way *this server* spells a `sub`.
    ///
    /// Two spellings and no others: a public subject is the account UUID, and
    /// a pairwise one is a SHA-256 digest in unpadded `base64url` (43
    /// symbols). Both are asserted against real values below, so this predicate
    /// cannot drift away from what the server actually issues without the test
    /// failing.
    fn looks_like_a_subject_identifier(value: &str) -> bool {
        Uuid::parse_str(value).is_ok()
            || (value.len() == 43
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    }

    /// FAPI 2.0 SP §6.7: a client that can influence its `client_id` may have
    /// it "mistaken for an end-user subject identifier". This asserts the
    /// stronger property the codebase actually holds — the two populations do
    /// not overlap at all — against subjects drawn the way the server draws
    /// them, rather than against a remembered description of their shape.
    ///
    /// An agent is the reason it matters here: an agent acts *for* a subject,
    /// so a log line, an audit row and a `sub` claim all carry both kinds of
    /// identifier within a few bytes of each other.
    #[test]
    fn no_minted_client_id_can_be_read_as_a_subject_this_server_issues() {
        // Arrange: one subject of each kind, from the real generators.
        let user = UserId::generate();
        let public = user.to_string();
        let pairwise = crate::PairwiseSalt::generate()
            .derive_subject(&crate::SectorIdentifier::public(), user)
            .as_str()
            .to_owned();

        // Act: a sample of minted client identifiers.
        let minted: Vec<String> = (0..64)
            .map(|_| crate::ClientId::mint().as_str().to_owned())
            .collect();

        // Assert.
        assert!(
            looks_like_a_subject_identifier(&public),
            "a public sub is a UUID: {public}"
        );
        assert!(
            looks_like_a_subject_identifier(&pairwise),
            "a pairwise sub is 43 base64url symbols: {pairwise}"
        );
        for id in &minted {
            assert!(
                !looks_like_a_subject_identifier(id),
                "{id} could be read as a subject identifier"
            );
        }
    }

    #[test]
    fn the_default_limits_permit_client_credentials_and_one_hop() {
        // Arrange & act.
        let limits = AgentLimits::default();

        // Assert.
        assert_eq!(
            limits.grant_types(),
            &BTreeSet::from([GrantType::ClientCredentials])
        );
        assert_eq!(limits.max_delegation_depth(), DEFAULT_MAX_DELEGATION_DEPTH);
    }

    #[test]
    fn a_stored_profile_round_trips_through_its_schema() {
        // Arrange.
        let limits = AgentLimits::default()
            .with_grant_types([GrantType::ClientCredentials, GrantType::TokenExchange])
            .with_scopes(["inventory:read"])
            .with_human_approval_scopes(["payments:write"])
            .with_access_token_ttl_cap(Duration::minutes(2));
        let profile = AgentProfile::new(owner(), limits);

        // Act.
        let stored = profile.to_json();
        let read_back = AgentProfile::from_json(&stored).expect("the document this build wrote");

        // Assert.
        assert_eq!(read_back, profile);
    }

    #[test]
    fn a_profile_with_no_owner_does_not_load() {
        // Arrange: the limits alone, which is a tenant document and not a
        // client one.
        let document = AgentLimits::default().to_json();

        // Act.
        let error = AgentProfile::from_json(&document);

        // Assert.
        assert_eq!(error, Err(AgentProfileError::OwnerNotAUser));
    }

    #[test]
    fn a_profile_naming_a_grant_an_agent_may_not_use_does_not_load() {
        // Arrange: `authorization_code` is a grant an agent cannot complete.
        let document = json!({
            "owner": owner().to_string(),
            "grant_types": ["authorization_code"],
        });

        // Act.
        let error = AgentProfile::from_json(&document);

        // Assert.
        assert_eq!(error, Err(AgentProfileError::UnusableGrantType));
    }

    #[test]
    fn a_profile_with_an_unbounded_delegation_depth_does_not_load() {
        // Arrange.
        let document = json!({
            "owner": owner().to_string(),
            "max_delegation_depth": u64::from(MAX_DELEGATION_DEPTH) + 1,
        });

        // Act.
        let error = AgentProfile::from_json(&document);

        // Assert.
        assert_eq!(error, Err(AgentProfileError::UnusableDelegationDepth));
    }

    #[test]
    fn a_delegation_depth_of_zero_does_not_load() {
        // Arrange: zero would mean "an agent may not act at all", which no
        // caller today would honour — so it is refused rather than stored.
        let document = json!({ "owner": owner().to_string(), "max_delegation_depth": 0 });

        // Act & assert.
        assert_eq!(
            AgentProfile::from_json(&document),
            Err(AgentProfileError::UnusableDelegationDepth)
        );
    }

    #[test]
    fn a_ttl_cap_above_the_profile_ceiling_does_not_load() {
        // Arrange.
        let document = json!({
            "owner": owner().to_string(),
            "access_token_ttl_seconds": MAX_ACCESS_TOKEN_LIFETIME.whole_seconds() + 1,
        });

        // Act & assert.
        assert_eq!(
            AgentProfile::from_json(&document),
            Err(AgentProfileError::UnusableLifetime(
                "access_token_ttl_seconds"
            ))
        );
    }

    #[test]
    fn an_unknown_member_does_not_load() {
        // Arrange: `additionalProperties: false`, so a member this build does
        // not know is a document written by something else.
        let document = json!({ "owner": owner().to_string(), "max_delegation_dept": 4 });

        // Act & assert.
        assert_eq!(
            AgentProfile::from_json(&document),
            Err(AgentProfileError::SchemaRejected)
        );
    }

    #[test]
    fn tenant_limits_refuse_a_document_naming_an_owner() {
        // Arrange.
        let document = json!({ "owner": owner().to_string() });

        // Act & assert.
        assert_eq!(
            AgentLimits::from_json(&document),
            Err(AgentProfileError::SchemaRejected)
        );
    }

    #[test]
    fn a_cap_shortens_the_tenants_access_token_lifetime() {
        // Arrange: the tenant says five minutes, the agent profile two.
        let lifetimes = TokenLifetimes::default();
        let profile = AgentProfile::new(
            owner(),
            AgentLimits::default().with_access_token_ttl_cap(Duration::minutes(2)),
        );

        // Act.
        let capped = profile.cap(lifetimes);

        // Assert.
        assert_eq!(capped.access_token(), Duration::minutes(2));
        assert_eq!(
            capped.authorization_code(),
            lifetimes.authorization_code(),
            "an agent never reaches the authorization endpoint"
        );
    }

    #[test]
    fn a_cap_longer_than_the_tenants_lifetime_does_not_extend_it() {
        // Arrange: the agent profile asks for more than the tenant allows.
        let lifetimes = TokenLifetimes::default();
        let profile = AgentProfile::new(
            owner(),
            AgentLimits::default().with_access_token_ttl_cap(MAX_ACCESS_TOKEN_LIFETIME),
        );

        // Act.
        let capped = profile.cap(lifetimes);

        // Assert.
        assert_eq!(capped.access_token(), lifetimes.access_token());
    }

    #[test]
    fn a_scope_the_tenant_marked_for_human_approval_is_named() {
        // Arrange.
        let profile = AgentProfile::new(
            owner(),
            AgentLimits::default().with_human_approval_scopes(["payments:write"]),
        );

        // Act.
        let found = profile.scope_needing_human_approval(["inventory:read", "payments:write"]);

        // Assert.
        assert_eq!(found, Some("payments:write"));
    }

    #[test]
    fn an_unattended_scope_needs_nobody() {
        // Arrange.
        let profile = AgentProfile::new(
            owner(),
            AgentLimits::default().with_human_approval_scopes(["payments:write"]),
        );

        // Act & assert.
        assert_eq!(
            profile.scope_needing_human_approval(["inventory:read"]),
            None
        );
    }
}
