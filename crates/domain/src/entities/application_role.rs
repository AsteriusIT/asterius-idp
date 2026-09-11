//! Application roles: the authority a tenant delegates to its own
//! applications, as opposed to the authority to administer this server.
//!
//! Two catalogues, following the model relying parties already know
//! (`ast-095`):
//!
//! * a **tenant role** is shared by every application of the tenant — one
//!   vocabulary, so `auditor` means the same thing to the BFF and to the API
//!   behind it;
//! * a **client role** belongs to one client and nothing else, so two teams
//!   can both mint `admin` without either of them widening the other.
//!
//! Neither is [`Role`](crate::Role). That type is the authority to administer
//! *this server* — a closed set of two, decided at compile time, because a
//! string somebody can invent at runtime must never become authority over
//! other people's credentials. What is defined here is the opposite: a name a
//! tenant invents, carried in a token, and interpreted by an application this
//! server knows nothing about. The two must not share a type, or a role
//! created from the admin API would be one hop away from being read as
//! `tenant_admin`.
//!
//! # Why the alphabet is this small
//!
//! A role name is copied into a JWT and read by third-party code that this
//! deployment does not review. A name carrying a space would split into two
//! roles at any resource server that splits on whitespace, one carrying `"`
//! would break a hand-rolled parser, one carrying a right-to-left override
//! would render as a *different* name in a console, and one differing from
//! another only in case would be two roles to Postgres and one to an
//! application comparing case-insensitively. Every one of those is an
//! authorization decision made about the wrong name.
//!
//! So [`RoleName`] admits ASCII lowercase letters, digits, and `-`, `_`, `.`,
//! `:` — the vocabulary Keycloak deployments and OAuth scope tokens already
//! use — with the first character alphanumeric, and nothing else. Uppercase is
//! *refused rather than folded*: lowercasing the input would silently make
//! `Admin` and `admin` the same role, and a parser that changes its input is a
//! parser whose output nobody predicted.

use crate::{ClientId, TenantId, UserId};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use time::OffsetDateTime;

/// Why a role name was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum RoleNameError {
    /// Empty, or longer than [`RoleName::MAX_LEN`].
    #[error("a role name must be 1 to {max} characters, found {found}", max = RoleName::MAX_LEN)]
    Length {
        /// How long the offered name was, in bytes.
        found: usize,
    },
    /// A character outside the alphabet, reported so an operator can see which
    /// one.
    #[error("a role name may only contain a-z, 0-9, '-', '_', '.' and ':' (found {0:?})")]
    Character(char),
    /// The name does not start with a lowercase letter or a digit.
    #[error("a role name must start with a lowercase letter or a digit")]
    Start,
}

/// The name of an application role, as it appears in a token.
///
/// Parsed once, at the edge, and stored parsed: every later use — the database
/// key, the JSON claim, the console — is then the same bytes, and there is no
/// second place where "is this a name we would mint" could be answered
/// differently.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoleName(String);

impl RoleName {
    /// The longest name this server will store.
    ///
    /// Sixty-four characters is long enough for `payments.settlement:approve`
    /// twice over and short enough that a user holding many roles still fits
    /// in a token: the claims set is capped, and a role catalogue is not a
    /// place to spend that budget.
    pub const MAX_LEN: usize = 64;

    /// Parses a name.
    ///
    /// # Errors
    ///
    /// [`RoleNameError`] for anything outside the alphabet the module
    /// documentation gives, including uppercase.
    // fuzz-target: role_name
    pub fn parse(raw: &str) -> Result<Self, RoleNameError> {
        // Counted in bytes first, so that a megabyte of multi-byte input is
        // refused before anything walks it. The alphabet is ASCII, so for
        // everything that gets past the loop below the two counts agree.
        if raw.is_empty() || raw.len() > Self::MAX_LEN {
            return Err(RoleNameError::Length { found: raw.len() });
        }
        for character in raw.chars() {
            if !matches!(character, 'a'..='z' | '0'..='9' | '-' | '_' | '.' | ':') {
                return Err(RoleNameError::Character(character));
            }
        }
        // A leading `-`, `.`, `:` or `_` is refused so that a name cannot be
        // made to sort or read like punctuation: `-admin` beside `admin` in a
        // console list is a name chosen to be misread.
        let first = raw
            .chars()
            .next()
            .ok_or(RoleNameError::Length { found: 0 })?;
        if !first.is_ascii_alphanumeric() {
            return Err(RoleNameError::Start);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The name as stored and as written into a token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RoleName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The longest description a role may carry.
///
/// Free text for a human, never parsed and never put in a token, so the only
/// property it needs is a bound: it is rendered in a console, and a role
/// carrying a novel is a screen nobody can read.
pub const MAX_ROLE_DESCRIPTION_LEN: usize = 200;

/// Why a role definition was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ApplicationRoleError {
    /// The name is not one this server will store.
    #[error(transparent)]
    Name(#[from] RoleNameError),
    /// The description is longer than [`MAX_ROLE_DESCRIPTION_LEN`].
    #[error(
        "a role description must be at most {max} characters, found {found}",
        max = MAX_ROLE_DESCRIPTION_LEN
    )]
    Description {
        /// How long the offered description was, in characters.
        found: usize,
    },
    /// The description carries a control character, which a console would
    /// render as a line break or not at all.
    #[error("a role description must not contain control characters (U+{0:04X})")]
    DescriptionCharacter(u32),
}

/// What a role belongs to.
///
/// An enum rather than an `Option<ClientId>`, because the two cases are read
/// differently at every call site — one is written into `roles` and the other
/// into `resource_access.<client_id>.roles` — and an `Option` invites a `None`
/// arm that silently means "tenant-wide" in a function that meant "not
/// specified".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoleOwner {
    /// Shared by every application of the tenant.
    Tenant,
    /// Belongs to one client.
    Client(ClientId),
}

impl RoleOwner {
    /// The client, or `None` for a tenant role. For an adapter binding a
    /// nullable column, and for nothing that decides authority.
    #[must_use]
    pub const fn client(&self) -> Option<&ClientId> {
        match self {
            Self::Tenant => None,
            Self::Client(client) => Some(client),
        }
    }
}

/// One entry of a role catalogue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationRole {
    /// The tenant that owns the catalogue.
    pub tenant: TenantId,
    /// Whether this is a tenant role or one client's.
    pub owner: RoleOwner,
    /// The name, as it appears in a token.
    pub name: RoleName,
    /// What it is for, for whoever assigns it. Never issued.
    pub description: Option<String>,
    /// When it was created. The audit trail carries who.
    pub created_at: OffsetDateTime,
}

impl ApplicationRole {
    /// Builds a catalogue entry, checking the name and the description.
    ///
    /// # Errors
    ///
    /// [`ApplicationRoleError`] for a name outside the alphabet, or a
    /// description that is too long or carries a control character.
    pub fn new(
        tenant: TenantId,
        owner: RoleOwner,
        name: &str,
        description: Option<&str>,
        created_at: OffsetDateTime,
    ) -> Result<Self, ApplicationRoleError> {
        let name = RoleName::parse(name)?;
        let description = description.map(str::to_owned);
        if let Some(text) = &description {
            let length = text.chars().count();
            if length > MAX_ROLE_DESCRIPTION_LEN {
                return Err(ApplicationRoleError::Description { found: length });
            }
            if let Some(control) = text.chars().find(|character| character.is_control()) {
                return Err(ApplicationRoleError::DescriptionCharacter(control as u32));
            }
        }
        Ok(Self {
            tenant,
            owner,
            name,
            description,
            created_at,
        })
    }
}

/// Everything one user holds, in the shape a token needs it.
///
/// Assembled by one read rather than by a query per client, and ordered:
/// [`BTreeSet`] and [`BTreeMap`] make the `roles` and `resource_access` claims
/// byte-identical for two issuances of the same authority, which is what lets
/// a token be compared in a test and cached by a resource server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeldRoles {
    /// Tenant roles, which every application of the tenant shares.
    pub tenant: BTreeSet<RoleName>,
    /// Client roles, by the client that defines them.
    pub clients: BTreeMap<ClientId, BTreeSet<RoleName>>,
}

impl HeldRoles {
    /// Nothing held, in a `const` context.
    ///
    /// `Default` cannot be called from a `const fn`, and the access-token
    /// builder's constructor is one — see `asterius_oidc::tokens::access`.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            tenant: BTreeSet::new(),
            clients: BTreeMap::new(),
        }
    }

    /// Whether the user holds nothing at all, in which case a token carries
    /// neither claim.
    ///
    /// An empty `roles` array is not the same statement as no `roles` claim:
    /// the first says "this person holds no roles", which a resource server
    /// may cache, and the second says nothing. Both are honest, and the absent
    /// one is chosen because it is the smaller token.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tenant.is_empty() && self.clients.values().all(BTreeSet::is_empty)
    }

    /// What a token issued to `client` may say, and nothing else.
    ///
    /// See `asterius_oidc::tokens::access` for why this narrowing exists: a
    /// resource server has no registered relationship with the other clients
    /// of its tenant, so the only client whose roles it can be told about
    /// without guessing is the one the token was issued to.
    #[must_use]
    pub fn for_client(&self, client: &ClientId) -> Self {
        Self {
            tenant: self.tenant.clone(),
            clients: self
                .clients
                .get(client)
                .filter(|roles| !roles.is_empty())
                .map(|roles| (client.clone(), roles.clone()))
                .into_iter()
                .collect(),
        }
    }

    /// One role claim's value, or `None` when there is nothing to say.
    ///
    /// The rendering lives here rather than in a token builder because two
    /// builders issue these claims — the access token (`ast-095`) and, when a
    /// client asks for them, the ID token (`ast-mqt`) — and a relying party
    /// that read `roles` from one and `resource_access` from the other must
    /// not find two shapes. `None` is the absent claim: an empty array says
    /// "this person holds no roles", which a resource server may cache, and
    /// an absent claim says nothing.
    ///
    /// [`RoleClaim::ResourceAccess`] renders no client that holds nothing, so
    /// no token carries an empty `roles` array under a client name. Narrowing
    /// to the token's own client is [`HeldRoles::for_client`]'s job and is not
    /// repeated here: one place to narrow is one place to widen.
    #[must_use]
    pub fn claim(&self, claim: RoleClaim) -> Option<serde_json::Value> {
        match claim {
            RoleClaim::Roles => {
                if self.tenant.is_empty() {
                    return None;
                }
                Some(serde_json::Value::Array(as_json(&self.tenant)))
            }
            RoleClaim::ResourceAccess => {
                let members: serde_json::Map<String, serde_json::Value> = self
                    .clients
                    .iter()
                    .filter(|(_, roles)| !roles.is_empty())
                    .map(|(client, roles)| {
                        (
                            client.as_str().to_owned(),
                            serde_json::json!({ "roles": as_json(roles) }),
                        )
                    })
                    .collect();
                if members.is_empty() {
                    return None;
                }
                Some(serde_json::Value::Object(members))
            }
        }
    }
}

/// Role names as the JSON array a claim carries, in catalogue order.
fn as_json(roles: &BTreeSet<RoleName>) -> Vec<serde_json::Value> {
    roles
        .iter()
        .map(|role| serde_json::Value::String(role.as_str().to_owned()))
        .collect()
}

/// A claim an authorization server computes from what an account holds.
///
/// Two names and no more: `roles` for the tenant's shared catalogue and
/// `resource_access` for a client's own, which is the shape Keycloak
/// deployments publish. An enum rather than two string literals spread across
/// the access token, the ID token and the `claims` request parser, because
/// those three have to agree on the same two names — a fourth spelling
/// anywhere would be a claim a relying party's library never reads, or a name
/// a user record could be made to assert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RoleClaim {
    /// The tenant's roles, as a flat array.
    Roles,
    /// One member per client, each an object with a `roles` array.
    ResourceAccess,
}

impl RoleClaim {
    /// Both of them, which is the list every consumer walks.
    pub const ALL: [Self; 2] = [Self::Roles, Self::ResourceAccess];

    /// The member name the claim is issued under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Roles => "roles",
            Self::ResourceAccess => "resource_access",
        }
    }

    /// Matches a claim name exactly, or nothing.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|claim| claim.as_str() == raw)
    }
}

/// One assignment: which user holds which role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAssignment {
    /// The user who holds it.
    pub user: UserId,
    /// Whose catalogue the role comes from.
    pub owner: RoleOwner,
    /// The role held.
    pub name: RoleName,
    /// When it was granted. The audit trail carries who.
    pub granted_at: OffsetDateTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    #[test]
    fn a_name_in_the_alphabet_parses_unchanged() {
        let parsed = RoleName::parse("payments.settlement:approve").expect("a name");

        assert_eq!(parsed.as_str(), "payments.settlement:approve");
    }

    #[test]
    fn a_name_with_a_space_is_refused() {
        assert_eq!(
            RoleName::parse("read write"),
            Err(RoleNameError::Character(' '))
        );
    }

    /// Folding would make two catalogue entries one role. Refusing keeps the
    /// name a tenant typed the name a token carries.
    #[test]
    fn an_uppercase_name_is_refused_rather_than_lowercased() {
        assert_eq!(RoleName::parse("Admin"), Err(RoleNameError::Character('A')));
    }

    #[test]
    fn a_name_that_starts_with_punctuation_is_refused() {
        assert_eq!(RoleName::parse("-admin"), Err(RoleNameError::Start));
    }

    #[test]
    fn an_empty_name_is_refused() {
        assert_eq!(RoleName::parse(""), Err(RoleNameError::Length { found: 0 }));
    }

    #[test]
    fn a_name_past_the_bound_is_refused() {
        let long = "a".repeat(RoleName::MAX_LEN + 1);

        assert_eq!(
            RoleName::parse(&long),
            Err(RoleNameError::Length {
                found: RoleName::MAX_LEN + 1
            })
        );
    }

    #[test]
    fn a_description_past_the_bound_is_refused() {
        let error = ApplicationRole::new(
            TenantId::new("demo"),
            RoleOwner::Tenant,
            "auditor",
            Some(&"d".repeat(MAX_ROLE_DESCRIPTION_LEN + 1)),
            epoch(),
        )
        .expect_err("a description past the bound");

        assert!(matches!(error, ApplicationRoleError::Description { .. }));
    }

    /// The filter the `resource_access` claim depends on: one client's roles
    /// are not another's, whatever else the user holds.
    #[test]
    fn narrowing_to_a_client_drops_every_other_clients_roles() {
        let mut held = HeldRoles::default();
        held.tenant
            .insert(RoleName::parse("auditor").expect("a name"));
        held.clients.insert(
            ClientId::new("billing"),
            [RoleName::parse("refund").expect("a name")]
                .into_iter()
                .collect(),
        );
        held.clients.insert(
            ClientId::new("reporting"),
            [RoleName::parse("export").expect("a name")]
                .into_iter()
                .collect(),
        );

        let narrowed = held.for_client(&ClientId::new("billing"));

        assert_eq!(narrowed.clients.len(), 1);
        assert!(narrowed.clients.contains_key(&ClientId::new("billing")));
        assert_eq!(narrowed.tenant, held.tenant);
    }

    /// A client with no roles gets no entry at all, so no token carries an
    /// empty `resource_access` object for it.
    #[test]
    fn a_client_holding_nothing_is_absent_rather_than_empty() {
        let held = HeldRoles::default();

        let narrowed = held.for_client(&ClientId::new("billing"));

        assert!(narrowed.is_empty());
        assert!(narrowed.clients.is_empty());
    }

    fn one_of_each() -> HeldRoles {
        let mut held = HeldRoles::default();
        held.tenant
            .insert(RoleName::parse("auditor").expect("a name"));
        held.clients.insert(
            ClientId::new("billing"),
            [RoleName::parse("refund").expect("a name")]
                .into_iter()
                .collect(),
        );
        held
    }

    #[test]
    fn the_tenant_claim_is_a_flat_array_of_names() {
        let rendered = one_of_each().claim(RoleClaim::Roles).expect("a claim");

        assert_eq!(rendered, serde_json::json!(["auditor"]));
    }

    #[test]
    fn the_client_claim_is_one_object_per_client() {
        let rendered = one_of_each()
            .claim(RoleClaim::ResourceAccess)
            .expect("a claim");

        assert_eq!(
            rendered,
            serde_json::json!({"billing": {"roles": ["refund"]}})
        );
    }

    /// Absent, not empty: an empty array is a statement a resource server may
    /// cache, and "holds nothing" is what an absent claim already means.
    #[test]
    fn nothing_held_renders_neither_claim() {
        let held = HeldRoles::default();

        for claim in RoleClaim::ALL {
            assert_eq!(held.claim(claim), None, "{} was rendered", claim.as_str());
        }
    }

    /// The names are the ones tokens carry; a third spelling would be a claim
    /// no relying party's library reads.
    #[test]
    fn the_two_claim_names_round_trip_through_parse() {
        for claim in RoleClaim::ALL {
            assert_eq!(RoleClaim::parse(claim.as_str()), Some(claim));
        }
        assert_eq!(RoleClaim::parse("realm_access"), None);
    }
}
