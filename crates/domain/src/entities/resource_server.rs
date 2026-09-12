//! Registered resource servers, and the `resource` values that may name them.
//!
//! RFC 8707 gives a client a way to say *what an access token is for*, and
//! RFC 9068 §3 turns that into the `aud` of the token. This module holds the
//! two halves that decision needs: the parser that turns an attacker-controlled
//! string into a resource indicator, and the per-tenant registry that says
//! which indicators this deployment has ever heard of.
//!
//! # Why a registry, and not just the client's allow-list
//!
//! A `resource` parameter names a *resource server*, and a resource server is
//! a property of the deployment: the operator knows which APIs exist, what
//! scopes each of them understands, and how long a token for it should live.
//! Without a registry the AS would mint `aud` values out of whatever a client
//! sent — RFC 8707 §3's "the authorization server MUST validate the resource
//! parameter" is exactly the check that stops a client from minting itself an
//! audience for a service it was never told about.
//!
//! So a `resource` must pass **both** gates: the client's own allow-list
//! (`ClientRegistration::resources`, which is who may ask) and this registry
//! (which is what exists). Either one failing is `invalid_target` (RFC 8707
//! §2.2) and the client is told nothing about which.
//!
//! # The audience is never empty
//!
//! [`ResourceRegistry::targets`] is the one function that decides what an
//! access token is audienced at, and it returns `Err(InvalidTarget)` rather
//! than an empty set. RFC 9068 §2.2 makes `aud` REQUIRED, and an audience-less
//! access token is not "a token for everything" — it is a token every
//! non-conforming resource server accepts. A client with no `resource`, no
//! authorized set and no default audiences gets an error, not a token.
//!
//! # Multi-audience policy (the choice `ast-gxh.7` had to make)
//!
//! RFC 8707 §2 allows several `resource` parameters, and this server takes
//! that option: two targets produce **one** token whose `aud` is an array,
//! rather than a refusal. The alternative — one audience per token — would
//! force a client wanting two APIs to run two flows, and RFC 8707 §2's
//! "multiple parameters" language exists precisely so it does not have to.
//! The bound is [`crate::Grant::MAX_RESOURCES`], and the scopes such a token
//! carries are the ones **every** named resource server permits (see
//! [`ResourceRegistry::permitted_scopes`]), so widening the audience never
//! widens the authority.

use std::collections::{BTreeMap, BTreeSet};
use time::Duration;

/// The longest `resource` value this server will look at.
///
/// A resource indicator is a URI an operator registered, not a document: 512
/// bytes is far past any real API identifier and short enough that a flood of
/// long values costs nothing to refuse.
pub const MAX_IDENTIFIER_LEN: usize = 512;

/// The most resource servers one tenant may have registered.
///
/// The registry is read on the request path, so it is bounded like everything
/// else that is: a tenant with thousands of rows would turn every token
/// request into a table scan.
pub const MAX_REGISTERED: usize = 256;

/// RFC 8707 §2.2's error for a `resource` this server will not honour.
///
/// One variant on purpose. "Not a URI", "not registered here" and "not in the
/// set your authorization request named" are three different facts, and a
/// client that could tell them apart could enumerate a tenant's resource
/// servers with a series of token requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the resource parameter does not name a resource this client may be issued a token for")]
pub struct InvalidTarget;

impl InvalidTarget {
    /// The OAuth error code (RFC 8707 §2.2).
    pub const CODE: &'static str = "invalid_target";
}

/// A `resource` value that is a usable resource indicator (RFC 8707 §2).
///
/// Construction is the proof: the only way to obtain one is
/// [`ResourceIdentifier::parse`], so a value of this type is a string that may
/// be compared against the registry and, eventually, written into an `aud`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceIdentifier(String);

impl ResourceIdentifier {
    /// Parses one `resource` parameter value.
    ///
    /// RFC 8707 §2: "The `resource` parameter URI value is an absolute URI as
    /// specified by Section 4.3 of RFC 3986. The `resource` parameter URI value
    /// MUST NOT include a fragment component." Both are checked here, and so is
    /// a length bound, because this is the point where attacker-controlled
    /// bytes become a typed value.
    ///
    /// A host is required as well, which is narrower than "absolute URI" and
    /// deliberate: every identifier this deployment can register is an `https`
    /// origin plus a path — the canonical MCP server URI of MCP Authorization
    /// 2025-11-25 is one — and a scheme-only URI (`urn:example:api`) is a value
    /// no resource server derives from the request it received. Registering one
    /// would be registering an audience nothing can check.
    ///
    /// The value is kept **exactly** as it was sent. RFC 8707 §2 says the
    /// comparison is a simple string comparison against what was registered,
    /// so normalising here would let two spellings of one identifier both
    /// match while a resource server, which does not normalise, matches
    /// neither.
    ///
    /// # Errors
    ///
    /// [`InvalidTarget`] for anything that is not an absolute, fragment-free,
    /// host-bearing URI within the length bound.
    // fuzz-target: resource_indicator
    pub fn parse(raw: &str) -> Result<Self, InvalidTarget> {
        if raw.is_empty() || raw.len() > MAX_IDENTIFIER_LEN {
            return Err(InvalidTarget);
        }
        // Checked before parsing as well as after: a fragment never reaches a
        // server, so two indicators differing only there name one resource
        // while looking like two.
        if raw.contains('#') {
            return Err(InvalidTarget);
        }
        let parsed = url::Url::parse(raw).map_err(|_| InvalidTarget)?;
        if parsed.fragment().is_some() || parsed.cannot_be_a_base() || !parsed.has_host() {
            return Err(InvalidTarget);
        }
        Ok(Self(raw.to_owned()))
    }

    /// The identifier, as it was registered and as it will be compared.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One registered resource server.
///
/// Deliberately not `#[non_exhaustive]`, like the other entities: the store
/// adapter builds these from rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceServer {
    /// The identifier a client names in `resource` and a token carries in
    /// `aud`.
    pub identifier: ResourceIdentifier,
    /// The scopes this resource server understands, or `None` for "whatever
    /// the grant carries".
    ///
    /// Three-valued on purpose. `None` is an operator who has not described
    /// the API's scopes and gets today's behaviour; `Some(set)` filters the
    /// `scope` claim down to what this API can act on (RFC 8707 §2, "the
    /// authorization server […] may restrict the scope"); and `Some(empty)` is
    /// a resource server that understands no scopes at all, which is a
    /// deliberate configuration rather than an accident of `NULL`.
    pub scopes: Option<BTreeSet<String>>,
    /// How long a token minted for this resource server should live, when the
    /// operator has an opinion.
    ///
    /// Recorded here and consumed by the lifetime story (`ast-5c6`); issuance
    /// keeps its own ceiling whatever this says.
    pub default_token_lifetime: Option<Duration>,
    /// The clients that speak *for* this resource server, and may therefore
    /// introspect the tokens audienced at it (RFC 7662 §2.1, `ast-1sk.1`).
    ///
    /// RFC 7662 §2.1: "the endpoint ... MUST ... require ... authorization",
    /// and §4: "the authorization server ... MUST only allow ... protected
    /// resources that are authorized to introspect" a given token. That is a
    /// relation between a *caller* and an *audience*, and this is where it is
    /// recorded: a resource server exists as a row already (RFC 8707 §3), and
    /// what was missing is which registered client is allowed to act as its
    /// mouth.
    ///
    /// # Why here and not on the client
    ///
    /// The alternative — a `resource_servers` list on the client
    /// registration — was considered and rejected. A resource server is a
    /// property of the deployment, which is the argument this module's opening
    /// section already makes for the registry existing at all; the operator
    /// who knows that `https://api.example/accounts` exists is the one who
    /// knows which credential fronts it. Putting the list on the client would
    /// also make it client metadata, which RFC 7591 §2 lets a client *send* at
    /// registration — an endpoint where a self-registering client would be
    /// naming the audiences it may read tokens for. There is no spelling of
    /// that which is not a privilege escalation, so the authority lives on the
    /// side no client can write.
    ///
    /// Empty is the default and means "no client introspects tokens for this
    /// resource server": a deployment that registers nothing here has an
    /// introspection endpoint only the token's own client can use, which is
    /// the narrowest thing §2.1 permits.
    pub introspection_clients: BTreeSet<crate::ClientId>,
}

impl ResourceServer {
    /// Whether this resource server understands `scope`.
    #[must_use]
    pub fn permits(&self, scope: &str) -> bool {
        self.scopes
            .as_ref()
            .is_none_or(|allowed| allowed.contains(scope))
    }

    /// Whether `caller` may introspect tokens audienced at this resource
    /// server (RFC 7662 §2.1).
    #[must_use]
    pub fn introspected_by(&self, caller: &crate::ClientId) -> bool {
        self.introspection_clients.contains(caller)
    }
}

/// One tenant's registered resource servers.
///
/// Built from a repository listing and consulted per request. Lookup is by the
/// exact identifier string, which is what RFC 8707 §2's simple string
/// comparison means.
#[derive(Debug, Clone, Default)]
pub struct ResourceRegistry(BTreeMap<String, ResourceServer>);

impl ResourceRegistry {
    /// Collects a listing into a registry, keeping at most
    /// [`MAX_REGISTERED`] entries.
    #[must_use]
    pub fn new<I: IntoIterator<Item = ResourceServer>>(servers: I) -> Self {
        Self(
            servers
                .into_iter()
                .take(MAX_REGISTERED)
                .map(|server| (server.identifier.as_str().to_owned(), server))
                .collect(),
        )
    }

    /// The resource server `raw` names, if this tenant registered one.
    ///
    /// # Errors
    ///
    /// [`InvalidTarget`] when `raw` is not a resource indicator at all, or is
    /// one this tenant has not registered.
    pub fn resolve(&self, raw: &str) -> Result<&ResourceServer, InvalidTarget> {
        let identifier = ResourceIdentifier::parse(raw)?;
        self.0.get(identifier.as_str()).ok_or(InvalidTarget)
    }

    /// Whether this tenant registered `raw`.
    #[must_use]
    pub fn registers(&self, raw: &str) -> bool {
        self.resolve(raw).is_ok()
    }

    /// Decides what an access token is audienced at.
    ///
    /// The one place that decision is made, for the authorization request
    /// (where `requested` is the `resource` parameters pushed and `authorised`
    /// is empty) and for the token request (where `authorised` is what the
    /// authorization request settled on).
    ///
    /// * `requested` — the `resource` values on the request being answered.
    /// * `authorised` — what the authorization request authorized, empty when
    ///   it named none.
    /// * `defaults` — this client's default audiences, used when neither of
    ///   the above names anything.
    ///
    /// The rules, in the order RFC 8707 states them:
    ///
    /// 1. every `requested` value is a resource indicator this tenant
    ///    registered (§2, §3);
    /// 2. the authorized set is `authorised`, or `defaults` when the
    ///    authorization request named no resource;
    /// 3. `requested` MUST be a subset of that set (§2.2) — a token request
    ///    cannot reach past its own authorization;
    /// 4. the result is `requested`, or the whole authorized set when the
    ///    request named none;
    /// 5. that result is non-empty, registered and within
    ///    [`crate::Grant::MAX_RESOURCES`], or there is no token to issue.
    ///
    /// # Errors
    ///
    /// [`InvalidTarget`] whenever any of those does not hold.
    pub fn targets(
        &self,
        requested: &BTreeSet<String>,
        authorised: &BTreeSet<String>,
        defaults: &BTreeSet<String>,
    ) -> Result<BTreeSet<String>, InvalidTarget> {
        // (1) Registered, whatever else is true. Done first so that a value
        // this deployment never heard of is refused before it is compared
        // against anything a client could learn from.
        for value in requested {
            self.resolve(value)?;
        }

        // (2) What this request is allowed to reach. A defaulted set is
        // filtered to what is registered — a client allow-list or a tenant
        // default naming a resource server that has since been withdrawn must
        // not keep minting tokens for it.
        let permitted: BTreeSet<String> = if authorised.is_empty() {
            defaults
                .iter()
                .filter(|value| self.registers(value))
                .cloned()
                .collect()
        } else {
            authorised.clone()
        };

        // (3) RFC 8707 §2.2: "the requested resources MUST be a subset of the
        // resources authorized".
        if !requested.iter().all(|value| permitted.contains(value)) {
            return Err(InvalidTarget);
        }

        // (4) The narrowest reading of the request that is still what it asked
        // for: a token request that named resources gets exactly those.
        let chosen = if requested.is_empty() {
            permitted
        } else {
            requested.clone()
        };

        // (5) No audience, no token (RFC 9068 §2.2, §3).
        if chosen.is_empty() || chosen.len() > crate::Grant::MAX_RESOURCES {
            return Err(InvalidTarget);
        }
        for value in &chosen {
            self.resolve(value)?;
        }
        Ok(chosen)
    }

    /// Whether `caller` is a registered resource server for **any** of the
    /// audiences a token names (RFC 7662 §2.1, §4).
    ///
    /// Any and not all, and that is the reading of §4 this server takes. A
    /// token audienced at two APIs was issued to be presented at each of them
    /// in turn; the one it is presented at is entitled to decide whether to
    /// act on it, and that decision is what introspection answers. Requiring
    /// the caller to front *every* audience would mean a token for two APIs
    /// could be introspected by neither, which is not a narrower rule — it is
    /// a broken one, and the deployments that hit it would answer it by
    /// issuing single-audience tokens, ending up in the same place with more
    /// tokens in flight.
    ///
    /// What the caller learns is bounded accordingly: the response is the
    /// token's own claims, and every audience named in it is one the caller
    /// can already read out of a token presented to it.
    ///
    /// An audience this tenant no longer registers matches nothing, so
    /// withdrawing a resource server withdraws its introspection rights in the
    /// same act.
    #[must_use]
    pub fn introspects<'a>(
        &self,
        caller: &crate::ClientId,
        audiences: impl IntoIterator<Item = &'a str>,
    ) -> bool {
        audiences.into_iter().any(|audience| {
            self.0
                .get(audience)
                .is_some_and(|server| server.introspected_by(caller))
        })
    }

    /// The scopes a token for `targets` may carry.
    ///
    /// `granted` is what the grant holds; the result is the subset every named
    /// resource server understands. Intersection rather than union, because
    /// the token is presented to each of them in turn: a scope one API accepts
    /// and another does not, carried in a token audienced at both, is authority
    /// the second one was never asked about.
    ///
    /// A resource server with no scope list restricts nothing, so a tenant that
    /// has described none gets its grants back untouched.
    #[must_use]
    pub fn permitted_scopes(
        &self,
        targets: &BTreeSet<String>,
        granted: &BTreeSet<String>,
    ) -> BTreeSet<String> {
        granted
            .iter()
            .filter(|scope| {
                targets.iter().all(|target| {
                    self.0
                        .get(target.as_str())
                        .is_none_or(|server| server.permits(scope))
                })
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(identifier: &str, scopes: Option<&[&str]>) -> ResourceServer {
        ResourceServer {
            identifier: ResourceIdentifier::parse(identifier).expect("a test identifier"),
            scopes: scopes.map(|s| s.iter().map(|s| (*s).to_owned()).collect()),
            default_token_lifetime: None,
            introspection_clients: BTreeSet::new(),
        }
    }

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    fn fronted_by(identifier: &str, callers: &[&str]) -> ResourceServer {
        ResourceServer {
            introspection_clients: callers.iter().map(|c| crate::ClientId::new(*c)).collect(),
            ..server(identifier, None)
        }
    }

    /// RFC 7662 §2.1: the caller must be authorized for *this* token. A client
    /// the operator registered as the mouth of an API introspects the tokens
    /// audienced at that API.
    #[test]
    fn a_registered_resource_server_introspects_its_own_audience() {
        // Arrange
        let registry = ResourceRegistry::new([fronted_by(
            "https://api.example/accounts",
            &["accounts-api"],
        )]);

        // Act
        let allowed = registry.introspects(
            &crate::ClientId::new("accounts-api"),
            ["https://api.example/accounts"],
        );

        // Assert
        assert!(allowed);
    }

    /// §4: only the protected resources that are authorized. A client that
    /// fronts one API learns nothing about another's tokens.
    #[test]
    fn a_resource_server_does_not_introspect_another_audience() {
        // Arrange
        let registry = ResourceRegistry::new([
            fronted_by("https://api.example/accounts", &["accounts-api"]),
            fronted_by("https://api.example/payments", &["payments-api"]),
        ]);

        // Act
        let allowed = registry.introspects(
            &crate::ClientId::new("accounts-api"),
            ["https://api.example/payments"],
        );

        // Assert
        assert!(!allowed);
    }

    /// A token audienced at two APIs is introspectable by each of them: the
    /// one it is presented at is the one entitled to decide about it.
    #[test]
    fn any_named_audience_is_enough() {
        // Arrange
        let registry = ResourceRegistry::new([
            fronted_by("https://api.example/accounts", &["accounts-api"]),
            fronted_by("https://api.example/payments", &["payments-api"]),
        ]);

        // Act
        let allowed = registry.introspects(
            &crate::ClientId::new("payments-api"),
            [
                "https://api.example/accounts",
                "https://api.example/payments",
            ],
        );

        // Assert
        assert!(allowed);
    }

    /// Withdrawing a resource server withdraws its introspection rights in the
    /// same act: an audience nobody registers matches nothing.
    #[test]
    fn an_unregistered_audience_authorises_nobody() {
        // Arrange
        let registry = ResourceRegistry::new([fronted_by(
            "https://api.example/accounts",
            &["accounts-api"],
        )]);

        // Act
        let allowed = registry.introspects(
            &crate::ClientId::new("accounts-api"),
            ["https://api.example/withdrawn"],
        );

        // Assert
        assert!(!allowed);
    }

    /// The default is the narrow one: a resource server nobody was registered
    /// to front is introspected by nobody, not by everybody.
    #[test]
    fn a_resource_server_with_no_registered_caller_authorises_nobody() {
        // Arrange
        let registry = ResourceRegistry::new([server("https://api.example/accounts", None)]);

        // Act
        let allowed = registry.introspects(
            &crate::ClientId::new("accounts-api"),
            ["https://api.example/accounts"],
        );

        // Assert
        assert!(!allowed);
    }

    /// A token with no audience at all authorises nobody. RFC 9068 §2.2 makes
    /// `aud` required, so this is not a token this server mints — and an empty
    /// iterator must not fall through to "allowed".
    #[test]
    fn no_audience_authorises_nobody() {
        // Arrange
        let registry = ResourceRegistry::new([fronted_by(
            "https://api.example/accounts",
            &["accounts-api"],
        )]);

        // Act
        let allowed = registry.introspects(&crate::ClientId::new("accounts-api"), []);

        // Assert
        assert!(!allowed);
    }

    /// RFC 8707 §2: "an absolute URI […] MUST NOT include a fragment
    /// component".
    #[test]
    fn a_fragment_a_relative_uri_or_a_non_uri_is_not_a_resource_indicator() {
        for wrong in [
            "https://api.example/v1#section",
            "https://api.example/#",
            "/v1/accounts",
            "api.example/v1",
            "",
            "not a uri",
            "https://",
            // Absolute, but no authority to derive from a request.
            "urn:example:api",
            "mailto:api@example.com",
        ] {
            assert_eq!(
                ResourceIdentifier::parse(wrong),
                Err(InvalidTarget),
                "accepted {wrong:?} as a resource indicator"
            );
        }
    }

    /// RFC 8707 §2: the value is compared as it was sent, so it is kept as it
    /// was sent.
    #[test]
    fn an_absolute_uri_is_kept_exactly_as_it_was_sent() {
        for good in [
            "https://api.example/",
            "https://api.example/v1/accounts",
            "https://api.example:8443/v1?tenant=a",
            "http://localhost:9443/mcp",
        ] {
            let parsed = ResourceIdentifier::parse(good).expect("a resource indicator");
            assert_eq!(parsed.as_str(), good);
        }
    }

    /// A bound on attacker-controlled bytes, before any parsing.
    #[test]
    fn an_overlong_value_is_refused() {
        let long = format!("https://api.example/{}", "a".repeat(MAX_IDENTIFIER_LEN));
        assert_eq!(ResourceIdentifier::parse(&long), Err(InvalidTarget));
    }

    /// RFC 8707 §3: the authorization server validates the parameter against
    /// what it knows, so an unregistered value is refused however well formed.
    #[test]
    fn an_unregistered_resource_is_invalid_target() {
        let registry = ResourceRegistry::new([server("https://api.example/", None)]);
        assert!(registry.registers("https://api.example/"));
        assert_eq!(
            registry.resolve("https://other.example/"),
            Err(InvalidTarget)
        );
    }

    /// RFC 8707 §2.2: "the requested resources MUST be a subset of the
    /// resources authorized".
    #[test]
    fn a_token_request_cannot_reach_past_its_authorization() {
        let registry = ResourceRegistry::new([
            server("https://api.example/", None),
            server("https://other.example/", None),
        ]);
        assert_eq!(
            registry.targets(
                &set(&["https://other.example/"]),
                &set(&["https://api.example/"]),
                &BTreeSet::new(),
            ),
            Err(InvalidTarget)
        );
        assert_eq!(
            registry
                .targets(
                    &set(&["https://api.example/"]),
                    &set(&["https://api.example/", "https://other.example/"]),
                    &BTreeSet::new(),
                )
                .expect("a subset of the authorized set"),
            set(&["https://api.example/"])
        );
    }

    /// RFC 9068 §2.2 makes `aud` REQUIRED: a client naming nothing and holding
    /// no default audience gets an error rather than a token.
    #[test]
    fn no_resource_and_no_default_audience_is_invalid_target() {
        let registry = ResourceRegistry::new([server("https://api.example/", None)]);
        assert_eq!(
            registry.targets(&BTreeSet::new(), &BTreeSet::new(), &BTreeSet::new()),
            Err(InvalidTarget)
        );
    }

    /// RFC 9068 §3: with no `resource` on the request, the default audience is
    /// what fills `aud` — and only the registered part of it.
    #[test]
    fn a_default_audience_is_used_and_is_filtered_to_what_is_registered() {
        let registry = ResourceRegistry::new([server("https://api.example/", None)]);
        assert_eq!(
            registry
                .targets(
                    &BTreeSet::new(),
                    &BTreeSet::new(),
                    &set(&["https://api.example/", "https://withdrawn.example/"]),
                )
                .expect("the registered half of the defaults"),
            set(&["https://api.example/"])
        );
        assert_eq!(
            registry.targets(
                &BTreeSet::new(),
                &BTreeSet::new(),
                &set(&["https://withdrawn.example/"]),
            ),
            Err(InvalidTarget),
            "a default audience nobody registers is no audience at all"
        );
    }

    /// RFC 8707 §2: several `resource` parameters are allowed, and this server
    /// takes the option — one token, an `aud` array.
    #[test]
    fn two_resources_are_one_token_audienced_at_both() {
        let registry = ResourceRegistry::new([
            server("https://api.example/", None),
            server("https://other.example/", None),
        ]);
        let both = set(&["https://api.example/", "https://other.example/"]);
        assert_eq!(
            registry
                .targets(&both, &both, &BTreeSet::new())
                .expect("both resources"),
            both
        );
    }

    /// FAPI 2.0 SP §5.3.2.1 item 14, and the bound a grant carries: an
    /// audience past it is no longer least privilege.
    #[test]
    fn more_targets_than_a_grant_may_hold_are_refused() {
        let many: Vec<ResourceServer> = (0..=crate::Grant::MAX_RESOURCES)
            .map(|i| server(&format!("https://api{i}.example/"), None))
            .collect();
        let all: BTreeSet<String> = many
            .iter()
            .map(|s| s.identifier.as_str().to_owned())
            .collect();
        let registry = ResourceRegistry::new(many);
        assert_eq!(
            registry.targets(&all, &all, &BTreeSet::new()),
            Err(InvalidTarget)
        );
    }

    /// RFC 8707 §2: the authorization server may restrict the scopes a token
    /// carries to what the named resource understands.
    #[test]
    fn scopes_are_filtered_to_what_the_resource_server_understands() {
        let registry = ResourceRegistry::new([server("https://api.example/", Some(&["read"]))]);
        assert_eq!(
            registry.permitted_scopes(
                &set(&["https://api.example/"]),
                &set(&["read", "write", "openid"]),
            ),
            set(&["read"])
        );
    }

    /// A token audienced at two resource servers carries only what both accept:
    /// widening the audience must not widen the authority.
    #[test]
    fn two_resources_carry_only_the_scopes_both_understand() {
        let registry = ResourceRegistry::new([
            server("https://api.example/", Some(&["read", "write"])),
            server("https://other.example/", Some(&["read"])),
        ]);
        assert_eq!(
            registry.permitted_scopes(
                &set(&["https://api.example/", "https://other.example/"]),
                &set(&["read", "write"]),
            ),
            set(&["read"])
        );
    }

    /// An operator who has described no scopes restricts none: the grant's own
    /// scopes are what the token carries.
    #[test]
    fn a_resource_server_with_no_scope_list_restricts_nothing() {
        let registry = ResourceRegistry::new([server("https://api.example/", None)]);
        assert_eq!(
            registry.permitted_scopes(&set(&["https://api.example/"]), &set(&["read", "openid"])),
            set(&["read", "openid"])
        );
    }
}
