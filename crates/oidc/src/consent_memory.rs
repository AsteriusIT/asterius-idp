//! What the user has already agreed to, read off the grants they agreed it in.
//!
//! Without this, every authorization shows the consent screen and OIDC Core
//! §3.1.2.1's `prompt=none` can never succeed: a server with no memory of past
//! consent must answer `consent_required`, because consent genuinely is
//! required. `asterius_oidc::decision` says so in as many words and leaves
//! [`crate::decision::Consent::Granted`] as the seam. This module is what fills
//! it.
//!
//! # There is no consent table
//!
//! The grant *is* the consent record. `ast-1sk.6` made that structural —
//! [`crate::claims::record_on_grant`] copies the consented claims request onto
//! the grant and [`crate::claims::resolve_for_grant`] reads nothing else at
//! issuance — and a second store of "what this user agreed to" would be a
//! second answer to the same question, free to disagree with the first. So the
//! memory is *derived*: [`Remembered::of_client`] folds the grants a user
//! already holds for one client into the material those grants cover, and
//! nothing here can remember something no grant records.
//!
//! Three properties fall out of that choice rather than having to be
//! implemented:
//!
//! * **Revocation traverses the memory.** A revoked grant is not folded in, so
//!   the next authorization asks again. `PgGrantRepository::revoke` already
//!   marks the grant and its refresh tokens in one transaction; nothing extra
//!   is needed for the memory to follow, because the memory has no row of its
//!   own to leave behind.
//! * **Expiry traverses it too**, for the same reason: [`Grant::status`] is
//!   computed against the clock, so a lapsed grant stops being remembered at
//!   the instant it lapses rather than when a sweep gets to it.
//! * **Retention is already decided.** The `grants` table is `Rule::Kept` in
//!   `asterius_store_pg::retention::POLICY` — deleting a grant would delete the
//!   only row that can revoke the tokens minted from it — and this memory
//!   inherits that. The one lifetime this module adds is
//!   [`MemoryPolicy::offline_access_memory`], enforced when the memory is
//!   *read* rather than by deleting anything, so the grant that is still
//!   revocable does not stop being revocable when its consent goes stale.
//!
//! # Remembering is deciding not to ask
//!
//! Which makes the dangerous failure silent widening: a consent remembered for
//! `openid` must never cover `openid payments` asked for a minute later. Every
//! comparison here is therefore *subset*, per dimension, and the delta — what
//! is asked for and not remembered — is what a caller shows. Nothing is
//! remembered "approximately": an `authorization_details` element is compared
//! as its canonical JSON text, and a claims request is compared as the set of
//! (destination, claim) pairs it would disclose, because that set is the
//! disclosure surface and the per-claim `essential`/`value`/`values` members
//! only ever narrow what comes back.
//!
//! # `offline_access` is not remembered like a scope
//!
//! OIDC Core §11: the OP "MUST obtain explicit consent" before returning a
//! refresh token for `offline_access`, because it is the difference between
//! acting while the user is watching and acting for months while they are not.
//! FAPI 2.0 Security Profile §6.1 makes the same point from the attacker's
//! side — a long-lived grant is a credential an attacker has a long time to
//! use — and asks that its lifetime be bounded rather than open-ended.
//!
//! So this module treats it as a scope with an expiry date of its own.
//! Remembered `offline_access` covers a new request only while the consent that
//! produced it is younger than [`MemoryPolicy::offline_access_memory`]
//! ([`DEFAULT_OFFLINE_ACCESS_MEMORY`], ninety days). After that the scope is in
//! the delta and the screen is shown again — the grant is untouched and any
//! refresh token still works; what has expired is this server's licence to
//! renew the arrangement without saying so. Ninety days is the shortest period
//! that does not put a quarterly-used application in front of the screen every
//! time, and the longest over which "I agreed to this" is a claim about a thing
//! the person can still be expected to remember.

use std::collections::BTreeSet;

use asterius_domain::{ClientId, Grant, SubjectId};
use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::claims::ClaimsRequest;
use crate::decision::Consent;

/// The scope that asks for a refresh token (OIDC Core §11).
pub const OFFLINE_ACCESS: &str = "offline_access";

/// How long a remembered `offline_access` consent stands by default.
///
/// See the module documentation for why this is bounded at all and why ninety
/// days is where it is bounded.
pub const DEFAULT_OFFLINE_ACCESS_MEMORY: Duration = Duration::days(90);

/// What the tenant does with a consent it could remember.
///
/// Both members are deployment decisions rather than protocol ones, which is
/// why they are here and not read off the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryPolicy {
    /// Show the consent screen on every authorization, whatever is remembered.
    ///
    /// The "always ask" switch. `false` by default: a deployment that asks a
    /// person the same question every morning trains them to answer without
    /// reading it, which is the consent failure FAPI 2.0 SP §7 calls
    /// insufficient understanding. A tenant that would rather have the
    /// friction can have it, and it is expressed here rather than by not
    /// calling this module, so that the audit trail says which it was.
    pub always_ask: bool,
    /// How long a remembered `offline_access` consent covers a new request.
    pub offline_access_memory: Duration,
}

impl Default for MemoryPolicy {
    fn default() -> Self {
        Self {
            always_ask: false,
            offline_access_memory: DEFAULT_OFFLINE_ACCESS_MEMORY,
        }
    }
}

impl MemoryPolicy {
    /// A tenant that remembers, or one that always asks.
    ///
    /// A constructor because the type is `#[non_exhaustive]`; the
    /// `offline_access` window keeps its default, which is the only value a
    /// tenant has any business not choosing deliberately.
    #[must_use]
    pub const fn new(always_ask: bool) -> Self {
        Self {
            always_ask,
            offline_access_memory: DEFAULT_OFFLINE_ACCESS_MEMORY,
        }
    }
}

/// The material one authorization asks the user to agree to.
///
/// Four dimensions, because those are the four things a grant records and a
/// person can be asked about separately. They are compared as sets: this type
/// is used both for what is asked and for what is remembered, so a comparison
/// that means "covers" in one direction means "delta" in the other and there
/// is only one shape to get wrong.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Asked {
    /// Scope tokens, including `offline_access` when it was asked for.
    pub scopes: BTreeSet<String>,
    /// The claims a §5.5 request would disclose, as `id_token:name` and
    /// `userinfo:name`.
    ///
    /// A flattened set rather than a [`ClaimsRequest`] because what matters for
    /// consent is *which claims go where*: the destination is part of the
    /// question — a claim in an ID token reaches the client, a claim at
    /// UserInfo reaches whoever holds the access token — and folding the two
    /// together would let a consent for one cover the other.
    pub claims: BTreeSet<String>,
    /// RFC 9396 `authorization_details` elements, as canonical JSON text.
    ///
    /// Compared verbatim. A per-type notion of "this element is covered by
    /// that one" is a decision for the RAR story and every guess at it here
    /// would widen: two elements that differ in one field differ in what they
    /// authorise, and this module cannot know in which direction.
    pub authorization_details: BTreeSet<String>,
    /// RFC 8707 resource indicators.
    pub resources: BTreeSet<String>,
}

impl Asked {
    /// Whether this asks for nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
            && self.claims.is_empty()
            && self.authorization_details.is_empty()
            && self.resources.is_empty()
    }

    /// Reads what a stored authorization request asks for.
    ///
    /// `parameters` is `http::par::serialise`'s output — this server's own
    /// JSON, holding the *parsed* request, so this is a read rather than a
    /// second parse of anything a client wrote. A member that is missing or the
    /// wrong shape asks for nothing on that dimension, which is the reading
    /// that cannot widen: a claims request this server fails to read back is
    /// then absent from `asked`, so it cannot be found "covered".
    #[must_use]
    pub fn from_parameters(parameters: &Value) -> Self {
        let strings = |name: &str| -> BTreeSet<String> {
            parameters
                .get(name)
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let claims = parameters
            .get("claims")
            .and_then(|value| ClaimsRequest::from_json(value).ok())
            .map(|request| claims_surface(&request))
            .unwrap_or_default();
        Self {
            scopes: strings("scopes"),
            claims,
            authorization_details: details_surface(parameters.get("authorization_details")),
            resources: strings("resources"),
        }
    }

    /// What this asks for and `other` does not.
    fn minus(&self, other: &Self) -> Self {
        let difference = |mine: &BTreeSet<String>, theirs: &BTreeSet<String>| -> BTreeSet<String> {
            mine.difference(theirs).cloned().collect()
        };
        Self {
            scopes: difference(&self.scopes, &other.scopes),
            claims: difference(&self.claims, &other.claims),
            authorization_details: difference(
                &self.authorization_details,
                &other.authorization_details,
            ),
            resources: difference(&self.resources, &other.resources),
        }
    }

    /// Folds `other` in, for the union across several grants.
    fn absorb(&mut self, other: Self) {
        self.scopes.extend(other.scopes);
        self.claims.extend(other.claims);
        self.authorization_details
            .extend(other.authorization_details);
        self.resources.extend(other.resources);
    }
}

/// The claims a request would disclose, as `destination:name`.
fn claims_surface(request: &ClaimsRequest) -> BTreeSet<String> {
    let section = |prefix: &'static str,
                   claims: &std::collections::BTreeMap<
        crate::claims::ReleasableClaim,
        crate::claims::ClaimRequest,
    >| {
        claims
            .keys()
            .map(move |claim| format!("{prefix}:{}", claim.as_str()))
            .collect::<Vec<_>>()
    };
    let mut surface: BTreeSet<String> = section("id_token", request.id_token())
        .into_iter()
        .collect();
    surface.extend(section("userinfo", request.userinfo()));
    surface
}

/// The `authorization_details` elements, as canonical JSON text.
fn details_surface(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .map(|elements| elements.iter().map(ToString::to_string).collect())
        .unwrap_or_default()
}

/// What one user has already agreed to for one client.
///
/// Built by [`Remembered::of_client`] and never by hand: the only thing that
/// can put material in here is a grant that still stands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Remembered {
    /// How many grants were folded in.
    ///
    /// Not a statistic: it is the difference between "this is covered" and
    /// "nothing was asked for". An empty [`Asked`] is a subset of every set,
    /// so a difference-based rule alone would call a request whose parameters
    /// could not be read *covered by a memory that does not exist* — which is
    /// consent inferred from an absence. Zero grants therefore means zero
    /// consent, whatever the arithmetic says.
    grants: usize,
    /// The union of what the live grants cover, `offline_access` excluded.
    covered: Asked,
    /// When `offline_access` was most recently consented to, if it ever was.
    ///
    /// Held apart from [`Self::covered`] so that no code path can treat it as
    /// an ordinary scope and skip the window check. See the module
    /// documentation.
    offline_access_at: Option<OffsetDateTime>,
}

impl Remembered {
    /// Folds every grant that still stands for `client` and `subject`.
    ///
    /// `grants` may hold a whole subject's grants across every client; the
    /// filtering is here rather than in the query so that "which grants count"
    /// is a rule with a test rather than a `where` clause. A grant that is
    /// revoked or expired is not folded in — [`Grant::status`]'s
    /// `may_issue` is the same predicate that decides whether a token could be
    /// minted from it, which is the right one: a grant nothing may be issued
    /// from is not a standing agreement.
    #[must_use]
    pub fn of_client(
        grants: &[Grant],
        client: &ClientId,
        subject: &SubjectId,
        now: OffsetDateTime,
    ) -> Self {
        let mut remembered = Self::default();
        for grant in grants {
            if &grant.client != client
                || grant.subject.as_ref() != Some(subject)
                || !grant.status(now).may_issue()
            {
                continue;
            }
            let mut covered = Asked {
                scopes: grant.scopes.clone(),
                claims: ClaimsRequest::from_json(&grant.claims)
                    .map(|request| claims_surface(&request))
                    .unwrap_or_default(),
                authorization_details: grant
                    .authorization_details
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                resources: grant.resources.clone(),
            };
            if covered.scopes.remove(OFFLINE_ACCESS) {
                // The most recent explicit consent is the one the window runs
                // from: a user who agreed again last week has agreed again.
                remembered.offline_access_at = remembered
                    .offline_access_at
                    .map_or(Some(grant.created_at), |held| {
                        Some(held.max(grant.created_at))
                    });
            }
            remembered.grants += 1;
            remembered.covered.absorb(covered);
        }
        remembered
    }

    /// What is left to ask about.
    ///
    /// The whole of the widening rule is here: the answer is the *difference*,
    /// so a dimension that is remembered contributes nothing and a dimension
    /// that is not contributes exactly what is new. There is no path that
    /// returns [`Coverage::Covered`] for material this memory does not hold.
    // fuzz-target: consent_memory
    #[must_use]
    pub fn covers(&self, asked: &Asked, policy: MemoryPolicy, now: OffsetDateTime) -> Coverage {
        if policy.always_ask || self.grants == 0 {
            // Full re-consent, and the delta is everything. Not `Covered` with
            // a flag somewhere: the caller renders the delta, so the tenant
            // switch has to change the delta or it changes nothing.
            //
            // A user with no standing grant takes the same road, and it is the
            // same reason: there is no consent here, so there is nothing this
            // function may subtract from what is being asked.
            return Coverage::Delta(asked.clone());
        }

        let wants_offline = asked.scopes.contains(OFFLINE_ACCESS);
        let mut delta = asked.minus(&self.covered);
        // `covered` never holds `offline_access`, so the difference above has
        // already put it in the delta. It is taken back out only by an explicit
        // consent that is still inside its window.
        if wants_offline && self.offline_access_is_fresh(policy, now) {
            delta.scopes.remove(OFFLINE_ACCESS);
        }

        if delta.is_empty() {
            Coverage::Covered
        } else {
            Coverage::Delta(delta)
        }
    }

    /// Whether an `offline_access` consent was given and is still inside the
    /// tenant's window.
    fn offline_access_is_fresh(&self, policy: MemoryPolicy, now: OffsetDateTime) -> bool {
        self.offline_access_at
            .is_some_and(|at| at + policy.offline_access_memory > now)
    }
}

/// Whether the screen can be skipped, and what it must show when it cannot.
///
/// Deliberately carries the delta rather than a `bool`. The acceptance
/// criterion is that a new scope prompts "limited to the delta", and a boolean
/// answer would leave every caller to recompute which part was new — which is
/// the recomputation that eventually disagrees with the one that decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coverage {
    /// Everything asked for is already agreed to. No screen.
    Covered,
    /// Something is new. This is the part the user has not agreed to.
    Delta(Asked),
}

impl Coverage {
    /// The answer `asterius_oidc::decision` wants.
    #[must_use]
    pub const fn consent(&self) -> Consent {
        match self {
            Self::Covered => Consent::Granted,
            Self::Delta(_) => Consent::Required,
        }
    }

    /// What is new, or nothing.
    #[must_use]
    pub const fn delta(&self) -> Option<&Asked> {
        match self {
            Self::Covered => None,
            Self::Delta(delta) => Some(delta),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::TenantId;
    use serde_json::json;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::days(20_000)
    }

    fn client() -> ClientId {
        ClientId::new("billing")
    }

    fn subject() -> SubjectId {
        SubjectId::new("sub-1")
    }

    fn asked(scopes: &[&str]) -> Asked {
        Asked {
            scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            ..Asked::default()
        }
    }

    /// A grant made `age` before [`now`], covering `scopes`.
    fn grant(scopes: &[&str], age: Duration) -> Grant {
        let mut grant = Grant::new(TenantId::new("demo"), client(), now() - age);
        grant.subject = Some(subject());
        grant.scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
        grant
    }

    #[test]
    fn a_remembered_scope_does_not_widen_to_one_that_was_never_granted() {
        // Arrange: the user agreed to `openid` and nothing else.
        let remembered = Remembered::of_client(
            &[grant(&["openid"], Duration::days(1))],
            &client(),
            &subject(),
            now(),
        );

        // Act: the client comes back asking for more.
        let coverage = remembered.covers(
            &asked(&["openid", "payments"]),
            MemoryPolicy::default(),
            now(),
        );

        // Assert: the new scope is asked about, and only the new scope.
        assert_eq!(coverage.consent(), Consent::Required);
        assert_eq!(coverage.delta(), Some(&asked(&["payments"])));
    }

    #[test]
    fn a_previously_granted_superset_needs_no_screen() {
        let remembered = Remembered::of_client(
            &[grant(&["openid", "profile", "payments"], Duration::days(1))],
            &client(),
            &subject(),
            now(),
        );

        let coverage = remembered.covers(
            &asked(&["openid", "profile"]),
            MemoryPolicy::default(),
            now(),
        );

        assert_eq!(coverage, Coverage::Covered);
        assert_eq!(coverage.consent(), Consent::Granted);
    }

    #[test]
    fn a_revoked_grant_is_not_remembered() {
        // Arrange: the user agreed, then withdrew it.
        let mut revoked = grant(&["openid", "payments"], Duration::days(1));
        revoked.revoked_at = Some(now() - Duration::hours(1));

        let remembered = Remembered::of_client(&[revoked], &client(), &subject(), now());

        // Assert: the next request is asked about in full.
        assert_eq!(
            remembered.covers(
                &asked(&["openid", "payments"]),
                MemoryPolicy::default(),
                now()
            ),
            Coverage::Delta(asked(&["openid", "payments"]))
        );
    }

    #[test]
    fn an_expired_grant_is_not_remembered() {
        let mut expired = grant(&["openid"], Duration::days(30));
        expired.expires_at = Some(now() - Duration::days(1));

        let remembered = Remembered::of_client(&[expired], &client(), &subject(), now());

        assert_eq!(
            remembered.covers(&asked(&["openid"]), MemoryPolicy::default(), now()),
            Coverage::Delta(asked(&["openid"]))
        );
    }

    #[test]
    fn another_clients_grant_is_not_remembered_for_this_one() {
        let mut elsewhere = grant(&["openid", "payments"], Duration::days(1));
        elsewhere.client = ClientId::new("somebody-else");

        let remembered = Remembered::of_client(&[elsewhere], &client(), &subject(), now());

        assert_eq!(
            remembered.covers(&asked(&["openid"]), MemoryPolicy::default(), now()),
            Coverage::Delta(asked(&["openid"]))
        );
    }

    #[test]
    fn another_subjects_grant_is_not_remembered_for_this_one() {
        let mut elsewhere = grant(&["openid"], Duration::days(1));
        elsewhere.subject = Some(SubjectId::new("sub-2"));

        let remembered = Remembered::of_client(&[elsewhere], &client(), &subject(), now());

        assert_eq!(
            remembered.covers(&asked(&["openid"]), MemoryPolicy::default(), now()),
            Coverage::Delta(asked(&["openid"]))
        );
    }

    #[test]
    fn offline_access_is_never_covered_by_an_ordinary_scope_consent() {
        // Arrange: a grant that says nothing about offline access.
        let remembered = Remembered::of_client(
            &[grant(&["openid", "profile"], Duration::days(1))],
            &client(),
            &subject(),
            now(),
        );

        // Act: the client now asks to act while the user is away.
        let coverage = remembered.covers(
            &asked(&["openid", "profile", OFFLINE_ACCESS]),
            MemoryPolicy::default(),
            now(),
        );

        // Assert: OIDC Core §11's explicit consent is asked for.
        assert_eq!(coverage.delta(), Some(&asked(&[OFFLINE_ACCESS])));
    }

    #[test]
    fn a_recent_offline_access_consent_is_remembered() {
        let remembered = Remembered::of_client(
            &[grant(&["openid", OFFLINE_ACCESS], Duration::days(30))],
            &client(),
            &subject(),
            now(),
        );

        assert_eq!(
            remembered.covers(
                &asked(&["openid", OFFLINE_ACCESS]),
                MemoryPolicy::default(),
                now()
            ),
            Coverage::Covered
        );
    }

    #[test]
    fn an_offline_access_consent_is_asked_for_again_once_its_window_has_passed() {
        // Arrange: agreed to, but longer ago than the tenant remembers.
        let remembered = Remembered::of_client(
            &[grant(&["openid", OFFLINE_ACCESS], Duration::days(91))],
            &client(),
            &subject(),
            now(),
        );

        // Act.
        let coverage = remembered.covers(
            &asked(&["openid", OFFLINE_ACCESS]),
            MemoryPolicy::default(),
            now(),
        );

        // Assert: only offline access is re-asked; the ordinary scopes stand.
        assert_eq!(coverage.delta(), Some(&asked(&[OFFLINE_ACCESS])));
    }

    #[test]
    fn the_always_ask_switch_asks_for_everything() {
        let remembered = Remembered::of_client(
            &[grant(&["openid", "payments"], Duration::days(1))],
            &client(),
            &subject(),
            now(),
        );

        let coverage = remembered.covers(
            &asked(&["openid", "payments"]),
            MemoryPolicy::new(true),
            now(),
        );

        assert_eq!(coverage.consent(), Consent::Required);
        assert_eq!(coverage.delta(), Some(&asked(&["openid", "payments"])));
    }

    #[test]
    fn a_claim_consented_for_the_id_token_is_not_covered_at_userinfo() {
        // Arrange: `email` was agreed to in the ID token only.
        let mut held = grant(&["openid"], Duration::days(1));
        held.claims = json!({"id_token": {"email": {}}, "userinfo": {}});
        let remembered = Remembered::of_client(&[held], &client(), &subject(), now());

        // Act: the same claim, asked for at the other endpoint.
        let coverage = remembered.covers(
            &Asked {
                scopes: ["openid".to_owned()].into(),
                claims: ["userinfo:email".to_owned()].into(),
                ..Asked::default()
            },
            MemoryPolicy::default(),
            now(),
        );

        // Assert: a different destination is a different disclosure.
        assert_eq!(
            coverage.delta().map(|delta| delta.claims.clone()),
            Some(["userinfo:email".to_owned()].into())
        );
    }

    #[test]
    fn a_new_resource_is_asked_about() {
        let mut held = grant(&["openid"], Duration::days(1));
        held.resources = ["https://api.example/one".to_owned()].into();
        let remembered = Remembered::of_client(&[held], &client(), &subject(), now());

        let coverage = remembered.covers(
            &Asked {
                scopes: ["openid".to_owned()].into(),
                resources: [
                    "https://api.example/one".to_owned(),
                    "https://api.example/two".to_owned(),
                ]
                .into(),
                ..Asked::default()
            },
            MemoryPolicy::default(),
            now(),
        );

        assert_eq!(
            coverage.delta().map(|delta| delta.resources.clone()),
            Some(["https://api.example/two".to_owned()].into())
        );
    }

    #[test]
    fn an_authorization_details_element_is_covered_only_verbatim() {
        let mut held = grant(&["openid"], Duration::days(1));
        held.authorization_details = vec![json!({"type": "payment", "amount": "10"})];
        let remembered = Remembered::of_client(&[held], &client(), &subject(), now());

        let coverage = remembered.covers(
            &Asked {
                scopes: ["openid".to_owned()].into(),
                authorization_details: [json!({"type": "payment", "amount": "20"}).to_string()]
                    .into(),
                ..Asked::default()
            },
            MemoryPolicy::default(),
            now(),
        );

        // A different amount is a different authorization.
        assert_eq!(coverage.consent(), Consent::Required);
    }

    /// The bug this rule exists to stop. An empty set is a subset of every
    /// set, so a request whose parameters this server could not read — no
    /// scopes, no claims, nothing — is arithmetically covered by a memory that
    /// holds nothing at all. It is not covered: nobody consented to anything.
    #[test]
    fn a_request_that_asks_for_nothing_is_not_covered_by_a_consent_that_does_not_exist() {
        // Arrange: a user who has never granted this client anything.
        let remembered = Remembered::of_client(&[], &client(), &subject(), now());

        // Act: a request that appears to ask for nothing.
        let coverage = remembered.covers(&Asked::default(), MemoryPolicy::default(), now());

        // Assert: the screen, not a silent completion.
        assert_eq!(coverage.consent(), Consent::Required);
    }

    #[test]
    fn nothing_is_remembered_for_a_user_with_no_grants() {
        let remembered = Remembered::of_client(&[], &client(), &subject(), now());

        assert_eq!(
            remembered.covers(&asked(&["openid"]), MemoryPolicy::default(), now()),
            Coverage::Delta(asked(&["openid"]))
        );
    }

    #[test]
    fn what_a_request_asks_for_is_read_off_the_stored_parameters() {
        let parameters = json!({
            "scopes": ["openid", "payments"],
            "resources": ["https://api.example/one"],
            "claims": {"id_token": {"email": {"essential": true}}, "userinfo": {}},
        });

        let asked = Asked::from_parameters(&parameters);

        assert_eq!(
            asked.scopes,
            ["openid".to_owned(), "payments".to_owned()].into()
        );
        assert_eq!(asked.claims, ["id_token:email".to_owned()].into());
        assert_eq!(
            asked.resources,
            ["https://api.example/one".to_owned()].into()
        );
        assert!(asked.authorization_details.is_empty());
    }

    #[test]
    fn an_unreadable_stored_claims_request_asks_for_nothing_rather_than_covering_something() {
        // A member this server cannot read back must not become a claim that
        // was consented to; it becomes a claim nobody asked for.
        let asked = Asked::from_parameters(&json!({"claims": "not an object"}));

        assert!(asked.claims.is_empty());
    }
}
