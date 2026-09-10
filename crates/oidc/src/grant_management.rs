//! The two Grant Management request parameters, and what they mean.
//!
//! Grant Management for OAuth 2.0, Implementer's Draft 1 (2023-07-10,
//! draft-03). §5.2 adds `grant_id` and `grant_management_action` to the
//! authorization request; §5.4 lists the ways a client can get them wrong;
//! §7.1 lets a deployment insist that every request name an action.
//!
//! # Why this is a module of its own, and a thin one
//!
//! The specification is an *Implementer's Draft*. Its parameter names, its
//! action list and its error codes are all still moving, and every one of them
//! is a string this server would otherwise have spelled out in the middle of
//! [`crate::authorize`], in the pushed-request endpoint, and again in the
//! handler that persists the grant. Keeping the whole vocabulary — the actions,
//! the errors, the combination rules — behind one small surface means a change
//! to the draft is a change to this file, and everything else keeps compiling
//! or stops compiling loudly.
//!
//! Two halves, and they run at different moments:
//!
//! * [`parse`] is the §5.4 validator. It is pure, it runs at the pushed
//!   authorization request, and it decides everything that can be decided from
//!   the parameters alone.
//! * [`Action::apply`] is §5.2's `merge`/`replace`, and it runs at the far end
//!   of the flow, once a person has signed in and consented, because that is
//!   when a grant is written.
//!
//! What is *not* here is the part that needs I/O: whether a `grant_id` names a
//! grant this tenant holds, whether that grant belongs to the client that
//! pushed the request, and whether it belongs to the person who eventually
//! signed in. Those are three lookups at three different moments and they live
//! with their callers — but they all report [`GrantManagementError::UnknownGrant`],
//! so the code a client sees is decided in one place.
//!
//! # Confidential clients only (§5.1)
//!
//! "Grant Management is only supported for confidential clients." Nothing in
//! this module checks it, and that is not an omission: ADR-0002 makes the
//! pushed authorization request the only way to start a flow here, and a push
//! is refused without client authentication (FAPI 2.0 SP §5.3.2.2 item 4). A
//! public client therefore never reaches a validator that could tell it so.
//! `a_public_client_cannot_reach_these_parameters_at_all` in the endpoint tests
//! is what keeps that argument honest.

use asterius_domain::Grant;
use std::collections::BTreeSet;

/// The longest `grant_id` this server will look up.
///
/// A grant id here is a v4 UUID — [`Grant::new`] mints it and nothing else can
/// — so 36 characters is the real length and this is generous. The bound
/// exists so that a flood of guesses costs a length comparison rather than a
/// database round trip, which is the same reasoning
/// [`crate::par::digest_of`] applies to a `request_uri`.
pub const MAX_GRANT_ID_LEN: usize = 64;

/// What a client asked to do with a grant (§5.2).
///
/// A closed enum rather than a string carried around, because §5.4 makes an
/// unrecognised action an error rather than a value to pass along: a server
/// that stored the string and looked at it later would have to decide what an
/// unknown one means at a point where the client is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Action {
    /// Start a new grant. The default posture, and what every request that
    /// names no action has always meant.
    Create,
    /// Add what this request asks for to the grant `grant_id` names.
    Merge,
    /// Make the grant `grant_id` names cover exactly what this request asks
    /// for, and nothing else.
    Replace,
}

impl Action {
    /// Every action this server implements, in the order §5.2 lists them.
    ///
    /// This is also the order `grant_management_actions_supported` is rendered
    /// in, so the metadata cannot advertise a value the parser refuses.
    pub const ALL: [Self; 3] = [Self::Create, Self::Merge, Self::Replace];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Merge => "merge",
            Self::Replace => "replace",
        }
    }

    /// Whether this action operates on a grant that already exists.
    ///
    /// §5.2: `merge` and `replace` "shall invalidate existing refresh tokens",
    /// which is only meaningful for a grant with a history. `create` has none.
    #[must_use]
    pub const fn needs_an_existing_grant(self) -> bool {
        matches!(self, Self::Merge | Self::Replace)
    }

    /// Parses one `grant_management_action` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|action| action.as_str() == value)
    }

    /// Rewrites `existing` to what §5.2 says this action leaves behind.
    ///
    /// `granted` is the grant this authorization would have created on its own
    /// — the scopes the person just approved, the resources, the rich
    /// authorization, the claims request and the language they asked to be
    /// answered in. `existing` is the row `grant_id` named, already checked by
    /// the caller to belong to this client and this person.
    ///
    /// * `replace`: "the AS shall replace the grant with the requested
    ///   privileges". `existing` ends up covering exactly what `granted` does.
    /// * `merge`: "the AS shall merge the requested privileges with those
    ///   already granted". The union, so nothing a person previously approved
    ///   is quietly withdrawn by a narrower request.
    ///
    /// **The identifier does not change.** §5.2 is explicit that the client
    /// keeps using the `grant_id` it already has, and a new one here would
    /// strand every access token carrying the old value.
    ///
    /// **The authentication does.** The person has just signed in, so the
    /// session, the `auth_time`, the `acr` and the `amr` recorded on the grant
    /// are this authorization's — not the one from a month ago. Reporting the
    /// older authentication would make `auth_time` in a refreshed ID token a
    /// lie about when the person was last there.
    ///
    /// `Action::Create` is a no-op: there is no existing grant to apply
    /// anything to, and a caller reaching here with it has already made its
    /// mistake. It is spelled as a no-op rather than a panic because this runs
    /// after consent, where a panic is a person's flow ending in a 500.
    ///
    /// # Errors
    ///
    /// [`MergeRefused`] when the union would exceed a bound a grant row must
    /// hold to. Only `merge` can reach it — `replace` cannot grow anything —
    /// and only through `authorization_details`, whose elements accumulate
    /// across merges where scopes and resources are drawn from the client's own
    /// bounded registration and so cannot.
    pub fn apply(
        self,
        existing: &mut Grant,
        granted: &Grant,
        now: time::OffsetDateTime,
    ) -> Result<(), MergeRefused> {
        match self {
            Self::Create => return Ok(()),
            Self::Replace => {
                existing.scopes.clone_from(&granted.scopes);
                existing.resources.clone_from(&granted.resources);
                existing
                    .authorization_details
                    .clone_from(&granted.authorization_details);
                existing.claims.clone_from(&granted.claims);
                existing.claims_locales.clone_from(&granted.claims_locales);
            }
            Self::Merge => {
                existing.scopes = union(&existing.scopes, &granted.scopes);
                existing.resources = union(&existing.resources, &granted.resources);
                existing.authorization_details = merged_details(
                    &existing.authorization_details,
                    &granted.authorization_details,
                )?;
                existing.claims = merged_claims(&existing.claims, &granted.claims);
                existing.claims_locales =
                    merged_locales(&existing.claims_locales, &granted.claims_locales);
            }
        }
        existing.session.clone_from(&granted.session);
        existing.authentication.clone_from(&granted.authentication);
        existing.subject.clone_from(&granted.subject);
        // Grant Management ID1 §6.4's `last_updated_at`. Set from the caller's
        // clock rather than from `granted.created_at`, so that the two grants a
        // merge touches cannot disagree about when it happened.
        existing.updated_at = now;
        Ok(())
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A `merge` that would produce a grant this server cannot store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "merging would exceed the {} authorization_details elements a grant may hold",
    asterius_domain::entities::authorization_details::MAX_ELEMENTS
)]
#[non_exhaustive]
pub struct MergeRefused;

/// What this tenant does with the two parameters.
///
/// Both fields are the conservative answer by default: a deployment that has
/// configured nothing does not offer Grant Management, and therefore cannot
/// require an action for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Policy {
    /// Whether [`asterius_domain::Feature::GrantManagement`] is on here.
    ///
    /// With it off, both parameters are ignored — not refused. A client that
    /// sends `grant_management_action` to a server whose metadata carries no
    /// `grant_management_actions_supported` has asked for something that was
    /// never advertised, and an ordinary authorization is what it gets, exactly
    /// as it would have from a server built before the draft existed.
    pub supported: bool,
    /// §7.1's `grant_management_action_required`: "the AS requires the
    /// `grant_management_action` parameter to be present in every authorization
    /// request".
    ///
    /// Only reachable when [`Self::supported`] is true. Requiring a parameter
    /// nobody may send would refuse every request this tenant receives, so
    /// [`Self::new`] will not build that combination.
    pub action_required: bool,
}

impl Policy {
    /// The policy of a tenant that offers Grant Management, or does not.
    ///
    /// `action_required` is forced false when the feature is off, because §7.1
    /// is a statement *about* Grant Management: a tenant that does not offer it
    /// cannot demand a parameter it also ignores. Making that impossible here
    /// rather than checking it at the two call sites is what keeps the metadata
    /// and the validator from ever disagreeing.
    #[must_use]
    pub const fn new(supported: bool, action_required: bool) -> Self {
        Self {
            supported,
            action_required: supported && action_required,
        }
    }
}

/// Why the two parameters were refused.
///
/// One variant per clause of §5.4, rather than one `invalid_request` with a
/// message: the clauses are what the tests are named after, and a client that
/// combined two mistakes should be told about the first in a way this server
/// can point at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GrantManagementError {
    /// §5.4: "`grant_management_action` is `create` and a `grant_id` is
    /// present".
    ///
    /// A client asking to create a grant and naming an existing one has
    /// contradicted itself, and neither reading is safe to guess: honouring the
    /// id would silently modify a grant the client asked to leave alone, and
    /// ignoring it would leave the client believing the id it sent still means
    /// something.
    #[error("grant_management_action=create cannot be combined with grant_id")]
    GrantIdWithCreate,
    /// §5.4: a `grant_id` with no `grant_management_action`.
    ///
    /// There is no default action for a request naming a grant. `merge` and
    /// `replace` differ in exactly what a person is agreeing to, so choosing
    /// one on the client's behalf would be consenting on its behalf.
    #[error("grant_id requires a grant_management_action")]
    ActionMissing,
    /// §5.4: `merge` or `replace` with no `grant_id`.
    #[error("grant_management_action={0} requires a grant_id")]
    GrantIdRequired(Action),
    /// §5.4: an action this server does not implement.
    ///
    /// Refused rather than ignored, for the reason
    /// [`crate::authorize::AuthorizationError::UnsupportedPrompt`] gives: a
    /// client that asked to `revoke` and got a `create` has been answered with
    /// something it did not ask for.
    #[error("grant_management_action is not one this server supports")]
    UnsupportedAction,
    /// §7.1: this tenant requires an action and the request named none.
    #[error("this tenant requires a grant_management_action on every authorization request")]
    ActionRequired,
    /// §5.4's `invalid_grant_id`: "the `grant_id` is invalid or unknown".
    ///
    /// Also what a malformed id gets, and deliberately: an id this server could
    /// not have minted is an id it does not hold, and giving it a code of its
    /// own would tell a caller which of its guesses were the right *shape*.
    #[error("grant_id is invalid or unknown")]
    UnknownGrant,
}

impl GrantManagementError {
    /// The OAuth 2.0 error code (§5.4).
    ///
    /// `invalid_grant_id` is registered by the draft itself; everything else is
    /// RFC 6749 §4.1.2.1's `invalid_request`, which is what §5.4 names for each
    /// of the four malformed-request cases.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnknownGrant => INVALID_GRANT_ID,
            Self::GrantIdWithCreate
            | Self::ActionMissing
            | Self::GrantIdRequired(_)
            | Self::UnsupportedAction
            | Self::ActionRequired => "invalid_request",
        }
    }
}

/// The error code §5.4 registers for a `grant_id` the AS will not act on.
pub const INVALID_GRANT_ID: &str = "invalid_grant_id";

/// What a request asked for, once §5.4 is satisfied.
///
/// An `Option<GrantManagement>` is the whole return of [`parse`]: `None` is an
/// ordinary authorization, which is every request on a deployment with the flag
/// off and most requests on one with it on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GrantManagement {
    /// What to do.
    pub action: Action,
    /// Which grant to do it to. `Some` exactly when
    /// [`Action::needs_an_existing_grant`], which [`parse`] is what guarantees.
    pub grant_id: Option<String>,
}

impl GrantManagement {
    /// The grant this request names, for the caller that has to look it up.
    #[must_use]
    pub fn grant_id(&self) -> Option<&str> {
        self.grant_id.as_deref()
    }
}

/// Validates `grant_management_action` and `grant_id` together (§5.4).
///
/// The two parameters only mean anything as a pair, so they are parsed as one:
/// three of §5.4's four `invalid_request` clauses are about the *combination*,
/// and a validator that looked at each parameter alone could not state them.
///
/// Returns `Ok(None)` for a request that asked for nothing — including every
/// request that arrives with the feature off, whatever it carried.
///
/// # Errors
///
/// The [`GrantManagementError`] for the first clause of §5.4 or §7.1 the
/// request breaks.
// fuzz-target: grant_management
pub fn parse(
    action: Option<&str>,
    grant_id: Option<&str>,
    policy: Policy,
) -> Result<Option<GrantManagement>, GrantManagementError> {
    if !policy.supported {
        // Both parameters ignored, and no error: see `Policy::supported`.
        return Ok(None);
    }

    // An empty parameter is an absent one. RFC 6749 §3.1 says a parameter "with
    // no value" is to be omitted, and a form encoder that writes `grant_id=`
    // for a value its caller left unset is common enough that reading it as a
    // present-but-unknown id would refuse requests nobody meant to make.
    let action = action.filter(|value| !value.is_empty());
    let grant_id = grant_id.filter(|value| !value.is_empty());

    let Some(action) = action else {
        // §5.4: "the `grant_id` is present but `grant_management_action` is
        // missing". Checked before §7.1, because a client that named a grant
        // has made a more specific mistake than one that named nothing.
        if grant_id.is_some() {
            return Err(GrantManagementError::ActionMissing);
        }
        // §7.1.
        if policy.action_required {
            return Err(GrantManagementError::ActionRequired);
        }
        return Ok(None);
    };

    let action = Action::parse(action).ok_or(GrantManagementError::UnsupportedAction)?;

    match (action, grant_id) {
        (Action::Create, Some(_)) => Err(GrantManagementError::GrantIdWithCreate),
        (Action::Create, None) => Ok(Some(GrantManagement {
            action,
            grant_id: None,
        })),
        (_, None) => Err(GrantManagementError::GrantIdRequired(action)),
        (_, Some(id)) => {
            if !is_plausible_grant_id(id) {
                return Err(GrantManagementError::UnknownGrant);
            }
            Ok(Some(GrantManagement {
                action,
                grant_id: Some(id.to_owned()),
            }))
        }
    }
}

/// Whether a `grant_id` is one this server could have minted.
///
/// Shape only, and checked before the database is touched. [`Grant::new`] mints
/// a v4 UUID, so the alphabet is hexadecimal and hyphens; anything else is an
/// id this tenant does not hold, and saying so without a query is what keeps a
/// guessing flood cheap.
///
/// Not a full UUID parse, deliberately. The storage adapter parses the id
/// properly and this must not become a second, subtly different rule about what
/// a grant id is — its job is to be a cheap and *conservative* filter in front
/// of that one.
#[must_use]
fn is_plausible_grant_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_GRANT_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

/// The union of two scope or resource sets.
///
/// Cannot exceed [`Grant::MAX_SCOPES`] or [`Grant::MAX_RESOURCES`]: both sides
/// are subsets of the same client's registration, which is bounded by the same
/// numbers, so their union is a subset of it too.
fn union(existing: &BTreeSet<String>, granted: &BTreeSet<String>) -> BTreeSet<String> {
    existing.union(granted).cloned().collect()
}

/// The union of two `authorization_details` arrays, by element equality.
///
/// RFC 9396 §2 elements are JSON objects with no identity of their own, so
/// "already granted" can only mean "an identical element is already there".
/// Comparing whole elements is the conservative reading: two elements of the
/// same `type` that differ in a `locations` or an `actions` member are two
/// different authorizations, and collapsing them would silently widen one or
/// narrow the other.
///
/// # Errors
///
/// [`MergeRefused`] when the union would hold more elements than
/// [`asterius_domain::entities::authorization_details::MAX_ELEMENTS`]. That
/// bound is what the parser enforces on the way in, and a row above it is one
/// nothing could read back.
fn merged_details(
    existing: &[serde_json::Value],
    granted: &[serde_json::Value],
) -> Result<Vec<serde_json::Value>, MergeRefused> {
    let mut merged = existing.to_vec();
    for element in granted {
        if !merged.contains(element) {
            merged.push(element.clone());
        }
    }
    if merged.len() > asterius_domain::entities::authorization_details::MAX_ELEMENTS {
        return Err(MergeRefused);
    }
    Ok(merged)
}

/// The union of two OIDC Core §5.5 `claims` requests.
///
/// The structure is two levels — a top-level member per delivery point
/// (`userinfo`, `id_token`) and a member per claim name inside it — and the
/// union is taken at both. A claim name present in both keeps the *new*
/// request's entry: it is the one the person was just shown and approved, and
/// the older one was approved under a decision this request is amending.
///
/// A non-object on either side is left alone rather than guessed at. Both come
/// from `ClaimsRequest::to_json`, which produces an object, so this is a
/// defensive branch and not a case.
fn merged_claims(existing: &serde_json::Value, granted: &serde_json::Value) -> serde_json::Value {
    let (Some(existing), Some(granted)) = (existing.as_object(), granted.as_object()) else {
        return granted.clone();
    };
    let mut merged = existing.clone();
    for (target, requested) in granted {
        match (merged.get_mut(target), requested.as_object()) {
            (Some(serde_json::Value::Object(held)), Some(requested)) => {
                for (claim, entry) in requested {
                    held.insert(claim.clone(), entry.clone());
                }
            }
            _ => {
                merged.insert(target.clone(), requested.clone());
            }
        }
    }
    serde_json::Value::Object(merged)
}

/// The union of two `claims_locales` preferences, most preferred first.
///
/// Order is the meaning of the parameter (OIDC Core §5.2), so the existing
/// preference stays in front and the new tags follow. Truncated at
/// [`Grant::MAX_CLAIMS_LOCALES`] rather than refused: a language preference is
/// a hint, and dropping the least preferred tags of an over-long list answers in
/// the language the person most wanted rather than refusing the flow — which is
/// the same call `crate::claims::ClaimsLocales::parse` makes on the way in.
fn merged_locales(existing: &[String], granted: &[String]) -> Vec<String> {
    let mut merged: Vec<String> = Vec::with_capacity(existing.len() + granted.len());
    for tag in existing.iter().chain(granted) {
        if !merged.iter().any(|held| held == tag) {
            merged.push(tag.clone());
        }
    }
    merged.truncate(Grant::MAX_CLAIMS_LOCALES);
    merged
}

/// Whether a grant may be the target of a `merge` or a `replace`.
///
/// §5.2 acts on "an existing grant", and a revoked or lapsed one is not that:
/// merging into it would bring a withdrawn authorization back to life with a
/// `grant_id` the client still holds, which is the one outcome revocation
/// exists to prevent.
///
/// A grant belonging to another client, or to another person, is refused by the
/// caller — those need a lookup this crate does not do — and reports the same
/// [`GrantManagementError::UnknownGrant`].
#[must_use]
pub fn may_be_amended(
    grant: &Grant,
    client: &asterius_domain::ClientId,
    now: time::OffsetDateTime,
) -> bool {
    grant.client == *client && grant.status(now).may_issue()
}

/// Whether `granted` may be applied to `existing` on this person's behalf.
///
/// §5.4's third `invalid_grant_id` case: a grant "whose user is not the
/// authenticated user". It cannot be checked at the pushed request — nobody has
/// signed in yet — so it is checked at the far end, where the authorization
/// completes, and reported as a redirect to the client.
#[must_use]
pub fn belongs_to(grant: &Grant, user: &asterius_domain::UserId) -> bool {
    grant.user.as_ref() == Some(user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{ClientId, TenantId, UserId};
    use serde_json::json;
    use time::OffsetDateTime;

    fn on() -> Policy {
        Policy::new(true, false)
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
    }

    fn grant() -> Grant {
        Grant::new(TenantId::new("demo"), ClientId::new("billing"), now())
    }

    /// A grant id shaped the way `Grant::new` mints them.
    fn id_of(grant: &Grant) -> String {
        grant.id.as_str().to_owned()
    }

    /// §5.4: "`grant_management_action` is set to `create` and a `grant_id` is
    /// present".
    #[test]
    fn create_with_a_grant_id_is_an_invalid_request() {
        let refusal =
            parse(Some("create"), Some(&id_of(&grant())), on()).expect_err("create names no grant");
        assert_eq!(refusal, GrantManagementError::GrantIdWithCreate);
        assert_eq!(refusal.code(), "invalid_request");
    }

    /// §5.4: "a `grant_id` is present but `grant_management_action` is missing".
    #[test]
    fn a_grant_id_without_an_action_is_an_invalid_request() {
        let refusal = parse(None, Some(&id_of(&grant())), on()).expect_err("no action was named");
        assert_eq!(refusal, GrantManagementError::ActionMissing);
        assert_eq!(refusal.code(), "invalid_request");
    }

    /// §5.4: "`grant_management_action` is not supported".
    #[test]
    fn an_action_this_server_does_not_implement_is_an_invalid_request() {
        for unknown in ["query", "revoke", "CREATE", "merge ", " "] {
            let refusal = parse(Some(unknown), Some(&id_of(&grant())), on())
                .expect_err("an action this server does not implement");
            assert_eq!(
                refusal,
                GrantManagementError::UnsupportedAction,
                "accepted {unknown:?}"
            );
            assert_eq!(refusal.code(), "invalid_request");
        }
    }

    /// An empty parameter is an absent one (RFC 6749 §3.1), so it is refused
    /// for the clause that actually applies rather than as a bad action.
    #[test]
    fn an_empty_action_is_an_absent_one() {
        assert_eq!(
            parse(Some(""), Some(&id_of(&grant())), on()).expect_err("a grant_id with no action"),
            GrantManagementError::ActionMissing
        );
        assert_eq!(
            parse(Some(""), Some(""), on()).expect("nothing was asked"),
            None
        );
    }

    /// §5.4: `merge` and `replace` act on a grant, so one must be named.
    #[test]
    fn merge_or_replace_without_a_grant_id_is_an_invalid_request() {
        for action in [Action::Merge, Action::Replace] {
            let refusal = parse(Some(action.as_str()), None, on()).expect_err("no grant was named");
            assert_eq!(refusal, GrantManagementError::GrantIdRequired(action));
            assert_eq!(refusal.code(), "invalid_request");
        }
    }

    /// §5.4's `invalid_grant_id`, decided on shape alone and before any lookup.
    #[test]
    fn a_grant_id_this_server_could_not_have_minted_is_invalid_grant_id() {
        for wrong in [
            "../../etc/passwd",
            "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
            "a b",
            &"a".repeat(MAX_GRANT_ID_LEN + 1),
        ] {
            let refusal = parse(Some("merge"), Some(wrong), on())
                .expect_err("a grant id this server could not have minted");
            assert_eq!(refusal, GrantManagementError::UnknownGrant, "{wrong:?}");
            assert_eq!(refusal.code(), INVALID_GRANT_ID);
        }
    }

    /// §7.1: `grant_management_action_required`.
    #[test]
    fn a_tenant_that_requires_an_action_refuses_a_request_without_one() {
        let policy = Policy::new(true, true);
        let refusal = parse(None, None, policy).expect_err("this tenant requires an action");
        assert_eq!(refusal, GrantManagementError::ActionRequired);
        assert_eq!(refusal.code(), "invalid_request");
        assert!(parse(Some("create"), None, policy).is_ok());
    }

    /// The flag is the whole switch: with it off both parameters are ignored,
    /// and a request carrying them is an ordinary authorization.
    #[test]
    fn with_the_feature_off_both_parameters_are_ignored() {
        let off = Policy::new(false, true);
        assert!(!off.action_required, "§7.1 cannot outlive the feature");
        for (action, id) in [
            (Some("create"), Some("anything")),
            (Some("merge"), None),
            (Some("nonsense"), None),
            (None, Some("anything")),
            (None, None),
        ] {
            assert_eq!(
                parse(action, id, off).expect("ignored, never refused"),
                None,
                "{action:?}/{id:?}"
            );
        }
    }

    /// A request naming nothing, on a tenant that requires nothing, is what
    /// every authorization has always been.
    #[test]
    fn an_ordinary_request_asks_for_no_grant_management() {
        assert_eq!(
            parse(None, None, on()).expect("nothing was asked for"),
            None
        );
    }

    #[test]
    fn an_accepted_pair_carries_the_action_and_the_grant_it_names() {
        let target = grant();
        let asked = parse(Some("replace"), Some(&id_of(&target)), on())
            .expect("a well-formed pair")
            .expect("something was asked for");
        assert_eq!(asked.action, Action::Replace);
        assert_eq!(asked.grant_id(), Some(target.id.as_str()));
        assert!(asked.action.needs_an_existing_grant());

        let created = parse(Some("create"), None, on())
            .expect("a well-formed pair")
            .expect("something was asked for");
        assert_eq!(created.action, Action::Create);
        assert_eq!(created.grant_id(), None);
        assert!(!created.action.needs_an_existing_grant());
    }

    /// §5.2: "the AS shall merge the requested privileges with those already
    /// granted", and the grant keeps its identifier.
    #[test]
    fn merge_unions_the_permissions_and_keeps_the_identifier() {
        let mut existing = grant();
        existing.scopes = ["openid", "invoices.read"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect();
        existing.resources = ["https://api.example/invoices".to_owned()]
            .into_iter()
            .collect();
        existing.authorization_details = vec![json!({"type": "invoice"})];
        let before = existing.id.clone();

        let mut granted = grant();
        granted.scopes = ["payments.write".to_owned()].into_iter().collect();
        granted.resources = ["https://api.example/payments".to_owned()]
            .into_iter()
            .collect();
        granted.authorization_details = vec![json!({"type": "payment"})];

        Action::Merge
            .apply(&mut existing, &granted, now())
            .expect("the union is within bounds");

        assert_eq!(existing.id, before, "§5.2 keeps the same grant_id");
        assert_eq!(
            existing.scopes,
            ["openid", "invoices.read", "payments.write"]
                .into_iter()
                .map(ToOwned::to_owned)
                .collect()
        );
        assert_eq!(existing.resources.len(), 2);
        assert_eq!(existing.authorization_details.len(), 2);
    }

    /// §5.2: "the AS shall replace the grant with the requested privileges",
    /// and the grant keeps its identifier.
    #[test]
    fn replace_sets_the_permissions_exactly_and_keeps_the_identifier() {
        let mut existing = grant();
        existing.scopes = ["openid", "invoices.read"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect();
        existing.authorization_details = vec![json!({"type": "invoice"})];
        let before = existing.id.clone();

        let mut granted = grant();
        granted.scopes = ["payments.write".to_owned()].into_iter().collect();

        Action::Replace
            .apply(&mut existing, &granted, now())
            .expect("replace never grows anything");

        assert_eq!(existing.id, before, "§5.2 keeps the same grant_id");
        assert_eq!(
            existing.scopes,
            ["payments.write".to_owned()].into_iter().collect()
        );
        assert!(
            existing.authorization_details.is_empty(),
            "replace withdraws what the request did not ask for"
        );
    }

    /// A merge that would produce a row nothing can read back is refused rather
    /// than truncated: a silently dropped element is an authorization the
    /// client believes it holds.
    #[test]
    fn a_merge_that_would_overflow_the_element_bound_is_refused() {
        let bound = asterius_domain::entities::authorization_details::MAX_ELEMENTS;
        let mut existing = grant();
        existing.authorization_details = (0..bound)
            .map(|n| json!({"type": format!("t{n}")}))
            .collect();
        let mut granted = grant();
        granted.authorization_details = vec![json!({"type": "one more"})];

        assert_eq!(
            Action::Merge.apply(&mut existing, &granted, now()),
            Err(MergeRefused)
        );
    }

    /// An identical element is not a second authorization.
    #[test]
    fn merging_the_same_rich_authorization_twice_does_not_duplicate_it() {
        let mut existing = grant();
        existing.authorization_details = vec![json!({"type": "invoice", "actions": ["read"]})];
        let mut granted = grant();
        granted.authorization_details = vec![json!({"type": "invoice", "actions": ["read"]})];

        Action::Merge
            .apply(&mut existing, &granted, now())
            .expect("within bounds");
        assert_eq!(existing.authorization_details.len(), 1);
    }

    /// OIDC Core §5.5's two levels are both unioned, and the language
    /// preference keeps the order it was expressed in.
    #[test]
    fn merge_unions_the_claims_request_and_the_language_preference() {
        let mut existing = grant();
        existing.claims = json!({"userinfo": {"email": null}});
        existing.claims_locales = vec!["fr-CA".to_owned()];
        let mut granted = grant();
        granted.claims = json!({"userinfo": {"name": null}, "id_token": {"acr": null}});
        granted.claims_locales = vec!["fr-CA".to_owned(), "en".to_owned()];

        Action::Merge
            .apply(&mut existing, &granted, now())
            .expect("within bounds");

        assert_eq!(
            existing.claims,
            json!({"userinfo": {"email": null, "name": null}, "id_token": {"acr": null}})
        );
        assert_eq!(existing.claims_locales, ["fr-CA", "en"]);
    }

    /// The authentication on the grant is this authorization's, because the
    /// person has just signed in.
    #[test]
    fn an_amended_grant_reports_the_authentication_that_amended_it() {
        let mut existing = grant();
        existing.authentication = Some(asterius_domain::GrantAuthentication {
            authenticated_at: now() - time::Duration::days(30),
            acr: Some("old".to_owned()),
            amr: Vec::new(),
        });
        let mut granted = grant();
        granted.authentication = Some(asterius_domain::GrantAuthentication {
            authenticated_at: now(),
            acr: Some("fresh".to_owned()),
            amr: Vec::new(),
        });

        Action::Merge
            .apply(&mut existing, &granted, now())
            .expect("within bounds");

        let authentication = existing.authentication.as_ref().expect("recorded");
        assert_eq!(authentication.authenticated_at, now());
        assert_eq!(authentication.acr.as_deref(), Some("fresh"));
        assert_eq!(existing.updated_at, now());
    }

    /// §5.2 acts on an existing grant, and a revoked or lapsed one is not that.
    #[test]
    fn a_revoked_or_lapsed_grant_may_not_be_amended() {
        let client = ClientId::new("billing");
        let live = grant();
        assert!(may_be_amended(&live, &client, now()));

        let mut revoked = grant();
        revoked.revoked_at = Some(now());
        revoked.revocation_reason = Some(asterius_domain::RevocationReason::UserRevoked);
        assert!(!may_be_amended(&revoked, &client, now()));

        let mut lapsed = grant();
        lapsed.expires_at = Some(now() - time::Duration::hours(1));
        assert!(!may_be_amended(&lapsed, &client, now()));
    }

    /// §5.4: a grant of another client is one this client does not have.
    #[test]
    fn a_grant_of_another_client_may_not_be_amended() {
        let theirs = grant();
        assert!(!may_be_amended(
            &theirs,
            &ClientId::new("someone-else"),
            now()
        ));
    }

    /// §5.4: a grant "whose user is not the authenticated user".
    #[test]
    fn a_grant_of_another_user_does_not_belong_to_this_one() {
        let mine = UserId::generate();
        let theirs = UserId::generate();
        let mut held = grant();
        held.user = Some(mine);

        assert!(belongs_to(&held, &mine));
        assert!(!belongs_to(&held, &theirs));

        // A grant with no user at all — a `client_credentials` grant — belongs
        // to nobody, so it is nobody's to amend.
        assert!(!belongs_to(&grant(), &mine));
    }

    /// The metadata and the parser read the same list, so a value this server
    /// advertises is one it accepts.
    #[test]
    fn every_advertised_action_parses_back_to_itself() {
        for action in Action::ALL {
            assert_eq!(Action::parse(action.as_str()), Some(action));
        }
        assert_eq!(Action::ALL.len(), 3);
    }
}
