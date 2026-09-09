//! Which claims a client receives, where they are delivered, and in what
//! language.
//!
//! Everything here is a pure function of (the user, the scopes the grant
//! covers, the `claims` request the grant covers, the requested locales). It
//! decides nothing about consent: by the time a value reaches [`resolve`] the
//! decision has been made and stored on the grant, and this is the projection
//! of that decision. Handing it an *authorization request's* scopes instead of
//! the *grant's* would release what was asked for rather than what was
//! granted, which is the one way to misuse it.
//!
//! Three rules carry the weight.
//!
//! ## The scope-to-claim table is fixed, not configuration
//!
//! OIDC Core §5.4 defines exactly what `profile`, `email`, `address` and
//! `phone` mean, and every relying party that trusts the standard meaning
//! trusts it without asking. A deployment that redefined `email` to carry a
//! username, or widened `profile` to include a national identifier, would
//! produce ID tokens that lie to every one of them — and the lie is invisible,
//! because the token is well-formed and the scope name is the one in the
//! specification. So the table below is `const`, there is no tenant override,
//! and adding an entry is a code change somebody reviews. A tenant that wants
//! to release something else has the `claims` parameter and its own scopes,
//! both of which are named differently and so cannot be mistaken for these.
//!
//! ## `essential: true` is a request, never an entitlement
//!
//! The `claims` parameter is attacker-shaped input. It arrives inside a pushed
//! authorization request, so it is authenticated — the client that sent it
//! proved who it was — but "authenticated" only narrows *who* is asking, not
//! *what they may have*. OIDC Core §5.5.1 settles it: the authorization server
//! "MUST NOT generate an error when Claims are not returned, whether they are
//! Essential or Voluntary". [`resolve`] therefore cannot fail. A claim the
//! user does not have is absent from the answer, and a claim the grant does
//! not cover was never a candidate.
//!
//! Its size is bounded, and so is its depth. [`ClaimsRequest::parse`] takes a
//! JSON document a client chose the shape of; the shape this specification
//! defines is three levels deep, and anything materially deeper is either a
//! mistake or an attempt to spend the parser's stack.
//!
//! ## Placement is a privacy decision, and this is the rule
//!
//! A claim in the ID token is visible to everything that sees the token: the
//! browser it passed through, the client's session store, the log line
//! somebody pasted into a ticket. A claim at UserInfo requires presenting the
//! access token, which under this profile is sender-constrained — so reading
//! it needs the client's key and not merely a copy of a string.
//!
//! OIDC Core §5.4: "The Claims requested by the `profile`, `email`, `address`,
//! and `phone` scope values are returned from the UserInfo Endpoint, as
//! described in Section 5.3.2, when a `response_type` value is used that
//! results in an Access Token being issued. However, when no Access Token is
//! issued (which is the case for the `response_type` value `id_token`), the
//! resulting Claims are returned in the ID Token."
//!
//! `code` is the only `response_type` this server implements (ADR-0002), so an
//! access token is *always* issued and the exception never applies. The rule
//! reduces to:
//!
//! * a claim implied by a scope goes to **UserInfo**;
//! * a claim the client asked for under the `claims` parameter's `id_token`
//!   member goes to the **ID token**, because asking there is asking for it in
//!   the less private of the two places and the client is entitled to make
//!   that trade for its own users;
//! * a claim asked for under `userinfo` goes to **UserInfo**.
//!
//! So a claim reaches the ID token only when a client named it and named the
//! ID token, never as a side effect of a scope.

use asterius_domain::{Claim, ClaimName, ClaimSet, Grant, User};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Scopes to claims (OIDC Core §5.4)
// ---------------------------------------------------------------------------

/// The `profile` scope's claims, in the order OIDC Core §5.4 lists them.
pub const PROFILE_CLAIMS: &[&str] = &[
    "name",
    "family_name",
    "given_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at",
];

/// The `email` scope's claims (OIDC Core §5.4).
pub const EMAIL_CLAIMS: &[&str] = &["email", "email_verified"];

/// The `address` scope's claim (OIDC Core §5.4). One member, whose value is
/// the JSON object OIDC Core §5.1.1 defines.
pub const ADDRESS_CLAIMS: &[&str] = &["address"];

/// The `phone` scope's claims (OIDC Core §5.4).
pub const PHONE_CLAIMS: &[&str] = &["phone_number", "phone_number_verified"];

/// The whole of OIDC Core §5.4, and nothing else.
///
/// `openid` is absent on purpose: it releases no claims, it selects the
/// protocol. `offline_access` is absent for the same reason — OIDC Core §11
/// makes it a request for a refresh token, not for information about anybody.
const SCOPE_CLAIMS: &[(&str, &[&str])] = &[
    ("profile", PROFILE_CLAIMS),
    ("email", EMAIL_CLAIMS),
    ("address", ADDRESS_CLAIMS),
    ("phone", PHONE_CLAIMS),
];

/// The claims one scope releases, or nothing.
///
/// An unknown scope yields an empty slice rather than an error. Refusing here
/// would be refusing at the wrong boundary twice over: whether a client may
/// ask for a scope was settled at registration and re-checked when the request
/// was pushed (`authorize::validate`), and a *tenant* scope such as
/// `payments` is a perfectly ordinary thing to have granted — it simply
/// releases no claim about the person. A resolver that errored on it would
/// turn every deployment-specific scope into a failed UserInfo response.
#[must_use]
pub fn claims_for_scope(scope: &str) -> &'static [&'static str] {
    SCOPE_CLAIMS
        .iter()
        .find(|(name, _)| *name == scope)
        .map_or(&[], |(_, claims)| *claims)
}

/// Every claim name any scope can release, sorted and deduplicated.
///
/// This is OIDC Discovery §3's `claims_supported`, generated from the table
/// rather than written out beside it — a hand-maintained list would eventually
/// advertise a claim the mapping cannot produce, or hide one it can. It is
/// deliberately *not* the whole answer for the metadata document: `sub` is
/// always supplied and is not in any scope's list, and a deployment's own
/// claims are not in this table at all. Assembling the published array is
/// `metadata`'s job (`ast-o0t.1`); this is the part derived from §5.4.
#[must_use]
pub fn claims_from_scopes() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = SCOPE_CLAIMS
        .iter()
        .flat_map(|(_, claims)| claims.iter().copied())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

// ---------------------------------------------------------------------------
// What may be released at all
// ---------------------------------------------------------------------------

/// A claim [`User`] holds in a field rather than in its claim set.
///
/// `email`, `email_verified` and `updated_at` are columns because the database
/// has an opinion about them — `users_by_email` is unique per tenant, and
/// `updated_at` is maintained by a trigger — so [`ClaimName::parse`] refuses
/// them and the bag can never hold one. They are still claims OIDC Core §5.4
/// releases, which is why they need a representation here: without one, the
/// `email` scope would resolve to nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UserAttribute {
    /// OIDC Core §5.1 `email`.
    Email,
    /// OIDC Core §5.1 `email_verified`.
    EmailVerified,
    /// OIDC Core §5.1 `updated_at`.
    UpdatedAt,
}

impl UserAttribute {
    /// The claim name, as it appears in a token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::EmailVerified => "email_verified",
            Self::UpdatedAt => "updated_at",
        }
    }

    /// Matches a column-backed claim by its exact name.
    ///
    /// Exact, and so no language tag: an address a unique index enforces has
    /// one spelling, and `email#de` is not a translation of it.
    #[must_use]
    fn parse(raw: &str) -> Option<Self> {
        [Self::Email, Self::EmailVerified, Self::UpdatedAt]
            .into_iter()
            .find(|attribute| attribute.as_str() == raw)
    }
}

/// A claim name that resolution is *allowed* to produce.
///
/// This type is the guarantee, and the guarantee is structural rather than
/// tested: **there is no variant for a claim the authorization server issues
/// about the exchange.** [`ClaimName::parse`] refuses every name in
/// [`ClaimName::SERVER_ISSUED`] — `sub`, `aud`, `acr`, `cnf`, `sid`, `nonce`,
/// `iss` and the rest — and the [`UserAttribute`] arm matches only the three
/// column-backed ones, so [`ReleasableClaim::parse`] has nothing to return for
/// `sub` and the maps below cannot be keyed by one.
///
/// That matters because the `claims` parameter is a client naming claims. A
/// resolver keyed by `String` would need a check on every path that writes a
/// member — the scope table, the `claims` parameter, the language fallback —
/// and the first path added later would be the one that forgot. Here, a `sub`
/// smuggled into a `claims` request is not a claim that gets filtered out; it
/// is a value that never becomes a key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReleasableClaim {
    /// Projected from a [`User`] field.
    Attribute(UserAttribute),
    /// Read from the user's [`ClaimSet`].
    Stored(ClaimName),
}

impl ReleasableClaim {
    /// Reads a requested claim name, or refuses it.
    ///
    /// `None` for anything the authorization server issues about the exchange,
    /// for a name that breaks [`ClaimName::parse`]'s rules — too long, a
    /// control or bidirectional formatting character, a `#` suffix that is not
    /// a language tag — and for a column-backed name carrying a language tag.
    ///
    /// Refusal is silent by design at the call sites in this module: OIDC Core
    /// §5.5 says members of the `claims` object that are not understood are
    /// ignored, and a `sub` in a claims request is exactly a member this
    /// server declines to understand.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        UserAttribute::parse(raw).map_or_else(
            || ClaimName::parse(raw).ok().map(Self::Stored),
            |attribute| Some(Self::Attribute(attribute)),
        )
    }

    /// The name this claim is delivered under.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Attribute(attribute) => attribute.as_str(),
            Self::Stored(name) => name.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// claims_locales (OIDC Core §5.2)
// ---------------------------------------------------------------------------

/// The languages a client asked for, in preference order (OIDC Core §5.2).
///
/// A wrapper rather than a bare `Vec<String>` because the order *is* the
/// meaning: "ordered by preference" is the whole of the parameter, and a set
/// or a map would lose it silently.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimsLocales(Vec<String>);

impl ClaimsLocales {
    /// The most languages one request may name.
    ///
    /// Each one costs a pass over the claim set for every claim resolved, and
    /// no honest client has more preferences than this. Extra entries are
    /// dropped rather than refused: OIDC Core §5.2 asks the OP to fall back to
    /// its default when it cannot satisfy the request, so truncating a list
    /// degrades an answer where refusing would deny one.
    pub const MAX: usize = 8;

    /// Parses the space-delimited parameter.
    ///
    /// Anything that is not shaped like a BCP 47 tag is dropped, not refused.
    /// A language preference is a hint about presentation; a request that
    /// misspells one should get the fallback, not an error page.
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Self {
        Self(
            raw.unwrap_or_default()
                .split_whitespace()
                .filter(|tag| is_language_tag(tag))
                .take(Self::MAX)
                .map(ToOwned::to_owned)
                .collect(),
        )
    }

    /// The tags, most preferred first.
    #[must_use]
    pub fn preferences(&self) -> &[String] {
        &self.0
    }

    /// Whether the client expressed no preference.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Rebuilds the preference list from stored tags.
    ///
    /// The same filter and the same bound as [`ClaimsLocales::parse`], because
    /// a row is not more trustworthy than a form field: the grant was written
    /// by an earlier version of this server, or by a migration, or by an
    /// operator, and a tag that is not shaped like one must not become a map
    /// key at issuance merely because it survived a round trip through the
    /// database.
    #[must_use]
    pub fn from_tags<I, S>(tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self(
            tags.into_iter()
                .filter(|tag| is_language_tag(tag.as_ref()))
                .take(Self::MAX)
                .map(|tag| tag.as_ref().to_owned())
                .collect(),
        )
    }
}

/// BCP 47's basic shape: `[A-Za-z]{1,8}` followed by alphanumeric subtags
/// joined with `-` (RFC 5646 §2.1).
///
/// A shape check and not a registry lookup, for the same reason
/// `ClaimName::parse` gives: what has to be true is that the value cannot be
/// arbitrary text used as a map key, not that somebody speaks it.
fn is_language_tag(tag: &str) -> bool {
    let mut subtags = tag.split('-');
    let Some(primary) = subtags.next() else {
        return false;
    };
    if !(1..=8).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    subtags.all(|subtag| {
        (1..=8).contains(&subtag.len()) && subtag.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// The primary language subtag: everything before the first `-`.
fn primary_subtag(tag: &str) -> &str {
    tag.split_once('-').map_or(tag, |(primary, _)| primary)
}

// ---------------------------------------------------------------------------
// The claims request parameter (OIDC Core §5.5)
// ---------------------------------------------------------------------------

/// Why a `claims` parameter was refused.
///
/// Short, and none of the variants repeats the parameter back. The value came
/// from a client, reaches an audit record through
/// [`AuthorizationError`](crate::authorize::AuthorizationError), and is a
/// place a client could park a credential-shaped string for a log to pick up.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClaimsRequestError {
    /// Longer than [`ClaimsRequest::MAX_LEN`].
    #[error("the claims parameter is longer than {} bytes", ClaimsRequest::MAX_LEN)]
    TooLarge,
    /// Not JSON at all, or nested past `serde_json`'s own recursion limit.
    #[error("the claims parameter is not a JSON object")]
    Malformed,
    /// JSON, but not an object (OIDC Core §5.5).
    #[error("the claims parameter must be a JSON object")]
    NotAnObject,
    /// `userinfo` or `id_token` is present but is not an object.
    #[error("the {0} member of the claims parameter must be a JSON object")]
    SectionNotAnObject(&'static str),
    /// An individual claim request is neither `null` nor an object
    /// (OIDC Core §5.5.1).
    #[error("an individual claim request must be null or a JSON object")]
    EntryNotAnObject,
    /// Nested deeper than [`ClaimsRequest::MAX_DEPTH`].
    #[error(
        "the claims parameter is nested more than {} levels deep",
        ClaimsRequest::MAX_DEPTH
    )]
    TooDeep,
    /// More members than [`ClaimsRequest::MAX_CLAIMS`] in one section.
    #[error(
        "one section of the claims parameter names more than {} claims",
        ClaimsRequest::MAX_CLAIMS
    )]
    TooManyClaims,
}

/// One entry of a `claims` object (OIDC Core §5.5.1).
///
/// `null` — "the Claim is being requested with default behaviour" — parses to
/// the default of this type, which is what makes `{"name": null}` and
/// `{"name": {}}` the same request rather than two shapes every consumer has
/// to handle.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClaimRequest {
    essential: bool,
    values: Vec<Value>,
}

impl ClaimRequest {
    /// Whether the client marked this claim essential (OIDC Core §5.5.1).
    ///
    /// Recorded and carried, because a consent screen has a legitimate use for
    /// it: "this application says it cannot work without your date of birth"
    /// is a true and useful thing to show a person. It changes nothing about
    /// what [`resolve`] releases. §5.5.1 is explicit that the authorization
    /// server "MUST NOT generate an error when Claims are not returned,
    /// whether they are Essential or Voluntary", and the reason is worth
    /// keeping in mind: if `essential` compelled a release, every client would
    /// mark every claim essential.
    #[must_use]
    pub const fn is_essential(&self) -> bool {
        self.essential
    }

    /// The values the client will accept — `value` and `values` folded
    /// together, since one is the singular of the other (OIDC Core §5.5.1).
    ///
    /// Honoured for `acr` and nothing else, which is why [`resolve`] does not
    /// read this. A filter on any *other* claim would turn the response into
    /// an oracle: a client that may ask "return `birthdate` only if it is
    /// 1970-01-01" and observe whether the member came back has learned the
    /// answer to a question the user never agreed to answer. For `acr` the
    /// semantics are defined by §5.5.1.1 and the value is one the
    /// authorization server itself asserts, so there is nothing to leak.
    #[must_use]
    pub fn accepted_values(&self) -> &[Value] {
        &self.values
    }

    /// This entry as the JSON object a grant stores (OIDC Core §5.5.1).
    ///
    /// `essential: false` and an empty `values` are written as absence rather
    /// than as members, because §5.5.1 makes both the default and `null` "the
    /// Claim is being requested with default behaviour". Two spellings of the
    /// same request would make a stored grant compare unequal to itself.
    ///
    /// `values` is always the plural form: §5.5.1 defines `value` as the
    /// singular of it, [`ClaimsRequest::parse`] folds one into the other, and
    /// writing back whichever the client happened to send would mean a grant
    /// whose shape depends on the request rather than on the decision.
    fn to_json(&self) -> Value {
        let mut members = Map::new();
        if self.essential {
            members.insert("essential".to_owned(), Value::Bool(true));
        }
        if !self.values.is_empty() {
            members.insert("values".to_owned(), Value::Array(self.values.clone()));
        }
        Value::Object(members)
    }
}

/// A parsed `claims` request parameter (OIDC Core §5.5).
///
/// The two maps are keyed by [`ReleasableClaim`], so no amount of ingenuity in
/// the JSON produces an entry for `sub`, `acr`, `aud` or anything else the
/// authorization server issues about the exchange. `acr` is kept separately
/// because §5.5.1.1 gives it its own semantics, and dropping it silently would
/// lose a request the ACR story has to honour.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClaimsRequest {
    id_token: BTreeMap<ReleasableClaim, ClaimRequest>,
    userinfo: BTreeMap<ReleasableClaim, ClaimRequest>,
    acr: Option<ClaimRequest>,
}

impl ClaimsRequest {
    /// The longest `claims` parameter accepted, in bytes.
    ///
    /// The parameter is sent in a form body, is stored whole on the pushed
    /// request and again on the grant, and is read back on every token
    /// issuance for the life of that grant. A realistic request naming twenty
    /// claims with their `essential` flags is a few hundred bytes; this leaves
    /// two orders of magnitude of headroom and still bounds what a client can
    /// make the server keep.
    pub const MAX_LEN: usize = 4096;

    /// How deep the JSON may nest.
    ///
    /// §5.5's structure is three levels — the object, a section, one claim's
    /// members — and a `values` array of JSON values adds a few more. Six is
    /// generous for every shape the specification defines and refuses the
    /// shapes it does not.
    ///
    /// This is not what keeps the parse off the stack: `serde_json` enforces
    /// its own recursion limit (128 by default, and the `unbounded_depth`
    /// feature that removes it is not enabled here) and reports nesting beyond
    /// it as an error rather than recursing into it. So by the time depth is
    /// measured, the document is already known to be shallow enough to walk.
    /// What this bound adds is a limit on what the server will *store* and
    /// copy, which is a different question from what it will parse.
    pub const MAX_DEPTH: usize = 6;

    /// The most claims one section may name.
    pub const MAX_CLAIMS: usize = 64;

    /// Parses the parameter.
    ///
    /// OIDC Core §5.5: the value is a JSON object with two possible members,
    /// `userinfo` and `id_token`; "Members with other names SHOULD be
    /// ignored." It is carried as UTF-8 JSON, form-urlencoded like any other
    /// OAuth parameter, so what arrives here is the JSON text itself.
    ///
    /// What is ignored and what is refused is a deliberate split. A member
    /// naming a claim this server will not release — `sub`, a name with a
    /// bidirectional override in it — is *ignored*, because §5.5 says
    /// unrecognised members are ignored and because refusing would let a
    /// client discover the reserved list by bisection. A member whose
    /// **shape** is wrong — `userinfo` holding a string, an entry holding an
    /// array — is *refused*, because a client that sent one has misunderstood
    /// the parameter and quietly dropping it would hand back a narrower
    /// authorization than the client believes it has.
    ///
    /// # Errors
    ///
    /// A [`ClaimsRequestError`] naming the first rule broken. No variant
    /// carries a byte of the parameter.
    // fuzz-target: claims_request
    pub fn parse(raw: &str) -> Result<Self, ClaimsRequestError> {
        if raw.len() > Self::MAX_LEN {
            return Err(ClaimsRequestError::TooLarge);
        }
        let document: Value =
            serde_json::from_str(raw).map_err(|_| ClaimsRequestError::Malformed)?;
        if depth(&document) > Self::MAX_DEPTH {
            return Err(ClaimsRequestError::TooDeep);
        }
        let Value::Object(root) = document else {
            return Err(ClaimsRequestError::NotAnObject);
        };

        // `id_token` first, so that an `acr` named in both sections is taken
        // from the one §5.5.1.1's examples use — `parse_section` keeps the
        // first it is given.
        let mut acr = None;
        let id_token = parse_section(&root, "id_token", &mut acr)?;
        let userinfo = parse_section(&root, "userinfo", &mut acr)?;
        Ok(Self {
            id_token,
            userinfo,
            acr,
        })
    }

    /// What the client asked to receive in the ID token.
    #[must_use]
    pub const fn id_token(&self) -> &BTreeMap<ReleasableClaim, ClaimRequest> {
        &self.id_token
    }

    /// What the client asked to receive from the UserInfo endpoint.
    #[must_use]
    pub const fn userinfo(&self) -> &BTreeMap<ReleasableClaim, ClaimRequest> {
        &self.userinfo
    }

    /// The `acr` request, if the client made one (OIDC Core §5.5.1.1).
    ///
    /// Kept out of the two maps because `acr` is not a claim about the person
    /// and is not read out of any user record: it is what the authorization
    /// server asserts about *how* the person authenticated, and honouring a
    /// request for a particular value means driving the authentication, not
    /// filtering an answer. Deciding that belongs to the ACR story; this is
    /// the parameter it needs, kept rather than dropped.
    #[must_use]
    pub const fn acr(&self) -> Option<&ClaimRequest> {
        self.acr.as_ref()
    }

    /// Whether the client asked for anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.id_token.is_empty() && self.userinfo.is_empty() && self.acr.is_none()
    }

    /// The canonical form of this request, as the JSON object a grant stores.
    ///
    /// **The parsed request is what is written down, not the document the
    /// client sent.** A grant records what the user agreed to, and the client's
    /// document is not that: it may carry members this server ignores, a
    /// `sub` it will never release, whitespace and key ordering nobody agreed
    /// to, and a size only [`ClaimsRequest::MAX_LEN`] bounds. What comes out of
    /// here is exactly the request [`ClaimsRequest::parse`] accepted — the
    /// releasable claims, their `essential` flag, their accepted values — and
    /// nothing else, so a grant cannot hold a member that was dropped at
    /// validation and might be picked up by a later reader.
    ///
    /// It round-trips: `from_json(&r.to_json()) == r` for every accepted `r`,
    /// which is the property the `claims_request` fuzz target asserts over
    /// arbitrary input.
    ///
    /// `acr` is re-emitted under `id_token`, the section OIDC Core §5.5.1.1's
    /// examples use and the one [`ClaimsRequest::parse`] reads first. Emitting
    /// it nowhere would lose an §5.5.1.1 request on the way to the grant, which
    /// is the one member the ACR story will need to find there.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut id_token = section_json(&self.id_token);
        if let Some(acr) = &self.acr {
            id_token.insert("acr".to_owned(), acr.to_json());
        }
        let mut root = Map::new();
        root.insert("id_token".to_owned(), Value::Object(id_token));
        root.insert(
            "userinfo".to_owned(),
            Value::Object(section_json(&self.userinfo)),
        );
        Value::Object(root)
    }

    /// Reads back a request stored by [`ClaimsRequest::to_json`].
    ///
    /// The same parser, over the same bounds. A stored value is re-checked
    /// rather than trusted: the column is `jsonb` and this server is not the
    /// only thing that can have written it, so "it came from our own
    /// serialiser" is an assumption and not a guarantee.
    ///
    /// # Errors
    ///
    /// A [`ClaimsRequestError`] when the stored value is not a request this
    /// server would have accepted in the first place.
    pub fn from_json(value: &Value) -> Result<Self, ClaimsRequestError> {
        Self::parse(&value.to_string())
    }
}

/// One section of [`ClaimsRequest::to_json`].
fn section_json(claims: &BTreeMap<ReleasableClaim, ClaimRequest>) -> Map<String, Value> {
    claims
        .iter()
        .map(|(claim, entry)| (claim.as_str().to_owned(), entry.to_json()))
        .collect()
}

/// One `userinfo` or `id_token` section.
///
/// `acr` is lifted out into `acr` rather than being dropped or stored: it
/// cannot be a [`ReleasableClaim`], so the map has no room for it, and losing
/// it would lose a request OIDC Core §5.5.1.1 defines.
fn parse_section(
    root: &Map<String, Value>,
    member: &'static str,
    acr: &mut Option<ClaimRequest>,
) -> Result<BTreeMap<ReleasableClaim, ClaimRequest>, ClaimsRequestError> {
    let mut claims = BTreeMap::new();
    let Some(section) = root.get(member) else {
        return Ok(claims);
    };
    // `null` for a whole section is the same statement as omitting it.
    if section.is_null() {
        return Ok(claims);
    }
    let Value::Object(section) = section else {
        return Err(ClaimsRequestError::SectionNotAnObject(member));
    };
    if section.len() > ClaimsRequest::MAX_CLAIMS {
        return Err(ClaimsRequestError::TooManyClaims);
    }

    for (name, entry) in section {
        let entry = parse_entry(entry)?;
        if name == "acr" {
            // First one wins, and `id_token` is parsed first — see
            // `ClaimsRequest::parse`.
            acr.get_or_insert(entry);
            continue;
        }
        // OIDC Core §5.5: a member this server does not understand is ignored.
        // A name that is not a `ReleasableClaim` is precisely that: either the
        // authorization server issues it, or it is not a claim name at all.
        if let Some(claim) = ReleasableClaim::parse(name) {
            claims.insert(claim, entry);
        }
    }
    Ok(claims)
}

/// One individual claim request: `null`, or an object (OIDC Core §5.5.1).
fn parse_entry(entry: &Value) -> Result<ClaimRequest, ClaimsRequestError> {
    match entry {
        Value::Null => Ok(ClaimRequest::default()),
        Value::Object(members) => {
            let mut values = Vec::new();
            if let Some(value) = members.get("value") {
                values.push(value.clone());
            }
            if let Some(Value::Array(listed)) = members.get("values") {
                values.extend(listed.iter().cloned());
            }
            Ok(ClaimRequest {
                // Anything other than JSON `true` is not `true`. §5.5.1 makes
                // `essential` a boolean and voluntary the default, so a
                // client that sends `"true"` gets the default rather than an
                // error — the wrong shape must not be a way to escalate.
                essential: members.get("essential") == Some(&Value::Bool(true)),
                values,
            })
        }
        _ => Err(ClaimsRequestError::EntryNotAnObject),
    }
}

/// How deep a JSON value nests, counting itself as one.
///
/// Recursive, and safe to be: `serde_json` refuses input nested past its own
/// recursion limit before this ever runs, so the value handed here is already
/// known to be shallow enough for the stack.
fn depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Object(members) => 1 + members.values().map(depth).max().unwrap_or(0),
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// What a client receives, and where.
///
/// Two maps and not one, because the difference between them is the privacy
/// decision this module exists to make. Neither carries `sub`: it is not a
/// [`ReleasableClaim`], the ID token issuer (`ast-a05.4`) and the UserInfo
/// endpoint (`ast-1sk.3`) each add their own, and a resolver able to write one
/// would be a resolver a `claims` parameter could aim at another user.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ResolvedClaims {
    /// Claims to place in the ID token.
    pub id_token: Map<String, Value>,
    /// Claims to serve from the UserInfo endpoint.
    pub userinfo: Map<String, Value>,
}

/// Resolves the claims a client receives.
///
/// **`scopes` and `requested` are the grant's, not the authorization
/// request's.** This function is not the consent decision; it is the
/// projection of one already made and stored. Everything it returns is
/// covered by one of the two, so "output ⊆ consented" holds by construction
/// rather than by a filter at the end — and a caller that passes what a client
/// asked for instead of what a user granted has not defeated a check, it has
/// answered a different question.
///
/// Infallible on purpose. There is no failure mode: a claim the user does not
/// have is absent, a claim no scope or request covers was never a candidate,
/// and OIDC Core §5.5.1 forbids erroring over an unmet essential claim.
///
/// Prefer [`resolve_for_grant`] at every issuance path: it is the same
/// function with the three consent-bearing arguments taken from one grant, so
/// there is no call site at which the request's copy could be passed by
/// mistake. This one stays public because it is the unit under test.
#[must_use]
pub fn resolve(
    user: &User,
    scopes: &BTreeSet<String>,
    requested: &ClaimsRequest,
    locales: &ClaimsLocales,
) -> ResolvedClaims {
    let mut resolved = ResolvedClaims::default();

    // OIDC Core §5.4: scope-derived claims go to UserInfo, because this server
    // always issues an access token. Nothing here can reach the ID token.
    for scope in scopes {
        for name in claims_for_scope(scope).iter().copied() {
            // Every name in the table is releasable by construction; the
            // `let Some` is the compiler holding us to it rather than a check
            // that can fail.
            if let Some(claim) = ReleasableClaim::parse(name)
                && let Some(value) = project(user, &claim, locales)
            {
                resolved.userinfo.insert(name.to_owned(), value);
            }
        }
    }

    // The `claims` parameter, which is the only way into the ID token.
    for claim in requested.id_token().keys() {
        if let Some(value) = project(user, claim, locales) {
            resolved.id_token.insert(claim.as_str().to_owned(), value);
        }
    }
    for claim in requested.userinfo().keys() {
        if let Some(value) = project(user, claim, locales) {
            resolved.userinfo.insert(claim.as_str().to_owned(), value);
        }
    }

    resolved
}

/// Records the claims half of an authorization onto the grant it produced.
///
/// **This copy is the consent boundary.** What the client asked for lives on
/// the pushed request; what the user agreed to lives on the grant, and
/// [`resolve_for_grant`] reads only the second. Writing it here — once, where
/// the grant is minted — is what makes the two sides of that sentence the same
/// value, and what stops a later reader reaching for the request because the
/// grant had nothing on it.
///
/// `parameters` is the stored authorization request (`http::par::serialise`),
/// which already holds the canonical form of the parsed request. A member that
/// is missing or malformed yields the empty request and no locale preference:
/// this runs after the user has approved, and refusing an authorization at
/// that point over a presentation hint would deny a consent that was actually
/// given. The empty request releases nothing that a scope does not already
/// cover, so the failure direction is closed.
pub fn record_on_grant(parameters: &Value, grant: &mut Grant) {
    let request = parameters
        .get("claims")
        .and_then(|value| ClaimsRequest::from_json(value).ok())
        .unwrap_or_default();
    grant.claims = request.to_json();
    grant.claims_locales = parameters
        .get("claims_locales")
        .and_then(Value::as_array)
        .map(|tags| {
            ClaimsLocales::from_tags(tags.iter().filter_map(Value::as_str))
                .preferences()
                .to_vec()
        })
        .unwrap_or_default();
}

/// Resolves the claims a client receives, from the grant and nothing else.
///
/// The form every issuance path should call. [`resolve`] takes the scopes, the
/// claims request and the locales as three separate arguments, and three
/// arguments are three chances to hand it the authorization request's copy of
/// one; here they come from one grant, so "output ⊆ consented" is a property
/// of the call and not of the caller's discipline.
///
/// # Errors
///
/// A [`ClaimsRequestError`] when `grant.claims` is not a request this server
/// would accept. Refused rather than defaulted: at issuance an unreadable
/// stored request means the row does not say what was consented to, and an
/// empty default would quietly release the scope-derived claims of a grant
/// whose record is damaged.
pub fn resolve_for_grant(user: &User, grant: &Grant) -> Result<ResolvedClaims, ClaimsRequestError> {
    let requested = ClaimsRequest::from_json(&grant.claims)?;
    let locales = ClaimsLocales::from_tags(&grant.claims_locales);
    Ok(resolve(user, &grant.scopes, &requested, &locales))
}

/// The value of one claim for one user, or `None` when the user has none.
///
/// Absent and not `null`. OIDC Core §5.3.2 asks for the claim name to be
/// omitted rather than returned empty, and the two say different things: an
/// absent claim is "no answer", a `null` one is "the provider asserts nothing
/// here", which an RP is entitled to treat as a fact about the user.
fn project(user: &User, claim: &ReleasableClaim, locales: &ClaimsLocales) -> Option<Value> {
    match claim {
        ReleasableClaim::Attribute(UserAttribute::Email) => user.email.clone().map(Value::String),
        // Tied to the address rather than standing alone: OIDC Core §5.1 makes
        // `email_verified` a statement *about* `email`, and `false` with no
        // address is an assertion about something that does not exist.
        ReleasableClaim::Attribute(UserAttribute::EmailVerified) => user
            .email
            .as_ref()
            .map(|_| Value::Bool(user.email_verified)),
        // OIDC Core §5.1: "a JSON number representing the number of seconds
        // from 1970-01-01T00:00:00Z as measured in UTC".
        ReleasableClaim::Attribute(UserAttribute::UpdatedAt) => {
            Some(Value::Number(user.updated_at.unix_timestamp().into()))
        }
        ReleasableClaim::Stored(name) => select(&user.claims, name, locales),
    }
}

/// Chooses between the stored spellings of one claim (OIDC Core §5.2).
///
/// A claim may be stored several times — `name`, `name#ja`, `name#ja-Kana-JP`
/// — because §5.2 makes the language tag part of the member name. Which one a
/// client gets is `claims_locales`, and the order is:
///
/// 1. **An exact request wins outright.** A client that asked for `name#ja`
///    through the `claims` parameter gets `name#ja` or nothing; it named a
///    language, so falling back to another one would answer a question it did
///    not ask.
/// 2. Otherwise, for each requested locale in order, the variant whose tag
///    matches it exactly, ignoring case (BCP 47 tags are case-insensitive).
/// 3. Then, for each requested locale in order, the variant whose primary
///    language subtag matches — `fr` accepts `fr-CA` — taking the first in the
///    claim set's own order, which is sorted and therefore stable across
///    processes.
/// 4. Then the untagged claim, which is OIDC Core §5.2's "its default language
///    or languages".
/// 5. Then nothing.
///
/// Every step is total and ordered, so the same inputs give the same answer on
/// every replica. That is not a nicety: two replicas that disagreed would give
/// one user two different ID tokens for one authorization.
fn select(claims: &ClaimSet, name: &ClaimName, locales: &ClaimsLocales) -> Option<Value> {
    if name.language_tag().is_some() {
        return claims.get(name).map(|claim| claim.value().clone());
    }

    let base = name.base();
    for wanted in locales.preferences() {
        if let Some(value) = claims
            .variants(base)
            .find(|(candidate, _)| {
                candidate
                    .language_tag()
                    .is_some_and(|tag| tag.eq_ignore_ascii_case(wanted))
            })
            .map(pick)
        {
            return Some(value);
        }
    }
    for wanted in locales.preferences() {
        if let Some(value) = claims
            .variants(base)
            .find(|(candidate, _)| {
                candidate.language_tag().is_some_and(|tag| {
                    primary_subtag(tag).eq_ignore_ascii_case(primary_subtag(wanted))
                })
            })
            .map(pick)
        {
            return Some(value);
        }
    }
    claims.get(name).map(|claim| claim.value().clone())
}

/// The value out of a `(name, claim)` pair.
fn pick((_, claim): (&ClaimName, &Claim)) -> Value {
    claim.value().clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{ClaimSource, ClientId, TenantId, UserId, UserStatus};
    use serde_json::json;
    use time::OffsetDateTime;

    fn epoch() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    /// A user with an address, and a claim set carrying one untagged claim and
    /// two language variants of another.
    fn a_user() -> User {
        let mut claims = ClaimSet::new();
        for (name, value) in [
            ("name", json!("Ada Lovelace")),
            ("name#en", json!("Ada Lovelace")),
            ("name#ja-Kana-JP", json!("エイダ")),
            ("given_name", json!("Ada")),
            ("phone_number", json!("+44 20 7946 0000")),
            ("address", json!({"country": "GB", "locality": "London"})),
        ] {
            claims.insert(
                ClaimName::parse(name).expect("a fixture claim name"),
                Claim::new(value, ClaimSource::Local).expect("a fixture claim"),
            );
        }
        User {
            tenant: TenantId::new("demo"),
            id: UserId::generate(),
            username: "ada".to_owned(),
            email: Some("ada@example.test".to_owned()),
            email_verified: true,
            status: UserStatus::Active,
            claims,
            created_at: epoch(),
            updated_at: epoch() + time::Duration::seconds(1_234),
        }
    }

    fn scopes(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn locales(raw: &str) -> ClaimsLocales {
        ClaimsLocales::parse(Some(raw))
    }

    // -----------------------------------------------------------------------
    // The scope table (OIDC Core §5.4)
    // -----------------------------------------------------------------------

    /// The table, checked against §5.4 name by name. This is the test a
    /// reviewer reads with the specification open, which is the reason it
    /// spells every claim out rather than looping over the constants.
    #[test]
    fn the_four_standard_scopes_map_to_exactly_the_claims_core_5_4_names() {
        assert_eq!(
            claims_for_scope("profile"),
            [
                "name",
                "family_name",
                "given_name",
                "middle_name",
                "nickname",
                "preferred_username",
                "profile",
                "picture",
                "website",
                "gender",
                "birthdate",
                "zoneinfo",
                "locale",
                "updated_at",
            ]
        );
        assert_eq!(claims_for_scope("email"), ["email", "email_verified"]);
        assert_eq!(claims_for_scope("address"), ["address"]);
        assert_eq!(
            claims_for_scope("phone"),
            ["phone_number", "phone_number_verified"]
        );
    }

    /// A scope nobody standardised releases nothing, and says so by returning
    /// an empty list rather than by failing.
    ///
    /// A deployment's own scope — `payments`, `accounts` — is an ordinary
    /// thing to have granted; the acceptance criterion is that it yields no
    /// claims, not that it is an error. `openid` is in the same position for a
    /// different reason: it selects the protocol and describes nobody.
    #[test]
    fn an_unknown_scope_yields_no_claims_rather_than_an_error() {
        for scope in [
            "openid",
            "offline_access",
            "payments",
            "",
            "PROFILE",
            "profile ",
            "email address",
        ] {
            assert!(
                claims_for_scope(scope).is_empty(),
                "{scope:?} released claims"
            );
        }

        // And resolution over such a grant answers with an empty set, not an
        // error: `resolve` has no error to return.
        let resolved = resolve(
            &a_user(),
            &scopes(&["openid", "payments"]),
            &ClaimsRequest::default(),
            &ClaimsLocales::default(),
        );
        assert!(resolved.userinfo.is_empty());
        assert!(resolved.id_token.is_empty());
    }

    /// Discovery §3's `claims_supported`, generated rather than transcribed.
    #[test]
    fn the_advertised_claims_are_generated_from_the_mapping() {
        let advertised = claims_from_scopes();
        assert!(advertised.windows(2).all(|pair| pair[0] < pair[1]));
        for scope in ["profile", "email", "address", "phone"] {
            for claim in claims_for_scope(scope) {
                assert!(advertised.contains(claim), "{claim} is not advertised");
            }
        }
        // Never `sub`: it is not released by a scope, it is what the token is
        // about, and this list feeds a metadata document rather than replacing
        // it.
        assert!(!advertised.contains(&"sub"));
    }

    // -----------------------------------------------------------------------
    // What may be released
    // -----------------------------------------------------------------------

    /// The whole reserved-name policy, walked over the domain's own list
    /// rather than a copy of it: no name the authorization server issues can
    /// become a claim this module is able to release.
    #[test]
    fn no_claim_the_server_issues_can_be_named_as_a_releasable_one() {
        for reserved in ClaimName::SERVER_ISSUED {
            assert_eq!(
                ReleasableClaim::parse(reserved),
                None,
                "{reserved} became releasable"
            );
            // ...and neither can a language-tagged spelling of it, which is
            // the way round a `base()` check would be tempting to skip.
            assert_eq!(
                ReleasableClaim::parse(&format!("{reserved}#en")),
                None,
                "{reserved}#en became releasable"
            );
        }
    }

    /// The three column-backed claims are releasable *because* the bag refuses
    /// them: without this arm the `email` scope would resolve to nothing.
    #[test]
    fn the_column_backed_claims_are_releasable_although_the_bag_refuses_them() {
        for name in ClaimName::HELD_IN_A_COLUMN {
            assert!(ClaimName::parse(name).is_err(), "{name} is in the bag");
            assert!(
                matches!(
                    ReleasableClaim::parse(name),
                    Some(ReleasableClaim::Attribute(_))
                ),
                "{name} is not projectable"
            );
            // Exact spelling only: a unique index has one, and `email#de` is
            // not a translation of an address.
            assert_eq!(ReleasableClaim::parse(&format!("{name}#de")), None);
        }
    }

    // -----------------------------------------------------------------------
    // The claims request parameter (OIDC Core §5.5)
    // -----------------------------------------------------------------------

    /// The acceptance criterion, and the reason [`ReleasableClaim`] exists: a
    /// client that names `sub` in the `claims` parameter gets nothing for it,
    /// and cannot overwrite the `sub` the authorization server computes.
    #[test]
    fn a_claims_parameter_cannot_produce_a_reserved_claim() {
        let raw = json!({
            "id_token": {
                "sub": {"value": "somebody-else"},
                "aud": {"value": "another-client"},
                "cnf": null,
                "sid": null,
                "iss": {"essential": true},
                "given_name": null
            },
            "userinfo": {"sub": {"value": "somebody-else"}, "name": null}
        })
        .to_string();
        let request = ClaimsRequest::parse(&raw).expect("a well-shaped claims parameter");

        // Only the two honest members survived parsing at all.
        let named: Vec<&str> = request
            .id_token()
            .keys()
            .chain(request.userinfo().keys())
            .map(ReleasableClaim::as_str)
            .collect();
        assert_eq!(named, ["given_name", "name"]);

        let resolved = resolve(
            &a_user(),
            &scopes(&["openid"]),
            &request,
            &ClaimsLocales::default(),
        );
        for reserved in ClaimName::SERVER_ISSUED {
            assert!(
                !resolved.id_token.contains_key(*reserved),
                "{reserved} reached the ID token"
            );
            assert!(
                !resolved.userinfo.contains_key(*reserved),
                "{reserved} reached UserInfo"
            );
        }
        assert_eq!(resolved.id_token["given_name"], json!("Ada"));
    }

    /// `null` and `{}` are the same request (OIDC Core §5.5.1), and the
    /// members that are not `userinfo` or `id_token` are ignored (§5.5).
    #[test]
    fn the_shapes_core_5_5_defines_all_parse_to_the_same_request() {
        let plain = ClaimsRequest::parse(r#"{"userinfo":{"name":null}}"#).expect("null entry");
        let empty = ClaimsRequest::parse(r#"{"userinfo":{"name":{}}}"#).expect("empty entry");
        assert_eq!(plain, empty);

        let with_noise = ClaimsRequest::parse(
            r#"{"userinfo":{"name":null},"transaction":{"x":1},"vendor_extension":"anything"}"#,
        )
        .expect("unknown top-level members are ignored");
        assert_eq!(with_noise, plain);

        assert!(ClaimsRequest::parse("{}").expect("empty object").is_empty());
        assert!(
            ClaimsRequest::parse(r#"{"userinfo":null,"id_token":null}"#)
                .expect("null sections")
                .is_empty()
        );
    }

    /// `essential` is recorded, and changes nothing about what comes back.
    ///
    /// OIDC Core §5.5.1: the authorization server "MUST NOT generate an error
    /// when Claims are not returned, whether they are Essential or Voluntary".
    /// So a client marking a claim the user does not have as essential gets an
    /// answer without it — not a failure, and not a `null`.
    #[test]
    fn an_essential_claim_the_user_does_not_have_is_absent_rather_than_an_error() {
        let request = ClaimsRequest::parse(
            r#"{"userinfo":{"birthdate":{"essential":true},"given_name":{"essential":true}}}"#,
        )
        .expect("a well-shaped claims parameter");

        let birthdate = ReleasableClaim::parse("birthdate").expect("releasable");
        assert!(
            request.userinfo()[&birthdate].is_essential(),
            "the flag was dropped"
        );

        let resolved = resolve(
            &a_user(),
            &scopes(&["openid"]),
            &request,
            &ClaimsLocales::default(),
        );
        assert_eq!(resolved.userinfo["given_name"], json!("Ada"));
        assert!(
            !resolved.userinfo.contains_key("birthdate"),
            "an unavailable claim was returned"
        );
        // Absent, and specifically not present-and-null: OIDC Core §5.3.2 asks
        // for the name to be omitted, and a `null` would be the provider
        // asserting that the user has no date of birth.
        assert_eq!(resolved.userinfo.get("birthdate"), None);
    }

    /// A wrongly *shaped* parameter is refused, because a client that sent one
    /// has misunderstood it and would otherwise be handed a narrower
    /// authorization than it believes it has.
    #[test]
    fn a_claims_parameter_of_the_wrong_shape_is_refused() {
        use ClaimsRequestError as E;
        for (raw, expected) in [
            ("not json at all", E::Malformed),
            ("[]", E::NotAnObject),
            ("\"claims\"", E::NotAnObject),
            ("null", E::NotAnObject),
            (r#"{"userinfo":"name"}"#, E::SectionNotAnObject("userinfo")),
            (r#"{"id_token":[]}"#, E::SectionNotAnObject("id_token")),
            (r#"{"userinfo":{"name":[]}}"#, E::EntryNotAnObject),
            (r#"{"userinfo":{"name":"Ada"}}"#, E::EntryNotAnObject),
        ] {
            assert_eq!(
                ClaimsRequest::parse(raw),
                Err(expected.clone()),
                "parsing {raw:?}"
            );
        }
    }

    /// The bounds. The parameter is client-chosen JSON that this server stores
    /// on the request, stores again on the grant, and reads on every issuance
    /// for the life of that grant.
    #[test]
    fn an_oversized_or_deeply_nested_claims_parameter_is_refused() {
        let long = format!(
            r#"{{"userinfo":{{"name":{{"value":"{}"}}}}}}"#,
            "a".repeat(4096)
        );
        assert!(long.len() > ClaimsRequest::MAX_LEN);
        assert_eq!(
            ClaimsRequest::parse(&long),
            Err(ClaimsRequestError::TooLarge)
        );

        // Nested past MAX_DEPTH but well inside serde_json's own recursion
        // limit, so this is our bound answering and not the parser's.
        let deep = format!("{}{}", "[".repeat(20), "]".repeat(20));
        assert_eq!(
            ClaimsRequest::parse(&deep),
            Err(ClaimsRequestError::TooDeep)
        );

        // Deeper than `serde_json`'s own recursion limit but still inside the
        // length bound, so nothing was ever built for `depth` to walk: the
        // refusal has to come from the parser, and it has to be a refusal
        // rather than a stack overflow.
        let just_deep = format!("{}{}", "[".repeat(400), "]".repeat(400));
        assert!(just_deep.len() < ClaimsRequest::MAX_LEN);
        assert_eq!(
            ClaimsRequest::parse(&just_deep),
            Err(ClaimsRequestError::Malformed),
            "serde_json must refuse deep nesting rather than recurse into it"
        );

        // And the length bound is checked before any of that, so a very large
        // document costs a comparison and not a parse.
        let very_deep = format!("{}{}", "[".repeat(2100), "]".repeat(2100));
        assert!(very_deep.len() > ClaimsRequest::MAX_LEN);
        assert_eq!(
            ClaimsRequest::parse(&very_deep),
            Err(ClaimsRequestError::TooLarge)
        );

        let many = format!(
            r#"{{"userinfo":{{{}}}}}"#,
            (0..=ClaimsRequest::MAX_CLAIMS)
                .map(|n| format!(r#""claim_{n}":null"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(
            ClaimsRequest::parse(&many),
            Err(ClaimsRequestError::TooManyClaims)
        );
    }

    /// `acr` is neither released nor dropped (OIDC Core §5.5.1.1). It is not a
    /// claim about the person and cannot be read out of a user record, so it
    /// cannot be a `ReleasableClaim` — but a client that asked for one has
    /// made a request the ACR story has to honour.
    #[test]
    fn an_acr_request_is_kept_aside_rather_than_released() {
        let request = ClaimsRequest::parse(
            r#"{"id_token":{"acr":{"essential":true,"values":["urn:mace:incommon:iap:silver"]}}}"#,
        )
        .expect("a well-shaped claims parameter");

        let acr = request.acr().expect("the acr request was dropped");
        assert!(acr.is_essential());
        assert_eq!(
            acr.accepted_values(),
            [json!("urn:mace:incommon:iap:silver")]
        );
        assert!(
            request.id_token().is_empty(),
            "acr reached the id_token map"
        );

        let resolved = resolve(
            &a_user(),
            &scopes(&["openid", "profile"]),
            &request,
            &ClaimsLocales::default(),
        );
        assert!(!resolved.id_token.contains_key("acr"));
        assert!(!resolved.userinfo.contains_key("acr"));
    }

    /// `value` and `values` are carried but not applied to ordinary claims.
    ///
    /// Filtering an answer by what the client guessed would make the response
    /// an oracle: the client learns whether the user's `given_name` is "Ada"
    /// by observing whether the member came back.
    #[test]
    fn value_and_values_are_recorded_but_do_not_filter_an_ordinary_claim() {
        let request = ClaimsRequest::parse(r#"{"userinfo":{"given_name":{"value":"Grace"}}}"#)
            .expect("shape");
        let given_name = ReleasableClaim::parse("given_name").expect("releasable");
        assert_eq!(
            request.userinfo()[&given_name].accepted_values(),
            [json!("Grace")]
        );

        let resolved = resolve(
            &a_user(),
            &scopes(&["openid"]),
            &request,
            &ClaimsLocales::default(),
        );
        assert_eq!(
            resolved.userinfo["given_name"],
            json!("Ada"),
            "the stored value was filtered against the client's guess"
        );
    }

    /// `essential` is a boolean (OIDC Core §5.5.1), and anything else is not
    /// `true`. The wrong shape must not be a way to escalate.
    #[test]
    fn only_a_json_true_makes_a_claim_essential() {
        let name = ReleasableClaim::parse("name").expect("releasable");
        for raw in [
            r#"{"userinfo":{"name":{"essential":"true"}}}"#,
            r#"{"userinfo":{"name":{"essential":1}}}"#,
            r#"{"userinfo":{"name":{"essential":false}}}"#,
            r#"{"userinfo":{"name":{}}}"#,
        ] {
            let request = ClaimsRequest::parse(raw).expect("shape");
            assert!(!request.userinfo()[&name].is_essential(), "{raw}");
        }
        let request =
            ClaimsRequest::parse(r#"{"userinfo":{"name":{"essential":true}}}"#).expect("shape");
        assert!(request.userinfo()[&name].is_essential());
    }

    // -----------------------------------------------------------------------
    // Placement (OIDC Core §5.4)
    // -----------------------------------------------------------------------

    /// The placement rule, in one test.
    ///
    /// A scope never puts a claim in the ID token: `code` is the only
    /// `response_type` this server implements, so an access token is always
    /// issued and §5.4's exception — "when no Access Token is issued (which is
    /// the case for the `response_type` value `id_token`)" — cannot arise.
    /// Only a client naming a claim under `id_token` reaches it, which is the
    /// client deliberately trading privacy for a round trip it does not have
    /// to make.
    #[test]
    fn a_scope_delivers_to_userinfo_and_only_the_claims_parameter_reaches_the_id_token() {
        let request = ClaimsRequest::parse(r#"{"id_token":{"given_name":null}}"#).expect("shape");
        let resolved = resolve(
            &a_user(),
            &scopes(&["openid", "email", "phone"]),
            &request,
            &ClaimsLocales::default(),
        );

        assert_eq!(resolved.userinfo["email"], json!("ada@example.test"));
        assert_eq!(resolved.userinfo["email_verified"], json!(true));
        assert_eq!(resolved.userinfo["phone_number"], json!("+44 20 7946 0000"));

        assert_eq!(resolved.id_token.len(), 1);
        assert_eq!(resolved.id_token["given_name"], json!("Ada"));
        assert!(
            !resolved.id_token.contains_key("email"),
            "a scope put a claim in the ID token"
        );
    }

    /// The acceptance criterion, stated as the bead states it: a grant for
    /// `email` never yields `name`.
    #[test]
    fn claims_never_exceed_the_scopes_the_grant_covers() {
        let resolved = resolve(
            &a_user(),
            &scopes(&["openid", "email"]),
            &ClaimsRequest::default(),
            &ClaimsLocales::default(),
        );
        assert_eq!(
            resolved.userinfo.keys().collect::<Vec<_>>(),
            ["email", "email_verified"]
        );
        assert!(!resolved.userinfo.contains_key("name"));
        assert!(!resolved.userinfo.contains_key("given_name"));
        assert!(resolved.id_token.is_empty());
    }

    /// `email_verified` is a statement about `email`, so an account without an
    /// address gets neither rather than a bare `false`.
    #[test]
    fn a_user_with_no_address_gets_neither_email_nor_email_verified() {
        let mut user = a_user();
        user.email = None;
        user.email_verified = false;
        let resolved = resolve(
            &user,
            &scopes(&["email"]),
            &ClaimsRequest::default(),
            &ClaimsLocales::default(),
        );
        assert!(resolved.userinfo.is_empty());
    }

    /// OIDC Core §5.1: `updated_at` is "a JSON number representing the number
    /// of seconds from 1970-01-01T00:00:00Z".
    #[test]
    fn updated_at_is_projected_from_the_column_as_seconds_since_the_epoch() {
        let resolved = resolve(
            &a_user(),
            &scopes(&["profile"]),
            &ClaimsRequest::default(),
            &ClaimsLocales::default(),
        );
        assert_eq!(resolved.userinfo["updated_at"], json!(1_234));
    }

    // -----------------------------------------------------------------------
    // Languages and scripts (OIDC Core §5.2)
    // -----------------------------------------------------------------------

    /// The fallback ladder, every rung of it, on one claim set.
    ///
    /// Determinism is the property that matters: two replicas answering
    /// differently would give one user two different tokens for one
    /// authorization.
    #[test]
    fn locale_fallback_is_deterministic_at_every_rung() {
        let user = a_user();
        let profile = scopes(&["profile"]);
        let none = ClaimsRequest::default();

        // 1. An exact tag match, taken in preference order.
        let resolved = resolve(&user, &profile, &none, &locales("ja-Kana-JP en"));
        assert_eq!(resolved.userinfo["name"], json!("エイダ"));

        // Order is preference: the same two tags the other way round pick the
        // other variant.
        let resolved = resolve(&user, &profile, &none, &locales("en ja-Kana-JP"));
        assert_eq!(resolved.userinfo["name"], json!("Ada Lovelace"));

        // Case-insensitively, because BCP 47 tags are.
        let resolved = resolve(&user, &profile, &none, &locales("JA-kana-jp"));
        assert_eq!(resolved.userinfo["name"], json!("エイダ"));

        // 2. The primary subtag, when no tag matches exactly: `ja` accepts
        //    `ja-Kana-JP`.
        let resolved = resolve(&user, &profile, &none, &locales("ja"));
        assert_eq!(resolved.userinfo["name"], json!("エイダ"));

        // 3. The untagged claim — OIDC Core §5.2's "default language" — when
        //    nothing the client asked for is stored.
        let resolved = resolve(&user, &profile, &none, &locales("de-CH fr"));
        assert_eq!(resolved.userinfo["name"], json!("Ada Lovelace"));

        // ...and with no preference expressed at all.
        let resolved = resolve(&user, &profile, &none, &ClaimsLocales::default());
        assert_eq!(resolved.userinfo["name"], json!("Ada Lovelace"));

        // 4. Nothing, for a claim with no variant in any language.
        assert!(!resolved.userinfo.contains_key("nickname"));

        // The answer is delivered under the name the client asked for, not the
        // tagged spelling it happened to be stored under.
        let resolved = resolve(&user, &profile, &none, &locales("ja-Kana-JP"));
        assert!(!resolved.userinfo.contains_key("name#ja-Kana-JP"));
    }

    /// Repeated resolution of the same inputs is the same answer. The claim
    /// set is a `BTreeMap` and the preference list is ordered, so there is no
    /// iteration order left for a process to disagree about.
    #[test]
    fn the_same_inputs_resolve_to_the_same_answer_every_time() {
        let user = a_user();
        let request =
            ClaimsRequest::parse(r#"{"id_token":{"name":null,"given_name":null}}"#).expect("shape");
        let first = resolve(&user, &scopes(&["profile"]), &request, &locales("ja en"));
        for _ in 0..8 {
            assert_eq!(
                resolve(&user, &scopes(&["profile"]), &request, &locales("ja en")),
                first
            );
        }
    }

    /// A client that named a language in the `claims` parameter asked for that
    /// language, so it gets it or nothing — falling back to another one would
    /// answer a question it did not ask (OIDC Core §5.5.2).
    #[test]
    fn a_claim_requested_with_a_language_tag_is_answered_exactly_or_not_at_all() {
        let user = a_user();
        let request =
            ClaimsRequest::parse(r#"{"userinfo":{"name#ja-Kana-JP":null,"given_name#fr":null}}"#)
                .expect("shape");
        let resolved = resolve(&user, &scopes(&[]), &request, &locales("en"));

        assert_eq!(resolved.userinfo["name#ja-Kana-JP"], json!("エイダ"));
        assert!(
            !resolved.userinfo.contains_key("given_name#fr"),
            "a tagged request fell back to another language"
        );
        assert!(
            !resolved.userinfo.contains_key("given_name"),
            "a tagged request was answered under the untagged name"
        );
    }

    /// `claims_locales` is a hint about presentation, so a malformed one
    /// degrades to the fallback rather than failing the request.
    #[test]
    fn a_malformed_claims_locales_is_dropped_rather_than_refused() {
        assert!(ClaimsLocales::parse(None).is_empty());
        assert!(ClaimsLocales::parse(Some("")).is_empty());
        assert_eq!(
            ClaimsLocales::parse(Some("en-GB  not/a/tag  ja")).preferences(),
            ["en-GB", "ja"]
        );
        // Bounded: every extra tag is a pass over the claim set per claim.
        let many = (0..64).map(|_| "en").collect::<Vec<_>>().join(" ");
        assert_eq!(
            ClaimsLocales::parse(Some(&many)).preferences().len(),
            ClaimsLocales::MAX
        );
    }

    // -----------------------------------------------------------------------
    // The grant: storage and the consent boundary
    // -----------------------------------------------------------------------

    fn a_grant() -> Grant {
        Grant::new(TenantId::new("demo"), ClientId::new("billing"), epoch())
    }

    /// What is stored is the parsed request, not the document the client sent:
    /// a member this server declined to understand must not reach the row that
    /// records what a person agreed to.
    #[test]
    fn storing_a_claims_request_keeps_what_was_parsed_and_drops_what_was_ignored() {
        let request = ClaimsRequest::parse(
            r#"{"id_token":{"given_name":{"essential":true},"sub":null},
                "userinfo":{"name":null},
                "transaction":{"id":"t-1"}}"#,
        )
        .expect("a well-shaped claims parameter");

        let stored = request.to_json();

        assert_eq!(
            stored,
            json!({
                "id_token": {"given_name": {"essential": true}},
                "userinfo": {"name": {}}
            })
        );
    }

    /// The property the `claims_request` fuzz target asserts over arbitrary
    /// input, pinned here on the shapes a reviewer can read.
    #[test]
    fn a_stored_claims_request_reads_back_as_the_same_request() {
        for raw in [
            "{}",
            r#"{"id_token":{"given_name":{"essential":true}}}"#,
            r#"{"userinfo":{"name":null,"phone_number":{"values":["+44 20 7946 0000"]}}}"#,
            r#"{"id_token":{"acr":{"essential":true,"values":["urn:example:loa:2"]}}}"#,
        ] {
            let request = ClaimsRequest::parse(raw).expect("a well-shaped claims parameter");

            let restored =
                ClaimsRequest::from_json(&request.to_json()).expect("a stored request re-parses");

            assert_eq!(restored, request, "{raw} did not survive storage");
        }
    }

    /// OIDC Core §5.5.1.1's `acr` request is kept aside by the parser, so it
    /// has to be written back somewhere or the ACR story finds nothing on the
    /// grant.
    #[test]
    fn an_acr_request_survives_the_trip_through_the_grant() {
        let request = ClaimsRequest::parse(r#"{"id_token":{"acr":{"essential":true}}}"#)
            .expect("an acr request");
        let mut grant = a_grant();

        record_on_grant(&json!({"claims": request.to_json()}), &mut grant);

        let stored = ClaimsRequest::from_json(&grant.claims).expect("a stored request");
        assert!(
            stored.acr().is_some_and(ClaimRequest::is_essential),
            "the acr request was lost on the way to the grant"
        );
    }

    /// The locale preference belongs to the authorization it was expressed in,
    /// and its order is its meaning (OIDC Core §5.2).
    #[test]
    fn the_locale_preference_reaches_the_grant_in_order() {
        let mut grant = a_grant();

        record_on_grant(
            &json!({"claims_locales": ["ja-Kana-JP", "not a tag", "en"]}),
            &mut grant,
        );

        assert_eq!(grant.claims_locales, ["ja-Kana-JP", "en"]);
    }

    /// A stored request that is not one this server would accept is refused at
    /// issuance rather than defaulted to the empty one: a damaged row does not
    /// say what was consented to, and quietly releasing the scope-derived
    /// claims anyway would answer a question nobody asked.
    #[test]
    fn a_grant_whose_claims_column_is_damaged_releases_nothing() {
        let mut grant = a_grant();
        grant.scopes = scopes(&["openid", "email"]);
        grant.claims = json!({"userinfo": "a-secret-looking-string"});

        let refused = resolve_for_grant(&a_user(), &grant);

        assert!(refused.is_err(), "a damaged claims column reached issuance");
    }

    /// **The consent boundary.** The client pushed a request naming two claims
    /// for the ID token; what reached the grant names one. Issuance reads the
    /// grant, so the second claim is not released — and the wider request is
    /// still sitting in the authorization request, which is exactly the value
    /// `resolve_for_grant` gives no call site a way to reach.
    #[test]
    fn a_claims_request_narrowed_at_consent_does_not_widen_at_issuance() {
        let asked_for = ClaimsRequest::parse(r#"{"id_token":{"name":null,"given_name":null}}"#)
            .expect("the request the client pushed");
        let consented_to =
            ClaimsRequest::parse(r#"{"id_token":{"given_name":null}}"#).expect("what was granted");

        let mut grant = a_grant();
        grant.scopes = scopes(&["openid"]);
        record_on_grant(&json!({"claims": consented_to.to_json()}), &mut grant);

        let released = resolve_for_grant(&a_user(), &grant).expect("a readable grant");

        assert_eq!(
            released.id_token.keys().collect::<Vec<_>>(),
            ["given_name"],
            "issuance released a claim the grant does not cover"
        );
        // And the user does hold the claim that was dropped, so the narrowing
        // is what kept it out rather than an empty claim set.
        assert!(asked_for.id_token().len() > consented_to.id_token().len());
        assert!(
            resolve(
                &a_user(),
                &grant.scopes,
                &asked_for,
                &ClaimsLocales::default()
            )
            .id_token
            .contains_key("name")
        );
    }

    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    use proptest::prelude::*;

    fn config() -> ProptestConfig {
        ProptestConfig {
            cases: 256,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(config())]

        /// The containment property the bead asks for: every claim released is
        /// one a granted scope names or the granted `claims` request named,
        /// and never `sub` — which this module cannot write at all, because
        /// `sub` is not a `ReleasableClaim`.
        #[test]
        fn every_released_claim_was_covered_by_the_grant(
            granted in proptest::collection::vec(
                proptest::sample::select(vec!["openid", "profile", "email", "address", "phone", "payments"]),
                0..6,
            ),
            asked in proptest::collection::vec(
                proptest::sample::select(vec![
                    "name", "given_name", "birthdate", "sub", "acr", "aud", "email", "cnf", "sid",
                ]),
                0..6,
            ),
            in_id_token in any::<bool>(),
        ) {
            let section = if in_id_token { "id_token" } else { "userinfo" };
            let members = asked
                .iter()
                .map(|name| format!("{}:null", serde_json::Value::String((*name).to_owned())))
                .collect::<Vec<_>>()
                .join(",");
            let request = ClaimsRequest::parse(&format!("{{\"{section}\":{{{members}}}}}"))
                .map_err(|e| TestCaseError::fail(format!("a generated request was refused: {e}")))?;

            let user = a_user();
            let granted: BTreeSet<String> =
                granted.iter().map(|s| (*s).to_owned()).collect();
            let resolved = resolve(&user, &granted, &request, &locales("en ja"));

            let mut covered: BTreeSet<String> = granted
                .iter()
                .flat_map(|scope| claims_for_scope(scope).iter().map(|c| (*c).to_owned()))
                .collect();
            covered.extend(
                request
                    .id_token()
                    .keys()
                    .chain(request.userinfo().keys())
                    .map(|claim| claim.as_str().to_owned()),
            );

            for name in resolved.id_token.keys().chain(resolved.userinfo.keys()) {
                prop_assert!(covered.contains(name), "released {name}, which nothing granted");
                prop_assert!(
                    !ClaimName::SERVER_ISSUED.contains(&name.as_str()),
                    "released the server-issued claim {name}"
                );
            }

            // Nothing is ever released as JSON `null`: OIDC Core §5.3.2 asks
            // for an unavailable claim to be omitted, and a `null` says
            // something different — that the provider asserts no value.
            for value in resolved.id_token.values().chain(resolved.userinfo.values()) {
                prop_assert!(!value.is_null(), "released a null claim value");
            }

            // A scope never reaches the ID token (OIDC Core §5.4, and `code`
            // is the only response type).
            for name in resolved.id_token.keys() {
                prop_assert!(
                    request.id_token().keys().any(|claim| claim.as_str() == name),
                    "{name} reached the ID token without being asked for there"
                );
            }
        }

        /// Whatever arrives, the parser answers rather than panics — and
        /// whatever it accepts is within its own bounds and free of reserved
        /// names.
        #[test]
        fn anything_the_parser_accepts_is_within_its_bounds(raw in ".{0,2000}") {
            if let Ok(request) = ClaimsRequest::parse(&raw) {
                prop_assert!(raw.len() <= ClaimsRequest::MAX_LEN);
                prop_assert!(request.id_token().len() <= ClaimsRequest::MAX_CLAIMS);
                prop_assert!(request.userinfo().len() <= ClaimsRequest::MAX_CLAIMS);
                for claim in request.id_token().keys().chain(request.userinfo().keys()) {
                    prop_assert!(
                        !ClaimName::SERVER_ISSUED.contains(&claim.as_str()),
                        "accepted the server-issued claim {}",
                        claim.as_str()
                    );
                }
            }
        }
    }
}
