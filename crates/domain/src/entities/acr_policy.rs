//! What authentication contexts a tenant can produce, and how (`ast-2vk.7`).
//!
//! OIDC Core §2 defines `acr` as "a value that identifies the Authentication
//! Context Class that the authentication performed satisfied" and `amr` as the
//! methods that were used. It defines neither *which* classes exist nor what
//! each one costs: that is a deployment's own statement, and this module is the
//! shape of that statement.
//!
//! A policy is an **ordered ladder** of [`AcrLevel`]s, weakest first. A level
//! is a name and the set of authentication methods that satisfy it — nothing
//! else. `urn:asterius:acr:passkey-uv` is "a WebAuthn assertion whose UV bit
//! was set", written as `{Passkey, UserVerified}`, and a session satisfies it
//! when its `amr` contains both.
//!
//! # Why a set of methods rather than a number
//!
//! Because "level 3" is not checkable. The question a step-up has to answer is
//! "what would the user have to do next", and only a set of methods answers it:
//! a level whose methods are already in the session's `amr` needs nothing, and
//! one whose methods are not says exactly which credential to ask for. A
//! numeric ladder would need a second table mapping numbers to credentials, and
//! the two would disagree the first time somebody added a method.
//!
//! # Aliases are deliberate
//!
//! Two levels may carry the same method set. EAP ACR Values 1.0 registers `phr`
//! for a phishing-resistant authentication, and a WebAuthn assertion *is* one —
//! a deployment that wants to answer both `phr` and its own URN for the same
//! ceremony should be able to say so. What makes an alias safe is
//! [`AcrPolicy::assign`]: the value written onto the session is chosen from
//! what the *request* asked for, so a client that asks for `phr` gets `phr`
//! back (OIDC Core §5.5.1.1: the returned `acr` matches one of the requested
//! values) rather than a synonym it would have to know about.
//!
//! `phrh` — phishing-resistant *and* hardware-protected — is not in the default
//! ladder and cannot be: attestation is `none` at enrolment, so this server
//! cannot tell a hardware authenticator from a software one, and an `acr` it
//! cannot stand behind is worse than one it does not offer.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::entities::session::AuthenticationMethod;

/// The most levels a policy may carry.
///
/// A bound rather than an opinion: the ladder is walked on every
/// authentication and published in the discovery document, and a policy
/// arriving from configuration or from a database column is untrusted input.
pub const MAX_LEVELS: usize = 32;

/// The longest `acr` value a policy may name.
///
/// `acr` is a JWT claim a relying party compares by string. Anything longer
/// than this is not a class name, it is a payload.
pub const MAX_VALUE_LENGTH: usize = 255;

/// Why a policy will not be accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AcrPolicyError {
    /// An `acr` value that is empty, over-long, or carries a character that
    /// could not survive `acr_values`.
    #[error("an acr value is not usable: {0}")]
    Value(&'static str),
    /// A level nothing could ever satisfy.
    #[error("an acr level names no authentication method")]
    NoMethods,
    /// The same `acr` value twice.
    ///
    /// Two rungs with one name is not an alias — it is an ambiguity about which
    /// methods that name means, and the answer would depend on iteration order.
    #[error("the acr value {0} appears twice")]
    Duplicate(String),
    /// More than [`MAX_LEVELS`].
    #[error("an acr policy may not carry more than {MAX_LEVELS} levels")]
    TooManyLevels,
    /// The stored form is not the shape this module writes.
    #[error("an acr policy document is malformed: {0}")]
    Malformed(&'static str),
}

/// One rung: a name, and what satisfies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcrLevel {
    /// The `acr` value, as it appears in an ID token.
    value: String,
    /// Every method that must be present for this level to be met.
    methods: BTreeSet<AuthenticationMethod>,
}

impl AcrLevel {
    /// A level, or the reason it is not one.
    ///
    /// # Errors
    ///
    /// [`AcrPolicyError::Value`] for a name that could not be requested through
    /// `acr_values` — which is space-delimited (OIDC Core §3.1.2.1), so a name
    /// containing whitespace is one no client could ever ask for — and
    /// [`AcrPolicyError::NoMethods`] for a level nothing satisfies.
    pub fn new(
        value: impl Into<String>,
        methods: impl IntoIterator<Item = AuthenticationMethod>,
    ) -> Result<Self, AcrPolicyError> {
        let value = value.into();
        if value.is_empty() {
            return Err(AcrPolicyError::Value("empty"));
        }
        if value.len() > MAX_VALUE_LENGTH {
            return Err(AcrPolicyError::Value("longer than 255 bytes"));
        }
        if value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || !c.is_ascii())
        {
            return Err(AcrPolicyError::Value(
                "carries whitespace, a control character or a non-ASCII byte",
            ));
        }
        let methods: BTreeSet<AuthenticationMethod> = methods.into_iter().collect();
        if methods.is_empty() {
            return Err(AcrPolicyError::NoMethods);
        }
        Ok(Self { value, methods })
    }

    /// The `acr` value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// What an authentication must have used to reach this level.
    #[must_use]
    pub const fn methods(&self) -> &BTreeSet<AuthenticationMethod> {
        &self.methods
    }

    /// Whether an authentication that used `used` reached this level.
    ///
    /// Containment, not equality: a session that also did something else has
    /// not done less. `{Passkey, UserVerified}` is met by a passkey with UV
    /// whether or not a password came first.
    #[must_use]
    pub fn is_met_by(&self, used: &[AuthenticationMethod]) -> bool {
        self.methods.iter().all(|method| used.contains(method))
    }
}

/// A tenant's ordered authentication contexts.
///
/// Weakest first. Order is the whole of "highest achievable": a voluntary
/// request naming three values gets the strongest of them the authentication
/// actually reached, and *strongest* means "latest in this list" and nothing
/// else. Deployments that disagree about whether a password beats a passkey
/// express that by reordering, not by arguing with this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcrPolicy {
    /// The ladder, weakest first.
    levels: Vec<AcrLevel>,
    /// Whether `amr` is released into the ID token (OIDC Core §2 makes it
    /// OPTIONAL).
    amr_in_id_token: bool,
}

impl AcrPolicy {
    /// A policy over `levels`, weakest first.
    ///
    /// # Errors
    ///
    /// [`AcrPolicyError::Duplicate`] when one value appears twice and
    /// [`AcrPolicyError::TooManyLevels`] past [`MAX_LEVELS`].
    pub fn new(levels: Vec<AcrLevel>) -> Result<Self, AcrPolicyError> {
        if levels.len() > MAX_LEVELS {
            return Err(AcrPolicyError::TooManyLevels);
        }
        let mut seen = BTreeSet::new();
        for level in &levels {
            if !seen.insert(level.value.clone()) {
                return Err(AcrPolicyError::Duplicate(level.value.clone()));
            }
        }
        Ok(Self {
            levels,
            amr_in_id_token: true,
        })
    }

    /// A tenant that has configured no authentication contexts.
    ///
    /// It produces no `acr` at all, which makes every *essential* request
    /// `unmet_authentication_requirements` (Unmet Authentication Requirements
    /// 1.0 §2) and every voluntary one a no-op. That is the correct answer for
    /// a deployment nobody has told what a class name would mean — the
    /// alternative, treating each requested value as met, asserts an
    /// authentication strength nobody configured.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            levels: Vec::new(),
            amr_in_id_token: true,
        }
    }

    /// The same policy, releasing `amr` or not.
    #[must_use]
    pub fn releasing_amr(mut self, release: bool) -> Self {
        self.amr_in_id_token = release;
        self
    }

    /// Whether an ID token from this tenant carries `amr`.
    #[must_use]
    pub const fn releases_amr(&self) -> bool {
        self.amr_in_id_token
    }

    /// The ladder, weakest first.
    #[must_use]
    pub fn levels(&self) -> &[AcrLevel] {
        &self.levels
    }

    /// `acr_values_supported`, strongest first (OIDC Discovery §3).
    ///
    /// Strongest first because the member is a list a human reads as much as a
    /// client does, and because Discovery attaches no meaning to the order —
    /// so the order that says something true is the one to publish.
    #[must_use]
    pub fn supported_values(&self) -> Vec<&str> {
        self.levels
            .iter()
            .rev()
            .map(|level| level.value.as_str())
            .collect()
    }

    /// The level with this exact value.
    #[must_use]
    pub fn level(&self, value: &str) -> Option<&AcrLevel> {
        self.levels.iter().find(|level| level.value == value)
    }

    /// Whether this tenant could ever produce `value`.
    #[must_use]
    pub fn can_produce(&self, value: &str) -> bool {
        self.level(value).is_some()
    }

    /// The strongest level an authentication using `used` reached, if any.
    #[must_use]
    pub fn achieved(&self, used: &[AuthenticationMethod]) -> Option<&AcrLevel> {
        self.levels.iter().rev().find(|level| level.is_met_by(used))
    }

    /// The strongest of `requested` that `used` reached.
    ///
    /// The whole of "voluntary picks the highest achievable" (OIDC Core
    /// §3.1.2.1) and of "essential is met by exactly one of the requested
    /// values" (§5.5.1.1) — the difference between the two is what the caller
    /// does with a `None`, not how the value is chosen.
    #[must_use]
    pub fn strongest_met(
        &self,
        requested: &[String],
        used: &[AuthenticationMethod],
    ) -> Option<&AcrLevel> {
        self.levels.iter().rev().find(|level| {
            requested.iter().any(|value| value == &level.value) && level.is_met_by(used)
        })
    }

    /// The `acr` to record for an authentication that used `used`, for a
    /// request that asked for `essential` and `voluntary`.
    ///
    /// The one place the claim is chosen, and the reason aliases are safe.
    ///
    /// 1. An **essential** value that was reached wins, because §5.5.1.1 says
    ///    the returned `acr` "MUST" be one of the requested values and this is
    ///    the only step that can make that true.
    /// 2. Then a **voluntary** one, for the same reason read as a preference
    ///    rather than a requirement (§3.1.2.1).
    /// 3. Otherwise the strongest level the authentication reached at all,
    ///    which is what a request that asked for nothing gets and what a
    ///    request whose values are all out of reach gets — §3.1.2.1's "the
    ///    Authorization Server ... does not fulfil" case, answered with what
    ///    did happen rather than with silence.
    #[must_use]
    // fuzz-target: acr_policy
    pub fn assign(
        &self,
        used: &[AuthenticationMethod],
        essential: &[String],
        voluntary: &[String],
    ) -> Option<String> {
        self.strongest_met(essential, used)
            .or_else(|| self.strongest_met(voluntary, used))
            .or_else(|| self.achieved(used))
            .map(|level| level.value.clone())
    }

    /// Whether any of `requested` is a value this tenant can produce.
    ///
    /// An empty request is trivially satisfiable: the client asked for no
    /// particular context.
    #[must_use]
    pub fn can_satisfy(&self, requested: &[String]) -> bool {
        requested.is_empty() || requested.iter().any(|value| self.can_produce(value))
    }

    /// What a step-up would have to produce, for a request that named
    /// `requested` and a session that has already used `used`.
    ///
    /// The weakest reachable rung, not the strongest: the point of a step-up is
    /// to ask the person for the least that satisfies the requirement. `None`
    /// when nothing is missing or nothing would help.
    #[must_use]
    pub fn step_up_target(
        &self,
        requested: &[String],
        used: &[AuthenticationMethod],
    ) -> Option<&AcrLevel> {
        if self.strongest_met(requested, used).is_some() {
            return None;
        }
        self.levels
            .iter()
            .find(|level| requested.iter().any(|value| value == &level.value))
    }

    /// Reads a policy out of the form [`Self::to_json`] writes.
    ///
    /// Untrusted: this is what a configuration file or a database column
    /// yields, so every bound [`AcrLevel::new`] and [`Self::new`] enforce is
    /// enforced here too.
    ///
    /// # Errors
    ///
    /// [`AcrPolicyError::Malformed`] for a document of the wrong shape, and
    /// whatever the constructors refuse otherwise.
    // fuzz-target: acr_policy
    pub fn from_json(document: &Value) -> Result<Self, AcrPolicyError> {
        let object = document
            .as_object()
            .ok_or(AcrPolicyError::Malformed("not an object"))?;
        let amr_in_id_token = match object.get("amr_in_id_token") {
            None => true,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => {
                return Err(AcrPolicyError::Malformed(
                    "amr_in_id_token is not a boolean",
                ));
            }
        };
        let raw = object
            .get("levels")
            .ok_or(AcrPolicyError::Malformed("no levels"))?
            .as_array()
            .ok_or(AcrPolicyError::Malformed("levels is not an array"))?;
        if raw.len() > MAX_LEVELS {
            return Err(AcrPolicyError::TooManyLevels);
        }
        let mut levels = Vec::with_capacity(raw.len());
        for entry in raw {
            let entry = entry
                .as_object()
                .ok_or(AcrPolicyError::Malformed("a level is not an object"))?;
            let value = entry
                .get("value")
                .and_then(Value::as_str)
                .ok_or(AcrPolicyError::Malformed("a level has no value"))?;
            let methods = entry
                .get("amr")
                .and_then(Value::as_array)
                .ok_or(AcrPolicyError::Malformed("a level has no amr array"))?;
            let mut parsed = Vec::with_capacity(methods.len());
            for method in methods {
                let name = method
                    .as_str()
                    .ok_or(AcrPolicyError::Malformed("an amr value is not a string"))?;
                // An unknown method is refused rather than dropped. Dropping it
                // would silently *weaken* the level — a rung that meant
                // "password and one-time code" would come back meaning
                // "password" — and a level that asks for less than it says is
                // the one failure mode this type exists to prevent.
                parsed.push(
                    AuthenticationMethod::parse(name)
                        .ok_or(AcrPolicyError::Malformed("an amr value is not recognised"))?,
                );
            }
            levels.push(AcrLevel::new(value, parsed)?);
        }
        Ok(Self::new(levels)?.releasing_amr(amr_in_id_token))
    }

    /// The stored form.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "amr_in_id_token": self.amr_in_id_token,
            "levels": self
                .levels
                .iter()
                .map(|level| json!({
                    "value": level.value,
                    "amr": level
                        .methods
                        .iter()
                        .map(|method| method.as_str())
                        .collect::<Vec<_>>(),
                }))
                .collect::<Vec<_>>(),
        })
    }
}

/// The ladder this server can actually walk, with nothing on it that it cannot
/// prove.
///
/// Three rungs, weakest first, and each one is a fact an authentication leaves
/// behind: a password verified, a WebAuthn assertion verified, and a WebAuthn
/// assertion whose UV bit was set. `phr` (EAP ACR Values 1.0) is an alias of
/// the second — origin binding is what phishing resistance *is*, and a client
/// asking for the registered name should not have to learn a vendor URN to get
/// it.
impl Default for AcrPolicy {
    fn default() -> Self {
        let levels = vec![
            AcrLevel::new(PASSWORD, [AuthenticationMethod::Password]),
            AcrLevel::new(PHISHING_RESISTANT, [AuthenticationMethod::Passkey]),
            AcrLevel::new(PASSKEY, [AuthenticationMethod::Passkey]),
            AcrLevel::new(
                PASSKEY_USER_VERIFIED,
                [
                    AuthenticationMethod::Passkey,
                    AuthenticationMethod::UserVerified,
                ],
            ),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("the default ladder names three well-formed levels");
        Self::new(levels).expect("the default ladder has no duplicate value")
    }
}

/// A password was verified.
pub const PASSWORD: &str = "urn:asterius:acr:pwd";
/// EAP ACR Values 1.0: the authentication was phishing-resistant.
pub const PHISHING_RESISTANT: &str = "phr";
/// A WebAuthn assertion was verified.
pub const PASSKEY: &str = "urn:asterius:acr:passkey";
/// A WebAuthn assertion whose UV bit was set.
pub const PASSKEY_USER_VERIFIED: &str = "urn:asterius:acr:passkey-uv";

#[cfg(test)]
mod tests {
    use super::*;
    use AuthenticationMethod::{Passkey, Password, UserVerified};

    fn values(requested: &[&str]) -> Vec<String> {
        requested.iter().map(|value| (*value).to_owned()).collect()
    }

    /// OIDC Core §2: `acr` identifies the class the authentication "satisfied".
    /// A rung is satisfied by containment, so doing more still counts.
    #[test]
    fn a_level_is_met_by_a_superset_of_its_methods() {
        let level = AcrLevel::new("x", [Passkey, UserVerified]).expect("a level");

        assert!(level.is_met_by(&[Password, Passkey, UserVerified]));
        assert!(!level.is_met_by(&[Passkey]));
    }

    /// `acr_values` is space-delimited (OIDC Core §3.1.2.1), so a class name
    /// carrying a space is one no client could ever request.
    #[test]
    fn a_level_whose_name_could_not_survive_acr_values_is_refused() {
        let refused = AcrLevel::new("two words", [Password]);

        assert_eq!(
            refused,
            Err(AcrPolicyError::Value(
                "carries whitespace, a control character or a non-ASCII byte"
            ))
        );
    }

    #[test]
    fn a_level_nothing_could_satisfy_is_refused() {
        let refused = AcrLevel::new("x", []);

        assert_eq!(refused, Err(AcrPolicyError::NoMethods));
    }

    /// One name may not mean two method sets: which one applied would depend on
    /// iteration order.
    #[test]
    fn one_acr_value_may_not_appear_on_two_levels() {
        let levels = vec![
            AcrLevel::new("x", [Password]).expect("a level"),
            AcrLevel::new("x", [Passkey]).expect("a level"),
        ];

        assert_eq!(
            AcrPolicy::new(levels),
            Err(AcrPolicyError::Duplicate("x".to_owned()))
        );
    }

    /// "Highest achievable" is the ladder's order and nothing else.
    #[test]
    fn the_strongest_level_the_methods_reached_is_the_last_one_they_meet() {
        let policy = AcrPolicy::default();

        let reached = policy
            .achieved(&[Passkey, UserVerified])
            .expect("a passkey with UV reaches a rung");

        assert_eq!(reached.value(), PASSKEY_USER_VERIFIED);
    }

    /// OIDC Core §3.1.2.1: a voluntary `acr_values` naming several values is
    /// answered with the highest of them the authentication reached.
    #[test]
    fn a_voluntary_request_takes_the_highest_value_it_reached() {
        let policy = AcrPolicy::default();

        let assigned = policy.assign(
            &[Passkey, UserVerified],
            &[],
            &values(&[PASSWORD, PASSKEY, PASSKEY_USER_VERIFIED]),
        );

        assert_eq!(assigned.as_deref(), Some(PASSKEY_USER_VERIFIED));
    }

    /// OIDC Core §3.1.2.1: a voluntary request the tenant cannot meet is not an
    /// error — the `acr` reports what the authentication *did* reach.
    #[test]
    fn a_voluntary_request_out_of_reach_still_reports_what_happened() {
        let policy = AcrPolicy::default();

        let assigned = policy.assign(
            &[Passkey, UserVerified],
            &[],
            &values(&["urn:mace:incommon:iap:silver"]),
        );

        assert_eq!(assigned.as_deref(), Some(PASSKEY_USER_VERIFIED));
    }

    /// OIDC Core §5.5.1.1: the returned `acr` matches one of the requested
    /// values. An essential request beats a stronger voluntary one, because
    /// only the essential one is a requirement.
    #[test]
    fn an_essential_value_that_was_reached_is_the_one_returned() {
        let policy = AcrPolicy::default();

        let assigned = policy.assign(
            &[Passkey, UserVerified],
            &values(&[PASSKEY]),
            &values(&[PASSKEY_USER_VERIFIED]),
        );

        assert_eq!(assigned.as_deref(), Some(PASSKEY));
    }

    /// The alias case, and why aliases are safe: a client that asks for the
    /// registered EAP name gets it back, not this server's URN for the same
    /// ceremony.
    #[test]
    fn an_alias_is_returned_under_the_name_that_was_asked_for() {
        let policy = AcrPolicy::default();

        let assigned = policy.assign(&[Passkey], &values(&[PHISHING_RESISTANT]), &[]);

        assert_eq!(assigned.as_deref(), Some(PHISHING_RESISTANT));
    }

    /// Unmet Authentication Requirements 1.0 §2 is about what the tenant can
    /// *ever* produce, which is a question about the ladder rather than about
    /// any session.
    #[test]
    fn a_value_that_is_not_on_the_ladder_can_never_be_satisfied() {
        let policy = AcrPolicy::default();

        assert!(!policy.can_satisfy(&values(&["urn:mace:incommon:iap:silver"])));
        assert!(policy.can_satisfy(&[]));
        assert!(policy.can_satisfy(&values(&["urn:mace:incommon:iap:silver", PASSKEY])));
    }

    /// A step-up asks for the least that satisfies the requirement.
    #[test]
    fn a_step_up_targets_the_weakest_requested_level_that_is_missing() {
        let policy = AcrPolicy::default();

        let target = policy
            .step_up_target(&values(&[PASSKEY_USER_VERIFIED, PASSKEY]), &[Password])
            .expect("a password session has a rung to climb");

        assert_eq!(target.value(), PASSKEY);
    }

    #[test]
    fn nothing_is_stepped_up_to_when_the_requirement_is_already_met() {
        let policy = AcrPolicy::default();

        let target = policy.step_up_target(&values(&[PASSKEY]), &[Passkey, UserVerified]);

        assert!(target.is_none());
    }

    /// OIDC Discovery §3: what is published is what the ladder holds.
    #[test]
    fn the_published_values_are_the_ladder_strongest_first() {
        let policy = AcrPolicy::default();

        assert_eq!(
            policy.supported_values(),
            vec![PASSKEY_USER_VERIFIED, PASSKEY, PHISHING_RESISTANT, PASSWORD]
        );
    }

    #[test]
    fn a_policy_survives_a_round_trip_through_its_stored_form() {
        let policy = AcrPolicy::default().releasing_amr(false);

        let read = AcrPolicy::from_json(&policy.to_json()).expect("the stored form parses");

        assert_eq!(read, policy);
    }

    /// A method this build does not know would silently weaken the rung that
    /// named it, so the document is refused instead.
    #[test]
    fn an_unrecognised_amr_value_is_refused_rather_than_dropped() {
        let document = json!({"levels": [{"value": "x", "amr": ["pwd", "telepathy"]}]});

        assert_eq!(
            AcrPolicy::from_json(&document),
            Err(AcrPolicyError::Malformed("an amr value is not recognised"))
        );
    }

    #[test]
    fn a_policy_with_no_levels_produces_nothing_and_satisfies_only_the_empty_request() {
        let policy = AcrPolicy::empty();

        assert!(policy.assign(&[Passkey, UserVerified], &[], &[]).is_none());
        assert!(policy.can_satisfy(&[]));
        assert!(!policy.can_satisfy(&values(&[PASSKEY])));
        assert!(policy.supported_values().is_empty());
    }
}
