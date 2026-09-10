//! Per-tenant settings: which optional features a tenant serves, and how long
//! the artefacts of one authorization live.
//!
//! # Why the caps are here and not in a form
//!
//! FAPI 2.0 Security Profile puts a hard ceiling on the lifetime of an
//! authorization code, and this server puts a ceiling on an access token's for
//! the reason §6.1 gives. Those ceilings are a property of the *deployment*,
//! not of the screen somebody edits them on: an administrator with a session
//! and a CSRF token can call the admin API with `curl` and never load the
//! form. So [`TenantSettings::validated`] is the only way to obtain a
//! `TenantSettings`, its fields are private, and the console's own bounds
//! checking is a courtesy that repeats a decision taken here.
//!
//! # Features are a subtraction, never an addition
//!
//! A tenant may switch a deployment's optional feature *off*; it cannot switch
//! one on. Enabling CIBA for one tenant would mean mounting a route the
//! operator did not ask for, in a binary that may not have been built for it,
//! and the tenant boundary is not where that decision belongs. So a tenant's
//! setting is a set of *disabled* features and
//! [`TenantSettings::effective_capabilities`] can only ever return something
//! narrower than the deployment's.

use crate::capabilities::{Capabilities, Feature};
use crate::entities::registration_policy::{
    RegistrationMode, RegistrationPolicy, RegistrationPolicyError,
};
use crate::locale::Locale;
use crate::messages::MessageOverrides;
use std::collections::BTreeSet;
use time::Duration;

/// The longest an authorization code may live, whatever a tenant asks for.
///
/// FAPI 2.0 Security Profile §5.3.2.1 item 11: an authorization server "shall
/// issue authorization codes with a maximum lifetime of 60 seconds".
///
/// This is the *only* place that number lives. `asterius_oidc::code::MAX_LIFETIME`
/// is an alias of it, and issuance no longer clamps: `ast-5c6` found the cap
/// enforced twice and differently — refused here, silently shortened there —
/// so an administrator could be told 300 seconds was rejected while the same
/// value arriving by another route would have been quietly rewritten. One
/// mechanism, and it refuses, so a lifetime that reaches issuance is under the
/// cap by construction.
pub const MAX_AUTHORIZATION_CODE_LIFETIME: Duration = Duration::seconds(60);

/// The longest an access token may live, whatever a tenant asks for.
///
/// FAPI 2.0 Security Profile §6.1 asks for short-lived access tokens behind
/// longer-lived grants without naming a number; fifteen minutes is what this
/// server will sign, and a stored setting above it would be a lifetime an
/// operator believes is in force and is not.
/// `asterius_oidc::tokens::AccessToken::MAX_LIFETIME` is an alias of this
/// constant, for the reason [`MAX_AUTHORIZATION_CODE_LIFETIME`] gives.
pub const MAX_ACCESS_TOKEN_LIFETIME: Duration = Duration::minutes(15);

/// The shortest either lifetime may be.
///
/// A zero or negative lifetime is a tenant that issues an artefact already
/// expired, which is indistinguishable from an outage.
pub const MIN_LIFETIME: Duration = Duration::seconds(1);

/// The lifetime an authorization code gets unless a tenant says otherwise: the
/// cap, and the value `asterius_oidc::code::DEFAULT_LIFETIME` aliases.
pub const DEFAULT_AUTHORIZATION_CODE_LIFETIME: Duration = MAX_AUTHORIZATION_CODE_LIFETIME;

/// The lifetime an access token gets unless a tenant says otherwise.
pub const DEFAULT_ACCESS_TOKEN_LIFETIME: Duration = Duration::minutes(5);

/// How long this tenant's authorization artefacts live.
///
/// Private fields, and no way to build one except [`TokenLifetimes::validated`]
/// — the same reason [`crate::entities::tenant::Tenant`]'s policy types state:
/// a public field would let a caller assemble the combination the validator
/// exists to refuse, and the guarantee would rest on nobody doing so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenLifetimes {
    authorization_code: Duration,
    access_token: Duration,
}

impl Default for TokenLifetimes {
    fn default() -> Self {
        Self {
            authorization_code: DEFAULT_AUTHORIZATION_CODE_LIFETIME,
            access_token: DEFAULT_ACCESS_TOKEN_LIFETIME,
        }
    }
}

impl TokenLifetimes {
    /// Checks a requested pair against the profile's ceilings.
    ///
    /// Refused rather than clamped, and that is the whole point of the type: a
    /// clamp answers "saved" to a request the server did not honour, and the
    /// administrator goes away believing a code lives for five minutes.
    ///
    /// # Errors
    ///
    /// [`TenantSettingsError::AuthorizationCodeLifetimeTooLong`] or
    /// [`TenantSettingsError::AccessTokenLifetimeTooLong`] above the ceiling,
    /// [`TenantSettingsError::LifetimeNotPositive`] at or below zero.
    pub fn validated(
        authorization_code: Duration,
        access_token: Duration,
    ) -> Result<Self, TenantSettingsError> {
        if authorization_code < MIN_LIFETIME || access_token < MIN_LIFETIME {
            return Err(TenantSettingsError::LifetimeNotPositive);
        }
        if authorization_code > MAX_AUTHORIZATION_CODE_LIFETIME {
            return Err(TenantSettingsError::AuthorizationCodeLifetimeTooLong {
                requested_seconds: authorization_code.whole_seconds(),
            });
        }
        if access_token > MAX_ACCESS_TOKEN_LIFETIME {
            return Err(TenantSettingsError::AccessTokenLifetimeTooLong {
                requested_seconds: access_token.whole_seconds(),
            });
        }
        Ok(Self {
            authorization_code,
            access_token,
        })
    }

    /// How long an authorization code lives.
    #[must_use]
    pub const fn authorization_code(&self) -> Duration {
        self.authorization_code
    }

    /// How long an access token lives.
    #[must_use]
    pub const fn access_token(&self) -> Duration {
        self.access_token
    }

    /// The same lifetimes with the access token no longer than `cap`.
    ///
    /// Clamped rather than refused, which is the opposite of
    /// [`TokenLifetimes::validated`] and is deliberate: `validated` answers an
    /// administrator who is watching and can be told "no", while this answers a
    /// caller holding two ceilings that are both in force — the tenant's and an
    /// agent profile's (`ast-lh3.1`) — where the only honest resolution is the
    /// shorter one. Nothing here can lengthen a lifetime, so a caller cannot
    /// use it to escape what `validated` already accepted.
    #[must_use]
    pub fn with_access_token_at_most(self, cap: Duration) -> Self {
        Self {
            access_token: self.access_token.min(cap),
            ..self
        }
    }
}

/// Everything a tenant may set about itself that this story covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSettings {
    disabled_features: BTreeSet<Feature>,
    lifetimes: TokenLifetimes,
    registration: RegistrationPolicy,
    /// Grant Management ID1 §7.1's `grant_management_action_required`.
    ///
    /// Last, and read through [`TenantSettings::grant_management_action_required`]
    /// rather than directly, because it is only meaningful when
    /// [`Feature::GrantManagement`] survives this tenant's own subtraction: a
    /// tenant that has switched the feature off cannot require a parameter it
    /// also ignores.
    grant_management_action_required: bool,
    /// The language this tenant's pages fall back to (OIDC Core §3.1.2.1).
    ///
    /// Last in the negotiation `asterius_domain::locale::negotiate` performs,
    /// and read only when neither the client's `ui_locales` nor the browser's
    /// `Accept-Language` names a language this build renders.
    default_locale: Locale,
    /// Wording this tenant has substituted for the built-in strings.
    ///
    /// Validated as text by [`MessageOverrides`] and against the catalogue's
    /// key space by `asterius_web::i18n`: this crate knows what a safe string
    /// is, the crate that renders the pages knows what a key is.
    messages: MessageOverrides,
    /// Whether an access token issued here carries the `grant_id` private
    /// claim (RFC 9068 §2.2.3.1, Grant Management ID1 §6).
    ///
    /// `true` unless this tenant says otherwise, which is what every
    /// deployment did before this setting existed and what this server's own
    /// UserInfo endpoint resolves a grant through. It is the one field here
    /// whose default is not [`Default::default`] for its type, which is why
    /// this struct's `Default` is written out.
    ///
    /// It is an option rather than a constant because the claim is a
    /// *correlator*: two tokens carrying the same `grant_id` tell a resource
    /// server they came from one authorization (RFC 9068 §6). A deployment
    /// whose resource servers are all third parties has no use for that and
    /// every reason to withhold it.
    ///
    /// Last, for the reason the field above it is last: a new member goes at
    /// the end so that a parallel change adding another one does not have to
    /// be reconciled line by line.
    grant_id_in_access_token: bool,
    /// Whether ending a browser session also revokes the refresh tokens issued
    /// under it (`ast-o4u.2`).
    ///
    /// `false` unless this tenant says otherwise, and the default is a
    /// decision rather than an oversight. A refresh token is not a session: it
    /// is offline access a person granted a client, it survives the browser
    /// being closed, and OIDC RP-Initiated Logout §2 asks the OP to end "the
    /// session", not the grants. A tenant whose clients are all first-party
    /// browser applications means the opposite by "log out" and turns this on;
    /// one whose clients hold `offline_access` would find every integration
    /// broken by a user signing out of the console.
    ///
    /// When it is on, the withdrawal reaches the access tokens too, through
    /// the grant cutoff — RFC 7009 §2.1: revoking a refresh token SHOULD "also
    /// invalidate all access tokens based on the same authorization grant".
    ///
    /// Last, for the reason the field above it is last: a new member goes at
    /// the end so that a parallel change adding another one does not have to
    /// be reconciled line by line.
    revoke_refresh_on_logout: bool,
}

impl Default for TenantSettings {
    /// A tenant that has expressed no opinion about anything.
    ///
    /// Written out rather than derived because of the last field: `false` is
    /// what `bool::default` would give and it is the wrong answer, since it
    /// would take the `grant_id` claim away from every tenant that has never
    /// heard of the setting — and with it UserInfo's way of resolving a grant.
    fn default() -> Self {
        Self {
            disabled_features: BTreeSet::new(),
            lifetimes: TokenLifetimes::default(),
            registration: RegistrationPolicy::default(),
            grant_management_action_required: false,
            default_locale: Locale::default(),
            messages: MessageOverrides::default(),
            grant_id_in_access_token: true,
            revoke_refresh_on_logout: false,
        }
    }
}

impl TenantSettings {
    /// Assembles settings, refusing any lifetime the profile does not allow.
    ///
    /// # Errors
    ///
    /// Whatever [`TokenLifetimes::validated`] refuses.
    pub fn validated(
        disabled_features: BTreeSet<Feature>,
        authorization_code_lifetime: Duration,
        access_token_lifetime: Duration,
    ) -> Result<Self, TenantSettingsError> {
        Ok(Self {
            disabled_features,
            lifetimes: TokenLifetimes::validated(
                authorization_code_lifetime,
                access_token_lifetime,
            )?,
            registration: RegistrationPolicy::default(),
            grant_management_action_required: false,
            default_locale: Locale::default(),
            messages: MessageOverrides::default(),
            grant_id_in_access_token: true,
            revoke_refresh_on_logout: false,
        })
    }

    /// The same settings with a registration policy attached.
    ///
    /// A separate builder rather than a fourth argument to
    /// [`TenantSettings::validated`], because a policy has already been through
    /// [`RegistrationPolicy::from_json`] by the time it gets here — there is
    /// nothing left for the validator to refuse, and widening a signature every
    /// caller passes defaults to would make the two look equally consequential.
    #[must_use]
    pub fn with_registration(mut self, registration: RegistrationPolicy) -> Self {
        self.registration = registration;
        self
    }

    /// The same settings with Grant Management ID1 §7.1 switched on.
    ///
    /// A builder rather than a fourth argument to [`TenantSettings::validated`],
    /// for the reason [`Self::with_registration`] gives.
    #[must_use]
    pub const fn requiring_a_grant_management_action(mut self, required: bool) -> Self {
        self.grant_management_action_required = required;
        self
    }

    /// Whether every authorization request here must name a
    /// `grant_management_action` (Grant Management ID1 §7.1).
    ///
    /// Never true for a tenant that does not offer Grant Management, whatever
    /// the stored row says: `deployment` is the deployment's own flag set, and
    /// the answer is taken from [`Self::effective_capabilities`] so that the
    /// discovery document and the pushed-request validator read one decision
    /// rather than two. A tenant that requires a parameter it also ignores
    /// would refuse every request it receives.
    #[must_use]
    pub fn grant_management_action_required(&self, deployment: Capabilities) -> bool {
        self.grant_management_action_required
            && self
                .effective_capabilities(deployment)
                .is_enabled(Feature::GrantManagement)
    }

    /// The same settings with a fallback language.
    ///
    /// A builder for the reason [`Self::with_registration`] gives: every
    /// existing caller means "the default", and widening the constructor would
    /// make a language look as consequential as a token lifetime.
    #[must_use]
    pub const fn with_default_locale(mut self, locale: Locale) -> Self {
        self.default_locale = locale;
        self
    }

    /// The same settings with a tenant's own wording attached.
    #[must_use]
    pub fn with_messages(mut self, messages: MessageOverrides) -> Self {
        self.messages = messages;
        self
    }

    /// The language this tenant's pages fall back to.
    #[must_use]
    pub const fn default_locale(&self) -> Locale {
        self.default_locale
    }

    /// The wording this tenant has substituted.
    #[must_use]
    pub const fn messages(&self) -> &MessageOverrides {
        &self.messages
    }

    /// The same settings with the `grant_id` access-token claim decided.
    ///
    /// A builder rather than another argument to [`TenantSettings::validated`],
    /// for the reason [`Self::with_registration`] gives.
    #[must_use]
    pub const fn with_grant_id_in_access_token(mut self, carried: bool) -> Self {
        self.grant_id_in_access_token = carried;
        self
    }

    /// The same settings with the logout's reach over refresh tokens decided.
    ///
    /// A builder rather than another argument to [`TenantSettings::validated`],
    /// for the reason [`Self::with_registration`] gives.
    #[must_use]
    pub const fn with_revoke_refresh_on_logout(mut self, revoke: bool) -> Self {
        self.revoke_refresh_on_logout = revoke;
        self
    }

    /// Whether ending a session here also revokes the refresh tokens issued
    /// under it (`ast-o4u.2`).
    ///
    /// See the field: `false` unless this tenant asked for it, because a
    /// refresh token is offline access rather than a session, and a default
    /// that revoked it would break every integration the moment somebody
    /// signed out of a browser.
    #[must_use]
    pub const fn revoke_refresh_on_logout(&self) -> bool {
        self.revoke_refresh_on_logout
    }

    /// Whether an access token minted here carries the `grant_id` claim.
    ///
    /// `true` unless this tenant has said otherwise, because that is what
    /// every token this server has ever issued carried and a default that
    /// changed the shape of a live token would break the resource servers
    /// reading it — including this server's own UserInfo endpoint.
    ///
    /// Deliberately *not* narrowed by [`Feature::GrantManagement`], unlike
    /// [`Self::grant_management_action_required`]: the claim predates Grant
    /// Management here and is what `/revoke` and UserInfo reach a token's
    /// authorization through, so a tenant that offers no Grant Management
    /// still has an opinion worth honouring.
    #[must_use]
    pub const fn grant_id_in_access_token(&self) -> bool {
        self.grant_id_in_access_token
    }

    /// This tenant's registration policy.
    #[must_use]
    pub const fn registration(&self) -> &RegistrationPolicy {
        &self.registration
    }

    /// Who may register a client here, given the deployment's own posture.
    #[must_use]
    pub fn registration_mode(&self, deployment: RegistrationMode) -> RegistrationMode {
        self.registration.effective_mode(deployment)
    }

    /// The features this tenant has switched off.
    #[must_use]
    pub const fn disabled_features(&self) -> &BTreeSet<Feature> {
        &self.disabled_features
    }

    /// The lifetimes this tenant issues with.
    #[must_use]
    pub const fn lifetimes(&self) -> TokenLifetimes {
        self.lifetimes
    }

    /// What this tenant can do, given what the deployment can do.
    ///
    /// Never wider than `deployment`: see the module documentation.
    #[must_use]
    pub fn effective_capabilities(&self, deployment: Capabilities) -> Capabilities {
        let mut effective = deployment;
        for feature in &self.disabled_features {
            effective.disable(*feature);
        }
        // A tenant that registers nobody has no registration endpoint, and
        // `ast-0qv` is that this must be the same subtraction every other
        // feature goes through: the discovery document and
        // `tenant_feature_guard` both read this, so the endpoint disappears
        // from the metadata and answers 404 in one step rather than two that
        // could disagree.
        if self.registration.mode() == Some(RegistrationMode::Closed) {
            effective.disable(Feature::DynamicClientRegistration);
        }
        effective
    }

    /// The settings as they are stored in `tenants.settings`.
    ///
    /// Written out in full rather than as a diff against the defaults, so that
    /// changing a default in this file never silently changes what an existing
    /// tenant does — the reason [`crate::RefreshPolicy::to_json`] states.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "disabled_features": self
                .disabled_features
                .iter()
                .map(|feature| feature.as_str())
                .collect::<Vec<_>>(),
            "authorization_code_lifetime_seconds":
                self.lifetimes.authorization_code.whole_seconds(),
            "access_token_lifetime_seconds": self.lifetimes.access_token.whole_seconds(),
            "registration_policy": self.registration.to_json(),
            "grant_management_action_required": self.grant_management_action_required,
            // OIDC Core §3.1.2.1's last resort. Written as the tag rather than
            // as an index into an enum, because the row outlives the build that
            // wrote it and a reordered enum must not silently change a
            // tenant's language.
            "default_locale": self.default_locale.as_tag(),
            "messages": self.messages.to_json(),
            "grant_id_in_access_token": self.grant_id_in_access_token,
            "revoke_refresh_on_logout": self.revoke_refresh_on_logout,
        })
    }

    /// Reads settings back out of `tenants.settings`.
    ///
    /// An *absent* member is a tenant that has never expressed an opinion,
    /// which is the defaults. A member that is present and wrong is refused:
    /// rows get edited by hand during incidents, and a lifetime that quietly
    /// fell back to a default is a setting an operator believes is in force
    /// and is not. A stored lifetime *above* the profile's ceiling is refused
    /// for the same reason — it can only have arrived by a route that did not
    /// go through [`TenantSettings::validated`].
    ///
    /// # Errors
    ///
    /// [`TenantSettingsError`] when the stored object is not one this server
    /// wrote.
    // fuzz-target: tenant_settings
    pub fn from_json(value: Option<&serde_json::Value>) -> Result<Self, TenantSettingsError> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        if value.is_null() {
            return Ok(Self::default());
        }
        let object = value.as_object().ok_or(TenantSettingsError::NotAnObject)?;

        let mut disabled_features = BTreeSet::new();
        match object.get("disabled_features") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Array(names)) => {
                for name in names {
                    let name = name.as_str().ok_or(TenantSettingsError::NotAFeatureName)?;
                    let feature = Feature::from_key(name)
                        .ok_or_else(|| TenantSettingsError::UnknownFeature(name.to_owned()))?;
                    disabled_features.insert(feature);
                }
            }
            Some(_) => return Err(TenantSettingsError::NotAFeatureName),
        }

        let authorization_code = seconds(object.get("authorization_code_lifetime_seconds"))?
            .unwrap_or(DEFAULT_AUTHORIZATION_CODE_LIFETIME);
        let access_token = seconds(object.get("access_token_lifetime_seconds"))?
            .unwrap_or(DEFAULT_ACCESS_TOKEN_LIFETIME);

        let registration = RegistrationPolicy::from_json(object.get("registration_policy"))?;

        // Grant Management ID1 §7.1. Absent is `false`, which is what every row
        // written before this setting existed means; present and not a boolean
        // is refused rather than coerced, for the reason the lifetimes give.
        let grant_management_action_required = match object.get("grant_management_action_required")
        {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Bool(required)) => *required,
            Some(_) => {
                return Err(TenantSettingsError::NotABoolean(
                    "grant_management_action_required",
                ));
            }
        };

        // Absent is the built-in default, which is what every row written
        // before this setting existed means. Present and not a language this
        // build renders is refused rather than coerced: a tenant that
        // configured French and is served English has a setting an operator
        // believes is in force and is not — the same rule the lifetimes follow.
        // Note the asymmetry with `ui_locales`, which is a *client's* hint and
        // must never fail a request (§3.1.2.1); this is the deployment's own
        // configuration, and it fails a settings read rather than a sign-in.
        let default_locale = match object.get("default_locale") {
            None | Some(serde_json::Value::Null) => Locale::default(),
            Some(serde_json::Value::String(tag)) => Locale::matching(tag)
                .ok_or_else(|| TenantSettingsError::UnsupportedLocale(tag.clone()))?,
            Some(_) => return Err(TenantSettingsError::UnsupportedLocale(String::new())),
        };

        let messages = MessageOverrides::from_json(object.get("messages"))?;

        // RFC 9068 §2.2.3.1's private claim. Absent is *not* `false` here: a
        // row written before this setting existed belongs to a deployment
        // whose tokens carried the claim, and reading silence as "withhold it"
        // would take UserInfo's only way of resolving a grant away from every
        // tenant that has never opened this file.
        let grant_id_in_access_token = match object.get("grant_id_in_access_token") {
            None | Some(serde_json::Value::Null) => true,
            Some(serde_json::Value::Bool(carried)) => *carried,
            Some(_) => {
                return Err(TenantSettingsError::NotABoolean("grant_id_in_access_token"));
            }
        };

        // Absent *is* `false` here, unlike the setting above it: a row written
        // before this existed belongs to a deployment whose logouts never
        // touched a refresh token, and reading silence as "revoke" would
        // withdraw offline access nobody asked to withdraw.
        let revoke_refresh_on_logout = match object.get("revoke_refresh_on_logout") {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::Bool(revoke)) => *revoke,
            Some(_) => {
                return Err(TenantSettingsError::NotABoolean("revoke_refresh_on_logout"));
            }
        };

        Ok(
            Self::validated(disabled_features, authorization_code, access_token)?
                .with_registration(registration)
                .requiring_a_grant_management_action(grant_management_action_required)
                .with_default_locale(default_locale)
                .with_messages(messages)
                .with_grant_id_in_access_token(grant_id_in_access_token)
                .with_revoke_refresh_on_logout(revoke_refresh_on_logout),
        )
    }
}

/// Reads a `…_seconds` member. `null` and absent both mean "not set".
fn seconds(value: Option<&serde_json::Value>) -> Result<Option<Duration>, TenantSettingsError> {
    match value {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => {
            let seconds = value
                .as_i64()
                .ok_or(TenantSettingsError::NotAWholeNumberOfSeconds)?;
            Ok(Some(Duration::seconds(seconds)))
        }
    }
}

/// Why a set of tenant settings was refused.
///
/// The messages name the clause they come from. An administrator who is told
/// "invalid lifetime" goes and tries 300 seconds next; one who is told which
/// profile forbids it stops.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TenantSettingsError {
    /// Above the 60-second ceiling.
    #[error(
        "an authorization code lifetime of {requested_seconds} s exceeds the maximum of 60 s \
         required by FAPI 2.0 Security Profile §5.3.2.1 item 11"
    )]
    AuthorizationCodeLifetimeTooLong {
        /// What was asked for.
        requested_seconds: i64,
    },
    /// Above this server's access-token ceiling.
    #[error(
        "an access token lifetime of {requested_seconds} s exceeds this server's maximum of \
         900 s, which follows FAPI 2.0 Security Profile §6.1"
    )]
    AccessTokenLifetimeTooLong {
        /// What was asked for.
        requested_seconds: i64,
    },
    /// Zero or negative.
    #[error("a lifetime must be at least one second")]
    LifetimeNotPositive,
    /// The stored settings member is not a JSON object.
    #[error("the stored tenant settings are not an object")]
    NotAnObject,
    /// `disabled_features` is not an array of strings.
    #[error("the disabled features are not a list of feature names")]
    NotAFeatureName,
    /// A feature name this build does not know.
    #[error("the stored tenant settings disable an unknown feature: {0}")]
    UnknownFeature(String),
    /// A duration that is not a whole number of seconds.
    #[error("a stored lifetime is not a whole number of seconds")]
    NotAWholeNumberOfSeconds,
    /// The stored registration policy is not one this server wrote.
    #[error("the stored registration policy is invalid: {0}")]
    RegistrationPolicy(#[from] RegistrationPolicyError),
    /// A language this build has no catalogue for.
    #[error(
        "the stored default locale '{0}' is not one this build renders; the supported tags are          the members of `ui_locales_supported`"
    )]
    UnsupportedLocale(String),
    /// The stored message overrides are not ones this server would accept.
    #[error("the stored message overrides are invalid: {0}")]
    MessageOverrides(#[from] crate::messages::MessageOverrideError),
    /// A member that must be `true` or `false` is something else.
    ///
    /// Refused rather than read as `false`, for the reason a stored lifetime is
    /// refused rather than defaulted: a row gets edited by hand during an
    /// incident, and a setting that quietly fell back is one an operator
    /// believes is in force and is not.
    #[error("the stored tenant setting {0} is not a boolean")]
    NotABoolean(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A row written before the setting existed still carries `grant_id`.
    ///
    /// The one default that cannot flip: UserInfo resolves a grant through the
    /// claim, so silence has to keep meaning what it has always meant.
    #[test]
    fn a_tenant_that_never_mentioned_the_grant_id_claim_still_carries_it() {
        // Arrange
        let stored = serde_json::json!({"disabled_features": []});

        // Act
        let settings = TenantSettings::from_json(Some(&stored)).expect("a readable row");

        // Assert
        assert!(settings.grant_id_in_access_token());
    }

    /// A tenant that withholds the claim round-trips as withholding it.
    #[test]
    fn withholding_the_grant_id_claim_round_trips() {
        // Arrange
        let settings = TenantSettings::default().with_grant_id_in_access_token(false);

        // Act
        let read_back =
            TenantSettings::from_json(Some(&settings.to_json())).expect("this server wrote it");

        // Assert
        assert!(!read_back.grant_id_in_access_token());
    }

    /// A `grant_id_in_access_token` that is not a boolean is refused.
    #[test]
    fn a_grant_id_claim_setting_that_is_not_a_boolean_is_refused() {
        // Arrange
        let stored = serde_json::json!({"grant_id_in_access_token": "yes"});

        // Act
        let error = TenantSettings::from_json(Some(&stored)).expect_err("not a boolean");

        // Assert
        assert!(
            matches!(
                error,
                TenantSettingsError::NotABoolean("grant_id_in_access_token")
            ),
            "{error}"
        );
    }

    /// A tenant that has never opened this file keeps the behaviour it had:
    /// signing out of a browser leaves a client's offline access alone
    /// (`ast-o4u.2`). Silence here means `false`, unlike the setting above it,
    /// because reading it as `true` would withdraw grants nobody asked to
    /// withdraw.
    #[test]
    fn a_tenant_that_never_mentioned_it_does_not_revoke_refresh_at_logout() {
        // Arrange
        let stored = serde_json::json!({"disabled_features": []});

        // Act
        let settings = TenantSettings::from_json(Some(&stored)).expect("a readable row");

        // Assert
        assert!(!settings.revoke_refresh_on_logout());
    }

    /// A tenant that asked for it round-trips as asking for it: this is the
    /// switch back-channel logout reads, and a setting that did not survive a
    /// write would be a policy an operator believes is in force.
    #[test]
    fn revoking_refresh_tokens_at_logout_round_trips() {
        // Arrange
        let settings = TenantSettings::default().with_revoke_refresh_on_logout(true);

        // Act
        let read_back =
            TenantSettings::from_json(Some(&settings.to_json())).expect("this server wrote it");

        // Assert
        assert!(read_back.revoke_refresh_on_logout());
    }

    /// The tenant default is the last layer of OIDC Core §3.1.2.1 negotiation,
    /// so it has to survive a write and a read.
    #[test]
    fn the_default_locale_round_trips_and_is_english_when_absent() {
        // Arrange
        let settings = TenantSettings::default().with_default_locale(Locale::French);

        // Act
        let read_back =
            TenantSettings::from_json(Some(&settings.to_json())).expect("this server wrote it");

        // Assert
        assert_eq!(read_back.default_locale(), Locale::French);
        assert_eq!(
            TenantSettings::from_json(Some(&serde_json::json!({})))
                .expect("an empty document is the defaults")
                .default_locale(),
            Locale::English
        );
    }

    /// A hand-edited row naming a language with no catalogue fails the read
    /// rather than quietly serving English.
    #[test]
    fn a_stored_locale_this_build_cannot_render_is_refused() {
        // Arrange
        let document = serde_json::json!({ "default_locale": "de" });

        // Act
        let refused = TenantSettings::from_json(Some(&document)).expect_err("no German catalogue");

        // Assert
        assert_eq!(
            refused,
            TenantSettingsError::UnsupportedLocale("de".to_owned())
        );
    }

    /// The overrides travel in the same document as the lifetimes, and markup
    /// in one of them fails the whole read.
    #[test]
    fn message_overrides_round_trip_and_markup_fails_the_read() {
        // Arrange
        let overrides =
            MessageOverrides::from_pairs([("consent.allow", "Autoriser")]).expect("plain text");
        let settings = TenantSettings::default().with_messages(overrides);

        // Act
        let read_back =
            TenantSettings::from_json(Some(&settings.to_json())).expect("this server wrote it");
        let hostile = TenantSettings::from_json(Some(&serde_json::json!({
            "messages": { "consent.allow": "<script>alert(1)</script>" }
        })));

        // Assert
        assert_eq!(read_back.messages().get("consent.allow"), Some("Autoriser"));
        assert!(matches!(
            hostile,
            Err(TenantSettingsError::MessageOverrides(_))
        ));
    }

    /// Grant Management ID1 §7.1 round-trips through the stored document, and
    /// a row written before the setting existed reads back as "not required".
    #[test]
    fn the_grant_management_action_requirement_round_trips() {
        // Arrange
        let offering = Capabilities {
            grant_management: true,
            ..Capabilities::default()
        };
        let settings = TenantSettings::default().requiring_a_grant_management_action(true);

        // Act
        let stored = settings.to_json();
        let read_back = TenantSettings::from_json(Some(&stored)).expect("this server wrote it");

        // Assert
        assert!(read_back.grant_management_action_required(offering));
        assert!(
            !TenantSettings::default().grant_management_action_required(offering),
            "a row that never mentioned the setting does not require an action"
        );
    }

    /// §7.1 is a statement about Grant Management: a tenant that has switched
    /// the feature off, or a deployment that never offered it, cannot require
    /// the parameter — it would refuse every request it receives.
    #[test]
    fn a_tenant_without_grant_management_never_requires_the_action() {
        // Arrange
        let offering = Capabilities {
            grant_management: true,
            ..Capabilities::default()
        };
        let settings = TenantSettings::validated(
            [Feature::GrantManagement].into_iter().collect(),
            DEFAULT_AUTHORIZATION_CODE_LIFETIME,
            DEFAULT_ACCESS_TOKEN_LIFETIME,
        )
        .expect("valid lifetimes")
        .requiring_a_grant_management_action(true);

        // Act & Assert
        assert!(
            !settings.grant_management_action_required(offering),
            "the tenant disabled the feature"
        );
        assert!(
            !TenantSettings::default()
                .requiring_a_grant_management_action(true)
                .grant_management_action_required(Capabilities::default()),
            "the deployment never offered the feature"
        );
    }

    /// A hand-edited row that says something other than `true` or `false` is
    /// refused, not read as `false`.
    #[test]
    fn a_non_boolean_action_requirement_is_refused() {
        // Arrange
        let stored = serde_json::json!({"grant_management_action_required": "yes"});

        // Act
        let outcome = TenantSettings::from_json(Some(&stored));

        // Assert
        assert_eq!(
            outcome,
            Err(TenantSettingsError::NotABoolean(
                "grant_management_action_required"
            ))
        );
    }

    /// FAPI 2.0 SP §5.3.2.1 item 11, which is the acceptance criterion of
    /// `ast-f7m.4`: the refusal happens below the API, so no caller can reach
    /// past a form to obtain a longer code.
    #[test]
    fn an_authorization_code_lifetime_above_sixty_seconds_is_refused() {
        // Arrange
        let requested = Duration::seconds(61);

        // Act
        let outcome = TokenLifetimes::validated(requested, DEFAULT_ACCESS_TOKEN_LIFETIME);

        // Assert
        assert_eq!(
            outcome,
            Err(TenantSettingsError::AuthorizationCodeLifetimeTooLong {
                requested_seconds: 61
            })
        );
    }

    /// The message is the other half of the criterion: it has to name the
    /// clause.
    #[test]
    fn the_refusal_cites_the_profile_clause() {
        // Arrange
        let error = TokenLifetimes::validated(Duration::minutes(5), DEFAULT_ACCESS_TOKEN_LIFETIME)
            .expect_err("five minutes is above the sixty-second ceiling");

        // Act
        let message = error.to_string();

        // Assert
        assert!(
            message.contains("FAPI 2.0 Security Profile §5.3.2.1 item 11"),
            "the refusal does not name the clause: {message}"
        );
    }

    #[test]
    fn exactly_sixty_seconds_is_allowed() {
        assert!(
            TokenLifetimes::validated(
                MAX_AUTHORIZATION_CODE_LIFETIME,
                DEFAULT_ACCESS_TOKEN_LIFETIME
            )
            .is_ok()
        );
    }

    #[test]
    fn an_access_token_lifetime_above_the_cap_is_refused() {
        // Arrange
        let requested = MAX_ACCESS_TOKEN_LIFETIME + Duration::seconds(1);

        // Act
        let outcome = TokenLifetimes::validated(DEFAULT_AUTHORIZATION_CODE_LIFETIME, requested);

        // Assert
        assert_eq!(
            outcome,
            Err(TenantSettingsError::AccessTokenLifetimeTooLong {
                requested_seconds: 901
            })
        );
    }

    #[test]
    fn a_zero_lifetime_is_refused() {
        assert_eq!(
            TokenLifetimes::validated(Duration::ZERO, DEFAULT_ACCESS_TOKEN_LIFETIME),
            Err(TenantSettingsError::LifetimeNotPositive)
        );
    }

    /// The subtraction rule: a tenant switching a flag off narrows the
    /// deployment's capabilities and can never widen them.
    #[test]
    fn a_tenant_can_only_narrow_the_deployments_capabilities() {
        // Arrange
        let deployment = Capabilities {
            dpop_nonce: true,
            request_object: true,
            mtls: true,
            ..Capabilities::default()
        };
        let settings = TenantSettings::validated(
            BTreeSet::from([Feature::DpopNonce]),
            DEFAULT_AUTHORIZATION_CODE_LIFETIME,
            DEFAULT_ACCESS_TOKEN_LIFETIME,
        )
        .expect("within the caps");

        // Act
        let effective = settings.effective_capabilities(deployment);

        // Assert
        assert!(!effective.is_enabled(Feature::DpopNonce));
        assert!(effective.is_enabled(Feature::Mtls));
    }

    /// Switching off a feature the deployment never had is not an error and is
    /// not a way to turn it on.
    #[test]
    fn disabling_a_feature_the_deployment_lacks_changes_nothing() {
        // Arrange
        let settings = TenantSettings::validated(
            BTreeSet::from([Feature::Ciba]),
            DEFAULT_AUTHORIZATION_CODE_LIFETIME,
            DEFAULT_ACCESS_TOKEN_LIFETIME,
        )
        .expect("within the caps");

        // Act
        let effective = settings.effective_capabilities(Capabilities::default());

        // Assert
        assert_eq!(effective, Capabilities::default());
    }

    #[test]
    fn settings_survive_a_round_trip_through_storage() {
        // Arrange
        let settings = TenantSettings::validated(
            BTreeSet::from([Feature::DpopNonce, Feature::Mtls]),
            Duration::seconds(30),
            Duration::minutes(10),
        )
        .expect("within the caps");

        // Act
        let read_back = TenantSettings::from_json(Some(&settings.to_json()));

        // Assert
        assert_eq!(read_back, Ok(settings));
    }

    #[test]
    fn absent_settings_are_the_defaults() {
        assert_eq!(
            TenantSettings::from_json(None),
            Ok(TenantSettings::default())
        );
        assert_eq!(
            TenantSettings::from_json(Some(&serde_json::Value::Null)),
            Ok(TenantSettings::default())
        );
    }

    /// A row edited by hand cannot smuggle a longer code past the profile: the
    /// read refuses it rather than serving it.
    #[test]
    fn a_stored_lifetime_above_the_cap_fails_the_read() {
        // Arrange
        let stored = serde_json::json!({
            "disabled_features": [],
            "authorization_code_lifetime_seconds": 3600,
            "access_token_lifetime_seconds": 300,
        });

        // Act
        let outcome = TenantSettings::from_json(Some(&stored));

        // Assert
        assert_eq!(
            outcome,
            Err(TenantSettingsError::AuthorizationCodeLifetimeTooLong {
                requested_seconds: 3600
            })
        );
    }

    #[test]
    fn a_stored_feature_name_this_build_does_not_know_fails_the_read() {
        // Arrange
        let stored = serde_json::json!({ "disabled_features": ["telepathy"] });

        // Act
        let outcome = TenantSettings::from_json(Some(&stored));

        // Assert
        assert_eq!(
            outcome,
            Err(TenantSettingsError::UnknownFeature("telepathy".to_owned()))
        );
    }

    /// The parser is reached from the admin API and from every row read, so it
    /// is fuzzed (`fuzz/fuzz_targets/tenant_settings.rs`). This is the
    /// property that target asserts: whatever the input, the parser either
    /// answers or refuses, and never panics.
    #[test]
    fn arbitrary_json_never_panics_the_parser() {
        for value in [
            serde_json::json!(42),
            serde_json::json!("settings"),
            serde_json::json!([]),
            serde_json::json!({ "authorization_code_lifetime_seconds": "sixty" }),
            serde_json::json!({ "authorization_code_lifetime_seconds": -1 }),
            serde_json::json!({ "disabled_features": {} }),
            serde_json::json!({ "disabled_features": [7] }),
        ] {
            let _ = TenantSettings::from_json(Some(&value));
        }
    }
}
