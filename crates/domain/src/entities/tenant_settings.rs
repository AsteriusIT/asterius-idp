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
}

/// Everything a tenant may set about itself that this story covers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TenantSettings {
    disabled_features: BTreeSet<Feature>,
    lifetimes: TokenLifetimes,
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
        })
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

        Self::validated(disabled_features, authorization_code, access_token)
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
