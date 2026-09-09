//! The tenant entity.

use crate::{Issuer, TenantId};
use time::{Duration, OffsetDateTime};

/// A tenant. One tenant is one issuer, and one issuer is one tenant.
///
/// Deliberately not `#[non_exhaustive]`: adapters build entities from rows, so
/// sealing the struct would only push every adapter through a constructor that
/// takes the same fields in the same order, with less type checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    /// The tenant's identifier, as it appears in a path-based issuer.
    pub id: TenantId,
    /// The canonical issuer identifier.
    pub issuer: Issuer,
    /// The resource identifier an access token is audienced at when the grant
    /// names none of its own.
    ///
    /// RFC 9068 §3 requires one: an access token must carry an `aud`, and a
    /// grant that went through no `resource` parameter (RFC 8707 §2) has
    /// nothing to put there. Leaving it to the issuance code would mean
    /// inventing an audience at the moment a token is signed, which is how a
    /// deployment ends up with tokens every resource server accepts.
    ///
    /// Per tenant rather than per deployment, because `aud` is what a resource
    /// server compares to decide a token was meant for it, and two tenants
    /// sharing one identifier would give it nothing to tell them apart by
    /// except `iss`.
    pub default_resource: String,
    /// A vanity host that resolves to this tenant without a path prefix.
    pub custom_host: Option<String>,
    /// Human-readable name, shown on login and consent pages.
    pub display_name: String,
    /// Whether the tenant answers requests.
    pub status: TenantStatus,
    /// What this tenant does with refresh tokens.
    ///
    /// Carried on the entity rather than looked up at the token endpoint,
    /// because every decision it governs — how long a refresh token lives,
    /// whether it is pinned to a DPoP key, whether refreshing replaces it — is
    /// taken inside one request that already holds the tenant. A handler that
    /// had to fetch it could also forget to.
    pub refresh: RefreshPolicy,
    /// When the tenant was created.
    pub created_at: OffsetDateTime,
    /// When the tenant was last modified.
    pub updated_at: OffsetDateTime,
}

impl Tenant {
    /// Whether this tenant should answer protocol requests.
    ///
    /// A disabled tenant's endpoints behave as if the tenant does not exist,
    /// rather than returning a distinguishable error: an unauthenticated caller
    /// should not be able to enumerate which tenants have been suspended.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == TenantStatus::Active
    }
}

/// Whether a tenant answers requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantStatus {
    /// Serving.
    Active,
    /// Suspended; endpoints behave as if the tenant is not there.
    Disabled,
}

impl TenantStatus {
    /// The value as stored in the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }
}

/// What this tenant does with refresh tokens.
///
/// A tenant option rather than a deployment one because it is a statement
/// about how long an authorization may be acted on without the user present,
/// and two tenants of one deployment routinely answer to different regulators
/// about exactly that.
///
/// The defaults are FAPI 2.0 SP's position rather than a compromise:
/// [`Rotation::None`], because §5.3.2.1 item 9 says an authorization server
/// "shall not use refresh token rotation except in extraordinary
/// circumstances"; and `bind_to_dpop_key` on, because §5.3.2.1 item 5 wants a
/// refresh token sender-constrained rather than merely accompanied by a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshPolicy {
    /// How long a refresh token may live at all, counted from issuance.
    ///
    /// It never moves. A grant that should outlive it is renewed by sending
    /// the user through authorization again, which is the point: an absolute
    /// deadline is the one lifetime an attacker holding the token cannot
    /// extend by using it.
    pub absolute_lifetime: Duration,
    /// How long a refresh token may sit unused before it lapses.
    ///
    /// This one *does* move: every successful refresh pushes it out. It
    /// answers a different question from the absolute deadline — "is this
    /// integration still in use" rather than "is this authorization still
    /// fresh" — which is why the two are separate values here and separate
    /// columns in storage, rather than one expiry meaning whichever of the two
    /// last wrote it.
    ///
    /// `None` switches the idle clock off; the absolute deadline still runs.
    pub idle_lifetime: Option<Duration>,
    /// Whether a refresh token may only be presented with the DPoP key it was
    /// issued to.
    ///
    /// RFC 9449 §5 requires this of public clients and leaves it open for
    /// confidential ones, which authenticate anyway. On is the stricter
    /// reading and the default: a refresh token copied out of a confidential
    /// client's store is then useless without that client's DPoP private key
    /// as well as its credentials.
    pub bind_to_dpop_key: bool,
    /// Whether a refresh reissues the token or hands back the same one.
    pub rotation: Rotation,
}

/// Whether refreshing replaces the refresh token.
///
/// Two variants and no third, because there are exactly two defensible
/// positions and "rotate because everyone does" is not one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    /// The same token comes back, unchanged.
    ///
    /// FAPI 2.0 SP §5.3.2.1 item 9. Rotation exists to detect the replay of a
    /// *bearer* refresh token; a sender-constrained one cannot be replayed by
    /// anybody who lacks the key, so rotation buys nothing here and costs the
    /// familiar failure where a client that loses one response loses the
    /// authorization with it.
    None,
    /// A new token is issued and the old one keeps working for a while.
    ///
    /// FAPI 2.0 SP Note 1's "extraordinary circumstances": a migration off a
    /// server that rotated, where clients in the field discard a refresh token
    /// they did not just receive. It is time-boxed by `grace` deliberately —
    /// the superseded token is accepted for that long, so a client that
    /// crashed between receiving the response and storing it can retry — and
    /// it is meant to be switched off again afterwards.
    Migration {
        /// How long a superseded token is still accepted.
        grace: Duration,
    },
}

/// How long a refresh token lives unless a tenant says otherwise.
///
/// Thirty days is the usual ceiling for a consumer integration and short
/// enough that an abandoned authorization stops working within a billing
/// cycle. FAPI 2.0 SP §6.1 asks for short access tokens behind longer-lived
/// grants and puts no number on the grant.
pub const DEFAULT_REFRESH_ABSOLUTE_LIFETIME: Duration = Duration::days(30);

/// How long a refresh token may sit unused by default.
///
/// Two weeks: long enough that a monthly batch job is not the thing that
/// breaks, short enough that a token stolen from an integration nobody runs
/// any more has stopped working before anybody notices it was still there.
pub const DEFAULT_REFRESH_IDLE_LIFETIME: Duration = Duration::days(14);

/// The shortest grace window a migration rotation may use.
pub const MIN_ROTATION_GRACE: Duration = Duration::seconds(1);

/// The longest grace window a migration rotation may use.
///
/// A grace window is a period in which two refresh tokens are live for one
/// grant, which is the state rotation exists to eliminate. An hour is generous
/// for a client retrying a failed request and far short of anything that could
/// be called a policy.
pub const MAX_ROTATION_GRACE: Duration = Duration::hours(1);

impl Default for RefreshPolicy {
    fn default() -> Self {
        Self {
            absolute_lifetime: DEFAULT_REFRESH_ABSOLUTE_LIFETIME,
            idle_lifetime: Some(DEFAULT_REFRESH_IDLE_LIFETIME),
            bind_to_dpop_key: true,
            rotation: Rotation::None,
        }
    }
}

impl RefreshPolicy {
    /// Clamps a configured policy into something coherent.
    ///
    /// The same treatment [`crate::entities::session::Lifetimes::clamped`]
    /// gives session timeouts, for the same reason: an idle window longer than
    /// the absolute lifetime is not a stricter setting, it is a setting with no
    /// effect, and ignoring it silently makes the configuration and the
    /// behaviour two different things.
    #[must_use]
    pub fn clamped(self) -> Self {
        let absolute = self.absolute_lifetime.max(Duration::minutes(1));
        Self {
            absolute_lifetime: absolute,
            idle_lifetime: self
                .idle_lifetime
                .map(|idle| idle.clamp(Duration::minutes(1), absolute)),
            bind_to_dpop_key: self.bind_to_dpop_key,
            rotation: match self.rotation {
                Rotation::None => Rotation::None,
                Rotation::Migration { grace } => Rotation::Migration {
                    grace: grace.clamp(MIN_ROTATION_GRACE, MAX_ROTATION_GRACE),
                },
            },
        }
    }

    /// Whether this policy replaces the token on every refresh.
    #[must_use]
    pub const fn rotates(&self) -> bool {
        matches!(self.rotation, Rotation::Migration { .. })
    }

    /// How long a superseded token stays acceptable; zero when the policy does
    /// not rotate, because then nothing is ever superseded.
    #[must_use]
    pub const fn grace(&self) -> Duration {
        match self.rotation {
            Rotation::None => Duration::ZERO,
            Rotation::Migration { grace } => grace,
        }
    }

    /// The policy as it is stored in `tenants.settings`.
    ///
    /// Written out in full rather than as a diff against the defaults, so that
    /// changing a default in this file never silently changes what an existing
    /// tenant does.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "absolute_lifetime_seconds": self.absolute_lifetime.whole_seconds(),
            "idle_lifetime_seconds": self.idle_lifetime.map(Duration::whole_seconds),
            "bind_to_dpop_key": self.bind_to_dpop_key,
            "rotation": match self.rotation {
                Rotation::None => serde_json::json!({ "mode": "none" }),
                Rotation::Migration { grace } => serde_json::json!({
                    "mode": "migration",
                    "grace_seconds": grace.whole_seconds(),
                }),
            },
        })
    }

    /// Reads a policy back out of `tenants.settings`.
    ///
    /// A stored value that no longer makes sense is refused rather than
    /// repaired. Rows get edited by hand during incidents, and a policy that
    /// quietly fell back to the defaults would be a tenant whose
    /// `bind_to_dpop_key` turned itself on unannounced — or, worse, a rotation
    /// window somebody believed they had closed.
    ///
    /// An *absent* value is a tenant that has never expressed an opinion, and
    /// that is the default policy rather than an error.
    ///
    /// # Errors
    ///
    /// [`RefreshPolicyError`] when the stored object is not one this server
    /// wrote.
    pub fn from_json(value: Option<&serde_json::Value>) -> Result<Self, RefreshPolicyError> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        if value.is_null() {
            return Ok(Self::default());
        }
        let object = value.as_object().ok_or(RefreshPolicyError::NotAnObject)?;

        let absolute = seconds(object.get("absolute_lifetime_seconds"))?
            .ok_or(RefreshPolicyError::MissingAbsoluteLifetime)?;
        let idle = seconds(object.get("idle_lifetime_seconds"))?;
        let bind_to_dpop_key = object
            .get("bind_to_dpop_key")
            .and_then(serde_json::Value::as_bool)
            .ok_or(RefreshPolicyError::MissingBinding)?;

        let rotation = match object.get("rotation") {
            None => Rotation::None,
            Some(rotation) => {
                let rotation = rotation
                    .as_object()
                    .ok_or(RefreshPolicyError::UnknownRotationMode)?;
                match rotation.get("mode").and_then(serde_json::Value::as_str) {
                    Some("none") => Rotation::None,
                    Some("migration") => Rotation::Migration {
                        grace: seconds(rotation.get("grace_seconds"))?
                            .ok_or(RefreshPolicyError::MissingGrace)?,
                    },
                    _ => return Err(RefreshPolicyError::UnknownRotationMode),
                }
            }
        };

        Ok(Self {
            absolute_lifetime: absolute,
            idle_lifetime: idle,
            bind_to_dpop_key,
            rotation,
        }
        .clamped())
    }
}

/// Reads a `…_seconds` member, refusing anything that is not a positive whole
/// number of seconds. `null` and absent both mean "not set".
fn seconds(value: Option<&serde_json::Value>) -> Result<Option<Duration>, RefreshPolicyError> {
    match value {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => {
            let seconds = value
                .as_i64()
                .ok_or(RefreshPolicyError::NotAWholeNumberOfSeconds)?;
            if seconds <= 0 {
                return Err(RefreshPolicyError::NotAWholeNumberOfSeconds);
            }
            Ok(Some(Duration::seconds(seconds)))
        }
    }
}

/// Why a stored refresh policy could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RefreshPolicyError {
    /// `settings.refresh` is present but is not a JSON object.
    #[error("the stored refresh policy is not an object")]
    NotAnObject,
    /// The absolute lifetime is missing.
    #[error("the stored refresh policy names no absolute lifetime")]
    MissingAbsoluteLifetime,
    /// `bind_to_dpop_key` is missing. Not defaulted: a policy silent about
    /// sender-constraining is not a policy this server can apply.
    #[error("the stored refresh policy does not say whether to bind to the DPoP key")]
    MissingBinding,
    /// A rotation mode this server does not implement.
    #[error("the stored refresh policy names an unknown rotation mode")]
    UnknownRotationMode,
    /// `migration` rotation with no grace window.
    #[error("a migration rotation names no grace window")]
    MissingGrace,
    /// A duration that is not a positive whole number of seconds.
    #[error("a stored lifetime is not a positive whole number of seconds")]
    NotAWholeNumberOfSeconds,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FAPI 2.0 SP §5.3.2.1 item 9. The default is the compliant position, so
    /// a deployment that configures nothing is compliant.
    #[test]
    fn the_default_policy_does_not_rotate() {
        // Arrange
        let policy = RefreshPolicy::default();

        // Act
        let rotates = policy.rotates();

        // Assert
        assert!(!rotates, "FAPI 2.0 forbids rotation by default");
    }

    /// The other half of the default: a refresh token is sender-constrained
    /// unless a tenant explicitly relaxes it.
    #[test]
    fn the_default_policy_binds_to_the_dpop_key() {
        assert!(RefreshPolicy::default().bind_to_dpop_key);
    }

    /// An idle window past the absolute deadline is a setting with no effect.
    #[test]
    fn an_idle_window_longer_than_the_absolute_lifetime_is_capped() {
        // Arrange
        let policy = RefreshPolicy {
            absolute_lifetime: Duration::days(1),
            idle_lifetime: Some(Duration::days(30)),
            ..RefreshPolicy::default()
        };

        // Act
        let clamped = policy.clamped();

        // Assert
        assert_eq!(clamped.idle_lifetime, Some(Duration::days(1)));
    }

    /// The grace window is bounded on both sides: it is the period in which
    /// two refresh tokens are live for one grant.
    #[test]
    fn a_migration_grace_window_is_clamped_to_an_hour() {
        // Arrange
        let policy = RefreshPolicy {
            rotation: Rotation::Migration {
                grace: Duration::days(7),
            },
            ..RefreshPolicy::default()
        };

        // Act
        let clamped = policy.clamped();

        // Assert
        assert_eq!(clamped.grace(), MAX_ROTATION_GRACE);
    }

    #[test]
    fn a_policy_survives_a_round_trip_through_settings() {
        // Arrange
        let policy = RefreshPolicy {
            absolute_lifetime: Duration::days(7),
            idle_lifetime: Some(Duration::hours(6)),
            bind_to_dpop_key: false,
            rotation: Rotation::Migration {
                grace: Duration::seconds(30),
            },
        };

        // Act
        let read_back = RefreshPolicy::from_json(Some(&policy.to_json())).expect("valid policy");

        // Assert
        assert_eq!(read_back, policy);
    }

    /// A tenant that has never expressed an opinion gets the compliant
    /// default, which is not the same as a stored policy that is broken.
    #[test]
    fn an_absent_policy_is_the_default() {
        assert_eq!(
            RefreshPolicy::from_json(None).expect("absent is fine"),
            RefreshPolicy::default()
        );
    }

    /// A hand-edited row that dropped `bind_to_dpop_key` must not read as
    /// "bound": the safe direction here is to refuse the row, because
    /// defaulting it either way is a policy nobody wrote.
    #[test]
    fn a_stored_policy_without_a_binding_decision_is_refused() {
        // Arrange
        let stored = serde_json::json!({ "absolute_lifetime_seconds": 3600 });

        // Act
        let error = RefreshPolicy::from_json(Some(&stored)).expect_err("must refuse");

        // Assert
        assert_eq!(error, RefreshPolicyError::MissingBinding);
    }

    #[test]
    fn a_stored_policy_with_an_unknown_rotation_mode_is_refused() {
        // Arrange
        let stored = serde_json::json!({
            "absolute_lifetime_seconds": 3600,
            "bind_to_dpop_key": true,
            "rotation": { "mode": "silent" },
        });

        // Act
        let error = RefreshPolicy::from_json(Some(&stored)).expect_err("must refuse");

        // Assert
        assert_eq!(error, RefreshPolicyError::UnknownRotationMode);
    }

    /// A null idle lifetime is "no idle clock", which is a policy; a negative
    /// one is a corrupted row.
    #[test]
    fn a_negative_lifetime_is_refused_but_a_null_idle_window_is_not() {
        // Arrange
        let no_idle = serde_json::json!({
            "absolute_lifetime_seconds": 3600,
            "idle_lifetime_seconds": serde_json::Value::Null,
            "bind_to_dpop_key": true,
        });
        let negative = serde_json::json!({
            "absolute_lifetime_seconds": -1,
            "bind_to_dpop_key": true,
        });

        // Act
        let read = RefreshPolicy::from_json(Some(&no_idle)).expect("null idle is a policy");
        let error = RefreshPolicy::from_json(Some(&negative)).expect_err("must refuse");

        // Assert
        assert_eq!(read.idle_lifetime, None);
        assert_eq!(error, RefreshPolicyError::NotAWholeNumberOfSeconds);
    }
}
