//! Per-tenant initial access tokens: the credential RFC 7591 §1.2 names and
//! that this deployment could not, until now, issue to anybody.
//!
//! # Why a table and not a configuration file
//!
//! `asterius_server::http::register::InitialAccessTokens` holds the digests of
//! strings an operator wrote in `asterius.toml`. That works for a deployment
//! with one posture and no tenants worth telling apart, and it is a dead end
//! for everything else: a tenant that narrows its own registration mode to
//! `initial_access_token` is asking for a credential *it* controls, and there
//! was nowhere to put one. The result was a setting that stored, reloaded and
//! evaluated cleanly and refused every caller — the failure mode `ast-cu3` was
//! filed about.
//!
//! A row per token fixes the three things a file cannot express:
//!
//! * **Who it belongs to.** A token is scoped to one tenant and is refused at
//!   every other, by the `tenant_id` in the lookup rather than by a check
//!   somebody has to remember to write.
//! * **How many clients it may create.** The per-tenant policy's
//!   `max_clients_per_initial_access_token` is stamped onto the row when the
//!   token is issued, and [`Reservation`] is the only way to spend one.
//! * **When it stops working.** An expiry a clock enforces, rather than an
//!   operator remembering to edit a file and restart.
//!
//! # The plaintext exists for one response
//!
//! [`NewInitialAccessToken`] carries a digest and never a token. The admin API
//! generates the credential, shows it once in the response to the call that
//! created it, and stores this. Nothing in this crate, in the store or in the
//! audit trail can render it again, because nothing holds it — the same shape
//! as a registration access token (`crate::ports::ClientRegistry::register`)
//! and for the same reason.
//!
//! # The threat this adds
//!
//! The console becomes an issuer of credentials that create clients. An
//! administrator holding `admin.clients:write` on a tenant can mint a token
//! and register clients with it outside the console's own trail — which is why
//! issuance is audited with its actor, why the quota is stamped at issuance
//! rather than read from a document at redemption time, and why the label is
//! recorded. `docs/threat-model.md` carries the row.

use crate::{DomainError, TenantId};
use time::OffsetDateTime;
use uuid::Uuid;

/// The longest label an operator may put on a token.
///
/// A label is shown in a list and written to the audit trail; it is not a
/// credential and it is not a key. The bound exists so that one row cannot
/// carry a megabyte into every rendering of the screen.
pub const MAX_LABEL_LEN: usize = 200;

/// A token about to be stored: everything but the plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewInitialAccessToken {
    /// The tenant that may register with it. Never widened afterwards.
    pub tenant: TenantId,
    /// What an operator calls it. Free text, bounded, never a credential.
    pub label: String,
    /// SHA-256 of the token, which is the only form that is ever stored.
    pub digest: [u8; 32],
    /// How many clients it may create, or `None` for "no ceiling".
    ///
    /// Stamped from the tenant's
    /// [`crate::RegistrationPolicy::max_clients_per_initial_access_token`] at
    /// issuance. Reading it at redemption time instead would mean a policy
    /// edit silently re-opened tokens an operator had already spent, and would
    /// make "how many clients can this credential still create" a question
    /// with no answer on the row.
    pub max_uses: Option<u32>,
    /// When it stops being accepted, or `None` for "until it is deleted".
    pub expires_at: Option<OffsetDateTime>,
    /// The administrator who minted it, as the admin API names an actor.
    ///
    /// On the row and not only in the audit trail: the trail answers "what
    /// happened", and this answers "whose is this credential" while it is
    /// still live, which is the question an incident asks first.
    pub issued_by: String,
}

impl NewInitialAccessToken {
    /// Builds one, refusing what a store would have to refuse anyway.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] for an over-long label, a zero quota — a token
    /// that may create no client at all is a token nobody should be handed —
    /// or an expiry that has already passed.
    pub fn new(
        tenant: TenantId,
        label: impl Into<String>,
        digest: [u8; 32],
        max_uses: Option<u32>,
        expires_at: Option<OffsetDateTime>,
        issued_by: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        let label = label.into();
        if label.chars().count() > MAX_LABEL_LEN {
            return Err(DomainError::invalid(
                "label",
                format!("at most {MAX_LABEL_LEN} characters"),
            ));
        }
        if max_uses == Some(0) {
            return Err(DomainError::invalid(
                "max_clients",
                "a token that may register nothing is not worth issuing",
            ));
        }
        if expires_at.is_some_and(|at| at <= now) {
            return Err(DomainError::invalid(
                "expires_at",
                "an expiry in the past would issue a token that never worked",
            ));
        }
        Ok(Self {
            tenant,
            label,
            digest,
            max_uses,
            expires_at,
            issued_by: issued_by.into(),
        })
    }
}

/// One stored token, as an operator sees it.
///
/// No digest and no plaintext: this is what the console renders, and a digest
/// on that screen is a stable per-token identifier in everybody's browser
/// history for no operational gain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialAccessToken {
    /// The row's identifier, which is what a later revocation names.
    pub id: Uuid,
    /// The tenant it registers into.
    pub tenant: TenantId,
    /// The operator's label.
    pub label: String,
    /// Clients created with it so far.
    pub uses: u32,
    /// Its ceiling, or `None` for "no ceiling".
    pub max_uses: Option<u32>,
    /// When it stops being accepted.
    pub expires_at: Option<OffsetDateTime>,
    /// When it was issued.
    pub created_at: OffsetDateTime,
}

impl InitialAccessToken {
    /// How many clients it may still create, or `None` when it has no ceiling.
    ///
    /// Saturating rather than wrapping: a row edited by hand to `uses >
    /// max_uses` reports nothing left, which is the safe direction.
    #[must_use]
    pub const fn remaining(&self) -> Option<u32> {
        match self.max_uses {
            None => None,
            Some(max) => Some(max.saturating_sub(self.uses)),
        }
    }

    /// Whether it is spent or out of time at `now`.
    #[must_use]
    pub fn is_exhausted(&self, now: OffsetDateTime) -> bool {
        self.remaining() == Some(0) || self.expires_at.is_some_and(|at| at <= now)
    }
}

/// What asking to spend one use of a token answered.
///
/// The three refusals are kept apart here and *deliberately collapsed at the
/// endpoint*: RFC 7591 §3.2.2 defers to RFC 6750 §3.1, which gives
/// `invalid_token` for all of them, and telling an unauthenticated caller
/// which of "no such token", "expired" and "spent" applies is an oracle over a
/// credential space. They are distinct here so that the audit trail can say
/// which happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation {
    /// One use is now held against the row. The caller must either register a
    /// client or release it.
    Reserved {
        /// The row that was charged, for the release.
        id: Uuid,
        /// Uses left after this one, or `None` for "no ceiling".
        remaining: Option<u32>,
    },
    /// No row of this tenant has that digest.
    Unknown,
    /// The row exists and its expiry has passed.
    Expired,
    /// The row exists and its quota is spent.
    Exhausted,
}

impl Reservation {
    /// The reason, from a closed set, for the audit trail.
    ///
    /// Never rendered to the caller: see the type's documentation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved { .. } => "reserved",
            Self::Unknown => "unknown",
            Self::Expired => "expired",
            Self::Exhausted => "exhausted",
        }
    }

    /// The row charged, when one was.
    #[must_use]
    pub const fn reserved(self) -> Option<Uuid> {
        match self {
            Self::Reserved { id, .. } => Some(id),
            Self::Unknown | Self::Expired | Self::Exhausted => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a fixed instant")
    }

    fn digest() -> [u8; 32] {
        [7_u8; 32]
    }

    fn token(
        uses: u32,
        max_uses: Option<u32>,
        expires_at: Option<OffsetDateTime>,
    ) -> InitialAccessToken {
        InitialAccessToken {
            id: Uuid::from_u128(1),
            tenant: TenantId::new("demo"),
            label: "onboarding".to_owned(),
            uses,
            max_uses,
            expires_at,
            created_at: now(),
        }
    }

    #[test]
    fn a_well_formed_token_is_accepted() {
        // Arrange
        let expires = now() + Duration::days(1);

        // Act
        let built = NewInitialAccessToken::new(
            TenantId::new("demo"),
            "onboarding",
            digest(),
            Some(5),
            Some(expires),
            "admin@example",
            now(),
        );

        // Assert
        assert_eq!(built.expect("well formed").max_uses, Some(5));
    }

    #[test]
    fn a_quota_of_zero_is_refused() {
        // Arrange / Act
        let built = NewInitialAccessToken::new(
            TenantId::new("demo"),
            "onboarding",
            digest(),
            Some(0),
            None,
            "admin@example",
            now(),
        );

        // Assert
        assert!(matches!(built, Err(DomainError::Invalid { field, .. }) if field == "max_clients"));
    }

    #[test]
    fn an_expiry_already_past_is_refused() {
        // Arrange / Act
        let built = NewInitialAccessToken::new(
            TenantId::new("demo"),
            "onboarding",
            digest(),
            None,
            Some(now() - Duration::seconds(1)),
            "admin@example",
            now(),
        );

        // Assert
        assert!(matches!(built, Err(DomainError::Invalid { field, .. }) if field == "expires_at"));
    }

    #[test]
    fn an_over_long_label_is_refused() {
        // Arrange
        let label = "x".repeat(MAX_LABEL_LEN + 1);

        // Act
        let built =
            NewInitialAccessToken::new(
                TenantId::new("demo"),
                label,
                digest(),
                None,
                None,
                "admin@example",
                now(),
            );

        // Assert
        assert!(matches!(built, Err(DomainError::Invalid { field, .. }) if field == "label"));
    }

    #[test]
    fn a_token_with_no_ceiling_has_no_remaining_count() {
        // Arrange
        let unlimited = token(9, None, None);

        // Act / Assert
        assert_eq!(unlimited.remaining(), None);
        assert!(!unlimited.is_exhausted(now()));
    }

    #[test]
    fn a_spent_token_is_exhausted() {
        // Arrange
        let spent = token(3, Some(3), None);

        // Act / Assert
        assert_eq!(spent.remaining(), Some(0));
        assert!(spent.is_exhausted(now()));
    }

    #[test]
    fn a_row_edited_past_its_ceiling_still_reports_nothing_left() {
        // Arrange
        let overspent = token(9, Some(3), None);

        // Act / Assert
        assert_eq!(overspent.remaining(), Some(0));
    }

    #[test]
    fn an_expired_token_is_exhausted_however_much_quota_is_left() {
        // Arrange
        let expired = token(0, Some(10), Some(now() - Duration::seconds(1)));

        // Act / Assert
        assert_eq!(expired.remaining(), Some(10));
        assert!(expired.is_exhausted(now()));
    }

    #[test]
    fn every_reservation_outcome_has_a_stable_label() {
        // Arrange
        let outcomes = [
            (
                Reservation::Reserved {
                    id: Uuid::from_u128(1),
                    remaining: None,
                },
                "reserved",
            ),
            (Reservation::Unknown, "unknown"),
            (Reservation::Expired, "expired"),
            (Reservation::Exhausted, "exhausted"),
        ];

        // Act / Assert
        for (outcome, expected) in outcomes {
            assert_eq!(outcome.as_str(), expected);
        }
    }

    #[test]
    fn only_a_reservation_names_a_row_to_release() {
        // Arrange
        let id = Uuid::from_u128(42);

        // Act / Assert
        assert_eq!(
            Reservation::Reserved {
                id,
                remaining: Some(1)
            }
            .reserved(),
            Some(id)
        );
        assert_eq!(Reservation::Exhausted.reserved(), None);
    }
}
