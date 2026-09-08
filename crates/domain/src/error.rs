//! Errors that adapters and protocol code share.

use crate::keys::SigningAlgorithm;
use thiserror::Error;

/// A failure raised by a port implementation or an entity invariant.
///
/// Adapters map their own failures (a `sqlx::Error`, an HSM timeout) onto this
/// type so that protocol code never sees infrastructure detail.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DomainError {
    /// The requested entity does not exist in this tenant.
    #[error("not found")]
    NotFound,
    /// The caller supplied a value that violates an entity invariant.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Field or parameter name, using its wire spelling where one exists.
        field: &'static str,
        /// Why the value was rejected. Never contains secret material.
        reason: String,
    },
    /// A conflicting write was detected (unique violation, lost update).
    #[error("conflict: {0}")]
    Conflict(String),
    /// The backing store or an external dependency failed.
    #[error("storage failure: {0}")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// No key this tenant may sign with is available.
    ///
    /// Its own variant rather than an [`DomainError::Invalid`], because
    /// nothing invalid was supplied: a client that registered `ES256`
    /// registered an algorithm FAPI 2.0 SP §5.4.1 permits and this server
    /// accepts, and the tenant simply holds no active key of it. That is an
    /// ordinary operational state — a tenant whose key schedule has only ever
    /// staged the default algorithm, or one whose keys were destroyed after a
    /// compromise — and it is a *configuration* fault rather than a transient
    /// one, so a caller must be able to tell it apart from
    /// [`DomainError::Storage`]: retrying will not fix it, and an operator has
    /// to create the key or stop accepting that registration.
    ///
    /// The one thing that must never happen instead is signing with a
    /// different algorithm. See [`crate::Signer::sign`].
    #[error("no active signing key{}", .algorithm.map_or_else(String::new, |alg| format!(" for {alg}")))]
    NoSigningKey {
        /// The algorithm that was required, or `None` when any active key
        /// would have done and the tenant holds none at all.
        algorithm: Option<SigningAlgorithm>,
    },
}

impl DomainError {
    /// Builds an [`DomainError::Invalid`] without repeating the struct syntax.
    #[must_use]
    pub fn invalid(field: &'static str, reason: impl Into<String>) -> Self {
        Self::Invalid {
            field,
            reason: reason.into(),
        }
    }
}
