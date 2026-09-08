//! Errors that adapters and protocol code share.

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
