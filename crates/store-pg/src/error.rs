//! Mapping `sqlx` failures onto the domain's vocabulary.

use asterius_domain::DomainError;

/// Translates a `sqlx` error into a [`DomainError`].
///
/// The mapping is deliberately narrow. A unique violation is a real domain
/// outcome — two tenants claiming one issuer, a code redeemed twice — and
/// callers branch on it. Everything else is infrastructure failing, and the
/// caller has nothing useful to do with the distinction.
#[must_use]
pub fn to_domain_error(error: sqlx::Error) -> DomainError {
    match &error {
        sqlx::Error::RowNotFound => DomainError::NotFound,
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            DomainError::Conflict(db.constraint().unwrap_or("unique violation").to_owned())
        }
        sqlx::Error::Database(db) if db.is_foreign_key_violation() => DomainError::Conflict(
            db.constraint()
                .unwrap_or("foreign key violation")
                .to_owned(),
        ),
        _ => DomainError::Storage(Box::new(error)),
    }
}
