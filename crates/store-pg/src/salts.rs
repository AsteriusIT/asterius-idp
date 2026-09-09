//! The per-tenant pairwise salt: sealing it once, and reading it back.
//!
//! Every `sub` this server issues is `SHA-256` over the sector, the local
//! account id and this (OIDC Core §8.1). The first two are not secret — a
//! sector is a public host name and a local account id is a UUID one join away
//! in `users` — so the salt is the only reason a pairwise Subject Identifier
//! "MUST NOT be reversible by any party other than the OpenID Provider" holds
//! against somebody holding a database dump. That makes it key material, and it
//! is stored the way key material is stored here: sealed under the [`Kek`] port
//! with the tenant bound in as additional authenticated data, so a row copied
//! into another tenant is undecryptable rather than useful. See
//! [`asterius_jose::kek`] and `signing_keys` for the pattern.
//!
//! # Written once, never rotated
//!
//! [`ensure`] is the only writer, and its statement is an insert with
//! `on conflict do nothing`: the first write for a tenant wins and no later
//! call can replace it, whatever it was called with. The table refuses `UPDATE`
//! outright, so the same is true of anything else that reaches the database.
//!
//! That is not caution about a difficult operation, it is the shape of the
//! problem. Every derived `sub` is written to `subject_identifiers` and read
//! back from there, so a new salt would not move an identifier already issued —
//! it would only mean the same user in the same sector derives *differently* if
//! that row were ever lost. OIDC Core §8 makes a Subject Identifier "a locally
//! unique and never reassigned identifier within the Issuer for the End-User".
//! Recovering from a leaked salt is therefore a reissue of every identifier in
//! the tenant, which is a relying-party migration and not a rotation.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, PairwiseSalt, TenantId};
use asterius_jose::{Kek, KeyBinding, TenantSecret, WrappedKey};
use sqlx::PgExecutor;

/// Gives a tenant its salt, if it does not already have one.
///
/// Called from tenant creation, inside the same transaction, so a tenant and
/// the salt its subjects derive from commit together: a crash between the two
/// would otherwise leave a tenant that exists and cannot mint a `sub`.
///
/// A fresh salt is generated and sealed on every call and thrown away on all
/// but the first, which costs one KEK operation per tenant write. That is the
/// price of not asking the database "does this tenant have a salt yet?" and
/// then acting on the answer — two callers racing that read would both decide
/// "no", and only the insert can settle it. Tenant writes are administrative
/// and rare; a wasted `wrap` on one is not worth a race on the one value in the
/// system that must never be written twice.
///
/// # Errors
///
/// Returns [`DomainError::Storage`] if the key-encryption key refuses, or a
/// storage error.
pub(crate) async fn ensure<'e, E>(
    executor: E,
    tenant: &TenantId,
    kek: &dyn Kek,
) -> Result<(), DomainError>
where
    E: PgExecutor<'e>,
{
    let salt = PairwiseSalt::generate();
    let binding = KeyBinding::tenant_secret(tenant, TenantSecret::PairwiseSalt);
    let wrapped = kek
        .wrap(binding, salt.expose())
        .await
        .map_err(|e| DomainError::Storage(Box::new(e)))?;

    sqlx::query!(
        "insert into tenant_pairwise_salts (tenant_id, salt_ciphertext, salt_nonce, kek_id)
         values ($1, $2, $3, $4)
         on conflict (tenant_id) do nothing",
        tenant.as_str(),
        wrapped.ciphertext(),
        wrapped.nonce(),
        wrapped.kek_id()
    )
    .execute(executor)
    .await
    .map(|_| ())
    .map_err(to_domain_error)
}

/// The tenant's salt, decrypted.
///
/// Decrypted on every call: the plaintext is returned to the caller and dropped
/// with it, and nothing here holds it between mints. ADR-0008 (`ast-f12`) is
/// the argument for that, and names the conditions under which it should be
/// revisited.
///
/// # Errors
///
/// Returns [`DomainError::Invalid`] when the tenant has no salt row, and
/// [`DomainError::Storage`] when the row does not decrypt under the configured
/// key-encryption key or does not hold 256 bits.
///
/// A missing row is an error and never a default. A tenant that mints subjects
/// under an empty or improvised salt would hand out identifiers anybody who
/// knows the algorithm could re-derive — and, because the first derivation is
/// the one that gets stored and given to a relying party, it could never be
/// taken back. Failing to mint a `sub` is recoverable; minting the wrong one is
/// not.
pub(crate) async fn read<'e, E>(
    executor: E,
    tenant: &TenantId,
    kek: &dyn Kek,
) -> Result<PairwiseSalt, DomainError>
where
    E: PgExecutor<'e>,
{
    let row = sqlx::query!(
        "select salt_ciphertext, salt_nonce, kek_id
         from tenant_pairwise_salts
         where tenant_id = $1",
        tenant.as_str()
    )
    .fetch_optional(executor)
    .await
    .map_err(to_domain_error)?
    .ok_or_else(|| {
        DomainError::invalid(
            "pairwise_salt",
            "the tenant has no pairwise salt; it is generated at tenant creation \
             and no subject can be derived without it",
        )
    })?;

    let wrapped = WrappedKey::from_parts(row.kek_id, row.salt_nonce, row.salt_ciphertext)
        .map_err(|e| DomainError::Storage(Box::new(e)))?;
    let binding = KeyBinding::tenant_secret(tenant, TenantSecret::PairwiseSalt);
    let plaintext = kek
        .unwrap(binding, &wrapped)
        .await
        .map_err(|e| DomainError::Storage(Box::new(e)))?;

    // Length-checked on the way out as well as on the way in. The AEAD already
    // proves the bytes are the ones that were sealed, but it proves nothing
    // about how many of them there are, and a salt of the wrong length is a
    // salt this code must not derive under.
    PairwiseSalt::from_storage(&plaintext).map_err(|e| DomainError::Storage(Box::new(e)))
}
