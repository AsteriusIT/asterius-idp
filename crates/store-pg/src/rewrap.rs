//! Moving every sealed row to a new key-encryption key.
//!
//! A KEK is the one secret in this system that is deliberately *not* in the
//! database, so rotating it is not a schema change and not a re-issue: the
//! plaintexts stay exactly what they were and only the envelope around them
//! changes. Two kinds of row are sealed — `signing_keys.private_key_ciphertext`
//! and `tenant_pairwise_salts.salt_ciphertext` — and both have to move, because
//! a deployment that rotated half of them still needs the old key to boot,
//! which is the same as not having rotated at all.
//!
//! # Why the salt is not simply updated
//!
//! `tenant_pairwise_salts` refuses `UPDATE` outright, and that trigger is a
//! security property rather than an oversight: every `sub` this server has
//! issued for the tenant derives from that salt (OIDC Core §8.1), so a salt
//! that changes value silently reassigns every subject identifier in the
//! tenant — which §8 says never happens. The trigger exists so that no
//! application code, migration or `psql` session can do that by accident.
//!
//! Re-wrapping is a different operation from an update, and it is expressed
//! differently: the row is deleted and re-inserted, in one transaction, with
//! the *same plaintext* sealed under the new key. `DELETE` is the one verb the
//! trigger leaves open — it has to, because a tenant's deletion cascades
//! through it — and using it here keeps the "one salt per tenant, forever"
//! shape that the primary key gives, rather than introducing a second row and
//! a rule about which of the two is current. Readers are unaffected: the whole
//! swap is one transaction, so no snapshot ever sees the tenant without a salt.
//!
//! [`PgKekRewrap::rewrap_tenant`] proves the plaintext survived rather than
//! asserting it: it re-reads the row it just wrote, opens it under the new KEK,
//! and compares the salt in constant time with the one it opened under the old.
//! A mismatch rolls the transaction back, so the failure mode is "the tenant is
//! still on the old KEK", not "every relying party lost its users".
//!
//! # Resumable, and safe on more than one replica
//!
//! One transaction per tenant, taken under `pg_try_advisory_xact_lock` in the
//! two-key space at `(tenant, 'kek-rewrap')` — the same pattern
//! [`crate::PgRetention`] uses for sweeps and [`crate::PgKeyRepository`] uses
//! for rotation, and distinct from both, so none of the three can block
//! another. A second operator or replica that finds a tenant busy is told
//! [`RewrapOutcome::Busy`] and moves on rather than waiting to redo work.
//!
//! Every statement selects on the *old* `kek_id`, so a pass that dies half-way
//! is resumed simply by running it again: rows already carrying the new id are
//! not selected, and a tenant that is entirely done reports an empty
//! [`Rewrap`]. Nothing here destroys anything the old KEK opens — it stays
//! usable until the operator destroys the material — so a rotation can also be
//! abandoned part-way and restarted.
//!
//! # What it does not cover
//!
//! Only what the KEK seals. Password hashes, recovery codes, passkey public
//! keys and audit records are not ciphertext under it, and nothing here touches
//! them. And a replica still running with the old KEK cannot open the rows this
//! has already moved: see [`Rewrap::left_behind`] and the backup runbook for
//! the order the two halves go in.

use crate::error::to_domain_error;
use asterius_domain::keys::{KeyPurpose, Kid, SigningAlgorithm};
use asterius_domain::{DomainError, PairwiseSalt, TenantId, ct_eq};
use asterius_jose::{Kek, KeyBinding, TenantSecret, WrappedKey};
use sqlx::postgres::PgPool;

/// One tenant's transaction, for the helpers below.
type Transaction<'c> = sqlx::Transaction<'c, sqlx::Postgres>;

/// What one tenant's pass moved.
///
/// Counts and flags only: nothing here is derived from a plaintext, so a
/// summary is safe to print, log and paste into a change ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rewrap {
    /// How many `signing_keys` rows were re-sealed.
    pub signing_keys: u64,
    /// Whether the tenant's pairwise salt was re-sealed. `false` also covers
    /// "already on the new KEK" and "the tenant has no salt".
    pub pairwise_salt: bool,
    /// Rows still sealed under the old KEK when the transaction committed.
    ///
    /// Normally zero. It is not zero when a replica still running on the old
    /// KEK wrote a row — a rotation sweep staging a signing key, a tenant being
    /// created — while this pass was in flight. Those rows are caught by
    /// running the pass again once the replicas have been moved over, which is
    /// why this is reported rather than treated as a failure.
    pub left_behind: u64,
    /// Rows sealed under neither the old KEK nor the new one.
    ///
    /// A pass cannot open these, and says so instead of skipping them quietly:
    /// they are the residue of an earlier, abandoned rotation, and the operator
    /// needs whichever KEK sealed them before the deployment can be brought
    /// onto one key.
    pub stranded: u64,
}

impl Rewrap {
    /// Whether this pass had anything to do.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.signing_keys == 0 && !self.pairwise_salt
    }

    /// Whether the tenant is now wholly on the new KEK.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.left_behind == 0 && self.stranded == 0
    }
}

/// The result of asking for one tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewrapOutcome {
    /// Somebody else holds the tenant's re-wrap lock; nothing was touched.
    Busy,
    /// The pass ran and committed.
    Rewrapped(Rewrap),
}

/// Re-seals a tenant's stored secrets under a different key-encryption key.
#[derive(Debug, Clone)]
pub struct PgKekRewrap {
    pool: PgPool,
}

impl PgKekRewrap {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Moves one tenant from `from` to `to`.
    ///
    /// Both keys have to be held at once, and there is no way around that: the
    /// old one is the only thing that can open a row and the new one is the
    /// only thing that can re-seal it. `from` is the KEK the deployment is
    /// running on today.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] if the two keys are the same one, or if a row
    /// names an algorithm or purpose this build does not know — a re-wrap
    /// cannot bind a row it cannot describe, and a wrong binding is a row that
    /// stops decrypting. [`DomainError::Storage`] if a key refuses, if a row
    /// does not open under `from`, or if the salt does not read back
    /// identically. In every one of those cases the transaction rolls back and
    /// the tenant is left exactly as it was.
    pub async fn rewrap_tenant(
        &self,
        tenant: &TenantId,
        from: &dyn Kek,
        to: &dyn Kek,
    ) -> Result<RewrapOutcome, DomainError> {
        distinct(from, to)?;

        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        // Try, not wait: a second operator running the same command against the
        // same tenant should be told to look elsewhere, not queued behind work
        // that is about to make its own pass a no-op. Held to the end of the
        // transaction, released whichever way that ends.
        let acquired: bool = sqlx::query_scalar(
            "select pg_try_advisory_xact_lock(hashtext($1), hashtext('kek-rewrap'))",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        if !acquired {
            return Ok(RewrapOutcome::Busy);
        }

        let rewrap = Rewrap {
            signing_keys: Self::signing_keys(&mut transaction, tenant, from, to).await?,
            pairwise_salt: Self::pairwise_salt(&mut transaction, tenant, from, to).await?,
            left_behind: Self::count_under(&mut transaction, tenant, from.id()).await?,
            stranded: Self::count_stranded(&mut transaction, tenant, from, to).await?,
        };

        transaction.commit().await.map_err(to_domain_error)?;
        Ok(RewrapOutcome::Rewrapped(rewrap))
    }

    /// Re-seals every signing key still under the old KEK.
    ///
    /// In place, because `signing_keys` takes an `UPDATE` and nothing about the
    /// row's identity changes: the `kid` is the thumbprint of the *public*
    /// half, which is not encrypted and is not touched here. The AEAD binding
    /// is rebuilt from the row's own columns, so the re-sealed ciphertext is
    /// bound to exactly the row it goes back into.
    async fn signing_keys(
        transaction: &mut Transaction<'_>,
        tenant: &TenantId,
        from: &dyn Kek,
        to: &dyn Kek,
    ) -> Result<u64, DomainError> {
        // `kek_id = $2` is what makes the three envelope columns non-null here:
        // a purged key carries no material and no `kek_id` at all (migration
        // `0003_key_purge`), so it cannot match, and there is nothing to
        // re-seal for a key whose private half no longer exists.
        let rows = sqlx::query!(
            "select kid, alg, purpose,
                    private_key_ciphertext as \"private_key_ciphertext!\",
                    private_key_nonce as \"private_key_nonce!\",
                    kek_id as \"kek_id!\"
               from signing_keys
              where tenant_id = $1 and kek_id = $2
              for update",
            tenant.as_str(),
            from.id()
        )
        .fetch_all(&mut **transaction)
        .await
        .map_err(to_domain_error)?;

        let mut moved = 0_u64;
        for row in rows {
            let kid = Kid::new(row.kid);
            let purpose = KeyPurpose::parse(&row.purpose).ok_or_else(|| {
                DomainError::invalid(
                    "signing_keys.purpose",
                    "the row names a key purpose this build does not know, so its \
                     ciphertext cannot be bound back to it",
                )
            })?;
            let algorithm = SigningAlgorithm::parse(&row.alg).ok_or_else(|| {
                DomainError::invalid(
                    "signing_keys.alg",
                    "the row names an algorithm this build does not know, so its \
                     ciphertext cannot be bound back to it",
                )
            })?;

            let wrapped = WrappedKey::from_parts(
                row.kek_id,
                row.private_key_nonce,
                row.private_key_ciphertext,
            )
            .map_err(storage_error)?;
            let binding = KeyBinding::new(tenant, &kid, purpose, algorithm);

            // The private key exists in this process for the width of these two
            // calls, in a buffer that zeroes itself on drop, and is never named
            // in a log line or an error.
            let plaintext = from
                .unwrap(binding, &wrapped)
                .await
                .map_err(storage_error)?;
            let resealed = to.wrap(binding, &plaintext).await.map_err(storage_error)?;

            // `kek_id = $6` makes the update idempotent under a retry: a row
            // somebody else already moved is not moved twice, and the three
            // envelope columns only ever change together.
            moved += sqlx::query!(
                "update signing_keys
                    set private_key_ciphertext = $1, private_key_nonce = $2, kek_id = $3
                  where tenant_id = $4 and kid = $5 and kek_id = $6",
                resealed.ciphertext(),
                resealed.nonce(),
                resealed.kek_id(),
                tenant.as_str(),
                kid.as_str(),
                from.id()
            )
            .execute(&mut **transaction)
            .await
            .map_err(to_domain_error)?
            .rows_affected();
        }
        Ok(moved)
    }

    /// Re-seals the tenant's pairwise salt, if it has one under the old KEK.
    ///
    /// Delete and insert rather than update, for the reason the module
    /// documentation gives, and with the original `created_at` carried across:
    /// the row holds the same salt it always held, and a timestamp saying
    /// otherwise would misdate the one value in a tenant that is never
    /// re-issued.
    async fn pairwise_salt(
        transaction: &mut Transaction<'_>,
        tenant: &TenantId,
        from: &dyn Kek,
        to: &dyn Kek,
    ) -> Result<bool, DomainError> {
        let Some(row) = sqlx::query!(
            "select salt_ciphertext, salt_nonce, kek_id, created_at
               from tenant_pairwise_salts
              where tenant_id = $1 and kek_id = $2
              for update",
            tenant.as_str(),
            from.id()
        )
        .fetch_optional(&mut **transaction)
        .await
        .map_err(to_domain_error)?
        else {
            return Ok(false);
        };

        let binding = KeyBinding::tenant_secret(tenant, TenantSecret::PairwiseSalt);
        let wrapped = WrappedKey::from_parts(row.kek_id, row.salt_nonce, row.salt_ciphertext)
            .map_err(storage_error)?;
        let opened = from
            .unwrap(binding, &wrapped)
            .await
            .map_err(storage_error)?;
        // Through the domain type, so the bytes spend their time in a value
        // that redacts itself and zeroes on drop, and so a row of the wrong
        // length is refused here rather than re-sealed as though it were a
        // salt.
        let salt = PairwiseSalt::from_storage(&opened).map_err(subject_error)?;
        let resealed = to
            .wrap(binding, salt.expose())
            .await
            .map_err(storage_error)?;

        sqlx::query!(
            "delete from tenant_pairwise_salts where tenant_id = $1 and kek_id = $2",
            tenant.as_str(),
            from.id()
        )
        .execute(&mut **transaction)
        .await
        .map_err(to_domain_error)?;

        sqlx::query!(
            "insert into tenant_pairwise_salts
                 (tenant_id, salt_ciphertext, salt_nonce, kek_id, created_at)
             values ($1, $2, $3, $4, $5)",
            tenant.as_str(),
            resealed.ciphertext(),
            resealed.nonce(),
            resealed.kek_id(),
            row.created_at
        )
        .execute(&mut **transaction)
        .await
        .map_err(to_domain_error)?;

        Self::prove_the_salt_survived(transaction, tenant, to, &salt).await?;
        Ok(true)
    }

    /// Reads the row back and checks it still holds the same salt.
    ///
    /// The one assertion this module exists to be able to make. Every `sub` in
    /// the tenant is `SHA-256` over the sector, the local account id and these
    /// bytes, so "the ciphertext changed and the plaintext did not" is the
    /// correctness condition of a KEK rotation — and it is cheap to check,
    /// because it is one row. Checked inside the transaction, so a mismatch
    /// rolls the swap back instead of being reported after the fact.
    async fn prove_the_salt_survived(
        transaction: &mut Transaction<'_>,
        tenant: &TenantId,
        to: &dyn Kek,
        expected: &PairwiseSalt,
    ) -> Result<(), DomainError> {
        let row = sqlx::query!(
            "select salt_ciphertext, salt_nonce, kek_id
               from tenant_pairwise_salts
              where tenant_id = $1",
            tenant.as_str()
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(to_domain_error)?;

        let wrapped = WrappedKey::from_parts(row.kek_id, row.salt_nonce, row.salt_ciphertext)
            .map_err(storage_error)?;
        let binding = KeyBinding::tenant_secret(tenant, TenantSecret::PairwiseSalt);
        let opened = to.unwrap(binding, &wrapped).await.map_err(storage_error)?;
        let stored = PairwiseSalt::from_storage(&opened).map_err(subject_error)?;

        if ct_eq(stored.expose(), expected.expose()) {
            Ok(())
        } else {
            // No salt, no ciphertext and no lengths in the message: an operator
            // reading this needs to know the tenant is unchanged, and nothing
            // else here is theirs to see.
            Err(DomainError::invalid(
                "pairwise_salt",
                "the re-sealed salt did not read back as the one that was stored; \
                 the tenant has been left on its previous key-encryption key",
            ))
        }
    }

    /// How many of the tenant's sealed rows still name `kek_id`.
    async fn count_under(
        transaction: &mut Transaction<'_>,
        tenant: &TenantId,
        kek_id: &str,
    ) -> Result<u64, DomainError> {
        let keys = sqlx::query_scalar!(
            "select count(*) as \"count!\" from signing_keys
              where tenant_id = $1 and kek_id = $2",
            tenant.as_str(),
            kek_id
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(to_domain_error)?;
        let salts = sqlx::query_scalar!(
            "select count(*) as \"count!\" from tenant_pairwise_salts
              where tenant_id = $1 and kek_id = $2",
            tenant.as_str(),
            kek_id
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(to_domain_error)?;
        Ok(keys.unsigned_abs() + salts.unsigned_abs())
    }

    /// How many of the tenant's sealed rows name neither key.
    async fn count_stranded(
        transaction: &mut Transaction<'_>,
        tenant: &TenantId,
        from: &dyn Kek,
        to: &dyn Kek,
    ) -> Result<u64, DomainError> {
        let keys = sqlx::query_scalar!(
            "select count(*) as \"count!\" from signing_keys
              where tenant_id = $1 and kek_id <> $2 and kek_id <> $3",
            tenant.as_str(),
            from.id(),
            to.id()
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(to_domain_error)?;
        let salts = sqlx::query_scalar!(
            "select count(*) as \"count!\" from tenant_pairwise_salts
              where tenant_id = $1 and kek_id <> $2 and kek_id <> $3",
            tenant.as_str(),
            from.id(),
            to.id()
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(to_domain_error)?;
        Ok(keys.unsigned_abs() + salts.unsigned_abs())
    }
}

/// Refuses a rotation from a key to itself.
///
/// Not merely a no-op worth skipping. An operator who installed the new
/// material in the wrong place and ran the command would otherwise be told "0
/// rows moved, complete", and would go on to destroy the old key — which is
/// still the only key. The id is derived from the material, so this compares
/// the keys themselves and not a label somebody typed.
fn distinct(from: &dyn Kek, to: &dyn Kek) -> Result<(), DomainError> {
    if from.id() == to.id() {
        return Err(DomainError::invalid(
            "kek",
            "the new key-encryption key is the one already in use; a rotation \
             that reports success without moving anything is how the old key \
             gets destroyed while it is still the only key",
        ));
    }
    Ok(())
}

fn storage_error(error: asterius_jose::JoseError) -> DomainError {
    DomainError::Storage(Box::new(error))
}

fn subject_error(error: asterius_domain::SubjectError) -> DomainError {
    DomainError::Storage(Box::new(error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_jose::LocalKek;

    #[test]
    fn rotating_a_key_onto_itself_is_refused() {
        let kek = LocalKek::from_bytes(&[0x11; 32]).expect("a 32-byte KEK");
        let same = LocalKek::from_bytes(&[0x11; 32]).expect("a 32-byte KEK");

        let refused = distinct(&kek, &same);

        assert!(
            refused.is_err(),
            "a rotation to the same key material reported success"
        );
    }

    #[test]
    fn rotating_to_different_material_is_allowed() {
        let from = LocalKek::from_bytes(&[0x11; 32]).expect("a 32-byte KEK");
        let to = LocalKek::from_bytes(&[0x22; 32]).expect("a 32-byte KEK");

        let allowed = distinct(&from, &to);

        assert!(allowed.is_ok(), "{allowed:?}");
    }

    #[test]
    fn a_pass_that_moved_nothing_and_left_nothing_behind_is_complete() {
        let done = Rewrap::default();

        assert!(done.is_empty());
        assert!(done.is_complete());
    }

    #[test]
    fn a_row_written_under_the_old_key_mid_pass_is_not_complete() {
        let interrupted = Rewrap {
            signing_keys: 3,
            pairwise_salt: true,
            left_behind: 1,
            stranded: 0,
        };

        assert!(!interrupted.is_complete());
    }
}
