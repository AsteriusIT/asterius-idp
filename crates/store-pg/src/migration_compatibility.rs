//! One immutable migration-history exception, selected under the SQLx lock.
//!
//! The corrected 0173 remains authoritative for new/pre-0173 databases. A
//! database that already applied the exact published 43191d6 payload validates
//! that original payload instead, then receives additive schema parity in0177.
//! No ledger entry is changed, unknown checksum accepted, or old SQL reapplied.

use std::borrow::Cow;

use sqlx::migrate::{AppliedMigration, Migrate, MigrateError, Migration, Migrator};
use sqlx::PgConnection;

use crate::store::MIGRATOR;

const LEGACY_VERSION: i64 = 173;
const LEGACY_SHA384: &str = "5a096a745c0a269c053f708ff30486e12d157900e081578bd58306eccd370e114d6f692b679cc29b51a5bf48d527b095";
const LEGACY_SQL: &str = include_str!("../migration-history/0173_uuid_client_ids_43191d6.sql");

fn selected_migrator(applied: &[AppliedMigration]) -> Result<Migrator, MigrateError> {
    let mut migrations = MIGRATOR.iter().cloned().collect::<Vec<_>>();
    let Some(current) = migrations.iter_mut().find(|m| m.version == LEGACY_VERSION) else {
        return Err(MigrateError::VersionNotPresent(LEGACY_VERSION));
    };
    if let Some(recorded) = applied.iter().find(|m| m.version == LEGACY_VERSION) {
        if hex::encode(recorded.checksum.as_ref()) == LEGACY_SHA384 {
            let historical = Migration::new(
                current.version,
                current.description.clone(),
                current.migration_type,
                Cow::Borrowed(LEGACY_SQL),
                current.no_tx,
            );
            // Independently pin the embedded payload too: changing history is
            // never excused just because a database has the recognized digest.
            if hex::encode(historical.checksum.as_ref()) != LEGACY_SHA384 {
                return Err(MigrateError::VersionMismatch(LEGACY_VERSION));
            }
            *current = historical;
        } else if recorded.checksum != current.checksum {
            return Err(MigrateError::VersionMismatch(LEGACY_VERSION));
        }
    }
    Ok(Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: MIGRATOR.ignore_missing,
        locking: MIGRATOR.locking,
        no_tx: MIGRATOR.no_tx,
    })
}

/// The caller owns this connection, so cancellation closes it and cannot return
/// a session holding the advisory lock to the pool.
pub(crate) async fn run(connection: &mut PgConnection) -> Result<(), MigrateError> {
    connection.lock().await?;
    let result = async {
        connection.ensure_migrations_table().await?;
        if let Some(version) = connection.dirty_version().await? {
            return Err(MigrateError::Dirty(version));
        }
        let mut selected = selected_migrator(&connection.list_applied_migrations().await?)?;
        // Selection and SQLx's full strict validation/application use the same
        // connection under the lock already acquired above. Do not acquire the
        // session-level lock twice (PostgreSQL advisory locks are reentrant).
        selected.set_locking(false);
        selected.run_direct(connection).await
    }
    .await;
    let unlocked = connection.unlock().await;
    result?;
    unlocked
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha384};

    fn recorded(checksum: Vec<u8>) -> AppliedMigration {
        AppliedMigration { version: LEGACY_VERSION, checksum: Cow::Owned(checksum) }
    }

    #[test]
    fn historical_payload_is_pinned_to_the_published_sha384() {
        assert_eq!(hex::encode(Sha384::digest(LEGACY_SQL.as_bytes())), LEGACY_SHA384);
    }

    #[test]
    fn new_and_corrected_databases_retain_the_terminal_cutover_migration() {
        let current = MIGRATOR.iter().find(|m| m.version == LEGACY_VERSION).expect("0173 embedded");
        for applied in [vec![], vec![recorded(current.checksum.to_vec())]] {
            let selected = selected_migrator(&applied).expect("current history accepted");
            assert_eq!(selected.iter().find(|m| m.version == LEGACY_VERSION).expect("0173 selected").sql, current.sql);
            assert!(selected.locking);
            assert!(!selected.ignore_missing);
        }
    }

    #[test]
    fn only_exact_known_history_selects_the_old_payload_and_preserves_other_migrations() {
        let selected = selected_migrator(&[recorded(hex::decode(LEGACY_SHA384).expect("pinned hex"))]).expect("known history accepted");
        assert_eq!(selected.iter().find(|m| m.version == LEGACY_VERSION).expect("0173 selected").sql, LEGACY_SQL);
        for (original, actual) in MIGRATOR.iter().zip(selected.iter()) {
            if original.version != LEGACY_VERSION {
                assert_eq!(actual.sql, original.sql);
                assert_eq!(actual.checksum, original.checksum);
            }
        }
        assert!(selected.locking);
        assert!(!selected.ignore_missing);
    }

    #[test]
    fn unknown_0173_checksum_is_refused_instead_of_adopted() {
        assert!(matches!(selected_migrator(&[recorded(vec![0; 48])]), Err(MigrateError::VersionMismatch(173))));
    }
}
