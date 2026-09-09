//! Scheduled deletion of the rows that are only meant to exist for a while.
//!
//! RFC 9700 §4.2–4.3 is about credentials leaking; FAPI 2.0 SP §7 is about the
//! authorization server itself being the leak. Both point at the same
//! operational fact: the cheapest way to lose a credential is to keep it after
//! it stopped being useful. An authorization code lives for sixty seconds and a
//! `jti` for the lifetime of one assertion, but the *rows* live until something
//! deletes them, and a store nobody sweeps ends up holding years of expired
//! codes, PAR parameters, session fingerprints and replay markers — a dump of
//! which is a dump of everything anybody ever did here.
//!
//! # The policy is the code
//!
//! [`POLICY`] names **every** table in the schema, and each entry is either the
//! statement that sweeps it or the reason it is kept. The two properties that
//! buys are worth the verbosity:
//!
//! * A statement cannot drift from its rule, because the rule *is* the
//!   statement. There is no second list to update.
//! * A new table added by a later migration with no thought given to retention
//!   fails `retention_policy_names_every_table_in_the_schema`, which is the
//!   failure mode this module exists to prevent. A forgotten table does not
//!   announce itself: it works perfectly and accumulates for a year.
//!
//! # Safe to run on more than one replica
//!
//! Two replicas sweep on the same timer, so both wake up to the same expired
//! rows. Correctness is not the problem — `delete` is idempotent — but doing
//! the work twice is, and so is holding row locks on `jti_replay` while the
//! endpoint that inserts into it is waiting.
//!
//! Two mechanisms, following the precedent set by the migrations at startup and
//! by [`crate::PgKeyRepository`]:
//!
//! * A per-tenant **advisory lock**, taken with `pg_try_advisory_lock` rather
//!   than `pg_advisory_lock`: a second replica that finds the tenant busy
//!   reports [`SweepOutcome::Busy`] and moves on to the next tenant. Waiting
//!   would only buy the right to redo work that has just been done. The lock
//!   lives in the two-key space under `(tenant, 'retention')`, distinct from
//!   the audit sink's one-key space and from key rotation's
//!   `(tenant, 'key-rotation')`, so none of the three can wait on another.
//! * **Batches.** Each statement deletes at most [`BATCH`] rows and commits,
//!   so no transaction holds locks on a hot table for long and a sweep that
//!   falls a million rows behind does not become one enormous transaction. A
//!   table that is still not empty after [`MAX_BATCHES`] passes is left for the
//!   next sweep, reported as [`Sweep::more_to_do`].
//!
//! The advisory lock is a *session* lock rather than a transaction lock,
//! because the batches are separate transactions and a transaction lock would
//! be released after the first one. It is taken on one connection held for the
//! whole sweep, and released explicitly; a connection that dies takes its
//! session locks with it, so a crashed replica cannot wedge a tenant.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, TenantId};
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgPool, Postgres};
use time::{Duration, OffsetDateTime};

/// What retention does with one table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Swept by `statement`, which takes the tenant as `$1`, the cutoff as
    /// `$2` and the batch size as `$3`, and deletes at most `$3` rows.
    ///
    /// `grace` is subtracted from the current time to make the cutoff. It is
    /// zero for most tables — a row whose `expires_at` has passed is a row
    /// nothing will look at again — and non-zero where the *expired* row is
    /// still doing work; see `authorization_codes` in [`POLICY`].
    Sweep {
        /// The batched `delete`.
        statement: &'static str,
        /// How long after expiry the row is still kept.
        grace: Duration,
    },
    /// Never swept, for the stated reason.
    Kept(&'static str),
}

/// One table and what happens to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// The table, exactly as the schema spells it.
    pub table: &'static str,
    /// Swept, or kept and why.
    pub rule: Rule,
}

/// Rows deleted per statement before committing and starting another.
///
/// A thousand rows is a few milliseconds of row locks. Small enough that a
/// concurrent insert into `jti_replay` never waits noticeably, large enough
/// that a backlog is cleared in seconds rather than minutes.
pub const BATCH: i64 = 1_000;

/// The most batches one table gets in one sweep.
///
/// A bound on the pass, not on the work: whatever is left is swept next time.
/// Without it, a first sweep over a store that has never been swept would run
/// for hours on one connection, holding the tenant's lock the whole time.
pub const MAX_BATCHES: usize = 100;

/// Every table in the schema, swept or kept.
///
/// Kept in the schema's own order so that reading this next to
/// `0001_baseline.sql` is a straight comparison.
pub const POLICY: &[Retention] = &[
    Retention {
        table: "tenants",
        rule: Rule::Kept(
            "the root of every cascade; removing a tenant is an operator action \
             with consequences no timer should decide",
        ),
    },
    Retention {
        table: "clients",
        rule: Rule::Kept(
            "a registration lives until it is deleted through RFC 7592; nothing \
             about a client expires on a clock",
        ),
    },
    Retention {
        table: "client_keys",
        rule: Rule::Sweep {
            // A cache of somebody else's JWKS. Past `expires_at` it is not
            // merely useless, it is a set of keys the client may have revoked.
            statement: "delete from client_keys where ctid = any (array(
                            select ctid from client_keys
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "users",
        rule: Rule::Kept("an account is deleted by a person, not by a sweep"),
    },
    Retention {
        table: "subject_identifiers",
        rule: Rule::Kept(
            "OIDC Core §8: a subject identifier is never reassigned, so the row \
             that reserves it outlives everything derived from it",
        ),
    },
    Retention {
        table: "tenant_pairwise_salts",
        rule: Rule::Kept(
            "write-once, enforced by a trigger: deleting a salt would reassign \
             every `sub` in the tenant",
        ),
    },
    Retention {
        table: "credentials",
        rule: Rule::Kept("a passkey or password lives as long as its account"),
    },
    Retention {
        table: "user_roles",
        rule: Rule::Kept(
            "authority is granted and revoked by a person: a deployment admin \
             whose role expired on a timer is a deployment nobody can administer",
        ),
    },
    Retention {
        table: "passkey_enrolments",
        rule: Rule::Sweep {
            // An outstanding registration challenge, five minutes wide. It
            // cascades from `sessions` too, but a session lives for hours and
            // the challenge must not: a row kept past `expires_at` is a
            // challenge that is refused on the clock and still sitting there
            // to be read.
            //
            // Before `sessions`, and that is the only thing the order in this
            // table decides. Either way the row is gone; swept first, it is
            // reported as swept rather than disappearing silently under a
            // cascade, and a sweep whose count for this table is always zero
            // is a rule nobody can tell is working.
            statement: "delete from passkey_enrolments where ctid = any (array(
                            select ctid from passkey_enrolments
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "sessions",
        rule: Rule::Sweep {
            // The absolute deadline only, matching
            // `PgSessionRepository::purge_expired`: an idle session may still
            // be revived by use, and deleting it signs out somebody who was
            // coming back. `session_clients` follows by cascade.
            statement: "delete from sessions where ctid = any (array(
                            select ctid from sessions
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "session_clients",
        rule: Rule::Kept("cascades from `sessions`; a row cannot outlive its session"),
    },
    Retention {
        table: "auth_requests",
        rule: Rule::Sweep {
            // The pushed parameters and the interaction state: `login_hint`,
            // `claims`, whatever the client asked for about the user. FAPI 2.0
            // SP §7 is explicit that this is the material an AS leaks.
            statement: "delete from auth_requests where ctid = any (array(
                            select ctid from auth_requests
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "grants",
        rule: Rule::Kept(
            "a grant is the revocable unit of authority: deleting one deletes \
             the only row that could revoke the tokens minted from it. Grant \
             Management ID1 §5.6's unclaimed-grant cleanup is `ast-uwv.4`",
        ),
    },
    Retention {
        table: "authorization_codes",
        rule: Rule::Sweep {
            statement: "delete from authorization_codes where ctid = any (array(
                            select ctid from authorization_codes
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            // A code expires in sixty seconds (FAPI 2.0 SP §5.3.2.1 item 11)
            // but the *row* is what detects a replay: `PgCodeRepository::redeem`
            // reads `consumed_at` on a code it could not spend, and revokes the
            // grant if it finds one. Delete the row at expiry and a stolen code
            // presented a minute late is an ordinary `invalid_grant` instead of
            // the incident it is (RFC 6749 §10.5, RFC 9700 §4.1.2). A day of
            // rows is a negligible amount of storage and the whole of that
            // signal.
            grace: Duration::days(1),
        },
    },
    Retention {
        table: "refresh_tokens",
        rule: Rule::Sweep {
            // `expires_at` is nullable — a refresh token may have none — and a
            // null must not be swept. Revoked-but-unexpired rows stay too: the
            // token is still presentable and the row is what refuses it.
            statement: "delete from refresh_tokens where ctid = any (array(
                            select ctid from refresh_tokens
                             where tenant_id = $1
                               and expires_at is not null and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "access_token_denylist",
        rule: Rule::Sweep {
            // Past `expires_at` the token fails on `exp` without help, so the
            // row stops earning its keep — the schema says so on the table.
            statement: "delete from access_token_denylist where ctid = any (array(
                            select ctid from access_token_denylist
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "jti_replay",
        rule: Rule::Sweep {
            // The single-use marker for client assertions and DPoP proofs, and
            // the fastest-growing table here: one row per authenticated
            // request. Its `expires_at` is the assertion's own `exp`, after
            // which a replay fails on the clock instead.
            statement: "delete from jti_replay where ctid = any (array(
                            select ctid from jti_replay
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
    Retention {
        table: "signing_keys",
        rule: Rule::Kept(
            "a retired key's row survives so its `kid` is never handed out \
             twice; the private half is ciphertext under a KEK held elsewhere",
        ),
    },
    Retention {
        table: "key_rotation_schedules",
        rule: Rule::Kept("one row per tenant and algorithm, rewritten rather than accumulated"),
    },
    Retention {
        table: "audit_events",
        rule: Rule::Kept(
            "append-only by trigger, and the trail is the one artefact meant to \
             outlive everything else. Trimming it is \
             `PgAuditSink::purge_older_than`, which announces itself to the \
             trigger — a deliberate operator act against a stated retention \
             window, not a timer",
        ),
    },
    Retention {
        table: "outbox",
        rule: Rule::Sweep {
            // Only rows that have reached a terminal state. A `pending` or
            // `failed` row is work still owed to a relying party, however old
            // it looks, and deleting it would drop a logout notification.
            statement: "delete from outbox where ctid = any (array(
                            select ctid from outbox
                             where tenant_id = $1
                               and status in ('delivered', 'abandoned')
                               and coalesce(delivered_at, created_at) <= $2
                             limit $3))",
            // A delivered logout token is evidence for a week: long enough to
            // answer "did the relying party get told" during an incident,
            // short enough that the payloads do not accumulate.
            grace: Duration::days(7),
        },
    },
    Retention {
        table: "rate_limits",
        rule: Rule::Sweep {
            statement: "delete from rate_limits where ctid = any (array(
                            select ctid from rate_limits
                             where tenant_id = $1 and expires_at <= $2
                             limit $3))",
            grace: Duration::ZERO,
        },
    },
];

/// What one tenant's sweep did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Sweep {
    /// Rows deleted, per table, in [`POLICY`] order. Tables that lost nothing
    /// are absent, so a quiet sweep logs nothing.
    pub deleted: Vec<(&'static str, u64)>,
    /// Whether a table hit its per-sweep batch ceiling and still had rows to
    /// give, so a caller can tell "nothing left" from "still catching up".
    ///
    /// The ceiling itself is not part of this contract — it bounds one pass,
    /// not the work — so what a caller does with a `true` is schedule another
    /// sweep, not compute how much is left.
    pub more_to_do: bool,
}

impl Sweep {
    /// Rows deleted across every table.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.deleted.iter().map(|(_, count)| count).sum()
    }
}

/// The result of asking one tenant to be swept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SweepOutcome {
    /// This replica held the lock and did the work.
    Swept(Sweep),
    /// Another replica is sweeping this tenant right now. Nothing was done,
    /// which is the correct amount of work to duplicate.
    Busy,
}

/// Deletes expired rows, one tenant at a time.
#[derive(Debug, Clone)]
pub struct PgRetention {
    pool: PgPool,
}

impl PgRetention {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Applies [`POLICY`] to one tenant.
    ///
    /// Returns [`SweepOutcome::Busy`] without touching a row if another
    /// connection is already sweeping this tenant.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if a connection cannot be acquired or a
    /// statement fails. A failure part-way through leaves the rows it already
    /// deleted deleted: every batch is its own transaction, and there is
    /// nothing to roll back to that would be more correct.
    pub async fn sweep_tenant(
        &self,
        tenant: &TenantId,
        now: OffsetDateTime,
    ) -> Result<SweepOutcome, DomainError> {
        let mut connection = self.pool.acquire().await.map_err(to_domain_error)?;

        let acquired: bool =
            sqlx::query_scalar("select pg_try_advisory_lock(hashtext($1), hashtext('retention'))")
                .bind(tenant.as_str())
                .fetch_one(&mut *connection)
                .await
                .map_err(to_domain_error)?;
        if !acquired {
            return Ok(SweepOutcome::Busy);
        }

        let swept = Self::run(&mut connection, tenant, now).await;
        Self::release(connection, tenant).await;
        swept.map(SweepOutcome::Swept)
    }

    /// One pass over [`POLICY`], with the tenant's lock held.
    async fn run(
        connection: &mut PoolConnection<Postgres>,
        tenant: &TenantId,
        now: OffsetDateTime,
    ) -> Result<Sweep, DomainError> {
        let mut sweep = Sweep::default();

        for entry in POLICY {
            let Rule::Sweep { statement, grace } = entry.rule else {
                continue;
            };
            let cutoff = now - grace;
            let mut removed = 0_u64;

            for batch in 0..MAX_BATCHES {
                let affected = sqlx::query(statement)
                    .bind(tenant.as_str())
                    .bind(cutoff)
                    .bind(BATCH)
                    .execute(&mut **connection)
                    .await
                    .map_err(to_domain_error)?
                    .rows_affected();
                removed += affected;

                if affected < BATCH.unsigned_abs() {
                    break;
                }
                if batch + 1 == MAX_BATCHES {
                    sweep.more_to_do = true;
                }
            }

            if removed > 0 {
                sweep.deleted.push((entry.table, removed));
            }
        }
        Ok(sweep)
    }

    /// Gives the tenant's lock back.
    ///
    /// A failure here is logged rather than returned: the sweep itself
    /// succeeded, and the lock is released by the connection dying in any case.
    /// The connection is closed rather than returned to the pool, because a
    /// pooled connection that still holds the lock would lock the tenant out
    /// until the pool happened to recycle it.
    async fn release(mut connection: PoolConnection<Postgres>, tenant: &TenantId) {
        let released =
            sqlx::query("select pg_advisory_unlock(hashtext($1), hashtext('retention'))")
                .bind(tenant.as_str())
                .execute(&mut *connection)
                .await;

        if let Err(error) = released {
            tracing::warn!(
                %error,
                tenant = %tenant,
                "could not release the retention lock; closing the connection to drop it"
            );
            let _ = connection.close().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every swept statement has to be tenant-scoped and has to name its own
    /// table. `crate::sql_audit` cannot see these — they are not literals
    /// inside a `sqlx::query!` call — so the same rule is asserted here.
    #[test]
    fn every_swept_statement_is_tenant_scoped_and_names_its_table() {
        for entry in POLICY {
            let Rule::Sweep { statement, .. } = entry.rule else {
                continue;
            };
            assert!(
                statement.contains("tenant_id = $1"),
                "{} is swept without a tenant predicate",
                entry.table
            );
            assert!(
                statement.starts_with(&format!("delete from {} ", entry.table)),
                "the statement filed under {} deletes from somewhere else: {statement}",
                entry.table
            );
            assert!(
                statement.contains("limit $3"),
                "{} is swept unbatched, which locks the table for as long as it takes",
                entry.table
            );
        }
    }

    /// A table filed twice would have one rule silently ignored by the
    /// completeness test, which compares sets.
    #[test]
    fn no_table_is_filed_twice() {
        let mut seen = BTreeSet::new();
        for entry in POLICY {
            assert!(seen.insert(entry.table), "{} appears twice", entry.table);
        }
    }

    /// A kept table has to say why. "Kept" with an empty reason is how a table
    /// nobody thought about gets past review.
    #[test]
    fn every_kept_table_carries_a_reason() {
        for entry in POLICY {
            if let Rule::Kept(reason) = entry.rule {
                assert!(
                    reason.len() > 20,
                    "{} is kept without a reason worth reading",
                    entry.table
                );
            }
        }
    }

    /// The one place a grace period is not zero is the one place it changes
    /// behaviour, so it is worth pinning rather than leaving to a comment.
    #[test]
    fn an_expired_authorization_code_survives_long_enough_to_catch_a_replay() {
        let code = POLICY
            .iter()
            .find(|entry| entry.table == "authorization_codes")
            .expect("authorization_codes has a rule");
        let Rule::Sweep { grace, .. } = code.rule else {
            panic!("authorization codes must be swept");
        };
        assert!(
            grace >= Duration::hours(1),
            "a code row deleted at expiry cannot detect the replay of that code"
        );
    }
}
