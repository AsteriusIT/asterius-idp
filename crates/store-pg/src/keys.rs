//! The signing-key repository: lifecycle, rotation and encryption at rest.
//!
//! # The state machine
//!
//! A key moves `pending -> active -> retiring -> retired`, and never backwards.
//! The shape comes from OIDC Core §10.1.1, which describes rotation as adding
//! new keys to the JWK Set, beginning to use one "at [the signer's] discretion"
//! and signalling the change through the `kid`, and retaining "recently
//! decommissioned signing keys for a reasonable period of time to facilitate a
//! smooth transition":
//!
//! * **`pending`** — published, not signing. It sits here for the tenant's
//!   propagation period, which is how a verifier's cached JWK Set gets a chance
//!   to turn over before the first token signed with the key arrives. A
//!   verifier should never meet an unfamiliar `kid`.
//! * **`active`** — the key new signatures are made with. Exactly one per
//!   tenant, purpose and algorithm; the schema's partial unique index is what
//!   makes "exactly" true even under a race.
//! * **`retiring`** — no longer signing, still published, for the grace period.
//!   That period must exceed the lifetime of the longest-lived token the key
//!   signed, or a token still inside its own `exp` stops verifying.
//! * **`retired`** — out of the JWKS. The row stays so the `kid` is never
//!   reused, and so an incident review can still see the key existed.
//!
//! And one state off that path, reached only by an operator responding to a
//! compromise (`ast-7rq`):
//!
//! * **`purged`** — out of the JWKS *and* the private material destroyed: the
//!   ciphertext, nonce and `kek_id` columns are emptied in place. Terminal. Its
//!   signatures also stop verifying, which the four states above never do —
//!   [`PgKeyRepository::public_key`] refuses to resolve it — because the
//!   reason to destroy a key is that somebody else may hold it.
//!
//! # Concurrency
//!
//! Rotation is a read-then-write over several rows, so two callers — an
//! operator triggering one while the background sweep runs, or two replicas
//! sweeping at once — would otherwise interleave into two new keys, or into two
//! keys both claiming to be active. Every lifecycle pass runs inside a
//! transaction holding a per-tenant advisory lock, so the second caller waits
//! and then observes the first caller's work rather than repeating it.
//! ([`PgKeyRepository::set_schedule`] does not take it: one statement is
//! already atomic, and it changes no key.)
//!
//! The lock uses the *two-key* advisory lock space, `(tenant, 'key-rotation')`.
//! [`crate::PgAuditSink`] takes a one-key lock on the same tenant, and the two
//! spaces do not overlap — which matters, because a rotation records an audit
//! event and a shared lock would be a deadlock rather than a queue.
//!
//! # Encryption at rest
//!
//! The private half is sealed by a [`Kek`] before it is written and is never
//! stored in any other form. The ciphertext is bound to the row's tenant,
//! `kid`, purpose and algorithm, so an attacker with an `UPDATE` can still move
//! a key between tenants or relabel it — and gets ciphertext that no longer
//! decrypts rather than a working key in the wrong place. See
//! [`asterius_jose::kek`].
//!
//! # What is not here
//!
//! This type does not implement [`Signer`](asterius_domain::keys::Signer).
//! Signing through it would mean unwrapping the private key on every token —
//! for a cloud KMS, a network round trip per token. The composition root loads
//! the active key once and signs from memory; `ast-f7m.7` owns the admin
//! endpoint that triggers a rotation, and this is the operation it will call.

use crate::error::to_domain_error;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::keys::{
    KeyPurge, KeyPurpose, KeyState, KeyStore, Kid, PublicKeyRecord, PurgeReason, SigningAlgorithm,
};
use asterius_domain::ports::TenantScoped;
use asterius_domain::{DomainError, TenantId};
use asterius_jose::{Kek, KeyBinding, SigningKey, WrappedKey, thumbprint};
use serde_json::Value;
use sqlx::postgres::PgPool;
use sqlx::{Acquire as _, PgTransaction};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

/// The signing-key repository for one tenant.
///
/// Constructed with the tenant, so every statement below binds it and a query
/// that forgot the tenant is not something a caller can phrase.
#[derive(Debug, Clone)]
pub struct PgKeyRepository {
    pool: PgPool,
    tenant: TenantId,
    kek: Arc<dyn Kek>,
    audit: Arc<dyn AuditSink>,
}

impl TenantScoped for PgKeyRepository {
    fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}

/// The only purpose this repository creates keys for.
///
/// ADR-0004: JWE is not implemented, so there is no encryption key to rotate.
/// The purpose is still written to every row and filtered on in every read, so
/// that an encryption key added later cannot be picked up by the signing path
/// — which is the reuse FAPI 2.0 SP §6.8 item 2 warns about.
const PURPOSE: KeyPurpose = KeyPurpose::Signing;

/// What one pass of the lifecycle did, and the policy it ran under.
///
/// Both names now belong to `asterius-domain`: `ast-f7m.7` put the admin API in
/// front of this repository, and `asterius-admin-api` may not depend on an
/// adapter. Re-exported under the spelling this module has always used, so the
/// move is invisible to the server's sweep and to the tests below.
pub use asterius_domain::keys::{KeyRotation as Rotation, RotationSchedule};

/// One row of `signing_keys`, before it becomes a record.
struct KeyRow {
    kid: String,
    alg: String,
    purpose: String,
    state: String,
    public_jwk: Value,
    created_at: OffsetDateTime,
}

impl KeyRow {
    /// Converts a row into a record, re-validating what the schema cannot.
    ///
    /// The algorithm, the purpose and the state are parsed again on the way
    /// out. The schema's `check` constraints already restrict all three, but a
    /// constraint can be dropped and a row can be edited during an incident,
    /// and the failure mode of guessing here is publishing a key in a JWKS
    /// under an algorithm it cannot sign with.
    fn into_record(self, tenant: &TenantId) -> Result<PublicKeyRecord, DomainError> {
        let algorithm = SigningAlgorithm::parse(&self.alg)
            .ok_or_else(|| DomainError::invalid("alg", format!("unknown: {}", self.alg)))?;
        let purpose = KeyPurpose::parse(&self.purpose)
            .ok_or_else(|| DomainError::invalid("purpose", format!("unknown: {}", self.purpose)))?;
        let state = KeyState::parse(&self.state)
            .ok_or_else(|| DomainError::invalid("state", format!("unknown: {}", self.state)))?;

        // The published `use` member and the purpose column say the same thing
        // in two places; the schema constrains them to agree, and a reader that
        // trusted only one of them would not notice if that constraint went
        // away.
        if self.public_jwk.get("use").and_then(Value::as_str) != Some(purpose.as_str()) {
            return Err(DomainError::invalid(
                "public_jwk",
                "the JWK `use` member disagrees with the stored purpose",
            ));
        }

        Ok(PublicKeyRecord {
            tenant: tenant.clone(),
            kid: Kid::new(self.kid),
            algorithm,
            purpose,
            state,
            public_jwk: self.public_jwk,
            created_at: self.created_at,
        })
    }
}

impl PgKeyRepository {
    /// Binds a pool to one tenant, a key-encryption key and an audit sink.
    ///
    /// The audit sink is a constructor argument and not a parameter of
    /// [`Self::rotate`], so that "a rotation is recorded" is a property of
    /// holding the repository rather than of remembering to pass a sink.
    #[must_use]
    pub const fn new(
        pool: PgPool,
        tenant: TenantId,
        kek: Arc<dyn Kek>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            pool,
            tenant,
            kek,
            audit,
        }
    }

    /// This tenant's rotation policy, creating the default one if it has none.
    ///
    /// The defaults are in the schema, not here: a tenant that has never been
    /// configured still has to rotate, and a policy that only exists once
    /// somebody sets it is a policy most deployments never get.
    ///
    /// # Errors
    ///
    /// Returns a storage error, or [`DomainError::Conflict`] if the tenant does
    /// not exist.
    pub async fn schedule(
        &self,
        algorithm: SigningAlgorithm,
    ) -> Result<RotationSchedule, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let schedule = self.ensure_schedule(&mut transaction, algorithm).await?;
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(schedule)
    }

    /// Replaces this tenant's rotation policy.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invalid`] if a period is negative or does not fit
    /// what the schema will hold — the bounds are checked there, and a caller
    /// gets the constraint name back rather than a panic.
    pub async fn set_schedule(
        &self,
        algorithm: SigningAlgorithm,
        schedule: RotationSchedule,
    ) -> Result<(), DomainError> {
        let (rotation, propagation, grace) = (
            seconds(schedule.rotation_period, "rotation_period")?,
            seconds(schedule.propagation_period, "propagation_period")?,
            seconds(schedule.grace_period, "grace_period")?,
        );

        sqlx::query!(
            "insert into key_rotation_schedules
                 (tenant_id, purpose, alg, rotation_period_seconds,
                  propagation_period_seconds, grace_period_seconds)
             values ($1, $2, $3, $4, $5, $6)
             on conflict (tenant_id, purpose, alg) do update
             set rotation_period_seconds = excluded.rotation_period_seconds,
                 propagation_period_seconds = excluded.propagation_period_seconds,
                 grace_period_seconds = excluded.grace_period_seconds",
            self.tenant.as_str(),
            PURPOSE.as_str(),
            algorithm.as_str(),
            rotation,
            propagation,
            grace
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(to_domain_error)
    }

    /// Rotates now, whatever the schedule says.
    ///
    /// This is the operator's lever, and the one `ast-f7m.7` will put behind an
    /// endpoint. It promotes whatever is due, retires whatever has outlived its
    /// grace period, and stages a new key — unless one is already staged, in
    /// which case it reports that one rather than piling up keys nobody has
    /// started using yet.
    ///
    /// The first key a tenant ever gets is created `active` rather than
    /// `pending`. The propagation period exists to protect verifiers that have
    /// already cached a JWK Set; on a tenant that has never published one there
    /// is nothing to protect, and waiting would mean a tenant that cannot issue
    /// a token for fifteen minutes after it is created.
    ///
    /// # Errors
    ///
    /// Returns a storage error, or [`DomainError::Storage`] wrapping a
    /// [`JoseError`](asterius_jose::JoseError) if key generation or the
    /// key-encryption key fails. A failure of the audit write fails the call:
    /// see the note in the implementation about the window this leaves.
    pub async fn rotate(
        &self,
        algorithm: SigningAlgorithm,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<Rotation, DomainError> {
        self.run(algorithm, actor, now, true).await
    }

    /// Applies the schedule: promotes, retires, and stages a new key only if
    /// one is due.
    ///
    /// This is what a background sweep calls, as often as it likes. It is
    /// cheap when there is nothing to do, and it records nothing in the audit
    /// trail on a pass that changed nothing — a trail with one "no change"
    /// record per minute is a trail nobody reads.
    ///
    /// # Errors
    ///
    /// As [`Self::rotate`].
    pub async fn apply_schedule(
        &self,
        algorithm: SigningAlgorithm,
        now: OffsetDateTime,
    ) -> Result<Rotation, DomainError> {
        self.run(algorithm, Actor::System, now, false).await
    }

    /// Every key this tenant holds, in any state, retired ones included.
    ///
    /// The read behind the console's key screen (`ast-f7m.7`), and deliberately
    /// wider than [`Self::published_keys`]: a retired key must not be in the
    /// JWKS, but an operator asking "what happened to that `kid`?" is asking
    /// about exactly the keys the JWKS no longer names.
    ///
    /// Ordered by algorithm and then by position in the state machine, because
    /// that is how the screen groups them and an order settled in SQL is one
    /// the console cannot get wrong.
    ///
    /// # Errors
    ///
    /// Returns a storage error, or [`DomainError::Invalid`] if a row's
    /// algorithm, purpose or state is not one this build knows — see
    /// [`KeyRow::into_record`].
    pub async fn inventory(&self) -> Result<Vec<PublicKeyRecord>, DomainError> {
        sqlx::query_as!(
            KeyRow,
            "select kid, alg, purpose, state, public_jwk, created_at
             from signing_keys
             where tenant_id = $1
             order by alg,
                      case state when 'active' then 0 when 'pending' then 1
                                 when 'retiring' then 2 else 3 end,
                      created_at desc, kid",
            self.tenant.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?
        .into_iter()
        .map(|row| row.into_record(&self.tenant))
        .collect()
    }

    /// Promotes a staged key now, without waiting out the propagation period.
    ///
    /// The other half of [`Activation::Immediate`]: [`Self::rotate`] stages the
    /// key and publishes it, and this makes it sign. Split in two because the
    /// intermediate state — a `pending` key in the JWKS — is a state the
    /// machine already has, so a caller that fails between them has published a
    /// key early and nothing worse. Merging them into one transaction would
    /// trade that for a rollback that unpublishes a key some verifier may
    /// already have cached.
    ///
    /// A `kid` that is already active is not an error: the tenant's first key
    /// is created active (see [`Self::stage`]), so an immediate rotation on a
    /// tenant with no keys arrives here with the work already done.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if the tenant holds no such key,
    /// [`DomainError::Conflict`] if it has already left `pending` for
    /// `retiring` or `retired` — a key that has stopped signing must not be
    /// brought back, because the reason it stopped may have been a compromise.
    pub async fn activate(
        &self,
        kid: &Kid,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<Rotation, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let connection = transaction.acquire().await.map_err(to_domain_error)?;
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('key-rotation'))")
            .bind(self.tenant.as_str())
            .execute(&mut *connection)
            .await
            .map_err(to_domain_error)?;

        let row = sqlx::query!(
            "select alg, state from signing_keys
             where tenant_id = $1 and kid = $2 and purpose = $3",
            self.tenant.as_str(),
            kid.as_str(),
            PURPOSE.as_str()
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?
        .ok_or(DomainError::NotFound)?;

        let state = KeyState::parse(&row.state)
            .ok_or_else(|| DomainError::invalid("state", format!("unknown: {}", row.state)))?;
        let algorithm = SigningAlgorithm::parse(&row.alg)
            .ok_or_else(|| DomainError::invalid("alg", format!("unknown: {}", row.alg)))?;

        match state {
            KeyState::Active => return Ok(Rotation::default()),
            KeyState::Pending => {}
            KeyState::Retiring | KeyState::Retired | KeyState::Purged => {
                return Err(DomainError::Conflict(format!(
                    "key {kid} is {}, and a key that has stopped signing is not \
                     brought back",
                    state.as_str()
                )));
            }
        }

        // Demote before promoting. The partial unique index permits one active
        // key per algorithm and is checked per statement, so the other order
        // fails rather than briefly allowing two.
        let superseded = sqlx::query_scalar!(
            "update signing_keys
             set state = 'retiring', retiring_at = $4
             where tenant_id = $1 and purpose = $2 and alg = $3 and state = 'active'
             returning kid",
            self.tenant.as_str(),
            PURPOSE.as_str(),
            algorithm.as_str(),
            now
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?
        .map(Kid::new);

        sqlx::query!(
            "update signing_keys set state = 'active', activated_at = $3
             where tenant_id = $1 and kid = $2",
            self.tenant.as_str(),
            kid.as_str(),
            now
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        transaction.commit().await.map_err(to_domain_error)?;

        let rotation = Rotation {
            activated: Some(kid.clone()),
            superseded,
            ..Rotation::default()
        };
        self.record(algorithm, actor, now, &rotation).await?;
        Ok(rotation)
    }

    /// Takes one key out of the published set, now.
    ///
    /// **The active key is refused.** Retiring the one key an algorithm signs
    /// with leaves the tenant unable to issue a token of that algorithm, and
    /// the operation that replaces an active key is [`Self::rotate`], which
    /// puts a successor in place first. A console button that could take an
    /// issuer offline in one click is a button somebody eventually presses.
    ///
    /// Everything else is retirable. A `pending` key never signed anything, so
    /// dropping it costs nothing — the schema anticipates this and requires
    /// only `retired_at` for a key retired straight out of `pending`. A
    /// `retiring` key's grace period is cut short, which is destructive and
    /// meant to be: it is how an operator stops honouring signatures from a key
    /// they no longer trust, and OIDC Core §10.1.1's "reasonable period of
    /// time" is a courtesy to verifiers rather than an obligation to a
    /// compromised key.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if the tenant holds no such key,
    /// [`DomainError::Conflict`] if it is the active one, or a storage failure.
    pub async fn retire(
        &self,
        kid: &Kid,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<Rotation, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let connection = transaction.acquire().await.map_err(to_domain_error)?;
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('key-rotation'))")
            .bind(self.tenant.as_str())
            .execute(&mut *connection)
            .await
            .map_err(to_domain_error)?;

        let row = sqlx::query!(
            "select alg, state from signing_keys
             where tenant_id = $1 and kid = $2 and purpose = $3",
            self.tenant.as_str(),
            kid.as_str(),
            PURPOSE.as_str()
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?
        .ok_or(DomainError::NotFound)?;

        let state = KeyState::parse(&row.state)
            .ok_or_else(|| DomainError::invalid("state", format!("unknown: {}", row.state)))?;
        let algorithm = SigningAlgorithm::parse(&row.alg)
            .ok_or_else(|| DomainError::invalid("alg", format!("unknown: {}", row.alg)))?;

        match state {
            // Already out of the JWKS. Reported as a pass that changed nothing
            // rather than as a failure: retiring a retired key is what a retried
            // request looks like, and a 409 there would be a lie about the
            // state the caller asked for. A purged key is retired and then
            // some — [`Self::purge`] leaves it out of the published set — so
            // asking to retire it is the same non-event.
            KeyState::Retired | KeyState::Purged => {
                transaction.commit().await.map_err(to_domain_error)?;
                return Ok(Rotation::default());
            }
            KeyState::Active => {
                return Err(DomainError::Conflict(format!(
                    "key {kid} is the active {algorithm} key; rotate to replace it \
                     rather than retiring the key the tenant signs with"
                )));
            }
            KeyState::Pending | KeyState::Retiring => {}
        }

        sqlx::query!(
            "update signing_keys set state = 'retired', retired_at = $3
             where tenant_id = $1 and kid = $2",
            self.tenant.as_str(),
            kid.as_str(),
            now
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        transaction.commit().await.map_err(to_domain_error)?;

        let rotation = Rotation {
            retired: vec![kid.clone()],
            ..Rotation::default()
        };
        self.record(algorithm, actor, now, &rotation).await?;
        Ok(rotation)
    }

    /// Destroys one key's private material: the response to a compromise.
    ///
    /// [`Self::retire`] stops a key being used; this stops it being *usable*.
    /// The row survives — the `kid` is an RFC 7638 thumbprint and must never be
    /// handed out twice, and an incident review has to see that the key existed
    /// — but the three envelope columns are emptied, the key leaves the
    /// published set, and the state becomes `purged`, which
    /// [`KeyState::is_trusted`] refuses and [`Self::public_key`] therefore
    /// stops resolving.
    ///
    /// **The active key is refused**, for the reason [`Self::retire`] refuses
    /// it and more so: this one cannot be undone by anybody, including the
    /// operator who did it. The compromise path is [`Self::rotate`] followed by
    /// [`Self::activate`] — which is what `Activation::Immediate` does — and
    /// then this.
    ///
    /// Every other state is purgeable, including `pending`: a key staged an
    /// hour ago and leaked since is exactly as compromised as one that signed
    /// for a year.
    ///
    /// # What it does not reach
    ///
    /// A token some resource server has already accepted. This server stops
    /// signing with the key, stops publishing it and stops accepting its
    /// signatures; it cannot reach into a third party that cached the JWK Set
    /// before the purge and is still inside the token's `exp`. That is why FAPI
    /// 2.0 SP §6.8 item 1 asks for short rotation periods as well as for a
    /// response to compromise — see `docs/threat-model.md`.
    ///
    /// # Errors
    ///
    /// [`DomainError::NotFound`] if the tenant holds no such key,
    /// [`DomainError::Conflict`] if it is the active one, or a storage failure.
    pub async fn purge(
        &self,
        kid: &Kid,
        reason: &PurgeReason,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<KeyPurge, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let connection = transaction.acquire().await.map_err(to_domain_error)?;
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('key-rotation'))")
            .bind(self.tenant.as_str())
            .execute(&mut *connection)
            .await
            .map_err(to_domain_error)?;

        let row = sqlx::query!(
            "select alg, state from signing_keys
             where tenant_id = $1 and kid = $2 and purpose = $3",
            self.tenant.as_str(),
            kid.as_str(),
            PURPOSE.as_str()
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?
        .ok_or(DomainError::NotFound)?;

        let state = KeyState::parse(&row.state)
            .ok_or_else(|| DomainError::invalid("state", format!("unknown: {}", row.state)))?;
        let algorithm = SigningAlgorithm::parse(&row.alg)
            .ok_or_else(|| DomainError::invalid("alg", format!("unknown: {}", row.alg)))?;

        match state {
            KeyState::Active => {
                return Err(DomainError::Conflict(format!(
                    "key {kid} is the active {algorithm} key; rotate with immediate \
                     activation to replace it, then purge it"
                )));
            }
            // Already destroyed. Reported as a purge that destroyed nothing
            // rather than as a failure: that is what a retried request looks
            // like, and there is no second destruction to perform.
            KeyState::Purged => {
                transaction.commit().await.map_err(to_domain_error)?;
                return Ok(KeyPurge {
                    kid: kid.clone(),
                    previous_state: state,
                    destroyed: false,
                });
            }
            KeyState::Pending | KeyState::Retiring | KeyState::Retired => {}
        }

        // `retired_at` is set here too, and coalesced so that a key that had
        // already left the JWK Set keeps the moment it left: a purge out of
        // `retiring` cuts the grace period short, and the schema's
        // `signing_keys_timestamps_follow_the_state` requires the final stamp
        // on any key that is out of the published set.
        //
        // The three envelope columns go to NULL in the same statement, which is
        // the destruction itself — there is no KMS handle to revoke instead.
        // The key-encryption key is one key held outside the database and
        // shared by every row, so it cannot be destroyed per key; erasing the
        // ciphertext is what makes a backup taken afterwards carry nothing.
        sqlx::query!(
            "update signing_keys
             set state = 'purged',
                 private_key_ciphertext = null,
                 private_key_nonce = null,
                 kek_id = null,
                 retired_at = coalesce(retired_at, $3),
                 purged_at = $3
             where tenant_id = $1 and kid = $2",
            self.tenant.as_str(),
            kid.as_str(),
            now
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        transaction.commit().await.map_err(to_domain_error)?;

        // After the commit, like every other audit write here: the sink owns
        // its own transaction and takes a lock this one conflicts with. A crash
        // in between leaves a destroyed key with no `key.purged` line — the
        // emptied columns and `purged_at` are still the evidence — and a failed
        // audit write fails this call, so the omission is reported.
        self.record_purge(kid, algorithm, state, reason, actor, now)
            .await?;

        Ok(KeyPurge {
            kid: kid.clone(),
            previous_state: state,
            destroyed: true,
        })
    }

    /// The active signing key for an algorithm, decrypted.
    ///
    /// Returns `None` when the tenant has no active key of that algorithm,
    /// which is a real state — a tenant created a moment ago, or one whose keys
    /// were all destroyed after a compromise — and not an error.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Storage`] if the row cannot be decrypted under
    /// the configured key-encryption key, or if the plaintext is not a key of
    /// the algorithm the row claims. Both mean the row has been tampered with
    /// or the KEK has been replaced, and neither may produce a usable key.
    pub async fn active_signing_key(
        &self,
        algorithm: SigningAlgorithm,
    ) -> Result<Option<(Kid, SigningKey)>, DomainError> {
        // The three envelope columns became nullable when `purged` was added to
        // the state machine (migration `0003_key_purge`), and the `!` forces
        // them back to non-null here. That is sound rather than convenient: the
        // schema's `signing_keys_material_is_absent_only_when_purged`
        // constraint makes material absent *exactly* when the state is
        // `purged`, and `state = 'active'` is in the `where` clause.
        let Some(row) = sqlx::query!(
            "select kid,
                    private_key_ciphertext as \"private_key_ciphertext!\",
                    private_key_nonce as \"private_key_nonce!\",
                    kek_id as \"kek_id!\"
             from signing_keys
             where tenant_id = $1 and purpose = $2 and alg = $3 and state = 'active'",
            self.tenant.as_str(),
            PURPOSE.as_str(),
            algorithm.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?
        else {
            return Ok(None);
        };

        let kid = Kid::new(row.kid);
        let wrapped = WrappedKey::from_parts(
            row.kek_id,
            row.private_key_nonce,
            row.private_key_ciphertext,
        )
        .map_err(storage_error)?;

        let binding = KeyBinding::new(&self.tenant, &kid, PURPOSE, algorithm);
        let pkcs8 = self
            .kek
            .unwrap(binding, &wrapped)
            .await
            .map_err(storage_error)?;

        let key = SigningKey::from_pkcs8(algorithm, &pkcs8).map_err(storage_error)?;
        Ok(Some((kid, key)))
    }

    /// One pass of the lifecycle, under the tenant's rotation lock.
    async fn run(
        &self,
        algorithm: SigningAlgorithm,
        actor: Actor,
        now: OffsetDateTime,
        forced: bool,
    ) -> Result<Rotation, DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let connection = transaction.acquire().await.map_err(to_domain_error)?;

        // Held until the transaction ends, whichever way it ends. The two-key
        // space keeps this clear of the audit sink's per-tenant lock; see the
        // module documentation.
        sqlx::query("select pg_advisory_xact_lock(hashtext($1), hashtext('key-rotation'))")
            .bind(self.tenant.as_str())
            .execute(&mut *connection)
            .await
            .map_err(to_domain_error)?;

        let schedule = self.ensure_schedule(&mut transaction, algorithm).await?;

        // Retire first, so a key whose grace has expired leaves the JWKS in the
        // same pass that adds its eventual replacement — and so the ordering
        // never has two keys of one algorithm sitting in `retiring`.
        //
        // Not scoped to `algorithm`: a grace period expires per key, and a
        // tenant that stopped rotating ES256 should still not publish an ES256
        // key past its grace period.
        let retired: Vec<Kid> = sqlx::query_scalar!(
            "update signing_keys
             set state = 'retired', retired_at = $4
             where tenant_id = $1 and purpose = $2 and state = 'retiring'
               and retiring_at <= $3
             returning kid",
            self.tenant.as_str(),
            PURPOSE.as_str(),
            now - schedule.grace_period,
            now
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(to_domain_error)?
        .into_iter()
        .map(Kid::new)
        .collect();

        // Promote a pending key that has been published long enough. OIDC Core
        // §10.1.1: the new key is in the JWK Set first, and only then does the
        // signer begin using it.
        let ready = sqlx::query_scalar!(
            "select kid from signing_keys
             where tenant_id = $1 and purpose = $2 and alg = $3
               and state = 'pending' and created_at <= $4",
            self.tenant.as_str(),
            PURPOSE.as_str(),
            algorithm.as_str(),
            now - schedule.propagation_period
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        let mut activated = None;
        let mut superseded = None;
        if let Some(kid) = ready {
            // Demote before promoting. The partial unique index permits one
            // active key per algorithm and is checked per statement, so the
            // other order fails rather than briefly allowing two.
            superseded = sqlx::query_scalar!(
                "update signing_keys
                 set state = 'retiring', retiring_at = $4
                 where tenant_id = $1 and purpose = $2 and alg = $3 and state = 'active'
                 returning kid",
                self.tenant.as_str(),
                PURPOSE.as_str(),
                algorithm.as_str(),
                now
            )
            .fetch_optional(&mut *transaction)
            .await
            .map_err(to_domain_error)?
            .map(Kid::new);

            sqlx::query!(
                "update signing_keys
                 set state = 'active', activated_at = $3
                 where tenant_id = $1 and kid = $2",
                self.tenant.as_str(),
                kid,
                now
            )
            .execute(&mut *transaction)
            .await
            .map_err(to_domain_error)?;
            activated = Some(Kid::new(kid));
        }

        let mut created = None;
        if forced || schedule.is_due(now) {
            created = Some(self.stage(&mut transaction, algorithm, now).await?);
            sqlx::query!(
                "update key_rotation_schedules set last_rotated_at = $4
                 where tenant_id = $1 and purpose = $2 and alg = $3",
                self.tenant.as_str(),
                PURPOSE.as_str(),
                algorithm.as_str(),
                now
            )
            .execute(&mut *transaction)
            .await
            .map_err(to_domain_error)?;
        }

        transaction.commit().await.map_err(to_domain_error)?;

        let rotation = Rotation {
            created,
            activated,
            superseded,
            retired,
        };

        // The audit record is written after the commit, because `AuditSink` owns
        // its own transaction and appending to the hash chain takes a lock this
        // one already conflicts with. A crash in between therefore leaves a
        // rotation with no audit line — the key rows and their timestamps are
        // still the evidence, and making the two atomic needs the outbox
        // (`ast-0ju.9`). A *failed* audit write fails this call, so the
        // omission is at least reported.
        if forced || !rotation.is_empty() {
            self.record(algorithm, actor, now, &rotation).await?;
        }
        Ok(rotation)
    }

    /// Generates, seals and inserts a new key.
    ///
    /// If one is already staged, that one is returned instead. Rotating twice
    /// inside the propagation period is an operator being careful, not a
    /// request for two keys.
    async fn stage(
        &self,
        transaction: &mut PgTransaction<'_>,
        algorithm: SigningAlgorithm,
        now: OffsetDateTime,
    ) -> Result<Kid, DomainError> {
        if let Some(staged) = sqlx::query_scalar!(
            "select kid from signing_keys
             where tenant_id = $1 and purpose = $2 and alg = $3 and state = 'pending'",
            self.tenant.as_str(),
            PURPOSE.as_str(),
            algorithm.as_str()
        )
        .fetch_optional(&mut **transaction)
        .await
        .map_err(to_domain_error)?
        {
            return Ok(Kid::new(staged));
        }

        let key = SigningKey::generate(algorithm).map_err(storage_error)?;
        let public_jwk = key.public_jwk().map_err(storage_error)?;
        let kid = thumbprint(&public_jwk).map_err(storage_error)?;

        let mut jwk = public_jwk;
        jwk["kid"] = Value::String(kid.as_str().to_owned());

        let binding = KeyBinding::new(&self.tenant, &kid, PURPOSE, algorithm);
        let wrapped = self
            .kek
            .wrap(binding, key.pkcs8())
            .await
            .map_err(storage_error)?;

        // A tenant with no active key of this algorithm has never published a
        // JWK Set anyone could have cached, so there is nothing for the
        // propagation period to protect and a wait would only mean an issuer
        // that cannot mint a token yet.
        let first = sqlx::query_scalar!(
            "select not exists (
                 select 1 from signing_keys
                 where tenant_id = $1 and purpose = $2 and alg = $3 and state = 'active'
             )",
            self.tenant.as_str(),
            PURPOSE.as_str(),
            algorithm.as_str()
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(to_domain_error)?
        .unwrap_or(false);

        let (state, activated_at) = if first {
            (KeyState::Active, Some(now))
        } else {
            (KeyState::Pending, None)
        };

        sqlx::query!(
            "insert into signing_keys
                 (tenant_id, kid, alg, purpose, public_jwk, private_key_ciphertext,
                  private_key_nonce, kek_id, state, created_at, activated_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            self.tenant.as_str(),
            kid.as_str(),
            algorithm.as_str(),
            PURPOSE.as_str(),
            jwk,
            wrapped.ciphertext(),
            wrapped.nonce(),
            wrapped.kek_id(),
            state.as_str(),
            now,
            activated_at
        )
        .execute(&mut **transaction)
        .await
        .map_err(to_domain_error)?;

        Ok(kid)
    }

    /// Reads this tenant's schedule, writing the schema's defaults first if it
    /// has none.
    async fn ensure_schedule(
        &self,
        transaction: &mut PgTransaction<'_>,
        algorithm: SigningAlgorithm,
    ) -> Result<RotationSchedule, DomainError> {
        sqlx::query!(
            "insert into key_rotation_schedules (tenant_id, purpose, alg) values ($1, $2, $3)
             on conflict (tenant_id, purpose, alg) do nothing",
            self.tenant.as_str(),
            PURPOSE.as_str(),
            algorithm.as_str()
        )
        .execute(&mut **transaction)
        .await
        .map_err(to_domain_error)?;

        let row = sqlx::query!(
            "select rotation_period_seconds, propagation_period_seconds,
                    grace_period_seconds, last_rotated_at
             from key_rotation_schedules
             where tenant_id = $1 and purpose = $2 and alg = $3",
            self.tenant.as_str(),
            PURPOSE.as_str(),
            algorithm.as_str()
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(to_domain_error)?;

        Ok(RotationSchedule {
            rotation_period: Duration::seconds(row.rotation_period_seconds),
            propagation_period: Duration::seconds(row.propagation_period_seconds),
            grace_period: Duration::seconds(row.grace_period_seconds),
            last_rotated_at: row.last_rotated_at,
        })
    }

    /// Records what the pass did.
    ///
    /// `kid` values are recorded as fingerprints rather than as text. They are
    /// public — the JWKS serves them — but they are long, high-entropy strings,
    /// which is exactly the shape [`Detail::text`] redacts; recording them as
    /// credentials keeps two events about one key correlatable and keeps the
    /// stored value from reading like an accident.
    async fn record(
        &self,
        algorithm: SigningAlgorithm,
        actor: Actor,
        now: OffsetDateTime,
        rotation: &Rotation,
    ) -> Result<(), DomainError> {
        let mut detail = Detail::new()
            .text("alg", algorithm.as_str())
            .text("purpose", PURPOSE.as_str())
            .number(
                "retired",
                i64::try_from(rotation.retired.len()).unwrap_or(i64::MAX),
            );

        for (field, kid) in [
            ("created_kid", rotation.created.as_ref()),
            ("activated_kid", rotation.activated.as_ref()),
            ("superseded_kid", rotation.superseded.as_ref()),
        ] {
            if let Some(kid) = kid {
                detail = detail.credential(field, kid.as_str());
            }
        }

        self.audit
            .record(
                AuditEvent::new(
                    self.tenant.clone(),
                    EventType::KEY_ROTATED,
                    Outcome::Success,
                    actor,
                    now,
                )
                .detail(detail),
            )
            .await
    }

    /// Records a destruction, and why it happened.
    ///
    /// Its own event type rather than a `key.rotated` with a flag: a rotation
    /// is routine and a trail full of them is background noise, while a purge
    /// is somebody deciding a key can no longer be trusted. An incident review
    /// starts from this line, so it carries the state the key was in, the
    /// algorithm it signed with, and the operator's reason.
    ///
    /// The `kid` is a fingerprint, like every other key event's — it is public,
    /// but it is a long high-entropy string, which is the shape [`Detail::text`]
    /// redacts. The *reason* is free text an operator typed and is recorded as
    /// such, which is why [`PurgeReason`] refuses control characters: a
    /// newline in it would be a second line in whatever reads the trail back.
    async fn record_purge(
        &self,
        kid: &Kid,
        algorithm: SigningAlgorithm,
        previous_state: KeyState,
        reason: &PurgeReason,
        actor: Actor,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let detail = Detail::new()
            .text("alg", algorithm.as_str())
            .text("purpose", PURPOSE.as_str())
            .text("previous_state", previous_state.as_str())
            .text("reason", reason.as_str())
            .credential("kid", kid.as_str());

        self.audit
            .record(
                AuditEvent::new(
                    self.tenant.clone(),
                    EventType::KEY_PURGED,
                    Outcome::Success,
                    actor,
                    now,
                )
                .detail(detail),
            )
            .await
    }
}

#[async_trait::async_trait]
impl KeyStore for PgKeyRepository {
    /// Every key this tenant publishes, active first.
    ///
    /// `retired` keys are absent by construction: the state is in the `where`
    /// clause, not applied by the caller, so there is no code path that serves
    /// a JWKS containing a key that has left it.
    async fn published_keys(&self, tenant: &TenantId) -> Result<Vec<PublicKeyRecord>, DomainError> {
        if tenant != &self.tenant {
            return Err(DomainError::invalid(
                "tenant_id",
                "does not match the tenant this repository is scoped to",
            ));
        }

        sqlx::query_as!(
            KeyRow,
            "select kid, alg, purpose, state, public_jwk, created_at
             from signing_keys
             where tenant_id = $1 and state in ('pending', 'active', 'retiring')
             order by case state when 'active' then 0 when 'pending' then 1 else 2 end,
                      created_at desc, kid",
            self.tenant.as_str()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?
        .into_iter()
        .map(|row| row.into_record(&self.tenant))
        .collect()
    }

    /// The key a `kid` names, in whatever state it is — except a purged one.
    ///
    /// Retiring and retired keys resolve: a token signed yesterday is verified
    /// today, and refusing an `id_token_hint` because the key that signed it
    /// has since been rotated out would break a logout for no security gain.
    ///
    /// A **purged** key does not resolve, and that is the whole point of
    /// purging one. It was destroyed because it was believed compromised, so
    /// its signatures — including the ones an attacker holding the leaked
    /// material made — must stop being accepted. The filter is here, on the
    /// port every verification path goes through, rather than at each call
    /// site: a caller that forgot to ask would otherwise trust it.
    /// [`Self::inventory`] is where an incident review sees the row.
    async fn public_key(
        &self,
        tenant: &TenantId,
        kid: &Kid,
    ) -> Result<Option<PublicKeyRecord>, DomainError> {
        if tenant != &self.tenant {
            return Err(DomainError::invalid(
                "tenant_id",
                "does not match the tenant this repository is scoped to",
            ));
        }

        sqlx::query_as!(
            KeyRow,
            "select kid, alg, purpose, state, public_jwk, created_at
             from signing_keys
             where tenant_id = $1 and kid = $2",
            self.tenant.as_str(),
            kid.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?
        .map(|row| row.into_record(&self.tenant))
        .transpose()
        // Filtered in Rust and not in the `where` clause, so that the one
        // definition of "a signature from this key may still be accepted"
        // lives on `KeyState` and every reader shares it.
        .map(|record| record.filter(|record| record.state.is_trusted()))
    }
}

/// Turns a JOSE or key-encryption failure into a storage failure.
///
/// A KEK that will not answer, a provider that will not generate a key and a
/// row that will not decrypt are all infrastructure failing, not a caller
/// passing something invalid — and the caller has nothing useful to do with the
/// distinction between them.
fn storage_error(error: asterius_jose::JoseError) -> DomainError {
    DomainError::Storage(Box::new(error))
}

/// Whole seconds, for a column that holds them.
fn seconds(duration: Duration, field: &'static str) -> Result<i64, DomainError> {
    if duration.is_negative() || duration.subsec_nanoseconds() != 0 {
        return Err(DomainError::invalid(
            field,
            "must be a positive whole number of seconds",
        ));
    }
    Ok(duration.whole_seconds())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_period_that_is_not_whole_seconds_is_refused_rather_than_rounded() {
        assert_eq!(seconds(Duration::seconds(900), "p").expect("whole"), 900);
        assert!(seconds(Duration::milliseconds(1500), "p").is_err());
        assert!(seconds(Duration::seconds(-1), "p").is_err());
    }
}
