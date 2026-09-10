//! The user repository, and the table that remembers which `sub` a user is
//! known by in each sector.
//!
//! Three rules shape this file.
//!
//! **A row is validated by the same code on the way out as on the way in.** The
//! `claims` column is JSONB, which the database will hold whatever shape is put
//! in it, so the guarantee has to come from the parser: a bag is read back
//! through [`ClaimSet`]'s deserializer, which re-runs [`ClaimName::parse`] over
//! every key. A row that grew a `sub` claim during an incident fails to load
//! rather than reaching a token (`ast-83p.3`).
//!
//! **A subject is derived once and then remembered.** OIDC Core §8 requires a
//! Subject Identifier to be "locally unique and never reassigned", and §8.1
//! requires the pairwise calculation to be deterministic — so the derivation
//! could be repeated on every request instead of stored. It is stored anyway,
//! in `subject_identifiers`, for three reasons: the unique index on
//! `(tenant_id, subject)` is what turns a derivation collision into a refused
//! write rather than two users sharing an identity; resolving a `sub` from a
//! token back to a user is an index lookup instead of a scan over every user
//! and every sector; and an identifier already handed to a relying party stops
//! depending on the salt still being the one it was derived under.
//!
//! **The salt is not an argument.** [`PgUserRepository::subject`] reads the
//! tenant's pairwise salt out of the store and decrypts it; it does not accept
//! one. A caller able to supply the salt is a caller able to supply the wrong
//! one — a fresh salt, an empty salt, another tenant's — and every one of those
//! mints a `sub` that is entirely well-formed and permanently wrong, because
//! the first derivation is the one written to `subject_identifiers` and handed
//! to a relying party. See [`crate::salts`].
//!
//! [`ClaimName::parse`]: asterius_domain::ClaimName::parse

use crate::audit::PgAuditSink;
use crate::error::to_domain_error;
use crate::salts;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink as _, Detail, EventType, Outcome};
use asterius_domain::ports::TenantScoped;
use asterius_domain::{
    ClaimSet, DomainError, SectorIdentifier, SubjectId, TenantId, User, UserId, UserStatus,
};
use asterius_jose::Kek;
use sqlx::postgres::PgPool;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

/// The user repository for one tenant.
///
/// Constructed from a [`TenantScope`], so the tenant is a precondition of
/// holding the handle rather than an argument a query might forget.
///
/// [`TenantScope`]: crate::TenantScope
#[derive(Clone)]
pub struct PgUserRepository {
    pool: PgPool,
    tenant: TenantId,
    kek: Arc<dyn Kek>,
}

impl std::fmt::Debug for PgUserRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgUserRepository")
            .field("tenant", &self.tenant)
            .field("kek", &self.kek.id())
            .finish_non_exhaustive()
    }
}

impl TenantScoped for PgUserRepository {
    fn tenant(&self) -> &TenantId {
        &self.tenant
    }
}

/// One row of `users`, before it becomes an entity.
struct Row {
    user_id: Uuid,
    username: String,
    email: Option<String>,
    email_verified: bool,
    status: String,
    claims: serde_json::Value,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Row {
    /// Converts a row into an entity, re-validating what the schema cannot
    /// express.
    ///
    /// `status` is a check constraint the database does enforce; it is parsed
    /// again anyway, because the entity has an enum and a string that got past
    /// the constraint but not the enum would otherwise be an `unwrap`. `claims`
    /// is JSONB and the database enforces nothing about its shape, so this is
    /// the only place the claims model is applied to what is stored.
    fn into_entity(self, tenant: &TenantId) -> Result<User, DomainError> {
        let status = UserStatus::parse(&self.status)
            .ok_or_else(|| DomainError::invalid("status", format!("unknown: {}", self.status)))?;
        let claims: ClaimSet = serde_json::from_value(self.claims)
            .map_err(|e| DomainError::invalid("claims", e.to_string()))?;
        Ok(User {
            tenant: tenant.clone(),
            id: UserId::new(self.user_id),
            username: self.username,
            email: self.email,
            email_verified: self.email_verified,
            status,
            claims,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl PgUserRepository {
    /// Binds a pool to one tenant.
    ///
    /// `kek` is the key-encryption key the tenant's pairwise salt is sealed
    /// under. It is a constructor argument rather than a parameter of
    /// [`Self::subject`] for the same reason the salt itself is neither: the
    /// fewer places a caller can name key material, the fewer places it can
    /// name the wrong key material.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId, kek: Arc<dyn Kek>) -> Self {
        Self { pool, tenant, kek }
    }

    /// Finds one user by their local account identifier.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invalid`] if the stored row no longer describes a
    /// user this model accepts, or a storage error.
    pub async fn find(&self, id: UserId) -> Result<Option<User>, DomainError> {
        let row = sqlx::query_as!(
            Row,
            "select user_id, username, email, email_verified, status, claims,
                    created_at, updated_at
             from users
             where tenant_id = $1 and user_id = $2",
            self.tenant.as_str(),
            id.as_uuid()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(|row| row.into_entity(&self.tenant)).transpose()
    }

    /// Finds one user by the login identifier they authenticate with.
    ///
    /// # Errors
    ///
    /// As [`Self::find`].
    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>, DomainError> {
        let row = sqlx::query_as!(
            Row,
            "select user_id, username, email, email_verified, status, claims,
                    created_at, updated_at
             from users
             where tenant_id = $1 and username = $2",
            self.tenant.as_str(),
            username
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(|row| row.into_entity(&self.tenant)).transpose()
    }

    /// Finds the user a `sub` refers to, in any sector.
    ///
    /// This is the lookup UserInfo and token introspection perform: a token
    /// carries a `sub`, and the sector it was minted in is not in the token.
    /// The unique index on `(tenant_id, subject)` is what makes "in any sector"
    /// an unambiguous question.
    ///
    /// # Errors
    ///
    /// As [`Self::find`].
    pub async fn find_by_subject(&self, subject: &SubjectId) -> Result<Option<User>, DomainError> {
        let row = sqlx::query_as!(
            Row,
            "select u.user_id, u.username, u.email, u.email_verified, u.status, u.claims,
                    u.created_at, u.updated_at
             from users u
             join subject_identifiers s
               on s.tenant_id = u.tenant_id and s.user_id = u.user_id
             where u.tenant_id = $1 and s.subject = $2",
            self.tenant.as_str(),
            subject.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(|row| row.into_entity(&self.tenant)).transpose()
    }

    /// Creates or replaces a user.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invalid`] when the entity belongs to another
    /// tenant, [`DomainError::Conflict`] when the tenant does not exist or when
    /// the username or address is already taken, and a storage error otherwise.
    pub async fn upsert(&self, user: &User) -> Result<(), DomainError> {
        if user.tenant != self.tenant {
            // The scope is the tenant. An entity from another one arriving here
            // is a bug in the caller, and writing it would put a person's
            // account under the wrong owner.
            return Err(DomainError::invalid(
                "tenant_id",
                "does not match the tenant this repository is scoped to",
            ));
        }
        let claims = serde_json::to_value(&user.claims)
            .map_err(|e| DomainError::invalid("claims", e.to_string()))?;
        sqlx::query!(
            "insert into users (tenant_id, user_id, username, email, email_verified,
                                status, claims)
             values ($1, $2, $3, $4, $5, $6, $7)
             on conflict (tenant_id, user_id) do update
             set username = excluded.username,
                 email = excluded.email,
                 email_verified = excluded.email_verified,
                 status = excluded.status,
                 claims = excluded.claims",
            self.tenant.as_str(),
            user.id.as_uuid(),
            user.username,
            user.email.as_deref(),
            user.email_verified,
            user.status.as_str(),
            claims
        )
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(to_domain_error)
    }

    /// Deletes a user, and by cascade their credentials, sessions and every
    /// subject identifier they were known by.
    ///
    /// The identifiers are freed as rows and not as values: a trigger copies
    /// each one into `retired_subject_identifiers` on its way out, which is
    /// what keeps OIDC Core §8's "never reassigned" true of an account that no
    /// longer exists (`ast-2vk.12`). See [`Self::subject`].
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::NotFound`] when there was no such user, or a
    /// storage error.
    pub async fn delete(&self, id: UserId) -> Result<(), DomainError> {
        let result = sqlx::query!(
            "delete from users where tenant_id = $1 and user_id = $2",
            self.tenant.as_str(),
            id.as_uuid()
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound);
        }
        Ok(())
    }

    /// The `sub` this user is known by in `sector`, minting it if this is the
    /// first time — OIDC Core §8.1.
    ///
    /// Public subjects go through the same call with
    /// [`SectorIdentifier::public`], which is the sentinel `''` sector the
    /// schema's primary key is built around: both subject types are one row
    /// shape, and `sub` is unique per tenant either way.
    ///
    /// Written before it is read, and read in a second statement rather than in
    /// the same one. The insert cannot see a row another connection committed
    /// after this transaction's snapshot was taken, so `on conflict do nothing`
    /// would silently do nothing and a `returning` clause would hand back no
    /// row at all; a fresh read afterwards sees the winner of that race. Both
    /// callers get the same `sub`, which is the whole requirement.
    ///
    /// The salt is read from the store and never passed in; see the module
    /// documentation. That costs one extra query and one KEK operation per
    /// mint, which is the price of the caller being unable to name the wrong
    /// salt. A repeat mint pays it too — it is the same read either way, and
    /// the derivation has to happen before the insert can be attempted.
    ///
    /// The decrypted salt is not cached, and ADR-0008 (`ast-f12`) is why: this
    /// method has one production caller, consent completion, which writes the
    /// subject into the `Grant` that every later issuance reads — so the unwrap
    /// is once per authorization and not once per `id_token`. A cache would be
    /// a process-lifetime container of key material bought against an AES-GCM
    /// open on a path that renders a consent page. If a KMS adapter ever makes
    /// the unwrap a network call, the cache to build is a TTL-bounded one in
    /// the composition root, shaped like `CachedSigner`, rather than one here.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Invalid`] when the tenant has no pairwise salt —
    /// which is a refusal to mint, never a fallback to a default one, because a
    /// `sub` derived under an empty or improvised salt is both re-derivable by
    /// anybody who knows the algorithm and impossible to withdraw once issued.
    ///
    /// Returns [`DomainError::Conflict`] when the user does not exist, and —
    /// the case worth naming — when the derived `sub` is already held by
    /// somebody else in this tenant. Two users sharing an identifier is the one
    /// outcome this table must never reach, so the unique index refuses the
    /// write rather than the application noticing later. The same answer covers
    /// a `sub` held by somebody who no longer exists: see
    /// the private `refuse_a_retired_subject`.
    pub async fn subject(
        &self,
        user: UserId,
        sector: &SectorIdentifier,
    ) -> Result<SubjectId, DomainError> {
        let salt = salts::read(&self.pool, &self.tenant, self.kek.as_ref()).await?;
        let derived = salt.derive_subject(sector, user);
        self.refuse_a_retired_subject(user, sector, &derived)
            .await?;
        sqlx::query!(
            "insert into subject_identifiers (tenant_id, user_id, sector_identifier, subject)
             values ($1, $2, $3, $4)
             on conflict (tenant_id, user_id, sector_identifier) do nothing",
            self.tenant.as_str(),
            user.as_uuid(),
            sector.as_str(),
            derived.as_str()
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let stored: String = sqlx::query_scalar!(
            "select subject from subject_identifiers
             where tenant_id = $1 and user_id = $2 and sector_identifier = $3",
            self.tenant.as_str(),
            user.as_uuid(),
            sector.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?
        // The row was written a statement ago and nothing deletes one except a
        // cascade from the user; if it is gone, the user was deleted underneath
        // us and there is no subject to return.
        .ok_or(DomainError::NotFound)?;

        Ok(SubjectId::new(stored))
    }

    /// Refuses a derivation that landed on a `sub` this tenant has already
    /// retired — OIDC Core §8's "never reassigned" (`ast-2vk.12`).
    ///
    /// `subject_identifiers` cascades from `users`, so an account deletion
    /// frees the row that reserved the value; `retired_subject_identifiers` is
    /// what remembers it anyway. The database refuses the reservation too, in a
    /// trigger, and that is the guarantee. This check exists so that the
    /// refusal reaching a caller is a `Conflict` naming what happened rather
    /// than a constraint violation, and so that it is recorded: the derivation
    /// takes a 256-bit secret salt, a public sector and a random UUID, so
    /// reaching a retired value means either that a local account id was reused
    /// or that somebody has a SHA-256 collision. Both want an incident, not a
    /// log line.
    ///
    /// **Refused, never regenerated.** There is no second derivation to fall
    /// back on: §8.1 requires the pairwise calculation to be deterministic, and
    /// handing out a different `sub` for a user a relying party already knows
    /// is the reassignment §8 forbids, seen from the other side. A `sub` that
    /// cannot be minted fails one authorization; a `sub` issued twice cannot be
    /// taken back.
    ///
    /// The audit record is written through a sink built here rather than one
    /// held by this repository. That is deliberate and it is the narrow choice:
    /// this is the only path in the file that records anything, and taking a
    /// sink in the constructor would put one in every call site that builds a
    /// user repository — `TenantScope::users` included — for a branch that has
    /// never been taken in production.
    async fn refuse_a_retired_subject(
        &self,
        user: UserId,
        sector: &SectorIdentifier,
        derived: &SubjectId,
    ) -> Result<(), DomainError> {
        let retired: Option<i32> = sqlx::query_scalar!(
            "select 1 from retired_subject_identifiers
             where tenant_id = $1 and subject = $2",
            self.tenant.as_str(),
            derived.as_str()
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?
        .flatten();
        if retired.is_none() {
            return Ok(());
        }

        let event = AuditEvent::new(
            self.tenant.clone(),
            EventType::SUBJECT_COLLISION,
            Outcome::Failure,
            Actor::System,
            OffsetDateTime::now_utc(),
        )
        .subject(derived.as_str())
        .detail(
            Detail::new()
                .text("sector_identifier", sector.as_str())
                .text("user_id", user.as_uuid().to_string()),
        );
        if let Err(error) = PgAuditSink::new(self.pool.clone()).record(event).await {
            // The refusal stands either way: a collision nobody could record is
            // still a collision nobody may be handed an identifier through.
            tracing::error!(
                %error,
                tenant = %self.tenant,
                "could not record a retired subject identifier collision"
            );
        }

        Err(DomainError::Conflict(
            "the derived subject identifier was retired with a deleted account and is \
             never reassigned (OIDC Core §8)"
                .to_owned(),
        ))
    }

    /// Every sector this user has ever been identified in, with the `sub` each
    /// one sees, ordered by sector.
    ///
    /// What an account page needs in order to show a person which relying
    /// parties know them, and what `ast-uwv.5`'s grant management builds on.
    ///
    /// # Errors
    ///
    /// Returns a storage error.
    pub async fn subjects(
        &self,
        user: UserId,
    ) -> Result<Vec<(SectorIdentifier, SubjectId)>, DomainError> {
        let rows = sqlx::query!(
            "select sector_identifier, subject from subject_identifiers
             where tenant_id = $1 and user_id = $2
             order by sector_identifier",
            self.tenant.as_str(),
            user.as_uuid()
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        rows.into_iter()
            .map(|row| {
                let sector = SectorIdentifier::stored(&row.sector_identifier)
                    .map_err(|e| DomainError::invalid("sector_identifier", e.to_string()))?;
                Ok((sector, SubjectId::new(row.subject)))
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl asterius_domain::SubjectResolver for PgUserRepository {
    async fn subject(
        &self,
        user: UserId,
        sector: &SectorIdentifier,
    ) -> Result<SubjectId, DomainError> {
        Self::subject(self, user, sector).await
    }
}

#[async_trait::async_trait]
impl asterius_domain::UserDirectory for PgUserRepository {
    async fn by_id(&self, id: UserId) -> Result<Option<User>, DomainError> {
        Self::find(self, id).await
    }
}
