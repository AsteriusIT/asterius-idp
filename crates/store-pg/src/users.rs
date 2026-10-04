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
    ClaimSet, ClientId, DomainError, ScimProfileReplacement, ScimUserState, SectorIdentifier,
    SubjectId, TenantId, User, UserId, UserStatus,
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
#[derive(sqlx::FromRow)]
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

#[derive(sqlx::FromRow)]
struct ScimRow {
    user_id: Uuid,
    username: String,
    email: Option<String>,
    email_verified: bool,
    status: String,
    claims: serde_json::Value,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    scim_revision: i64,
    external_id: Option<String>,
}

impl ScimRow {
    fn into_state(self, tenant: &TenantId) -> Result<ScimUserState, DomainError> {
        let revision = self.scim_revision;
        let external_id = self.external_id;
        let user = Row {
            user_id: self.user_id,
            username: self.username,
            email: self.email,
            email_verified: self.email_verified,
            status: self.status,
            claims: self.claims,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
        .into_entity(tenant)?;
        Ok(ScimUserState {
            user,
            external_id,
            revision,
        })
    }
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
    /// Serialize lifecycle writes with final issuance before locking a user.
    /// The caller keeps this tenant lock through commit on the same connection.
    /// An inactive tenant remains writable for cleanup; absence is refused.
    pub(crate) async fn lifecycle_fence_on(
        connection: &mut sqlx::PgConnection,
        tenant: &TenantId,
    ) -> Result<(), DomainError> {
        let found: Option<String> = sqlx::query_scalar(
            "select tenant_id from tenants where tenant_id = $1 for no key update",
        )
        .bind(tenant.as_str())
        .fetch_optional(connection)
        .await
        .map_err(to_domain_error)?;
        found.ok_or(DomainError::NotFound).map(|_| ())
    }

    /// Conditionally replaces the approved SCIM profile and external ID.
    /// The revision predicate and both writes share one transaction.
    pub async fn scim_replace_profile(
        &self,
        replacement: &ScimProfileReplacement,
    ) -> Result<(ScimUserState, Vec<(String, String)>), DomainError> {
        if replacement.tenant != self.tenant || replacement.expected_revision < 1 {
            return Err(DomainError::invalid(
                "scim.profile",
                "invalid tenant or revision",
            ));
        }
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        Self::lifecycle_fence_on(&mut tx, &self.tenant).await?;
        let previous_status: Option<String> = sqlx::query_scalar(
            "select status from users where tenant_id = $1 and user_id = $2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(replacement.user.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        self.scim_write_identity(&mut tx, replacement).await?;
        let ended_sessions = if replacement.status == UserStatus::Disabled || replacement.delete {
            self.scim_revoke_credentials(&mut tx, replacement).await?
        } else {
            Vec::new()
        };
        if replacement.delete
            || (replacement.status == UserStatus::Disabled
                && previous_status.as_deref() != Some(UserStatus::Disabled.as_str()))
        {
            self.queue_provider_commands(
                &mut tx,
                replacement.user,
                if replacement.delete {
                    "delete"
                } else {
                    "invalidate"
                },
            )
            .await?;
        }
        let row: ScimRow = sqlx::query_as(
            "select u.user_id, u.username, u.email, u.email_verified, u.status,
                    u.claims, u.created_at, u.updated_at, u.scim_revision,
                    e.external_id
             from users u join scim_user_external_ids e
               on e.tenant_id = u.tenant_id and e.user_id = u.user_id
              and e.client_id = $3
             where u.tenant_id = $1 and u.user_id = $2",
        )
        .bind(self.tenant.as_str())
        .bind(replacement.user.as_uuid())
        .bind(replacement.client.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        crate::audit::append(
            &mut tx,
            AuditEvent::new(
                self.tenant.clone(),
                EventType::USER_SCIM_PROFILE_CHANGED,
                Outcome::Success,
                Actor::Client(replacement.client.clone()),
                OffsetDateTime::now_utc(),
            )
            .subject(replacement.user.to_string())
            .detail(
                Detail::new()
                    .label("operation", replacement.operation)
                    .flag("deprovisioned", replacement.delete)
                    .flag(
                        "active",
                        !replacement.delete && replacement.status == UserStatus::Active,
                    ),
            ),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        Ok((row.into_state(&self.tenant)?, ended_sessions))
    }

    /// Queue only clients that already received this user's OIDC subject.
    /// The durable reservation retains the exact public or pairwise `sub`
    /// issued to that RP even after the grant itself expires.
    async fn queue_provider_commands(
        &self,
        tx: &mut sqlx::PgTransaction<'_>,
        user: UserId,
        command: &str,
    ) -> Result<(), DomainError> {
        let recipients: Vec<(String, String)> = sqlx::query_as(
            "select p.client_id, p.subject
             from provider_command_subjects p join clients c
               on c.tenant_id = p.tenant_id and c.client_id = p.client_id
             where p.tenant_id = $1 and p.user_id = $2
               and c.command_endpoint is not null and c.status = 'active'",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .fetch_all(&mut **tx)
        .await
        .map_err(to_domain_error)?;
        for (client, subject) in recipients {
            let key = format!("{client}\u{1f}{subject}");
            crate::outbox::enqueue(
                tx,
                &self.tenant,
                &crate::outbox::NewOutboxEntry::new(
                    "provider_command.account",
                    &client,
                    serde_json::json!({"command": command, "subject": subject}),
                )
                .ordered_by(&key),
                OffsetDateTime::now_utc(),
            )
            .await?;
        }
        Ok(())
    }

    /// Disables a console-managed account and queues RP invalidation intents
    /// in the same transaction. Repeating a disable never queues a second set.
    pub async fn disable_with_provider_commands(&self, user: UserId) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        Self::lifecycle_fence_on(&mut tx, &self.tenant).await?;
        let previous: Option<String> = sqlx::query_scalar(
            "select status from users where tenant_id = $1 and user_id = $2 for update",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let Some(previous) = previous else {
            return Err(DomainError::NotFound);
        };
        if previous != UserStatus::Disabled.as_str() {
            sqlx::query(
                "update users set status = 'disabled' where tenant_id = $1 and user_id = $2",
            )
            .bind(self.tenant.as_str())
            .bind(user.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(to_domain_error)?;
            self.queue_provider_commands(&mut tx, user, "invalidate")
                .await?;
        }
        tx.commit().await.map_err(to_domain_error)
    }

    async fn scim_write_identity(
        &self,
        connection: &mut sqlx::PgConnection,
        replacement: &ScimProfileReplacement,
    ) -> Result<(), DomainError> {
        let tombstoned: bool = sqlx::query_scalar(
            "select exists(select 1 from scim_user_external_ids
             where tenant_id = $1 and client_id = $2 and user_id = $3
               and deleted_at is not null)",
        )
        .bind(self.tenant.as_str())
        .bind(replacement.client.as_str())
        .bind(replacement.user.as_uuid())
        .fetch_one(&mut *connection)
        .await
        .map_err(to_domain_error)?;
        if tombstoned {
            return Err(DomainError::NotFound);
        }
        // SCIM deactivation is narrower than clearing an administrator's lock:
        // keep Locked through disable/delete so a later active=true cannot bypass it.
        // A reviewed reserved-incarnation DELETE retains its identity tombstone but
        // releases personal email. Disable/archive and ordinary SCIM lifecycles
        // retain email; active-account uniqueness is never weakened.
        let updated = sqlx::query(
            "with retirement as (
               select $7::boolean and exists(
                 select 1 from scim_user_external_ids
                 where tenant_id=$1 and client_id=$8 and user_id=$2
                   and external_id=$9 and deleted_at is null
                   and scim_outbound_reserved_external(external_id,'user')
               ) as erase_email
             )
             update users set username = $4,
             email = case when retirement.erase_email then null else $5 end,
             status = case when status = 'locked' then 'locked' else $6 end,
             email_verified = case when retirement.erase_email or email is distinct from $5
                                   then false else email_verified end
             from retirement
             where tenant_id = $1 and user_id = $2 and scim_revision = $3
               and (status <> 'locked' or $6 <> 'active')",
        )
        .bind(self.tenant.as_str())
        .bind(replacement.user.as_uuid())
        .bind(replacement.expected_revision)
        .bind(&replacement.username)
        .bind(&replacement.email)
        .bind(if replacement.delete {
            UserStatus::Disabled.as_str()
        } else {
            replacement.status.as_str()
        })
        .bind(replacement.delete)
        .bind(replacement.client.as_str())
        .bind(&replacement.external_id)
        .execute(&mut *connection)
        .await
        .map_err(to_domain_error)?
        .rows_affected();
        if updated == 0 {
            let exists: bool = sqlx::query_scalar(
                "select exists(select 1 from users where tenant_id = $1 and user_id = $2)",
            )
            .bind(self.tenant.as_str())
            .bind(replacement.user.as_uuid())
            .fetch_one(&mut *connection)
            .await
            .map_err(to_domain_error)?;
            return Err(if exists {
                DomainError::Conflict("SCIM revision changed".to_owned())
            } else {
                DomainError::NotFound
            });
        }
        sqlx::query(
            "insert into scim_user_external_ids
             (tenant_id, client_id, user_id, external_id, deleted_at)
             values ($1, $2, $3, $4, case when $5 then $6 else null end)
             on conflict (tenant_id, client_id, user_id)
             do update set external_id = excluded.external_id,
                           deleted_at = excluded.deleted_at",
        )
        .bind(self.tenant.as_str())
        .bind(replacement.client.as_str())
        .bind(replacement.user.as_uuid())
        .bind(&replacement.external_id)
        .bind(replacement.delete)
        .bind(OffsetDateTime::now_utc())
        .execute(&mut *connection)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    async fn scim_revoke_credentials(
        &self,
        connection: &mut sqlx::PgConnection,
        replacement: &ScimProfileReplacement,
    ) -> Result<Vec<(String, String)>, DomainError> {
        let now = OffsetDateTime::now_utc();
        let ended_sessions: Vec<(String, String)> = sqlx::query_as(
            "select session_id, public_sid from sessions
             where tenant_id = $1 and user_id = $2 and revoked_at is null
               and expires_at > $3 and idle_expires_at > $3",
        )
        .bind(self.tenant.as_str())
        .bind(replacement.user.as_uuid())
        .bind(now)
        .fetch_all(&mut *connection)
        .await
        .map_err(to_domain_error)?;
        sqlx::query(
            "update sessions set revoked_at = $3, revocation_reason = $4
             where tenant_id = $1 and user_id = $2 and revoked_at is null",
        )
        .bind(self.tenant.as_str())
        .bind(replacement.user.as_uuid())
        .bind(now)
        .bind(asterius_domain::SessionRevocation::AccountClosed.as_str())
        .execute(&mut *connection)
        .await
        .map_err(to_domain_error)?;
        let grants: Vec<Uuid> = sqlx::query_scalar(
            "update grants set revoked_at = $3, revocation_reason = $4
             where tenant_id = $1 and user_id = $2 and revoked_at is null
             returning grant_id",
        )
        .bind(self.tenant.as_str())
        .bind(replacement.user.as_uuid())
        .bind(now)
        .bind(asterius_domain::RevocationReason::AdminRevoked.as_str())
        .fetch_all(&mut *connection)
        .await
        .map_err(to_domain_error)?;
        sqlx::query(
            "update refresh_tokens set revoked_at = $3
             where tenant_id = $1 and revoked_at is null
               and grant_id in (select grant_id from grants
                                where tenant_id = $1 and user_id = $2)",
        )
        .bind(self.tenant.as_str())
        .bind(replacement.user.as_uuid())
        .bind(now)
        .execute(&mut *connection)
        .await
        .map_err(to_domain_error)?;
        for grant in &grants {
            let grant_id = grant.to_string();
            crate::cutoffs::withdraw(
                &mut *connection,
                &self.tenant,
                crate::cutoffs::Principal::Grant(&grant_id),
                now,
            )
            .await?;
        }
        if replacement.delete {
            self.scim_clear_memberships(connection, replacement, now)
                .await?;
        }
        Ok(ended_sessions)
    }

    async fn scim_clear_memberships(
        &self,
        connection: &mut sqlx::PgConnection,
        replacement: &ScimProfileReplacement,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        // A deleted provisioning resource must not retain managed
        // group authority if an operator later reactivates the same
        // canonical account. Lock groups before membership rows, the
        // same order a group replacement uses, then advance ETags.
        let groups: Vec<Uuid> = sqlx::query_scalar(
            "select group_id from managed_groups
             where tenant_id = $1 and group_id in (
                 select group_id from group_memberships
                 where tenant_id = $1 and user_id = $2)
             order by group_id for update",
        )
        .bind(self.tenant.as_str())
        .bind(replacement.user.as_uuid())
        .fetch_all(&mut *connection)
        .await
        .map_err(to_domain_error)?;
        sqlx::query(
            "delete from group_memberships
             where tenant_id = $1 and user_id = $2",
        )
        .bind(self.tenant.as_str())
        .bind(replacement.user.as_uuid())
        .execute(&mut *connection)
        .await
        .map_err(to_domain_error)?;
        if !groups.is_empty() {
            sqlx::query(
                "update managed_groups set revision = revision + 1, updated_at = $3
                 where tenant_id = $1 and group_id = any($2::uuid[])",
            )
            .bind(self.tenant.as_str())
            .bind(&groups)
            .bind(now)
            .execute(&mut *connection)
            .await
            .map_err(to_domain_error)?;
        }
        Ok(())
    }

    /// Bounded SCIM page with version and per-client external identifiers.
    pub async fn scim_page(
        &self,
        client: &ClientId,
        offset: u32,
        limit: u16,
    ) -> Result<(u64, Vec<ScimUserState>), DomainError> {
        if offset > 10_000 || !(1..=200).contains(&limit) {
            return Err(DomainError::invalid("page", "outside SCIM page bounds"));
        }
        let total: i64 = sqlx::query_scalar(
            "select count(*) from users u left join scim_user_external_ids e
               on e.tenant_id = u.tenant_id and e.user_id = u.user_id and e.client_id = $2
             where u.tenant_id = $1 and e.deleted_at is null",
        )
        .bind(self.tenant.as_str())
        .bind(client.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let rows: Vec<ScimRow> = sqlx::query_as(
            "select u.user_id, u.username, u.email, u.email_verified, u.status,
                    u.claims, u.created_at, u.updated_at, u.scim_revision,
                    e.external_id
             from users u left join scim_user_external_ids e
               on e.tenant_id = u.tenant_id and e.user_id = u.user_id
              and e.client_id = $2
             where u.tenant_id = $1 and e.deleted_at is null
             order by u.username, u.user_id offset $3 limit $4",
        )
        .bind(self.tenant.as_str())
        .bind(client.as_str())
        .bind(i64::from(offset))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let states = rows
            .into_iter()
            .map(|row| row.into_state(&self.tenant))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((u64::try_from(total).unwrap_or(0), states))
    }

    /// Reads a canonical account with this client's SCIM metadata.
    pub async fn scim_find(
        &self,
        client: &ClientId,
        id: UserId,
    ) -> Result<Option<ScimUserState>, DomainError> {
        let row: Option<ScimRow> = sqlx::query_as(
            "select u.user_id, u.username, u.email, u.email_verified, u.status,
                    u.claims, u.created_at, u.updated_at, u.scim_revision,
                    e.external_id
             from users u left join scim_user_external_ids e
               on e.tenant_id = u.tenant_id and e.user_id = u.user_id
              and e.client_id = $3
             where u.tenant_id = $1 and u.user_id = $2
               and e.deleted_at is null",
        )
        .bind(self.tenant.as_str())
        .bind(id.as_uuid())
        .bind(client.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        row.map(|row| row.into_state(&self.tenant)).transpose()
    }

    /// Creates a credential-free account and its client-owned external ID in
    /// one transaction. A uniqueness conflict rolls back both records.
    pub async fn scim_create(
        &self,
        client: &ClientId,
        user: &User,
        external_id: Option<&str>,
    ) -> Result<ScimUserState, DomainError> {
        if user.tenant != self.tenant {
            return Err(DomainError::invalid("tenant_id", "does not match scope"));
        }
        let claims = serde_json::to_value(&user.claims)
            .map_err(|error| DomainError::invalid("claims", error.to_string()))?;
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        sqlx::query(
            "insert into users (tenant_id, user_id, username, email,
                                email_verified, status, claims)
             values ($1, $2, $3, $4, false, $5, $6)",
        )
        .bind(self.tenant.as_str())
        .bind(user.id.as_uuid())
        .bind(&user.username)
        .bind(&user.email)
        .bind(user.status.as_str())
        .bind(claims)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        sqlx::query(
            "insert into scim_user_external_ids
             (tenant_id, client_id, user_id, external_id)
             values ($1, $2, $3, $4)",
        )
        .bind(self.tenant.as_str())
        .bind(client.as_str())
        .bind(user.id.as_uuid())
        .bind(external_id)
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        let row: ScimRow = sqlx::query_as(
            "select u.user_id, u.username, u.email, u.email_verified, u.status,
                    u.claims, u.created_at, u.updated_at, u.scim_revision,
                    e.external_id
             from users u join scim_user_external_ids e
               on e.tenant_id = u.tenant_id and e.user_id = u.user_id
              and e.client_id = $3
             where u.tenant_id = $1 and u.user_id = $2",
        )
        .bind(self.tenant.as_str())
        .bind(user.id.as_uuid())
        .bind(client.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        crate::audit::append(
            &mut tx,
            AuditEvent::new(
                self.tenant.clone(),
                EventType::USER_CREATED,
                Outcome::Success,
                Actor::Client(client.clone()),
                OffsetDateTime::now_utc(),
            )
            .subject(user.id.to_string())
            .detail(
                Detail::new()
                    .label("operation", "scim.users.create")
                    .flag("active", user.can_authenticate()),
            ),
        )
        .await?;
        tx.commit().await.map_err(to_domain_error)?;
        row.into_state(&self.tenant)
    }

    /// One bounded SCIM offset page and the tenant's total account count.
    /// Offset pagination is capped at 10,000 so a remote client cannot force
    /// an arbitrarily deep index walk with one request.
    pub async fn page(&self, offset: u32, limit: u16) -> Result<(u64, Vec<User>), DomainError> {
        if offset > 10_000 || !(1..=200).contains(&limit) {
            return Err(DomainError::invalid("page", "outside SCIM page bounds"));
        }
        let total: i64 = sqlx::query_scalar("select count(*) from users where tenant_id = $1")
            .bind(self.tenant.as_str())
            .fetch_one(&self.pool)
            .await
            .map_err(to_domain_error)?;
        let rows: Vec<Row> = sqlx::query_as(
            "select user_id, username, email, email_verified, status, claims,
                    created_at, updated_at from users where tenant_id = $1
             order by username, user_id offset $2 limit $3",
        )
        .bind(self.tenant.as_str())
        .bind(i64::from(offset))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let users = rows
            .into_iter()
            .map(|row| row.into_entity(&self.tenant))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((u64::try_from(total).unwrap_or(0), users))
    }

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

    /// One page of this tenant's accounts, ordered by username (`ast-f7m.6`).
    ///
    /// The filtering and the cut are the *database's*, not a caller's: a
    /// tenant may hold millions of accounts, and a listing that read them all
    /// and filtered in memory would be a way to make this server materialise a
    /// directory on request. `after` is the username the previous page ended
    /// on, which turns paging into a range scan over the unique
    /// `(tenant_id, username)` index instead of an `OFFSET` that walks and
    /// discards.
    ///
    /// `term` matches the username or the address, case-insensitively, and an
    /// empty one matches everything. `ilike` with the term interpolated as a
    /// *parameter*: the `%` wrappers are added by the query, so a term
    /// carrying `%` or `_` widens its own search and nothing else — it is a
    /// bound value and never SQL.
    ///
    /// # Errors
    ///
    /// As [`Self::find`].
    pub async fn search_ordered(
        &self,
        term: &str,
        after: Option<&str>,
        limit: i64,
        descending: bool,
    ) -> Result<Vec<User>, DomainError> {
        if !descending {
            return self.search(term, after, limit).await;
        }
        let pattern = format!("%{term}%");
        sqlx::query_as::<_, Row>(
            "select user_id, username, email, email_verified, status, claims, created_at, updated_at
             from users where tenant_id = $1
             and ($2 = '' or username ilike $3 or email ilike $3)
             and ($4::text is null or username < $4) order by username desc limit $5"
        ).bind(self.tenant.as_str()).bind(term).bind(pattern).bind(after).bind(limit)
            .fetch_all(&self.pool).await.map_err(to_domain_error)?.into_iter()
            .map(|row| row.into_entity(&self.tenant)).collect()
    }

    /// Restricts account status in PostgreSQL before the cursor page is cut.
    pub async fn search_filtered(
        &self,
        term: &str,
        after: Option<&str>,
        limit: i64,
        status: Option<UserStatus>,
        descending: bool,
    ) -> Result<Vec<User>, DomainError> {
        let pattern = format!("%{term}%");
        let statement = if descending {
            "select user_id, username, email, email_verified, status, claims, created_at, updated_at
             from users where tenant_id = $1
             and ($2 = '' or username ilike $3 or email ilike $3)
             and ($4::text is null or username < $4)
             and ($5::text is null or status = $5)
             order by username desc limit $6"
        } else {
            "select user_id, username, email, email_verified, status, claims, created_at, updated_at
             from users where tenant_id = $1
             and ($2 = '' or username ilike $3 or email ilike $3)
             and ($4::text is null or username > $4)
             and ($5::text is null or status = $5)
             order by username limit $6"
        };
        sqlx::query_as::<_, Row>(statement)
            .bind(self.tenant.as_str())
            .bind(term)
            .bind(pattern)
            .bind(after)
            .bind(status.map(UserStatus::as_str))
            .bind(limit)
            .fetch_all(&self.pool)
            .await
            .map_err(to_domain_error)?
            .into_iter()
            .map(|row| row.into_entity(&self.tenant))
            .collect()
    }

    pub async fn search(
        &self,
        term: &str,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<User>, DomainError> {
        let pattern = format!("%{term}%");
        sqlx::query_as!(
            Row,
            "select user_id, username, email, email_verified, status, claims,
                    created_at, updated_at
             from users
             where tenant_id = $1
               and ($2 = '' or username ilike $3 or email ilike $3)
               and ($4::text is null or username > $4)
             order by username
             limit $5",
            self.tenant.as_str(),
            term,
            pattern,
            after,
            limit
        )
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?
        .into_iter()
        .map(|row| row.into_entity(&self.tenant))
        .collect()
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

    /// Finds one user by the address on their account.
    ///
    /// Case-insensitive on the whole address, against the `users_by_email`
    /// unique index — which is `lower(email)`, so this query uses it rather
    /// than scanning. The domain part is case-insensitive by RFC 5321 §2.4 and
    /// the local part is technically not; folding both anyway is the choice
    /// the index already made, and it is the one that matches what a person
    /// typing their own address expects. It cannot merge two accounts,
    /// because the index forbids two rows that fold together.
    ///
    /// Its caller is account recovery, and the shape matters there: this must
    /// answer the same way for an address with no account as for one with a
    /// disabled account, which it does, because it says nothing about either —
    /// the *caller* is what must not turn `None` into a different page.
    ///
    /// # Errors
    ///
    /// As [`Self::find`].
    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, DomainError> {
        let row = sqlx::query_as!(
            Row,
            "select user_id, username, email, email_verified, status, claims,
                    created_at, updated_at
             from users
             where tenant_id = $1 and lower(email) = lower($2)",
            self.tenant.as_str(),
            email
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
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        Self::lifecycle_fence_on(&mut tx, &self.tenant).await?;
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
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        tx.commit().await.map_err(to_domain_error)
    }

    /// Turns a proved address into OIDC Core §5.1's `email_verified`
    /// (`ast-vae`).
    ///
    /// One statement, and every predicate in it is load-bearing:
    ///
    /// * `email = $3` — the address the *token* was mailed to, not the one the
    ///   handler happened to read a moment ago. The comparison is in SQL so
    ///   that an address changed between the read and this write loses the
    ///   race rather than winning it: without it, the sequence "ask for a link
    ///   at a mailbox you own, change the address, follow the link" would set
    ///   the flag on a mailbox nobody proved. The handler checks the same thing
    ///   with [`asterius_domain::VerifiedAddress::still_matches`]; this is the
    ///   half that is atomic.
    /// * `email_verified = false` — so a repeated confirmation is a no-op that
    ///   reports `false` rather than a second write and a second audit event.
    ///
    /// Case-insensitive on the whole address for the reason
    /// `still_matches` gives: both sides were recorded by this server for this
    /// account, so a difference in case is somebody retyping their own
    /// address, and a different mailbox differs by more than case.
    ///
    /// Returns whether a row moved — `false` for an account that has since
    /// changed its address, one that was already confirmed, and one that no
    /// longer exists. The caller must not tell the three apart in anything a
    /// browser sees.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the update fails.
    pub async fn mark_email_verified(
        &self,
        id: UserId,
        address: &str,
    ) -> Result<bool, DomainError> {
        let result = sqlx::query!(
            "update users
                set email_verified = true
              where tenant_id = $1
                and user_id = $2
                and lower(email) = lower($3)
                and email_verified = false",
            self.tenant.as_str(),
            id.as_uuid(),
            address,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(result.rows_affected() > 0)
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
        let mut tx = self.pool.begin().await.map_err(to_domain_error)?;
        Self::lifecycle_fence_on(&mut tx, &self.tenant).await?;
        let result = sqlx::query!(
            "delete from users where tenant_id = $1 and user_id = $2",
            self.tenant.as_str(),
            id.as_uuid()
        )
        .execute(&mut *tx)
        .await
        .map_err(to_domain_error)?;
        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound);
        }
        tx.commit().await.map_err(to_domain_error)
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

    /// Resolves a subject while an independent lifecycle transaction holds a
    /// lock on the user row. It cannot reserve a new identifier here: an insert
    /// would need a foreign-key KEY SHARE lock and deadlock behind that row.
    /// The tenant salt is immutable, so a first-use derivation is identical
    /// to the identifier a later issuance will reserve.
    pub async fn subject_for_notification(
        &self,
        user: UserId,
        sector: &SectorIdentifier,
    ) -> Result<SubjectId, DomainError> {
        let stored: Option<String> = sqlx::query_scalar(
            "select subject from subject_identifiers
             where tenant_id = $1 and user_id = $2 and sector_identifier = $3",
        )
        .bind(self.tenant.as_str())
        .bind(user.as_uuid())
        .bind(sector.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        if let Some(stored) = stored {
            return Ok(SubjectId::new(stored));
        }
        let salt = salts::read(&self.pool, &self.tenant, self.kek.as_ref()).await?;
        let derived = salt.derive_subject(sector, user);
        self.refuse_a_retired_subject(user, sector, &derived)
            .await?;
        Ok(derived)
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

#[cfg(test)]
mod scim_security_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "slow PostgreSQL reserved SCIM retirement regression; CI only"]
    async fn reserved_delete_releases_email_but_ordinary_delete_retains_it() {
        let url = std::env::var("DATABASE_URL").expect("CI database URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("test database");
        crate::MIGRATOR.run(&pool).await.expect("migrated fixture");
        let tenant = TenantId::parse(&format!("scim-retire-{}", Uuid::new_v4().simple()))
            .expect("fixture tenant");
        let client = ClientId::new("retirement-fixture".to_owned());
        sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values($1,$2,'Retirement fixture','https://api.example/')")
            .bind(tenant.as_str()).bind(format!("https://id.example/t/{}",tenant.as_str()))
            .execute(&pool).await.expect("fixture tenant");
        sqlx::query("insert into clients(tenant_id,client_id,redirect_uris) values($1,$2,'{}')")
            .bind(tenant.as_str())
            .bind(client.as_str())
            .execute(&pool)
            .await
            .expect("fixture client");
        let repository = PgUserRepository {
            pool: pool.clone(),
            tenant: tenant.clone(),
            kek: Arc::new(asterius_jose::LocalKek::from_bytes(&[0x58; 32]).expect("fixture KEK")),
        };
        let (_, reserved) = asterius_domain::outbound_scim::resource_identity(
            &tenant,
            Uuid::new_v4(),
            asterius_domain::outbound_scim::ResourceKind::User,
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let malformed_source = reserved.replacen(tenant.as_str(), "INVALID", 1);
        for (name, external, erase) in [
            ("reserved", reserved.as_str(), true),
            ("ordinary", "ordinary-owned", false),
            ("malformed", malformed_source.as_str(), false),
        ] {
            let user = UserId::generate();
            let email = format!("{name}@example.test");
            sqlx::query("insert into users(tenant_id,user_id,username,email,email_verified,status) values($1,$2,$3,$4,true,'locked')")
                .bind(tenant.as_str()).bind(user.as_uuid()).bind(name).bind(&email)
                .execute(&pool).await.expect("locked owned user");
            sqlx::query("insert into scim_user_external_ids(tenant_id,client_id,user_id,external_id) values($1,$2,$3,$4)")
                .bind(tenant.as_str()).bind(client.as_str()).bind(user.as_uuid()).bind(external)
                .execute(&pool).await.expect("SCIM ownership");
            let held = repository
                .scim_find(&client, user)
                .await
                .expect("read user")
                .expect("owned user");
            let mut edit = ScimProfileReplacement {
                operation: "patch",
                tenant: tenant.clone(),
                client: client.clone(),
                user,
                expected_revision: held.revision,
                username: name.to_owned(),
                email: Some(email.clone()),
                external_id: Some(external.to_owned()),
                status: UserStatus::Disabled,
                delete: false,
            };
            let (disabled, _) = repository
                .scim_replace_profile(&edit)
                .await
                .expect("disable");
            assert_eq!(disabled.user.email.as_deref(), Some(email.as_str()));
            edit.expected_revision = disabled.revision;
            edit.delete = true;
            let (deleted, _) = repository
                .scim_replace_profile(&edit)
                .await
                .expect("delete");
            assert_eq!(deleted.user.status, UserStatus::Locked);
            assert_eq!(deleted.user.email.is_none(), erase);
            assert_eq!(deleted.user.email_verified, !erase);
            assert_eq!(deleted.external_id.as_deref(), Some(external));
            let retained: bool = sqlx::query_scalar("select deleted_at is not null from scim_user_external_ids where tenant_id=$1 and client_id=$2 and user_id=$3")
                .bind(tenant.as_str()).bind(client.as_str()).bind(user.as_uuid())
                .fetch_one(&pool).await.expect("retained identity");
            assert!(retained);
            assert_retirement_key(&pool, &tenant, &client, user, erase).await;
            if erase {
                sqlx::query("insert into users(tenant_id,user_id,username,email) values($1,$2,'fresh-generation',$3)")
                    .bind(tenant.as_str()).bind(Uuid::new_v4()).bind(&email)
                    .execute(&pool).await.expect("fresh generation may use same email");
            }
        }
        sqlx::query("delete from tenants where tenant_id=$1")
            .bind(tenant.as_str())
            .execute(&pool)
            .await
            .expect("fixture cleanup");
    }

    async fn assert_retirement_key(
        pool: &PgPool,
        tenant: &TenantId,
        client: &ClientId,
        user: UserId,
        expected: bool,
    ) {
        let present: bool = sqlx::query_scalar(
            "select exists(select 1 from scim_outbound_incarnation_tombstones
             where tenant_id=$1 and client_id=$2 and kind='user' and target_id=$3)",
        )
        .bind(tenant.as_str())
        .bind(client.as_str())
        .bind(user.as_uuid())
        .fetch_one(pool)
        .await
        .expect("read reserved retirement key");
        assert_eq!(present, expected);
    }

    #[tokio::test]
    #[ignore = "slow PostgreSQL SCIM security-lock regression; CI only"]
    // One persisted lifecycle proves disable, reactivation refusal and delete retain the same lock.
    #[allow(clippy::too_many_lines)]
    async fn scim_disable_then_reactivate_never_clears_a_security_lock() {
        let url = std::env::var("DATABASE_URL").expect("CI database URL");
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .expect("test database");
        crate::MIGRATOR.run(&pool).await.expect("migrated fixture");
        let tenant = TenantId::parse(&format!("scim-lock-{}", Uuid::new_v4().simple()))
            .expect("fixture tenant");
        let client = ClientId::new("security-lock-fixture".to_owned());
        let user = UserId::generate();
        sqlx::query("insert into tenants(tenant_id,issuer,display_name,default_resource) values($1,$2,'Security fixture','https://api.example/')")
            .bind(tenant.as_str()).bind(format!("https://id.example/t/{}",tenant.as_str()))
            .execute(&pool).await.expect("fixture tenant");
        sqlx::query("insert into clients(tenant_id,client_id,redirect_uris) values($1,$2,'{}')")
            .bind(tenant.as_str())
            .bind(client.as_str())
            .execute(&pool)
            .await
            .expect("fixture client");
        sqlx::query("insert into users(tenant_id,user_id,username,status) values($1,$2,'security-fixture','locked')")
            .bind(tenant.as_str()).bind(user.as_uuid()).execute(&pool).await.expect("locked user");
        sqlx::query("insert into scim_user_external_ids(tenant_id,client_id,user_id,external_id) values($1,$2,$3,'fixture-owned')")
            .bind(tenant.as_str()).bind(client.as_str()).bind(user.as_uuid())
            .execute(&pool).await.expect("SCIM ownership");
        let repository = PgUserRepository {
            pool: pool.clone(),
            tenant: tenant.clone(),
            kek: Arc::new(asterius_jose::LocalKek::from_bytes(&[0x57; 32]).expect("fixture KEK")),
        };
        let before = repository
            .scim_find(&client, user)
            .await
            .expect("read user")
            .expect("owned user");
        let mut edit = ScimProfileReplacement {
            operation: "patch",
            tenant: tenant.clone(),
            client: client.clone(),
            user,
            expected_revision: before.revision,
            username: before.user.username.clone(),
            email: None,
            external_id: Some("fixture-owned".to_owned()),
            status: UserStatus::Disabled,
            delete: false,
        };
        let (disabled, _) = repository
            .scim_replace_profile(&edit)
            .await
            .expect("SCIM disable");
        assert_eq!(disabled.user.status, UserStatus::Locked);
        assert!(!disabled.user.can_authenticate());
        assert!(disabled.revision > before.revision);
        edit.expected_revision = disabled.revision;
        edit.status = UserStatus::Active;
        assert!(matches!(
            repository.scim_replace_profile(&edit).await,
            Err(DomainError::Conflict(_))
        ));
        let after = repository
            .scim_find(&client, user)
            .await
            .expect("read after refusal")
            .expect("owned user");
        assert_eq!(after.user.status, UserStatus::Locked);
        assert_eq!(after.revision, disabled.revision);
        edit.status = UserStatus::Disabled;
        edit.delete = true;
        repository
            .scim_replace_profile(&edit)
            .await
            .expect("SCIM delete");
        let stored: String =
            sqlx::query_scalar("select status from users where tenant_id=$1 and user_id=$2")
                .bind(tenant.as_str())
                .bind(user.as_uuid())
                .fetch_one(&pool)
                .await
                .expect("retained locked account");
        assert_eq!(stored, "locked");
        assert!(
            repository
                .scim_find(&client, user)
                .await
                .expect("deleted read")
                .is_none()
        );
        sqlx::query("delete from tenants where tenant_id=$1")
            .bind(tenant.as_str())
            .execute(&pool)
            .await
            .expect("own fixture cleanup");
        pool.close().await;
    }
}

#[cfg(test)]
#[path = "users_lifecycle_tests.rs"]
mod lifecycle_tests;
