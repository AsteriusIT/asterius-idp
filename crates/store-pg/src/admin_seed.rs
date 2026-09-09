//! Seeding the deployment admin.
//!
//! `docker compose up` has to give a deployment somebody can administer, and
//! ADR-0010 says what that somebody is: a user of the reserved tenant, holding
//! a deployment-scoped role. This module writes exactly that, idempotently, at
//! startup — the same way `[[tenant]]` is re-asserted on every boot.
//!
//! # What it asserts, and what it leaves alone
//!
//! Missing pieces are created: the reserved tenant, the user, a password
//! credential, the role. The password is re-written only when the configured
//! one does not already verify, so a restart does not churn the hash — and
//! *that verification is the point*: it runs through
//! [`PgPasswordVerifier`], the same code the login flow uses, so
//! "the seeded admin can authenticate" is proven at boot rather than asserted
//! in a comment.
//!
//! What it does not do is fight the operator. A user or credential that has
//! been disabled is not silently re-enabled — an admin account disabled during
//! an incident coming back at the next restart is the kind of helpfulness
//! nobody wants. [`Seeded::can_authenticate`] reports it instead, and the
//! caller decides; the binary refuses to start.
//!
//! # Where the password comes from
//!
//! Not from here. [`DeploymentAdmin::password`] is a [`Secret`], read from a
//! file or an environment variable named in the configuration — the same shape
//! as the key-encryption key, and for the same reason: a credential baked into
//! an image or a compose file is a credential every copy of that image shares.
//! It is checked against the same policy a user's password is
//! ([`AcceptedPassword`], NIST SP 800-63B §5.1.1.2) before it is hashed.

use crate::audit::PgAuditSink;
use crate::error::to_domain_error;
use crate::key_store::TenantKeyStore;
use crate::passwords::PgPasswordVerifier;
use crate::provisioning::ProvisionedTenants;
use crate::roles::PgRoleRepository;
use crate::tenants::PgTenantRepository;
use crate::users::PgUserRepository;
use asterius_domain::ports::{CredentialVerifier as _, SystemClock, TenantRepository as _};
use asterius_domain::{
    AcceptedPassword, Argon2Parameters, ClaimSet, DomainError, Issuer, Role, Secret, Tenant,
    TenantId, TenantStatus, User, UserId, UserStatus,
};
use asterius_jose::Kek;
use sqlx::postgres::PgPool;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

/// The display name the reserved tenant is created with.
///
/// Only a label, and only on creation: an operator who renames it keeps the
/// new name across restarts.
const RESERVED_DISPLAY_NAME: &str = "Deployment administration";

/// The label on the seeded password credential, so an operator reading
/// `credentials` can tell where the row came from.
const SEEDED_CREDENTIAL_LABEL: &str = "seeded deployment admin";

/// The deployment admin a configuration asks for.
#[derive(Debug)]
pub struct DeploymentAdmin {
    /// The reserved tenant this admin lives in.
    pub tenant: TenantId,
    /// That tenant's issuer. A reserved tenant is a real tenant: it has an
    /// issuer, it is served by the same code, and its login surface is the
    /// ordinary one (ADR-0010).
    pub issuer: Issuer,
    /// The login identifier, unique within the reserved tenant.
    pub username: String,
    /// The initial password, from a file or an environment variable.
    pub password: Secret<String>,
}

/// What seeding found or made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seeded {
    /// The reserved tenant.
    pub tenant: TenantId,
    /// The admin's account identifier.
    pub user: UserId,
    /// Whether the account was created by this pass rather than already there.
    pub created: bool,
    /// Whether the configured password authenticates the account, checked
    /// through the ordinary verifier after everything else was written.
    ///
    /// False means the account or its credential is disabled: the row exists
    /// and the password matches it, but a login would be refused. Seeding does
    /// not undo that, so the caller has to decide what a deployment whose
    /// declared admin cannot sign in is worth.
    pub can_authenticate: bool,
}

/// Writes the deployment admin the configuration declares.
pub struct PgAdminSeed {
    pool: PgPool,
    kek: Arc<dyn Kek>,
    argon2: Argon2Parameters,
}

impl std::fmt::Debug for PgAdminSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgAdminSeed")
            .field("kek", &self.kek.id())
            .field("argon2", &self.argon2)
            .finish_non_exhaustive()
    }
}

impl PgAdminSeed {
    /// Builds a seeder.
    ///
    /// `kek` seals the reserved tenant's pairwise salt, which is written with
    /// the tenant; `argon2` is the cost the password is hashed at, the same
    /// parameters every other password in the deployment uses.
    #[must_use]
    pub const fn new(pool: PgPool, kek: Arc<dyn Kek>, argon2: Argon2Parameters) -> Self {
        Self { pool, kek, argon2 }
    }

    /// Creates or re-asserts the deployment admin, then checks it can sign in.
    ///
    /// Idempotent: running it on every boot is the intended use.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] if the configured password fails policy,
    /// [`DomainError::Conflict`] if another tenant is already the reserved one
    /// or the role is refused by the schema, and a storage error otherwise.
    pub async fn ensure(&self, admin: &DeploymentAdmin) -> Result<Seeded, DomainError> {
        // Policy before anything is written. A password the login form would
        // refuse must not become the one credential that administers the
        // deployment. The deny-list argument is a closure the breach-check port
        // (`ast-2vk.10`) fills in; until then nothing is denied by name.
        let password = AcceptedPassword::accept(admin.password.expose(), |_| false)
            .map_err(|e| DomainError::invalid("admin.password", e.to_string()))?;

        self.reserve_tenant(admin).await?;
        let (user, created) = self.ensure_user(admin).await?;
        self.ensure_password(&admin.tenant, user, password.expose())
            .await?;

        PgRoleRepository::new(self.pool.clone(), admin.tenant.clone())
            .grant(user, Role::DeploymentAdmin)
            .await?;

        // The proof, through the verifier the login flow uses rather than
        // through a second implementation that could agree with the seed and
        // disagree with production.
        let verifier =
            PgPasswordVerifier::new(self.pool.clone(), admin.tenant.clone(), self.argon2)?;
        let authenticated = verifier
            .verify(&admin.username, Secret::new(password.expose().to_owned()))
            .await?;

        Ok(Seeded {
            tenant: admin.tenant.clone(),
            user,
            created,
            can_authenticate: authenticated == Some(*user.as_uuid()),
        })
    }

    /// Creates the reserved tenant if it is absent, and marks it reserved.
    ///
    /// The mark is a separate statement from the upsert because
    /// [`TenantRepository::upsert`] writes an ordinary tenant and nothing here
    /// wants `is_reserved` reachable from the general tenant path: the admin
    /// API creating a tenant must not be able to reserve one.
    ///
    /// Written through [`ProvisionedTenants`], so the reserved tenant holds a
    /// signing key of every advertised algorithm by the time this returns. It
    /// used to hold them only because `main` happened to name it in the
    /// startup loop, one step after this one — a guarantee that depended on
    /// the order of two functions in the composition root, which is the kind
    /// that survives until the first refactor. The reserved tenant is the one
    /// whose login page a deployment admin uses, and a login that mints no
    /// session because the tenant cannot sign is a deployment nobody can
    /// administer.
    ///
    /// The key store is built here rather than injected because there is one
    /// audit sink for a PostgreSQL deployment and it is this pool: a
    /// constructor argument would let a caller wire a seed that creates keys
    /// and records nothing.
    ///
    /// [`TenantRepository::upsert`]: asterius_domain::ports::TenantRepository::upsert
    async fn reserve_tenant(&self, admin: &DeploymentAdmin) -> Result<(), DomainError> {
        let tenants = ProvisionedTenants::new(
            PgTenantRepository::new(self.pool.clone(), Arc::clone(&self.kek)),
            TenantKeyStore::new(
                self.pool.clone(),
                Arc::clone(&self.kek),
                Arc::new(PgAuditSink::new(self.pool.clone())),
            ),
            Arc::new(SystemClock),
        );
        let existing = tenants.find_by_id(&admin.tenant).await?;

        let now = OffsetDateTime::now_utc();
        tenants
            .upsert(&Tenant {
                id: admin.tenant.clone(),
                issuer: admin.issuer.clone(),
                custom_host: existing.as_ref().and_then(|t| t.custom_host.clone()),
                display_name: existing.as_ref().map_or_else(
                    || RESERVED_DISPLAY_NAME.to_owned(),
                    |t| t.display_name.clone(),
                ),
                // A tenant is its own default audience unless somebody says
                // otherwise, and nothing fronts the admin tenant.
                default_resource: existing.as_ref().map_or_else(
                    || admin.issuer.as_str().to_owned(),
                    |t| t.default_resource.clone(),
                ),
                // Not forced active: an operator who suspended this tenant did
                // it on purpose, and a restart is not consent to undo it.
                status: existing.as_ref().map_or(TenantStatus::Active, |t| t.status),
                created_at: now,
                updated_at: now,
            })
            .await?;

        sqlx::query!(
            "update tenants set is_reserved = true
              where tenant_id = $1 and not is_reserved",
            admin.tenant.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            // The partial unique index. Two reserved tenants would make "where
            // does deployment authority live" a question with two answers.
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict(format!(
                    "another tenant is already the reserved one, so {} cannot be: \
                 a deployment has exactly one (ADR-0010)",
                    admin.tenant
                ))
            }
            _ => to_domain_error(e),
        })?;
        Ok(())
    }

    /// Finds the admin's account, creating it on first boot.
    async fn ensure_user(&self, admin: &DeploymentAdmin) -> Result<(UserId, bool), DomainError> {
        let users = PgUserRepository::new(
            self.pool.clone(),
            admin.tenant.clone(),
            Arc::clone(&self.kek),
        );
        if let Some(existing) = users.find_by_username(&admin.username).await? {
            return Ok((existing.id, false));
        }

        let now = OffsetDateTime::now_utc();
        let user = User {
            tenant: admin.tenant.clone(),
            id: UserId::generate(),
            username: admin.username.clone(),
            email: None,
            email_verified: false,
            status: UserStatus::Active,
            claims: ClaimSet::default(),
            created_at: now,
            updated_at: now,
        };
        users.upsert(&user).await?;
        Ok((user.id, true))
    }

    /// Makes the configured password the admin's password, if it is not already.
    ///
    /// Verified before it is written, so an unchanged configuration costs one
    /// Argon2id verification at boot instead of a fresh hash and a new salt in
    /// the row every time the process restarts.
    async fn ensure_password(
        &self,
        tenant: &TenantId,
        user: UserId,
        password: &str,
    ) -> Result<(), DomainError> {
        let verifier = PgPasswordVerifier::new(self.pool.clone(), tenant.clone(), self.argon2)?;
        let existing: Option<String> = sqlx::query_scalar!(
            "select password_hash from credentials
              where tenant_id = $1 and user_id = $2 and kind = 'password'",
            tenant.as_str(),
            user.as_uuid(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?
        .flatten();

        if let Some(stored) = existing {
            if verifier.matches(&stored, password) && !verifier.should_rehash(&stored) {
                return Ok(());
            }
            return verifier.rehash(*user.as_uuid(), password).await;
        }

        sqlx::query!(
            "insert into credentials
                 (tenant_id, credential_id, user_id, kind, password_hash, label)
             values ($1, $2, $3, 'password', $4, $5)",
            tenant.as_str(),
            Uuid::new_v4(),
            user.as_uuid(),
            verifier.hash_for_storage(password)?,
            SEEDED_CREDENTIAL_LABEL,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }
}
