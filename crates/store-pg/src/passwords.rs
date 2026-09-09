//! Argon2id password verification.
//!
//! # The dummy verification is the point
//!
//! The obvious implementation looks up the user, and if there is none, returns
//! `Ok(None)`. That returns in a millisecond, where a real verification takes
//! the tens of milliseconds Argon2id is configured to cost. An attacker with a
//! list of email addresses can separate the ones with accounts from the ones
//! without by watching a clock, and no amount of identical error text changes
//! that.
//!
//! So the unknown-user path verifies a *real* Argon2id hash — one computed at
//! construction, of a value nobody knows — and throws the answer away. The two
//! paths then do the same work.
//!
//! What this does not equalise: the database lookup itself, which is fast and
//! roughly constant, and a *disabled* account, which takes the same path as an
//! active one because the check happens after verification rather than before.
//! Both are deliberate.

use crate::error::to_domain_error;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use asterius_domain::{
    Argon2Parameters, CredentialVerifier, DomainError, OpaqueToken, Secret, TenantId,
};
use sqlx::postgres::PgPool;

/// Verifies passwords for one tenant.
pub struct PgPasswordVerifier {
    pool: PgPool,
    tenant: TenantId,
    parameters: Argon2Parameters,
    /// A real hash of a value nobody knows, verified against on the
    /// unknown-user path so it costs what a real verification costs.
    decoy: String,
}

impl std::fmt::Debug for PgPasswordVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgPasswordVerifier")
            .field("tenant", &self.tenant)
            .field("parameters", &self.parameters)
            .finish_non_exhaustive()
    }
}

impl PgPasswordVerifier {
    /// Builds a verifier.
    ///
    /// The decoy hash is computed once, here, with the same parameters real
    /// hashes use — computing it per request would itself be a timing signal,
    /// and a slower one than the verification it is hiding.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the decoy cannot be hashed, which means the
    /// process has no working CSPRNG and should not start.
    pub fn new(
        pool: PgPool,
        tenant: TenantId,
        parameters: Argon2Parameters,
    ) -> Result<Self, DomainError> {
        let unknowable = OpaqueToken::generate();
        let decoy = hash(&argon2(parameters), unknowable.expose())
            .map_err(|e| DomainError::Storage(Box::new(e)))?;
        Ok(Self {
            pool,
            tenant,
            parameters,
            decoy,
        })
    }

    /// The parameters this verifier hashes with.
    #[must_use]
    pub const fn parameters(&self) -> Argon2Parameters {
        self.parameters
    }

    /// Hashes a password for storage.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if hashing fails.
    pub fn hash_for_storage(&self, password: &str) -> Result<String, DomainError> {
        hash(&argon2(self.parameters), password).map_err(|e| DomainError::Storage(Box::new(e)))
    }

    /// Whether `password` is the one behind `stored`.
    ///
    /// No database, no user, and deliberately no dummy verification: this is
    /// not a login path. Its one caller is the deployment-admin seed, which
    /// asks "is the configured password already the stored one?" so that a
    /// restart does not rewrite a hash it does not need to. There is no
    /// enumeration to hide, because the caller already holds both values.
    ///
    /// An unparseable stored hash is `false` rather than an error: it cannot
    /// verify anything, and the caller's next move — replace it — is the same
    /// either way.
    #[must_use]
    pub fn matches(&self, stored: &str, password: &str) -> bool {
        PasswordHash::new(stored).is_ok_and(|parsed| {
            argon2(self.parameters)
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
    }

    /// Whether a stored hash was computed with weaker parameters than these.
    ///
    /// Used to rehash on the next successful login — the only moment the
    /// plaintext is available.
    #[must_use]
    pub fn should_rehash(&self, stored: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(stored) else {
            // Unparseable: it cannot verify anything, so rehashing it is the
            // least surprising answer if it ever does.
            return true;
        };
        let Ok(params) = Params::try_from(&parsed) else {
            return true;
        };
        let Ok(stored) = Argon2Parameters::new(params.m_cost(), params.t_cost(), params.p_cost())
        else {
            // Below the floor. Definitely rehash.
            return true;
        };
        stored.is_weaker_than(self.parameters)
    }

    /// Replaces a stored hash after a successful login.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the update fails.
    pub async fn rehash(&self, user: uuid::Uuid, password: &str) -> Result<(), DomainError> {
        let fresh = self.hash_for_storage(password)?;
        sqlx::query!(
            "update credentials
                set password_hash = $3
              where tenant_id = $1 and user_id = $2 and kind = 'password'",
            self.tenant.as_str(),
            user,
            fresh,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }
}

/// Builds an Argon2id instance for `parameters`.
fn argon2(parameters: Argon2Parameters) -> Argon2<'static> {
    // `Params::new` cannot fail for values that passed `Argon2Parameters`,
    // which enforces the same bounds; falling back to the default keeps this
    // total rather than panicking on a request path.
    let params = Params::new(
        parameters.memory_kib(),
        parameters.iterations(),
        parameters.parallelism(),
        None,
    )
    .unwrap_or_default();
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn hash(argon2: &Argon2<'_>, password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

#[async_trait::async_trait]
impl CredentialVerifier for PgPasswordVerifier {
    async fn verify(
        &self,
        username: &str,
        password: Secret<String>,
    ) -> Result<Option<uuid::Uuid>, DomainError> {
        let row = sqlx::query!(
            "select u.user_id, c.password_hash, u.status, c.disabled_at
               from users u
               join credentials c
                 on c.tenant_id = u.tenant_id and c.user_id = u.user_id
              where u.tenant_id = $1 and u.username = $2 and c.kind = 'password'",
            self.tenant.as_str(),
            username,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        // The hash to verify against: the user's, or the decoy. Both paths run
        // the same Argon2id work from here.
        let (stored, user) = match &row {
            Some(row) => (
                row.password_hash.as_deref().unwrap_or(&self.decoy),
                Some(row.user_id),
            ),
            None => (self.decoy.as_str(), None),
        };

        let argon2 = argon2(self.parameters);
        let verified = PasswordHash::new(stored).is_ok_and(|parsed| {
            argon2
                .verify_password(password.expose().as_bytes(), &parsed)
                .is_ok()
        });

        // Only now is the account's state consulted. Checking it earlier would
        // let a disabled account be told apart from an active one by how long
        // the answer took.
        let usable = row
            .as_ref()
            .is_some_and(|row| row.status == "active" && row.disabled_at.is_none());

        if verified && usable {
            Ok(user)
        } else {
            Ok(None)
        }
    }
}
