//! Refresh tokens, over PostgreSQL.
//!
//! Three statements matter here, and each one is written so that the check and
//! the write are the same statement.
//!
//! # Redemption is one `update … returning`
//!
//! [`PgRefreshTokenRepository::redeem`] puts every acceptance rule into a
//! `where` clause — not revoked, inside the absolute deadline, inside the idle
//! deadline, and either not superseded or still inside its grace window — and
//! pushes the idle deadline out in the same statement. Reading the row and
//! then deciding would leave a window in which two concurrent refreshes both
//! read a live token; here the second one either sees the same live row (which
//! is correct: without rotation, a refresh token is deliberately reusable) or
//! matches nothing, and there is no third outcome.
//!
//! # What it does *not* check
//!
//! The grant. A refresh token whose grant has been revoked must fail, but that
//! is a fact about the grant and this repository would have to join to find
//! it. The token endpoint loads the grant anyway — it needs the scopes, the
//! subject and the session to mint anything — so the check lives there, next
//! to the identical one the authorization-code grant makes. What *does* reach
//! the tokens automatically is deletion: the foreign key cascades from
//! `grants`, and [`crate::grants::PgGrantRepository::revoke`] stamps every live
//! refresh token of a grant inside the same transaction that stamps the grant.
//! So a revoked grant's tokens are already revoked rows by the time anybody
//! presents one, and the check in the handler is the second of two.
//!
//! # Supersession is a transaction, or it is nothing
//!
//! Under the migration rotation mode (FAPI 2.0 SP §5.3.2.1 item 9, Note 1) a
//! refresh mints a replacement and stamps the old row. If the insert succeeded
//! and the stamp did not, the deployment would hold two unsuperseded tokens
//! for one grant forever; if the stamp succeeded and the insert did not, the
//! client would be told to use a token that does not exist. Neither is a state
//! worth recovering from, so both happen or neither does.

use crate::cutoffs;
use crate::error::to_domain_error;
use asterius_domain::{ClientId, DomainError, GrantId, TenantId};
use sqlx::postgres::PgPool;
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};

/// What a refresh token is bound to (RFC 9449 §5, RFC 8705 §3).
///
/// One of the two, never neither and never both, which is the schema's
/// `refresh_tokens_are_sender_constrained` — `(dpop_jkt is null) <>
/// (cert_thumbprint is null)` — said in the type that writes the row. A
/// refresh token bound to nothing is a bearer refresh token, which FAPI 2.0 SP
/// §5.3.2.1 does not admit, and the binding is always *recorded* even where a
/// tenant does not *enforce* it: a deployment that turns
/// `bind_to_dpop_key` on later must find the bindings already there.
///
/// The binding of a refresh token is the binding of the access token it was
/// issued beside, because it is the client's registered `TokenBinding` that
/// decides both. So a certificate-bound grant refreshed under a different
/// certificate fails the same way a DPoP-bound one refreshed under a different
/// key does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshBinding {
    /// The JWK thumbprint of the DPoP key (RFC 9449 §5), as base64url.
    Dpop(String),
    /// The SHA-256 of the DER of the client certificate (RFC 8705 §3.1), as
    /// bytes rather than base64url because that is the column's type: a digest
    /// stored as text is a digest two spellings of which compare unequal.
    Certificate([u8; 32]),
}

impl RefreshBinding {
    /// The `dpop_jkt` column's value.
    fn dpop_jkt(&self) -> Option<&str> {
        match self {
            Self::Dpop(jkt) => Some(jkt),
            Self::Certificate(_) => None,
        }
    }

    /// The `cert_thumbprint` column's value.
    fn cert_thumbprint(&self) -> Option<&[u8]> {
        match self {
            Self::Dpop(_) => None,
            Self::Certificate(digest) => Some(digest),
        }
    }

    /// Reads the pair of columns back, refusing a row that is neither.
    fn from_columns(
        dpop_jkt: Option<String>,
        cert_thumbprint: Option<Vec<u8>>,
    ) -> Result<Self, DomainError> {
        // `dpop_jkt` first, and the order matters only for a hand-edited row
        // that carries both: the `CHECK` makes it unreachable, and reading one
        // binding out of it is better than reading a binding that is the union
        // of two.
        if let Some(jkt) = dpop_jkt {
            return Ok(Self::Dpop(jkt));
        }
        let digest: [u8; 32] = cert_thumbprint
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                DomainError::invalid(
                    "refresh_token",
                    "a stored refresh token is not sender-constrained",
                )
            })?;
        Ok(Self::Certificate(digest))
    }
}

/// A refresh token about to be written.
///
/// Every field is a binding: the grant it draws on, the client that may
/// present it, the scopes it may be refreshed for, the DPoP key it is tied to,
/// and the two deadlines. There is no constructor with defaults, because a
/// refresh token with a defaulted binding is a refresh token with one fewer
/// thing an attacker needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRefreshToken {
    /// The grant this token draws its authority from.
    pub grant: GrantId,
    /// The client it was issued to. Checked at redemption against the
    /// authenticated client, so a token leaked to another registered client is
    /// not redeemable by it.
    pub client: ClientId,
    /// The scopes it may be refreshed for. A narrowed refresh writes a
    /// narrowed set, and the narrowing is then permanent for that token.
    pub scopes: BTreeSet<String>,
    /// What holds it: a DPoP key or a client certificate.
    ///
    /// Not optional, and not two nullable fields. See [`RefreshBinding`].
    pub binding: RefreshBinding,
    /// The deadline that never moves.
    pub absolute_expires_at: OffsetDateTime,
    /// The deadline that moves on every use, or `None` for a tenant with no
    /// idle clock.
    pub idle_expires_at: Option<OffsetDateTime>,
}

/// A refresh token as stored, once it has been accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefreshTokenRecord {
    /// The grant it draws on.
    pub grant: GrantId,
    /// The client it was issued to.
    pub client: ClientId,
    /// The scopes it may be refreshed for.
    pub scopes: BTreeSet<String>,
    /// What holds it, as the row records it.
    pub binding: RefreshBinding,
    /// When it was minted.
    pub issued_at: OffsetDateTime,
    /// The deadline that never moves.
    pub absolute_expires_at: OffsetDateTime,
    /// Whether this presentation was of a token already replaced.
    ///
    /// Only ever true under the migration rotation mode, and only inside the
    /// grace window — outside it the row does not match at all. The handler
    /// uses it to decide whether to hand back the same value or the
    /// replacement, and the audit trail records it, because a superseded token
    /// still in use is the signal that says a migration is not finished.
    pub superseded: bool,
}

/// What happened when a refresh token was presented.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Presentation {
    /// It was live, and its idle deadline has been pushed out.
    Accepted(Box<RefreshTokenRecord>),
    /// It was not.
    ///
    /// One variant for five facts — no such token, expired on the absolute
    /// clock, expired on the idle clock, revoked, or superseded past its grace
    /// — because RFC 6749 §5.2 gives them one code and telling them apart
    /// would let whoever holds a stolen token find out which. Which it was is
    /// a question for the log, and [`PgRefreshTokenRepository::redeem`] does
    /// not ask it: the answer would cost a second query on the failure path of
    /// a credential that is guessed at, and the endpoint's audit event already
    /// records that a refusal happened.
    Rejected,
}

/// Refresh tokens for one tenant.
#[derive(Debug, Clone)]
pub struct PgRefreshTokenRepository {
    pool: PgPool,
    tenant: TenantId,
}

impl PgRefreshTokenRepository {
    /// Scopes a repository to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    /// The digest as the column holds it.
    fn digest_bytes(digest: &str) -> Result<Vec<u8>, DomainError> {
        hex::decode(digest).map_err(|e| DomainError::invalid("refresh_token", e.to_string()))
    }

    /// Stores a freshly minted refresh token.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the digest already exists, which at 256
    /// bits means a broken generator rather than bad luck.
    /// [`DomainError::Storage`] otherwise.
    pub async fn issue(
        &self,
        digest: &str,
        token: &NewRefreshToken,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        Self::insert(&mut transaction, &self.tenant, digest, token, now).await?;
        transaction.commit().await.map_err(to_domain_error)
    }

    /// Presents a refresh token, and pushes its idle deadline out if it lives.
    ///
    /// `grace` is the tenant's rotation grace window, and is
    /// [`Duration::ZERO`] for the non-rotating default — under which no row is
    /// ever superseded, so the clause it feeds can never admit one.
    /// `next_idle_expiry` is the deadline the caller has computed from the
    /// tenant's idle lifetime; `None` leaves the row without an idle clock.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. Never treat
    /// that as [`Presentation::Rejected`]: an unavailable database is not
    /// permission to refuse a legitimate refresh, and it is certainly not
    /// permission to accept one.
    pub async fn redeem(
        &self,
        digest: &str,
        now: OffsetDateTime,
        grace: Duration,
        next_idle_expiry: Option<OffsetDateTime>,
    ) -> Result<Presentation, DomainError> {
        let digest = Self::digest_bytes(digest)?;
        // The grace window as an instant rather than an interval, so the
        // comparison in SQL is between two timestamps and the arithmetic
        // happens once, here, against the same `now` every other check uses.
        let superseded_after = now - grace;

        let row = sqlx::query!(
            // `least` is the cap the doc comment promises, applied in the
            // statement that writes it rather than left to a caller: the
            // schema's `refresh_tokens_idle_within_absolute` would otherwise
            // abort a legitimate refresh whenever the tenant's idle window is
            // longer than what remains of the absolute lifetime, which is the
            // ordinary state of a token near the end of its life. `null` is
            // "no idle clock" and must survive as `null`, which `least` would
            // not do on its own — it ignores nulls.
            "update refresh_tokens
                set last_used_at = $3,
                    idle_expires_at = case
                        when $5::timestamptz is null then null
                        else least($5, absolute_expires_at)
                    end
              where tenant_id = $1
                and token_hash = $2
                and revoked_at is null
                and absolute_expires_at > $3
                and (idle_expires_at is null or idle_expires_at > $3)
                and (superseded_at is null or superseded_at > $4)
             returning grant_id, client_id, scopes, dpop_jkt, cert_thumbprint,
                       issued_at, absolute_expires_at, superseded_at",
            self.tenant.as_str(),
            digest,
            now,
            superseded_after,
            next_idle_expiry,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let Some(row) = row else {
            return Ok(Presentation::Rejected);
        };

        Ok(Presentation::Accepted(Box::new(RefreshTokenRecord {
            grant: GrantId::new(row.grant_id.to_string()),
            client: ClientId::new(row.client_id),
            scopes: row.scopes.into_iter().collect(),
            binding: RefreshBinding::from_columns(row.dpop_jkt, row.cert_thumbprint)?,
            issued_at: row.issued_at,
            absolute_expires_at: row.absolute_expires_at,
            superseded: row.superseded_at.is_some(),
        })))
    }

    /// Revokes one refresh token, if it belongs to `client`.
    ///
    /// RFC 7009 §2.1's revocation, and §2.2's rule about whose token it is,
    /// written as one statement: the `client_id` is in the `where` clause, so a
    /// client asking for a token issued to another one matches no row and
    /// learns nothing. §2.2 requires exactly that — "the client MUST NOT be
    /// able to revoke a token issued to another client", and such a request is
    /// treated as one carrying an invalid token, which is a 200 and no action.
    ///
    /// The row is stamped, never deleted. A deleted row is a revocation nobody
    /// can audit afterwards, and the retention sweep already collects revoked
    /// rows once they are past their expiry as well.
    ///
    /// `coalesce` makes a second revocation of the same token a no-op rather
    /// than a rewrite: §2.2 expects a repeated request to succeed, and the
    /// instant the trail records must be the one the withdrawal happened at.
    ///
    /// Returns the grant the token drew on when a row matched — read by the
    /// audit event and by nothing else — and `None` when no row of this tenant
    /// answers to that digest and that client.
    ///
    /// ## The access tokens the same grant paid for
    ///
    /// RFC 7009 §2.1: "If the particular token is a refresh token and the
    /// authorization server supports the revocation of access tokens, then the
    /// authorization server SHOULD also invalidate all access tokens based on
    /// the same authorization grant." Those tokens cannot be listed — they are
    /// stateless JWTs (RFC 9068) and nothing here wrote their `jti` down — and
    /// the grant itself is deliberately left standing (Grant Management ID1
    /// §6.5 Note), so its `revoked_at` will not refuse them either.
    ///
    /// So a cutoff is written for the grant in the same transaction
    /// (the private `cutoffs::withdraw`): every access token minted from it
    /// before `now` stops verifying, and the ones minted afterwards — there
    /// are none, the refresh token that would mint them has just been
    /// revoked — would not be affected. Tokens of the *same client* under
    /// another grant are untouched, which is what makes this §2.1's rule and
    /// not a client-wide logout.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] if the digest is not hexadecimal, or
    /// [`DomainError::Storage`] if the store could not be reached. Never treat
    /// a storage failure as "there was nothing to revoke": a client told 200
    /// will not retry, and the token would stay live.
    pub async fn revoke(
        &self,
        digest: &str,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Option<GrantId>, DomainError> {
        let digest = Self::digest_bytes(digest)?;
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        let row = sqlx::query!(
            "update refresh_tokens
                set revoked_at = coalesce(revoked_at, $4)
              where tenant_id = $1 and token_hash = $2 and client_id = $3
             returning grant_id",
            self.tenant.as_str(),
            digest,
            client.as_str(),
            now,
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        let grant = row.map(|row| GrantId::new(row.grant_id.to_string()));
        if let Some(grant) = grant.as_ref() {
            cutoffs::withdraw(
                &mut *transaction,
                &self.tenant,
                cutoffs::Principal::Grant(grant.as_str()),
                now,
            )
            .await?;
        }

        transaction.commit().await.map_err(to_domain_error)?;
        Ok(grant)
    }

    /// Issues a replacement and stamps the token it replaces, together.
    ///
    /// The migration rotation mode only (FAPI 2.0 SP Note 1). The stamp uses
    /// `coalesce`, so a second refresh inside the grace window supersedes
    /// nothing again and the original instant — the one the grace window is
    /// measured from — is not pushed out by a client retrying.
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if the replacement's digest already exists,
    /// [`DomainError::Storage`] otherwise. Either way nothing is written: the
    /// old token stays live and the client can retry with it.
    ///
    /// # Revocation
    ///
    /// See [`Self::revoke`], which is the other writing path and the one RFC
    /// 7009 defines.
    pub async fn supersede(
        &self,
        superseded: &str,
        replacement_digest: &str,
        replacement: &NewRefreshToken,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let superseded = Self::digest_bytes(superseded)?;
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;

        Self::insert(
            &mut transaction,
            &self.tenant,
            replacement_digest,
            replacement,
            now,
        )
        .await?;

        sqlx::query!(
            "update refresh_tokens
                set superseded_at = coalesce(superseded_at, $3)
              where tenant_id = $1 and token_hash = $2",
            self.tenant.as_str(),
            superseded,
            now,
        )
        .execute(&mut *transaction)
        .await
        .map_err(to_domain_error)?;

        transaction.commit().await.map_err(to_domain_error)
    }

    /// The insert both writing paths share, so the column list is written once.
    async fn insert(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant: &TenantId,
        digest: &str,
        token: &NewRefreshToken,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let digest = Self::digest_bytes(digest)?;
        let scopes: Vec<String> = token.scopes.iter().cloned().collect();

        sqlx::query!(
            "insert into refresh_tokens
                 (tenant_id, token_hash, grant_id, client_id, scopes, dpop_jkt,
                  cert_thumbprint, issued_at, absolute_expires_at, idle_expires_at)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            tenant.as_str(),
            digest,
            crate::grants::uuid(&token.grant)?,
            token.client.as_str(),
            &scopes,
            token.binding.dpop_jkt(),
            token.binding.cert_thumbprint(),
            now,
            token.absolute_expires_at,
            token.idle_expires_at,
        )
        .execute(&mut **transaction)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("refresh token already exists".to_owned())
            }
            _ => to_domain_error(error),
        })?;
        Ok(())
    }
}
