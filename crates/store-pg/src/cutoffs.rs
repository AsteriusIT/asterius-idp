//! Withdrawing access tokens this server does not hold.
//!
//! A JWT access token (RFC 9068) is verified from its signature and its `exp`,
//! and this deployment keeps no inventory of the `jti` values it has signed —
//! that is the trade FAPI 2.0 SP §6.8 item 3 buys, and it is why
//! `access_token_denylist` can only ever hold the tokens somebody *presented*.
//!
//! Two obligations need more than that:
//!
//! * RFC 7592 §2.3 — deprovisioning a client "SHOULD immediately invalidate
//!   ... currently active access tokens";
//! * RFC 7009 §2.1 — revoking a refresh token SHOULD "also invalidate all
//!   access tokens based on the same authorization grant".
//!
//! Both are about a *set* of tokens nobody can enumerate. So the withdrawal is
//! a mark, not a list: one row per principal saying "nothing issued to this
//! one before that instant is still good", read on the resource path against
//! the token's own `iat`. One row per withdrawal, not one per token, and it
//! does not grow with traffic — which was the objection to inventorying every
//! `jti` at issuance (`ast-1sk.2`).
//!
//! The mark is written by [`withdraw`] and read by [`revoked_before`], and
//! neither is a public API: the callers are this crate's repositories, because
//! the mark must be written in the same transaction as the act it records.

use crate::error::to_domain_error;
use asterius_domain::entities::tenant_settings::MAX_ACCESS_TOKEN_LIFETIME;
use asterius_domain::{DomainError, TenantId};
use sqlx::PgExecutor;
use time::OffsetDateTime;

/// Who a mark is about.
///
/// The two kinds are one mechanism read in one place, so they share a table
/// and a read. They are not interchangeable: a client mark outlives the client
/// row it names, and a grant mark outlives nothing but is written far more
/// often.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Principal<'a> {
    /// Every access token issued to this `client_id`.
    Client(&'a str),
    /// Every access token minted from this `grant_id`.
    Grant(&'a str),
}

impl<'a> Principal<'a> {
    /// The `principal_kind` the schema's check constraint accepts.
    const fn kind(self) -> &'static str {
        match self {
            Self::Client(_) => "client",
            Self::Grant(_) => "grant",
        }
    }

    /// The identifier, as stored.
    const fn id(self) -> &'a str {
        match self {
            Self::Client(id) | Self::Grant(id) => id,
        }
    }
}

/// Marks every access token this principal was issued before `now` withdrawn.
///
/// Takes an executor rather than a pool because the callers have a transaction
/// open: a mark written outside the act it records is a window in which the
/// client is gone and its tokens still work, or the other way round.
///
/// The row expires at `now + MAX_ACCESS_TOKEN_LIFETIME`. That cap is enforced
/// when a tenant's settings are validated, so no token can carry an `exp`
/// beyond its own `iat` plus that — and once the mark's `expires_at` has
/// passed, every token it could have refused already fails on `exp`. Keeping
/// the row longer would be a table that grows with the number of withdrawals
/// forever; keeping it shorter would let a withdrawn token come back.
///
/// Idempotent, and monotonic: a second withdrawal moves the mark forward and
/// never back, because a mark that moved back would resurrect the tokens the
/// first one withdrew.
///
/// # Errors
///
/// A storage error, in which case nothing was marked and the caller must not
/// commit the act it was recording.
pub(crate) async fn withdraw<'e, E>(
    executor: E,
    tenant: &TenantId,
    principal: Principal<'_>,
    now: OffsetDateTime,
) -> Result<(), DomainError>
where
    E: PgExecutor<'e>,
{
    sqlx::query!(
        "insert into access_token_cutoffs
             (tenant_id, principal_kind, principal_id, revoked_before, expires_at)
         values ($1, $2, $3, $4, $5)
         on conflict (tenant_id, principal_kind, principal_id) do update
             set revoked_before = greatest(access_token_cutoffs.revoked_before,
                                           excluded.revoked_before),
                 expires_at     = greatest(access_token_cutoffs.expires_at,
                                           excluded.expires_at)",
        tenant.as_str(),
        principal.kind(),
        principal.id(),
        now,
        now + MAX_ACCESS_TOKEN_LIFETIME,
    )
    .execute(executor)
    .await
    .map_err(to_domain_error)?;
    Ok(())
}

/// The instant before which this token's client and grant withdrew everything.
///
/// One read for both marks, and the later of the two, because a token has to
/// survive both to be good. `grant` is optional: a `client_credentials` token
/// names no grant (RFC 6749 §4.4 has no resource owner, so there is no
/// authorization to record), and a token whose `grant_id` claim a tenant left
/// off is in the same position.
///
/// `expires_at` is not consulted, for the reason
/// [`crate::PgGrantRepository::is_denylisted`] gives about the denylist: a
/// token older than an expired mark has itself expired, so comparing against a
/// clock here would only add a way for a skewed one to make a withdrawn token
/// live again.
///
/// # Errors
///
/// A storage error. Never `None` because the store was unreachable: the caller
/// must refuse a token it could not check.
pub(crate) async fn revoked_before<'e, E>(
    executor: E,
    tenant: &TenantId,
    client: &str,
    grant: Option<&str>,
) -> Result<Option<OffsetDateTime>, DomainError>
where
    E: PgExecutor<'e>,
{
    sqlx::query_scalar!(
        "select max(revoked_before) from access_token_cutoffs
          where tenant_id = $1
            and ((principal_kind = 'client' and principal_id = $2)
              or (principal_kind = 'grant'  and principal_id = $3))",
        tenant.as_str(),
        client,
        grant,
    )
    .fetch_one(executor)
    .await
    .map_err(to_domain_error)
}
