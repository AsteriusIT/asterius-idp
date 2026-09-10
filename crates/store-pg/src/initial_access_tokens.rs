//! One tenant's RFC 7591 initial access tokens (`ast-cu3`).
//!
//! # Reserving is one statement, deliberately
//!
//! [`InitialAccessTokenStore::reserve`] has to answer "is this credential
//! valid, and does it have quota left" *and* spend the quota, and the two
//! cannot be two statements. A `select` followed by an `update` lets two
//! requests presenting the last use of a token both read `uses = max_uses - 1`
//! and both be admitted, which turns a quota of one into a quota of two under
//! exactly the conditions a quota exists for. So the increment carries its own
//! predicate and the row is only charged if it was chargeable.
//!
//! A row that was *not* charged still has to be told apart from a digest that
//! matches nothing — the audit trail wants to know whether an operator's token
//! expired or an attacker guessed — so the statement is a CTE that updates
//! what it can and reports what the row looked like either way. One round trip
//! and one lock, with no transaction to hold open across an HTTP handler.
//!
//! # These are runtime queries, not `query!`
//!
//! The same trade [`crate::tenant_settings`] states. `sqlx::query!` checks
//! against a live database at compile time and records the answer in `.sqlx/`,
//! which makes a new statement impossible to add without a migrated database
//! to hand; what it would catch here is caught by the database tests in
//! `crates/store-pg/tests/database.rs`, which exercise every statement in this
//! file against the real schema. `crate::audit` and `crate::retention` make
//! the same choice. The tenant predicate that `crate::sql_audit` enforces on
//! these literals is what keeps that choice from costing a cross-tenant read.

use crate::error::to_domain_error;
use asterius_domain::ports::InitialAccessTokenStore;
use asterius_domain::{
    DomainError, InitialAccessToken, InitialAccessTokenReservation, NewInitialAccessToken, TenantId,
};
use sqlx::Row as _;
use sqlx::postgres::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// `InitialAccessTokenStore` over `PostgreSQL`.
#[derive(Debug, Clone)]
pub struct PgInitialAccessTokens {
    pool: PgPool,
}

impl PgInitialAccessTokens {
    /// Wraps a pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Reads one row into the domain entity.
    ///
    /// `uses` and `max_uses` are `integer` in the schema, guarded by
    /// `check (uses >= 0)` and `check (max_uses > 0)`, so the conversion cannot
    /// fail on a row this code wrote. A row edited to a negative value by hand
    /// is clamped to zero rather than failing the read: a token that reports
    /// "spent" is the safe reading of a corrupt count, and failing would take
    /// the whole list screen down with it.
    fn record(row: &sqlx::postgres::PgRow) -> Result<InitialAccessToken, DomainError> {
        let uses: i32 = row.try_get("uses").map_err(to_domain_error)?;
        let max_uses: Option<i32> = row.try_get("max_uses").map_err(to_domain_error)?;
        Ok(InitialAccessToken {
            id: row.try_get("id").map_err(to_domain_error)?,
            tenant: TenantId::new(
                row.try_get::<String, _>("tenant_id")
                    .map_err(to_domain_error)?,
            ),
            label: row.try_get("label").map_err(to_domain_error)?,
            uses: u32::try_from(uses).unwrap_or(0),
            max_uses: max_uses.map(|max| u32::try_from(max).unwrap_or(0)),
            expires_at: row.try_get("expires_at").map_err(to_domain_error)?,
            created_at: row.try_get("created_at").map_err(to_domain_error)?,
        })
    }
}

#[async_trait::async_trait]
impl InitialAccessTokenStore for PgInitialAccessTokens {
    async fn issue(
        &self,
        token: &NewInitialAccessToken,
    ) -> Result<InitialAccessToken, DomainError> {
        // `max_uses` is `Option<u32>` and the column is `integer`. A quota
        // beyond `i32::MAX` is refused rather than silently truncated: an
        // operator who typed four billion gets an error, not a ceiling they
        // did not choose.
        let max_uses = match token.max_uses {
            None => None,
            Some(max) => Some(i32::try_from(max).map_err(|_| {
                DomainError::invalid("max_clients", "beyond what one token can be charged")
            })?),
        };

        let row = sqlx::query(
            "insert into initial_access_tokens
                 (id, tenant_id, label, token_hash, uses, max_uses, expires_at,
                  created_at, created_by)
             values ($1, $2, $3, $4, 0, $5, $6, now(), $7)
             returning id, tenant_id, label, uses, max_uses, expires_at, created_at",
        )
        .bind(Uuid::new_v4())
        .bind(token.tenant.as_str())
        .bind(&token.label)
        .bind(token.digest.as_slice())
        .bind(max_uses)
        .bind(token.expires_at)
        .bind(&token.issued_by)
        .fetch_one(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Self::record(&row)
    }

    async fn reserve(
        &self,
        tenant: &TenantId,
        digest: &[u8; 32],
        now: OffsetDateTime,
    ) -> Result<InitialAccessTokenReservation, DomainError> {
        // `charged` updates the row only if it is live and has quota left;
        // `found` reports the row whether or not it was charged, so the caller
        // can tell "no such token" from "this one is spent". Both read the same
        // tenant-scoped predicate, and the `update` is what takes the row lock,
        // so two concurrent reservations serialise on it.
        let row = sqlx::query(
            "with charged as (
                 update initial_access_tokens
                    set uses = uses + 1
                  where tenant_id = $1
                    and token_hash = $2
                    and (expires_at is null or expires_at > $3)
                    and (max_uses is null or uses < max_uses)
              returning id, max_uses, uses
             ),
             found as (
                 select id, expires_at
                   from initial_access_tokens
                  where tenant_id = $1 and token_hash = $2
             )
             select found.id as found_id,
                    found.expires_at as found_expires_at,
                    charged.id as charged_id,
                    charged.uses as charged_uses,
                    charged.max_uses as charged_max_uses
               from found left join charged on charged.id = found.id",
        )
        .bind(tenant.as_str())
        .bind(digest.as_slice())
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let Some(row) = row else {
            return Ok(InitialAccessTokenReservation::Unknown);
        };

        let charged: Option<Uuid> = row.try_get("charged_id").map_err(to_domain_error)?;
        if let Some(id) = charged {
            let uses: i32 = row.try_get("charged_uses").map_err(to_domain_error)?;
            let max_uses: Option<i32> = row.try_get("charged_max_uses").map_err(to_domain_error)?;
            let remaining = max_uses.map(|max| u32::try_from(max - uses).unwrap_or(0));
            return Ok(InitialAccessTokenReservation::Reserved { id, remaining });
        }

        // Not charged. Expiry is reported ahead of exhaustion because it is the
        // one an operator can act on: a token past its expiry is not going to
        // start working again when its quota is raised.
        let expires_at: Option<OffsetDateTime> =
            row.try_get("found_expires_at").map_err(to_domain_error)?;
        if expires_at.is_some_and(|at| at <= now) {
            return Ok(InitialAccessTokenReservation::Expired);
        }
        Ok(InitialAccessTokenReservation::Exhausted)
    }

    async fn release(&self, tenant: &TenantId, id: Uuid) -> Result<(), DomainError> {
        // `greatest(uses - 1, 0)` rather than `uses - 1`: a release with no
        // matching reservation — a retry, a duplicated handler — must not mint
        // quota that was never charged, and the column's `check (uses >= 0)`
        // would otherwise turn it into a 500 on the *refusal* path.
        sqlx::query(
            "update initial_access_tokens
                set uses = greatest(uses - 1, 0)
              where tenant_id = $1 and id = $2",
        )
        .bind(tenant.as_str())
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(())
    }

    async fn list(&self, tenant: &TenantId) -> Result<Vec<InitialAccessToken>, DomainError> {
        let rows = sqlx::query(
            "select id, tenant_id, label, uses, max_uses, expires_at, created_at
               from initial_access_tokens
              where tenant_id = $1
              order by created_at desc, id",
        )
        .bind(tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(to_domain_error)?;

        rows.iter().map(Self::record).collect()
    }
}
