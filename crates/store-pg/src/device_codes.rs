//! Device authorizations (RFC 8628), over PostgreSQL.
//!
//! Four statements, and which of them is atomic is the whole of the security
//! here.
//!
//! * **The poll** (§3.4, §3.5) stamps `last_polled_at` and raises the interval
//!   in the same statement that reads the previous one, so that two polls
//!   racing cannot both be judged against the same "last poll" and both escape
//!   `slow_down`.
//! * **The redemption** is `update … where redeemed_at is null … returning`, so
//!   the check and the spend are one statement and two token requests carrying
//!   the same device code cannot both be served. RFC 8628 §3.4 defers to
//!   RFC 6749 §4.1.3, and a device code is single-use for the same reason an
//!   authorization code is.
//! * **The approval** and **the refusal** move a row out of `pending` only
//!   while it is still `pending` and still live, so a browser that submits an
//!   approval twice — a double-clicked button, a resubmitted form — does not
//!   create a second grant.
//!
//! # Expiry is the clock, not a state
//!
//! Nothing here writes an `expired` status. Every read compares `expires_at`
//! against the instant handed in, so `expired_token` is the honest answer from
//! the moment it is true rather than from the moment a sweep next runs. The
//! retention sweep deletes the row afterwards; if it is late, the answers do
//! not change.
//!
//! # Neither code appears in this file
//!
//! Every method takes a digest. The lookup key for a user code is the digest of
//! its *canonical* form — upper case, no separator — so RFC 8628 §6.1's
//! case-insensitivity is decided once, in `asterius_oidc::device::UserCode`,
//! and never by a `lower()` here that an index would then have to match.

use crate::error::to_domain_error;
use asterius_domain::{DomainError, GrantId, TenantId, UserId};
use sqlx::postgres::PgPool;
use time::{Duration, OffsetDateTime};

/// A device authorization to record (RFC 8628 §3.1).
#[derive(Debug, Clone)]
pub struct NewDeviceAuthorization {
    /// The authenticated client that asked.
    pub client_id: String,
    /// What it asked for, already narrowed to its registration.
    pub scopes: Vec<String>,
    /// RFC 9396 §3's rich authorization, as the parser accepted it.
    pub authorization_details: serde_json::Value,
    /// §3.2's `expires_in`, as an instant.
    pub expires_at: OffsetDateTime,
    /// §3.2's `interval`, as this authorization starts out.
    pub interval: Duration,
}

/// A pending authorization, as the verification page sees it.
///
/// No device code and no user code: the page has already been given the one
/// the person typed, and it has no business being handed the credential the
/// device is polling with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDevice {
    /// Which client is asking, so the page can name it (§5.3).
    pub client_id: String,
    /// What it asked for, so the page can show it.
    pub scopes: Vec<String>,
    /// RFC 9396 §3's elements, for the same reason.
    pub authorization_details: serde_json::Value,
    /// When it stops being approvable.
    pub expires_at: OffsetDateTime,
    /// How many failed confirmations this authorization has already survived
    /// (§5.1).
    pub failed_attempts: i32,
}

/// What a poll of the token endpoint found (RFC 8628 §3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Poll {
    /// Nobody has answered yet: `authorization_pending`.
    Pending,
    /// The device polled faster than the interval it was given: `slow_down`.
    /// The stored interval has been raised, so the value here is the one the
    /// device must now use.
    SlowDown {
        /// The new interval.
        interval: Duration,
    },
    /// Somebody approved it. Redeemable exactly once, by [`redeem`].
    ///
    /// [`redeem`]: PgDeviceCodeRepository::redeem
    Approved,
    /// Somebody refused it: `access_denied`.
    Denied,
    /// It ran out before anybody answered: `expired_token`.
    Expired,
    /// It has already been redeemed.
    ///
    /// The caller answers this exactly as it answers an unknown device code:
    /// only the client that already holds the tokens can provoke it, and
    /// distinguishing it would confirm to anybody else that the code was real.
    Spent,
}

/// One poll, and whose authorization it was.
///
/// The client is returned with every state rather than only with an approval,
/// so that the token endpoint can refuse another client's device code before
/// it acts on what the state says. A handler that checked ownership only at
/// redemption would let any authenticated client of the tenant read the
/// progress of a flow it has nothing to do with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polled {
    /// The client the device code was issued to.
    pub client_id: String,
    /// What the poll found.
    pub state: Poll,
}

/// An approved authorization, spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemedDevice {
    /// The client the device code was issued to. Compared against the client
    /// that authenticated, which is what stops one client redeeming another's
    /// device code.
    pub client_id: String,
    /// The authorization the approval created.
    pub grant_id: GrantId,
}

/// Device authorizations for one tenant.
#[derive(Debug, Clone)]
pub struct PgDeviceCodeRepository {
    pool: PgPool,
    tenant: TenantId,
}

impl PgDeviceCodeRepository {
    /// Scopes a repository to `tenant`.
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId) -> Self {
        Self { pool, tenant }
    }

    fn digest_bytes(name: &'static str, digest: &str) -> Result<Vec<u8>, DomainError> {
        hex::decode(digest).map_err(|e| DomainError::invalid(name, e.to_string()))
    }

    /// Records a device authorization (RFC 8628 §3.1).
    ///
    /// # Errors
    ///
    /// [`DomainError::Conflict`] if either digest is already in this tenant.
    /// For the device code that means a broken generator; for the user code it
    /// means a collision in a ~34.5-bit space, which is rare but *possible*
    /// with enough outstanding authorizations — the caller draws another one
    /// rather than sharing a code between two flows.
    /// [`DomainError::Storage`] otherwise.
    pub async fn issue(
        &self,
        device_code_digest: &str,
        user_code_digest: &str,
        request: &NewDeviceAuthorization,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let device = Self::digest_bytes("device_code", device_code_digest)?;
        let user = Self::digest_bytes("user_code", user_code_digest)?;
        let interval = i32::try_from(request.interval.whole_seconds())
            .map_err(|_| DomainError::invalid("interval", "is not a number of seconds"))?;
        sqlx::query!(
            "insert into device_codes
                 (tenant_id, device_code_hash, user_code_hash, client_id, scopes,
                  authorization_details, issued_at, expires_at, poll_interval_seconds)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            self.tenant.as_str(),
            device,
            user,
            request.client_id,
            &request.scopes,
            request.authorization_details,
            now,
            request.expires_at,
            interval,
        )
        .execute(&self.pool)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                DomainError::Conflict("device authorization already exists".to_owned())
            }
            _ => to_domain_error(error),
        })?;
        Ok(())
    }

    /// One poll of the token endpoint (RFC 8628 §3.4, §3.5).
    ///
    /// The stamp and the interval are written in the same statement that
    /// returns the values the decision is made from, so the "was this too
    /// fast?" comparison and the record of this poll cannot be separated by
    /// another poll.
    ///
    /// `slow_down` is RFC 8628 §3.5's five seconds, handed in rather than
    /// written here: this crate is the adapter layer and the protocol
    /// constants live in `asterius-oidc`, so the number the response
    /// advertises and the number the store adds are one value (`ast-5c6` is
    /// the bead about what happens when a constant like that exists twice).
    ///
    /// A poll of an *approved* authorization is never `slow_down`: the answer
    /// is ready, and telling a client to wait longer for a decision that has
    /// already been made would delay a token for no reason. The interval is
    /// still stamped, so a client that then polls again is judged normally.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. Never read
    /// that as `Ok(None)`: an unavailable database is not permission to
    /// refuse a legitimate device or to forget that one is polling too fast.
    pub async fn poll(
        &self,
        device_code_digest: &str,
        slow_down: Duration,
        now: OffsetDateTime,
    ) -> Result<Option<Polled>, DomainError> {
        let device = Self::digest_bytes("device_code", device_code_digest)?;
        let increment = i32::try_from(slow_down.whole_seconds())
            .map_err(|_| DomainError::invalid("interval", "is not a number of seconds"))?;

        let row = sqlx::query!(
            "with target as (
                 select device_code_hash, client_id, status, expires_at,
                        redeemed_at, last_polled_at, poll_interval_seconds
                   from device_codes
                  where tenant_id = $1 and device_code_hash = $2
                    for update
             ),
             stamped as (
                 update device_codes as d
                    set last_polled_at = $3,
                        poll_interval_seconds = case
                            when t.status <> 'approved'
                             and t.last_polled_at is not null
                             and $3 < t.last_polled_at
                                      + make_interval(secs => t.poll_interval_seconds)
                            then t.poll_interval_seconds + $4
                            else t.poll_interval_seconds
                        end
                   from target as t
                  where d.tenant_id = $1 and d.device_code_hash = t.device_code_hash
              returning d.poll_interval_seconds as new_interval
             )
             select t.client_id, t.status, t.expires_at, t.redeemed_at,
                    t.last_polled_at, t.poll_interval_seconds, s.new_interval
               from target as t, stamped as s",
            self.tenant.as_str(),
            device,
            now,
            increment,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let state = if row.expires_at <= now {
            // Expiry first, and before the rate check: a device that keeps
            // polling an authorization nobody answered must be told it is
            // over, not told to slow down for another ten minutes.
            Poll::Expired
        } else if row.redeemed_at.is_some() {
            Poll::Spent
        } else if row.status == "approved" {
            Poll::Approved
        } else if row.status == "denied" {
            Poll::Denied
        } else if row.last_polled_at.is_some_and(|previous| {
            // §3.5: "the client is polling too frequently". Measured against
            // the interval the row held *before* this poll, which is the one
            // the device was told to use.
            now < previous + Duration::seconds(i64::from(row.poll_interval_seconds))
        }) {
            Poll::SlowDown {
                interval: Duration::seconds(i64::from(row.new_interval)),
            }
        } else {
            Poll::Pending
        };

        Ok(Some(Polled {
            client_id: row.client_id,
            state,
        }))
    }

    /// Spends an approved authorization, once.
    ///
    /// `Ok(None)` is every reason it could not be spent — unknown, expired,
    /// still pending, refused, or already redeemed — because a token endpoint
    /// that distinguished them would answer questions about a credential the
    /// caller may not hold. The caller has already learned which it was from
    /// [`Self::poll`]; this is the atomic spend that follows.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    pub async fn redeem(
        &self,
        device_code_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<RedeemedDevice>, DomainError> {
        let device = Self::digest_bytes("device_code", device_code_digest)?;
        let row = sqlx::query!(
            "update device_codes
                set redeemed_at = $3
              where tenant_id = $1 and device_code_hash = $2
                and status = 'approved' and redeemed_at is null and expires_at > $3
          returning client_id, grant_id",
            self.tenant.as_str(),
            device,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(row.and_then(|row| {
            row.grant_id.map(|grant| RedeemedDevice {
                client_id: row.client_id,
                // A grant deleted between the approval and the redemption
                // leaves the column null (`on delete set null`), and the
                // `and_then` above turns that into "not redeemable" rather
                // than into a token minted from an authorization that no
                // longer exists.
                grant_id: GrantId::new(grant.to_string()),
            })
        }))
    }

    /// Finds the pending authorization a typed user code names (§3.3).
    ///
    /// Only a live, pending one. An expired, approved or refused row reads as
    /// absent, because the verification page says the same thing to all four
    /// (§5.1): "unknown", "expired" and "already used" would each be an oracle
    /// for somebody working through a code space of ~34.5 bits.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    pub async fn pending(
        &self,
        user_code_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<PendingDevice>, DomainError> {
        let user_code = Self::digest_bytes("user_code", user_code_digest)?;
        let row = sqlx::query!(
            "select client_id, scopes, authorization_details, expires_at, failed_attempts
               from device_codes
              where tenant_id = $1 and user_code_hash = $2
                and status = 'pending' and expires_at > $3",
            self.tenant.as_str(),
            user_code,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(row.map(|row| PendingDevice {
            client_id: row.client_id,
            scopes: row.scopes,
            authorization_details: row.authorization_details,
            expires_at: row.expires_at,
            failed_attempts: row.failed_attempts,
        }))
    }

    /// Approves a pending authorization, binding it to the person and the
    /// grant their approval created.
    ///
    /// `false` means there was nothing pending and live to approve — which is
    /// the answer a second submission of the same form gets, so the grant the
    /// first one created is not joined by another.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    pub async fn approve(
        &self,
        user_code_digest: &str,
        user: &UserId,
        grant: &GrantId,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let user_code = Self::digest_bytes("user_code", user_code_digest)?;
        let user_id = *user.as_uuid();
        let grant_id = crate::grants::uuid(grant)?;
        let done = sqlx::query!(
            "update device_codes
                set status = 'approved', user_id = $3, grant_id = $4, approved_at = $5
              where tenant_id = $1 and user_code_hash = $2
                and status = 'pending' and expires_at > $5",
            self.tenant.as_str(),
            user_code,
            user_id,
            grant_id,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(done.rows_affected() == 1)
    }

    /// Refuses a pending authorization (§3.5's `access_denied`).
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    pub async fn deny(
        &self,
        user_code_digest: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let user_code = Self::digest_bytes("user_code", user_code_digest)?;
        let done = sqlx::query!(
            "update device_codes
                set status = 'denied'
              where tenant_id = $1 and user_code_hash = $2
                and status = 'pending' and expires_at > $3",
            self.tenant.as_str(),
            user_code,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(done.rows_affected() == 1)
    }

    /// Counts one failed confirmation against an authorization, and refuses it
    /// outright once there have been `ceiling` of them (§5.1).
    ///
    /// The per-address limit is the defence against somebody sweeping the code
    /// space; this is the defence against somebody who has *found* a live code
    /// and is now working at the ceremony in front of it. The row is taken out
    /// of the space rather than left to be attempted again, and the device
    /// learns `access_denied` on its next poll — which is the right thing for
    /// the person in front of it to see.
    ///
    /// Returns the new count.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    pub async fn record_failure(
        &self,
        user_code_digest: &str,
        ceiling: i32,
        now: OffsetDateTime,
    ) -> Result<i32, DomainError> {
        let user_code = Self::digest_bytes("user_code", user_code_digest)?;
        let row = sqlx::query!(
            "update device_codes
                set failed_attempts = failed_attempts + 1,
                    status = case
                        when failed_attempts + 1 >= $3 and status = 'pending'
                        then 'denied' else status
                    end
              where tenant_id = $1 and user_code_hash = $2 and expires_at > $4
          returning failed_attempts",
            self.tenant.as_str(),
            user_code,
            ceiling,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(row.map_or(0, |row| row.failed_attempts))
    }
}
