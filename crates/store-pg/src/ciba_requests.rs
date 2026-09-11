//! Backchannel authentication requests (CIBA Core 1.0), over PostgreSQL.
//!
//! Four actors move one row through three states, and the statements here are
//! theirs: the client records the request (`ast-lh3.4`, [`issue`]) and then
//! polls the token endpoint with it (`ast-lh3.5`, [`poll`] and [`redeem`]);
//! the person approves or refuses it (`ast-lh3.6`, [`approve`] and [`deny`]);
//! and in ping mode the delivery worker reads what the §10.2 notification
//! needs ([`for_notification`]) and records that it was sent
//! ([`mark_notified`]). The rule the device flow's store follows holds here
//! too: a check and the write it authorises are one statement.
//!
//! # Nothing here appears in the clear
//!
//! The `auth_req_id` arrives as a digest, and so does the
//! `client_notification_token`. The first is what the token endpoint answers
//! to; the second is what a §10.2 notification will carry in an
//! `Authorization` header. Both are bearer values, and a copy of this table is
//! a list of digests rather than a list of credentials.
//!
//! In ping mode the two values are *also* kept sealed under the tenant's KEK
//! (`0034_ciba_ping_credentials.sql`), because the notification presents them
//! rather than comparing them, and a digest cannot be posted. The seal is
//! bound to the row — the tenant and the `auth_req_id` digest are in the
//! AEAD's additional data — so a ciphertext copied over another request's row
//! stops opening instead of notifying one client of another's approval. The
//! plaintext exists in this process for the width of one call and is handed
//! out in a type whose `Debug` does not render it.
//!
//! The `binding_message` is the exception and is stored in the clear, because
//! it exists to be *rendered*: §7.1 puts the same string on the consumption
//! device and on the authentication device so that a person can see the two
//! are one transaction. A digest could not be shown to anybody.
//!
//! # The decision and the notification are one transaction
//!
//! [`approve`] and [`deny`] move the row and, for a ping request, queue the
//! `ciba.ping` outbox row in the same transaction. §10.2 sends the ping "after
//! a successful or failed end-user authentication"; a decision that committed
//! without its notification would be a client waiting on a callback that is
//! never coming, and a notification queued for a decision that rolled back
//! would tell a client to fetch a result that does not exist. Expiry queues
//! nothing: §10.2 names the two outcomes it notifies, and expiry is not one.
//!
//! [`issue`]: PgCibaRequestRepository::issue
//! [`poll`]: PgCibaRequestRepository::poll
//! [`redeem`]: PgCibaRequestRepository::redeem
//! [`approve`]: PgCibaRequestRepository::approve
//! [`deny`]: PgCibaRequestRepository::deny
//! [`for_notification`]: PgCibaRequestRepository::for_notification
//! [`mark_notified`]: PgCibaRequestRepository::mark_notified

use crate::error::to_domain_error;
use crate::outbox::{NewOutboxEntry, PgTransaction, enqueue};
use asterius_domain::{DomainError, GrantId, TenantId, UserId, sha256_hex};
use asterius_jose::{Kek, KeyBinding, RowSecret, WrappedKey};
use sqlx::postgres::PgPool;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

/// The outbox `kind` a §10.2 ping notification is queued under.
///
/// The family is `ciba`, which is what the delivery worker dispatches on; the
/// name is `ping` because it is the one thing this family sends.
pub const PING_OUTBOX_KIND: &str = "ciba.ping";

/// What a §10.2 notification presents, on its way into the seal.
///
/// Both values are bearer credentials — one at this server's token endpoint,
/// one at the client's notification endpoint — so the type renders neither.
#[derive(Clone)]
pub struct PingCredentials {
    /// §7.3's `auth_req_id`, as it was handed to the client.
    pub auth_req_id: String,
    /// §7.1's `client_notification_token`, as the client sent it.
    pub client_notification_token: String,
}

impl std::fmt::Debug for PingCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingCredentials")
            .field("auth_req_id", &"[REDACTED]")
            .field("client_notification_token", &"[REDACTED]")
            .finish()
    }
}

/// A backchannel authentication request to record (§7.1, §7.2).
///
/// Every field is post-validation: the scopes are narrowed to the client's
/// registration, the user is what the hint resolved to, and the lifetime is
/// already clamped to the tenant's maximum. Nothing here is re-decided.
#[derive(Debug, Clone)]
pub struct NewCibaRequest {
    /// The authenticated client that asked.
    pub client_id: String,
    /// Who the hint named (§7.2 step 2).
    pub user_id: UserId,
    /// What it asked for, already narrowed to its registration.
    pub scopes: Vec<String>,
    /// RFC 9396 §3's rich authorization, as the parser accepted it.
    pub authorization_details: serde_json::Value,
    /// §7.1's `acr_values`, most preferred first.
    pub acr_values: Vec<String>,
    /// §7.1's `binding_message`, in the clear because it is displayed.
    pub binding_message: Option<String>,
    /// §4's delivery mode, copied onto the row: a registration that changes
    /// after the request must not change how the request is answered.
    pub delivery_mode: String,
    /// What the §10.2 notification will present, in ping mode. `None` in
    /// poll mode, where nothing is ever posted. The store digests the token
    /// for the `*_hash` column and seals both values for the worker.
    pub ping: Option<PingCredentials>,
    /// §7.3's `expires_in`, as an instant.
    pub expires_at: OffsetDateTime,
    /// §7.3's `interval`, as this request starts out.
    pub interval: Duration,
}

/// What a poll of the token endpoint found (§10.1, §11).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum CibaPoll {
    /// Nobody has answered yet: `authorization_pending`.
    Pending,
    /// The client polled faster than the interval it was given: `slow_down`.
    /// The stored interval has been raised, so the value here is the one the
    /// client must now use.
    SlowDown {
        /// The new interval.
        interval: Duration,
    },
    /// The client polled too fast *again*, after every `slow_down` it is
    /// allowed: `invalid_request`, and it "MUST stop polling". The interval is
    /// not raised further — it is already at the ceiling — and the row is
    /// otherwise untouched, so a client that does stop and comes back after
    /// its interval is judged normally.
    TooFast,
    /// Somebody approved it. Redeemable exactly once, by [`redeem`].
    ///
    /// [`redeem`]: PgCibaRequestRepository::redeem
    Approved,
    /// Somebody refused it: `access_denied`.
    Denied,
    /// It ran out before anybody answered: `expired_token`.
    Expired,
    /// It has already been redeemed. Answered as an unknown `auth_req_id`
    /// (§10.1.1: "no longer valid"), for the reason the device flow gives.
    Spent,
}

/// One poll, and whose request it was.
///
/// The client is returned with every state rather than only with an approval,
/// so that the token endpoint can refuse another client's `auth_req_id` before
/// it acts on what the state says (§10.1: the OP "MUST check whether the
/// `auth_req_id` was issued to this Client").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CibaPolled {
    /// The client the request was issued to.
    pub client_id: String,
    /// What the poll found.
    pub state: CibaPoll,
}

/// An approved request, spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedeemedCiba {
    /// The client the request was issued to. Compared against the client that
    /// authenticated, which is what stops one client redeeming another's.
    pub client_id: String,
    /// The authorization the approval created.
    pub grant_id: GrantId,
}

/// What the ping worker needs to post one §10.2 notification.
///
/// Opened from the seal on demand and never held anywhere else; the `Debug`
/// renders neither credential.
#[derive(Clone)]
pub struct PingTarget {
    /// The client to notify, for the trail.
    pub client_id: String,
    /// When it was already notified, if it was — a retry after a lost ack
    /// must not post twice.
    pub notified_at: Option<OffsetDateTime>,
    /// What to present.
    pub credentials: PingCredentials,
}

impl std::fmt::Debug for PingTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PingTarget")
            .field("client_id", &self.client_id)
            .field("notified_at", &self.notified_at)
            .finish_non_exhaustive()
    }
}

/// Backchannel authentication requests for one tenant.
#[derive(Clone)]
pub struct PgCibaRequestRepository {
    pool: PgPool,
    tenant: TenantId,
    kek: Arc<dyn Kek>,
}

impl std::fmt::Debug for PgCibaRequestRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgCibaRequestRepository")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl PgCibaRequestRepository {
    /// Scopes a repository to `tenant`.
    ///
    /// `kek` is what seals and opens a ping request's credentials; see
    /// [`asterius_jose::RowSecret::CibaPing`].
    #[must_use]
    pub const fn new(pool: PgPool, tenant: TenantId, kek: Arc<dyn Kek>) -> Self {
        Self { pool, tenant, kek }
    }

    fn digest_bytes(digest: &str) -> Result<Vec<u8>, DomainError> {
        hex::decode(digest).map_err(|error| DomainError::invalid("auth_req_id", error.to_string()))
    }

    fn binding<'a>(&'a self, auth_req_id_digest: &'a str) -> KeyBinding<'a> {
        KeyBinding::row_secret(&self.tenant, RowSecret::CibaPing, auth_req_id_digest)
    }

    /// Seals what the notification will present, bound to this row.
    async fn seal(
        &self,
        auth_req_id_digest: &str,
        credentials: &PingCredentials,
    ) -> Result<WrappedKey, DomainError> {
        let plaintext = serde_json::json!({
            "auth_req_id": credentials.auth_req_id,
            "client_notification_token": credentials.client_notification_token,
        })
        .to_string();
        self.kek
            .wrap(self.binding(auth_req_id_digest), plaintext.as_bytes())
            .await
            .map_err(|e| DomainError::Storage(Box::new(e)))
    }

    /// Opens a stored envelope.
    ///
    /// A row that does not open is an error and never a notification sent
    /// without its credential: §10.2 makes the bearer mandatory, and a
    /// callback that dropped it would be refused by the client and look like
    /// the client's fault.
    async fn open(
        &self,
        auth_req_id_digest: &str,
        sealed: WrappedKey,
    ) -> Result<PingCredentials, DomainError> {
        let plaintext = self
            .kek
            .unwrap(self.binding(auth_req_id_digest), &sealed)
            .await
            .map_err(|e| DomainError::Storage(Box::new(e)))?;
        let malformed = || {
            DomainError::invalid(
                "ciba_requests.ping_ciphertext",
                "a stored ping credential is not the shape this server seals",
            )
        };
        let document: serde_json::Value =
            serde_json::from_slice(&plaintext).map_err(|_| malformed())?;
        let field = |name: &str| {
            document
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(malformed)
        };
        Ok(PingCredentials {
            auth_req_id: field("auth_req_id")?,
            client_notification_token: field("client_notification_token")?,
        })
    }

    /// Records a backchannel authentication request (§7.1, §7.3).
    ///
    /// The `auth_req_id` is handed in as a digest and never as itself, except
    /// inside [`NewCibaRequest::ping`] where the notification will need it —
    /// and that copy reaches the row sealed.
    ///
    /// # Errors
    ///
    /// [`DomainError::Invalid`] when the digest is not hexadecimal or the
    /// interval is not a number of seconds — both of which are bugs in the
    /// caller rather than anything a client sent. [`DomainError::Conflict`]
    /// when the digest is already in this tenant, which for a 256-bit value
    /// means a broken generator. [`DomainError::Storage`] otherwise, including
    /// a KEK that would not seal.
    pub async fn issue(
        &self,
        auth_req_id_digest: &str,
        request: &NewCibaRequest,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let auth_req_id = Self::digest_bytes(auth_req_id_digest)?;
        let interval = i32::try_from(request.interval.whole_seconds())
            .map_err(|_| DomainError::invalid("interval", "is not a number of seconds"))?;
        let notification_hash = request.ping.as_ref().map(|ping| {
            hex::decode(sha256_hex(ping.client_notification_token.as_bytes())).unwrap_or_default()
        });
        let sealed = match &request.ping {
            Some(credentials) => Some(self.seal(auth_req_id_digest, credentials).await?),
            None => None,
        };

        sqlx::query!(
            "insert into ciba_requests
                 (tenant_id, auth_req_id_hash, client_id, user_id, scopes,
                  authorization_details, acr_values, binding_message, delivery_mode,
                  client_notification_token_hash, issued_at, expires_at,
                  poll_interval_seconds, ping_ciphertext, ping_nonce, ping_kek_id)
             values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
            self.tenant.as_str(),
            auth_req_id,
            request.client_id,
            request.user_id.as_uuid(),
            &request.scopes,
            request.authorization_details,
            &request.acr_values,
            request.binding_message.as_deref(),
            request.delivery_mode,
            notification_hash.as_deref(),
            now,
            request.expires_at,
            interval,
            sealed.as_ref().map(WrappedKey::ciphertext),
            sealed.as_ref().map(WrappedKey::nonce),
            sealed.as_ref().map(WrappedKey::kek_id),
        )
        .execute(&self.pool)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(db) if db.is_unique_violation() => DomainError::Conflict(
                "backchannel authentication request already exists".to_owned(),
            ),
            _ => to_domain_error(error),
        })?;
        Ok(())
    }

    /// One poll of the token endpoint (§10.1, §11).
    ///
    /// The stamp and the interval are written in the same statement that
    /// returns the values the decision is made from, so the "was this too
    /// fast?" comparison and the record of this poll cannot be separated by
    /// another poll. The shape is the device flow's; what is added is the
    /// `ceiling`: a row whose interval has already been raised to it is a
    /// client that has ignored every `slow_down` it is allowed
    /// (`asterius_oidc::ciba::MAX_SLOW_DOWNS`), and a further poll inside the
    /// interval is [`CibaPoll::TooFast`]
    /// rather than another raise. Both numbers are handed in rather than
    /// written here: the protocol constants live in `asterius-oidc`.
    ///
    /// A poll of an *approved* request is never `slow_down`: the answer is
    /// ready, and making the client wait longer for a decision already made
    /// would delay a token for no reason. The interval is still stamped, so a
    /// client that then polls again is judged normally.
    ///
    /// Only the client the request was issued to leaves a stamp. The row is
    /// still returned for anybody else — with the owner's `client_id`, so the
    /// caller can refuse (§10.1) — but a stranger's poll must not raise the
    /// owner's interval or be the "previous poll" the owner is judged against:
    /// otherwise any client of the tenant could throttle another's flow by
    /// polling it.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. Never read
    /// that as `Ok(None)`: an unavailable database is not permission to
    /// refuse a legitimate client or to forget that one is polling too fast.
    pub async fn poll(
        &self,
        auth_req_id_digest: &str,
        client_id: &str,
        slow_down: Duration,
        ceiling: Duration,
        now: OffsetDateTime,
    ) -> Result<Option<CibaPolled>, DomainError> {
        let auth_req_id = Self::digest_bytes(auth_req_id_digest)?;
        let seconds = |duration: Duration| {
            i32::try_from(duration.whole_seconds())
                .map_err(|_| DomainError::invalid("interval", "is not a number of seconds"))
        };
        let increment = seconds(slow_down)?;
        let ceiling = seconds(ceiling)?;

        let row = sqlx::query!(
            "with target as (
                 select auth_req_id_hash, client_id, status, expires_at,
                        redeemed_at, last_polled_at, poll_interval_seconds
                   from ciba_requests
                  where tenant_id = $1 and auth_req_id_hash = $2
                    for update
             ),
             stamped as (
                 update ciba_requests as c
                    set last_polled_at = $3,
                        poll_interval_seconds = case
                            when t.status <> 'approved'
                             and t.last_polled_at is not null
                             and t.poll_interval_seconds < $5
                             and $3 < t.last_polled_at
                                      + make_interval(secs => t.poll_interval_seconds)
                            then least(t.poll_interval_seconds + $4, $5)
                            else t.poll_interval_seconds
                        end
                   from target as t
                  where c.tenant_id = $1 and c.auth_req_id_hash = t.auth_req_id_hash
                    and t.client_id = $6
              returning c.poll_interval_seconds as new_interval
             )
             select t.client_id, t.status, t.expires_at, t.redeemed_at,
                    t.last_polled_at, t.poll_interval_seconds,
                    s.new_interval as \"new_interval?\"
               from target as t left join stamped as s on true",
            self.tenant.as_str(),
            auth_req_id,
            now,
            increment,
            ceiling,
            client_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        let Some(row) = row else {
            return Ok(None);
        };

        // Only the owner was stamped; for anybody else the interval is what
        // it was, and the state below is never acted on by the caller.
        let new_interval = row.new_interval.unwrap_or(row.poll_interval_seconds);
        let too_fast = row.last_polled_at.is_some_and(|previous| {
            // §11: "polling too frequently". Measured against the interval the
            // row held *before* this poll, which is the one the client was
            // told to use.
            now < previous + Duration::seconds(i64::from(row.poll_interval_seconds))
        });
        let state = if row.expires_at <= now {
            // Expiry first, and before the rate check: a client that keeps
            // polling a request nobody answered must be told it is over, not
            // told to slow down.
            CibaPoll::Expired
        } else if row.redeemed_at.is_some() {
            CibaPoll::Spent
        } else if row.status == "approved" {
            CibaPoll::Approved
        } else if row.status == "denied" {
            CibaPoll::Denied
        } else if too_fast && row.poll_interval_seconds >= ceiling {
            CibaPoll::TooFast
        } else if too_fast {
            CibaPoll::SlowDown {
                interval: Duration::seconds(i64::from(new_interval)),
            }
        } else {
            CibaPoll::Pending
        };

        Ok(Some(CibaPolled {
            client_id: row.client_id,
            state,
        }))
    }

    /// Spends an approved request, once (§10.1.1: after the tokens are
    /// issued the `auth_req_id` "is no longer valid").
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
        auth_req_id_digest: &str,
        now: OffsetDateTime,
    ) -> Result<Option<RedeemedCiba>, DomainError> {
        let auth_req_id = Self::digest_bytes(auth_req_id_digest)?;
        let row = sqlx::query!(
            "update ciba_requests
                set redeemed_at = $3
              where tenant_id = $1 and auth_req_id_hash = $2
                and status = 'approved' and redeemed_at is null and expires_at > $3
          returning client_id, grant_id",
            self.tenant.as_str(),
            auth_req_id,
            now,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;

        Ok(row.and_then(|row| {
            // A grant deleted between the approval and the redemption leaves
            // the column null (`on delete set null`); that is "not redeemable"
            // rather than a token minted from an authorization that no longer
            // exists.
            row.grant_id.map(|grant| RedeemedCiba {
                client_id: row.client_id,
                grant_id: GrantId::new(grant.to_string()),
            })
        }))
    }

    /// Approves a pending request, binding it to the grant the approval
    /// created, and queues the §10.2 notification if the client is to be
    /// pinged.
    ///
    /// `false` means there was nothing pending and live to approve — which is
    /// the answer a second submission of the same form gets, so the grant the
    /// first one created is not joined by another and the client is not
    /// pinged twice.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. Nothing was
    /// written: the decision and its notification commit together or not at
    /// all.
    pub async fn approve(
        &self,
        auth_req_id_digest: &str,
        grant: &GrantId,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let auth_req_id = Self::digest_bytes(auth_req_id_digest)?;
        let grant_id = crate::grants::uuid(grant)?;
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let moved = sqlx::query!(
            "update ciba_requests
                set status = 'approved', grant_id = $3, approved_at = $4
              where tenant_id = $1 and auth_req_id_hash = $2
                and status = 'pending' and expires_at > $4
          returning client_id, delivery_mode",
            self.tenant.as_str(),
            auth_req_id,
            grant_id,
            now,
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        let Some(moved) = moved else {
            return Ok(false);
        };
        if moved.delivery_mode == "ping" {
            self.queue_ping(&mut transaction, auth_req_id_digest, &moved.client_id, now)
                .await?;
        }
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(true)
    }

    /// Refuses a pending request (§11's `access_denied`), and queues the §10.2
    /// notification if the client is to be pinged: the ping is sent "after a
    /// successful *or failed* end-user authentication".
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached. Nothing was
    /// written.
    pub async fn deny(
        &self,
        auth_req_id_digest: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let auth_req_id = Self::digest_bytes(auth_req_id_digest)?;
        let mut transaction = self.pool.begin().await.map_err(to_domain_error)?;
        let moved = sqlx::query!(
            "update ciba_requests
                set status = 'denied'
              where tenant_id = $1 and auth_req_id_hash = $2
                and status = 'pending' and expires_at > $3
          returning client_id, delivery_mode",
            self.tenant.as_str(),
            auth_req_id,
            now,
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(to_domain_error)?;
        let Some(moved) = moved else {
            return Ok(false);
        };
        if moved.delivery_mode == "ping" {
            self.queue_ping(&mut transaction, auth_req_id_digest, &moved.client_id, now)
                .await?;
        }
        transaction.commit().await.map_err(to_domain_error)?;
        Ok(true)
    }

    /// Queues the `ciba.ping` outbox row inside the decision's transaction.
    ///
    /// The destination is the client's *current*
    /// `backchannel_client_notification_endpoint`: the mode was frozen onto
    /// the row when the request arrived (§4), but the URL is the client's to
    /// move, and a callback to an address it has since left would reach whoever
    /// holds it now. A ping client that no longer registers an endpoint at all
    /// is not notified — there is nowhere to post — and is left to poll, which
    /// §10.2 has it do anyway.
    ///
    /// The payload names the row by digest and carries no credential; the
    /// worker opens the seal when it delivers.
    async fn queue_ping(
        &self,
        transaction: &mut PgTransaction<'_>,
        auth_req_id_digest: &str,
        client_id: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let endpoint = sqlx::query_scalar!(
            "select backchannel_client_notification_endpoint
               from clients
              where tenant_id = $1 and client_id = $2",
            self.tenant.as_str(),
            client_id,
        )
        .fetch_optional(&mut **transaction)
        .await
        .map_err(to_domain_error)?
        .flatten();
        let Some(endpoint) = endpoint else {
            tracing::warn!(
                tenant = %self.tenant,
                client = client_id,
                "a ping-mode backchannel request was decided, but the client no longer \
                 registers a notification endpoint; it is left to poll"
            );
            return Ok(());
        };
        let entry = NewOutboxEntry::new(
            PING_OUTBOX_KIND,
            &endpoint,
            serde_json::json!({ "request": auth_req_id_digest }),
        );
        enqueue(transaction, &self.tenant, &entry, now).await?;
        Ok(())
    }

    /// What the ping worker needs for one row: the client, whether it was
    /// already notified, and the two credentials, opened.
    ///
    /// `Ok(None)` for a row that does not exist, was swept, or is not a ping
    /// request — all of which are a row the worker has nothing to do for.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached or the seal
    /// did not open.
    pub async fn for_notification(
        &self,
        auth_req_id_digest: &str,
    ) -> Result<Option<PingTarget>, DomainError> {
        let auth_req_id = Self::digest_bytes(auth_req_id_digest)?;
        let row = sqlx::query!(
            "select client_id, notified_at, ping_ciphertext, ping_nonce, ping_kek_id
               from ciba_requests
              where tenant_id = $1 and auth_req_id_hash = $2 and delivery_mode = 'ping'",
            self.tenant.as_str(),
            auth_req_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(to_domain_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let sealed = match (row.ping_kek_id, row.ping_nonce, row.ping_ciphertext) {
            (Some(kek_id), Some(nonce), Some(ciphertext)) => {
                WrappedKey::from_parts(kek_id, nonce, ciphertext)
                    .map_err(|e| DomainError::Storage(Box::new(e)))?
            }
            _ => {
                return Err(DomainError::invalid(
                    "ciba_requests.ping_ciphertext",
                    "a ping request is missing part of its envelope",
                ));
            }
        };
        let credentials = self.open(auth_req_id_digest, sealed).await?;
        Ok(Some(PingTarget {
            client_id: row.client_id,
            notified_at: row.notified_at,
            credentials,
        }))
    }

    /// Records that the §10.2 notification was posted and accepted, so that a
    /// redelivery of the same outbox row does not post it again.
    ///
    /// `false` if the row is gone or was already marked.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the store could not be reached.
    pub async fn mark_notified(
        &self,
        auth_req_id_digest: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let auth_req_id = Self::digest_bytes(auth_req_id_digest)?;
        let done = sqlx::query!(
            "update ciba_requests
                set notified_at = $3
              where tenant_id = $1 and auth_req_id_hash = $2
                and delivery_mode = 'ping' and notified_at is null",
            self.tenant.as_str(),
            auth_req_id,
            now,
        )
        .execute(&self.pool)
        .await
        .map_err(to_domain_error)?;
        Ok(done.rows_affected() == 1)
    }
}
