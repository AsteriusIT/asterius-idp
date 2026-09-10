//! Fixed-window counters, and the login limits built out of them.
//!
//! # Why the state is in the database
//!
//! A counter in process memory limits nothing on a deployment with two
//! replicas: an attacker who reconnects lands on the other one and starts from
//! zero, and the limit an operator configured is silently multiplied by the
//! replica count. ADR-0008 makes the same argument about the pairwise-salt
//! cache, where a per-process view is exact within one process and useless
//! between replicas. There is no Redis to reach for (ADR-0001: one binary, one
//! PostgreSQL), so the window counters live in the `rate_limits` table, behind
//! [`RateLimitStore`], and the increment is one atomic statement.
//!
//! # Fixed windows, not sliding ones
//!
//! A fixed window admits at most `2 × max` attempts across a window boundary,
//! which for online guessing is a rounding error against the numbers involved:
//! ten attempts per quarter hour versus twenty in the worst-aligned quarter
//! hour is not the difference between safe and unsafe. What it buys is a
//! counter that is one row and one statement rather than a list of timestamps
//! per bucket, which matters when the store is the same database that is
//! serving the login.
//!
//! # The account bucket is keyed by what was typed
//!
//! [`account_bucket`] hashes the *submitted* username, not a resolved account
//! id — because there may be no account, and a limiter that only counts
//! attempts against accounts that exist is an enumeration oracle wearing a
//! limiter's clothes: ten wrong guesses lock a real account and do nothing at
//! all for an invented one, and the attacker reads the difference off the
//! response. Keying by the typed string makes "locked out" and "no such user"
//! the same observable, which is the property NIST SP 800-63B §5.2.2 asks for
//! in throttling and OWASP ASVS V2.2 asks for in the messages.
//!
//! The username is normalised before it is hashed so that `Alice `, `alice`
//! and a full-width `ａlice` share one bucket. Without that, case is a free
//! bypass of the account limit.

use crate::error::DomainError;
use crate::ids::TenantId;
use std::fmt::Debug;
use time::{Duration, OffsetDateTime};
use unicode_normalization::UnicodeNormalization as _;

/// A counter key: what is being limited, for whom.
///
/// A newtype rather than a `String` so that a caller cannot pass a username
/// where a bucket is wanted. It is opaque and never rendered to a client: the
/// account form contains a digest precisely so that the table does not become
/// a list of the usernames people have failed to sign in as.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bucket(String);

impl Bucket {
    /// The key as it is stored.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Bucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The bucket for failed sign-ins from one client address.
///
/// The address must be the one resolved from the socket peer and the trusted
/// proxy set, never a header taken at face value: a client that can choose the
/// address can choose its own bucket, and the limit stops limiting anything.
#[must_use]
pub fn ip_bucket(ip: std::net::IpAddr) -> Bucket {
    Bucket(format!("login:ip:{ip}"))
}

/// The bucket for one client address at the admin API (`ast-f7m.1`).
///
/// Deliberately its own prefix rather than a share of [`ip_bucket`]'s: an
/// administrator working through the console and an attacker guessing
/// passwords at the login form are not the same traffic, and one limit for
/// both would let a burst of failed sign-ins lock an operator out of the
/// surface they need to respond with — or, the other way round, spend the
/// login budget on ordinary console use.
///
/// Not a [`LimitedEndpoint`] either, and that is the same argument once more.
/// That enum is the *protocol* surface a client reaches, whose limits an
/// operator tunes against traffic they do not control; `/admin/api` is one
/// first-party console making many small calls per screen, and its number
/// bounds something else entirely. A shared enum would be one name for two
/// decisions.
#[must_use]
pub fn admin_api_bucket(ip: std::net::IpAddr) -> Bucket {
    Bucket(format!("admin:ip:{ip}"))
}

/// The bucket for failed sign-ins against one typed identifier.
///
/// The identifier is normalised (see [`normalise_username`]) and then hashed,
/// so the stored key is fixed-length and says nothing about who was targeted.
#[must_use]
// fuzz-target: login_bucket
pub fn account_bucket(username: &str) -> Bucket {
    Bucket(format!(
        "login:account:{}",
        crate::credentials::sha256_hex(normalise_username(username).as_bytes())
    ))
}

/// Folds the variations of one typed identifier onto one key.
///
/// NFKC first, then lowercase, then trim — in that order, because
/// compatibility composition can produce characters that are themselves
/// uppercase or whitespace (`ﬀ`, the ideographic space), and folding them
/// after the case pass would leave two spellings in different buckets.
/// Lowercasing is `to_lowercase`, not `to_ascii_lowercase`: an attacker's
/// script does not restrict itself to ASCII.
///
/// This is a *bucketing* key and never a lookup key. The credential lookup
/// still uses the string as typed, so nothing here changes which account a
/// password is checked against.
/// The composition and the case pass are repeated to a fixed point, because
/// one pass of each does not reach one: `J` followed by a combining caron has
/// no precomposed form, so NFKC leaves it alone; lowercasing gives `j` plus
/// the mark, and *that* composes to `ǰ`. Computing the key a second time would
/// otherwise land in a different bucket from the first, which is a limit that
/// can be walked out of by whoever notices.
///
/// Bounded rather than looped until stable: both passes are stabilising, so
/// Unicode converges on the second, and a bound is what keeps a value from the
/// network out of the loop condition.
#[must_use]
pub fn normalise_username(username: &str) -> String {
    /// Enough for the convergence above, with room to spare.
    const MAX_FOLDING_PASSES: usize = 4;

    let mut folded = username.to_owned();
    for _ in 0..MAX_FOLDING_PASSES {
        let next = folded.nfkc().collect::<String>().to_lowercase();
        if next == folded {
            break;
        }
        folded = next;
    }
    folded.trim().to_owned()
}

/// How many events one bucket may hold, and over how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Events permitted per window. Zero refuses everything, which is a
    /// legitimate way to switch a method off.
    pub max: u32,
    /// How long a window lasts.
    pub window: Duration,
}

impl RateLimit {
    /// The start of the window `now` falls in.
    ///
    /// Windows are aligned to the epoch rather than to first use, so every
    /// replica computes the same boundary from the same clock without
    /// coordinating. A non-positive window degenerates to a single window
    /// starting at `now`; configuration cannot produce one — the validator has
    /// a floor — and defining it here is better than dividing by zero.
    #[must_use]
    pub fn window_start(&self, now: OffsetDateTime) -> OffsetDateTime {
        let seconds = self.window.whole_seconds();
        if seconds <= 0 {
            return now;
        }
        let elapsed = now.unix_timestamp().rem_euclid(seconds);
        now - Duration::seconds(elapsed)
    }

    /// When the window `now` falls in ends, which is when the counter resets.
    #[must_use]
    pub fn window_end(&self, now: OffsetDateTime) -> OffsetDateTime {
        self.window_start(now) + self.window.max(Duration::seconds(1))
    }

    /// Whether a bucket already holding `counted` events may hold one more.
    #[must_use]
    pub const fn admits(&self, counted: u32) -> bool {
        counted < self.max
    }

    /// How long until the current window rolls over, at least one second.
    ///
    /// The floor is there because this is shown to a person and sent as
    /// `Retry-After`: "try again in 0 seconds" is worse than saying nothing.
    #[must_use]
    pub fn retry_after(&self, now: OffsetDateTime) -> Duration {
        (self.window_end(now) - now).max(Duration::seconds(1))
    }
}

/// What a limiter decided about one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The attempt may proceed.
    Allowed,
    /// The attempt is refused until the window rolls over.
    Throttled {
        /// Which limit was reached, for the metric and the audit record.
        scope: Scope,
        /// How long until that window rolls over. Reported to the client as a
        /// hint, and never less than a second so that it is not a misleading
        /// "0".
        retry_after: Duration,
    },
}

/// Which of the two login limits an attempt ran into.
///
/// Both are needed and they stop different attacks: the account limit bounds
/// the guessing of one password, and the address limit bounds a sweep across
/// many accounts, which the account limit never sees because no single account
/// is tried twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// Too many failures from one client address.
    Address,
    /// Too many failures against one typed identifier.
    Account,
    /// Too many requests to one endpoint from one authenticated client
    /// (`ast-p2l.3`).
    Client,
}

impl Scope {
    /// The label used in metrics and audit details.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Address => "ip",
            Self::Account => "account",
            Self::Client => "client",
        }
    }
}

/// The two limits a login is subject to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginLimits {
    /// Failures permitted from one client address.
    pub per_address: RateLimit,
    /// Failures permitted against one typed identifier.
    pub per_account: RateLimit,
}

/// Where fixed-window counters live.
///
/// Two methods rather than one "check and increment": a login is limited by
/// its *failures*, so the read happens before the credential is verified and
/// the write only if it did not verify. Collapsing them would count every
/// successful sign-in against the limit.
///
/// Deliberately general — a bucket is a string and a window is a timestamp —
/// so that `ast-p2l.3` can limit other endpoints through the same port and the
/// same table rather than growing a second limiter.
#[async_trait::async_trait]
pub trait RateLimitStore: Debug + Send + Sync {
    /// How many events `bucket` holds in the window starting at
    /// `window_start`.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the read fails.
    async fn count(
        &self,
        tenant: &TenantId,
        bucket: &Bucket,
        window_start: OffsetDateTime,
    ) -> Result<u32, DomainError>;

    /// Counts one event in that window, returning the new total.
    ///
    /// `expires_at` is when the row stops meaning anything and retention may
    /// sweep it.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the write fails.
    async fn record(
        &self,
        tenant: &TenantId,
        bucket: &Bucket,
        window_start: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<u32, DomainError>;

    /// Forgets every window of `bucket`, so the next read counts zero.
    ///
    /// The operation a *successful* authentication needs (`ast-b3u`). A fixed
    /// window does not forget on its own: somebody who mistypes nine times and
    /// then signs in correctly would otherwise spend the rest of the window one
    /// attempt away from being locked out, having just proved they are who the
    /// counter is about. Clearing is what makes the counter measure "attempts
    /// since the last proof" rather than "attempts this quarter hour".
    ///
    /// Every window, not just the current one, because the boundary is aligned
    /// to the epoch: a proof a second before a rollover must not leave a
    /// counter that the next request inherits.
    ///
    /// A caller must only reach this after a credential actually verified.
    /// Clearing on a refusal — including the refusal that means "no such
    /// identifier" — would make the reset observable, and a limiter whose state
    /// differs between a real account and an invented one is the enumeration
    /// oracle the account bucket exists to close.
    ///
    /// # Errors
    ///
    /// [`DomainError::Storage`] if the delete fails.
    async fn clear(&self, tenant: &TenantId, bucket: &Bucket) -> Result<(), DomainError>;
}

// ---------------------------------------------------------------------------
// Per-endpoint request limits (`ast-p2l.3`)
// ---------------------------------------------------------------------------

/// An endpoint whose *requests* are counted, rather than its failures.
///
/// A closed set rather than a string, for two reasons. It is a metric label,
/// and a label a caller could choose is a way to mint time series; and it is
/// half of a bucket key, so a free-form name would let one endpoint's counter
/// be spent from another's.
///
/// The set is the endpoints that are both built and reachable without having
/// already passed a limiter. `/authorize` and `/interaction` are absent
/// deliberately: the sign-in they lead to is bounded by the login limiter
/// (`ast-2vk.9`), and a second counter over the same requests would silently
/// halve a number an operator configured once. `/introspect` is absent because
/// it is not built — it answers 501 — and limiting a constant answer limits
/// nothing.
///
/// `/revoke` is built (`ast-1sk.2`) and is *not* limited yet, which is a gap
/// rather than a decision: it authenticates its caller with a signature
/// verification, so a flood of unauthenticated requests to it costs the same
/// as one at `/token`. Adding it here means adding a field to
/// [`EndpointLimits`], a key to the configuration surface and a default an
/// operator can read, which is a change to that surface rather than to this
/// endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LimitedEndpoint {
    /// `POST /register` — RFC 7591 dynamic client registration.
    Registration,
    /// `GET`/`PUT`/`DELETE /register/{client_id}` — RFC 7592.
    ClientConfiguration,
    /// `POST /par` — RFC 9126.
    PushedAuthorizationRequest,
    /// `POST /token` — RFC 6749 §3.2.
    Token,
    /// `GET`/`POST /userinfo` — OIDC Core §5.3.
    UserInfo,
}

impl LimitedEndpoint {
    /// Every endpoint that has limits, so a caller can iterate over them
    /// without writing the list a second time.
    pub const ALL: [Self; 5] = [
        Self::Registration,
        Self::ClientConfiguration,
        Self::PushedAuthorizationRequest,
        Self::Token,
        Self::UserInfo,
    ];

    /// The name used in bucket keys, metric labels and audit details.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::ClientConfiguration => "client_configuration",
            Self::PushedAuthorizationRequest => "par",
            Self::Token => "token",
            Self::UserInfo => "userinfo",
        }
    }
}

impl std::fmt::Display for LimitedEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The bucket for requests to one endpoint from one client address.
///
/// Namespaced per endpoint, so that a busy `/token` cannot spend the budget
/// `/register` was given: the two numbers bound different abuse and would
/// otherwise be one number.
///
/// The address must be the one resolved from the socket peer and the trusted
/// proxy set, for the reason [`ip_bucket`] gives: a caller who can choose the
/// address can choose its own bucket.
#[must_use]
pub fn endpoint_address_bucket(endpoint: LimitedEndpoint, ip: std::net::IpAddr) -> Bucket {
    Bucket(format!("ep:{}:ip:{ip}", endpoint.as_str()))
}

/// The bucket for requests to one endpoint from one *authenticated* client.
///
/// Hashed, like [`account_bucket`] and for two of the same reasons. A
/// `client_id` arrives in a request body and may be a megabyte long, and a key
/// derived from it has to stay a bounded row; and a raw id could contain the
/// separator, so `client_id = "x:ip:198.51.100.7"` would otherwise name an
/// address bucket. A client id is not a secret — the digest hides nothing
/// anybody wants — but a fixed-length opaque key cannot be made to name a
/// bucket it should not.
#[must_use]
// fuzz-target: endpoint_bucket
pub fn endpoint_client_bucket(endpoint: LimitedEndpoint, client_id: &str) -> Bucket {
    Bucket(format!(
        "ep:{}:client:{}",
        endpoint.as_str(),
        crate::credentials::sha256_hex(client_id.as_bytes())
    ))
}

/// The marker that says "this bucket has already been written to the trail in
/// this window".
///
/// A counter of its own rather than a flag on the first one, because the
/// counter it shadows keeps rising while an attacker keeps knocking, and the
/// trail is to hold one record per window rather than one per request: a trail
/// an attacker can grow without bound is a way to bury everything else in it.
/// [`RateLimitStore::record`] returns the new total, so "is this the first
/// refusal in this window" is the answer `1`.
#[must_use]
pub fn audited_once_bucket(bucket: &Bucket) -> Bucket {
    Bucket(format!("audited:{}", bucket.0))
}

/// What one endpoint permits, per window.
///
/// The address limit always exists. The client limit exists only where a
/// request can prove which client it belongs to, and where it does, a
/// *successful* request is charged there instead of to the address — which is
/// what keeps one busy legitimate client from spending the budget of every
/// other caller behind the same NAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointLimit {
    /// Requests permitted from one client address.
    pub per_address: RateLimit,
    /// Requests permitted from one authenticated client, where the endpoint
    /// has one to charge.
    pub per_client: Option<RateLimit>,
}

/// Every endpoint's limits, as one deployment configured them.
///
/// A field per endpoint rather than a map: a map can be missing an entry, and
/// a missing entry is an unlimited endpoint that nothing would report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointLimits {
    /// `POST /register`.
    pub registration: EndpointLimit,
    /// The RFC 7592 client configuration endpoint.
    pub client_configuration: EndpointLimit,
    /// `POST /par`.
    pub par: EndpointLimit,
    /// `POST /token`.
    pub token: EndpointLimit,
    /// UserInfo.
    pub userinfo: EndpointLimit,
}

impl EndpointLimits {
    /// The limits one endpoint is subject to.
    #[must_use]
    pub const fn for_endpoint(&self, endpoint: LimitedEndpoint) -> EndpointLimit {
        match endpoint {
            LimitedEndpoint::Registration => self.registration,
            LimitedEndpoint::ClientConfiguration => self.client_configuration,
            LimitedEndpoint::PushedAuthorizationRequest => self.par,
            LimitedEndpoint::Token => self.token,
            LimitedEndpoint::UserInfo => self.userinfo,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("a valid timestamp")
    }

    #[test]
    fn a_window_starts_on_a_boundary_aligned_to_the_epoch() {
        let limit = RateLimit {
            max: 1,
            window: Duration::minutes(15),
        };

        let start = limit.window_start(now());

        assert_eq!(start.unix_timestamp() % (15 * 60), 0);
        assert!(start <= now() && now() < limit.window_end(now()));
    }

    /// Every replica computes the same boundary, which is what makes one
    /// counter in the database mean the same thing to all of them.
    #[test]
    fn two_instants_in_one_window_agree_on_where_it_starts() {
        let limit = RateLimit {
            max: 1,
            window: Duration::minutes(15),
        };

        let early = limit.window_start(limit.window_start(now()));
        let late = limit.window_start(limit.window_end(now()) - Duration::seconds(1));

        assert_eq!(early, late);
    }

    #[test]
    fn a_bucket_at_its_limit_admits_nothing_more() {
        let limit = RateLimit {
            max: 3,
            window: Duration::minutes(1),
        };

        assert!(limit.admits(2));
        assert!(!limit.admits(3));
    }

    #[test]
    fn a_hint_is_never_the_misleading_zero() {
        let limit = RateLimit {
            max: 0,
            window: Duration::minutes(15),
        };
        let last_moment = limit.window_end(now()) - Duration::milliseconds(1);

        let hint = limit.retry_after(last_moment);

        assert!(hint >= Duration::seconds(1));
    }

    /// One pass of NFKC and one of lowercasing do not reach a fixed point:
    /// `J` plus a combining caron composes only once the case pass has made it
    /// a `j`. A key that moves the second time it is computed is a limit that
    /// resets itself.
    #[test]
    fn normalising_a_normalised_identifier_changes_nothing() {
        // Arrange
        let typed = "J\u{30c}";

        // Act
        let once = normalise_username(typed);

        // Assert
        assert_eq!(normalise_username(&once), once);
        assert_eq!(account_bucket(&once), account_bucket(typed));
    }

    #[test]
    fn case_and_width_variants_of_one_identifier_share_a_bucket() {
        let plain = account_bucket("alice");

        assert_eq!(account_bucket("  ALICE "), plain);
        assert_eq!(account_bucket("\u{ff41}lice"), plain);
    }

    /// Two accounts must not share a limit: one locking the other out would be
    /// a denial of service anybody could aim.
    #[test]
    fn different_identifiers_get_different_buckets() {
        assert_ne!(account_bucket("alice"), account_bucket("bob"));
    }

    #[test]
    fn a_bucket_never_carries_the_identifier_it_counts() {
        let bucket = account_bucket("alice@example.test");

        assert!(!bucket.as_str().contains("alice"));
    }

    /// One endpoint's budget must not be spendable from another's, or the
    /// number an operator set for `/register` is really a number about
    /// `/token` too.
    #[test]
    fn two_endpoints_count_one_address_separately() {
        // Arrange
        let address = "198.51.100.7".parse().expect("a literal address");

        // Act
        let registration = endpoint_address_bucket(LimitedEndpoint::Registration, address);
        let token = endpoint_address_bucket(LimitedEndpoint::Token, address);

        // Assert
        assert_ne!(registration, token);
    }

    /// A client id is chosen by whoever registers, so a separator in one must
    /// not be able to name an address bucket.
    #[test]
    fn a_client_id_containing_a_separator_cannot_name_an_address_bucket() {
        // Arrange
        let address = "198.51.100.7".parse().expect("a literal address");
        let hostile = "x:ip:198.51.100.7";

        // Act
        let bucket = endpoint_client_bucket(LimitedEndpoint::Token, hostile);

        // Assert
        assert_ne!(
            bucket,
            endpoint_address_bucket(LimitedEndpoint::Token, address)
        );
        assert!(!bucket.as_str().contains("198.51.100.7"));
    }

    /// A megabyte in `client_id` must not become a megabyte-wide key.
    #[test]
    fn a_client_bucket_is_bounded_whatever_the_client_id_was() {
        // Arrange
        let long = "c".repeat(100_000);

        // Act
        let bucket = endpoint_client_bucket(LimitedEndpoint::PushedAuthorizationRequest, &long);

        // Assert
        assert_eq!(bucket.as_str().len(), "ep:par:client:".len() + 64);
    }

    /// The audit marker shadows a bucket without colliding with it: if it did,
    /// deciding "have I already written this" would consume the budget it is
    /// deciding about.
    #[test]
    fn an_audit_marker_is_not_the_bucket_it_shadows() {
        // Arrange
        let bucket = endpoint_address_bucket(
            LimitedEndpoint::Registration,
            "198.51.100.7".parse().expect("a literal address"),
        );

        // Act
        let marker = audited_once_bucket(&bucket);

        // Assert
        assert_ne!(marker, bucket);
    }

    #[test]
    fn an_address_bucket_is_not_an_account_bucket() {
        let address = ip_bucket("198.51.100.7".parse().expect("a literal address"));

        assert_ne!(address, account_bucket("198.51.100.7"));
    }
}
