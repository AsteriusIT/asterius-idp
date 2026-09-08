//! Client keys: from a registered `jwks` or `jwks_uri` to verifying keys.
//!
//! A client authenticates with a signature — a `private_key_jwt` assertion
//! (`ast-m9c.2`), a signed request object, a CIBA request — and this module
//! answers the question that comes first: *which keys could have made it?*
//!
//! Two registered shapes, one answer. [`JwksSource::Inline`] carries the JWK
//! Set by value; [`JwksSource::Uri`] carries a URL the client controls and the
//! server fetches. OIDC Registration §2 says of `jwks` that "the semantics of
//! the `jwks` parameter are the same as the `jwks_uri` parameter, other than
//! that the JWK Set is passed by value", so both go through one parser and
//! produce one [`ClientKeySet`]. A rule that applied to only one of them —
//! the algorithm allow-list, say — would be a rule a client could opt out of
//! by choosing the other spelling.
//!
//! ## What this module is not
//!
//! It does not fetch. `asterius-jose` has no HTTP client and
//! `scripts/check-layering.sh` will not let it grow one, which is the right
//! answer for a different reason than tidiness: dereferencing a URL an attacker
//! chose is a security decision of its own size — which addresses, which
//! redirects, how many bytes — and it belongs in one place, next to the socket,
//! rather than smuggled into a crate whose job is cryptography. The fetch is
//! [`asterius_domain::ports::JwksFetcher`], implemented in
//! `asterius_server::outbound`, and this module holds it at arm's length behind
//! that port.
//!
//! ## What is filtered out, and why filtering rather than failing
//!
//! A client's JWK Set is a document written by somebody else, and it routinely
//! contains keys that are none of our business: an encryption key, an RSA key
//! for a service that still uses RS256, a key type this server has never
//! supported. [`parse_jwk_set`] therefore *skips* what it cannot use and keeps
//! what it can — one unusable entry must not cost the client every other key it
//! published, because the failure would land at authentication time and look
//! like a broken credential.
//!
//! The exception is private key material. A `d` in a published JWK Set is not a
//! key we should skip past; it means the client has published its private key,
//! and any key in that document is suspect. That set is refused whole.

use crate::verify::KeyResolver;
use crate::{MIN_RSA_BITS, VerifyingKey};
use asterius_domain::ports::JwksFetcher;
use asterius_domain::{ClientId, JwksSource, Kid, SigningAlgorithm, TenantId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use time::{Duration, OffsetDateTime};

/// The largest JWK Set document this server will parse.
///
/// A client's whole key set is a few hundred bytes per key. 64 KiB is room for
/// far more keys than [`MAX_KEYS`] permits, so the cap that actually binds is
/// the key count — this one exists so that a hostile `jwks_uri` serving a
/// gigabyte costs a length comparison rather than a JSON parse.
pub const MAX_JWK_SET_BYTES: usize = 64 * 1024;

/// The most keys one client's JWK Set may contain.
///
/// Every key in the set is a candidate a signature may be checked against, so
/// the set's length is the number of public-key operations one unauthenticated
/// request can ask for. Thirty-two is generous for a client mid-rotation across
/// three algorithms and small enough that the work stays bounded.
pub const MAX_KEYS: usize = 32;

/// How long a fetched JWK Set is used before it is fetched again.
///
/// Rotation does not wait for this: OIDC Core §10.1.1 has the verifier "go back
/// to the `jwks_uri` location to re-retrieve the keys when it sees an
/// unfamiliar `kid` value", which [`ClientKeyCache`] does, rate-limited. The
/// TTL is what picks up a *withdrawn* key — one removed from the set, which no
/// `kid` will ever announce — so it is measured in minutes, not hours.
pub const DEFAULT_TTL: Duration = Duration::minutes(10);

/// How long a failed fetch is remembered.
///
/// Without this, a client whose `jwks_uri` is broken — or pointed at somebody
/// else — turns every request naming that client into an outbound request. The
/// server would be a willing amplifier, and the third party would see the
/// traffic, not the attacker.
pub const DEFAULT_NEGATIVE_TTL: Duration = Duration::seconds(60);

/// The shortest interval between two fetches for one client.
///
/// This is what makes refresh-on-unknown-`kid` safe to offer. A `kid` is chosen
/// by whoever wrote the token, so "refetch when the `kid` is unfamiliar" is an
/// instruction an attacker can issue at will: send assertions with random
/// `kid`s and the server fetches on every one. The rate limit is per client and
/// is checked *before* the fetch starts, so concurrent requests collapse into
/// one attempt rather than each starting their own.
pub const DEFAULT_MIN_REFRESH_INTERVAL: Duration = Duration::seconds(60);

/// The most clients whose keys are cached at once.
///
/// The cache is a convenience, not a store: past this many entries the least
/// recently attempted one is dropped and will simply be fetched again.
pub const DEFAULT_MAX_ENTRIES: usize = 4096;

/// Why client keys could not be produced.
///
/// Deliberately coarse about *fetch* failures: [`ClientKeyError::Unavailable`]
/// covers "the fetch failed", "the fetch was refused by the SSRF guard" and
/// "the last attempt failed recently enough that we did not try again". A
/// caller has the same job in all three cases, and a client that could tell
/// them apart would have a probe for what this server can reach.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClientKeyError {
    /// The document is larger than [`MAX_JWK_SET_BYTES`].
    #[error("JWK Set is {size} bytes, limit is {limit}")]
    TooLarge {
        /// The offered size.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// The document is not a JWK Set (RFC 7517 §5).
    #[error("malformed JWK Set: {0}")]
    Malformed(&'static str),
    /// The set holds more than [`MAX_KEYS`] keys.
    #[error("JWK Set holds {count} keys, limit is {limit}")]
    TooManyKeys {
        /// How many were offered.
        count: usize,
        /// The limit.
        limit: usize,
    },
    /// A key in the set carries private material.
    ///
    /// Not a parse failure — a disclosure. The whole set is refused; see the
    /// module documentation.
    #[error("JWK Set contains private key material")]
    PrivateKeyMaterial,
    /// The client's `jwks_uri` could not be dereferenced.
    #[error("client keys are unavailable")]
    Unavailable,
}

/// One usable key from a client's JWK Set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKey {
    kid: Option<Kid>,
    key: VerifyingKey,
}

impl ClientKey {
    /// The key's `kid`, when the client published one (RFC 7517 §4.5).
    #[must_use]
    pub const fn kid(&self) -> Option<&Kid> {
        self.kid.as_ref()
    }

    /// The verifying key.
    #[must_use]
    pub const fn key(&self) -> &VerifyingKey {
        &self.key
    }

    /// The algorithm this key verifies.
    #[must_use]
    pub const fn algorithm(&self) -> SigningAlgorithm {
        self.key.algorithm()
    }
}

/// A client's usable keys, in the order the client published them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientKeySet {
    keys: Vec<ClientKey>,
}

impl ClientKeySet {
    /// The keys, as parsed.
    #[must_use]
    pub fn keys(&self) -> &[ClientKey] {
        &self.keys
    }

    /// Whether the set produced no usable key at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Whether some key in the set carries this `kid`.
    ///
    /// This is the question that drives refresh-on-miss: a `kid` we have never
    /// seen is the signal OIDC Core §10.1.1 gives a verifier that the signer
    /// has rotated.
    #[must_use]
    pub fn contains(&self, kid: &Kid) -> bool {
        self.keys.iter().any(|key| key.kid.as_ref() == Some(kid))
    }

    /// Every verifying key in the set.
    ///
    /// The shape both registered forms produce: an inline `jwks` and a fetched
    /// `jwks_uri` are indistinguishable from here on.
    #[must_use]
    pub fn verifying_keys(&self) -> Vec<VerifyingKey> {
        self.keys.iter().map(|key| key.key.clone()).collect()
    }
}

impl KeyResolver for ClientKeySet {
    /// Candidate keys for a token bearing this `kid`.
    ///
    /// A `kid` narrows an already-trusted set; it is never followed. When it
    /// matches, only the matches are offered — including several, which is
    /// exactly the case FAPI 2.0 SP §5.4.3 describes and which
    /// [`crate::verify()`] resolves by `alg` and then by trying each.
    ///
    /// When it matches nothing, the keys that carry no `kid` at all are
    /// offered: RFC 7517 §4.5 makes `kid` optional, so an unlabelled key cannot
    /// assert that it is *not* the one meant, and a client with a single
    /// unlabelled key and a `kid` in its header is a real and harmless
    /// combination. Keys labelled with a *different* `kid` are not offered,
    /// because there the client has said which key it means.
    fn candidates(&self, kid: Option<&Kid>) -> Vec<VerifyingKey> {
        let Some(kid) = kid else {
            return self.verifying_keys();
        };
        let matching: Vec<VerifyingKey> = self
            .keys
            .iter()
            .filter(|key| key.kid.as_ref() == Some(kid))
            .map(|key| key.key.clone())
            .collect();
        if matching.is_empty() {
            return self
                .keys
                .iter()
                .filter(|key| key.kid.is_none())
                .map(|key| key.key.clone())
                .collect();
        }
        matching
    }
}

/// Parses a JWK Set document (RFC 7517 §5) into the keys this server can use.
///
/// The bytes are attacker-controlled: they are whatever a client's `jwks_uri`
/// served, or whatever was in its registration document. Nothing here trusts
/// the input's shape.
///
/// # Errors
///
/// Returns [`ClientKeyError`] if the document is too large, is not a JWK Set,
/// holds more than [`MAX_KEYS`] keys, or contains private key material. Keys
/// this server cannot use are skipped, not refused.
// fuzz-target: jwk_set_parse
pub fn parse_jwk_set(raw: &[u8]) -> Result<ClientKeySet, ClientKeyError> {
    // Before parsing: an oversized document should cost a comparison. The
    // fetcher caps the body as it reads it, so reaching this with something
    // huge means it came from storage.
    if raw.len() > MAX_JWK_SET_BYTES {
        return Err(ClientKeyError::TooLarge {
            size: raw.len(),
            limit: MAX_JWK_SET_BYTES,
        });
    }
    let document: Value =
        serde_json::from_slice(raw).map_err(|_| ClientKeyError::Malformed("not JSON"))?;
    keys_from_jwk_set(&document)
}

/// Parses an already-decoded JWK Set.
///
/// The entry point for [`JwksSource::Inline`], whose document was parsed by
/// `serde_json` on the way into storage and comes back as a value rather than
/// as bytes.
///
/// # Errors
///
/// As [`parse_jwk_set`], less the size check — a value is already parsed, so
/// there is no parse to avoid.
pub fn keys_from_jwk_set(document: &Value) -> Result<ClientKeySet, ClientKeyError> {
    let keys = document
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(ClientKeyError::Malformed(
            "must be an object with a `keys` array (RFC 7517 §5)",
        ))?;

    // Counted before anything is decoded, so a set of ten thousand keys costs
    // one length check rather than ten thousand base64 decodes.
    if keys.len() > MAX_KEYS {
        return Err(ClientKeyError::TooManyKeys {
            count: keys.len(),
            limit: MAX_KEYS,
        });
    }

    let mut usable = Vec::new();
    for entry in keys {
        // RFC 7517 §5: "The value of the 'keys' parameter is an array of JWK
        // values." Something that is not an object is not a JWK; skip it rather
        // than refusing the set, on the same reasoning as an unusable key.
        let Some(jwk) = entry.as_object() else {
            continue;
        };
        if let Some(key) = admit(jwk)? {
            usable.push(key);
        }
    }
    Ok(ClientKeySet { keys: usable })
}

/// JWK members that hold private or symmetric key material.
///
/// `d`, `p`, `q`, `dp`, `dq`, `qi` and `oth` are RFC 7518 §6.3.2's private RSA
/// members and §6.2.2's private EC member; `k` is §6.4.1's symmetric key. Any
/// of them in a document a client published means the client has published a
/// secret.
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Decides whether one JWK becomes a usable key.
///
/// `Ok(None)` is "not for us" — a key this server cannot or must not use.
/// `Err` is reserved for the one condition that condemns the whole document.
fn admit(jwk: &Map<String, Value>) -> Result<Option<ClientKey>, ClientKeyError> {
    if PRIVATE_MEMBERS
        .iter()
        .any(|member| jwk.contains_key(*member))
    {
        return Err(ClientKeyError::PrivateKeyMaterial);
    }

    // RFC 7517 §4.2: `use` identifies the intended use of the *public* key.
    // Absent means unrestricted, so absent is usable; `enc` is not. FAPI 2.0 SP
    // §6.8 item 2's separation of signing and encryption keys is only real if
    // the declared use is honoured.
    if jwk
        .get("use")
        .is_some_and(|declared| declared.as_str() != Some("sig"))
    {
        return Ok(None);
    }

    // RFC 7517 §4.3: when `key_ops` is present it enumerates the permitted
    // operations, and checking a signature is `verify`.
    if let Some(operations) = jwk.get("key_ops") {
        let permitted = operations
            .as_array()
            .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some("verify")));
        if !permitted {
            return Ok(None);
        }
    }

    let Some(kty) = jwk.get("kty").and_then(Value::as_str) else {
        return Ok(None);
    };

    // RFC 8725 §3.1: the algorithm is decided by the verifier from what it
    // already knows. Here that is the key's own type and, when the client
    // published one, its `alg` — never the token's header. An `alg` outside
    // ADR-0003's set, or one that disagrees with the key type, takes the key
    // out of the running rather than the set.
    let algorithm = match jwk.get("alg") {
        Some(declared) => {
            let Some(algorithm) = declared.as_str().and_then(SigningAlgorithm::parse) else {
                return Ok(None);
            };
            if algorithm.key_type() != kty {
                return Ok(None);
            }
            algorithm
        }
        None => match kty {
            "OKP" => SigningAlgorithm::EdDsa,
            "EC" => SigningAlgorithm::Es256,
            "RSA" => SigningAlgorithm::Ps256,
            _ => return Ok(None),
        },
    };

    let Some(key) = verifying_key(algorithm, jwk) else {
        return Ok(None);
    };

    // A `kid` that is not a string is not a `kid`. Taking the key without one
    // would be worse than skipping it: it would answer to every lookup that
    // found no match.
    let kid = match jwk.get("kid") {
        Some(value) => match value.as_str() {
            Some(kid) => Some(Kid::new(kid)),
            None => return Ok(None),
        },
        None => None,
    };

    Ok(Some(ClientKey { kid, key }))
}

/// Builds a verifying key from a JWK's public members, or `None` if they are
/// not a well-formed key of that algorithm.
fn verifying_key(algorithm: SigningAlgorithm, jwk: &Map<String, Value>) -> Option<VerifyingKey> {
    let member = |name: &str| -> Option<Vec<u8>> {
        // RFC 7515 §2: JWK members holding key material are base64url without
        // padding. The engine also rejects a final character with non-zero
        // unused bits, so one value has one encoding.
        B64.decode(jwk.get(name)?.as_str()?).ok()
    };
    let curve = jwk.get("crv").and_then(Value::as_str);

    match algorithm {
        SigningAlgorithm::EdDsa => {
            // RFC 8037 §2: an Ed25519 public key is `crv: "Ed25519"` and `x`,
            // the 32-byte encoded point. Ed448 and X25519 are `OKP` too, which
            // is why the curve is checked rather than assumed.
            if curve != Some("Ed25519") {
                return None;
            }
            let x = member("x")?;
            if x.len() != 32 {
                return None;
            }
            Some(VerifyingKey::new(algorithm, x))
        }
        SigningAlgorithm::Es256 => {
            // RFC 7518 §6.2.1.2–3: `x` and `y` are each the full coordinate
            // length for the curve, left-padded — 32 bytes for P-256. A short
            // value is not a small coordinate, it is a different encoding, and
            // accepting it would mean two spellings of one key.
            if curve != Some("P-256") {
                return None;
            }
            let (x, y) = (member("x")?, member("y")?);
            if x.len() != 32 || y.len() != 32 {
                return None;
            }
            // aws-lc-rs takes a P-256 public key as the uncompressed point.
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            Some(VerifyingKey::new(algorithm, point))
        }
        SigningAlgorithm::Ps256 => {
            // RFC 7518 §6.3.1: `n` and `e` are the modulus and exponent as
            // big-endian octets. aws-lc-rs holds the same "minimum number of
            // octets" rule §6.3.1.1 states — it refuses a component with a
            // leading zero byte — so a padded modulus is rejected here rather
            // than silently becoming a second spelling of one key.
            let (n, e) = (member("n")?, member("e")?);
            // FAPI 2.0 SP §5.4.1: RSA keys are at least 2048 bits. Byte
            // granularity, as at key import in `crate::key`; aws-lc-rs enforces
            // the exact bit range again at verification.
            if n.len() * 8 < MIN_RSA_BITS {
                return None;
            }
            let components = aws_lc_rs::signature::RsaPublicKeyComponents { n, e };
            let der = aws_lc_rs::encoding::AsDer::<
                aws_lc_rs::encoding::PublicKeyX509Der<'static>,
            >::as_der(&components)
            .ok()?;
            Some(VerifyingKey::new(algorithm, der.as_ref().to_vec()))
        }
    }
}

// ---------------------------------------------------------------------------
// The cache
// ---------------------------------------------------------------------------

/// How long resolved keys are kept, and how often a client may be fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheLimits {
    /// How long a fetched set is served before it is fetched again.
    pub ttl: Duration,
    /// How long a failed fetch is remembered.
    pub negative_ttl: Duration,
    /// The shortest interval between two fetches for one client.
    pub min_refresh_interval: Duration,
    /// The most clients held at once.
    pub max_entries: usize,
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            ttl: DEFAULT_TTL,
            negative_ttl: DEFAULT_NEGATIVE_TTL,
            min_refresh_interval: DEFAULT_MIN_REFRESH_INTERVAL,
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

/// What the cache has been doing.
///
/// Counters rather than a log line: the useful questions — is anything being
/// fetched, is a client failing, is somebody driving refreshes — are rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheCounts {
    /// Resolutions answered from the cache.
    pub hits: u64,
    /// Resolutions that had to fetch.
    pub misses: u64,
    /// Fetches that produced a usable document.
    pub fetches_succeeded: u64,
    /// Fetches that failed, and negative-cache hits.
    pub failures: u64,
    /// Refreshes declined because this client was fetched too recently.
    ///
    /// A rising count here is somebody sending unknown `kid`s.
    pub refreshes_suppressed: u64,
}

#[derive(Debug, Default)]
struct Counters {
    hits: AtomicU64,
    misses: AtomicU64,
    fetches_succeeded: AtomicU64,
    failures: AtomicU64,
    refreshes_suppressed: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> CacheCounts {
        CacheCounts {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            fetches_succeeded: self.fetches_succeeded.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            refreshes_suppressed: self.refreshes_suppressed.load(Ordering::Relaxed),
        }
    }
}

/// What is known about one client's keys.
#[derive(Debug, Clone)]
enum State {
    /// Keys, good until `expires_at`.
    Keys {
        keys: ClientKeySet,
        expires_at: OffsetDateTime,
    },
    /// The last fetch failed, and no fetch is worth trying until `until`.
    Failed { until: OffsetDateTime },
}

/// One client's cache entry.
#[derive(Debug, Clone)]
struct Entry {
    /// The `jwks_uri` these keys came from. A client that re-registers with a
    /// different URL must not be served the old URL's keys, so the entry is
    /// keyed by client and *checked* against the URL rather than keyed by URL —
    /// keying by URL would leave the old entry behind to be re-used if the
    /// client ever pointed back at it.
    uri: String,
    state: State,
    /// When a fetch was last *started* for this client, whatever came of it.
    /// The rate limit is measured from here.
    last_attempt: OffsetDateTime,
}

/// Resolves a client's keys, and remembers them.
///
/// One instance per process, shared. It holds no tenant, because the tenant is
/// part of every lookup key — a client id means nothing outside its tenant, and
/// two tenants may each have a client called `demo`.
///
/// # What the cache is protecting
///
/// Three separate things, and they are worth naming separately:
///
/// * **The client's server**, from being fetched on every request.
/// * **A third party**, from being fetched on every request. A `jwks_uri` is a
///   URL a client chose, and it need not be the client's own; without a
///   negative cache, a registration is enough to point this server at somebody
///   else and a stream of requests turns into a stream of outbound ones.
/// * **This server**, from doing unbounded outbound work on demand. The refresh
///   that OIDC Core §10.1.1 asks for on an unknown `kid` is triggered by a value
///   the token's author chose, so it is rate-limited per client.
pub struct ClientKeyCache {
    fetcher: std::sync::Arc<dyn JwksFetcher>,
    limits: CacheLimits,
    entries: Mutex<HashMap<(TenantId, ClientId), Entry>>,
    counters: Counters,
}

impl std::fmt::Debug for ClientKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Entry contents are public keys, not secrets, but a cache dumped into
        // a log line is noise that hides the line somebody was looking for.
        let entries = self.entries.lock().map(|map| map.len()).unwrap_or_default();
        f.debug_struct("ClientKeyCache")
            .field("entries", &entries)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl ClientKeyCache {
    /// A cache over `fetcher`, with the defaults above.
    #[must_use]
    pub fn new(fetcher: std::sync::Arc<dyn JwksFetcher>) -> Self {
        Self::with_limits(fetcher, CacheLimits::default())
    }

    /// A cache with limits chosen by the caller.
    #[must_use]
    pub fn with_limits(fetcher: std::sync::Arc<dyn JwksFetcher>, limits: CacheLimits) -> Self {
        Self {
            fetcher,
            limits,
            entries: Mutex::new(HashMap::new()),
            counters: Counters::default(),
        }
    }

    /// What the cache has been doing since it was built.
    #[must_use]
    pub fn counts(&self) -> CacheCounts {
        self.counters.snapshot()
    }

    /// Forgets what is known about one client.
    ///
    /// For the registration endpoint: a client that changes its `jwks_uri` or
    /// its inline `jwks` should not have to wait out a TTL. Resolution already
    /// notices a changed URL on its own; this is for the case where the URL is
    /// the same and its contents are not.
    pub fn invalidate(&self, tenant: &TenantId, client: &ClientId) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(&(tenant.clone(), client.clone()));
        }
    }

    /// The keys a client may have signed with.
    ///
    /// `kid` is the one from the token being verified, and is a *hint*: it
    /// narrows the answer and, when it names nothing known, triggers at most one
    /// refresh per [`CacheLimits::min_refresh_interval`]. `now` is passed in for
    /// the same reason [`crate::verify()`] takes it — one instant per request, and
    /// a test that does not sleep.
    ///
    /// # Errors
    ///
    /// Returns [`ClientKeyError`] if the registered document is unusable, or
    /// [`ClientKeyError::Unavailable`] if a `jwks_uri` could not be fetched.
    /// Note that an *empty* result is `Ok`: a client whose published set holds
    /// no key this server can use has published no usable key, which is a fact
    /// about the client rather than a failure here.
    pub async fn resolve(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        source: &JwksSource,
        kid: Option<&Kid>,
        now: OffsetDateTime,
    ) -> Result<ClientKeySet, ClientKeyError> {
        match source {
            // Nothing to cache and nothing to rate-limit: the document is
            // already in memory, having come from the client's registration.
            // Parsing it every time is a few hundred microseconds and keeps one
            // path from serving keys the other would have rejected.
            JwksSource::Inline(document) => {
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                keys_from_jwk_set(document)
            }
            JwksSource::Uri(uri) => self.resolve_uri(tenant, client, uri, kid, now).await,
        }
    }

    async fn resolve_uri(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        uri: &str,
        kid: Option<&Kid>,
        now: OffsetDateTime,
    ) -> Result<ClientKeySet, ClientKeyError> {
        let key = (tenant.clone(), client.clone());

        // Everything the lock is needed for happens here, before the fetch: a
        // guard held across an `await` would serialise every client behind one
        // slow `jwks_uri`.
        {
            let mut entries = self.entries.lock().map_err(|_| {
                // A poisoned lock means a panic while the map was borrowed.
                // Refusing is the only safe reading: the alternative is to
                // recover state that a panic left half-written.
                ClientKeyError::Unavailable
            })?;

            // A client that re-registered with a different URL has no cache
            // entry, whatever is filed under its name.
            if entries
                .get(&key)
                .is_some_and(|entry| entry.uri.as_str() != uri)
            {
                entries.remove(&key);
            }

            match entries.get(&key) {
                Some(entry) if entry.serves(kid, now) => {
                    self.counters.hits.fetch_add(1, Ordering::Relaxed);
                    return entry.keys();
                }
                // The negative cache. A failure is remembered for its own
                // period, which an operator may set longer than the refresh
                // interval without the two rules interfering.
                Some(Entry {
                    state: State::Failed { until },
                    ..
                }) if now < *until => {
                    self.counters.failures.fetch_add(1, Ordering::Relaxed);
                    return Err(ClientKeyError::Unavailable);
                }
                // Keys we hold, and a refresh asked for too soon after the last
                // attempt. This is the unknown-`kid` rate limit.
                Some(entry) if now - entry.last_attempt < self.limits.min_refresh_interval => {
                    self.counters
                        .refreshes_suppressed
                        .fetch_add(1, Ordering::Relaxed);
                    return entry.keys();
                }
                _ => {}
            }

            // Claim the attempt before releasing the lock. This is what makes
            // the rate limit hold under concurrency: a second request arriving
            // while this fetch is in flight sees a fresh `last_attempt` and
            // takes one of the branches above rather than starting its own
            // fetch. The state a new entry starts in is a failure, so a fetch
            // that never returns leaves behind "we could not get this client's
            // keys" rather than nothing.
            self.reserve(&mut entries, &key, uri, now);
        }

        self.counters.misses.fetch_add(1, Ordering::Relaxed);
        let fetched = self.fetcher.fetch(uri).await;
        let parsed = match fetched {
            Ok(body) => parse_jwk_set(&body),
            Err(_) => Err(ClientKeyError::Unavailable),
        };

        let mut entries = self
            .entries
            .lock()
            .map_err(|_| ClientKeyError::Unavailable)?;
        let state = if let Ok(keys) = &parsed {
            self.counters
                .fetches_succeeded
                .fetch_add(1, Ordering::Relaxed);
            State::Keys {
                keys: keys.clone(),
                expires_at: now + self.limits.ttl,
            }
        } else {
            // Every failure is negative-cached, including a document that
            // parsed as something other than a JWK Set. "The client serves
            // garbage" is not a reason to keep asking.
            self.counters.failures.fetch_add(1, Ordering::Relaxed);
            State::Failed {
                until: now + self.limits.negative_ttl,
            }
        };
        entries.insert(
            key,
            Entry {
                uri: uri.to_owned(),
                state,
                last_attempt: now,
            },
        );
        parsed
    }

    /// Records that a fetch is starting, evicting if the cache is full.
    fn reserve(
        &self,
        entries: &mut HashMap<(TenantId, ClientId), Entry>,
        key: &(TenantId, ClientId),
        uri: &str,
        now: OffsetDateTime,
    ) {
        // An existing entry keeps its keys while the refresh is in flight, so a
        // concurrent request is answered from a set that is at most one fetch
        // timeout past its TTL rather than being told there are no keys. The
        // window is bounded by the fetch, not by the outage: a fetch that fails
        // replaces the state.
        if let Some(entry) = entries.get_mut(key) {
            entry.last_attempt = now;
            return;
        }
        self.evict_if_full(entries, now);
        entries.insert(
            key.clone(),
            Entry {
                uri: uri.to_owned(),
                state: State::Failed {
                    until: now + self.limits.negative_ttl,
                },
                last_attempt: now,
            },
        );
    }

    /// Makes room for one entry, if there is none.
    fn evict_if_full(
        &self,
        entries: &mut HashMap<(TenantId, ClientId), Entry>,
        now: OffsetDateTime,
    ) {
        if entries.len() < self.limits.max_entries {
            return;
        }
        // Anything nobody could be served from goes first.
        entries.retain(|_, entry| entry.serves(None, now));
        if entries.len() < self.limits.max_entries {
            return;
        }
        // Otherwise the client nobody has asked about for longest.
        if let Some(oldest) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_attempt)
            .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
    }
}

impl Entry {
    /// Whether this entry can answer a lookup for `kid` at `now`.
    fn serves(&self, kid: Option<&Kid>, now: OffsetDateTime) -> bool {
        match &self.state {
            State::Keys { keys, expires_at } => {
                now < *expires_at && kid.is_none_or(|kid| keys.contains(kid))
            }
            State::Failed { .. } => false,
        }
    }

    /// Whatever this entry holds, as a result.
    fn keys(&self) -> Result<ClientKeySet, ClientKeyError> {
        match &self.state {
            State::Keys { keys, .. } => Ok(keys.clone()),
            State::Failed { .. } => Err(ClientKeyError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SigningKey, jws};
    use asterius_domain::DomainError;
    use serde_json::json;
    use std::sync::Arc;

    fn tenant() -> TenantId {
        TenantId::new("demo")
    }

    fn client() -> ClientId {
        ClientId::new("client-1")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("fixed instant")
    }

    /// A JWK Set holding the public halves of freshly generated keys.
    fn published(keys: &[(&SigningKey, Option<&str>)]) -> Value {
        let entries: Vec<Value> = keys
            .iter()
            .map(|(key, kid)| {
                let mut jwk = key.public_jwk().expect("jwk");
                if let Some(kid) = kid {
                    jwk["kid"] = json!(kid);
                }
                jwk
            })
            .collect();
        json!({ "keys": entries })
    }

    // ---- parsing ---------------------------------------------------------

    /// The acceptance criterion the whole module exists for: whichever way a
    /// client registered its keys, verification sees the same thing.
    #[test]
    fn an_inline_set_and_a_fetched_set_produce_the_same_keys() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let document = published(&[(&key, Some("k1"))]);

        let inline = keys_from_jwk_set(&document).expect("inline");
        let fetched = parse_jwk_set(serde_json::to_vec(&document).expect("serialise").as_slice())
            .expect("fetched");

        assert_eq!(inline, fetched);
        assert_eq!(inline.verifying_keys(), fetched.verifying_keys());
    }

    /// Every algorithm ADR-0003 permits survives the round trip from a
    /// published JWK back to a key that verifies the signature its private half
    /// made. This is the test that proves the encodings — the uncompressed
    /// point, the RSA `SubjectPublicKeyInfo` — are right rather than merely
    /// self-consistent.
    #[test]
    fn a_published_jwk_verifies_the_signature_its_private_half_made() {
        for algorithm in SigningAlgorithm::ALL {
            let signing = SigningKey::generate(algorithm).expect("generate");
            let set = keys_from_jwk_set(&published(&[(&signing, Some("k"))])).expect("parse");
            assert_eq!(set.keys().len(), 1, "{algorithm} produced no usable key");

            let message = b"assertion";
            let signature = signing.sign(message).expect("sign");
            set.keys()[0]
                .key()
                .verify(message, &signature)
                .unwrap_or_else(|e| panic!("{algorithm} did not verify its own signature: {e}"));
        }
    }

    /// A whole client assertion, verified through the resolver, which is how
    /// `ast-m9c.2` will use this.
    #[test]
    fn a_client_assertion_verifies_against_the_key_its_kid_names() {
        let signing = SigningKey::generate(SigningAlgorithm::Es256).expect("generate");
        let other = SigningKey::generate(SigningAlgorithm::Es256).expect("generate");
        let set = keys_from_jwk_set(&published(&[
            (&other, Some("old")),
            (&signing, Some("current")),
        ]))
        .expect("parse");

        let assertion = jws::sign(
            &signing,
            &Kid::new("current"),
            "JWT",
            &json!({"iss": "client-1"}),
        )
        .expect("sign");

        let candidates = set.candidates(Some(&Kid::new("current")));
        assert_eq!(candidates.len(), 1, "a kid must narrow the candidates");
        jws::parse(assertion.as_str())
            .expect("parse")
            .verify(&candidates[0])
            .expect("the key the kid names must verify the assertion");
    }

    /// FAPI 2.0 SP §5.4.1 and ADR-0003: the allow-list is EdDSA, ES256 and
    /// PS256. A client that publishes an RS256 key keeps its other keys and
    /// loses that one.
    #[test]
    fn a_key_outside_the_algorithm_allow_list_is_skipped_not_fatal() {
        let usable = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let mut document = published(&[(&usable, Some("good"))]);
        document["keys"].as_array_mut().expect("array").push(json!({
            "kty": "RSA",
            "alg": "RS256",
            "kid": "legacy",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB"
        }));

        let set = keys_from_jwk_set(&document).expect("the set must survive one unusable key");
        assert_eq!(set.keys().len(), 1);
        assert_eq!(set.keys()[0].kid(), Some(&Kid::new("good")));
    }

    /// `alg: none` is not a value [`SigningAlgorithm`] has, so it cannot select
    /// a key. Asserted anyway, because "cannot happen" is the claim most worth
    /// a test.
    #[test]
    fn none_and_hs256_select_no_key() {
        for algorithm in ["none", "HS256", "RS256", "ES384", ""] {
            let document = json!({"keys": [{
                "kty": "oct", "alg": algorithm, "kid": "x"
            }]});
            let set = keys_from_jwk_set(&document).expect("parse");
            assert!(set.is_empty(), "{algorithm} produced a key");
        }
    }

    /// RFC 7517 §4.2: `use` says what the public key is for. An encryption key
    /// must never end up checking a signature — FAPI 2.0 SP §6.8 item 2.
    #[test]
    fn a_key_marked_for_encryption_is_never_used_to_verify() {
        let key = SigningKey::generate(SigningAlgorithm::Es256).expect("generate");
        let mut document = published(&[(&key, Some("k"))]);
        document["keys"][0]["use"] = json!("enc");
        assert!(
            keys_from_jwk_set(&document).expect("parse").is_empty(),
            "a key marked `use: enc` was offered as a verifying key"
        );
    }

    /// RFC 7517 §4.3: `key_ops` enumerates the permitted operations.
    #[test]
    fn a_key_whose_key_ops_exclude_verify_is_skipped() {
        let key = SigningKey::generate(SigningAlgorithm::Es256).expect("generate");
        let mut document = published(&[(&key, Some("k"))]);
        document["keys"][0]["key_ops"] = json!(["encrypt"]);
        assert!(keys_from_jwk_set(&document).expect("parse").is_empty());

        document["keys"][0]["key_ops"] = json!(["verify", "wrapKey"]);
        assert_eq!(keys_from_jwk_set(&document).expect("parse").keys().len(), 1);
    }

    /// A JWK Set with a `d` means the client published its private key. Nothing
    /// in that document is trustworthy afterwards, so the set is refused rather
    /// than filtered.
    #[test]
    fn a_set_containing_private_key_material_is_refused_whole() {
        let good = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        for member in PRIVATE_MEMBERS {
            let mut document = published(&[(&good, Some("good"))]);
            document["keys"].as_array_mut().expect("array").push(json!({
                "kty": "OKP", "crv": "Ed25519", "x": "x", member: "leaked"
            }));
            assert_eq!(
                keys_from_jwk_set(&document),
                Err(ClientKeyError::PrivateKeyMaterial),
                "a set leaking {member} was accepted"
            );
        }
    }

    /// FAPI 2.0 SP §5.4.1: RSA keys are at least 2048 bits.
    #[test]
    fn an_rsa_key_below_the_size_floor_is_skipped() {
        // A 1024-bit modulus: 128 bytes, high bit set so there is no leading
        // zero to strip.
        let modulus = vec![0xff_u8; 128];
        let document = json!({"keys": [{
            "kty": "RSA",
            "kid": "small",
            "n": B64.encode(&modulus),
            "e": B64.encode([0x01, 0x00, 0x01]),
        }]});
        assert!(keys_from_jwk_set(&document).expect("parse").is_empty());
    }

    /// RFC 7518 §6.2.1.2: a coordinate is the full length for the curve. A
    /// short `x` is a different encoding of a key, not the same key, and two
    /// encodings of one key is one more than a lookup should have.
    #[test]
    fn coordinates_of_the_wrong_length_are_refused() {
        let key = SigningKey::generate(SigningAlgorithm::Es256).expect("generate");
        let document = published(&[(&key, Some("k"))]);

        for member in ["x", "y"] {
            let mut short = document.clone();
            let decoded = B64
                .decode(short["keys"][0][member].as_str().expect("string"))
                .expect("base64url");
            short["keys"][0][member] = json!(B64.encode(&decoded[1..]));
            assert!(
                keys_from_jwk_set(&short).expect("parse").is_empty(),
                "a P-256 key with a short {member} was accepted"
            );
        }
    }

    /// RFC 8037 §2: Ed25519 is one curve among the `OKP` key type's. X25519 is
    /// a key agreement key and must not be read as a signature key.
    #[test]
    fn an_okp_key_on_another_curve_is_skipped() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let mut document = published(&[(&key, Some("k"))]);
        document["keys"][0]["crv"] = json!("X25519");
        assert!(keys_from_jwk_set(&document).expect("parse").is_empty());
    }

    /// A JWK whose `alg` and `kty` disagree is not a key with an opinion, it is
    /// a key trying to be verified with the wrong primitive.
    #[test]
    fn an_alg_that_disagrees_with_the_key_type_is_skipped() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let mut document = published(&[(&key, Some("k"))]);
        document["keys"][0]["alg"] = json!("ES256");
        assert!(keys_from_jwk_set(&document).expect("parse").is_empty());
    }

    #[test]
    fn a_document_that_is_not_a_jwk_set_is_rejected_without_panicking() {
        let hostile: [&[u8]; 8] = [
            b"",
            b"null",
            b"[]",
            b"{}",
            br#"{"keys": {}}"#,
            br#"{"keys": null}"#,
            br#"{"keys": [null, 1, "x", []]}"#,
            b"\xff\xfe not json",
        ];
        for document in hostile {
            match parse_jwk_set(document) {
                // `{"keys": [...]}` with unusable entries is a valid, empty set.
                Ok(set) => assert!(set.is_empty(), "{document:?} produced keys"),
                Err(ClientKeyError::Malformed(_)) => {}
                Err(other) => panic!("{document:?} produced {other}"),
            }
        }
    }

    #[test]
    fn a_set_larger_than_the_cap_is_refused_before_it_is_parsed() {
        let oversized = vec![b'a'; MAX_JWK_SET_BYTES + 1];
        assert_eq!(
            parse_jwk_set(&oversized),
            Err(ClientKeyError::TooLarge {
                size: MAX_JWK_SET_BYTES + 1,
                limit: MAX_JWK_SET_BYTES
            })
        );
    }

    /// The number of keys bounds the number of signature checks one
    /// unauthenticated request can ask for.
    #[test]
    fn a_set_with_too_many_keys_is_refused() {
        let entries: Vec<Value> = (0..=MAX_KEYS)
            .map(|i| json!({"kty": "OKP", "crv": "Ed25519", "x": "x", "kid": i.to_string()}))
            .collect();
        let count = entries.len();
        assert_eq!(
            keys_from_jwk_set(&json!({"keys": entries})),
            Err(ClientKeyError::TooManyKeys {
                count,
                limit: MAX_KEYS
            })
        );
    }

    /// FAPI 2.0 SP §5.4.2 says a JWK Set *should not* carry two keys with one
    /// `kid`, and §5.4.3 says what a verifier does when one does: keep both and
    /// choose among them. Dropping the duplicate would break exactly the
    /// mid-rotation case the clause is about.
    #[test]
    fn two_keys_sharing_a_kid_are_both_kept_as_candidates() {
        let first = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let second = SigningKey::generate(SigningAlgorithm::Es256).expect("generate");
        let set = keys_from_jwk_set(&published(&[(&first, Some("k")), (&second, Some("k"))]))
            .expect("parse");

        assert_eq!(set.candidates(Some(&Kid::new("k"))).len(), 2);
    }

    /// RFC 7517 §4.5 makes `kid` optional, and RFC 7515 §4.1.4 makes the header
    /// `kid` optional too. An unlabelled key is a candidate for a token whose
    /// `kid` matches nothing — it has not claimed to be a different key.
    #[test]
    fn an_unlabelled_key_answers_for_a_kid_that_matches_nothing() {
        let unlabelled = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let labelled = SigningKey::generate(SigningAlgorithm::Es256).expect("generate");
        let set = keys_from_jwk_set(&published(&[
            (&unlabelled, None),
            (&labelled, Some("named")),
        ]))
        .expect("parse");

        assert_eq!(set.candidates(Some(&Kid::new("unknown"))).len(), 1);
        // A kid that does match is not widened by the unlabelled key.
        assert_eq!(set.candidates(Some(&Kid::new("named"))).len(), 1);
        assert_eq!(set.candidates(None).len(), 2);
    }

    // ---- the cache -------------------------------------------------------

    /// A fetcher that serves canned bytes and counts the calls, so a test can
    /// assert on how often the network would have been touched.
    #[derive(Debug)]
    struct StubFetcher {
        response: Mutex<Result<Vec<u8>, ()>>,
        calls: AtomicU64,
    }

    impl StubFetcher {
        fn serving(document: &Value) -> Arc<Self> {
            Arc::new(Self {
                response: Mutex::new(Ok(serde_json::to_vec(document).expect("serialise"))),
                calls: AtomicU64::new(0),
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                response: Mutex::new(Err(())),
                calls: AtomicU64::new(0),
            })
        }

        fn now_serving(&self, document: &Value) {
            *self.response.lock().expect("lock") =
                Ok(serde_json::to_vec(document).expect("serialise"));
        }

        fn calls(&self) -> u64 {
            self.calls.load(Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl JwksFetcher for StubFetcher {
        async fn fetch(&self, _url: &str) -> Result<Vec<u8>, DomainError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.response
                .lock()
                .expect("lock")
                .clone()
                .map_err(|()| DomainError::invalid("jwks_uri", "stub failure"))
        }
    }

    const URI: &str = "https://client.example/jwks";

    #[tokio::test]
    async fn a_second_resolution_within_the_ttl_does_not_fetch_again() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let fetcher = StubFetcher::serving(&published(&[(&key, Some("k1"))]));
        let cache = ClientKeyCache::new(fetcher.clone());
        let source = JwksSource::Uri(URI.to_owned());

        for offset in [0, 1, 60, 300] {
            let set = cache
                .resolve(
                    &tenant(),
                    &client(),
                    &source,
                    Some(&Kid::new("k1")),
                    now() + Duration::seconds(offset),
                )
                .await
                .expect("resolve");
            assert_eq!(set.keys().len(), 1);
        }
        assert_eq!(fetcher.calls(), 1, "the cache fetched more than once");
        assert_eq!(cache.counts().hits, 3);
    }

    /// The TTL is what notices a *withdrawn* key: no `kid` announces a key that
    /// has been removed, so only the expiry brings the change in.
    #[tokio::test]
    async fn keys_are_fetched_again_once_the_ttl_has_passed() {
        let first = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let fetcher = StubFetcher::serving(&published(&[(&first, Some("k1"))]));
        let cache = ClientKeyCache::new(fetcher.clone());
        let source = JwksSource::Uri(URI.to_owned());

        cache
            .resolve(&tenant(), &client(), &source, None, now())
            .await
            .expect("first");

        let second = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        fetcher.now_serving(&published(&[(&second, Some("k2"))]));

        let after = now() + DEFAULT_TTL + Duration::seconds(1);
        let set = cache
            .resolve(&tenant(), &client(), &source, None, after)
            .await
            .expect("second");
        assert_eq!(fetcher.calls(), 2);
        assert!(set.contains(&Kid::new("k2")));
        assert!(
            !set.contains(&Kid::new("k1")),
            "the old key was still served"
        );
    }

    /// OIDC Core §10.1.1: the verifier re-retrieves the keys when it sees an
    /// unfamiliar `kid`. That is what makes a rotation visible before the TTL
    /// expires.
    #[tokio::test]
    async fn an_unknown_kid_triggers_one_refresh_and_finds_the_rotated_key() {
        let old = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let fetcher = StubFetcher::serving(&published(&[(&old, Some("old"))]));
        let cache = ClientKeyCache::new(fetcher.clone());
        let source = JwksSource::Uri(URI.to_owned());

        cache
            .resolve(&tenant(), &client(), &source, Some(&Kid::new("old")), now())
            .await
            .expect("first");

        let new = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        fetcher.now_serving(&published(&[(&old, Some("old")), (&new, Some("new"))]));

        let later = now() + DEFAULT_MIN_REFRESH_INTERVAL;
        let set = cache
            .resolve(&tenant(), &client(), &source, Some(&Kid::new("new")), later)
            .await
            .expect("refresh");
        assert_eq!(fetcher.calls(), 2);
        assert!(set.contains(&Kid::new("new")));
    }

    /// The attack the rate limit exists for: a stream of assertions naming
    /// `kid`s that do not exist, each of which would otherwise be an outbound
    /// request the attacker chose the target of.
    #[tokio::test]
    async fn unknown_kids_cannot_be_used_to_drive_repeated_fetches() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let fetcher = StubFetcher::serving(&published(&[(&key, Some("k1"))]));
        let cache = ClientKeyCache::new(fetcher.clone());
        let source = JwksSource::Uri(URI.to_owned());

        // One second apart, for a minute: far inside the refresh interval.
        for second in 0..60 {
            let _ = cache
                .resolve(
                    &tenant(),
                    &client(),
                    &source,
                    Some(&Kid::new(format!("guess-{second}"))),
                    now() + Duration::seconds(second),
                )
                .await;
        }
        assert_eq!(
            fetcher.calls(),
            1,
            "an attacker drove {} fetches with unknown kids",
            fetcher.calls()
        );
        assert!(cache.counts().refreshes_suppressed >= 58);
    }

    /// A rate-limited refresh still answers with the keys it has: the request
    /// being served may be an honest one that happens to arrive during the
    /// window, and it should fail at signature verification, not before.
    #[tokio::test]
    async fn a_suppressed_refresh_still_serves_the_keys_it_has() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let fetcher = StubFetcher::serving(&published(&[(&key, Some("k1"))]));
        let cache = ClientKeyCache::new(fetcher.clone());
        let source = JwksSource::Uri(URI.to_owned());

        cache
            .resolve(&tenant(), &client(), &source, None, now())
            .await
            .expect("first");
        let set = cache
            .resolve(
                &tenant(),
                &client(),
                &source,
                Some(&Kid::new("unknown")),
                now() + Duration::seconds(1),
            )
            .await
            .expect("suppressed refresh still answers");
        assert!(set.contains(&Kid::new("k1")));
    }

    /// A broken `jwks_uri` must not turn every request naming that client into
    /// an outbound request — least of all when the URL points at a third party.
    #[tokio::test]
    async fn a_failing_jwks_uri_is_fetched_at_most_once_per_negative_ttl() {
        let fetcher = StubFetcher::failing();
        let cache = ClientKeyCache::new(fetcher.clone());
        let source = JwksSource::Uri(URI.to_owned());

        for second in 0..60 {
            let result = cache
                .resolve(
                    &tenant(),
                    &client(),
                    &source,
                    None,
                    now() + Duration::seconds(second),
                )
                .await;
            assert_eq!(result, Err(ClientKeyError::Unavailable));
        }
        assert_eq!(fetcher.calls(), 1);

        // Once the negative entry expires, one more attempt is made.
        let _ = cache
            .resolve(
                &tenant(),
                &client(),
                &source,
                None,
                now() + DEFAULT_NEGATIVE_TTL,
            )
            .await;
        assert_eq!(fetcher.calls(), 2);
    }

    /// A document that is served but is not a JWK Set is a failure like any
    /// other: negative-cached, not retried on the next request.
    #[tokio::test]
    async fn a_jwks_uri_serving_garbage_is_negative_cached() {
        let fetcher = Arc::new(StubFetcher {
            response: Mutex::new(Ok(b"<html>not a jwks</html>".to_vec())),
            calls: AtomicU64::new(0),
        });
        let cache = ClientKeyCache::new(fetcher.clone());
        let source = JwksSource::Uri(URI.to_owned());

        assert!(
            cache
                .resolve(&tenant(), &client(), &source, None, now())
                .await
                .is_err()
        );
        assert!(
            cache
                .resolve(&tenant(), &client(), &source, None, now())
                .await
                .is_err()
        );
        assert_eq!(fetcher.calls(), 1);
    }

    /// The cache is keyed by tenant and client, so one tenant's client cannot
    /// be served another tenant's keys — the same rule every other store here
    /// follows.
    #[tokio::test]
    async fn one_tenants_cached_keys_never_answer_for_another() {
        let alpha_key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let fetcher = StubFetcher::serving(&published(&[(&alpha_key, Some("alpha"))]));
        let cache = ClientKeyCache::new(fetcher.clone());
        let source = JwksSource::Uri(URI.to_owned());

        cache
            .resolve(&TenantId::new("alpha"), &client(), &source, None, now())
            .await
            .expect("alpha");

        let beta_key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        fetcher.now_serving(&published(&[(&beta_key, Some("beta"))]));

        let beta = cache
            .resolve(&TenantId::new("beta"), &client(), &source, None, now())
            .await
            .expect("beta");
        assert!(beta.contains(&Kid::new("beta")));
        assert!(!beta.contains(&Kid::new("alpha")));
        assert_eq!(fetcher.calls(), 2);
    }

    /// A client that re-registers with a different `jwks_uri` is a different
    /// key source. Serving the old URL's keys would mean a client could not
    /// move away from a compromised key server.
    #[tokio::test]
    async fn changing_the_jwks_uri_discards_the_keys_fetched_from_the_old_one() {
        let old = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let fetcher = StubFetcher::serving(&published(&[(&old, Some("old"))]));
        let cache = ClientKeyCache::new(fetcher.clone());

        cache
            .resolve(
                &tenant(),
                &client(),
                &JwksSource::Uri(URI.to_owned()),
                None,
                now(),
            )
            .await
            .expect("first");

        let new = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        fetcher.now_serving(&published(&[(&new, Some("new"))]));

        let set = cache
            .resolve(
                &tenant(),
                &client(),
                &JwksSource::Uri("https://elsewhere.example/jwks".to_owned()),
                None,
                now(),
            )
            .await
            .expect("second");
        assert!(set.contains(&Kid::new("new")));
        assert_eq!(fetcher.calls(), 2);
    }

    /// An inline `jwks` is already in memory: resolving it must never reach the
    /// fetcher, whatever the `kid` says.
    #[tokio::test]
    async fn an_inline_jwks_is_never_fetched() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let fetcher = StubFetcher::failing();
        let cache = ClientKeyCache::new(fetcher.clone());
        let source = JwksSource::Inline(published(&[(&key, Some("k1"))]));

        let set = cache
            .resolve(
                &tenant(),
                &client(),
                &source,
                Some(&Kid::new("nothing-like-it")),
                now(),
            )
            .await
            .expect("inline");
        assert_eq!(set.keys().len(), 1);
        assert_eq!(fetcher.calls(), 0);
    }

    #[tokio::test]
    async fn invalidating_a_client_forces_the_next_resolution_to_fetch() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let fetcher = StubFetcher::serving(&published(&[(&key, Some("k1"))]));
        let cache = ClientKeyCache::new(fetcher.clone());
        let source = JwksSource::Uri(URI.to_owned());

        cache
            .resolve(&tenant(), &client(), &source, None, now())
            .await
            .expect("first");
        cache.invalidate(&tenant(), &client());
        cache
            .resolve(&tenant(), &client(), &source, None, now())
            .await
            .expect("second");
        assert_eq!(fetcher.calls(), 2);
    }

    /// The cache is bounded: a deployment with more clients than it holds
    /// re-fetches rather than growing without limit.
    #[tokio::test]
    async fn the_cache_does_not_grow_without_bound() {
        let key = SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate");
        let fetcher = StubFetcher::serving(&published(&[(&key, Some("k1"))]));
        let cache = ClientKeyCache::with_limits(
            fetcher.clone(),
            CacheLimits {
                max_entries: 4,
                ..CacheLimits::default()
            },
        );
        let source = JwksSource::Uri(URI.to_owned());

        for index in 0..16 {
            cache
                .resolve(
                    &tenant(),
                    &ClientId::new(format!("client-{index}")),
                    &source,
                    None,
                    now() + Duration::seconds(index),
                )
                .await
                .expect("resolve");
        }
        assert!(cache.entries.lock().expect("lock").len() <= 4);
    }
}
