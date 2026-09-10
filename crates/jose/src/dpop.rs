//! DPoP proofs: RFC 9449 §4.2 syntax, §4.3 checking, §6.1 confirmation, §8
//! nonces, §10 key binding.
//!
//! A DPoP proof is the one JWT this server verifies against a key the token
//! itself carries. Everywhere else that would be the mistake RFC 8725 §3.1
//! names — a verifier letting the token choose its own key — so it is worth
//! being precise about why it is not one here.
//!
//! A proof proves *possession of a key*, not *identity*. Verifying it against
//! the `jwk` in its own header establishes exactly one fact: whoever wrote
//! this header holds the matching private key. That fact is worth nothing on
//! its own — RFC 9449 §4 says so outright — and becomes worth something only
//! when the key is *corroborated* downstream:
//!
//! * at the token endpoint, against the `dpop_jkt` the authorization request
//!   pinned ([`matches_pinned_key`], RFC 9449 §10);
//! * at a resource, against the `cnf.jkt` inside the access token
//!   ([`Proof::confirmation`], RFC 9449 §6.1 and §7.1).
//!
//! So this module's job is to make the "whoever wrote this header" part
//! airtight, and to hand the caller the thumbprint that the corroboration is
//! done against. It never decides that anybody is authenticated.
//!
//! # The three things that actually stop a replay
//!
//! RFC 9449 §4.3 lists twelve checks. Three of them carry the weight, and each
//! defends a different attacker:
//!
//! * **`htm`/`htu`** stop a proof captured at one endpoint from being
//!   presented at another (RFC 9449 §11 opening paragraph). This is why
//!   [`NormalisedUri`] is written as carefully as it is: too strict and honest
//!   clients loop, too loose and the binding stops being a binding.
//! * **`jti` single use**, within the `iat` window, stops the same proof being
//!   presented twice at the *same* endpoint (§11.1). The store is
//!   [`asterius_domain::ports::ReplayGuard`]; this module supplies the `jti`
//!   and the instant its row stops earning its keep.
//! * **The server nonce** stops proofs minted in advance (§11.2). An attacker
//!   who controls the client — including its legitimate user — can otherwise
//!   sign a year of proofs today and carry them to a machine that has never
//!   held the key. [`NonceIssuer`] is how this server issues them without a
//!   write on the authentication path.
//!
//! # What is not here
//!
//! No HTTP. This module is handed a method string and a URI and says yes or
//! no; extracting them from a request, deciding whether a proof was required
//! at all, and rendering `invalid_dpop_proof` belong to
//! `asterius_server::http::dpop`, which is also where the replay store is
//! reached.

use crate::verify::{self, Policy, TypRule};
use crate::{JoseError, VerifyingKey, client_keys, jws, store};
use asterius_domain::{Kid, SigningAlgorithm, ct_eq};
use aws_lc_rs::hmac;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use time::{Duration, OffsetDateTime};

/// The `typ` a DPoP proof must carry (RFC 9449 §4.2, registered in §12.5).
pub const PROOF_TYP: &str = "dpop+jwt";

/// The largest proof this server will parse.
///
/// A proof is a header with one public key and five short claims. An RSA key
/// is the big one and still leaves most of this unused. Past it, the input is
/// not a proof — it is a way to make an unauthenticated caller's request cost
/// this server a base64 decode and a JSON parse.
pub const MAX_PROOF_BYTES: usize = 4 * 1024;

/// The longest `jti` this server will accept.
///
/// RFC 9449 §11.1: "a server that is tracking `jti` values should reject DPoP
/// proof JWTs with unnecessarily large `jti` values or store only a hash
/// thereof." We do both. The value is only ever compared for equality, so its
/// length is pure cost, and 96 bits of pseudorandom data — what §4.2
/// recommends — encodes to sixteen characters.
pub const MAX_JTI_LEN: usize = 255;

/// The longest `htu` this server will parse.
///
/// The `htu` must equal one of this server's own endpoint URLs, and those are
/// an issuer plus a short fixed path. Anything longer cannot match, so parsing
/// it is work with no possible outcome but a rejection.
pub const MAX_URI_BYTES: usize = 2 * 1024;

/// How old a proof may be, by default.
///
/// RFC 9449 §11.1: servers "MUST only accept DPoP proofs for a limited time
/// after their creation (preferably only for a relatively brief period on the
/// order of seconds or minutes)". Five minutes is the outer end of "minutes",
/// and it is also what sizes the replay table: every accepted proof costs one
/// row for this long and not a second more.
pub const DEFAULT_MAX_AGE: Duration = Duration::seconds(300);

/// The oldest a proof may be under any policy.
///
/// A deployment may shorten [`DEFAULT_MAX_AGE`]; it may not lengthen it past
/// this. The window is simultaneously the replay-detection window, so widening
/// it widens both the interval an intercepted proof stays useful *and* the
/// table that has to remember every `jti` in it.
pub const MAX_MAX_AGE: Duration = Duration::minutes(10);

/// How long one nonce window lasts, by default.
///
/// The ticket's figure and a reasonable one: a nonce minted now is accepted
/// for at least this long — see [`NonceIssuer`] on the boundary.
pub const DEFAULT_NONCE_WINDOW: Duration = Duration::minutes(5);

/// The shortest and longest permitted nonce window.
///
/// Below the floor, the lookback that makes the boundary survivable stops
/// being enough time for a client to receive a nonce and send its retry. Above
/// the ceiling, a nonce stops limiting proof lifetimes, which is the only
/// thing it is for (RFC 9449 §11.2).
pub const MIN_NONCE_WINDOW: Duration = Duration::minutes(1);
/// See [`MIN_NONCE_WINDOW`].
pub const MAX_NONCE_WINDOW: Duration = Duration::minutes(10);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a DPoP proof was refused.
///
/// Every variant but the two nonce ones maps to `invalid_dpop_proof` (RFC 9449
/// §5, registered in §12.2). The split that matters is [`DpopError::code`]:
/// the nonce failures are a *protocol step*, not a bad credential, and a client
/// told `invalid_dpop_proof` when it should have been told `use_dpop_nonce`
/// will give up instead of retrying.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DpopError {
    /// The proof is larger than [`MAX_PROOF_BYTES`].
    #[error("DPoP proof is {size} bytes, limit is {limit}")]
    TooLarge {
        /// The offered size.
        size: usize,
        /// The limit.
        limit: usize,
    },
    /// The proof is not a well-formed JWS, or its header is unusable.
    #[error(transparent)]
    Jose(#[from] JoseError),
    /// The proof did not survive the shared JWT checks.
    #[error(transparent)]
    Verification(#[from] verify::VerificationError),
    /// The header carries no `jwk`, or one that is not a JSON object.
    ///
    /// RFC 9449 §4.2 makes `jwk` a required JOSE Header Parameter; §4.3 item 3
    /// makes its absence a rejection rather than a proof verified some other
    /// way.
    #[error("the DPoP proof header carries no jwk")]
    MissingKey,
    /// The `jwk` contains private or symmetric key material.
    ///
    /// RFC 9449 §4.2: "It MUST NOT contain a private key"; §4.3 item 7.
    /// Refused as its own variant, not folded into "unusable key", because it
    /// is a disclosure and an operator should be able to see that it happened.
    #[error("the DPoP proof's jwk contains private key material")]
    PrivateKeyMaterial,
    /// The `jwk` is not a well-formed public key for the header's `alg`.
    #[error("the DPoP proof's jwk is not a usable {0} public key")]
    UnusableKey(SigningAlgorithm),
    /// A required claim is absent or the wrong JSON type (RFC 9449 §4.3 item 3).
    #[error("DPoP proof claim {0} is missing or malformed")]
    MalformedClaim(&'static str),
    /// `htm` is not the method of the request the proof arrived on.
    #[error("the DPoP proof is for a different HTTP method")]
    MethodMismatch,
    /// `htu` is not the URI of the request the proof arrived on.
    ///
    /// One variant for "unparseable" and "parsed, and names somewhere else":
    /// both mean this proof was not made for this endpoint, and telling them
    /// apart tells whoever sent it how far their URL got.
    #[error("the DPoP proof is for a different URI")]
    UriMismatch,
    /// The proof is older than the policy's window (RFC 9449 §11.1).
    #[error("the DPoP proof is {age}s old, limit is {limit}s")]
    TooOld {
        /// How old it is.
        age: i64,
        /// The window.
        limit: i64,
    },
    /// The proof's `iat` is further ahead than the skew allowance.
    ///
    /// FAPI 2.0 SP §5.3.2.1 item 13 sets both ends of that allowance.
    #[error("the DPoP proof's iat is {seconds_ahead}s in the future, limit is {limit}s")]
    TooFarAhead {
        /// How far ahead.
        seconds_ahead: i64,
        /// The allowance.
        limit: i64,
    },
    /// A nonce is required and the proof carries none (RFC 9449 §8).
    #[error("this endpoint requires a DPoP nonce")]
    NonceRequired,
    /// The nonce is not one this server issued recently.
    #[error("the DPoP nonce is not one this server issued recently")]
    NonceStale,
    /// `ath` does not hash the access token presented with it.
    ///
    /// RFC 9449 §4.3 item 12. Not reachable from the token endpoint; it is the
    /// resource-side half of the same function.
    #[error("the DPoP proof is bound to a different access token")]
    AccessTokenMismatch,
}

impl DpopError {
    /// The OAuth 2.0 error code this failure is reported with.
    ///
    /// RFC 9449 §5 defines `invalid_dpop_proof` for a proof that does not check
    /// out and §8 defines `use_dpop_nonce` for "you need a nonce, here is one".
    /// The second is not a diagnosis of the client's credential — it is an
    /// instruction to retry, and the client's retry loop keys off exactly this
    /// string.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NonceRequired | Self::NonceStale => "use_dpop_nonce",
            _ => "invalid_dpop_proof",
        }
    }

    /// Whether the client should be handed a fresh nonce and asked to retry.
    #[must_use]
    pub const fn wants_nonce(&self) -> bool {
        matches!(self, Self::NonceRequired | Self::NonceStale)
    }
}

// ---------------------------------------------------------------------------
// htu normalisation
// ---------------------------------------------------------------------------

/// An `htu`, reduced to the one spelling this server compares.
///
/// # Why this is a security boundary and not a formatting nicety
///
/// The `htu` claim is what stops a proof captured at one endpoint being
/// presented at another (RFC 9449 §11, opening paragraph). That defence is a
/// string comparison, and a string comparison has two ways to fail:
///
/// * **Too strict.** `https://as.example/token` and
///   `https://AS.EXAMPLE:443/token?x=1` are the same resource. A server that
///   calls them different refuses conforming clients, which is why RFC 9449
///   §4.3 asks for syntax-based (RFC 3986 §6.2.2) and scheme-based (RFC 3986
///   §6.2.3) normalisation "to reduce the likelihood of false negatives".
/// * **Too loose.** Every step that widens the set of strings accepted as "our
///   token endpoint" is a step toward accepting one that is not, and the
///   binding stops meaning anything.
///
/// So the rule here is: apply exactly the normalisations RFC 9110 §4.2.3
/// enumerates for `http`/`https` URIs, run *both sides* through this same
/// function, and add nothing.
///
/// # What is normalised
///
/// 1. **Scheme and host are lowercased**, and only those. RFC 9110 §4.2.3:
///    "The scheme and host are case-insensitive and normally provided in
///    lowercase; all other components are compared in a case-sensitive
///    manner." The path is therefore *not* lowercased — `/Token` and `/token`
///    are different resources.
/// 2. **A default port is dropped.** `https://as.example:443/token` and
///    `https://as.example/token` are one URI (RFC 9110 §4.2.3, first bullet;
///    RFC 3986 §6.2.3). A non-default port is kept and is significant.
/// 3. **Query and fragment are removed**, from both sides. RFC 9449 §4.2 says
///    a client must not put them in `htu` at all, but §4.3 item 9 — the
///    *checking* rule, which is the one a server implements — says to compare
///    "ignoring any query and fragment parts". Ignoring is strictly more
///    forgiving than refusing and costs nothing: they are removed before the
///    comparison, so a proof that carries them is neither refused nor able to
///    smuggle anything past it.
/// 4. **An empty path becomes `/`**, per RFC 9110 §4.2.3's second bullet. A
///    *trailing slash anywhere else is significant*: `/token` and `/token/`
///    stay different, because RFC 3986 §6.2.2.3 removes dot-segments and
///    nothing else, and a trailing slash is a real empty final segment. This
///    server's endpoints are mounted without one, so a proof for `/token/` is
///    a proof for a path this server does not serve.
/// 5. **Percent-encoded unreserved octets are decoded**, then dot-segments are
///    removed again. RFC 9110 §4.2.3, fourth bullet: `%7E` and `~` are the same
///    character and the normal form is not to encode it. Decoding is limited
///    to the unreserved set of RFC 3986 §2.3 — never `%2F`, never `%3F` — so
///    it cannot introduce a delimiter and change the URI's structure. A
///    triplet that stays encoded has its **hex digits uppercased**, per RFC
///    3986 §6.2.2.1 ("should be normalized to use uppercase letters"): §2.1
///    makes `%2f` and `%2F` the same octet, so a client that spells a reserved
///    character in lowercase names the same path and its proof must not be
///    refused. The
///    second dot-segment pass is RFC 3986 §6.2.2's own ordering: percent-
///    encoding normalisation (§6.2.2.2) precedes path segment normalisation
///    (§6.2.2.3), so a decoded `%2E%2E` has to be collapsed like the `..` it
///    now is. A `%` that begins no escape is written as `%25`, so that the
///    output holds no `%` this function would read differently on a second
///    pass — normalisation has to be a fixed point to be a comparison.
///
/// # What is refused outright
///
/// * **A scheme other than `http` or `https`.** Those are the two whose
///   normalisation rules RFC 9110 §4.2.3 defines, and they are the only ones
///   an HTTP request can be made to. (`http` is not refused here: it simply
///   cannot equal this server's `https` endpoint, and refusing it separately
///   would be a second rule saying the same thing.)
/// * **Userinfo.** RFC 9110 §4.2.4: "Before making use of an `http` or `https`
///   URI reference received from an untrusted source, a recipient SHOULD parse
///   for userinfo and treat its presence as an error; it is likely being used
///   to obscure the authority for the sake of phishing attacks." A `htu` is
///   precisely such a reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalisedUri(String);

impl NormalisedUri {
    /// Normalises one URI.
    ///
    /// # Errors
    ///
    /// Returns [`DpopError::UriMismatch`] if `raw` is not an absolute
    /// `http`/`https` URI with a host, carries userinfo, or is longer than
    /// [`MAX_URI_BYTES`]. One error for all of them: the caller's next move is
    /// the same in every case, and a finer answer would tell whoever sent the
    /// proof how far their URL got through this function.
    // fuzz-target: dpop_proof
    pub fn parse(raw: &str) -> Result<Self, DpopError> {
        if raw.len() > MAX_URI_BYTES {
            return Err(DpopError::UriMismatch);
        }
        let parsed = url::Url::parse(raw).map_err(|_| DpopError::UriMismatch)?;

        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(DpopError::UriMismatch);
        }
        // RFC 9110 §4.2.4.
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(DpopError::UriMismatch);
        }
        // A URI with no authority cannot name an endpoint of ours. `url`
        // guarantees a host for the two schemes above, but asking is cheaper
        // than relying on it.
        if parsed.host().is_none() {
            return Err(DpopError::UriMismatch);
        }

        let mut normalised = parsed;
        normalised.set_query(None);
        normalised.set_fragment(None);
        let decoded = decode_unreserved(normalised.path());
        // Re-parse rather than `set_path`: decoding may have produced `.` or
        // `..` segments that were percent-encoded on the way in, and a full
        // parse is what re-applies RFC 3986 §6.2.2.3 to them.
        let reparsed = url::Url::parse(&format!(
            "{}://{}{}{}",
            normalised.scheme(),
            normalised.host_str().ok_or(DpopError::UriMismatch)?,
            normalised
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default(),
            if decoded.starts_with('/') {
                decoded
            } else {
                format!("/{decoded}")
            },
        ))
        .map_err(|_| DpopError::UriMismatch)?;

        Ok(Self(reparsed.into()))
    }

    /// The normalised form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for NormalisedUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Decodes percent-escapes that name an unreserved character (RFC 3986 §2.3).
///
/// Only `ALPHA / DIGIT / "-" / "." / "_" / "~"`. Every other escape is kept as
/// an escape — decoding a reserved octet such as `%2F` would change where the
/// path's segment boundaries are, which is the difference between normalising
/// a URI and rewriting it — but its two hex digits are uppercased, which is the
/// normal form of RFC 3986 §6.2.2.1 and changes no octet (§2.1: the hexadecimal
/// digits are case-insensitive).
///
/// A `%` that begins no escape at all is written out as `%25`, which is what
/// RFC 3986 §2.1 says a literal percent sign is. The output therefore contains
/// no `%` that is not the start of a triplet, and feeding it back in is a
/// fixed point.
fn decode_unreserved(path: &str) -> String {
    const fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    const fn is_unreserved(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
    }

    let bytes = path.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            out.push(bytes[index]);
            index += 1;
            continue;
        }
        match (
            bytes.get(index + 1).copied().and_then(hex),
            bytes.get(index + 2).copied().and_then(hex),
        ) {
            // An unreserved octet: RFC 3986 §6.2.2.2, the normal form is the
            // character itself.
            (Some(high), Some(low)) if is_unreserved(high * 16 + low) => {
                out.push(high * 16 + low);
                index += 3;
            }
            // A well-formed triplet that must stay encoded — `%2F`, `%3F`.
            // Rewritten from the decoded nibbles rather than copied, so that
            // the hex digits come out uppercase: RFC 3986 §2.1 makes `%2f`
            // and `%2F` the same octet and §6.2.2.1 names the uppercase
            // spelling as the normal form. Copying the input verbatim let two
            // spellings of one path compare unequal, which is a false break
            // of the `htu` binding (`ast-7t9`). Uppercase hex maps to itself,
            // so this stays a fixed point. Three bytes in, three bytes out,
            // and `index` still steps past both digits, so neither is ever
            // re-examined as the start of something else.
            (Some(high), Some(low)) => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push(b'%');
                out.push(HEX[high as usize]);
                out.push(HEX[low as usize]);
                index += 3;
            }
            // A `%` that begins no triplet at all. RFC 3986 §2.1 has no such
            // thing: the normal form of a literal percent sign is `%25`.
            //
            // Leaving it bare is not merely untidy, it breaks idempotence,
            // and idempotence is what makes this function a canonical form
            // rather than one step of an unbounded rewrite. Decoding an
            // unreserved octet shortens the string, so a bare `%` can end up
            // against the hex digits that followed the triplet: `%%370`
            // becomes `%70`, which the *next* normalisation reads as `p`.
            // Two spellings of one path then compare unequal, and `htu`
            // stops being a binding.
            _ => {
                out.extend_from_slice(b"%25");
                index += 1;
            }
        }
    }
    // Every byte written is either one that was already in a `&str` or an
    // ASCII octet, so this cannot fail; the fallback exists so that a future
    // change to the loop is a wrong answer rather than a panic in a parser
    // reachable before authentication.
    String::from_utf8(out).unwrap_or_else(|_| path.to_owned())
}

// ---------------------------------------------------------------------------
// Nonces
// ---------------------------------------------------------------------------

/// Issues and checks server nonces without storing any (RFC 9449 §8).
///
/// # Why derived rather than stored
///
/// A nonce that lives in a table is a write on the authentication path: every
/// token request would insert a row and every retry would read one, for a value
/// whose only job is to be unguessable and recent. Deriving it from a secret
/// and a time window gives the same two properties with no write, no read, no
/// expiry sweep, and — the part that matters for more than one replica — no
/// shared state beyond the secret itself.
///
/// The nonce is `base64url(HMAC-SHA256(secret, domain ‖ audience ‖ window)[..16])`.
/// It is unpredictable to anyone without the secret, which is RFC 9449 §8's
/// only requirement of the value ("Nonce values MUST be unpredictable"), and it
/// encodes the server's own clock, which §11.1 notes is the point: a nonce
/// "containing the time at the server" bounds a proof's age "even in the face
/// of arbitrarily large clock skews".
///
/// `audience` is folded in so that a nonce issued by one tenant is not accepted
/// at another. RFC 9449 §9 says a nonce "should be used only at the issuing
/// server", and two tenants of this process are two issuers.
///
/// # The window boundary
///
/// This is the part worth being explicit about, because getting it wrong
/// produces an infinite `use_dpop_nonce` loop rather than a visible failure.
///
/// A nonce is minted for the window containing the current instant. A presented
/// nonce is accepted if it matches the **current window or the immediately
/// preceding one**. So a nonce handed to a client at any moment is usable for
/// *at least* one whole window and at most two — five to ten minutes at the
/// default.
///
/// Without that one step of lookback the guaranteed lifetime would be zero: a
/// client that received a nonce a millisecond before a boundary would be told
/// `use_dpop_nonce` on its retry, receive the next window's nonce, and — if it
/// were unlucky twice — be told again. RFC 9449 §8 describes the nonce
/// mismatch as "self-correcting"; that is true only if the correction
/// converges, and a window with no lookback is a window where it need not.
///
/// The lookback costs nothing in replay terms. RFC 9449 §11.1: "it is
/// acceptable for clients to use the same nonce multiple times and for the
/// server to accept the same nonce multiple times. As long as the `jti` value
/// is tracked and duplicates are rejected for the lifetime of the nonce, there
/// is no additional risk of token replay." The binding constraint on a proof's
/// life here is [`DEFAULT_MAX_AGE`] on `iat`, which is shorter than the nonce's,
/// and the `jti` is tracked for exactly that long.
///
/// # Restarts and replicas
///
/// [`NonceIssuer::generate`] makes a per-process secret, which is correct for a
/// single replica and wrong for several: two replicas would reject each other's
/// nonces, and every restart would invalidate the outstanding ones. Both are
/// survivable — the client is told `use_dpop_nonce` and retries with the value
/// it is handed — but a deployment with more than one replica should pass a
/// shared secret to [`NonceIssuer::from_secret`] so that the retry is not the
/// normal case.
pub struct NonceIssuer {
    key: hmac::Key,
    window: Duration,
}

impl std::fmt::Debug for NonceIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key, not even its length: a `Debug` of a MAC key is
        // exactly the line that ends up in an issue report.
        f.debug_struct("NonceIssuer")
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

impl NonceIssuer {
    /// Domain separation, so this HMAC key can never be confused with another
    /// use of the same secret.
    const DOMAIN: &'static [u8] = b"asterius/dpop-nonce/v1";

    /// An issuer over an operator-supplied secret.
    ///
    /// Share this across replicas. The secret is only ever used as an HMAC key,
    /// so any length is accepted; 32 bytes of CSPRNG output is the sensible
    /// one.
    #[must_use]
    pub fn from_secret(secret: &[u8]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            window: DEFAULT_NONCE_WINDOW,
        }
    }

    /// An issuer over a freshly generated per-process secret.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::KeyGeneration`] if the provider has no working
    /// CSPRNG, which is a reason not to start rather than to carry on with a
    /// predictable nonce.
    pub fn generate() -> Result<Self, JoseError> {
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &aws_lc_rs::rand::SystemRandom::new())
            .map_err(|_| JoseError::KeyGeneration(SigningAlgorithm::EdDsa))?;
        Ok(Self {
            key,
            window: DEFAULT_NONCE_WINDOW,
        })
    }

    /// Sets the window, clamped to [`MIN_NONCE_WINDOW`]–[`MAX_NONCE_WINDOW`].
    ///
    /// Clamped rather than refused, as elsewhere: an operator who configures
    /// this badly should get a compliant server rather than a broken one.
    #[must_use]
    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window.clamp(MIN_NONCE_WINDOW, MAX_NONCE_WINDOW);
        self
    }

    /// The window in force.
    #[must_use]
    pub const fn window(&self) -> Duration {
        self.window
    }

    /// The nonce a client should use now.
    #[must_use]
    pub fn issue(&self, audience: &str, now: OffsetDateTime) -> String {
        self.derive(audience, self.window_index(now))
    }

    /// Whether `presented` is a nonce this server issued for `audience` in the
    /// current or previous window.
    ///
    /// Compared in constant time and without short-circuiting between the two
    /// windows. The nonce is not a secret in the sense a password is — the
    /// server hands it out — but it is a value derived from one, and a
    /// comparison that stops at the first differing byte is a per-byte oracle
    /// for the derivation.
    // fuzz-target: dpop_proof
    #[must_use]
    pub fn accepts(&self, presented: &str, audience: &str, now: OffsetDateTime) -> bool {
        let index = self.window_index(now);
        let current = self.derive(audience, index);
        let previous = self.derive(audience, index.saturating_sub(1));
        // `|` and not `||`: both comparisons always run, so the time taken
        // does not say which window matched, or that neither did early.
        ct_eq(presented.as_bytes(), current.as_bytes())
            | ct_eq(presented.as_bytes(), previous.as_bytes())
    }

    /// Which window `now` falls in.
    fn window_index(&self, now: OffsetDateTime) -> i64 {
        // `div_euclid` and not `/`: before 1970 the two disagree about
        // rounding, and a window that is a different length on one side of the
        // epoch is a boundary condition waiting to be found by a test fixture.
        let seconds = self.window.whole_seconds().max(1);
        now.unix_timestamp().div_euclid(seconds)
    }

    /// The nonce for one window.
    fn derive(&self, audience: &str, index: i64) -> String {
        let mut message = Vec::with_capacity(Self::DOMAIN.len() + audience.len() + 16);
        message.extend_from_slice(Self::DOMAIN);
        // A zero byte between the fields, so that two different (audience,
        // window) pairs cannot serialise to the same message.
        message.push(0);
        message.extend_from_slice(audience.as_bytes());
        message.push(0);
        message.extend_from_slice(&index.to_be_bytes());

        let tag = hmac::sign(&self.key, &message);
        // 128 bits. RFC 9449 §8 asks only that the value be unpredictable;
        // half a SHA-256 is comfortably that, and a shorter nonce is a shorter
        // header on every request that carries one. The encoding is base64url,
        // which is inside §8.1's `NQCHAR` — no quote, no backslash, nothing
        // that needs escaping in the `DPoP-Nonce` header or in the proof.
        B64.encode(&tag.as_ref()[..16])
    }
}

/// What a proof's `nonce` claim must satisfy.
#[derive(Debug, Clone, Copy)]
pub enum NonceRule<'a> {
    /// This deployment issues no nonces.
    ///
    /// RFC 9449 §8 is a MAY and FAPI 2.0 SP §5.3.2.1 item 10 keeps it one. A
    /// proof may still carry a `nonce`; it is ignored, because a server that
    /// has never issued one has nothing to compare it against.
    NotRequired,
    /// A nonce is required, and must be one `issuer` minted for `audience`.
    ///
    /// RFC 9449 §11.3 — "A server MUST NOT accept any DPoP proofs without the
    /// `nonce` claim when a DPoP nonce has been provided to the client" — is
    /// a per-client rule that a stateless server cannot evaluate per client.
    /// The resolution is to make it deployment-wide: with the feature on,
    /// every proof needs a nonce, whether or not this particular client has
    /// been handed one yet. That is strictly stronger than the RFC's rule and
    /// has no downgrade to negotiate.
    Required {
        /// The issuer whose nonces are accepted.
        issuer: &'a NonceIssuer,
        /// The tenant this nonce was minted for — its issuer identifier.
        audience: &'a str,
    },
}

// ---------------------------------------------------------------------------
// Checking a proof
// ---------------------------------------------------------------------------

/// What the receiving endpoint requires of a proof.
///
/// Deliberately not `Default`: the method and the URI are the binding, and a
/// caller that has not supplied them has not checked anything.
#[derive(Debug, Clone)]
pub struct Expectation<'a> {
    /// The HTTP method of the request the proof arrived on.
    ///
    /// Compared byte-for-byte. RFC 9110 §9.1: "The method token is
    /// case-sensitive", so `post` is not `POST` and accepting both would be
    /// this server inventing an equivalence HTTP does not have.
    pub method: &'a str,
    /// This endpoint's own URI, already normalised.
    ///
    /// The caller builds this from the tenant's issuer and the endpoint's
    /// path, never from a request header — see
    /// `asterius_server::http::dpop`.
    pub uri: &'a NormalisedUri,
    /// What the `nonce` claim must satisfy.
    pub nonce: NonceRule<'a>,
    /// The access token this proof accompanies, when there is one.
    ///
    /// RFC 9449 §4.3 item 12: at a protected resource the `ath` claim must
    /// hash the token presented alongside. `None` at the token endpoint, where
    /// there is no access token yet and §4.2 therefore does not require `ath`.
    pub access_token: Option<&'a str>,
    /// How old the proof may be. Clamped to [`MAX_MAX_AGE`].
    pub max_age: Duration,
    /// How far ahead `iat` may be. Clamped to [`verify::MAX_FUTURE_SKEW`].
    pub future_skew: Duration,
}

impl<'a> Expectation<'a> {
    /// The ordinary expectation: this method, this URI, the profile's windows,
    /// no nonce and no access token.
    #[must_use]
    pub const fn new(method: &'a str, uri: &'a NormalisedUri) -> Self {
        Self {
            method,
            uri,
            nonce: NonceRule::NotRequired,
            access_token: None,
            max_age: DEFAULT_MAX_AGE,
            future_skew: verify::DEFAULT_FUTURE_SKEW,
        }
    }

    /// Requires a nonce from `issuer`, minted for `audience`.
    #[must_use]
    pub const fn requiring_nonce(mut self, issuer: &'a NonceIssuer, audience: &'a str) -> Self {
        self.nonce = NonceRule::Required { issuer, audience };
        self
    }

    /// Requires `ath` to hash this access token (RFC 9449 §4.3 item 12).
    #[must_use]
    pub const fn with_access_token(mut self, token: &'a str) -> Self {
        self.access_token = Some(token);
        self
    }

    /// Narrows how old a proof may be.
    #[must_use]
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age.clamp(Duration::ZERO, MAX_MAX_AGE);
        self
    }
}

/// A proof that passed every check in RFC 9449 §4.3.
///
/// Carries the two things a caller owes somebody else: the thumbprint the
/// token is to be bound to, and the `jti` the replay store has to remember
/// until `replay_expires_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The JWK SHA-256 Thumbprint of the proof's public key (RFC 7638).
    ///
    /// The value that goes in `cnf.jkt` (RFC 9449 §6.1), that is compared with
    /// `dpop_jkt` (§10), and that namespaces the `jti` in the replay store.
    pub jkt: Kid,
    /// The `jti`, single use within the `iat` window.
    pub jti: String,
    /// The `iat`, as an instant.
    pub issued_at: OffsetDateTime,
    /// When the replay entry for this `jti` stops being worth keeping.
    ///
    /// `iat` plus the policy's window: past that the proof is refused on age
    /// before the replay check is reached, so the row protects nothing.
    pub replay_expires_at: OffsetDateTime,
    /// The algorithm that verified it.
    pub algorithm: SigningAlgorithm,
}

impl Proof {
    /// The `cnf` claim value for a token bound to this proof's key.
    ///
    /// RFC 9449 §6.1: `{"jkt": "<base64url SHA-256 thumbprint>"}`, under `cnf`
    /// in an access token (RFC 7800) and at the top level of an introspection
    /// response (§6.2).
    #[must_use]
    pub fn confirmation(&self) -> Value {
        serde_json::json!({ "jkt": self.jkt.as_str() })
    }
}

/// Checks a DPoP proof (RFC 9449 §4.3).
///
/// `now` is passed in rather than read, so that one request uses one instant
/// and a test can pin it.
///
/// # What this does not do
///
/// **It does not consume the `jti`.** RFC 9449 §4.3 item 11's window is
/// enforced here and the replay check of §11.1 is not, because the replay
/// store is shared state and this crate reaches nothing. The caller must claim
/// [`Proof::jti`] through [`asterius_domain::ports::ReplayGuard`], namespaced
/// by [`Proof::jkt`], and must do so *after* this returns — claiming first
/// would let anyone who can reach the endpoint burn a key's identifiers with
/// proofs that were never going to be accepted.
///
/// **It does not decide that a proof was required.** A request with no `DPoP`
/// header never reaches here; whether that is acceptable depends on the client
/// (RFC 9449 §5.2) and on the endpoint.
///
/// # Errors
///
/// Returns the first [`DpopError`] that applies. The order of the checks is
/// cheapest-first, which RFC 9449 §4.3 explicitly permits ("These checks may
/// be performed in any order").
// fuzz-target: dpop_proof
pub fn check(
    proof: &str,
    expectation: &Expectation<'_>,
    now: OffsetDateTime,
) -> Result<Proof, DpopError> {
    // Before anything is decoded: an oversized "proof" should cost a length
    // comparison.
    if proof.len() > MAX_PROOF_BYTES {
        return Err(DpopError::TooLarge {
            size: proof.len(),
            limit: MAX_PROOF_BYTES,
        });
    }

    // §4.3 item 2, and items 4–5 by way of `jws::parse`: three segments, no
    // `crit` we do not understand, and an `alg` inside ADR-0003's set — which
    // contains no symmetric algorithm and no `none`, so item 5's "MUST NOT be
    // none or ... a symmetric algorithm" is structural here rather than a
    // check that could be forgotten.
    let unverified = jws::parse(proof)?;

    // §4.3 item 4, before any key is looked at.
    let typ = TypRule::Exactly(PROOF_TYP);
    if !typ.accepts(unverified.claimed_typ()) {
        return Err(DpopError::Verification(
            verify::VerificationError::UnexpectedType {
                expected: PROOF_TYP.to_owned(),
                found: unverified.claimed_typ().map(ToOwned::to_owned),
            },
        ));
    }

    // The algorithm is fixed here and the key is then built *for it*. Taking
    // the algorithm from the `jwk` instead would let a proof present an EC key
    // and an EdDSA header and leave the two to be reconciled by whichever
    // check ran last.
    let claimed_alg = unverified.claimed_alg().to_owned();
    let algorithm = SigningAlgorithm::parse(&claimed_alg)
        .ok_or(verify::VerificationError::AlgorithmNotAllowed { found: claimed_alg })?;

    let key = public_key(unverified.raw_header(), algorithm)?;

    // §4.3 item 6, plus everything RFC 8725 asks of the envelope. The resolver
    // offers exactly the key the proof carries — see the module documentation
    // for why that is sound *here* and nowhere else.
    //
    // `without_expiry`: §4.2's required claims are `jti`, `htm`, `htu` and
    // `iat`, not `exp`. A proof that carries one anyway is still refused once
    // it has passed, which is the safe direction.
    let policy = Policy {
        max_bytes: MAX_PROOF_BYTES,
        ..Policy::new(typ, vec![algorithm])
    }
    .without_expiry()
    .with_future_skew(expectation.future_skew);
    let resolver = move |_: Option<&Kid>| vec![key.clone()];
    let verified = verify::verify(proof, &policy, &resolver, now)?;

    // Everything below reads claims from a token whose signature holds.
    let claims = &verified.claims;

    // §4.3 item 8. Byte-exact: RFC 9110 §9.1 makes the method token
    // case-sensitive.
    let htm = claims
        .get("htm")
        .and_then(Value::as_str)
        .ok_or(DpopError::MalformedClaim("htm"))?;
    if htm != expectation.method {
        return Err(DpopError::MethodMismatch);
    }

    // §4.3 item 9, through the one normaliser both sides go through.
    let htu = claims
        .get("htu")
        .and_then(Value::as_str)
        .ok_or(DpopError::MalformedClaim("htu"))?;
    if &NormalisedUri::parse(htu)? != expectation.uri {
        return Err(DpopError::UriMismatch);
    }

    // §4.3 item 3: `jti` is required, and it is what the replay store will
    // remember, so an unusable one is refused rather than accepted-and-untracked.
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|jti| !jti.is_empty() && jti.len() <= MAX_JTI_LEN)
        .ok_or(DpopError::MalformedClaim("jti"))?
        .to_owned();

    // §4.3 item 11 with §11.1's window. The future half is enforced twice —
    // once by the shared verifier against FAPI 2.0 SP §5.3.2.1 item 13, once
    // here — on purpose: a rule that holds only because of the order two
    // functions happen to run in is a rule waiting for the order to change.
    let issued_at = numeric_claim(claims, "iat")
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .ok_or(DpopError::MalformedClaim("iat"))?;
    let max_age = expectation.max_age.clamp(Duration::ZERO, MAX_MAX_AGE);
    let skew = expectation
        .future_skew
        .clamp(Duration::ZERO, verify::MAX_FUTURE_SKEW);
    if now - issued_at > max_age {
        return Err(DpopError::TooOld {
            age: (now - issued_at).whole_seconds(),
            limit: max_age.whole_seconds(),
        });
    }
    if issued_at - now > skew {
        return Err(DpopError::TooFarAhead {
            seconds_ahead: (issued_at - now).whole_seconds(),
            limit: skew.whole_seconds(),
        });
    }

    // §4.3 item 10, and §11.3's rule against a downgrade.
    if let NonceRule::Required { issuer, audience } = expectation.nonce {
        let nonce = claims
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or(DpopError::NonceRequired)?;
        if !issuer.accepts(nonce, audience, now) {
            return Err(DpopError::NonceStale);
        }
    }

    // §4.3 item 12's first half. The second — that the token's `cnf.jkt` is
    // this key — belongs to whoever holds the token, and is `Proof::jkt`
    // against `cnf.jkt`.
    if let Some(access_token) = expectation.access_token {
        let ath = claims
            .get("ath")
            .and_then(Value::as_str)
            .ok_or(DpopError::MalformedClaim("ath"))?;
        let expected = B64.encode(Sha256::digest(access_token.as_bytes()));
        // Constant time: the access token is a bearer-ish secret and `ath` is
        // a function of it, so a comparison that stops at the first difference
        // is a per-byte oracle for the hash.
        if !ct_eq(ath.as_bytes(), expected.as_bytes()) {
            return Err(DpopError::AccessTokenMismatch);
        }
    }

    let jkt = thumbprint_of(unverified.raw_header(), algorithm)?;

    Ok(Proof {
        jkt,
        jti,
        issued_at,
        replay_expires_at: issued_at + max_age,
        algorithm,
    })
}

/// The `jwk` from a proof's header, as a verifying key for `algorithm`.
///
/// RFC 9449 §4.3 items 3, 6 and 7 all land here.
fn public_key(raw_header: &[u8], algorithm: SigningAlgorithm) -> Result<VerifyingKey, DpopError> {
    let jwk = header_jwk(raw_header)?;

    // §4.3 item 7, first: a disclosure is worth reporting even if the key
    // would also have been unusable.
    if client_keys::has_private_members(&jwk) {
        return Err(DpopError::PrivateKeyMaterial);
    }

    // The `kty` must be the one this algorithm uses, and a declared `alg` must
    // be the header's. Neither is redundant with building the key below: an
    // `{"kty":"EC","alg":"PS256"}` whose coordinates happen to parse would
    // otherwise be verified under an algorithm its author did not name.
    if jwk.get("kty").and_then(Value::as_str) != Some(algorithm.key_type()) {
        return Err(DpopError::UnusableKey(algorithm));
    }
    if let Some(declared) = jwk.get("alg")
        && declared.as_str() != Some(algorithm.as_str())
    {
        return Err(DpopError::UnusableKey(algorithm));
    }

    client_keys::verifying_key(algorithm, &jwk).ok_or(DpopError::UnusableKey(algorithm))
}

/// The RFC 7638 thumbprint of the `jwk` in a proof's header.
fn thumbprint_of(raw_header: &[u8], algorithm: SigningAlgorithm) -> Result<Kid, DpopError> {
    let jwk = header_jwk(raw_header)?;
    store::thumbprint(&Value::Object(jwk)).map_err(|_| DpopError::UnusableKey(algorithm))
}

/// The `jwk` JOSE Header Parameter, as an object.
fn header_jwk(raw_header: &[u8]) -> Result<Map<String, Value>, DpopError> {
    let header: Value = serde_json::from_slice(raw_header).map_err(|_| DpopError::MissingKey)?;
    header
        .get("jwk")
        .and_then(Value::as_object)
        .cloned()
        .ok_or(DpopError::MissingKey)
}

/// Reads a NumericDate claim (RFC 7519 §2).
///
/// A string is not a NumericDate, however numeric it looks — the same rule the
/// shared verifier applies, restated because this module reads `iat` itself.
fn numeric_claim(claims: &Value, name: &str) -> Option<i64> {
    let value = claims.get(name)?;
    value.as_i64().or_else(|| {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "seconds since the epoch; the fraction is what we are discarding"
        )]
        value.as_f64().map(|seconds| seconds.trunc() as i64)
    })
}

// ---------------------------------------------------------------------------
// Key binding (RFC 9449 §10)
// ---------------------------------------------------------------------------

/// Whether the key that signed a proof is the key an earlier request pinned.
///
/// RFC 9449 §10: "When a token request is received, the authorization server
/// computes the JWK Thumbprint of the proof-of-possession public key in the
/// DPoP proof and verifies that it matches the `dpop_jkt` parameter value in
/// the authorization request. If they do not match, it MUST reject the
/// request." FAPI 2.0 SP §5.3.2.1 item 12 makes supporting this mandatory.
///
/// `pinned` is what the pushed authorization request stored; `presented` is
/// [`Proof::jkt`] from the proof at the token endpoint. The three cases:
///
/// * **Nothing pinned** — nothing to correlate, and the code was never bound
///   to a key. `true`. (Whether the *token* may then be DPoP-bound is a
///   separate decision, and one for the grant.)
/// * **Pinned and presented, equal** — the end-to-end binding §10 describes.
/// * **Pinned and anything else**, including no proof at all — refused. A code
///   issued against a pinned key must not be redeemable without it, or the
///   binding would be advisory.
#[must_use]
pub fn matches_pinned_key(pinned: Option<&str>, presented: Option<&Kid>) -> bool {
    match (pinned, presented) {
        (None, _) => true,
        (Some(pinned), Some(presented)) => ct_eq(pinned.as_bytes(), presented.as_str().as_bytes()),
        (Some(_), None) => false,
    }
}

/// Reconciles the two ways a pushed authorization request can pin a DPoP key.
///
/// RFC 9449 §10.1 gives a client a choice: send `dpop_jkt` in the PAR body, or
/// attach a `DPoP` header to the PAR request and let the server behave "as if
/// the contained public key's thumbprint was provided using `dpop_jkt`". It
/// then requires that **both** be supported, and that "if both mechanisms are
/// used at the same time, the authorization server MUST reject the request if
/// the JWK Thumbprint in `dpop_jkt` does not match the public key in the DPoP
/// header."
///
/// Returns the thumbprint to store on the request, or `None` when neither
/// mechanism was used.
///
/// # Errors
///
/// Returns [`DpopError::UriMismatch`]'s sibling for the mismatch case —
/// specifically [`DpopError::MalformedClaim`] naming `dpop_jkt`, because from
/// the client's side that is what is wrong: two parameters of one request
/// disagree about which key this flow is for.
pub fn reconcile_pinned_key(
    from_header: Option<&Kid>,
    from_parameter: Option<&str>,
) -> Result<Option<String>, DpopError> {
    match (from_header, from_parameter) {
        (None, None) => Ok(None),
        (Some(header), None) => Ok(Some(header.as_str().to_owned())),
        (None, Some(parameter)) => Ok(Some(parameter.to_owned())),
        (Some(header), Some(parameter)) => {
            if ct_eq(header.as_str().as_bytes(), parameter.as_bytes()) {
                Ok(Some(parameter.to_owned()))
            } else {
                Err(DpopError::MalformedClaim("dpop_jkt"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SigningKey;

    const ENDPOINT: &str = "https://as.example/t/demo/token";
    const AUDIENCE: &str = "https://as.example/t/demo";

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("fixed instant")
    }

    fn endpoint() -> NormalisedUri {
        NormalisedUri::parse(ENDPOINT).expect("our own endpoint parses")
    }

    /// Signs a proof by hand, so a test can put anything at all in the header.
    fn sign_proof(key: &SigningKey, header: &Value, claims: &Value) -> String {
        let header_json = serde_json::to_vec(header).expect("header");
        let claims_json = serde_json::to_vec(claims).expect("claims");
        let signing_input = format!("{}.{}", B64.encode(&header_json), B64.encode(&claims_json));
        let signature = key.sign(signing_input.as_bytes()).expect("sign");
        format!("{signing_input}.{}", B64.encode(signature))
    }

    fn proof_header(key: &SigningKey) -> Value {
        let mut jwk = key.public_jwk().expect("jwk");
        // A DPoP proof's `jwk` is a bare public key: `use` and `alg` are
        // permitted but are not what identifies it, and the thumbprint ignores
        // them either way (RFC 7638 §3.2).
        if let Some(object) = jwk.as_object_mut() {
            object.remove("use");
        }
        serde_json::json!({
            "typ": PROOF_TYP,
            "alg": key.algorithm().as_str(),
            "jwk": jwk,
        })
    }

    fn proof_claims() -> Value {
        serde_json::json!({
            "jti": "0123456789abcdef",
            "htm": "POST",
            "htu": ENDPOINT,
            "iat": now().unix_timestamp(),
        })
    }

    fn valid_proof(key: &SigningKey) -> String {
        sign_proof(key, &proof_header(key), &proof_claims())
    }

    fn key() -> SigningKey {
        SigningKey::generate(SigningAlgorithm::EdDsa).expect("generate")
    }

    // ---- the happy path ---------------------------------------------------

    #[test]
    fn a_well_formed_proof_is_accepted_for_every_permitted_algorithm() {
        for algorithm in SigningAlgorithm::ALL {
            let key = SigningKey::generate(algorithm).expect("generate");
            let uri = endpoint();
            let proof = check(&valid_proof(&key), &Expectation::new("POST", &uri), now())
                .unwrap_or_else(|e| panic!("{algorithm} proof refused: {e}"));
            assert_eq!(proof.algorithm, algorithm);
            assert_eq!(proof.jti, "0123456789abcdef");
            assert_eq!(proof.issued_at, now());
        }
    }

    /// RFC 9449 §6.1: the `cnf.jkt` is the RFC 7638 thumbprint of the proof's
    /// key. Recomputed here from the JWK rather than read back from the proof,
    /// so the two cannot share a mistake.
    #[test]
    fn the_thumbprint_is_the_rfc_7638_thumbprint_of_the_proofs_key() {
        let key = key();
        let uri = endpoint();
        let proof = check(&valid_proof(&key), &Expectation::new("POST", &uri), now()).expect("ok");

        let expected = store::thumbprint(&key.public_jwk().expect("jwk")).expect("thumbprint");
        assert_eq!(proof.jkt, expected);
        assert_eq!(
            proof.confirmation(),
            serde_json::json!({"jkt": expected.as_str()})
        );
        // 43 characters of base64url: the shape `dpop_jkt` is validated
        // against in `asterius_oidc::authorize`.
        assert_eq!(proof.jkt.as_str().len(), 43);
    }

    /// The replay row must outlive the proof's acceptance window exactly.
    #[test]
    fn the_replay_entry_expires_when_the_proof_stops_being_acceptable() {
        let key = key();
        let uri = endpoint();
        let proof = check(&valid_proof(&key), &Expectation::new("POST", &uri), now()).expect("ok");
        assert_eq!(proof.replay_expires_at, now() + DEFAULT_MAX_AGE);
    }

    /// The RFC's own worked example, end to end.
    ///
    /// The proof is Figure 2 of RFC 9449, reassembled from its RFC 8792 line
    /// wrapping; the thumbprint asserted against it is the one the RFC prints
    /// in Figure 9 as the `cnf.jkt` of the access token issued for it. This is
    /// the only test here whose expected value was not produced by this
    /// codebase, which is what makes it worth more than the others: it checks
    /// the ES256 verification, the RFC 7638 canonicalisation and the `htu`
    /// comparison against a third party that has already published the answer.
    ///
    /// `now` is the proof's own `iat`. A vector from 2019 has no other
    /// meaningful instant to be checked at, and it is why the verifier takes
    /// the time as an argument.
    #[test]
    fn the_rfc_9449_worked_example_verifies_and_reproduces_its_published_jkt() {
        const RFC_PROOF: &str = concat!(
            "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4",
            "dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09r",
            "X282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGk",
            "iOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV",
            "4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdr",
            "j8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg",
        );
        /// RFC 9449 Figure 9.
        const RFC_JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

        let uri = NormalisedUri::parse("https://server.example.com/token").expect("parse");
        let issued_at = OffsetDateTime::from_unix_timestamp(1_562_262_616).expect("the RFC's iat");

        let proof =
            check(RFC_PROOF, &Expectation::new("POST", &uri), issued_at).expect("the RFC's proof");
        assert_eq!(proof.jkt.as_str(), RFC_JKT);
        assert_eq!(proof.jti, "-BwC3ESc6acc2lTc");
        assert_eq!(proof.algorithm, SigningAlgorithm::Es256);
        assert_eq!(proof.confirmation(), serde_json::json!({"jkt": RFC_JKT}));

        // And the same vector at the wrong endpoint, to show the acceptance
        // above is the signature and the binding rather than a permissive
        // path through the function.
        let elsewhere =
            NormalisedUri::parse("https://server.example.com/introspect").expect("parse");
        assert_eq!(
            check(RFC_PROOF, &Expectation::new("POST", &elsewhere), issued_at),
            Err(DpopError::UriMismatch)
        );
    }

    // ---- the rejections RFC 9449 §4.3 requires -----------------------------

    #[test]
    fn a_proof_with_the_wrong_typ_is_refused() {
        let key = key();
        let mut header = proof_header(&key);
        header["typ"] = serde_json::json!("JWT");
        let proof = sign_proof(&key, &header, &proof_claims());
        let uri = endpoint();
        let error = check(&proof, &Expectation::new("POST", &uri), now()).expect_err("refused");
        assert_eq!(error.code(), "invalid_dpop_proof");
    }

    #[test]
    fn a_proof_with_no_typ_is_refused() {
        let key = key();
        let mut header = proof_header(&key);
        header.as_object_mut().expect("object").remove("typ");
        let proof = sign_proof(&key, &header, &proof_claims());
        let uri = endpoint();
        assert!(check(&proof, &Expectation::new("POST", &uri), now()).is_err());
    }

    /// RFC 9449 §4.3 item 3 and §4.2: without `jwk` there is nothing to verify
    /// against, and falling back to any other key would be the whole attack.
    #[test]
    fn a_proof_with_no_jwk_is_refused() {
        let key = key();
        let mut header = proof_header(&key);
        header.as_object_mut().expect("object").remove("jwk");
        let proof = sign_proof(&key, &header, &proof_claims());
        let uri = endpoint();
        assert_eq!(
            check(&proof, &Expectation::new("POST", &uri), now()),
            Err(DpopError::MissingKey)
        );
    }

    /// RFC 9449 §4.2: "It MUST NOT contain a private key." A private member is
    /// a disclosure, and is refused as such — the same rule
    /// `crate::client_keys` applies to a published JWK Set, and for the same
    /// reason.
    #[test]
    fn a_proof_whose_jwk_carries_private_material_is_refused() {
        // Every private member RFC 7518 §6.2.2, §6.3.2 and §6.4.1 define, so a
        // future key type cannot slip one past by using a member nobody
        // thought to list.
        for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            let key = key();
            let mut header = proof_header(&key);
            header["jwk"][member] = serde_json::json!("c2VjcmV0");
            let proof = sign_proof(&key, &header, &proof_claims());
            let uri = endpoint();
            assert_eq!(
                check(&proof, &Expectation::new("POST", &uri), now()),
                Err(DpopError::PrivateKeyMaterial),
                "a jwk carrying `{member}` was not refused as a disclosure"
            );
        }
    }

    /// The signature must verify against the key in the header, and only that
    /// key. A proof signed by one key advertising another is the forgery this
    /// check exists for.
    #[test]
    fn a_proof_signed_by_a_key_other_than_the_one_it_advertises_is_refused() {
        let signer = key();
        let advertised = key();
        let proof = sign_proof(&signer, &proof_header(&advertised), &proof_claims());
        let uri = endpoint();
        assert!(check(&proof, &Expectation::new("POST", &uri), now()).is_err());
    }

    /// RFC 9449 §4.3 item 5: `alg` must not be `none` or symmetric. Neither is
    /// expressible in this server's allow-list, which is the strongest form of
    /// the check — but it is worth a test that the allow-list is what is
    /// actually consulted.
    #[test]
    fn a_proof_naming_an_algorithm_outside_the_allow_list_is_refused() {
        let key = key();
        for algorithm in ["none", "HS256", "RS256", "ES384", ""] {
            let mut header = proof_header(&key);
            header["alg"] = serde_json::json!(algorithm);
            let proof = sign_proof(&key, &header, &proof_claims());
            let uri = endpoint();
            assert!(
                check(&proof, &Expectation::new("POST", &uri), now()).is_err(),
                "alg {algorithm:?} was accepted"
            );
        }
    }

    /// A key type that disagrees with the header's `alg` must not be
    /// reconciled by whichever check happens to run last.
    #[test]
    fn a_jwk_whose_kty_or_alg_disagrees_with_the_header_is_refused() {
        let key = SigningKey::generate(SigningAlgorithm::Es256).expect("generate");
        let uri = endpoint();

        let mut header = proof_header(&key);
        header["jwk"]["kty"] = serde_json::json!("OKP");
        assert!(
            check(
                &sign_proof(&key, &header, &proof_claims()),
                &Expectation::new("POST", &uri),
                now()
            )
            .is_err()
        );

        let mut header = proof_header(&key);
        header["jwk"]["alg"] = serde_json::json!("PS256");
        assert_eq!(
            check(
                &sign_proof(&key, &header, &proof_claims()),
                &Expectation::new("POST", &uri),
                now()
            ),
            Err(DpopError::UnusableKey(SigningAlgorithm::Es256))
        );
    }

    #[test]
    fn a_proof_for_another_method_is_refused() {
        let key = key();
        let uri = endpoint();
        let proof = valid_proof(&key);
        assert_eq!(
            check(&proof, &Expectation::new("GET", &uri), now()),
            Err(DpopError::MethodMismatch)
        );
        // RFC 9110 §9.1: the method token is case-sensitive.
        assert_eq!(
            check(&proof, &Expectation::new("post", &uri), now()),
            Err(DpopError::MethodMismatch)
        );
    }

    #[test]
    fn a_proof_for_another_url_is_refused() {
        let key = key();
        let uri = endpoint();
        for htu in [
            "https://as.example/t/demo/introspect",
            "https://as.example/t/other/token",
            "https://attacker.example/t/demo/token",
            "http://as.example/t/demo/token",
            "https://as.example:8443/t/demo/token",
            // A trailing slash is a real, empty final segment.
            "https://as.example/t/demo/token/",
            // Userinfo is refused outright (RFC 9110 §4.2.4).
            "https://as.example@as.example/t/demo/token",
            "not-a-uri",
            "",
        ] {
            let mut claims = proof_claims();
            claims["htu"] = serde_json::json!(htu);
            let proof = sign_proof(&key, &proof_header(&key), &claims);
            assert_eq!(
                check(&proof, &Expectation::new("POST", &uri), now()),
                Err(DpopError::UriMismatch),
                "htu {htu:?} was accepted for {ENDPOINT}"
            );
        }
    }

    /// The normalisations RFC 9449 §4.3 asks for, each one a proof that would
    /// otherwise be refused for no security reason.
    #[test]
    fn a_proof_whose_htu_needs_normalising_is_accepted() {
        let key = key();
        let uri = endpoint();
        for htu in [
            "https://as.example/t/demo/token",
            "HTTPS://AS.EXAMPLE/t/demo/token",
            "https://As.Example:443/t/demo/token",
            "https://as.example/t/demo/token?client_id=billing",
            "https://as.example/t/demo/token#anchor",
            "https://as.example/t/demo/token?a=1#b",
            "https://as.example/t/./demo/token",
            "https://as.example/t/other/../demo/token",
            "https://as.example/t/demo/%74oken",
            "https://as.example/t/demo/tok%65n",
        ] {
            let mut claims = proof_claims();
            claims["htu"] = serde_json::json!(htu);
            let proof = sign_proof(&key, &proof_header(&key), &claims);
            assert!(
                check(&proof, &Expectation::new("POST", &uri), now()).is_ok(),
                "htu {htu:?} was refused, though it names {ENDPOINT}"
            );
        }
    }

    /// The path is compared case-sensitively (RFC 9110 §4.2.3), and a decoded
    /// unreserved octet must not be able to introduce a delimiter.
    #[test]
    fn htu_normalisation_does_not_widen_beyond_the_rules() {
        let uri = endpoint();
        for htu in [
            "https://as.example/T/DEMO/TOKEN",
            // `%2F` is reserved; decoding it would merge two segments into one.
            "https://as.example/t%2Fdemo/token",
            // `..` that is only `..` after decoding must still be collapsed —
            // this one names `/t/demo/token`, so it is *accepted*; the point of
            // the case is that it is not accepted as some other path.
        ] {
            let key = key();
            let mut claims = proof_claims();
            claims["htu"] = serde_json::json!(htu);
            let proof = sign_proof(&key, &proof_header(&key), &claims);
            assert_eq!(
                check(&proof, &Expectation::new("POST", &uri), now()),
                Err(DpopError::UriMismatch),
                "htu {htu:?} was accepted for {ENDPOINT}"
            );
        }
    }

    /// Percent-encoded dot segments are decoded and then collapsed, in that
    /// order — RFC 3986 §6.2.2.2 before §6.2.2.3.
    #[test]
    fn percent_encoded_dot_segments_are_collapsed_after_decoding() {
        assert_eq!(
            NormalisedUri::parse("https://as.example/t/other/%2E%2E/demo/token").expect("parse"),
            endpoint()
        );
        assert_eq!(
            NormalisedUri::parse("https://as.example/t/%2E/demo/token").expect("parse"),
            endpoint()
        );
    }

    /// RFC 9110 §4.2.3: an empty path is equivalent to `/`.
    #[test]
    fn an_empty_path_normalises_to_a_single_slash() {
        assert_eq!(
            NormalisedUri::parse("https://as.example").expect("parse"),
            NormalisedUri::parse("https://as.example/").expect("parse")
        );
    }

    /// A non-default port is significant; the default one is not.
    #[test]
    fn only_the_default_port_is_elided() {
        assert_eq!(
            NormalisedUri::parse("https://as.example:443/token").expect("parse"),
            NormalisedUri::parse("https://as.example/token").expect("parse")
        );
        assert_ne!(
            NormalisedUri::parse("https://as.example:8443/token").expect("parse"),
            NormalisedUri::parse("https://as.example/token").expect("parse")
        );
        assert_eq!(
            NormalisedUri::parse("http://as.example:80/token").expect("parse"),
            NormalisedUri::parse("http://as.example/token").expect("parse")
        );
    }

    /// Normalising twice must give the same answer as normalising once, or the
    /// comparison depends on how many times each side has been through it.
    #[test]
    fn normalisation_is_idempotent() {
        for raw in [
            "https://AS.EXAMPLE:443/t/./demo/%74oken?x=1#y",
            "http://as.example",
            "https://as.example/a/b/../c",
            // A `%` that begins no valid escape. Decoding an unreserved octet
            // shortens what follows it, so two of these in a row can slide a
            // stray `%` up against hex digits and manufacture an escape that
            // was not in the input (`ast-l4n`, found by the `dpop_proof`
            // fuzz target).
            "https://as.example/a%%370",
            "https://as.example/%%%370",
            "https://as.example/100%",
            "https://as.example/%zz",
        ] {
            let once = NormalisedUri::parse(raw).expect("parse");
            let twice = NormalisedUri::parse(once.as_str()).expect("re-parse");
            assert_eq!(once, twice, "normalising {raw:?} twice changed the answer");
        }
    }

    /// RFC 3986 §2.1: a `%` in a URI always introduces a triplet. One that
    /// does not is malformed, and its normal form is the escape for the
    /// character itself. Leaving it bare is what let the fuzzer build
    /// `%%370` -> `%70` -> `p`: a path that means one thing to this server
    /// and another to whoever normalises once more.
    #[test]
    fn a_stray_percent_is_escaped_rather_than_left_to_form_a_new_escape() {
        let uri = NormalisedUri::parse("https://as.example/a%%370").expect("parse");
        // `%` -> `%25`, then `%37` is `7`, then a literal `0`.
        assert_eq!(uri.as_str(), "https://as.example/a%2570");
        assert!(
            !uri.as_str().contains("%70"),
            "normalisation manufactured an escape: {}",
            uri.as_str()
        );
    }

    /// The escaping of a stray `%` must not make two different paths equal,
    /// nor split one path in two.
    #[test]
    fn escaping_a_stray_percent_keeps_distinct_paths_distinct() {
        assert_ne!(
            NormalisedUri::parse("https://as.example/a%").expect("parse"),
            NormalisedUri::parse("https://as.example/a").expect("parse")
        );
        assert_eq!(
            NormalisedUri::parse("https://as.example/a%25").expect("parse"),
            NormalisedUri::parse("https://as.example/a%").expect("parse")
        );
    }

    /// RFC 3986 §2.1: "The uppercase hexadecimal digits 'A' through 'F' are
    /// equivalent to the lowercase digits". §6.2.2.1 names the uppercase
    /// spelling as the normal form. A client that encodes a reserved octet in
    /// lowercase names the very same path, and refusing its proof would be a
    /// false break of the `htu` binding.
    #[test]
    fn the_hex_of_a_retained_triplet_is_case_insensitive() {
        assert_eq!(
            NormalisedUri::parse("https://as.example/t%2fdemo/token").expect("parse"),
            NormalisedUri::parse("https://as.example/t%2Fdemo/token").expect("parse")
        );
    }

    /// RFC 3986 §6.2.2.1: the normal form of a retained triplet is uppercase.
    #[test]
    fn a_retained_triplet_is_normalised_to_uppercase_hex() {
        assert_eq!(
            NormalisedUri::parse("https://as.example/t%2fdemo/token")
                .expect("parse")
                .as_str(),
            "https://as.example/t%2Fdemo/token"
        );
    }

    #[test]
    fn a_proof_missing_a_required_claim_is_refused() {
        for claim in ["jti", "htm", "htu", "iat"] {
            let key = key();
            let mut claims = proof_claims();
            claims.as_object_mut().expect("object").remove(claim);
            let proof = sign_proof(&key, &proof_header(&key), &claims);
            let uri = endpoint();
            assert!(
                check(&proof, &Expectation::new("POST", &uri), now()).is_err(),
                "a proof with no {claim} was accepted"
            );
        }
    }

    #[test]
    fn an_unusable_jti_is_refused() {
        for jti in [
            serde_json::json!(""),
            serde_json::json!("x".repeat(MAX_JTI_LEN + 1)),
            serde_json::json!(42),
            serde_json::json!(["a"]),
            Value::Null,
        ] {
            let key = key();
            let mut claims = proof_claims();
            claims["jti"] = jti.clone();
            let proof = sign_proof(&key, &proof_header(&key), &claims);
            let uri = endpoint();
            assert_eq!(
                check(&proof, &Expectation::new("POST", &uri), now()),
                Err(DpopError::MalformedClaim("jti")),
                "jti {jti:?} was accepted"
            );
        }
    }

    /// RFC 9449 §11.1 on the old end, FAPI 2.0 SP §5.3.2.1 item 13 on the new.
    #[test]
    fn an_iat_outside_the_window_is_refused() {
        let uri = endpoint();
        let boundary = DEFAULT_MAX_AGE.whole_seconds();
        let skew = verify::DEFAULT_FUTURE_SKEW.whole_seconds();
        for (offset, acceptable) in [
            (-boundary - 1, false),
            (-boundary, true),
            (-1, true),
            (0, true),
            (skew, true),
            (skew + 1, false),
            (3600, false),
        ] {
            let key = key();
            let mut claims = proof_claims();
            claims["iat"] = serde_json::json!(now().unix_timestamp() + offset);
            let proof = sign_proof(&key, &proof_header(&key), &claims);
            let outcome = check(&proof, &Expectation::new("POST", &uri), now());
            assert_eq!(
                outcome.is_ok(),
                acceptable,
                "an iat {offset}s from now was {}: {outcome:?}",
                if acceptable { "refused" } else { "accepted" }
            );
        }
    }

    /// A tenant may shorten the window; it may not lengthen it past the
    /// ceiling, because the window is also how long the replay table has to
    /// remember every `jti` in it.
    #[test]
    fn the_max_age_is_clamped_to_the_ceiling() {
        let uri = endpoint();
        let expectation = Expectation::new("POST", &uri).with_max_age(Duration::hours(1));
        assert_eq!(expectation.max_age, MAX_MAX_AGE);

        let key = key();
        let mut claims = proof_claims();
        claims["iat"] =
            serde_json::json!((now() - MAX_MAX_AGE - Duration::seconds(1)).unix_timestamp());
        let proof = sign_proof(&key, &proof_header(&key), &claims);
        assert!(matches!(
            check(&proof, &expectation, now()),
            Err(DpopError::TooOld { .. })
        ));
    }

    #[test]
    fn an_oversized_proof_is_refused_before_it_is_parsed() {
        let uri = endpoint();
        let proof = "a".repeat(MAX_PROOF_BYTES + 1);
        assert!(matches!(
            check(&proof, &Expectation::new("POST", &uri), now()),
            Err(DpopError::TooLarge { .. })
        ));
    }

    // ---- nonces -----------------------------------------------------------

    #[test]
    fn a_nonce_is_accepted_in_the_window_it_was_issued_in_and_the_next_one() {
        let issuer = NonceIssuer::from_secret(b"a shared secret");
        let window = issuer.window();
        let nonce = issuer.issue(AUDIENCE, now());

        assert!(issuer.accepts(&nonce, AUDIENCE, now()));
        // Anywhere in the same window.
        assert!(issuer.accepts(&nonce, AUDIENCE, now() + Duration::seconds(1)));
        // The whole of the next window: this is the lookback, and it is what
        // stops a client that fetched a nonce near a boundary from looping.
        assert!(issuer.accepts(&nonce, AUDIENCE, now() + window));

        // And exactly where it stops. The boundary is a property of the
        // *windows*, not of the moment of issue, so it is computed the way the
        // issuer computes it rather than as "issued_at plus something".
        let seconds = window.whole_seconds();
        let window_ends_at = OffsetDateTime::from_unix_timestamp(
            (now().unix_timestamp().div_euclid(seconds) + 1) * seconds,
        )
        .expect("a window boundary is a valid instant");
        assert!(issuer.accepts(
            &nonce,
            AUDIENCE,
            window_ends_at + window - Duration::seconds(1)
        ));
        assert!(!issuer.accepts(&nonce, AUDIENCE, window_ends_at + window));
    }

    #[test]
    fn a_nonce_older_than_two_windows_is_refused() {
        let issuer = NonceIssuer::from_secret(b"a shared secret");
        let nonce = issuer.issue(AUDIENCE, now());
        assert!(!issuer.accepts(&nonce, AUDIENCE, now() + issuer.window() * 3));
    }

    /// The guarantee that makes the boundary survivable: whenever a nonce is
    /// issued, it is still good a whole window later.
    #[test]
    fn a_nonce_is_good_for_at_least_one_whole_window_whenever_it_was_issued() {
        let issuer = NonceIssuer::from_secret(b"a shared secret");
        let window = issuer.window();
        // Every second of one window, including both boundaries.
        for offset in [0, 1, 59, 60, 149, window.whole_seconds() - 1] {
            let issued_at = now() + Duration::seconds(offset);
            let nonce = issuer.issue(AUDIENCE, issued_at);
            assert!(
                issuer.accepts(&nonce, AUDIENCE, issued_at + window),
                "a nonce issued at +{offset}s had expired one window later"
            );
        }
    }

    #[test]
    fn a_nonce_from_another_tenant_or_another_secret_is_refused() {
        let issuer = NonceIssuer::from_secret(b"a shared secret");
        let other = NonceIssuer::from_secret(b"a different secret");
        let nonce = issuer.issue(AUDIENCE, now());

        assert!(!issuer.accepts(&nonce, "https://as.example/t/other", now()));
        assert!(!other.accepts(&nonce, AUDIENCE, now()));
        assert!(!issuer.accepts("", AUDIENCE, now()));
        assert!(!issuer.accepts("not a nonce", AUDIENCE, now()));
    }

    /// RFC 9449 §8.1: `nonce = 1*NQCHAR`, which excludes the double quote and
    /// the backslash. base64url has neither, so the value never needs escaping
    /// in a header or in JSON — worth asserting rather than assuming.
    #[test]
    fn a_nonce_is_nqchar_and_unpredictable_looking() {
        let issuer = NonceIssuer::generate().expect("csprng");
        let nonce = issuer.issue(AUDIENCE, now());
        assert!(!nonce.is_empty());
        assert!(
            nonce
                .bytes()
                .all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e)),
            "nonce {nonce:?} is not NQCHAR"
        );
        assert!(
            nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        // Two processes must not agree on a nonce by accident.
        let elsewhere = NonceIssuer::generate().expect("csprng");
        assert_ne!(nonce, elsewhere.issue(AUDIENCE, now()));
    }

    #[test]
    fn the_window_is_clamped() {
        let issuer = NonceIssuer::from_secret(b"s");
        assert_eq!(issuer.window(), DEFAULT_NONCE_WINDOW);
        assert_eq!(
            NonceIssuer::from_secret(b"s")
                .with_window(Duration::seconds(1))
                .window(),
            MIN_NONCE_WINDOW
        );
        assert_eq!(
            NonceIssuer::from_secret(b"s")
                .with_window(Duration::hours(1))
                .window(),
            MAX_NONCE_WINDOW
        );
    }

    #[test]
    fn a_proof_with_no_nonce_is_refused_when_one_is_required() {
        let issuer = NonceIssuer::from_secret(b"a shared secret");
        let key = key();
        let uri = endpoint();
        let expectation = Expectation::new("POST", &uri).requiring_nonce(&issuer, AUDIENCE);

        let error = check(&valid_proof(&key), &expectation, now()).expect_err("refused");
        assert_eq!(error, DpopError::NonceRequired);
        // The client is told to retry, not that its credential is bad.
        assert_eq!(error.code(), "use_dpop_nonce");
        assert!(error.wants_nonce());
    }

    #[test]
    fn a_proof_with_a_stale_or_foreign_nonce_is_refused() {
        let issuer = NonceIssuer::from_secret(b"a shared secret");
        let uri = endpoint();
        let expectation = Expectation::new("POST", &uri).requiring_nonce(&issuer, AUDIENCE);

        for nonce in [
            issuer.issue(AUDIENCE, now() - issuer.window() * 3),
            issuer.issue("https://as.example/t/other", now()),
            "guessed".to_owned(),
        ] {
            let key = key();
            let mut claims = proof_claims();
            claims["nonce"] = serde_json::json!(nonce);
            let proof = sign_proof(&key, &proof_header(&key), &claims);
            assert_eq!(
                check(&proof, &expectation, now()),
                Err(DpopError::NonceStale),
                "nonce {nonce:?} was accepted"
            );
        }
    }

    #[test]
    fn a_proof_with_a_current_nonce_is_accepted() {
        let issuer = NonceIssuer::from_secret(b"a shared secret");
        let key = key();
        let uri = endpoint();
        let mut claims = proof_claims();
        claims["nonce"] = serde_json::json!(issuer.issue(AUDIENCE, now()));
        let proof = sign_proof(&key, &proof_header(&key), &claims);
        assert!(
            check(
                &proof,
                &Expectation::new("POST", &uri).requiring_nonce(&issuer, AUDIENCE),
                now()
            )
            .is_ok()
        );
    }

    /// A deployment that issues no nonces must not start requiring one just
    /// because a client volunteered a value.
    #[test]
    fn a_volunteered_nonce_is_ignored_when_none_is_required() {
        let key = key();
        let uri = endpoint();
        let mut claims = proof_claims();
        claims["nonce"] = serde_json::json!("whatever the client felt like");
        let proof = sign_proof(&key, &proof_header(&key), &claims);
        assert!(check(&proof, &Expectation::new("POST", &uri), now()).is_ok());
    }

    // ---- ath (RFC 9449 §4.3 item 12) --------------------------------------

    #[test]
    fn ath_must_hash_the_access_token_it_accompanies() {
        let key = key();
        let uri = endpoint();
        let token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";

        let mut claims = proof_claims();
        claims["ath"] = serde_json::json!(B64.encode(Sha256::digest(token.as_bytes())));
        let proof = sign_proof(&key, &proof_header(&key), &claims);
        assert!(
            check(
                &proof,
                &Expectation::new("POST", &uri).with_access_token(token),
                now()
            )
            .is_ok()
        );
        assert_eq!(
            check(
                &proof,
                &Expectation::new("POST", &uri).with_access_token("another token"),
                now()
            ),
            Err(DpopError::AccessTokenMismatch)
        );

        // And a proof with no `ath` at all, where one is required.
        assert_eq!(
            check(
                &valid_proof(&key),
                &Expectation::new("POST", &uri).with_access_token(token),
                now()
            ),
            Err(DpopError::MalformedClaim("ath"))
        );
    }

    // ---- key binding (RFC 9449 §10) ---------------------------------------

    #[test]
    fn a_pinned_key_must_be_the_key_that_signed_the_proof() {
        let pinned = Kid::new("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        let other = Kid::new("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");

        assert!(matches_pinned_key(Some(pinned.as_str()), Some(&pinned)));
        assert!(!matches_pinned_key(Some(pinned.as_str()), Some(&other)));
        // A code bound to a key must not be redeemable without one.
        assert!(!matches_pinned_key(Some(pinned.as_str()), None));
        // Nothing pinned, nothing to correlate.
        assert!(matches_pinned_key(None, Some(&pinned)));
        assert!(matches_pinned_key(None, None));
    }

    /// RFC 9449 §10.1: both mechanisms must be supported, and disagreement
    /// between them is a rejection rather than a preference.
    #[test]
    fn the_two_par_binding_mechanisms_are_reconciled_or_refused() {
        let key = Kid::new("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        let other = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

        assert_eq!(reconcile_pinned_key(None, None), Ok(None));
        assert_eq!(
            reconcile_pinned_key(Some(&key), None),
            Ok(Some(key.as_str().to_owned()))
        );
        assert_eq!(
            reconcile_pinned_key(None, Some(other)),
            Ok(Some(other.to_owned()))
        );
        assert_eq!(
            reconcile_pinned_key(Some(&key), Some(key.as_str())),
            Ok(Some(key.as_str().to_owned()))
        );
        assert_eq!(
            reconcile_pinned_key(Some(&key), Some(other)),
            Err(DpopError::MalformedClaim("dpop_jkt"))
        );
    }

    // ---- error mapping ----------------------------------------------------

    #[test]
    fn only_the_nonce_failures_ask_the_client_to_retry() {
        let uri = endpoint();
        let key = key();
        let refusals = [
            check("not a jwt", &Expectation::new("POST", &uri), now()).expect_err("refused"),
            check(&valid_proof(&key), &Expectation::new("GET", &uri), now()).expect_err("refused"),
        ];
        for refusal in refusals {
            assert_eq!(refusal.code(), "invalid_dpop_proof");
            assert!(!refusal.wants_nonce());
        }
    }
}
