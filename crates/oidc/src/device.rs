//! The device authorization grant (RFC 8628): its two codes and its request.
//!
//! A device flow issues *two* credentials for one authorization, and they are
//! deliberately unalike.
//!
//! The **device code** never leaves the machine that asked for it. It is a
//! bearer credential presented at the token endpoint over TLS by an
//! authenticated client, so it is drawn the way every other bearer value here
//! is — 256 bits, stored as a SHA-256 digest — and RFC 8628 §5.2's brute-force
//! concern is answered by entropy alone.
//!
//! The **user code** is read off a screen and typed by a human, so it cannot
//! be. §6.1 puts the trade-off plainly: the code has to be short enough to
//! transcribe and long enough not to be guessed, and it recommends a
//! restricted alphabet with a worked example of "8 characters from a 20
//! character base-20 alphabet ≈ 34.5 bits". That is exactly what
//! [`UserCode::generate`] draws, from [`USER_CODE_ALPHABET`] — the twenty
//! consonants that leave no pair a person can confuse (no `0`/`O`, no `1`/`I`,
//! no `5`/`S`, no vowels, so no accidental words either).
//!
//! 34.5 bits is *not* enough on its own, and §5.1 says so: "the user code
//! SHOULD have enough entropy that... an attack is unlikely to succeed" is
//! paired with a rate limit, because a live code space of a few thousand
//! outstanding authorizations against 2.56 × 10¹⁰ codes is guessable by
//! somebody with a script and no limit. The limit is
//! [`crate::device`]'s caller's, in `crates/server/src/http/device.rs`, and
//! this module's contribution is the second half: [`UserCode::parse`] refuses
//! anything that could not have been minted before a database is touched, so a
//! guess costs a comparison rather than a query.
//!
//! # Case and hyphens are not part of the code
//!
//! §6.1: "the user code SHOULD be case-insensitive". A person shown
//! `BCDF-GHJK` will type `bcdf ghjk`, `BCDFGHJK`, or paste it with the hyphen
//! the display added. All four are the same code, and [`UserCode::parse`]
//! normalises them to one canonical eight-character form *before* the digest
//! that is looked up is computed — so the tolerance lives in one function
//! rather than in a `lower()` somewhere in SQL, and the stored form is one
//! string rather than a family of them.
//!
//! The hyphen is a display convention (§3.3.1's non-textual guidance is about
//! the same readability problem) and never part of the value: [`UserCode::formatted`]
//! adds it, [`UserCode::parse`] removes it.

use asterius_domain::entities::client::ClientRegistration;
use asterius_domain::{AuthorizationDetails, OpaqueToken, sha256_hex};
use std::collections::BTreeSet;
use time::Duration;

use crate::authorize::AuthorizationError;
use crate::form::Parameters;

/// The alphabet a user code is drawn from (RFC 8628 §6.1).
///
/// Twenty characters: the ASCII consonants minus the ones that collide with a
/// digit or with each other. No digits at all, so `0`/`O` and `1`/`I` cannot
/// arise; no vowels, so no draw spells a word somebody would rather not read
/// off a screen in an office.
pub const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

/// How many characters a user code has.
///
/// Eight, which over [`USER_CODE_ALPHABET`] is 20⁸ ≈ 2.56 × 10¹⁰ ≈ 34.5 bits —
/// the worked example RFC 8628 §6.1 gives.
pub const USER_CODE_LENGTH: usize = 8;

/// How many characters go between the hyphen in the displayed form.
const USER_CODE_GROUP: usize = 4;

/// Bits of entropy in a device code.
///
/// The acceptance criterion asks for at least 128. This uses the 256 every
/// other bearer value in this codebase draws (RFC 8628 §5.2 asks only that the
/// space be too large to search).
pub const DEVICE_CODE_BITS: usize = 256;

/// The `interval` a device authorization response carries (RFC 8628 §3.2).
///
/// Five seconds, which is also §3.5's default for a client that finds no
/// `interval` at all — so a client that ignores the parameter and a client
/// that honours it poll at the same rate.
pub const POLL_INTERVAL: Duration = Duration::seconds(5);

/// What `slow_down` adds to the interval (RFC 8628 §3.5).
///
/// "the client MUST increase its polling interval by 5 seconds". The server
/// increases *its* copy by the same amount at the same moment, so the two
/// agree on what "too fast" means from the next poll onwards; a server that
/// kept the old interval would answer `slow_down` to a client that had already
/// obeyed it.
pub const SLOW_DOWN_INCREMENT: Duration = Duration::seconds(5);

/// The longest a device authorization may stay pending.
///
/// Ten minutes. RFC 8628 §3.2 makes `expires_in` the server's choice; this is
/// the acceptance criterion's ceiling and the value used, because the user
/// code is on a screen for the whole of it and §5.1's guessing budget grows
/// with every second an outstanding code stays live.
pub const MAX_LIFETIME: Duration = Duration::seconds(600);

/// A user code, in the one form this server stores and compares.
///
/// Canonical means: eight characters, all from [`USER_CODE_ALPHABET`], upper
/// case, no hyphen. Everything a person may type is turned into this by
/// [`UserCode::parse`] before anything is looked up, so there is exactly one
/// string per code.
#[derive(Clone, PartialEq, Eq)]
pub struct UserCode(String);

impl std::fmt::Debug for UserCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A live user code is a credential for as long as the authorization is
        // pending: it is the whole of what an attacker needs to type into the
        // verification page of a flow somebody else started. It does not go in
        // a log line.
        f.debug_struct("UserCode")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// A value that could not be a user code this server minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a user code")]
pub struct MalformedUserCode;

impl UserCode {
    /// Draws a fresh code.
    ///
    /// Rejection sampling rather than `byte % 20`: 256 is not a multiple of
    /// 20, so the modulo alone would make the first sixteen characters of the
    /// alphabet ~7 % likelier than the last four and cost a fraction of a bit
    /// out of 34.5 that the specification's estimate assumes is there. Bytes
    /// at or above 240 (= 12 × 20) are discarded, which is uniform by
    /// construction.
    #[must_use]
    pub fn generate() -> Self {
        let modulus = u8::try_from(USER_CODE_ALPHABET.len()).expect("the alphabet is 20 long");
        let ceiling = (u8::MAX / modulus) * modulus;
        let mut code = String::with_capacity(USER_CODE_LENGTH);
        let mut buffer = [0_u8; USER_CODE_LENGTH];
        while code.len() < USER_CODE_LENGTH {
            // A failure here is the operating system refusing to seed us.
            // Carrying on would mint a guessable code, so there is nothing to
            // fall back to: stop.
            getrandom::fill(&mut buffer).expect("the OS CSPRNG must be available");
            for byte in buffer {
                if byte >= ceiling {
                    continue;
                }
                code.push(char::from(USER_CODE_ALPHABET[usize::from(byte % modulus)]));
                if code.len() == USER_CODE_LENGTH {
                    break;
                }
            }
        }
        Self(code)
    }

    /// Reads a code somebody typed.
    ///
    /// Case is folded and ASCII whitespace and hyphens are dropped, because
    /// none of the three is part of the value (§6.1). Everything else is
    /// refused: this is a shape check standing in front of a database lookup,
    /// so a guess costs a comparison rather than a query, and the rate limit
    /// it sits beside is spent per *attempt* rather than per query.
    ///
    /// # Errors
    ///
    /// [`MalformedUserCode`] when the value could not have been minted here.
    // fuzz-target: device_user_code
    pub fn parse(presented: &str) -> Result<Self, MalformedUserCode> {
        // A person can paste an essay into the field. Nothing longer than a
        // code plus its separators can be one, and the bound is what stops a
        // megabyte of input being uppercased before it is refused.
        if presented.len() > 64 {
            return Err(MalformedUserCode);
        }
        let mut canonical = String::with_capacity(USER_CODE_LENGTH);
        for byte in presented.bytes() {
            if byte == b'-' || byte.is_ascii_whitespace() {
                continue;
            }
            let upper = byte.to_ascii_uppercase();
            if !USER_CODE_ALPHABET.contains(&upper) {
                return Err(MalformedUserCode);
            }
            if canonical.len() == USER_CODE_LENGTH {
                return Err(MalformedUserCode);
            }
            canonical.push(char::from(upper));
        }
        if canonical.len() != USER_CODE_LENGTH {
            return Err(MalformedUserCode);
        }
        Ok(Self(canonical))
    }

    /// The canonical form: eight characters, upper case, no separator.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The form a device displays and a page echoes back: `XXXX-XXXX`.
    #[must_use]
    pub fn formatted(&self) -> String {
        let (head, tail) = self.0.split_at(USER_CODE_GROUP);
        format!("{head}-{tail}")
    }

    /// The value to store and to look up by.
    ///
    /// A digest, for the reason every other credential here is stored as one:
    /// a copy of the database is then a list of digests rather than a list of
    /// codes somebody could type into the verification page of an
    /// authorization that is still pending.
    #[must_use]
    pub fn digest(&self) -> String {
        sha256_hex(self.0.as_bytes())
    }
}

/// A freshly minted device code and the digest to store.
///
/// The value reaches exactly two places: the device authorization response,
/// and — as a digest — the database.
pub struct MintedDeviceCode {
    value: OpaqueToken,
    digest: String,
}

impl MintedDeviceCode {
    /// Mints a device code.
    #[must_use]
    pub fn generate() -> Self {
        let value = OpaqueToken::generate_bits::<DEVICE_CODE_BITS>();
        let digest = sha256_hex(value.expose().as_bytes());
        Self { value, digest }
    }

    /// The value to put in the response.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.value.expose()
    }

    /// The value to store.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

impl std::fmt::Debug for MintedDeviceCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedDeviceCode")
            .field("value", &"[REDACTED]")
            .field("digest", &self.digest)
            .finish()
    }
}

/// A value that could not be a device code this server minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a device code")]
pub struct MalformedDeviceCode;

/// Turns a presented device code into the digest to look up.
///
/// The same shape-before-query rule [`crate::code::digest_of`] applies to an
/// authorization code, and for RFC 8628 §5.2's reason: a device code is polled
/// for, repeatedly, by design — so the cheap refusal is the one that runs
/// thousands of times.
///
/// # Errors
///
/// [`MalformedDeviceCode`] when the value could not have been issued here.
pub fn device_code_digest_of(presented: &str) -> Result<String, MalformedDeviceCode> {
    let expected = DEVICE_CODE_BITS.div_ceil(6);
    if presented.len() != expected
        || !presented
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(MalformedDeviceCode);
    }
    Ok(sha256_hex(presented.as_bytes()))
}

/// What a device authorization request asked for (RFC 8628 §3.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceRequest {
    /// The scopes, already checked against the client's registration.
    pub scopes: BTreeSet<String>,
    /// RFC 9396 §3's rich authorization, already checked against the client's
    /// §9.2 allow-list.
    pub authorization_details: AuthorizationDetails,
}

/// Validates a device authorization request.
///
/// `client_id` is the *authenticated* client — FAPI 2.0 SP §5.3.2.1 item 3
/// admits no public client, so unlike RFC 8628 §3.1's usual reading there is
/// always one — and the `client_id` parameter is checked against it rather
/// than believed.
///
/// RFC 8628 §3.1 lists `client_id` and `scope` and nothing else. There is no
/// `redirect_uri` (the flow has no redirect), no PKCE (there is no
/// authorization response to protect), and no `response_type`. What is refused
/// beyond the specification's own list is `request` and `request_uri`: a
/// device authorization request is not an authorization request, this endpoint
/// unwraps no request object, and silently ignoring one would honour exactly
/// the parameters an object exists to protect.
///
/// # Errors
///
/// The first [`AuthorizationError`] that applies. The codes are shared with
/// the authorization endpoint on purpose: `invalid_scope` means the same thing
/// to a client here as it does there.
// fuzz-target: device_authorization_request
pub fn validate(
    params: &Parameters,
    client_id: &str,
    registration: &ClientRegistration,
) -> Result<DeviceRequest, AuthorizationError> {
    if params.present("request_uri") {
        return Err(AuthorizationError::RequestUriNotAllowed);
    }
    if params.present("request") {
        return Err(AuthorizationError::RequestObjectNotSupported);
    }
    if let Some(presented) = params.get("client_id")?
        && presented != client_id
    {
        return Err(AuthorizationError::ClientMismatch);
    }

    let mut scopes = BTreeSet::new();
    for token in params.get("scope")?.unwrap_or_default().split_whitespace() {
        // As at the authorization endpoint: an over-broad request is refused
        // rather than trimmed, so a client is never handed a token narrower
        // than the one it believes it asked for.
        if !registration.scopes.contains(token) {
            return Err(AuthorizationError::ScopeNotPermitted);
        }
        if scopes.len() == MAX_SCOPES {
            return Err(AuthorizationError::Invalid("scope"));
        }
        scopes.insert(token.to_owned());
    }

    let authorization_details = match params.get("authorization_details")? {
        None => AuthorizationDetails::default(),
        Some(raw) => {
            let details = AuthorizationDetails::parse(raw)?;
            for name in details.types() {
                if !registration.authorization_details_types.contains(name) {
                    return Err(AuthorizationError::InvalidAuthorizationDetails(
                        asterius_domain::InvalidAuthorizationDetails,
                    ));
                }
            }
            details
        }
    };

    Ok(DeviceRequest {
        scopes,
        authorization_details,
    })
}

/// The most scopes one request may name.
///
/// The same bound the authorization endpoint applies, restated rather than
/// imported so that the two limits are visible where they are enforced.
const MAX_SCOPES: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn registration() -> ClientRegistration {
        ClientRegistration::from_json(
            &serde_json::to_vec(&json!({
                "client_name": "Agent",
                "redirect_uris": [],
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
                "response_types": [],
                "scope": "openid profile payments",
                "token_endpoint_auth_method": "private_key_jwt",
                "token_endpoint_auth_signing_alg": "ES256",
                "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
            }))
            .expect("the fixture serialises"),
            // The device grant is behind a flag, and a registration
            // naming it is refused where the flag is off — which is the
            // parity `ast-o0t.3` bought and which this fixture must respect
            // rather than route around.
            asterius_domain::Capabilities {
                device_flow: true,
                ..asterius_domain::Capabilities::default()
            },
        )
        .expect("the fixture registers")
    }

    fn params(pairs: &[(&str, &str)]) -> Parameters {
        Parameters::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        )
    }

    /// RFC 8628 §6.1: the alphabet is unambiguous and the code is eight of it.
    #[test]
    fn a_minted_user_code_is_eight_characters_of_the_unambiguous_alphabet() {
        for _ in 0..64 {
            let code = UserCode::generate();
            assert_eq!(code.as_str().len(), USER_CODE_LENGTH);
            assert!(
                code.as_str()
                    .bytes()
                    .all(|b| USER_CODE_ALPHABET.contains(&b)),
                "outside the alphabet: {}",
                code.as_str()
            );
        }
    }

    /// §6.1's worked example: twenty characters, eight positions, ≈ 34.5 bits.
    ///
    /// Asserted as the *size of the space* rather than as a float, so the test
    /// says what the alphabet and the length buy without going through a
    /// logarithm: 20⁸ = 25 600 000 000, which is 2^34.5 to the half-bit the
    /// specification quotes.
    #[test]
    fn the_user_code_space_is_the_entropy_the_specification_estimates() {
        assert_eq!(USER_CODE_ALPHABET.len(), 20);
        let space = 20_u64.pow(8);
        assert_eq!(space, 25_600_000_000);
        assert!(space > 1 << 34 && space < 1 << 35, "{space} codes");
    }

    /// §6.1: the code is displayed with a separator that is not part of it.
    #[test]
    fn the_displayed_form_is_two_groups_of_four() {
        let code = UserCode::parse("BCDFGHJK").expect("a well-formed code");
        assert_eq!(code.formatted(), "BCDF-GHJK");
    }

    /// §6.1: "the user code SHOULD be case-insensitive".
    #[test]
    fn case_and_hyphens_and_spaces_are_not_part_of_the_code() {
        let canonical = UserCode::parse("BCDFGHJK").expect("a well-formed code");
        for spelling in [
            "bcdfghjk",
            "BCDF-GHJK",
            "bcdf-ghjk",
            " BCDF GHJK ",
            "BcDf-GhJk",
        ] {
            let parsed = UserCode::parse(spelling).expect("a spelling of the same code");
            assert_eq!(parsed.as_str(), canonical.as_str(), "{spelling}");
            assert_eq!(parsed.digest(), canonical.digest(), "{spelling}");
        }
    }

    /// The characters the alphabet excludes are refused rather than coerced
    /// into the ones they resemble: `0` is not `O`, and `O` is not in the
    /// alphabet either.
    #[test]
    fn a_character_outside_the_alphabet_is_refused() {
        for spelling in [
            "BCDFGHJ0",
            "BCDFGHJO",
            "BCDFGHJI",
            "BCDFGHJ1",
            "BCDFGHJA",
            "BCDFGHJ",
            "BCDFGHJKL",
            "",
            "BCDF_GHJK",
        ] {
            assert_eq!(
                UserCode::parse(spelling),
                Err(MalformedUserCode),
                "{spelling} was accepted"
            );
        }
    }

    /// A minted code is one its own parser accepts. A drift here would be a
    /// server that shows a code nobody can type back in.
    #[test]
    fn a_minted_code_round_trips_through_its_displayed_form() {
        for _ in 0..64 {
            let minted = UserCode::generate();
            let typed = UserCode::parse(&minted.formatted()).expect("its own display form");
            assert_eq!(typed.as_str(), minted.as_str());
        }
    }

    /// RFC 8628 §5.2: a device code is a bearer credential and is stored as a
    /// digest, never as itself.
    #[test]
    fn a_device_code_is_never_stored_as_itself() {
        let minted = MintedDeviceCode::generate();
        assert_ne!(minted.expose(), minted.digest());
        assert_eq!(
            device_code_digest_of(minted.expose()).expect("its own shape check"),
            minted.digest()
        );
        const { assert!(DEVICE_CODE_BITS >= 128, "below the acceptance criterion") };
    }

    #[test]
    fn a_device_code_of_the_wrong_shape_never_reaches_a_query() {
        // One character short, one too long, and one of the right length made
        // of a character the encoding never produces. The right length is 43:
        // 256 bits of unpadded base64url.
        for presented in [
            "",
            "short",
            &"a".repeat(42),
            &"a".repeat(44),
            &"$".repeat(43),
        ] {
            assert_eq!(
                device_code_digest_of(presented),
                Err(MalformedDeviceCode),
                "{presented} was accepted"
            );
        }
    }

    /// RFC 8628 §3.2: five seconds, and no more than ten minutes.
    #[test]
    fn the_advertised_interval_and_ceiling_are_the_ones_the_criterion_names() {
        assert_eq!(POLL_INTERVAL, Duration::seconds(5));
        assert_eq!(SLOW_DOWN_INCREMENT, Duration::seconds(5));
        assert!(MAX_LIFETIME <= Duration::seconds(600));
    }

    /// RFC 8628 §3.1: `scope` is the request, and it is bounded by the
    /// registration.
    #[test]
    fn a_scope_the_client_did_not_register_is_refused() {
        let refused = validate(
            &params(&[("scope", "openid banking")]),
            "agent",
            &registration(),
        );
        assert_eq!(refused, Err(AuthorizationError::ScopeNotPermitted));
    }

    #[test]
    fn a_registered_scope_is_carried_through() {
        let accepted = validate(
            &params(&[("scope", "openid profile")]),
            "agent",
            &registration(),
        )
        .expect("a registered scope");
        assert_eq!(
            accepted.scopes,
            ["openid".to_owned(), "profile".to_owned()].into()
        );
    }

    /// The `client_id` parameter is not the source of truth: the client that
    /// authenticated is.
    #[test]
    fn a_client_id_parameter_naming_another_client_is_refused() {
        let refused = validate(
            &params(&[("client_id", "someone-else")]),
            "agent",
            &registration(),
        );
        assert_eq!(refused, Err(AuthorizationError::ClientMismatch));
    }

    #[test]
    fn a_parameter_sent_twice_is_refused() {
        let doubled = Parameters::from_pairs([
            ("scope".to_owned(), "openid".to_owned()),
            ("scope".to_owned(), "profile".to_owned()),
        ]);
        assert_eq!(
            validate(&doubled, "agent", &registration()),
            Err(AuthorizationError::DuplicateParameter("scope".to_owned()))
        );
    }

    /// A request object is refused rather than ignored: this endpoint unwraps
    /// none, so ignoring one would honour the parameters beside it.
    #[test]
    fn a_request_object_is_refused_rather_than_ignored() {
        assert_eq!(
            validate(
                &params(&[("request", "ey.ey.ey")]),
                "agent",
                &registration()
            ),
            Err(AuthorizationError::RequestObjectNotSupported)
        );
        assert_eq!(
            validate(
                &params(&[("request_uri", "urn:x")]),
                "agent",
                &registration()
            ),
            Err(AuthorizationError::RequestUriNotAllowed)
        );
    }
}
