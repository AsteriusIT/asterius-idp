//! Client data, as the browser assembles it (WebAuthn L3 §5.8.1, §7.1).
//!
//! `clientDataJSON` is the browser's account of what it was asked to do and
//! where it was asked to do it. It is the half of the ceremony the *browser*
//! attests to, and the authenticator signs a hash of it — so what is checked
//! here is what binds a credential to this origin and to this challenge rather
//! than to whoever relayed the request.
//!
//! # Why the bytes are not re-encoded
//!
//! §7.1 step 11 hashes `clientDataJSON` — the octets received, not a
//! re-serialisation of the object parsed out of them. §5.8.1 is explicit that
//! a relying party must not assume the JSON is in any canonical form, because
//! future fields may be added and clients are free to order and escape as they
//! like. So this parses a *copy* to read three fields and keeps the original
//! slice for hashing; the two never have to agree beyond those fields.

use serde::Deserialize;
use subtle::ConstantTimeEq;

/// Why client data was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClientDataError {
    /// Not UTF-8, or not JSON, or not an object with the fields §5.8.1 requires.
    #[error("clientDataJSON is not the structure the specification defines")]
    Malformed,
    /// `type` is not the ceremony that was being performed.
    ///
    /// The check §7.1 step 7 exists for: a `webauthn.get` response replayed
    /// into a registration would otherwise be a way to register a credential
    /// the user only meant to authenticate with.
    #[error("clientDataJSON is for a different ceremony")]
    WrongCeremony,
    /// `challenge` is not the one this server issued.
    #[error("the challenge is not the one that was issued")]
    ChallengeMismatch,
    /// `origin` is not one this relying party accepts.
    #[error("the origin is not one this server accepts")]
    UntrustedOrigin,
}

/// The ceremony a client data blob claims to belong to (§5.8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ceremony {
    /// `navigator.credentials.create()`.
    Create,
    /// `navigator.credentials.get()`.
    Get,
}

impl Ceremony {
    /// The `type` member's value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "webauthn.create",
            Self::Get => "webauthn.get",
        }
    }
}

/// The three members this server reads.
///
/// `#[serde(deny_unknown_fields)]` is deliberately *not* used: §5.8.1 says a
/// relying party must ignore members it does not understand, because clients
/// are permitted to add them. Refusing an unknown member would make every
/// future browser release a compatibility incident.
#[derive(Debug, Deserialize)]
struct Parsed {
    #[serde(rename = "type")]
    ceremony: String,
    challenge: String,
    origin: String,
    #[serde(default)]
    #[serde(rename = "crossOrigin")]
    cross_origin: bool,
}

/// Client data that has been checked against what this server expects.
#[derive(Debug, Clone)]
pub struct ClientData {
    origin: String,
}

impl ClientData {
    /// The origin the ceremony actually happened at.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// Checks client data against the ceremony, challenge and origins expected.
///
/// This is §7.1 steps 5 to 10, in order.
///
/// `challenge` is the raw bytes this server issued; the comparison is against
/// their base64url spelling, because that is what §5.8.1 puts in the JSON. It
/// is constant-time — a challenge is single-use and short-lived, but it is
/// still a value an attacker would like to learn one byte at a time, and the
/// comparison costs nothing.
///
/// `origins` is the exact set this relying party accepts. Comparison is
/// byte-exact: §7.1 step 9 says a relying party may apply its own policy, and
/// this one's policy is a list somebody wrote down. Nothing is parsed, so
/// there is no normalisation for a hostile origin to exploit — the failure
/// mode of a looser check is a credential registered against an origin that
/// only *resembles* the tenant's.
///
/// # Errors
///
/// [`ClientDataError`] if any step fails.
// fuzz-target: webauthn_client_data
pub fn verify(
    client_data_json: &[u8],
    ceremony: Ceremony,
    challenge: &[u8],
    origins: &[String],
) -> Result<ClientData, ClientDataError> {
    let parsed: Parsed =
        serde_json::from_slice(client_data_json).map_err(|_| ClientDataError::Malformed)?;

    // Step 7.
    if parsed.ceremony != ceremony.as_str() {
        return Err(ClientDataError::WrongCeremony);
    }

    // Step 8. `base64url` without padding, per §5.8.1's `challenge` member.
    let expected = base64_url(challenge);
    // `ConstantTimeEq for [u8]` already answers `false` for a length mismatch
    // without comparing, so this one call covers both. The length itself is
    // not a secret — every challenge this server issues is the same size.
    if !bool::from(parsed.challenge.as_bytes().ct_eq(expected.as_bytes())) {
        return Err(ClientDataError::ChallengeMismatch);
    }

    // Steps 9 and 10. A cross-origin ceremony is refused outright rather than
    // checked against `topOrigin`: this server's pages are same-origin, so a
    // registration arriving from inside somebody's iframe is not a shape it
    // ever produces.
    if parsed.cross_origin {
        return Err(ClientDataError::UntrustedOrigin);
    }
    if !origins.contains(&parsed.origin) {
        return Err(ClientDataError::UntrustedOrigin);
    }

    Ok(ClientData {
        origin: parsed.origin,
    })
}

/// Unpadded base64url, which is the only spelling §5.8.1 permits.
fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
