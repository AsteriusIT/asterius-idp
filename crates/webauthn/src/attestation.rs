//! The attestation object (WebAuthn L3 §6.5).
//!
//! A CBOR map of exactly three members — `fmt`, `attStmt`, `authData` — which
//! is the envelope an authenticator wraps a new credential in.
//!
//! # Only `none` is accepted
//!
//! Attestation says *what kind of authenticator* made a credential, signed by
//! a manufacturer key. Verifying it means shipping and maintaining a root
//! store, and acting on it means deciding which hardware a person is allowed
//! to own.
//!
//! This server asks for `none` (§5.4.7) and accepts nothing else. That is not
//! a gap: FIDO's passkey guidance is that a consumer relying party should not
//! request attestation, because the only thing it can do with the answer is
//! refuse somebody's authenticator, and privacy-preserving attestation is
//! precisely the thing platform authenticators decline to provide. A
//! deployment that genuinely needs enterprise attestation with an AAGUID
//! allow-list is a separate decision with a separate root store, and it is not
//! this one.
//!
//! Accepting only `none` also removes every attestation-statement signature
//! verifier from this crate — `packed`, `tpm`, `android-key`, `apple`,
//! `fido-u2f` — which between them are the majority of the code and nearly all
//! of the risk in a WebAuthn library.

use ciborium::value::Value;

/// Why an attestation object was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationError {
    /// Not CBOR, or not a map, or missing a member §6.5 requires.
    #[error("the attestation object is not the structure the specification defines")]
    Malformed,
    /// An attestation format this server does not accept.
    #[error("this server accepts only the `none` attestation format")]
    UnsupportedFormat,
    /// `fmt` is `none` and `attStmt` is not empty.
    ///
    /// §8.7 defines the `none` statement as an empty map. Anything inside it
    /// is a field this server would be ignoring, and a signature nobody
    /// checks is worse than no signature at all.
    #[error("a `none` attestation statement must be empty")]
    NonEmptyStatement,
}

/// An attestation object, unwrapped.
#[derive(Debug, Clone)]
pub struct AttestationObject {
    /// The authenticator data, still packed. §6.1 parses it.
    pub authenticator_data: Vec<u8>,
}

/// Unwraps an attestation object and refuses anything but `none`.
///
/// # Errors
///
/// [`AttestationError`] if the CBOR is not §6.5's structure, or the format is
/// one this server does not accept.
// fuzz-target: attestation_object
pub fn parse(attestation_object: &[u8]) -> Result<AttestationObject, AttestationError> {
    let value: Value =
        ciborium::from_reader(attestation_object).map_err(|_| AttestationError::Malformed)?;
    let map = value.as_map().ok_or(AttestationError::Malformed)?;

    let fmt = text(map, "fmt").ok_or(AttestationError::Malformed)?;
    if fmt != "none" {
        return Err(AttestationError::UnsupportedFormat);
    }

    // §8.7. Present and empty, not merely absent: a missing `attStmt` is a
    // malformed object, and an object with something in it is one this parser
    // would be silently discarding.
    let statement = member(map, "attStmt").ok_or(AttestationError::Malformed)?;
    match statement.as_map() {
        Some(entries) if entries.is_empty() => {}
        Some(_) => return Err(AttestationError::NonEmptyStatement),
        None => return Err(AttestationError::Malformed),
    }

    let authenticator_data = member(map, "authData")
        .and_then(Value::as_bytes)
        .ok_or(AttestationError::Malformed)?
        .clone();

    Ok(AttestationObject { authenticator_data })
}

/// The member at `name`, if there is one.
fn member<'a>(map: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    map.iter()
        .find(|(key, _)| key.as_text() == Some(name))
        .map(|(_, value)| value)
}

/// The text member at `name`, if there is one and it is text.
fn text<'a>(map: &'a [(Value, Value)], name: &str) -> Option<&'a str> {
    member(map, name).and_then(Value::as_text)
}
