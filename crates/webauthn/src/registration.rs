//! The registration ceremony (WebAuthn L3 §7.1).
//!
//! Two halves that have to be joined by something the server issued: the
//! browser says where the ceremony happened, the authenticator says what it
//! made, and the challenge is what makes both of them statements about *this*
//! request rather than a recording of an older one.

use crate::authenticator_data::{self, AttestedCredential, UserVerification};
use crate::client_data::{self, Ceremony};
use crate::cose::CoseAlgorithm;
use crate::{Challenge, RelyingParty, attestation};

/// Why a registration was refused.
///
/// The variants exist for the log. What the browser is told is one generic
/// failure: §7.1 defines no error vocabulary, and the steps that fail here
/// distinguish "your authenticator is old" from "somebody is replaying a
/// captured ceremony" — which is a distinction an attacker would like drawn
/// for them and a user cannot act on either way.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistrationError {
    /// The browser's half was refused.
    #[error("client data: {0}")]
    ClientData(#[from] client_data::ClientDataError),
    /// The attestation envelope was refused.
    #[error("attestation: {0}")]
    Attestation(#[from] attestation::AttestationError),
    /// The authenticator's half was refused.
    #[error("authenticator data: {0}")]
    AuthenticatorData(#[from] authenticator_data::AuthenticatorDataError),
    /// The credential's algorithm was not among those offered.
    ///
    /// §7.1 step 17. An authenticator that returns a key of a type nobody
    /// asked for has either ignored `pubKeyCredParams` or is not the thing
    /// that was asked.
    #[error("the credential uses an algorithm that was not offered")]
    AlgorithmNotOffered,
    /// The challenge had already been spent, or had expired.
    ///
    /// Not something this function can detect — a challenge store owns it —
    /// but named here so a caller has one error type to report.
    #[error("the challenge is not one that is currently outstanding")]
    StaleChallenge,
}

/// What the ceremony proved, ready to be stored against a user.
#[derive(Debug, Clone)]
pub struct Registration {
    /// The credential, its key, and the flags the authenticator reported.
    pub credential: AttestedCredential,
    /// The origin the ceremony actually happened at, for the audit record.
    pub origin: String,
}

/// Verifies a registration response.
///
/// This is §7.1 in the order the specification writes it, with the steps that
/// belong to a store — is this challenge outstanding, is this credential id
/// already registered — left to the caller, because they are queries and this
/// function does no I/O.
///
/// # What the caller still has to do
///
/// * Spend the challenge, and refuse a second use of it (§7.1 step 8 is only
///   half the story: comparing is not consuming).
/// * Refuse a `credential_id` already registered *anywhere in the tenant*
///   (step 22). The unique index on `credentials` is what actually enforces
///   it; checking first only makes the error a nicer one.
///
/// # Errors
///
/// [`RegistrationError`] if any step fails.
pub fn verify(
    relying_party: &RelyingParty,
    challenge: &Challenge,
    client_data_json: &[u8],
    attestation_object: &[u8],
    offered: &[CoseAlgorithm],
) -> Result<Registration, RegistrationError> {
    // Steps 5-10.
    let client = client_data::verify(
        client_data_json,
        Ceremony::Create,
        challenge.as_bytes(),
        relying_party.origins(),
    )?;

    // Step 12, and the format decision.
    let envelope = attestation::parse(attestation_object)?;

    // Steps 13-16, and the attested credential data of §6.5.2.
    let credential = authenticator_data::verify_registration(
        &envelope.authenticator_data,
        relying_party.id_hash(),
        relying_party.user_verification(),
    )?;

    // Step 17.
    if !offered.contains(&credential.public_key.algorithm()) {
        return Err(RegistrationError::AlgorithmNotOffered);
    }

    // Steps 19-21 are the attestation statement, and `none` has none: §8.7
    // defines its verification procedure as returning success. `attestation`
    // has already refused every other format, so there is nothing to do here
    // rather than something skipped.

    Ok(Registration {
        credential,
        origin: client.origin().to_owned(),
    })
}

/// Defaults for [`UserVerification`], so a caller that does not care gets the
/// strict one.
#[must_use]
pub const fn default_user_verification() -> UserVerification {
    UserVerification::Required
}
