//! Authenticator data (WebAuthn L3 §6.1).
//!
//! A packed binary structure, not CBOR — the authenticator signs these exact
//! bytes, so the layout is fixed:
//!
//! ```text
//! 32  rpIdHash
//!  1  flags   UP(0) UV(2) BE(3) BS(4) AT(6) ED(7)
//!  4  signCount, big-endian
//!     attestedCredentialData, if AT
//!     extensions (CBOR map), if ED
//! ```
//!
//! Everything here is length arithmetic over attacker-supplied bytes, which is
//! why every read goes through a bounds check that returns rather than panics.
//! A slice index would be a denial of service reachable by anyone who can
//! reach the registration endpoint.

use crate::cose::{self, CredentialPublicKey};

/// Why authenticator data was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthenticatorDataError {
    /// Shorter than the fixed header, or truncated inside a field.
    #[error("the authenticator data is truncated")]
    Truncated,
    /// `rpIdHash` is not the hash of the relying party this server is.
    ///
    /// §7.1 step 13. The check that stops a credential made for one origin
    /// being presented as one made for this one.
    #[error("the authenticator data is for a different relying party")]
    WrongRelyingParty,
    /// The user-presence bit is clear.
    ///
    /// §7.1 step 14 makes this unconditional: a credential created without a
    /// human present is a credential created by software.
    #[error("the authenticator did not report user presence")]
    NoUserPresence,
    /// User verification was required and the bit is clear (§7.1 step 15).
    #[error("the authenticator did not verify the user")]
    NoUserVerification,
    /// The backup-state bit is set while backup-eligible is clear.
    ///
    /// §6.1: "If the BE flag is not set, the BS flag MUST NOT be set." A
    /// credential that reports itself as backed up while also reporting that
    /// it *cannot* be is describing something that does not exist.
    #[error("the backup flags contradict each other")]
    InconsistentBackupFlags,
    /// Registration requires attested credential data and the AT bit is clear.
    #[error("the authenticator data carries no attested credential data")]
    NoAttestedCredentialData,
    /// The credential id is longer than §6.5.2 permits.
    #[error("the credential id is longer than 1023 bytes")]
    CredentialIdTooLong,
    /// The credential public key was refused.
    #[error("the credential public key was refused: {0}")]
    PublicKey(#[from] cose::CoseError),
}

/// Whether the ceremony must prove a *user*, not merely a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserVerification {
    /// The UV bit must be set or the ceremony fails.
    ///
    /// The default, and what FIDO's passkey guidance assumes: a passkey that
    /// is only user-*presence* is a single factor, and this server treats
    /// passkeys as sufficient on their own.
    #[default]
    Required,
    /// The UV bit is recorded but not required.
    Discouraged,
}

/// The flag bits (§6.1).
const FLAG_UP: u8 = 1 << 0;
const FLAG_UV: u8 = 1 << 2;
const FLAG_BE: u8 = 1 << 3;
const FLAG_BS: u8 = 1 << 4;
const FLAG_AT: u8 = 1 << 6;

/// The fixed header: 32 bytes of hash, one of flags, four of counter.
const HEADER_LEN: usize = 37;

/// §6.5.2: "credentialIdLength […] MUST be 1023 bytes or less."
const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// What a registration ceremony's authenticator data proved.
#[derive(Debug, Clone)]
pub struct AttestedCredential {
    /// The authenticator model, or all zeroes when it declines to say.
    pub aaguid: [u8; 16],
    /// The credential id, which is what an assertion will name later.
    pub credential_id: Vec<u8>,
    /// The public key an assertion will be verified with.
    pub public_key: CredentialPublicKey,
    /// Whether the user was verified, not merely present.
    pub user_verified: bool,
    /// Whether the credential may be backed up (§6.1.3).
    pub backup_eligible: bool,
    /// Whether it currently is.
    pub backup_state: bool,
    /// The authenticator's counter at registration.
    pub sign_count: u32,
}

/// What an assertion ceremony's authenticator data reported.
///
/// No key and no credential id: an assertion names a credential the server
/// already holds, and the authenticator repeats nothing about it. What is new
/// each time are the flags and the counter, which is why those are the whole
/// of this structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssertedAuthenticator {
    /// Whether the user was verified, not merely present.
    pub user_verified: bool,
    /// Whether the credential may be backed up (§6.1.3).
    pub backup_eligible: bool,
    /// Whether it currently is.
    pub backup_state: bool,
    /// The authenticator's counter for this assertion.
    pub sign_count: u32,
}

/// The fixed header both ceremonies share: §7.1 steps 13-16, §7.2 steps 15-18.
///
/// One function because the two ceremonies check the *same* things about the
/// same 37 bytes, and the specification writes them out twice only because it
/// describes two procedures. Two copies here would be two places for the UV
/// rule to be relaxed in one and not in the other.
fn header(
    authenticator_data: &[u8],
    rp_id_hash: &[u8; 32],
    user_verification: UserVerification,
) -> Result<(u8, u32), AuthenticatorDataError> {
    if authenticator_data.len() < HEADER_LEN {
        return Err(AuthenticatorDataError::Truncated);
    }

    // §7.1 step 13, §7.2 step 15. Not constant-time on purpose: both sides are
    // public. The RP ID is in the discovery document and the hash is in a
    // structure the browser hands to script.
    if &authenticator_data[..32] != rp_id_hash.as_slice() {
        return Err(AuthenticatorDataError::WrongRelyingParty);
    }

    let flags = authenticator_data[32];
    let sign_count = u32::from_be_bytes([
        authenticator_data[33],
        authenticator_data[34],
        authenticator_data[35],
        authenticator_data[36],
    ]);

    // §7.1 step 14, §7.2 step 16.
    if flags & FLAG_UP == 0 {
        return Err(AuthenticatorDataError::NoUserPresence);
    }
    // §7.1 step 15, §7.2 step 17.
    if user_verification == UserVerification::Required && flags & FLAG_UV == 0 {
        return Err(AuthenticatorDataError::NoUserVerification);
    }

    // §6.1, and step 16 in L3.
    if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        return Err(AuthenticatorDataError::InconsistentBackupFlags);
    }

    Ok((flags, sign_count))
}

/// Parses authenticator data from an assertion and checks §7.2 steps 15-18.
///
/// The bytes are the ones the authenticator signed, so nothing here may
/// re-encode them: this reads the header and reports it. Attested credential
/// data is neither required nor read — an assertion carries no new key, and
/// the AT bit being set on one would only mean an authenticator repeated
/// something the server already has.
///
/// # Errors
///
/// [`AuthenticatorDataError`] if the bytes are truncated, name another relying
/// party, or report a state the specification forbids.
// fuzz-target: authenticator_data
pub fn verify_assertion(
    authenticator_data: &[u8],
    rp_id_hash: &[u8; 32],
    user_verification: UserVerification,
) -> Result<AssertedAuthenticator, AuthenticatorDataError> {
    let (flags, sign_count) = header(authenticator_data, rp_id_hash, user_verification)?;
    Ok(AssertedAuthenticator {
        user_verified: flags & FLAG_UV != 0,
        backup_eligible: flags & FLAG_BE != 0,
        backup_state: flags & FLAG_BS != 0,
        sign_count,
    })
}

/// Parses authenticator data from a registration and checks §7.1 steps 13-16.
///
/// `rp_id_hash` is `SHA-256(rp_id)`, computed by the caller so this function
/// stays free of anything but arithmetic and comparison.
///
/// # Errors
///
/// [`AuthenticatorDataError`] if the bytes are truncated, name another relying
/// party, or report a state the specification forbids.
// fuzz-target: authenticator_data
pub fn verify_registration(
    authenticator_data: &[u8],
    rp_id_hash: &[u8; 32],
    user_verification: UserVerification,
) -> Result<AttestedCredential, AuthenticatorDataError> {
    // Steps 13-16, which an assertion checks too.
    let (flags, sign_count) = header(authenticator_data, rp_id_hash, user_verification)?;
    let user_verified = flags & FLAG_UV != 0;
    let backup_eligible = flags & FLAG_BE != 0;
    let backup_state = flags & FLAG_BS != 0;

    if flags & FLAG_AT == 0 {
        return Err(AuthenticatorDataError::NoAttestedCredentialData);
    }

    // --- attested credential data (§6.5.2) --------------------------------
    //
    // 16 aaguid, 2 credentialIdLength, credentialId, then the COSE key, which
    // runs to the end unless extensions follow it.
    let rest = &authenticator_data[HEADER_LEN..];
    if rest.len() < 18 {
        return Err(AuthenticatorDataError::Truncated);
    }
    let mut aaguid = [0_u8; 16];
    aaguid.copy_from_slice(&rest[..16]);

    let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
    if id_len > MAX_CREDENTIAL_ID_LEN {
        return Err(AuthenticatorDataError::CredentialIdTooLong);
    }
    // Checked before it is used as an index. `18 + id_len` cannot overflow: a
    // `u16` is at most 65535.
    let key_start = 18 + id_len;
    if rest.len() < key_start {
        return Err(AuthenticatorDataError::Truncated);
    }
    let credential_id = rest[18..key_start].to_vec();

    // The COSE key is a CBOR item followed, when the ED flag is set, by a
    // second one. `ciborium` stops at the end of the first item, so a trailing
    // extension map is skipped rather than mistaken for part of the key —
    // which is why this hands it the remainder rather than trying to find the
    // key's own length first. That length is not encoded anywhere.
    let public_key = cose::parse(&rest[key_start..])?;

    Ok(AttestedCredential {
        aaguid,
        credential_id,
        public_key,
        user_verified,
        backup_eligible,
        backup_state,
        sign_count,
    })
}
