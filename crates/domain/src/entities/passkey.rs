//! A registered passkey, and the enrolment that produced it.
//!
//! The ceremony itself is `asterius-webauthn`, which does no I/O and holds no
//! opinion about storage. These are the two shapes that cross that boundary:
//! what an enrolment page has outstanding, and what a finished ceremony leaves
//! behind.

use crate::UserId;
use time::OffsetDateTime;

/// The longest a registration challenge may be outstanding.
///
/// Five minutes is the ceiling `ast-2vk.3` sets. It is generous for a ceremony
/// that is one touch of a fingerprint reader, and it is what a user who had to
/// go and find their security key needs. Longer would only widen the window in
/// which a captured challenge is still worth something.
pub const ENROLMENT_TTL: time::Duration = time::Duration::minutes(5);

/// An enrolment page that has been rendered, and what it is waiting for.
///
/// One per session: a second rendering replaces the first, so a browser with
/// two tabs open has one outstanding ceremony rather than two, and the tab that
/// finishes second finds nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolment {
    /// SHA-256 of the synchroniser token the page carries.
    pub csrf_digest: String,
    /// The outstanding challenge, if one has been issued and not yet spent.
    pub challenge: Option<Vec<u8>>,
    /// When the row stops being usable.
    pub expires_at: OffsetDateTime,
}

/// A passkey that a ceremony has just proved into existence.
///
/// Every field except [`Self::label`] comes from the authenticator or from the
/// relying-party description the server checked the ceremony against. Nothing
/// here is chosen by the browser: `rp_id` is this server's, and the flags are
/// what the authenticator reported inside the bytes that were verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPasskey {
    /// Whose it is.
    pub user: UserId,
    /// The credential id, as the authenticator minted it. Not a secret — it
    /// travels to the browser on every assertion — and unique per tenant.
    pub credential_id: Vec<u8>,
    /// The COSE public key, in the encoding it arrived in.
    pub public_key: Vec<u8>,
    /// The authenticator's counter at registration.
    pub sign_count: u32,
    /// The authenticator model, or `None` when it declined to say (all zeroes).
    pub aaguid: Option<uuid::Uuid>,
    /// Whether the credential may ever be backed up (§6.1.3).
    pub backup_eligible: bool,
    /// Whether it currently is.
    pub backup_state: bool,
    /// Whether the user was verified, not merely present.
    pub user_verified: bool,
    /// The RP ID the credential is scoped to, recorded rather than assumed.
    pub rp_id: String,
    /// What to call it in a list of credentials. Renaming is `ast-2vk.3`.
    pub label: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::ENROLMENT_TTL;

    /// The bead's ceiling, asserted rather than trusted to a comment: a
    /// constant that drifted upward would widen a replay window silently.
    #[test]
    fn an_enrolment_is_outstanding_for_no_more_than_five_minutes() {
        assert!(ENROLMENT_TTL <= time::Duration::minutes(5));
        assert!(ENROLMENT_TTL > time::Duration::ZERO);
    }
}
