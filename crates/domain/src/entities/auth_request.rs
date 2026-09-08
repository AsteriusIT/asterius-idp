//! A pushed authorization request, as it is stored between the push and the
//! redirect.
//!
//! The *shape* of the parameters belongs to `asterius-oidc`, which validated
//! them; this crate holds what the store needs to key, expire and consume a
//! row. The parameters travel as an opaque JSON document, so the store never
//! has to be recompiled because a protocol parameter was added.

use crate::{ClientId, GrantId, TenantId};
use serde_json::Value;
use time::OffsetDateTime;

/// A validated authorization request, waiting for its user agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedRequest {
    /// Which tenant issued the reference.
    pub tenant: TenantId,
    /// SHA-256 of the reference, lower-case hex. The reference itself is never
    /// stored: it is a bearer credential, and a leaked row must not yield one.
    pub request_uri_digest: String,
    /// The client that pushed it. A reference is usable only by the client it
    /// was issued to (RFC 9126 §2.2).
    pub client: ClientId,
    /// The validated parameters, exactly as they will be executed.
    pub parameters: Value,
    /// RFC 9449 §10: the key the eventual code is bound to.
    pub dpop_jkt: Option<String>,
    /// When it was pushed.
    pub pushed_at: OffsetDateTime,
    /// When the reference stops working.
    pub expires_at: OffsetDateTime,
}

/// What happened when a reference was presented.
///
/// Named variants rather than `Option`/`bool` because the three outcomes lead
/// to three different responses, and because "not found" and "already used"
/// must be *indistinguishable to the client* while remaining distinguishable
/// in a log — an operator debugging a double submission needs to know which,
/// and a caller guessing references must not.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Consumed {
    /// The reference was live, and is now spent.
    Request(Box<PushedRequest>),
    /// No such reference in this tenant.
    NotFound,
    /// Found, but already consumed.
    AlreadyUsed,
    /// Found, but past its expiry.
    Expired,
}

/// An authorization request as the *browser* sees it, mid-interaction.
///
/// The same row as [`PushedRequest`], reached by the other credential. What is
/// different is what the caller needs: a browser driving login and consent
/// cares about progress and the client's identity, not about the reference the
/// client is holding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractionRecord {
    /// Which tenant. A resumed interaction cannot cross one.
    pub tenant: TenantId,
    /// The client the user is being asked to authorise.
    pub client: ClientId,
    /// The validated authorization parameters.
    pub parameters: Value,
    /// Login and consent progress, owned and shaped by `asterius-web`.
    ///
    /// Opaque here on purpose: the stage machine belongs to the crate that
    /// renders the pages, and a store that understood it would have to be
    /// changed every time a stage was added.
    pub state: Value,
    /// The session that authenticated the user, once one has.
    pub session: Option<String>,
    /// When the interaction stops being usable.
    pub expires_at: OffsetDateTime,
}

/// What an authorization code was bound to at issuance.
///
/// Every field is compared at redemption. Grouping them means a new binding is
/// added in one place and checked in one place, rather than being remembered
/// at both ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBinding {
    /// The client the code was issued to.
    pub client_id: String,
    /// The grant it draws its authority from.
    pub grant_id: GrantId,
    /// The PKCE challenge, which is public (RFC 7636 §4.2).
    pub code_challenge: String,
    /// The redirect URI it was sent to, compared byte-for-byte.
    pub redirect_uri: String,
    /// `nonce`, carried into the ID token.
    pub nonce: Option<String>,
    /// The DPoP key the code is pinned to, if any.
    pub dpop_jkt: Option<String>,
    /// When it stops being redeemable.
    pub expires_at: OffsetDateTime,
}
