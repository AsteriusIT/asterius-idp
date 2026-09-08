//! A pushed authorization request, as it is stored between the push and the
//! redirect.
//!
//! The *shape* of the parameters belongs to `asterius-oidc`, which validated
//! them; this crate holds what the store needs to key, expire and consume a
//! row. The parameters travel as an opaque JSON document, so the store never
//! has to be recompiled because a protocol parameter was added.

use crate::{ClientId, TenantId};
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
    /// RFC 9449 §12: the key the eventual code is bound to.
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
