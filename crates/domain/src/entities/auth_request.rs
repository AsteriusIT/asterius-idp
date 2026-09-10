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
    ///
    /// RFC 9449 §10's pin lives in here, under `dpop_jkt`, and nowhere else
    /// (`ast-rno`): the endpoint reconciles the `dpop_jkt` parameter with the
    /// thumbprint of any proof on the push, and the code issuer builds the
    /// binding from these parameters. A column beside them holding a second
    /// copy is a second answer to "which key is this code for", which is the
    /// shape `ast-36g` was found in.
    pub parameters: Value,
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

/// Where an interaction ends.
///
/// The one closed answer to "what is this login *for*". An interaction is
/// either an OAuth authorization, which ends at a client's validated
/// `redirect_uri`, or an entry into a page of this server, which ends at a
/// place named by a **variant**.
///
/// # Why the first-party arm carries no URL
///
/// Because a destination that is data is a destination somebody else can
/// supply. There is no `next` parameter here, no allow-list to keep in step
/// with the router, and therefore no open redirect to get wrong: the places a
/// first-party interaction can end are the variants of
/// [`FirstPartyDestination`], fixed when this crate is compiled. If this arm
/// ever grows a `String`, that property is gone.
///
/// # Why the OAuth arm carries the client rather than an `Option`
///
/// The absence has to be representable without making an *authorization* with
/// no client representable. Two `Option` fields would allow four states, two of
/// which are nonsense — an authorization with no client, and a first-party
/// interaction that names one. [`ClientRequest`] holds a [`ClientId`] and the
/// validated parameters, neither optional, so the only way to have neither is
/// to be on the other arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Continuation {
    /// An OAuth 2.0 authorization, on behalf of a client.
    Client(Box<ClientRequest>),
    /// A first-party page of this server (ADR-0009).
    FirstParty(FirstPartyDestination),
}

impl Continuation {
    /// An authorization for `client` with `parameters`.
    #[must_use]
    pub fn for_client(client: ClientId, parameters: Value) -> Self {
        Self::Client(Box::new(ClientRequest { client, parameters }))
    }

    /// The client this interaction authorises, when there is one.
    ///
    /// Deliberately the only way to reach it: a caller that wants a client has
    /// to say what it does when there is none.
    #[must_use]
    pub fn client_request(&self) -> Option<&ClientRequest> {
        match self {
            Self::Client(request) => Some(request),
            Self::FirstParty(_) => None,
        }
    }

    /// The first-party destination, when this interaction has one.
    #[must_use]
    pub const fn first_party(&self) -> Option<FirstPartyDestination> {
        match self {
            Self::FirstParty(destination) => Some(*destination),
            Self::Client(_) => None,
        }
    }
}

/// The client's half of an interaction: who asked, and for what.
///
/// Both fields are required, which is the point — see [`Continuation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRequest {
    /// The client the user is being asked to authorise.
    pub client: ClientId,
    /// The validated authorization parameters.
    pub parameters: Value,
}

/// A page of this server an interaction may end at.
///
/// A closed enum and nothing else. Adding a destination is a code change and a
/// compile error in every match, which is what makes "a browser cannot choose
/// where a login ends" true by construction rather than by review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstPartyDestination {
    /// The admin console, which lives under its tenant's URL space at
    /// `/t/{tenant}/admin/` (ADR-0009 for what it is, ADR-0010 for why it is
    /// under a tenant).
    AdminConsole,
}

impl FirstPartyDestination {
    /// How the destination is written in storage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdminConsole => "admin_console",
        }
    }

    /// Reads back a stored destination.
    ///
    /// `None` for anything else, which a caller must treat as an interaction it
    /// cannot finish: a row naming a destination this binary does not have was
    /// written by a newer one, and guessing would mean choosing a page on
    /// somebody else's behalf.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "admin_console" => Some(Self::AdminConsole),
            _ => None,
        }
    }
}

/// An authorization request as the *browser* sees it, mid-interaction.
///
/// The same row as [`PushedRequest`] when the continuation is a client's,
/// reached by the other credential; a row of its own when it is not. What is
/// different is what the caller needs: a browser driving login and consent
/// cares about progress and about where it ends, not about the reference a
/// client is holding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractionRecord {
    /// Which tenant. A resumed interaction cannot cross one.
    pub tenant: TenantId,
    /// What this interaction is for, and where it ends.
    pub continuation: Continuation,
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

impl InteractionRecord {
    /// The client this interaction authorises, when there is one.
    #[must_use]
    pub fn client_request(&self) -> Option<&ClientRequest> {
        self.continuation.client_request()
    }
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
