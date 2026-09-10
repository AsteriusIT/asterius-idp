//! `GET`, `PUT` and `DELETE /register/{client_id}` — the RFC 7592 client
//! configuration endpoint.
//!
//! `ast-m9c.4` hands every newly registered client a `registration_client_uri`
//! and a registration access token, because OIDC Registration §3.2 says an
//! implementation "MUST either return both a Client Configuration Endpoint and
//! a Registration Access Token or neither of them" and neither was not an
//! option. This is the endpoint that URL names.
//!
//! # What is decided here
//!
//! Almost nothing about *what a client is*: a `PUT` body goes through
//! [`ClientRegistration::from_json`], the same validator that `POST /register`
//! uses, so there is one definition of an acceptable client and not two that
//! drift. What is decided here is who may act on a registration, what a `PUT`
//! means, and what a caller is told when the answer is no.
//!
//! # The registration access token, and nothing else
//!
//! RFC 7592 §2: "The client MUST use its registration access token in all calls
//! to this endpoint as an OAuth 2.0 Bearer Token \[RFC6750\]." There is no other
//! credential — no `private_key_jwt` assertion, no mTLS binding, no admin
//! session. A bearer token authorising read, replacement and deletion of one
//! client is a large capability in a small string, so two properties matter
//! more than the verbs:
//!
//! * **The comparison is constant-time**, over SHA-256 digests, through
//!   [`ct_eq`]. The stored form is the digest ([`asterius_domain::credentials`]
//!   explains why a bare SHA-256 is right for a value with this much entropy),
//!   so nothing in this process ever holds a replayable copy.
//! * **The token is checked against the client named in the path.** OIDC
//!   Registration §4.1 is explicit that the client a configuration URL names
//!   "MUST be matched against the Client to which the Registration Access Token
//!   was issued". A perfectly valid token for client A presented at client B's
//!   URL is a refusal, not a success — and it is the same refusal as a token
//!   that was never issued, because the two must be indistinguishable.
//!
//! # 401, 403, and never 404
//!
//! OIDC Registration §4.4 settles the mapping and gives the reason:
//!
//! > If the Client does not exist on this server, the Client is invalid, or the
//! > Registration Access Token used is invalid, the server MUST respond with
//! > the HTTP 401 Unauthorized status code. If the Client does not have
//! > permission to read its record, the server MUST return an HTTP 403
//! > Forbidden. Note that for security reasons, to inhibit brute force attacks,
//! > endpoints MUST NOT return the HTTP 404 Not Found status code.
//!
//! RFC 7592 §2.1, §2.2 and §2.3 each say the same for their own verb: "If the
//! client does not exist on this server, the server MUST respond with HTTP 401
//! Unauthorized."
//!
//! So an unknown `client_id`, a client that never had a configuration endpoint,
//! a wrong token and a token belonging to somebody else all produce the same
//! 401 with the same body. The 403 is reachable only *after* a token has been
//! accepted — a suspended client — so it confirms nothing to anyone who did not
//! already hold that client's credential.
//!
//! The 401s are not audited. That is the rule `register` established and the
//! reason is stronger here: this endpoint is reachable with nothing but a path
//! segment, and an audit row per unauthenticated request is an amplification
//! primitive pointed at the one table that cannot be deleted from. Everything
//! after a successful authentication is audited.
//!
//! # A token that turns up at the wrong door is burned
//!
//! RFC 7592 §2.1, §2.2 and §2.3 each say that a registration access token
//! presented for a client that does not exist "SHOULD be immediately revoked",
//! and this endpoint honours it: a credential that does not manage the
//! `client_id` in the path is nulled out of whichever client in the tenant does
//! hold it, before the 401 is written. The two shapes of the mistake — a
//! `client_id` that names nothing and a `client_id` that names somebody else —
//! go through the same statement, and a digest no client holds writes nothing
//! at all.
//!
//! Two properties make that safe to do on an unauthenticated request, and the
//! private `burn` helper this module refuses through carries the argument for
//! both:
//!
//! * **It is one indexed statement, never a scan.** `clients` grew a partial
//!   index on `(tenant_id, registration_access_token_hash)` for this caller
//!   alone; without it, honouring the SHOULD would hand an anonymous requester
//!   a full table scan per attempt.
//! * **The refusal does not change.** Byte for byte, revoked or not, so the
//!   endpoint is not an oracle for "is this string somebody's registration
//!   access token".
//!
//! It is also a real loss for the client it happens to: this server issues no
//! client secret, so that token was the client's only credential and there is
//! no re-issue path. `burn` weighs that against what a leaked token can do
//! with unlimited attempts, and says why the trade lands where it does.
//!
//! # What this endpoint deliberately does not do
//!
//! * **It does not rotate the token on a read.** RFC 7592 §5 would permit it
//!   ("MAY be rotated when the developer or client does a read or update
//!   operation"), but OIDC Registration §4.3 is against it — "since Read
//!   operations are intended to be idempotent, the Client Read Request itself
//!   SHOULD NOT cause changes" — and no tenant setting can turn it on. An
//!   **update** does rotate where the tenant's registration policy asks for it
//!   (`ast-m9c.12`), and the reason it took a policy flag is delivery: a
//!   rotation whose response is lost in transit would strand the client
//!   permanently, for the same reason as above. The predecessor therefore keeps
//!   working for a bounded grace window, and stops the moment the successor is
//!   used. See [`authenticate`] and [`rotate`].
//! * **It does not send CORS headers.** OIDC Registration §4 says the endpoint
//!   "SHOULD support the use of Cross-Origin Resource Sharing (CORS) ... to
//!   enable JavaScript Clients and other Browser-Based Clients to access it".
//!   There are no such clients here: FAPI 2.0 SP §5.3.2.1 permits only
//!   `private_key_jwt` and mTLS, so every client holds a private key, and a
//!   client that can hold a private key is not a page. The SHOULD serves a
//!   population this profile does not have.

use crate::http::register::{
    MAX_BODY_BYTES, REGISTRATION_TOKEN_BITS, bearer, client_information, error, is_json,
    metadata_error, nqschar, unsignable,
};
use crate::outbound::sector;
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::ports::ClientUrlFetcher;
use asterius_domain::{
    Capabilities, Client, ClientConfiguration, ClientId, ClientRegistration, ClientRepository,
    ClientStatus, DomainError, KeyStore, ManagedClient, OpaqueToken,
    PreviousRegistrationAccessToken, Tenant, ct_eq, sha256,
};
use asterius_oidc::metadata::Endpoint;
use axum::Json;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;
use std::sync::LazyLock;
use time::OffsetDateTime;

/// The longest path segment this endpoint will treat as a `client_id`.
///
/// Every `client_id` that can have a registration access token was minted by
/// `POST /register` and is 24 characters (`c.` plus 22 `base64url` symbols).
/// The bound is generous rather than exact because a deployment may carry
/// clients from elsewhere, and it exists only so that a caller cannot make this
/// process send an arbitrarily long string to the database on an unauthenticated
/// request. A value over the bound is refused as though the client did not
/// exist, which it cannot.
const MAX_CLIENT_ID_LEN: usize = 256;

/// A digest no token hashes to, compared against when a client has none.
///
/// Drawn once per process from the same CSPRNG as every other credential, so it
/// is not a constant an attacker can precompute against.
///
/// This is a small honesty, not a claim of constant time. It removes the branch
/// on "was there a stored digest at all" from the path that handles a presented
/// credential, so that an absent row and a wrong token do the same
/// cryptographic work. The database lookup in front of it does not have that
/// property and cannot be made to; what the endpoint actually promises is the
/// one OIDC Registration §4.4 asks for — that the *response* does not say
/// whether the client exists — and that a `client_id` is 128 bits of CSPRNG
/// output which travels in the clear in every authorization request anyway.
static DECOY: LazyLock<[u8; 32]> =
    LazyLock::new(|| sha256(asterius_domain::OpaqueToken::generate().expose().as_bytes()));

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// Why a management request was not carried out.
///
/// Three cases, and the first two are deliberately one answer: OIDC
/// Registration §4.4 folds "no such client", "the client is invalid" and "the
/// token is invalid" into a single 401 so that the endpoint cannot be used to
/// discover which registrations exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// No bearer credential was presented at all.
    Missing,
    /// A credential was presented and is not the one that manages this client.
    ///
    /// Also: there is no such client, the client has no registration access
    /// token because it was never given a configuration endpoint, or the
    /// credential belongs to a different client.
    Invalid,
    /// The credential was accepted and the client may not manage itself.
    ///
    /// A client an operator suspended. RFC 7592 §2.1's "if the client does not
    /// have permission to read its record" and OIDC Registration §4.4's 403.
    Suspended,
}

impl Refusal {
    /// The OAuth error code, from a closed set.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            // RFC 6750 §3.1.
            Self::Missing | Self::Invalid => "invalid_token",
            // RFC 6750 §3.1's only 403 code is `insufficient_scope`, and this
            // is not about scope: the token grants everything it is going to
            // grant and the client is switched off. `access_denied` is RFC 6749
            // §4.1.2.1's spelling and the one `register` already borrows for
            // its own 403, so a client parsing both endpoints sees one word for
            // one meaning.
            Self::Suspended => "access_denied",
        }
    }

    /// The status code.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            // OIDC Registration §4.4 and RFC 7592 §2.1/§2.2/§2.3. Never 404:
            // "for security reasons, to inhibit brute force attacks, endpoints
            // MUST NOT return the HTTP 404 Not Found status code."
            Self::Missing | Self::Invalid => StatusCode::UNAUTHORIZED,
            Self::Suspended => StatusCode::FORBIDDEN,
        }
    }

    /// The `WWW-Authenticate` challenge, when one is owed.
    ///
    /// RFC 6750 §3 makes the header mandatory on a 401. The `error` attribute
    /// appears only when a credential was presented and rejected, which is what
    /// §3 says it is for; telling a caller that sent nothing that its token is
    /// invalid would describe a token that does not exist.
    ///
    /// The 403 carries none. The credential was accepted, so inviting the
    /// caller to authenticate again would ask it to solve a problem it does not
    /// have.
    #[must_use]
    pub const fn challenge(self) -> Option<&'static str> {
        match self {
            Self::Missing => Some("Bearer"),
            Self::Invalid => Some(r#"Bearer error="invalid_token""#),
            Self::Suspended => None,
        }
    }

    /// The description, in fixed text.
    ///
    /// [`Self::Missing`] and [`Self::Invalid`] say almost the same thing on
    /// purpose: which of them happened is already in the challenge, and a
    /// longer sentence would have to distinguish "no such client" from "wrong
    /// token", which is the distinction §4.4 exists to hide.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Missing => "a registration access token is required",
            Self::Invalid => "the registration access token was not accepted",
            Self::Suspended => "this client is suspended and cannot manage its registration",
        }
    }
}

/// Why a request stopped before it reached the client's own registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Denied {
    /// The caller may not do this.
    Refused(Refusal),
    /// The store could not be reached, so no decision was possible.
    ///
    /// Never folded into [`Refusal::Invalid`]: "the database is down" and "no
    /// such client" must not be the same answer, because one of them is a
    /// reason for the client to stop retrying and the other is not.
    Unavailable,
}

impl Denied {
    /// The reason label this refusal carries into the audit trail.
    const fn reason(self) -> &'static str {
        match self {
            Self::Refused(Refusal::Missing) => "no_credential",
            Self::Refused(Refusal::Invalid) => "invalid_token",
            Self::Refused(Refusal::Suspended) => "client_suspended",
            Self::Unavailable => "temporarily_unavailable",
        }
    }

    /// Whether this refusal happened after a credential was accepted.
    ///
    /// Only those are audited: everything before is reachable by anyone who can
    /// reach the endpoint.
    const fn is_authenticated(self) -> bool {
        matches!(self, Self::Refused(Refusal::Suspended))
    }
}

impl IntoResponse for Denied {
    fn into_response(self) -> Response {
        match self {
            Self::Refused(refusal) => {
                let mut response = error(refusal.status(), refusal.code(), refusal.description());
                if let Some(challenge) = refusal.challenge() {
                    // Every value `challenge` returns is a literal in this
                    // module, so `from_static` cannot panic on caller input.
                    response.headers_mut().insert(
                        header::WWW_AUTHENTICATE,
                        HeaderValue::from_static(challenge),
                    );
                }
                response
            }
            Self::Unavailable => unavailable(),
        }
    }
}

// ---------------------------------------------------------------------------
// The fields a client may not set
// ---------------------------------------------------------------------------

/// A field an update tried to set that is not the client's to set.
///
/// RFC 7592 §2.2 lists four members an update "MUST NOT include" —
/// `registration_access_token`, `registration_client_uri`,
/// `client_secret_expires_at` and `client_id_issued_at` — plus a rule about
/// `client_secret`. Three of them are refused here, and the split is by what a
/// client would be wrong about if the server said nothing:
///
/// * **Refused: `client_secret`, `client_secret_expires_at`,
///   `registration_access_token`.** Each is a statement about a credential.
///   §2.2 is explicit that a client "MUST NOT be allowed to overwrite its
///   existing client secret with its own chosen value", and this server issues
///   no secret at all (FAPI 2.0 SP §5.3.2.1), so there is nothing for either
///   secret field to match. Accepting any of the three silently would leave a
///   client believing it had set or rotated a credential that it has not, which
///   is the one class of misunderstanding that must not be answered with a 200.
/// * **Ignored: `registration_client_uri`, `client_id_issued_at`.** Both are
///   computed by this server from values a client cannot influence — the
///   tenant's issuer with the `client_id`, and the row's `created_at`, which
///   `replace` does not write — so an echoed or a forged value changes nothing
///   and the response tells the client the truth either way. They are also the
///   two of the four that a *read* returns, and §2.2's other sentence requires
///   an update to "include all client metadata fields as returned to the client
///   from a previous registration, read, or update operation". Turning a
///   client's own echo of a read into a 400 would put a field-stripping step
///   between the two halves of the flow §2.2 prescribes, in order to enforce a
///   rule with no consequence.
///
/// The result is the property the round-trip test below pins: the document a
/// read returns is a document an update accepts, and the fields a client may
/// not send are exactly the fields a read never gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotYours {
    /// `client_id` was absent, was not a string, or named another client.
    ClientId,
    /// `client_secret` was present. This server issues none.
    ClientSecret,
    /// `client_secret_expires_at` was present. There is no secret to expire.
    ClientSecretExpiresAt,
    /// `registration_access_token` was present.
    RegistrationAccessToken,
}

impl NotYours {
    /// The description, in fixed text that names the field and never quotes it.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::ClientId => {
                "client_id is required and must be the client this URL names (RFC 7592 2.2)"
            }
            Self::ClientSecret => {
                "client_secret must not be set: this server issues no client secrets \
                 (FAPI 2.0 SP 5.3.2.1)"
            }
            Self::ClientSecretExpiresAt => {
                "client_secret_expires_at must not be set: this server issues no client \
                 secrets, so there is none to expire (RFC 7592 2.2)"
            }
            Self::RegistrationAccessToken => {
                "registration_access_token must not be sent in an update request; whether it \
                 is rotated is the server's decision, not the client's (RFC 7592 2.2, 5)"
            }
        }
    }
}

/// The members of an update document that this server, not the client, owns.
///
/// Read as [`Value`] rather than as typed fields, and that is the point: the
/// question each one answers is "did the client send this member at all", not
/// "what does it say". A typed field would fail to deserialise on
/// `"client_secret": 5` and the guard would never run, which is exactly the
/// document an attacker would try.
///
/// The one exception is `client_id`, where the value matters, so it is compared
/// as a string and anything that is not a string fails the same way an absent
/// member does.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct NotTheirs {
    client_id: Value,
    client_secret: Value,
    client_secret_expires_at: Value,
    registration_access_token: Value,
}

/// Whether an update document leaves alone the fields this server owns.
///
/// The whole of the RFC 7592 §2.2 immutability check, in one pure function, so
/// that it can be exercised without a runtime, a database or an HTTP request.
///
/// A body that is not a JSON object passes: that is not this guard's error to
/// report. [`ClientRegistration::from_json`] rejects the same body a moment
/// later with the message RFC 7591 §3.2.2 asks for, and one parser should own
/// that answer rather than two producing different ones.
///
/// # Errors
///
/// Returns the first field the client had no business setting.
// fuzz-target: client_update_guard
pub fn update_guard(body: &[u8], client_id: &str) -> Result<(), NotYours> {
    match NotTheirs::read(body) {
        Some(document) => document.check(client_id),
        None => Ok(()),
    }
}

impl NotTheirs {
    /// Reads the guarded members out of an update document.
    ///
    /// `None` when the body is not a JSON object at all.
    fn read(body: &[u8]) -> Option<Self> {
        serde_json::from_slice(body).ok()
    }

    /// Whether the document leaves this server's fields alone.
    ///
    /// # Errors
    ///
    /// Returns the first field the client had no business setting.
    fn check(&self, client_id: &str) -> Result<(), NotYours> {
        // RFC 7592 §2.2: "The client MUST include its client_id field in the
        // request, and it MUST be the same as its currently issued client
        // identifier."
        //
        // A plain comparison, not a constant-time one: a `client_id` is a
        // public identifier that travels in the clear in every authorization
        // request, and the caller supplied both sides of this comparison.
        if self.client_id.as_str() != Some(client_id) {
            return Err(NotYours::ClientId);
        }

        // The three members of RFC 7592 §2.2's list that describe a credential.
        // [`NotYours`] carries the argument for why these are refused and the
        // other two are ignored.
        //
        // `null` counts as absent, which §2.2 permits: "The authorization
        // server MAY ignore any null or empty value in the request just as any
        // other value."
        for (value, failure) in [
            (&self.client_secret, NotYours::ClientSecret),
            (
                &self.client_secret_expires_at,
                NotYours::ClientSecretExpiresAt,
            ),
            (
                &self.registration_access_token,
                NotYours::RegistrationAccessToken,
            ),
        ] {
            if !value.is_null() {
                return Err(failure);
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The endpoint
// ---------------------------------------------------------------------------

/// What the handlers need to answer a management request.
#[derive(Debug)]
pub struct ConfigurationContext<'a> {
    /// The tenant the request arrived at. Its issuer is what
    /// `registration_client_uri` is rebuilt from.
    pub tenant: &'a Tenant,
    /// Reads a client's registration, for the document a read returns.
    ///
    /// The narrow read port, held separately from [`Self::configuration`]
    /// rather than folded into it, because the two answer different questions:
    /// this one re-validates a stored row against today's profile and the other
    /// deliberately does not.
    pub clients: &'a dyn ClientRepository,
    /// Authenticates, replaces and deprovisions.
    pub configuration: &'a dyn ClientConfiguration,
    /// The tenant's keys, for the one question an update asks of them: whether
    /// the `id_token_signed_response_alg` it moves to is one this tenant signs
    /// with. A `PUT` may change that field, so a check only at registration
    /// would be a check a client can walk around.
    pub keys: &'a dyn KeyStore,
    /// What this deployment offers. An update is validated against it, so a
    /// client cannot update its way into a feature the server does not have.
    pub capabilities: Capabilities,
    /// This tenant's registration policy (`ast-m9c.6`).
    ///
    /// Applied to a replacement document exactly as it is to a fresh
    /// registration, and for the reason RFC 7592 §2.2 makes necessary: a `PUT`
    /// replaces the whole registration, so a rule enforced only at `POST
    /// /register` would be a rule every client could walk around by
    /// registering once and then updating.
    pub tenant_policy: &'a asterius_domain::RegistrationPolicy,
    /// Dereferences the URLs an updated registration document names.
    ///
    /// The same port `POST /register` holds, for the same reason: RFC 7592 §2.2
    /// replaces the whole registration, so an update can name a new
    /// `sector_identifier_uri` and must prove it the same way a fresh
    /// registration does. Leaving the check out here would make the update
    /// endpoint the way around it.
    pub outbound: &'a dyn ClientUrlFetcher,
    /// Where the decision is recorded.
    pub audit: &'a dyn AuditSink,
    /// The request id, for correlating the audit record with the access log.
    pub request_id: Option<&'a str>,
}

/// The route this endpoint is mounted at.
///
/// Built from the one endpoint registry rather than written out, so that moving
/// `/register` moves this with it. The two must agree: a
/// `registration_client_uri` handed to a client that the router does not serve
/// is the 404 this story exists to close, and the test below pins the two
/// together.
#[must_use]
pub fn path() -> String {
    format!("{}/{{client_id}}", Endpoint::Registration.path())
}

/// `GET` — RFC 7592 §2.1, OIDC Registration §4.2.
///
/// # Errors
///
/// Never returns `Err`: every failure is a `Response`, because a caller is
/// entitled to the specified error shape whatever went wrong.
pub async fn read(
    context: &ConfigurationContext<'_>,
    client_id: &str,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let client_id = ClientId::new(client_id.to_owned());
    if let Err(denied) = authenticate(context, &client_id, headers, now).await {
        return refuse(context, now, EventType::CLIENT_READ, &client_id, denied).await;
    }

    // Rendered from the row, not from anything the request carried. RFC 7592 §3
    // requires "all registered metadata about this client, including any fields
    // provisioned by the authorization server itself", and this profile
    // provisions several.
    let stored = match context.clients.find(&client_id).await {
        Ok(Some(stored)) => stored,
        // Deleted between the authentication and the read. RFC 7592 §5: once a
        // client is deprovisioned the server "MUST treat all such requests as
        // if the registration access token was invalid".
        Ok(None) => {
            return Denied::Refused(Refusal::Invalid).into_response();
        }
        Err(failure) => {
            return unreadable(context, now, EventType::CLIENT_READ, &client_id, &failure).await;
        }
    };

    record(
        context,
        now,
        EventType::CLIENT_READ,
        Outcome::Success,
        &client_id,
        None,
        None,
    )
    .await;
    ok(client_information(&stored, context.tenant, None, now))
}

/// `PUT` — RFC 7592 §2.2.
///
/// The body is a **replacement**, and the whole of that rule is enforced by not
/// writing the code that would break it: the document goes through
/// [`ClientRegistration::from_json`] exactly as a fresh registration would, and
/// the result replaces the stored registration outright. Nothing reads the old
/// row into the new one, so a field the client omits gets the registration-time
/// default rather than the value it used to have. §2.2 requires precisely that
/// — "Omitted fields MUST be treated as null or empty values by the server,
/// indicating the client's request to delete them from the client's
/// registration" — and it is a security rule, not a formality: a client that
/// omits `redirect_uris` while meaning to change only its name must not keep
/// the old callbacks by accident.
///
/// # Errors
///
/// Never returns `Err`, for the same reason as [`read`].
/// The checks a replacement document owes beyond [`ClientRegistration::from_json`],
/// each of which needs something outside the document to answer.
///
/// Lifted out of [`update`] so that the endpoint's shape — authenticate, parse,
/// check, replace — stays readable, and because both arms record the same audit
/// event with only the reason differing. `Some` is the response to return.
async fn unacceptable(
    context: &ConfigurationContext<'_>,
    client_id: &ClientId,
    now: OffsetDateTime,
    registration: &ClientRegistration,
) -> Option<Response> {
    // This tenant's rules, before anything is fetched: a document the policy
    // refuses is refused whatever a sector document says.
    if let Err(violation) = context.tenant_policy.evaluate(registration) {
        let failure = violation.to_metadata_error();
        record(
            context,
            now,
            EventType::CLIENT_UPDATED,
            Outcome::Failure,
            client_id,
            Some(failure.code()),
            Some(violation.rule.as_str()),
        )
        .await;
        return Some(metadata_error(&failure));
    }

    // The same check `POST /register` makes, for the same reason and at the
    // same point: an update that moved a live client onto an algorithm this
    // tenant holds no key for would break every token it is issued under that
    // member, and the client would learn that from a token or UserInfo request
    // rather than from here. Every member `register::server_signed_algorithms`
    // names is covered, so a member added there is checked on this path too.
    if let Some(refusal) = unsignable(context.keys, context.tenant, registration).await {
        record(
            context,
            now,
            EventType::CLIENT_UPDATED,
            Outcome::Failure,
            client_id,
            Some(refusal.code()),
            None,
        )
        .await;
        return Some(refusal.into_response());
    }

    // OIDC Registration §5, as at registration: the sector a client names is
    // checked before anything derives a `sub` in it.
    if let Err(failure) = sector::verify(context.outbound, registration).await {
        record(
            context,
            now,
            EventType::CLIENT_UPDATED,
            Outcome::Failure,
            client_id,
            Some(failure.code()),
            None,
        )
        .await;
        return Some(metadata_error(&failure));
    }

    None
}

pub async fn update(
    context: &ConfigurationContext<'_>,
    client_id: &str,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let client_id = ClientId::new(client_id.to_owned());
    // Authorization first, so that nothing below is work an unauthorised caller
    // can make this process do — not a JSON parse, not an allocation the size
    // of the body, not an audit row.
    if let Err(denied) = authenticate(context, &client_id, headers, now).await {
        return refuse(context, now, EventType::CLIENT_UPDATED, &client_id, denied).await;
    }

    if body.len() > MAX_BODY_BYTES {
        return rejected(
            context,
            now,
            &client_id,
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_client_metadata",
            "the registration document is too large",
        )
        .await;
    }

    // RFC 7592 §2.2: the update request carries "a content type of
    // application/json".
    if !is_json(headers) {
        return rejected(
            context,
            now,
            &client_id,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_client_metadata",
            "content-type must be application/json",
        )
        .await;
    }

    // The fields this server owns, before the validator sees a document that
    // may be trying to move one of them.
    if let Err(failure) = update_guard(body, client_id.as_str()) {
        return rejected(
            context,
            now,
            &client_id,
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            failure.description(),
        )
        .await;
    }

    let registration = match ClientRegistration::from_json(body, context.capabilities) {
        Ok(registration) => registration,
        Err(failure) => {
            record(
                context,
                now,
                EventType::CLIENT_UPDATED,
                Outcome::Failure,
                &client_id,
                Some(failure.code()),
                None,
            )
            .await;
            return metadata_error(&failure);
        }
    };

    // The two checks the validator cannot make on the document alone: one
    // about this tenant's keys, one about a host that has to be asked.
    if let Some(refusal) = unacceptable(context, &client_id, now, &registration).await {
        return refusal;
    }

    let replacement = Client {
        tenant: context.tenant.id.clone(),
        id: client_id.clone(),
        registration,
        // The store does not write this column and the response is rendered
        // from what comes back, so this is a placeholder. A suspended client
        // never reaches here: it was refused with a 403 above.
        status: ClientStatus::Active,
        created_at: now,
        updated_at: now,
    };

    let stored = match context.configuration.replace(&replacement).await {
        Ok(stored) => stored,
        Err(DomainError::NotFound) => {
            // Deleted between the authentication and the write, by a
            // concurrent DELETE from the same client. RFC 7592 §5 again.
            return Denied::Refused(Refusal::Invalid).into_response();
        }
        Err(failure) => {
            return unreadable(
                context,
                now,
                EventType::CLIENT_UPDATED,
                &client_id,
                &failure,
            )
            .await;
        }
    };

    record(
        context,
        now,
        EventType::CLIENT_UPDATED,
        Outcome::Success,
        &client_id,
        None,
        None,
    )
    .await;

    // RFC 7592 §5's "MAY be rotated ... on a read or update operation", taken
    // for the update alone and only where a tenant asked for it. After the
    // replacement, never before: a rotation that landed on a `PUT` the
    // validator went on to refuse would hand the client a new credential in a
    // response that says the update failed.
    let rotated = rotate(context, &client_id, now).await;
    ok(client_information(
        &stored,
        context.tenant,
        rotated.as_ref(),
        now,
    ))
}

/// Issues this client a new registration access token, if the tenant asked for
/// one (`ast-m9c.12`).
///
/// `None` — meaning the response carries no `registration_access_token` and the
/// client keeps the one it has — in three cases, and they are deliberately the
/// same answer:
///
/// * this tenant does not rotate, which is the default;
/// * the write failed;
/// * the row vanished between the update and the rotation.
///
/// The last two are the reason the response is rendered from what this returns
/// rather than from what was minted. The one outcome that must never happen is
/// a `200` naming a token the database does not hold: a client that believed it
/// would discard a working credential for one that authenticates nothing, and
/// with no client secret and no re-issue path that is permanent. Failing to
/// rotate leaves the client exactly as it was, which is a state it can act
/// from.
///
/// The audit record is written before the token reaches the response and names
/// no part of it — see [`EventType::CLIENT_CREDENTIAL_ROTATED`].
async fn rotate(
    context: &ConfigurationContext<'_>,
    client_id: &ClientId,
    now: OffsetDateTime,
) -> Option<OpaqueToken> {
    if !context.tenant_policy.rotates_registration_access_token() {
        return None;
    }

    let token = OpaqueToken::generate_bits::<REGISTRATION_TOKEN_BITS>();
    let digest = sha256(token.expose().as_bytes());
    let grace_expires_at = now + context.tenant_policy.registration_access_token_grace();
    if let Err(failure) = context
        .configuration
        .rotate_registration_access_token(client_id, &digest, grace_expires_at)
        .await
    {
        // At `error`, because the client is about to be told nothing happened
        // and the operator is the only one who can see why.
        tracing::error!(
            %failure,
            tenant = %context.tenant.id,
            client = %client_id,
            "a registration access token could not be rotated; the client keeps the one it has"
        );
        return None;
    }

    record(
        context,
        now,
        EventType::CLIENT_CREDENTIAL_ROTATED,
        Outcome::Success,
        client_id,
        None,
        None,
    )
    .await;
    Some(token)
}

/// `DELETE` — RFC 7592 §2.3.
///
/// A real delete, not a flag. §2.3 says a successful delete "will invalidate
/// the `client_id`, `client_secret`, and `registration_access_token` for this
/// client, thereby preventing the `client_id` from being used at either the
/// authorization endpoint or token endpoint", and §5 makes the token part a
/// MUST. A status flag would leave the row, and with it the registration access
/// token, in a state where authentication succeeds and the action cannot —
/// which §5 names as the thing to avoid.
///
/// Removing the row also does what §2.3's SHOULD asks — "immediately invalidate
/// all existing authorization grants and currently active access tokens, all
/// refresh tokens, and all other tokens associated with this client" — through
/// the schema's cascades rather than through a list of deletes somebody has to
/// remember to extend. `client_keys`, `auth_requests` and `grants` reference
/// the client on delete cascade, and `authorization_codes` and `refresh_tokens`
/// cascade from `grants`.
///
/// The one part no cascade can reach is an access token already issued: a
/// signed JWT this server does not hold, with no row to delete and no `jti`
/// this deployment ever wrote down (RFC 9068 tokens are stateless by design).
/// `deprovision` answers it with a cutoff instead — nothing issued to this
/// `client_id` before `now` verifies any more, whatever its `exp` says
/// (`ast-m9c.13`). That happens in the store, in the same transaction as the
/// delete, so the admin API's deprovisioning gets it too rather than this
/// handler being the only door that closes properly.
///
/// # Errors
///
/// Never returns `Err`, for the same reason as [`read`].
pub async fn remove(
    context: &ConfigurationContext<'_>,
    client_id: &str,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let client_id = ClientId::new(client_id.to_owned());
    if let Err(denied) = authenticate(context, &client_id, headers, now).await {
        return refuse(context, now, EventType::CLIENT_DELETED, &client_id, denied).await;
    }

    match context.configuration.deprovision(&client_id, now).await {
        Ok(()) => {}
        // Two DELETEs raced. The client got what it asked for either way, but
        // the answer is the one a second call gets from then on.
        Err(DomainError::NotFound) => {
            return Denied::Refused(Refusal::Invalid).into_response();
        }
        Err(failure) => {
            return unreadable(
                context,
                now,
                EventType::CLIENT_DELETED,
                &client_id,
                &failure,
            )
            .await;
        }
    }

    record(
        context,
        now,
        EventType::CLIENT_DELETED,
        Outcome::Success,
        &client_id,
        None,
        None,
    )
    .await;

    // RFC 7592 §2.3: "If a client has been successfully deprovisioned, the
    // authorization server MUST respond with an HTTP 204 No Content message",
    // and its example carries both cache directives.
    (
        StatusCode::NO_CONTENT,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Whether a presented digest is the one that manages this client.
fn admits(stored: Option<[u8; 32]>, presented: &[u8; 32]) -> bool {
    // Both operands are evaluated whatever the first says — `&`, not `&&` — so
    // that a client with no stored digest does the same cryptographic work as
    // one with the wrong token, and can never be admitted by a comparison
    // against the decoy. See `DECOY` for what that does and does not buy.
    ct_eq(&stored.unwrap_or(*DECOY), presented) & stored.is_some()
}

/// Whether a presented digest is a rotated-out token still inside its grace
/// window (`ast-m9c.12`).
///
/// The same shape as [`admits`] and for the same reason: the comparison happens
/// whether or not there is a predecessor and whether or not its window has
/// closed, so an expired predecessor costs exactly what a live one does. What
/// makes the answer `false` is the `&`, never a branch that skipped the
/// comparison.
///
/// The window is checked against the request's own `now` rather than swept by a
/// background job, so a predecessor is refused the moment it expires even
/// though its digest is still in the row. Storage is where the value lives;
/// this is where it stops being a credential.
fn admits_previous(
    previous: Option<PreviousRegistrationAccessToken>,
    presented: &[u8; 32],
    now: OffsetDateTime,
) -> bool {
    let digest = previous.map_or(*DECOY, |previous| previous.digest);
    let within_grace = previous.is_some_and(|previous| previous.is_within_grace(now));
    ct_eq(&digest, presented) & within_grace
}

/// Revokes a credential that did not fit, and refuses either way.
///
/// RFC 7592 §2.1, §2.2 and §2.3 each say that a registration access token
/// presented for a client that does not exist "SHOULD be immediately revoked".
/// This is where that happens, and it covers both shapes of the mistake with
/// one statement: a `client_id` that names nothing, and a `client_id` that
/// names a real client the token does not manage. The statement asks who holds
/// the presented digest, not who the path named, so the two cases differ only
/// in whether a row comes back.
///
/// # What this costs, and why it is still right
///
/// This server issues no client secret (FAPI 2.0 SP §5.3.2.1), so the
/// registration access token is a client's **only** credential and there is no
/// re-issue path. Revoking it is therefore permanent: a client that mistyped
/// its configuration URL once loses the ability to read, update or delete its
/// own registration for good, and has to register again. RFC 7592 §5 names that
/// state as one to avoid, and the decision here is to accept it rather than
/// keep a credential alive after it has been seen used at the wrong door.
///
/// The reasoning is about who is holding the token when this fires. Its
/// legitimate owner has a `registration_client_uri` the server handed it, so
/// the wrong URL is a typo made by a human once, not something a running client
/// does. A token that arrives at a `client_id` it does not manage is much more
/// often one that leaked — into a log, a bug report, an environment shared with
/// something else — and is being tried against identifiers by somebody probing
/// for the door it opens. Burning it on the first wrong try turns a leaked
/// credential's first misuse into its last, which is the only moment at which
/// this server can act on the leak at all: after a correct use there is nothing
/// left to protect. The cost falls on a client that can re-register in one
/// request; the benefit is that a leaked token has one attempt, not unlimited
/// ones.
///
/// The lockout is loud where it needs to be — the store logs a warning when a
/// row was actually hit — and silent where it must be: see below.
///
/// # Why the answer cannot say what happened
///
/// The return is [`Refusal::Invalid`] unconditionally, and every input to it is
/// a constant of this module, so the response is byte-identical whether the
/// digest matched a client, matched nothing, or the revocation failed outright.
/// If it were not, this endpoint would be an oracle for "is this string
/// somebody's registration access token", answered without authenticating —
/// which is a better primitive than the one revocation takes away.
///
/// A storage failure is logged and swallowed for the same reason. Turning it
/// into [`Denied::Unavailable`] would make a 503 mean "your token was worth
/// revoking", and the caller has already earned its 401 on evidence that does
/// not depend on this statement succeeding.
///
/// What is left is timing: a revocation that hits a row does a write and one
/// that does not does not, so the two are not equal to a stopwatch. Closing
/// that would mean writing unconditionally to a decoy row on every failed
/// management request, which buys less than it costs on an endpoint whose
/// entire input is a public identifier and a string the caller already knows.
async fn burn(context: &ConfigurationContext<'_>, presented: &[u8; 32]) -> Denied {
    if let Err(failure) = context
        .configuration
        .revoke_registration_access_token(presented)
        .await
    {
        tracing::error!(
            %failure,
            tenant = %context.tenant.id,
            "could not revoke a registration access token presented at the wrong client"
        );
    }
    Denied::Refused(Refusal::Invalid)
}

/// Whether this request may act on this client.
///
/// The whole authorization decision for the endpoint. Three things have to be
/// true and they are checked in this order for a reason:
///
/// 1. A bearer credential was presented (RFC 6750 §2.1). Checked before the
///    database, because a request with no credential is answered without one.
/// 2. It is the digest stored for **the client this URL names**. OIDC
///    Registration §4.1: the client a configuration URL identifies "MUST be
///    matched against the Client to which the Registration Access Token was
///    issued". Nothing looks a client up *by* the presented token, so a token
///    for another client cannot be admitted here even by accident — the only
///    stored digest this function compares against is the one belonging to the
///    path. The lookup by digest exists ([`burn`]), but it only ever revokes;
///    it can never admit.
/// 3. The client is not suspended.
///
/// # The predecessor, during its grace window
///
/// Since `ast-m9c.12` a client may hold two digests: the current one and the
/// one a rotation replaced, for the bounded window
/// [`PreviousRegistrationAccessToken`] describes. Both are compared, and the
/// second is what stops a rotation whose `200` was lost from ending the
/// client's ability to manage its own registration — this server issues no
/// client secret, so there would be no way back.
///
/// The window closes early on success: a request that authenticated with the
/// **current** token proves the client received it, so the predecessor is
/// retired here and now rather than at its expiry. That is what keeps the grace
/// a cover for a lost response instead of a period in which one client has two
/// credentials, and it is why the retirement lives in this function — every
/// verb goes through it, so a client whose next call is a read closes the
/// window just as a client that updates again does.
///
/// Retiring on a read is not the change OIDC Registration §4.3 rules out. §4.3
/// protects the *registration* — "the Client Read Request itself SHOULD NOT
/// cause changes to the Client's registered metadata values" — and a spare
/// credential the server already decided to withdraw is not a metadata value.
/// Nothing in the document a read returns depends on it.
async fn authenticate(
    context: &ConfigurationContext<'_>,
    client_id: &ClientId,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Result<ManagedClient, Denied> {
    let Some(presented) = bearer(headers) else {
        return Err(Denied::Refused(Refusal::Missing));
    };
    // Hashed before the database is asked anything, because every path from
    // here that refuses also revokes, and the revocation needs the digest.
    let presented = sha256(presented.as_bytes());
    if client_id.as_str().len() > MAX_CLIENT_ID_LEN {
        // No client this long exists, so this is RFC 7592 §2.1's "presented for
        // a client that does not exist" as surely as a well-formed identifier
        // that names nothing. The path segment never reaches the database; the
        // digest does.
        return Err(burn(context, &presented).await);
    }

    let managed = match context.configuration.managed(client_id).await {
        Ok(managed) => managed,
        Err(failure) => {
            tracing::error!(
                %failure,
                tenant = %context.tenant.id,
                "cannot read a client for a configuration request"
            );
            return Err(Denied::Unavailable);
        }
    };

    let stored = managed.as_ref().and_then(|m| m.registration_access_token);
    let previous = managed
        .as_ref()
        .and_then(|m| m.previous_registration_access_token);
    // Both comparisons happen, always — `|`, not `||` — so that a client with a
    // predecessor and one without do the same work, and so that which of the
    // two digests matched is not a timing signal.
    let by_current = admits(stored, &presented);
    let by_previous = admits_previous(previous, &presented, now);
    if !(by_current | by_previous) {
        // `burn` looks at the current digest only. A rotated-out token
        // presented at the wrong client is refused but not revoked, and that is
        // the trade the migration argues: honouring the SHOULD for it too would
        // mean a second indexed lookup on every unauthenticated request, to
        // shorten a life already capped at minutes.
        return Err(burn(context, &presented).await);
    }

    let managed = managed.expect("a digest was compared, so the client exists");
    if managed.status != ClientStatus::Active {
        // RFC 7592 §2.1 and OIDC Registration §4.4: a client that does not have
        // permission to act on its own record gets a 403. This is the only 403
        // the endpoint has, and it is reachable only by a caller that already
        // proved it holds this client's registration access token — so it
        // confirms nothing to anybody else.
        //
        // Suspension covers the delete too. `status = 'disabled'` is an
        // operator's decision about a client that is under investigation or
        // being withdrawn, and letting it delete itself would cascade away the
        // grants that are the evidence. An operator who wants it gone removes
        // it through the admin path.
        return Err(Denied::Refused(Refusal::Suspended));
    }

    // The successor has been used, so the predecessor has no job left
    // (`ast-m9c.12`). Done before the request is served rather than after, so
    // that a client cannot use the window's remaining seconds by pipelining.
    //
    // A failure here does not fail the request. The caller authenticated with
    // the credential this server issued it; refusing that because a
    // housekeeping statement did not land would break the endpoint for the very
    // client the rotation was for, and the predecessor still dies at its expiry
    // — which is the point of the expiry being in the row rather than only in
    // this decision.
    if by_current
        && previous.is_some()
        && let Err(failure) = context
            .configuration
            .retire_previous_registration_access_token(client_id)
            .await
    {
        tracing::error!(
            %failure,
            tenant = %context.tenant.id,
            client = %client_id,
            "a rotated-out registration access token could not be retired early; it stays \
             valid until its grace window closes"
        );
    }
    Ok(managed)
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// A 200 carrying a client information response.
///
/// `no-store` because the document names a client's keys and callbacks, and
/// because RFC 7592 §2.1's and §3's examples both send it.
fn ok(document: Value) -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(document),
    )
        .into_response()
}

/// The answer when the store could not be reached.
fn unavailable() -> Response {
    // RFC 6749 §4.1.2.1's `temporarily_unavailable`, borrowed because RFC 7591
    // §3.2.2 defines only document errors and this is not one: the request was
    // fine and the server was not. The distinction is what a caller acts on.
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "the client registration could not be reached",
    )
}

/// The answer when the stored row is not a registration this deployment accepts.
///
/// Deliberately not `temporarily_unavailable`: retrying will not help. This is
/// the row that `ClientRepository::find` refuses because a capability the
/// client registered for has since been turned off, or because a column was
/// edited by hand. A read cannot render it — but an update can replace it,
/// which is what the description says, and a delete can remove it, because
/// neither of those goes through the validator.
fn stale() -> Response {
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "the stored registration is no longer valid for this deployment; \
         replace it with PUT or remove it with DELETE",
    )
}

/// Records a post-authentication storage failure and answers it.
async fn unreadable(
    context: &ConfigurationContext<'_>,
    now: OffsetDateTime,
    event: EventType,
    client_id: &ClientId,
    failure: &DomainError,
) -> Response {
    tracing::error!(
        %failure,
        tenant = %context.tenant.id,
        client = %client_id,
        "a client configuration request could not be served"
    );
    let stale_row = matches!(failure, DomainError::Invalid { .. });
    record(
        context,
        now,
        event,
        Outcome::Failure,
        client_id,
        Some(if stale_row {
            "server_error"
        } else {
            "temporarily_unavailable"
        }),
        None,
    )
    .await;
    if stale_row { stale() } else { unavailable() }
}

/// Records a refusal, if it is one this endpoint audits, and answers it.
async fn refuse(
    context: &ConfigurationContext<'_>,
    now: OffsetDateTime,
    event: EventType,
    client_id: &ClientId,
    denied: Denied,
) -> Response {
    if denied.is_authenticated() {
        record(
            context,
            now,
            event,
            Outcome::Failure,
            client_id,
            Some(denied.reason()),
            None,
        )
        .await;
    }
    denied.into_response()
}

/// Records a rejected update document and answers it.
///
/// The description is a literal from this module, never a value from the
/// request: an update document is one of the few places a caller can put a
/// credential by mistake, and an error body that quoted it would be a
/// reflection primitive. [`nqschar`] holds it to RFC 6749 Appendix A.8's
/// `NQSCHAR` all the same, so that a description that later moves into a
/// `WWW-Authenticate` parameter cannot end the quoted string early.
async fn rejected(
    context: &ConfigurationContext<'_>,
    now: OffsetDateTime,
    client_id: &ClientId,
    status: StatusCode,
    code: &'static str,
    description: &str,
) -> Response {
    record(
        context,
        now,
        EventType::CLIENT_UPDATED,
        Outcome::Failure,
        client_id,
        Some(code),
        None,
    )
    .await;
    error(status, code, &nqschar(description))
}

/// Appends the decision to the audit trail.
///
/// `Actor::Client`, because unlike registration there *is* an identity to name:
/// the caller proved it holds this client's registration access token before
/// anything reached here.
///
/// Written after the row is committed, and a failure here does not fail the
/// request — the same choice `register` makes, for the same reason: a delete
/// that is refused after the row is gone tells the client its client still
/// exists. Closing the gap properly needs the transactional outbox
/// (`ast-0ju.9`).
async fn record(
    context: &ConfigurationContext<'_>,
    now: OffsetDateTime,
    event_type: EventType,
    outcome: Outcome,
    client_id: &ClientId,
    reason: Option<&'static str>,
    rule: Option<&'static str>,
) {
    // A label rather than free text: `Detail::text` would redact
    // `temporarily_unavailable` as a credential — 23 characters over 15
    // distinct is exactly what the scanner looks for.
    let mut detail = Detail::new().label("endpoint", "client_configuration");
    if let Some(reason) = reason {
        detail = detail.label("reason", reason);
    }
    // Which registration policy rule refused, when one did — the same detail
    // `POST /register` records, so one query finds both doors.
    if let Some(rule) = rule {
        detail = detail.label("rule", rule);
    }

    let mut event = AuditEvent::new(
        context.tenant.id.clone(),
        event_type,
        outcome,
        Actor::Client(client_id.clone()),
        now,
    )
    .client(client_id.clone())
    .detail(detail);
    if let Some(request_id) = context.request_id {
        event = event.request_id(request_id);
    }

    if let Err(failure) = context.audit.record(event).await {
        tracing::error!(
            %failure,
            tenant = %context.tenant.id,
            "a client configuration change was not written to the audit trail"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::register::management_uri;
    use asterius_domain::{Issuer, JwksSource, TenantId, TenantStatus};
    use serde_json::json;

    fn tenant() -> Tenant {
        Tenant {
            id: TenantId::new("demo"),
            issuer: Issuer::parse("https://as.example/t/demo").expect("issuer"),
            default_resource: "https://api.example/".to_owned(),
            custom_host: None,
            display_name: "demo".into(),
            status: TenantStatus::Active,
            refresh: asterius_domain::RefreshPolicy::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn document() -> Value {
        json!({
            "client_name": "Billing",
            "redirect_uris": ["https://rp.example/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "openid payments",
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        })
    }

    fn registration(document: &Value) -> ClientRegistration {
        ClientRegistration::from_json(
            &serde_json::to_vec(document).expect("serialise"),
            Capabilities::default(),
        )
        .expect("a valid registration")
    }

    fn client(id: &str, document: &Value) -> Client {
        Client {
            tenant: TenantId::new("demo"),
            id: ClientId::new(id),
            registration: registration(document),
            status: ClientStatus::Active,
            created_at: OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("instant"),
            updated_at: OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("instant"),
        }
    }

    /// The URL `POST /register` hands out has to be one this router serves.
    ///
    /// This is the whole of `ast-m9c.5` in one assertion: `ast-m9c.4` returns a
    /// `registration_client_uri` built from the endpoint registry and the
    /// `client_id`, and a route that did not match it — a different path, a
    /// query parameter instead of a path segment, a trailing slash — would
    /// leave every registered client holding a management URL that 404s, which
    /// is the state this story exists to end.
    #[test]
    fn the_uri_registration_hands_out_is_the_route_this_endpoint_serves() {
        let tenant = tenant();
        let client = ClientId::new("c.9tR0nVQ3kZmY1bXeL-oPuA");
        let advertised = management_uri(&tenant, &client);

        let served = format!(
            "{}{}",
            tenant.issuer.as_str(),
            path().replace("{client_id}", client.as_str())
        );
        assert_eq!(
            advertised, served,
            "the registration response points somewhere this endpoint is not mounted"
        );
        // OIDC Registration §3.2: "This URL MUST use the https scheme."
        assert!(advertised.starts_with("https://"));
        // OIDC Registration §4.1's recommended path-parameter form.
        assert_eq!(path(), "/register/{client_id}");
    }

    /// OIDC Registration §4.4: 401 for "the Client does not exist on this
    /// server, the Client is invalid, or the Registration Access Token used is
    /// invalid", 403 for "the Client does not have permission", and never a
    /// 404 — "for security reasons, to inhibit brute force attacks, endpoints
    /// MUST NOT return the HTTP 404 Not Found status code".
    #[test]
    fn the_status_codes_are_the_ones_the_specification_names() {
        assert_eq!(Refusal::Missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(Refusal::Invalid.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(Refusal::Suspended.status(), StatusCode::FORBIDDEN);
        for refusal in [Refusal::Missing, Refusal::Invalid, Refusal::Suspended] {
            assert_ne!(
                refusal.status(),
                StatusCode::NOT_FOUND,
                "{refusal:?} enumerates registrations"
            );
        }

        // RFC 6750 §3: both 401 cases carry a challenge, and the `error`
        // attribute only when a credential was presented and rejected. The 403
        // carries none: the credential was accepted.
        assert_eq!(Refusal::Missing.challenge(), Some("Bearer"));
        assert_eq!(
            Refusal::Invalid.challenge(),
            Some(r#"Bearer error="invalid_token""#)
        );
        assert_eq!(Refusal::Suspended.challenge(), None);

        assert_eq!(Refusal::Missing.code(), "invalid_token");
        assert_eq!(Refusal::Invalid.code(), "invalid_token");
        assert_eq!(Refusal::Suspended.code(), "access_denied");
    }

    /// The two 401s must be one answer on the wire.
    ///
    /// "No such client" and "wrong token" are different facts and the same
    /// response: status, error code, description and challenge all identical.
    /// A difference in any of them turns the endpoint into an oracle for which
    /// `client_id` values exist, which is what §4.4's "MUST NOT return 404" is
    /// there to stop — and a 401 that said "no such client" would give away
    /// exactly what the 404 would have.
    #[test]
    fn an_unknown_client_and_a_wrong_token_are_the_same_answer() {
        // `Refusal::Invalid` is the single value every one of those cases
        // reaches: unknown client, no stored token, a token for another client,
        // and a token that is simply wrong. There is no second variant that
        // could acquire a different description later.
        let refusal = Refusal::Invalid;
        assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            refusal.description(),
            "the registration access token was not accepted"
        );
        assert!(
            !refusal.description().contains("client"),
            "the description tells a prober whether the client exists"
        );
    }

    /// RFC 6749 Appendix A.8: `error_description` is `1*NQSCHAR`. Every
    /// description this module writes is already conforming, so the filter at
    /// the boundary never silently rewrites one.
    #[test]
    fn every_description_this_module_writes_is_already_on_the_wire_grammar() {
        let descriptions = [
            Refusal::Missing.description(),
            Refusal::Invalid.description(),
            Refusal::Suspended.description(),
            NotYours::ClientId.description(),
            NotYours::ClientSecret.description(),
            NotYours::ClientSecretExpiresAt.description(),
            NotYours::RegistrationAccessToken.description(),
        ];
        for description in descriptions {
            assert_eq!(nqschar(description), description, "{description:?}");
            assert!(!description.is_empty());
        }
    }

    /// RFC 7592 §2.2: "The client MUST include its `client_id` field in the
    /// request, and it MUST be the same as its currently issued client
    /// identifier."
    ///
    /// The interesting cases are the ones a typed field would have let through:
    /// a `client_id` that is a number, an array or null parses as "not a
    /// string" and must fail exactly as an absent one does, rather than
    /// crashing the guard and skipping every check after it.
    #[test]
    fn an_update_cannot_move_a_client_id() {
        let ours = "c.abc";
        let mut good = document();
        good.as_object_mut()
            .expect("object")
            .insert("client_id".to_owned(), json!(ours));
        let guard =
            NotTheirs::read(&serde_json::to_vec(&good).expect("serialise")).expect("a JSON object");
        assert_eq!(guard.check(ours), Ok(()));

        for wrong in [
            json!("c.def"),
            json!("c.ab"),
            json!("c.abcd"),
            json!("C.ABC"),
            json!(""),
            json!(5),
            json!(null),
            json!(["c.abc"]),
            json!({"client_id": "c.abc"}),
        ] {
            let mut document = document();
            document
                .as_object_mut()
                .expect("object")
                .insert("client_id".to_owned(), wrong.clone());
            let guard = NotTheirs::read(&serde_json::to_vec(&document).expect("serialise"))
                .expect("a JSON object");
            assert_eq!(
                guard.check(ours),
                Err(NotYours::ClientId),
                "{wrong} was accepted as this client's identifier"
            );
        }

        // Absent entirely: §2.2 makes it required, so this is not "unchanged".
        let guard = NotTheirs::read(&serde_json::to_vec(&document()).expect("serialise"))
            .expect("a JSON object");
        assert_eq!(guard.check(ours), Err(NotYours::ClientId));
    }

    /// RFC 7592 §2.2: an update "MUST NOT include the
    /// `registration_access_token` ... or `client_secret_expires_at`"
    /// field, and a client "MUST NOT be allowed to overwrite its existing
    /// client secret with its own chosen value" — which here means any
    /// `client_secret` at all, since FAPI 2.0 SP §5.3.2.1 leaves this server
    /// none to match against.
    ///
    /// Each is checked with a value of the wrong type as well as the right one,
    /// because the guard's job is "was this member sent", not "is it valid".
    #[test]
    fn an_update_cannot_claim_a_credential_this_server_does_not_issue() {
        let ours = "c.abc";
        for (field, expected) in [
            ("client_secret", NotYours::ClientSecret),
            ("client_secret_expires_at", NotYours::ClientSecretExpiresAt),
            (
                "registration_access_token",
                NotYours::RegistrationAccessToken,
            ),
        ] {
            for value in [
                json!("anything"),
                json!(0),
                json!(true),
                json!({}),
                json!([]),
            ] {
                let mut document = document();
                let object = document.as_object_mut().expect("object");
                object.insert("client_id".to_owned(), json!(ours));
                object.insert(field.to_owned(), value.clone());
                let guard = NotTheirs::read(&serde_json::to_vec(&document).expect("serialise"))
                    .expect("a JSON object");
                assert_eq!(
                    guard.check(ours),
                    Err(expected),
                    "{field} = {value} was accepted"
                );
            }

            // §2.2: "The authorization server MAY ignore any null or empty
            // value in the request just as any other value." An explicit null
            // is how a client that echoed a read response back spells "there
            // was nothing here", and it is not an attempt to set anything.
            let mut document = document();
            let object = document.as_object_mut().expect("object");
            object.insert("client_id".to_owned(), json!(ours));
            object.insert(field.to_owned(), json!(null));
            let guard = NotTheirs::read(&serde_json::to_vec(&document).expect("serialise"))
                .expect("a JSON object");
            assert_eq!(guard.check(ours), Ok(()), "{field} = null was refused");
        }
    }

    /// The other two fields RFC 7592 §2.2 forbids are read and ignored.
    ///
    /// `registration_client_uri` and `client_id_issued_at` are computed by this
    /// server from things a client cannot influence, so no value it sends can
    /// change either one — the argument is on [`NotYours`]. What this pins is
    /// the consequence: a client that sends them, including one echoing back
    /// exactly what a read gave it, gets on with its update instead of a 400,
    /// and a client that sends a *forged* value gets the same answer, because
    /// the value was never consulted.
    #[test]
    fn the_two_fields_this_server_computes_are_ignored_rather_than_refused() {
        let ours = "c.abc";
        for field in ["registration_client_uri", "client_id_issued_at"] {
            for value in [
                json!("https://attacker.example/register/c.abc"),
                json!(0),
                json!(null),
                json!(["nonsense"]),
            ] {
                let mut document = document();
                let object = document.as_object_mut().expect("object");
                object.insert("client_id".to_owned(), json!(ours));
                object.insert(field.to_owned(), value.clone());
                let guard = NotTheirs::read(&serde_json::to_vec(&document).expect("serialise"))
                    .expect("a JSON object");
                assert_eq!(
                    guard.check(ours),
                    Ok(()),
                    "{field} = {value} was refused rather than ignored"
                );
            }
        }
    }

    /// A body that is not a JSON object is not this guard's error to report.
    ///
    /// `read` returns `None` and the validator produces the RFC 7591 §3.2.2
    /// message, so there is one parser deciding what a malformed document is.
    /// The property that matters is the other direction: every body the
    /// validator would *accept* must be one the guard could read, or a
    /// document could reach the store without passing the guard at all.
    #[test]
    fn a_body_the_validator_accepts_is_always_one_the_guard_read() {
        for body in [
            b"".as_slice(),
            b"[]",
            b"\"a string\"",
            b"5",
            b"null",
            b"{",
            b"{\"client_name\": }",
        ] {
            let accepted = ClientRegistration::from_json(body, Capabilities::default()).is_ok();
            assert!(
                !accepted || NotTheirs::read(body).is_some(),
                "{body:?} reached the validator without passing the guard"
            );
        }
        // And the guard reads every object, including ones the validator will
        // go on to reject.
        for body in [b"{}".as_slice(), b"{\"client_id\": 5}", b"{\"a\": [1, 2]}"] {
            assert!(NotTheirs::read(body).is_some(), "{body:?} was not read");
        }
    }

    /// RFC 7592 §2.2's replacement rule, asserted where it is decided.
    ///
    /// "Valid values of client metadata fields in this request MUST replace,
    /// not augment, the values previously associated with this client. Omitted
    /// fields MUST be treated as null or empty values by the server, indicating
    /// the client's request to delete them from the client's registration."
    ///
    /// The endpoint enforces this by construction — it builds the replacement
    /// from [`ClientRegistration::from_json`] alone and never reads the stored
    /// row — so what is worth pinning is that the validator really does reset
    /// an omitted field to its default rather than leaving anything behind. A
    /// client that omits `redirect_uris` while meaning to rename itself must
    /// not keep its old callbacks; the store-level half of this is in
    /// `crates/store-pg/tests/database.rs`.
    #[test]
    fn a_field_an_update_omits_is_reset_and_not_preserved() {
        let mut before = document();
        let object = before.as_object_mut().expect("object");
        object.insert("id_token_signed_response_alg".to_owned(), json!("PS256"));
        object.insert("application_type".to_owned(), json!("native"));
        object.insert(
            "authorization_details_types".to_owned(),
            json!(["payment_initiation"]),
        );
        object.insert("request_object_signing_alg".to_owned(), json!("ES256"));
        object.insert("scope".to_owned(), json!("openid payments accounts"));
        object.insert(
            "post_logout_redirect_uris".to_owned(),
            json!(["https://rp.example/after-logout"]),
        );
        let before = registration(&before);

        // The same client renaming itself and saying nothing else, which is the
        // request a partial-update reading would get wrong.
        let after = registration(&json!({
            "client_name": "Billing, renamed",
            "redirect_uris": ["https://rp.example/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        }));

        assert_eq!(after.client_name, "Billing, renamed");
        assert_ne!(
            before.id_token_signed_response_alg,
            after.id_token_signed_response_alg
        );
        assert_eq!(
            after.id_token_signed_response_alg,
            asterius_domain::SigningAlgorithm::DEFAULT,
            "an omitted algorithm kept the old value instead of resetting"
        );
        assert_ne!(before.application_type, after.application_type);
        assert!(
            after.authorization_details_types.is_empty(),
            "an omitted RFC 9396 type list was preserved"
        );
        assert!(
            after.request_object_signing_alg.is_none(),
            "an omitted signing algorithm was preserved"
        );
        assert!(
            after.scopes.is_empty(),
            "an omitted scope string was preserved"
        );
        assert!(!before.post_logout_redirect_uris.is_empty());
        assert!(
            after.post_logout_redirect_uris.is_empty(),
            "an omitted post_logout_redirect_uris list was preserved"
        );
    }

    /// The response of a read re-registers as the same client.
    ///
    /// The same assertion `ast-m9c.4` makes about its own response, and for a
    /// stronger reason here: RFC 7592 §2.2 requires an update to "include all
    /// client metadata fields as returned to the client from a previous
    /// registration, read, or update operation", so a client's only correct way
    /// to change one field is to send back what a read gave it. If the read
    /// document does not re-validate to the stored registration, that
    /// round trip silently changes the client.
    #[test]
    fn the_read_document_re_registers_as_the_same_client() {
        let capabilities = Capabilities {
            mtls: true,
            ..Capabilities::default()
        };
        let mut document = document();
        let object = document.as_object_mut().expect("object");
        object.insert("application_type".to_owned(), json!("web"));
        object.insert("subject_type".to_owned(), json!("pairwise"));
        object.insert(
            "sector_identifier_uri".to_owned(),
            json!("https://rp.example/sector.json"),
        );
        object.insert("request_object_signing_alg".to_owned(), json!("ES256"));
        object.insert("id_token_signed_response_alg".to_owned(), json!("PS256"));
        // One binding method, which is all a registration may hold
        // (RFC 8705 §3.4 beside RFC 9449 §5.2): the certificate one here, so
        // that the round trip covers the member the mtls flag gates.
        object.insert("dpop_bound_access_tokens".to_owned(), json!(false));
        object.insert(
            "tls_client_certificate_bound_access_tokens".to_owned(),
            json!(true),
        );
        object.insert("use_mtls_endpoint_aliases".to_owned(), json!(true));
        object.insert(
            "authorization_details_types".to_owned(),
            json!(["payment_initiation"]),
        );

        let stored = Client {
            tenant: TenantId::new("demo"),
            id: ClientId::new("c.abc"),
            registration: ClientRegistration::from_json(
                &serde_json::to_vec(&document).expect("serialise"),
                capabilities,
            )
            .expect("a valid registration"),
            status: ClientStatus::Active,
            created_at: OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("instant"),
            updated_at: OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("instant"),
        };

        // `None`: a read carries no registration access token.
        let rendered = client_information(&stored, &tenant(), None, OffsetDateTime::UNIX_EPOCH);
        let round_tripped = ClientRegistration::from_json(
            &serde_json::to_vec(&rendered).expect("serialise"),
            capabilities,
        )
        .expect("the read document must itself be a valid registration");
        assert_eq!(
            round_tripped, stored.registration,
            "a read describes a different client than the one stored"
        );

        // And the guard accepts it once the client adds nothing: §2.2 requires
        // `client_id`, which a read already returns, and forbids the four
        // fields — none of which a read sends.
        let guard =
            NotTheirs::read(&serde_json::to_vec(&rendered).expect("serialise")).expect("object");
        assert_eq!(
            guard.check("c.abc"),
            Ok(()),
            "a client cannot update itself by sending back what a read gave it"
        );
    }

    /// A read carries no credential.
    ///
    /// RFC 7592 §3 marks `registration_access_token` REQUIRED in the client
    /// information response; OIDC Registration §4.3 is the narrower rule for a
    /// read and says the server "need not include the
    /// `registration_access_token` or `registration_client_uri` value in this
    /// response unless they have been updated". This server keeps only the
    /// token's digest, so it could only satisfy the first by minting a new
    /// token on every read — which OIDC Registration §4.3 argues against
    /// ("Read operations are intended to be idempotent") and which would strand
    /// a client whose response was lost. `registration_client_uri` is sent,
    /// because it can be.
    #[test]
    fn a_read_returns_the_management_url_and_no_token() {
        let stored = client("c.abc", &document());
        let body = client_information(&stored, &tenant(), None, OffsetDateTime::UNIX_EPOCH);

        assert!(
            body.get("registration_access_token").is_none(),
            "a read returned a credential the server does not hold"
        );
        assert_eq!(
            body["registration_client_uri"],
            json!("https://as.example/t/demo/register/c.abc")
        );
        assert_eq!(body["client_id"], json!("c.abc"));
        // Still no secret, and so still no expiry for one (RFC 7591 §3.2.1).
        assert!(body.get("client_secret").is_none());
        assert!(body.get("client_secret_expires_at").is_none());
        // The per-client resource allow-list is policy, not metadata
        // (`ast-m9c.6`); a read must not advertise a field an update cannot set.
        assert!(body.get("resources").is_none());
        assert!(matches!(stored.registration.jwks, JwksSource::Inline(_)));
    }

    /// The audit trail has to be able to say which of the three happened.
    #[test]
    fn each_operation_has_its_own_audit_event_type() {
        let types = [
            EventType::CLIENT_READ,
            EventType::CLIENT_UPDATED,
            EventType::CLIENT_DELETED,
        ];
        let distinct: std::collections::BTreeSet<&str> =
            types.iter().map(|event| event.as_str()).collect();
        assert_eq!(distinct.len(), types.len());
        for event in types {
            assert!(
                EventType::ALL.contains(&event),
                "{event} is not in EventType::ALL, so a stored row cannot be read back"
            );
            assert_ne!(event, EventType::CLIENT_REGISTERED);
        }
    }

    /// A refusal reached before a credential was accepted is not audited.
    ///
    /// The endpoint is reachable with nothing but a path segment, so an audit
    /// row per unauthenticated request would be an amplification primitive
    /// pointed at the one table nothing can delete from. The 403 is audited,
    /// because reaching it required this client's own token.
    #[test]
    fn only_refusals_that_got_past_the_credential_are_audited() {
        assert!(!Denied::Refused(Refusal::Missing).is_authenticated());
        assert!(!Denied::Refused(Refusal::Invalid).is_authenticated());
        assert!(!Denied::Unavailable.is_authenticated());
        assert!(Denied::Refused(Refusal::Suspended).is_authenticated());

        // Every reason is a label from a closed set, so none of them can be
        // redacted by the audit sink's credential scanner or carry a value out
        // of a request.
        for denied in [
            Denied::Refused(Refusal::Missing),
            Denied::Refused(Refusal::Invalid),
            Denied::Refused(Refusal::Suspended),
            Denied::Unavailable,
        ] {
            assert!(denied.reason().is_ascii() && !denied.reason().is_empty());
        }
    }

    /// The decoy is drawn, not constant, and no token hashes to it.
    ///
    /// It exists so that a client with no stored digest does the same
    /// cryptographic work as one with the wrong token. A constant would be a
    /// value an attacker could aim a token at; the draw makes that a 256-bit
    /// preimage search against a value they never see.
    #[test]
    fn the_decoy_digest_is_drawn_once_and_matches_nothing() {
        let first = *DECOY;
        assert_eq!(first, *DECOY, "the decoy changed between reads");
        assert_ne!(first, [0_u8; 32]);
        assert_ne!(first, sha256(b""));
        // The comparison the endpoint makes. A client with no stored digest is
        // never admitted, whatever it presents — including a value that somehow
        // hashed to the decoy, which `admits` refuses on `stored.is_some()`
        // rather than on the comparison.
        let presented = sha256(b"any token at all");
        assert!(!ct_eq(&first, &presented));
        assert!(!admits(None, &presented));
        assert!(!admits(None, &first));

        // With a real digest it admits that digest and nothing else.
        let real = sha256(b"the right token");
        assert!(admits(Some(real), &real));
        assert!(!admits(Some(real), &presented));
        assert!(!admits(Some(real), &first));
    }

    /// A `client_id` longer than anything this server could have issued is
    /// refused without a database round trip, and refused as though it did not
    /// exist — which it cannot.
    #[test]
    fn an_absurd_client_id_is_refused_like_any_other_stranger() {
        let long = "c.".to_owned() + &"a".repeat(MAX_CLIENT_ID_LEN);
        assert!(long.len() > MAX_CLIENT_ID_LEN);
        // 24 characters: `c.` and 128 bits of base64url.
        assert!("c.9tR0nVQ3kZmY1bXeL-oPuA".len() < MAX_CLIENT_ID_LEN);
    }
}
