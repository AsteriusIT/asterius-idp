//! Passkey enrolment: the page, the options, and the finished ceremony.
//!
//! Three routes, and the whole of the plumbing `asterius-webauthn` deliberately
//! left to a caller (`ast-2vk.15`):
//!
//! * `GET /passkeys` renders the one scripted page in this tree and opens an
//!   enrolment against the session behind the cookie.
//! * `POST /passkeys/options` draws a challenge and answers with
//!   `PublicKeyCredentialCreationOptions`, base64url where the script decodes.
//! * `POST /passkeys/finish` verifies what came back and writes the credential.
//!
//! # Why this is not an interaction
//!
//! Enrolment has no client, no `redirect_uri` and no consent: a signed-in user
//! adds a credential to their own account. So it hangs off the **session**
//! rather than off `auth_requests`, and the session cookie —  written by
//! `interaction::set_session_cookie` and, until now, read by nothing — is what
//! says who is asking.
//!
//! # The challenge
//!
//! Thirty-two bytes, single-use, five minutes, and bound to the session by a
//! foreign key rather than by a convention. [`PasskeyRepository::spend_challenge`]
//! is one statement that reads and clears, so two finishes racing on one
//! challenge cannot both get bytes; signing out deletes the row by cascade; and
//! rendering the page again replaces whatever was outstanding, so the tab a
//! user is looking at is the one that works.
//!
//! # One refusal
//!
//! Every way a ceremony can fail — a challenge that expired, an origin that is
//! not ours, an RP ID that is not ours, a missing UV bit, a credential id
//! already registered — produces the same status and the same body. §7.1
//! defines no error vocabulary, the distinctions are ones an attacker would
//! like drawn and a user cannot act on, and "this credential id is already
//! registered" in particular would answer a question about somebody else's
//! account. The real reason goes to the log with a correlation id.

use crate::http::interaction::record_registered_passkey;
use asterius_domain::entities::session::{COOKIE_NAME, SessionId};
use asterius_domain::{
    AuditSink, ENROLMENT_TTL, NewPasskey, OpaqueToken, PasskeyRepository, SessionRepository,
    Tenant, UserDirectory, UserId, UserStatus, sha256, sha256_hex,
};
use asterius_web::interaction::{self, CsrfToken};
use asterius_web::pages::{self, ErrorPage, PasskeyPage, nonce_attribute};
use asterius_web::{Document, csp::Nonce};
use asterius_webauthn::cose::CoseAlgorithm;
use asterius_webauthn::{
    CHALLENGE_BYTES, Challenge, RelyingParty, RelyingPartyError, UserVerification, registration,
};
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

/// Where the enrolment page lives.
pub const PAGE_PATH: &str = "/passkeys";

/// Where the script asks for creation options.
pub const OPTIONS_PATH: &str = "/passkeys/options";

/// Where the script posts the attestation it got back.
pub const FINISH_PATH: &str = "/passkeys/finish";

/// The largest body either JSON endpoint will look at.
///
/// An attestation object with a long credential id and an RSA key is a few
/// kilobytes; sixty-four leaves room for an authenticator nobody has met yet
/// and still refuses to parse a megabyte somebody posted for fun. The global
/// body limit is much larger because a client registration document may be.
const MAX_BODY: usize = 64 * 1024;

/// What the passkey handlers need.
///
/// Five things, against [`crate::http::interaction::InteractionContext`]'s
/// eleven, and the difference is the point: enrolment reaches no client, no
/// grant, no code and no subject resolver, so it is not given them.
pub struct PasskeyContext<'a> {
    /// The tenant the request arrived at.
    pub tenant: &'a Tenant,
    /// Outstanding enrolments and the credentials they produce.
    pub passkeys: &'a dyn PasskeyRepository,
    /// Resolves the session cookie.
    pub sessions: &'a dyn SessionRepository,
    /// Names the person enrolling.
    pub users: &'a dyn UserDirectory,
    /// The CSP nonce the document middleware drew for this response.
    pub nonce: &'a Nonce,
    /// Where a created credential is recorded.
    pub audit: &'a dyn AuditSink,
}

impl std::fmt::Debug for PasskeyContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyContext").finish_non_exhaustive()
    }
}

/// Describes this server to an authenticator (§5.4.2).
///
/// # The RP ID is the issuer's host, and the origin list is not guesswork
///
/// A credential is scoped to a *domain*, and an authenticator will offer it at
/// any origin the RP ID is a registrable suffix of. This server's RP ID is the
/// issuer's host with the port removed — a port is not part of an RP ID — so a
/// path-based tenant and the deployment it lives in share one RP ID, which is
/// correct: they are one origin.
///
/// A `custom_host` is the ambiguous case the bead names. It is added to the
/// origin list **only** when it is the RP ID or a subdomain of it, because that
/// is exactly when a browser would allow the credential there. A vanity host on
/// an unrelated domain cannot use a credential scoped to the issuer's host, and
/// listing it would not make it work — it would only accept a ceremony from an
/// origin this server never scoped anything to. Giving such a tenant its own RP
/// ID is a per-tenant policy decision with a migration behind it (`ast-2vk.3`),
/// not something to infer from a column.
///
/// # Errors
///
/// [`RelyingPartyError`] if the issuer's authority is not a bare domain, which
/// would mean a tenant that cannot run a WebAuthn ceremony at all.
pub fn relying_party(tenant: &Tenant) -> Result<RelyingParty, RelyingPartyError> {
    let authority = tenant.issuer.authority();
    // `authority` is `host` or `host:port`; an RP ID is a domain and nothing
    // else, so the port goes. An IPv6 literal has colons of its own and is not
    // a domain — `RelyingParty::new` refuses whatever is left, which is the
    // answer we want.
    let id = authority.split(':').next().unwrap_or(authority);

    let mut origins = vec![format!("https://{authority}")];
    if let Some(host) = tenant.custom_host.as_deref()
        && (host == id || host.ends_with(&format!(".{id}")))
    {
        let origin = format!("https://{host}");
        if !origins.contains(&origin) {
            origins.push(origin);
        }
    }

    // `uv=required` is this server's policy and the crate's default: a passkey
    // is treated as sufficient on its own, so one that proved only presence is
    // not one of them. Per-tenant relaxation is `ast-2vk.3`.
    RelyingParty::new(id, origins, UserVerification::Required)
}

/// `GET /passkeys` — the enrolment page.
///
/// Opens (or reopens) the enrolment: one fresh synchroniser token per
/// rendering, stored as a digest, with any outstanding challenge cleared.
pub async fn page(
    context: PasskeyContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Response {
    let Some(who) = signed_in(&context, headers, now).await else {
        return unauthenticated(&context);
    };

    let token = CsrfToken::generate();
    if let Err(error) = context
        .passkeys
        .open_enrolment(&who.session_digest, &digest_of(&token), now + ENROLMENT_TTL)
        .await
    {
        tracing::error!(%error, tenant = %context.tenant.id, "cannot open a passkey enrolment");
        return error_page(&context, StatusCode::SERVICE_UNAVAILABLE);
    }

    let document = Document::render(context.nonce, |nonce| {
        pages::render(&PasskeyPage {
            locale: "en",
            tenant_name: &context.tenant.display_name,
            username: &who.username,
            options_action: OPTIONS_PATH,
            finish_action: FINISH_PATH,
            // Both are this server's own path. Nothing from the query string
            // reaches either: a "where to go next" parameter on a page reached
            // with a session cookie is an open redirect with extra steps, and
            // the account page that will own this destination is `ast-2vk.3`.
            next_href: PAGE_PATH,
            password_href: PAGE_PATH,
            csrf: token.expose(),
            message: None,
            nonce_attribute: nonce_attribute(nonce),
        })
    });
    (StatusCode::OK, no_store(), document).into_response()
}

/// `POST /passkeys/options` — draw a challenge and describe the credential.
pub async fn options(
    context: PasskeyContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let Some(who) = signed_in(&context, headers, now).await else {
        return unauthenticated_json();
    };
    let Some(request) = parse::<CsrfOnly>(body) else {
        return refused("the options request is not the shape this page posts");
    };
    if checked_csrf(&context, &who, &request.csrf, now)
        .await
        .is_none()
    {
        return refused("the options request carried no usable synchroniser token");
    }

    let relying_party = match relying_party(context.tenant) {
        Ok(relying_party) => relying_party,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "this tenant has no usable RP ID");
            return refused("no relying party could be described for this tenant");
        }
    };

    let challenge = draw_challenge();
    match context
        .passkeys
        .issue_challenge(
            &who.session_digest,
            challenge.as_bytes(),
            now + ENROLMENT_TTL,
            now,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return refused("the enrolment expired before options were asked for"),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot store a challenge");
            return refused("the challenge could not be stored");
        }
    }

    // A courtesy, not a control: it stops an authenticator silently making a
    // second credential for an account it already holds one for. The unique
    // index is what actually refuses a duplicate.
    let known = context
        .passkeys
        .credential_ids(&who.user)
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "cannot list existing credentials; excludeCredentials omitted");
            Vec::new()
        });

    let document = creation_options(&relying_party, &context, &who, &challenge, &known);
    (StatusCode::OK, no_store(), axum::Json(document)).into_response()
}

/// `POST /passkeys/finish` — verify the ceremony and store the credential.
pub async fn finish(
    context: PasskeyContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    let Some(who) = signed_in(&context, headers, now).await else {
        return unauthenticated_json();
    };
    let Some(request) = parse::<FinishRequest>(body) else {
        return refused("the finish request is not the shape this page posts");
    };
    if checked_csrf(&context, &who, &request.csrf, now)
        .await
        .is_none()
    {
        return refused("the finish request carried no usable synchroniser token");
    }
    // §5.1: the only credential type this ceremony produces.
    if request.kind != "public-key" {
        return refused("the browser returned a credential of another type");
    }

    // Before anything is parsed, because a challenge that is only compared is
    // not consumed: this is the statement that makes the ceremony single-use.
    let spent = match context
        .passkeys
        .spend_challenge(&who.session_digest, now)
        .await
    {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return refused("no challenge was outstanding for this session"),
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot spend a challenge");
            return refused("the challenge could not be spent");
        }
    };
    let Ok(challenge) = Challenge::new(spent) else {
        return refused("the stored challenge was shorter than the minimum");
    };

    let (Some(client_data), Some(attestation)) = (
        decode(&request.client_data_json),
        decode(&request.attestation_object),
    ) else {
        return refused("the ceremony's halves are not base64url");
    };

    let relying_party = match relying_party(context.tenant) {
        Ok(relying_party) => relying_party,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "this tenant has no usable RP ID");
            return refused("no relying party could be described for this tenant");
        }
    };

    // §7.1 steps 5-21. Origin, RP ID hash, the UV bit and the algorithm are all
    // decided in here, and every one of them fails into the same refusal.
    let verified = match registration::verify(
        &relying_party,
        &challenge,
        &client_data,
        &attestation,
        &CoseAlgorithm::ALL,
    ) {
        Ok(verified) => verified,
        Err(error) => {
            tracing::info!(
                %error,
                tenant = %context.tenant.id,
                "a passkey registration was refused"
            );
            return refused("the registration ceremony did not verify");
        }
    };

    let credential = &verified.credential;
    let passkey = NewPasskey {
        user: who.user,
        // The credential id from the attested credential data, which is the
        // one the ceremony verified. `id` and `rawId` are what the browser
        // said, and nothing checked them.
        credential_id: credential.credential_id.clone(),
        public_key: credential.public_key.encoded().to_vec(),
        sign_count: credential.sign_count,
        // All-zeroes means the authenticator declined to identify its model,
        // which is the common and expected answer under attestation `none`.
        aaguid: (credential.aaguid != [0u8; 16]).then(|| uuid::Uuid::from_bytes(credential.aaguid)),
        backup_eligible: credential.backup_eligible,
        backup_state: credential.backup_state,
        user_verified: credential.user_verified,
        rp_id: relying_party.id().to_owned(),
        label: None,
    };

    let stored = match context.passkeys.register(&passkey).await {
        Ok(stored) => stored,
        Err(error) => {
            // A conflict here is the tenant-wide unique index refusing a
            // credential id that is already registered — possibly to somebody
            // else, which is precisely why the answer is the generic one.
            tracing::info!(
                %error,
                tenant = %context.tenant.id,
                origin = %verified.origin,
                "a verified passkey was not stored"
            );
            return refused("the credential could not be stored");
        }
    };

    record_registered_passkey(
        context.audit,
        &context.tenant.id,
        &passkey.user,
        &stored,
        now,
    )
    .await;
    tracing::info!(tenant = %context.tenant.id, origin = %verified.origin, "a passkey was registered");

    // No body worth reading: the script navigates on success and there is
    // nothing here it needs. An empty 204 is also nothing to leak.
    (StatusCode::NO_CONTENT, no_store()).into_response()
}

/// Who the session cookie says is asking.
struct SignedIn {
    /// The session's lookup digest — what the enrolment row is keyed by.
    session_digest: String,
    /// Whose account it is.
    user: UserId,
    /// What to call them on screen.
    username: String,
}

/// Resolves the session cookie, or `None` when there is nobody to enrol for.
///
/// Four ways to be nobody, all one answer: no cookie, no row, a session that is
/// expired, idle or revoked, and an account that may not authenticate. A
/// disabled account must not be able to add a credential it would then be
/// unable to use — and, more to the point, an account disabled *because*
/// something went wrong must not be able to add one at all.
async fn signed_in(
    context: &PasskeyContext<'_>,
    headers: &HeaderMap,
    now: OffsetDateTime,
) -> Option<SignedIn> {
    let cookies = cookies(headers);
    let presented =
        SessionId::from_presented(interaction::cookie_value(&cookies, COOKIE_NAME)?.to_owned());
    let digest = presented.digest();

    let session = match context.sessions.find(&digest).await {
        Ok(Some(session)) if session.status(now).is_usable() => session,
        Ok(_) => return None,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read a session");
            return None;
        }
    };

    let user = UserId::new(session.user);
    let account = match context.users.by_id(user).await {
        Ok(Some(account)) if account.status == UserStatus::Active => account,
        Ok(_) => return None,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read an account");
            return None;
        }
    };

    Some(SignedIn {
        session_digest: digest,
        user,
        username: account.username,
    })
}

/// Checks the synchroniser token against the enrolment this session opened.
///
/// The ceremony is two `fetch` calls rather than two form submissions, so the
/// token cannot ride on a form — it is in the JSON body, and this is where it
/// is compared. The stored form is a digest, and the comparison is the same
/// constant-time one every other token in this codebase gets.
async fn checked_csrf(
    context: &PasskeyContext<'_>,
    who: &SignedIn,
    presented: &str,
    now: OffsetDateTime,
) -> Option<()> {
    let enrolment = match context.passkeys.enrolment(&who.session_digest, now).await {
        Ok(Some(enrolment)) => enrolment,
        Ok(None) => return None,
        Err(error) => {
            tracing::error!(%error, tenant = %context.tenant.id, "cannot read an enrolment");
            return None;
        }
    };
    let presented = digest_of(&CsrfToken::from_presented(presented.to_owned()));
    asterius_domain::ct_eq(presented.as_bytes(), enrolment.csrf_digest.as_bytes()).then_some(())
}

/// Every `Cookie` header the request carries, joined into one list.
///
/// Not `HeaderMap::get`. HTTP/2 permits a cookie list to be split across
/// several `cookie` fields — RFC 9113 §8.2.3 says a user agent MAY do it and
/// that a server MUST join them before parsing — and Chromium does, so `get`
/// returns whichever cookie happened to be sent first. That is a bug with no
/// symptom until two `__Host-` cookies exist at once, which is exactly this
/// page: the interaction cookie arrives first and the session cookie is
/// silently missed, so a signed-in user is told they are not signed in.
fn cookies(headers: &HeaderMap) -> String {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ")
}

/// The at-rest form of a synchroniser token.
fn digest_of(token: &CsrfToken) -> String {
    sha256_hex(token.expose().as_bytes())
}

/// Draws a registration challenge.
///
/// [`CHALLENGE_BYTES`] of it, from the generator everything else in this
/// codebase draws from. `OpaqueToken` is text, and a challenge is bytes, so it
/// is hashed rather than reinterpreted: SHA-256 of a freshly drawn 256-bit
/// token is 32 bytes carrying the entropy the token had, and the alternative —
/// using the token's ASCII — would be 43 bytes of a 64-symbol alphabet
/// pretending to be uniform.
fn draw_challenge() -> Challenge {
    let drawn = OpaqueToken::generate_bits::<256>();
    let bytes = sha256(drawn.expose().as_bytes());
    debug_assert_eq!(bytes.len(), CHALLENGE_BYTES);
    Challenge::new(bytes.to_vec())
        .expect("32 bytes is above the 16-byte floor Challenge::new enforces")
}

/// `PublicKeyCredentialCreationOptions` (§5.4), base64url where the script
/// decodes.
///
/// `attestation: "none"` because that is the only format this server verifies
/// and ADR-0007 says why: asking for one it would then refuse is worse than not
/// asking. `residentKey: "required"` because a passkey that is not discoverable
/// is not a passkey — it cannot start a sign-in of its own.
fn creation_options(
    relying_party: &RelyingParty,
    context: &PasskeyContext<'_>,
    who: &SignedIn,
    challenge: &Challenge,
    known: &[Vec<u8>],
) -> Value {
    let parameters: Vec<Value> = CoseAlgorithm::ALL
        .iter()
        .map(|algorithm| json!({ "type": "public-key", "alg": algorithm.value() }))
        .collect();
    let exclude: Vec<Value> = known
        .iter()
        .map(|id| json!({ "type": "public-key", "id": base64_url(id) }))
        .collect();
    let user_verification = match relying_party.user_verification() {
        UserVerification::Required => "required",
        UserVerification::Discouraged => "discouraged",
    };

    json!({
        "rp": { "id": relying_party.id(), "name": context.tenant.display_name },
        "user": {
            // §5.4.3: an opaque byte sequence, never anything personal. The
            // account id is already the opaque handle this server uses.
            "id": base64_url(who.user.as_bytes()),
            "name": who.username,
            "displayName": who.username,
        },
        "challenge": base64_url(challenge.as_bytes()),
        "pubKeyCredParams": parameters,
        "excludeCredentials": exclude,
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": true,
            "userVerification": user_verification,
        },
        // The same window the row has, in the milliseconds §5.4 asks for. A
        // longer client-side timeout than server-side lifetime would end in a
        // ceremony the user completed and the server refused.
        "timeout": ENROLMENT_TTL.whole_milliseconds(),
        "attestation": "none",
    })
}

/// `{"csrf": "…"}`, which is all the options request carries.
#[derive(Debug, Deserialize)]
struct CsrfOnly {
    csrf: String,
}

/// What the script posts once the authenticator has answered.
///
/// `id` is deliberately absent: it is the base64url spelling of `rawId`, and
/// neither is trusted. The credential id that gets stored comes out of the
/// attested credential data, which is inside the bytes the ceremony verified.
#[derive(Debug, Deserialize)]
struct FinishRequest {
    csrf: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
}

/// Reads a JSON body, refusing anything oversized or unparseable.
fn parse<T: for<'de> Deserialize<'de>>(body: &Bytes) -> Option<T> {
    if body.len() > MAX_BODY {
        return None;
    }
    serde_json::from_slice(body).ok()
}

/// Unpadded base64url, which is what the script's `decode` expects and what
/// §5.8.1 uses on the way back.
fn base64_url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Reads unpadded base64url, accepting the padded spelling too.
///
/// The script sends unpadded, but the value has crossed a browser and a
/// `fetch`, and refusing padding would be a parsing difference an attacker
/// could measure for nothing gained.
fn decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .ok()
}

/// `Cache-Control: no-store`, on every response here.
///
/// The page carries a synchroniser token, the options carry a challenge, and
/// neither is something a shared cache should keep.
fn no_store() -> [(header::HeaderName, &'static str); 1] {
    [(header::CACHE_CONTROL, "no-store")]
}

/// The one answer every failed ceremony gets.
///
/// `reason` reaches the log and nothing else. 400 rather than 401/403/409: a
/// status is a distinction too, and the three that would be natural here are
/// exactly the three an attacker would like told apart.
fn refused(reason: &str) -> Response {
    let correlation = interaction::correlation_id();
    tracing::info!(correlation_id = %correlation, reason, "a passkey ceremony was refused");
    (
        StatusCode::BAD_REQUEST,
        no_store(),
        axum::Json(json!({
            "error": "registration_failed",
            "correlation_id": correlation,
        })),
    )
        .into_response()
}

/// No session, on a JSON endpoint.
fn unauthenticated_json() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        no_store(),
        axum::Json(json!({ "error": "not_signed_in" })),
    )
        .into_response()
}

/// No session, on the page.
fn unauthenticated(context: &PasskeyContext<'_>) -> Response {
    error_page(context, StatusCode::UNAUTHORIZED)
}

/// The generic error page, with a correlation id and nothing else.
fn error_page(context: &PasskeyContext<'_>, status: StatusCode) -> Response {
    let correlation = interaction::correlation_id();
    tracing::info!(
        correlation_id = %correlation,
        tenant = %context.tenant.id,
        "passkey error page shown"
    );
    let document = Document::render(context.nonce, |nonce| {
        pages::render(&ErrorPage {
            locale: "en",
            tenant_name: &context.tenant.display_name,
            message: "Something went wrong, and this request cannot continue.",
            correlation_id: &correlation,
            nonce_attribute: nonce_attribute(nonce),
        })
    });
    (status, no_store(), document).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{Issuer, TenantId, TenantStatus};
    use axum::http::HeaderValue;

    fn tenant(issuer: &str, custom_host: Option<&str>) -> Tenant {
        Tenant {
            id: TenantId::new("demo"),
            issuer: Issuer::parse(issuer).expect("a valid issuer"),
            default_resource: "https://api.example.com".to_owned(),
            custom_host: custom_host.map(ToOwned::to_owned),
            display_name: "Demo".to_owned(),
            status: TenantStatus::Active,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn the_rp_id_is_the_issuers_host_without_its_path() {
        // Arrange
        let tenant = tenant("https://id.example.com/t/demo", None);

        // Act
        let relying_party = relying_party(&tenant).expect("a relying party");

        // Assert
        assert_eq!(relying_party.id(), "id.example.com");
    }

    /// An RP ID is a domain: a port belongs to an origin and not to it.
    #[test]
    fn a_port_stays_out_of_the_rp_id_and_stays_in_the_origin() {
        // Arrange
        let tenant = tenant("https://localhost:9443/t/demo", None);

        // Act
        let relying_party = relying_party(&tenant).expect("a relying party");

        // Assert
        assert_eq!(relying_party.id(), "localhost");
        assert_eq!(relying_party.origins(), ["https://localhost:9443"]);
    }

    /// The bead's ambiguity, resolved: a vanity host the RP ID actually covers
    /// is an origin a browser would allow, so it is listed.
    #[test]
    fn a_custom_host_under_the_rp_id_becomes_a_second_origin() {
        // Arrange
        let tenant = tenant("https://example.com", Some("login.example.com"));

        // Act
        let relying_party = relying_party(&tenant).expect("a relying party");

        // Assert
        assert_eq!(
            relying_party.origins(),
            ["https://example.com", "https://login.example.com"]
        );
    }

    /// ...and one it does not cover is *not* listed: accepting a ceremony from
    /// an origin no credential of ours is scoped to would widen the check for
    /// nothing.
    #[test]
    fn a_custom_host_on_another_domain_is_not_an_origin() {
        // Arrange
        let tenant = tenant("https://id.example.com", Some("login.elsewhere.test"));

        // Act
        let relying_party = relying_party(&tenant).expect("a relying party");

        // Assert
        assert_eq!(relying_party.origins(), ["https://id.example.com"]);
    }

    /// A near-miss that a naive suffix check would let through.
    #[test]
    fn a_custom_host_that_merely_ends_with_the_rp_id_is_refused() {
        // Arrange
        let tenant = tenant("https://example.com", Some("evilexample.com"));

        // Act
        let relying_party = relying_party(&tenant).expect("a relying party");

        // Assert
        assert_eq!(relying_party.origins(), ["https://example.com"]);
    }

    #[test]
    fn user_verification_is_required() {
        // Arrange
        let tenant = tenant("https://id.example.com", None);

        // Act
        let relying_party = relying_party(&tenant).expect("a relying party");

        // Assert
        assert_eq!(
            relying_party.user_verification(),
            UserVerification::Required
        );
    }

    #[test]
    fn a_drawn_challenge_is_the_size_this_server_issues() {
        // Arrange, Act
        let challenge = draw_challenge();

        // Assert
        assert_eq!(challenge.as_bytes().len(), CHALLENGE_BYTES);
    }

    /// Two challenges in a row must not be the same, or the store would be
    /// spending one value forever.
    #[test]
    fn challenges_are_drawn_fresh_each_time() {
        // Arrange, Act
        let first = draw_challenge();
        let second = draw_challenge();

        // Assert
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn base64url_round_trips_without_padding() {
        // Arrange
        let bytes = [0u8, 1, 2, 250, 251, 252, 253];

        // Act
        let encoded = base64_url(&bytes);

        // Assert
        assert!(!encoded.contains('='), "{encoded}");
        assert_eq!(decode(&encoded).as_deref(), Some(bytes.as_slice()));
    }

    /// A padded spelling is the same bytes, because the value crossed a
    /// browser and refusing padding would buy nothing.
    #[test]
    fn a_padded_spelling_decodes_to_the_same_bytes() {
        // Arrange
        let bytes = [7u8, 8];

        // Act
        let padded = format!("{}==", base64_url(&bytes));

        // Assert
        assert_eq!(decode(&padded).as_deref(), Some(bytes.as_slice()));
    }

    #[test]
    fn a_body_over_the_ceiling_is_not_parsed() {
        // Arrange
        let body = Bytes::from(vec![b'x'; MAX_BODY + 1]);

        // Act
        let parsed: Option<CsrfOnly> = parse(&body);

        // Assert
        assert!(parsed.is_none());
    }

    /// The contract the page's script was written against (`ast-ndk.7`).
    #[test]
    fn the_finish_request_reads_the_field_names_the_script_sends() {
        // Arrange
        let body = Bytes::from_static(
            br#"{"csrf":"t","id":"ignored","type":"public-key","rawId":"AQ",
                 "clientDataJSON":"e30","attestationObject":"oA"}"#,
        );

        // Act
        let parsed: FinishRequest = parse(&body).expect("the script's body shape");

        // Assert
        assert_eq!(parsed.csrf, "t");
        assert_eq!(parsed.kind, "public-key");
        assert_eq!(parsed.client_data_json, "e30");
        assert_eq!(parsed.attestation_object, "oA");
    }

    /// Every refusal is the same refusal: same status, same body but for the
    /// correlation id an operator needs.
    #[test]
    fn every_refusal_is_indistinguishable_from_every_other() {
        // Arrange
        let reasons = [
            "the origin was not ours",
            "the RP ID was not ours",
            "the UV bit was missing",
            "the credential id is already registered",
        ];

        // Act
        let responses: Vec<_> = reasons.iter().map(|reason| refused(reason)).collect();

        // Assert
        for response in &responses {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        for reason in reasons {
            assert!(
                !format!("{:?}", responses[0]).contains(reason),
                "a refusal must not carry its reason"
            );
        }
    }

    /// The bug this page found: two `__Host-` cookies, split across two
    /// `cookie` fields the way HTTP/2 permits, and the session one second.
    /// Reading only the first field is a signed-in user told they are not.
    #[test]
    fn a_cookie_split_across_http2_fields_is_still_read() {
        // Arrange
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-asterius_ix=an-interaction"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-asterius_session=a-session"),
        );

        // Act
        let joined = cookies(&headers);

        // Assert
        assert_eq!(
            interaction::cookie_value(&joined, COOKIE_NAME),
            Some("a-session")
        );
    }

    /// ...and the duplicate rule survives the join: two cookies of one name,
    /// however they were split, are still no answer at all.
    #[test]
    fn a_duplicated_cookie_across_two_fields_is_refused() {
        // Arrange
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-asterius_session=one"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("__Host-asterius_session=two"),
        );

        // Act
        let joined = cookies(&headers);

        // Assert
        assert_eq!(interaction::cookie_value(&joined, COOKIE_NAME), None);
    }

    /// The three paths are distinct, and the two JSON ones live under the page
    /// so a future account page can host all three.
    #[test]
    fn the_three_paths_are_the_ones_the_template_names() {
        assert_eq!(PAGE_PATH, "/passkeys");
        assert_eq!(OPTIONS_PATH, "/passkeys/options");
        assert_eq!(FINISH_PATH, "/passkeys/finish");
    }
}
