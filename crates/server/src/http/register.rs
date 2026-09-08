//! `POST /register` — dynamic client registration (RFC 7591 §3).
//!
//! Almost nothing is decided here. [`ClientRegistration::from_json`] already
//! owns what an acceptable client is — the algorithm allow-list, the redirect
//! URI rules of ADR-0005, `jwks` xor `jwks_uri`, the auth methods FAPI 2.0
//! permits, the RFC 7591 §2.1 tie between `grant_types` and `response_types` —
//! and this module is the shell that turns that decision into an HTTP response.
//! Anything it re-checked would be a second definition of a valid client, and
//! the two would drift.
//!
//! What *is* decided here is who may call at all, what identifier the new
//! client gets, and what the caller is told afterwards.
//!
//! # Why this endpoint is gated by default
//!
//! RFC 7591 §3 says the registration endpoint "SHOULD allow registration
//! requests with no authorization" and adds that such requests "MAY be
//! rate-limited or otherwise limited to prevent a denial-of-service attack on
//! the client registration endpoint". That SHOULD exists to make clients
//! interoperable across servers nobody has agreed with in advance. It is the
//! wrong default for a FAPI deployment, where every client is confidential,
//! carries keys, and is somebody's counterparty.
//!
//! So the deployment chooses, in configuration, and the default is [closed].
//! An open registration endpoint writes an attacker-controlled row into
//! `clients` on demand: unbounded rows, unbounded inline JWKS blobs, and — once
//! `jwks_uri` fetching lands (`ast-mxc.5`) — an outbound fetch per registration
//! at an address the caller chose. None of that is hypothetical enough to be
//! the default. An operator who wants RFC 7591's SHOULD writes
//! `mode = "open"` and takes the consequences with a rate limiter.
//!
//! **This module does not rate-limit.** `ast-p2l.3` owns rate limiting and the
//! `rate_limits` table; open mode is only safe behind it, and gated mode still
//! wants it so that a leaked initial access token cannot be spent without
//! bound. The dependency is stated rather than assumed.
//!
//! # What the caller learns
//!
//! On success, exactly what was stored — read back out of the row in the same
//! statement that wrote it, never reflected from the request. RFC 7591 §3.2.1
//! requires the server to return "all registered metadata about this client,
//! including any fields provisioned by the authorization server itself", and
//! this profile provisions several: a client that asked for
//! `client_secret_basic` is refused rather than silently upgraded, but one that
//! asked for nothing is told which method it actually got.
//!
//! On failure, an error code from RFC 7591 §3.2.2's closed list and a
//! description this server wrote. The description names the field and never
//! quotes its value: a registration document is one of the few places a caller
//! can put a credential by mistake, and an endpoint reachable before
//! authentication must not be a reflection primitive.
//!
//! [closed]: RegistrationPolicy::Closed

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::{
    Capabilities, Client, ClientId, ClientMetadataError, ClientRegistration, ClientRegistry,
    ClientStatus, JwksSource, OpaqueToken, Tenant, ct_eq, sha256,
};
use asterius_oidc::metadata::Endpoint;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Json, body::Bytes};
use serde_json::{Value, json};
use time::OffsetDateTime;

/// The largest registration document this endpoint will read.
///
/// The same 16 KiB as the PAR endpoint, and for a stronger reason: PAR is
/// behind client authentication and this may not be. A registration document is
/// a handful of URLs, a scope string and an inline JWKS — a few kilobytes for
/// anything real.
///
/// It is deliberately *smaller* than the largest document the validator would
/// accept: [`ClientRegistration::MAX_REDIRECT_URIS`] times
/// [`asterius_domain::RedirectUri::MAX_LEN`] is 64 KiB of redirect URIs alone.
/// A caller that needs a registration that big is not one this endpoint serves;
/// the admin API is. The bound an unauthenticated caller can make this process
/// buffer must be a constant, not the product of two other limits that somebody
/// may raise later for an unrelated reason.
pub const MAX_BODY_BYTES: usize = 16 * 1024;

/// The prefix every `client_id` this endpoint mints begins with.
///
/// A full stop is not in the `base64url` alphabet (RFC 4648 §5) and not in the
/// hexadecimal-and-hyphen shape of a UUID, so no identifier carrying it can
/// collide with either spelling of a `sub` this server issues — a public one
/// (a UUID) or a pairwise one (43 `base64url` symbols).
///
/// That is FAPI 2.0 SP §6.7 taken literally. It warns that a client able to
/// influence its `client_id` may make it "mistaken for an end-user subject
/// identifier", and points at §4.15 of the OAuth Security BCP. The primary
/// mitigation is that a client cannot influence this value at all — any
/// `client_id` in the request is ignored — and the prefix is what makes the
/// separation visible to a human reading a log rather than merely true.
const CLIENT_ID_PREFIX: &str = "c.";

/// Entropy in a minted `client_id`.
///
/// A `client_id` is not a credential and RFC 7591 §3.2.1 does not ask for it to
/// be unguessable. It is made unguessable anyway, because a sequential or
/// derived identifier lets anyone who can reach `/register` enumerate the
/// deployment's client list, and because `client_id` is what an authorization
/// request names — a guessable one is the first half of impersonating a client
/// at an endpoint that has not authenticated it yet.
///
/// 128 bits is FAPI 2.0 SP §5.4.1's floor for credentials. Borrowing it here is
/// a ceiling argument, not a floor one: whatever an identifier needs, it needs
/// no more than what the profile demands of a secret.
const CLIENT_ID_BITS: usize = 128;

/// Entropy in a registration access token.
///
/// This one *is* a credential — a bearer credential authorising changes to the
/// client it was issued for (OIDC Registration §3.2, RFC 7592 §2) — so it takes
/// [`asterius_domain::credentials::DEFAULT_ENTROPY_BITS`], twice the FAPI floor,
/// like every other opaque token this server issues.
const REGISTRATION_TOKEN_BITS: usize = 256;

/// The shortest initial access token an operator may configure.
///
/// 22 unpadded `base64url` symbols is 128 bits, FAPI 2.0 SP §5.4.1's floor for a
/// credential no end user handles. An initial access token is exactly that: it
/// is the only thing standing between the internet and a row in `clients`, and
/// a short one turns this endpoint back into an open one for anybody willing to
/// guess. Checked at configuration load, where an operator is watching.
pub const MIN_INITIAL_ACCESS_TOKEN_LEN: usize = 22;

// ---------------------------------------------------------------------------
// Who may register
// ---------------------------------------------------------------------------

/// The digests of the initial access tokens this deployment honours.
///
/// Digests, not tokens: the process holds no value that could be replayed if it
/// were dumped, and a configuration file is not a place a plaintext credential
/// should survive being read. See [`asterius_domain::credentials`] for why a
/// bare SHA-256 is the right at-rest form for a value with this much entropy.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct InitialAccessTokens(Vec<[u8; 32]>);

impl std::fmt::Debug for InitialAccessTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The digests are not secret, but printing them would put a stable
        // per-token identifier into every log line that debugs a config.
        write!(f, "InitialAccessTokens({} configured)", self.0.len())
    }
}

impl InitialAccessTokens {
    /// Hashes the tokens an operator provisioned.
    #[must_use]
    pub fn from_tokens<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Self {
        Self(
            tokens
                .into_iter()
                .map(|token| sha256(token.as_bytes()))
                .collect(),
        )
    }

    /// How many are configured. Zero means nobody can register.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether none are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `presented` is one of them.
    ///
    /// Every configured digest is compared, and the results are accumulated
    /// rather than short-circuited, so the answer takes the same time whether
    /// the match is first, last or absent. The comparison itself goes through
    /// [`asterius_domain::ct_eq`] because this codebase has no other kind: `==`
    /// on secret bytes does not compile (see `asterius_domain::secret`).
    ///
    /// Both precautions are belt and braces here and are worth naming as such.
    /// The values compared are already digests of the presented string, so an
    /// attacker who could time this would learn a prefix of the hash of their
    /// own input, which they can compute. The reason to write it this way
    /// anyway is that the next person to copy this loop may be comparing
    /// something where it does matter.
    fn admits(&self, presented: &[u8; 32]) -> bool {
        let mut found = false;
        for known in &self.0 {
            found |= ct_eq(known, presented);
        }
        found
    }
}

/// Who this deployment lets register a client.
///
/// Deliberately not a `bool` and deliberately not defaulted to something
/// permissive: "closed", "gated" and "open" are three different security
/// postures and an operator should have to name one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RegistrationPolicy {
    /// Nobody. The default, and what an absent `[registration]` table means.
    ///
    /// The endpoint still exists and still answers, because it is still
    /// advertised in the discovery document — see [`Denial::status`] for why
    /// that is a 403 and not a 404.
    #[default]
    Closed,
    /// Callers holding an initial access token (RFC 7591 §3), presented as an
    /// RFC 6750 bearer credential.
    Gated(InitialAccessTokens),
    /// Anybody. RFC 7591 §3's SHOULD, and only safe behind `ast-p2l.3`.
    Open,
}

impl RegistrationPolicy {
    /// The label this policy carries into the audit trail and the logs.
    ///
    /// A closed set, because it becomes an audit detail and a metric label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Gated(_) => "initial_access_token",
            Self::Open => "open",
        }
    }

    /// Whether the request may proceed to validation.
    ///
    /// The whole authorization decision for this endpoint, in one pure
    /// function, so that it can be exercised without a database or a runtime.
    ///
    /// # Errors
    ///
    /// Returns the [`Denial`] to answer with. Never returns `Ok` for
    /// [`Self::Closed`], and never for [`Self::Gated`] without a credential
    /// this deployment issued.
    // fuzz-target: initial_access_token
    pub fn admit(&self, headers: &HeaderMap) -> Result<(), Denial> {
        match self {
            Self::Closed => Err(Denial::Closed),
            Self::Open => Ok(()),
            Self::Gated(known) => match bearer(headers) {
                None => Err(Denial::Missing),
                // The presented value is hashed before it is compared, so the
                // only thing this function ever holds next to a stored digest
                // is another digest.
                Some(presented) if known.admits(&sha256(presented.as_bytes())) => Ok(()),
                Some(_) => Err(Denial::Invalid),
            },
        }
    }
}

/// Why a caller was not allowed to register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// This deployment registers nobody.
    Closed,
    /// No bearer credential was presented.
    Missing,
    /// A bearer credential was presented and is not one this server issued.
    Invalid,
}

impl Denial {
    /// The OAuth error code, from a closed set.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            // RFC 6749 §4.1.2.1's spelling, reused here because RFC 7591 §3.2.2
            // defines no code for "this endpoint is switched off" — its list
            // covers documents, not authorization. RFC 7591 §3.2.2 defers those
            // to "an error response appropriate to the OAuth 2.0 token type",
            // which for a bearer token is RFC 6750 §3.1 — and that list has no
            // code for it either, because it presumes the resource exists.
            Self::Closed => "access_denied",
            // RFC 6750 §3.1.
            Self::Missing | Self::Invalid => "invalid_token",
        }
    }

    /// The status code.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            // 403 and not 404: the endpoint exists, is advertised in this
            // tenant's metadata, and the caller is looking in the right place.
            // A 404 would send an integrator hunting for a URL that is correct.
            //
            // A deployment that wants the endpoint to disappear from the
            // discovery document needs a capability flag; `Endpoint` has no
            // feature gate for registration today (`ast-f7m.4`).
            Self::Closed => StatusCode::FORBIDDEN,
            // RFC 6750 §3: a request without credentials, or with credentials
            // that do not grant access, is a 401 carrying `WWW-Authenticate`.
            Self::Missing | Self::Invalid => StatusCode::UNAUTHORIZED,
        }
    }

    /// The `WWW-Authenticate` challenge, when one is owed.
    ///
    /// RFC 6750 §3 makes the header mandatory for both 401 cases. The `error`
    /// attribute is added only when a credential was actually presented and
    /// rejected, which is what §3 says it is for: telling a client that its
    /// token is the problem. Sending `error="invalid_token"` to a caller that
    /// sent no token would be describing a token that does not exist.
    #[must_use]
    pub const fn challenge(self) -> Option<&'static str> {
        match self {
            Self::Closed => None,
            Self::Missing => Some("Bearer"),
            Self::Invalid => Some(r#"Bearer error="invalid_token""#),
        }
    }

    /// The description, in fixed text.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Closed => "dynamic client registration is not enabled",
            Self::Missing => "an initial access token is required",
            // Deliberately the same shape as `Missing`: which of the two
            // happened is already in the status line and the challenge, and
            // there is nothing further a legitimate caller learns from a longer
            // sentence.
            Self::Invalid => "the initial access token was not accepted",
        }
    }
}

/// The bearer credential in `Authorization`, if there is one.
///
/// RFC 6750 §2.1: `Authorization: Bearer <b64token>`. The scheme name is
/// matched case-insensitively because RFC 9110 §11.1 makes an auth-scheme
/// case-insensitive; the credential after it is not touched at all — no
/// trimming, no decoding, no length check. [`OpaqueToken::from_presented`]
/// explains why: every shape check on a presented credential is a second oracle
/// that answers faster than the real comparison does.
pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, credential) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    // Exactly one space, per the `credentials` production: `Bearer  x` presents
    // the token " x", not "x", and treating them alike would let one spelling
    // of a token be accepted where the other was issued.
    Some(credential)
}

// ---------------------------------------------------------------------------
// The endpoint
// ---------------------------------------------------------------------------

/// What the handler needs to answer a registration.
#[derive(Debug)]
pub struct RegisterContext<'a> {
    /// The tenant the request arrived at. Its issuer is what
    /// `registration_client_uri` is built from.
    pub tenant: &'a Tenant,
    /// Where the new client is written.
    pub clients: &'a dyn ClientRegistry,
    /// What this deployment offers. The document is validated against it, so a
    /// client cannot register for a grant the server does not implement.
    pub capabilities: Capabilities,
    /// Who may call.
    pub policy: &'a RegistrationPolicy,
    /// Where the registration decision is recorded.
    pub audit: &'a dyn AuditSink,
    /// The request id, for correlating the audit record with the access log.
    pub request_id: Option<&'a str>,
}

/// Handles a registration request.
///
/// Returns the RFC 7591 §3.2.1 client information response on success, and an
/// RFC 7591 §3.2.2 error object otherwise.
///
/// # Errors
///
/// Never returns `Err`: every failure is a `Response`, because a caller is
/// entitled to the specified error shape whatever went wrong.
pub async fn register(
    context: RegisterContext<'_>,
    headers: &HeaderMap,
    body: &Bytes,
    now: OffsetDateTime,
) -> Response {
    // Authorization first, so that nothing after it is work an unauthorized
    // caller can make this process do — not a JSON parse, not an allocation the
    // size of the body, not an audit row.
    if let Err(denial) = context.policy.admit(headers) {
        return refusal(denial);
    }

    if body.len() > MAX_BODY_BYTES {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid_client_metadata",
            "the registration document is too large",
        );
    }

    // RFC 7591 §3: the endpoint "MUST accept HTTP POST messages with request
    // parameters encoded in the entity body using the application/json format".
    // Only that: a second encoding would be a second parser with a second
    // chance to disagree about the same document.
    if !is_json(headers) {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_client_metadata",
            "content-type must be application/json",
        );
    }

    // The whole of the validation, in one call, in the domain. Nothing below
    // re-checks any part of it.
    let registration = match ClientRegistration::from_json(body, context.capabilities) {
        Ok(registration) => registration,
        Err(failure) => {
            // Audited, because a caller that got this far holds whatever
            // credential the policy demanded and a stream of rejected documents
            // from one initial access token is worth seeing. Denials *before*
            // this point are not audited: they are reachable without a
            // credential, and an audit row per unauthenticated request is an
            // amplification primitive pointed at the one table that cannot be
            // deleted from.
            record(&context, now, Outcome::Failure, None, Some(failure.code())).await;
            return metadata_error(&failure);
        }
    };

    // Minted after validation, so a rejected document consumes no identifier
    // and no entropy.
    let client_id = mint_client_id();
    let token = OpaqueToken::generate_bits::<REGISTRATION_TOKEN_BITS>();

    let client = Client {
        tenant: context.tenant.id.clone(),
        id: client_id.clone(),
        registration,
        status: ClientStatus::Active,
        // Both are decided by the row's defaults; these are placeholders that
        // the store overwrites and the response never sees, because the
        // response is rendered from what comes back.
        created_at: now,
        updated_at: now,
    };

    let stored = match context
        .clients
        .register(&client, &sha256(token.expose().as_bytes()))
        .await
    {
        Ok(stored) => stored,
        Err(failure) => {
            tracing::error!(
                %failure,
                tenant = %context.tenant.id,
                "cannot store a client registration"
            );
            record(
                &context,
                now,
                Outcome::Failure,
                None,
                Some("temporarily_unavailable"),
            )
            .await;
            // RFC 6749 §4.1.2.1's `temporarily_unavailable`, borrowed because
            // RFC 7591 §3.2.2 defines only document errors and this is not one:
            // the document was fine and the server was not. The distinction is
            // what a caller acts on — a 400 says "fix your document", this says
            // "try again" — and a `client_id` collision at 128 bits arrives
            // here too, where retrying is exactly the right response.
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "the registration could not be stored",
            );
        }
    };

    record(
        &context,
        now,
        Outcome::Success,
        Some(stored.id.clone()),
        None,
    )
    .await;

    // RFC 7591 §3.2.1: 201, `application/json`, `no-store`. The body carries a
    // credential exactly once; a cached 201 is that credential handed to
    // whoever asks next.
    (
        StatusCode::CREATED,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(client_information(
            &stored,
            context.tenant,
            Some(&token),
            now,
        )),
    )
        .into_response()
}

/// The path this endpoint is mounted at, from the one registry.
#[must_use]
pub const fn path() -> &'static str {
    Endpoint::Registration.path()
}

/// Draws a fresh `client_id`.
///
/// [`OpaqueToken`] is the codebase's one CSPRNG path and its output is already
/// unpadded `base64url` (RFC 4648 §5), which is what makes an identifier safe in
/// a URL path, a form field and a JSON string without escaping. It is used here
/// for the draw and the encoding only: the value is public by design, so it is
/// taken out of the wrapper immediately rather than carried around as something
/// that must not be printed.
fn mint_client_id() -> ClientId {
    let drawn = OpaqueToken::generate_bits::<CLIENT_ID_BITS>();
    ClientId::new(format!("{CLIENT_ID_PREFIX}{}", drawn.expose()))
}

/// The RFC 7591 §3.2.1 / RFC 7592 §3 client information response.
///
/// One renderer for both endpoints, on purpose: a registration, a read and an
/// update all return the same document, and two renderers would be two lists of
/// fields to keep in step — with the one that is read less often being the one
/// that rots. `token` is `Some` only at the moment the credential is minted;
/// see the comment on the field for the specification's two readings.
///
/// Rendered from the **stored** registration, which is why `stored` comes back
/// out of the write rather than being the entity that went in. RFC 7591 §3.2.1
/// requires "all registered metadata about this client, including any fields
/// provisioned by the authorization server itself", and this profile provisions
/// plenty: `require_pushed_authorization_requests` is always true (ADR-0002),
/// `token_endpoint_auth_method` and `id_token_signed_response_alg` have defaults
/// that are not RFC 7591 §2's, and `response_types` is derived from
/// `grant_types` rather than taken.
///
/// Written by hand rather than derived, for the same reason `par::serialise` is:
/// adding a field to [`ClientRegistration`] should be a decision about what a
/// client is told, not an automatic consequence.
///
/// Two things are deliberately absent.
///
/// * **`client_secret`.** FAPI 2.0 SP §5.3.2.1 permits only `private_key_jwt`
///   and mTLS, so this server issues none — and RFC 7591 §3.2.1 makes
///   `client_secret_expires_at` "REQUIRED if `client_secret` is issued", so that
///   field is absent too. Sending `client_secret_expires_at: 0` with no secret
///   would tell a client it holds a secret that never expires.
/// * **`resources`.** The per-client audience allow-list is policy and is not a
///   registration metadata field; it is not settable here and `ast-m9c.6` owns
///   it. Echoing it would advertise a field a client cannot set.
pub(crate) fn client_information(
    stored: &Client,
    tenant: &Tenant,
    token: Option<&OpaqueToken>,
    now: OffsetDateTime,
) -> Value {
    let registration = &stored.registration;
    let mut document = json!({
        // --- RFC 7591 §3.2.1 registration response fields ---
        "client_id": stored.id.as_str(),
        // The row's own timestamp, not the wall clock this request read, so the
        // number a client is given is the one the database will always agree
        // with. Falls back to `now` only if the column somehow predates the
        // epoch, which the schema's `default now()` makes unreachable.
        "client_id_issued_at": issued_at(stored, now),

        // --- OIDC Registration §3.2 ---
        //
        // "Implementations MUST either return both a Client Configuration
        // Endpoint and a Registration Access Token or neither of them." Both,
        // at registration. The URI is answered by
        // [`crate::http::client_configuration`], and the token is stored as a
        // digest so that reading a registration back needs no plaintext copy.
        "registration_client_uri": management_uri(tenant, &stored.id),

        // --- client metadata, as registered ---
        "client_name": registration.client_name,
        "application_type": registration.application_type.as_str(),
        "token_endpoint_auth_method": registration.token_endpoint_auth_method.as_str(),
        "redirect_uris": registration
            .redirect_uris
            .iter()
            .map(asterius_domain::RedirectUri::as_str)
            .collect::<Vec<_>>(),
        "grant_types": registration
            .grant_types
            .iter()
            .map(|grant| grant.as_str())
            .collect::<Vec<_>>(),
        "response_types": registration.response_types(),
        // RFC 6749 §3.3: the order of scope values is not significant, which is
        // as well — they are stored in a set and come back sorted. A client
        // comparing the string it sent against the string it got will see a
        // difference; a client comparing the sets will not.
        "scope": registration
            .scopes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        "id_token_signed_response_alg": registration.id_token_signed_response_alg.as_str(),
        "subject_type": registration.subject_type.as_str(),
        // Provisioned by this server and not settable to anything else
        // (ADR-0002, RFC 9126 §6): PAR is the only way in.
        "require_pushed_authorization_requests":
            ClientRegistration::REQUIRE_PUSHED_AUTHORIZATION_REQUESTS,
        "dpop_bound_access_tokens": registration.token_binding.is_dpop_bound(),
        "tls_client_certificate_bound_access_tokens":
            registration.token_binding.is_certificate_bound(),
        "authorization_details_types": registration
            .authorization_details_types
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        "use_mtls_endpoint_aliases": registration.use_mtls_endpoint_aliases,
    });

    let object = document
        .as_object_mut()
        .expect("the document above is a JSON object");

    // Present exactly once, when the token is minted. RFC 7592 §3 marks
    // `registration_access_token` REQUIRED in the client information response,
    // but the server holds only its digest after this moment, and OIDC
    // Registration §4.3 is the narrower rule for the read that comes later:
    // "The Authorization Server need not include the registration_access_token
    // or registration_client_uri value in this response unless they have been
    // updated." So a registration carries it and a read does not — see
    // [`crate::http::client_configuration`] for why re-minting it on every read
    // would be worse than omitting it.
    if let Some(token) = token {
        object.insert(
            "registration_access_token".to_owned(),
            json!(token.expose()),
        );
    }

    // RFC 7591 §2: `jwks` and `jwks_uri` must never both appear. The stored
    // registration can only hold one, so this reproduces that rather than
    // deciding it again.
    match &registration.jwks {
        JwksSource::Inline(keys) => object.insert("jwks".to_owned(), keys.clone()),
        JwksSource::Uri(uri) => object.insert("jwks_uri".to_owned(), json!(uri)),
    };

    // Omitted rather than sent as null when the client registered none: an
    // absent member and a null one mean different things to a strict client,
    // and RFC 7591 §2 makes every metadata field optional.
    if let Some(alg) = registration.request_object_signing_alg {
        object.insert("request_object_signing_alg".to_owned(), json!(alg.as_str()));
    }
    if let Some(alg) = registration.backchannel_authentication_request_signing_alg {
        object.insert(
            "backchannel_authentication_request_signing_alg".to_owned(),
            json!(alg.as_str()),
        );
    }
    if let Some(uri) = &registration.sector_identifier_uri {
        object.insert("sector_identifier_uri".to_owned(), json!(uri));
    }

    document
}

/// The `client_id_issued_at` value: seconds since the epoch, from the row.
fn issued_at(stored: &Client, fallback: OffsetDateTime) -> i64 {
    let issued = if stored.created_at > OffsetDateTime::UNIX_EPOCH {
        stored.created_at
    } else {
        fallback
    };
    issued.unix_timestamp()
}

/// The `registration_client_uri` for a client.
///
/// OIDC Registration §4.1 recommends "the Client Registration Endpoint's URL
/// and the issued Client ID for this Client, with the latter as either a path
/// parameter or a query parameter", and requires the https scheme. The path
/// form is used because it is the one [`crate::http::client_configuration`]
/// serves, and a test there asserts the two agree — a URL handed to a client
/// that the router does not answer is the worst of both readings. The scheme is
/// https by construction: [`asterius_domain::Issuer`] refuses anything else.
pub(crate) fn management_uri(tenant: &Tenant, client: &ClientId) -> String {
    format!(
        "{}{}/{}",
        tenant.issuer.as_str(),
        Endpoint::Registration.path(),
        client.as_str()
    )
}

/// Appends the registration decision to the audit trail.
///
/// Written after the row is committed, and a failure here does **not** fail the
/// request. That is the opposite of the choice `TenantKeyStore::apply_schedule`
/// makes, and the difference is which way the damage runs: a rotation that is
/// refused after the fact can be retried from the key rows, but a registration
/// refused after the row exists strands a live client whose owner was told it
/// failed and never received the only copy of its registration access token.
/// The gap is logged at `error` and closing it properly needs the transactional
/// outbox (`ast-0ju.9`), which is the same answer the key store reaches.
async fn record(
    context: &RegisterContext<'_>,
    now: OffsetDateTime,
    outcome: Outcome,
    client: Option<ClientId>,
    reason: Option<&'static str>,
) {
    // `Actor::System`, because there is no identity to name. The registrant is
    // either anonymous or holds an initial access token, and an initial access
    // token is authorization to use this endpoint rather than a statement about
    // who is using it (RFC 7591 §5). The token is fingerprinted into the detail
    // instead, which is what makes per-token quota (`ast-m9c.6`) and abuse
    // investigation possible without the trail holding a usable credential.
    let mut detail = Detail::new().label("policy", context.policy.as_str()).flag(
        "open_registration",
        matches!(context.policy, RegistrationPolicy::Open),
    );
    if let Some(reason) = reason {
        detail = detail.label("reason", reason);
    }

    let mut event = AuditEvent::new(
        context.tenant.id.clone(),
        EventType::CLIENT_REGISTERED,
        outcome,
        Actor::System,
        now,
    )
    .detail(detail);
    if let Some(client) = client {
        event = event.client(client);
    }
    if let Some(request_id) = context.request_id {
        event = event.request_id(request_id);
    }

    if let Err(failure) = context.audit.record(event).await {
        tracing::error!(
            %failure,
            tenant = %context.tenant.id,
            "a client registration was not written to the audit trail"
        );
    }
}

/// Whether the request body is JSON, ignoring any charset parameter.
pub(crate) fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
        })
}

/// The RFC 7591 §3.2.2 error for a rejected document.
///
/// The code comes from [`ClientMetadataError::code`], which is where the
/// mapping onto §3.2.2's list lives — `invalid_redirect_uri` when a redirect URI
/// was the problem, `invalid_client_metadata` otherwise. Getting a generic code
/// for a redirect URI failure is exactly the case §3.2.2 gives the second code
/// for.
///
/// The description is the error's own `Display`, which every variant of
/// [`ClientMetadataError`] renders from field names, indexes and fixed text —
/// never from a value in the document. That property is asserted where it is
/// established, in `asterius_domain::entities::client`.
pub(crate) fn metadata_error(failure: &ClientMetadataError) -> Response {
    error(
        StatusCode::BAD_REQUEST,
        failure.code(),
        &nqschar(&failure.to_string()),
    )
}

/// Reduces a description to the characters RFC 6749 Appendix A.8 permits.
///
/// `error_description` is `1*NQSCHAR`, and `NQSCHAR` is
/// `%x20-21 / %x23-5B / %x5D-7E`: printable US-ASCII without `"` and `\`.
/// RFC 7591 §3.2.2 says the same thing in prose — "human-readable ASCII text".
///
/// This is needed because the domain's rejection messages are written for a
/// human and cite specifications the way a human writes them: "FAPI 2.0 SP
/// §5.3.2.2 item 8" contains U+00A7, which is not ASCII. That is the right
/// spelling in a log, a test failure and a doc comment, and the wrong one on
/// the wire, so the transliteration happens here — at the boundary — rather
/// than by making every message in the domain uglier.
///
/// Offending characters are dropped rather than replaced. In these messages the
/// only one that occurs is a section sign preceded by a space, so dropping it
/// leaves "FAPI 2.0 SP 5.3.2.2 item 8" — the citation a reader needs, intact.
///
/// The exclusion of `"` and `\` is not cosmetic. This body is JSON, where both
/// would be escaped safely, but the same string is the natural thing to put in a
/// `WWW-Authenticate` parameter, where a quotation mark ends the value early.
/// RFC 6749 excluded them for that reason; keeping to its set means a
/// description that later moves into a header cannot become a header-injection
/// bug in a change nobody thought was about escaping.
///
/// No fuzz target: the input is not attacker-controlled. Every string reaching
/// here is a literal in this crate or a [`ClientMetadataError`] rendering, and
/// those are built from field names, indexes and counts by construction — a
/// property asserted where it is established, in
/// `asterius_domain::entities::client`. The test below pins the closed set.
pub(crate) fn nqschar(description: &str) -> String {
    description
        .chars()
        .filter(|c| matches!(c, '\x20'..='\x21' | '\x23'..='\x5b' | '\x5d'..='\x7e'))
        .collect()
}

/// The response to a caller the policy refused.
fn refusal(denial: Denial) -> Response {
    let mut response = error(denial.status(), denial.code(), denial.description());
    if let Some(challenge) = denial.challenge() {
        // Every value `challenge` can return is a literal in this module, so
        // `from_static` cannot panic on anything a caller supplied.
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static(challenge),
        );
    }
    response
}

/// An error object: RFC 7591 §3.2.2's two members.
///
/// `error_description` is written by this server, never echoed from the
/// request. RFC 7591 §3.2.2 calls it "human-readable ASCII text ... used for
/// debugging", and every value that reaches it here is a literal or a field
/// name from a closed set.
pub(crate) fn error(status: StatusCode, code: &str, description: &str) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({ "error": code, "error_description": description })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{Issuer, TenantId, TenantStatus};

    const TOKEN: &str = "0PIVxTz6ThDcJdxCoWnk8w";

    fn headers(authorization: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = authorization {
            headers.insert(
                header::AUTHORIZATION,
                value.parse().expect("a valid header value"),
            );
        }
        headers
    }

    fn gated() -> RegistrationPolicy {
        RegistrationPolicy::Gated(InitialAccessTokens::from_tokens([
            "other-token-entirely",
            TOKEN,
        ]))
    }

    fn tenant() -> Tenant {
        Tenant {
            id: TenantId::new("demo"),
            issuer: Issuer::parse("https://as.example/t/demo").expect("issuer"),
            custom_host: None,
            display_name: "demo".into(),
            status: TenantStatus::Active,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn registration(document: &Value) -> ClientRegistration {
        ClientRegistration::from_json(
            &serde_json::to_vec(document).expect("serialise"),
            Capabilities::default(),
        )
        .expect("a valid registration")
    }

    fn minimal_document() -> Value {
        json!({
            "client_name": "Billing",
            "redirect_uris": ["https://rp.example/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "openid payments",
            "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "abc"}]},
        })
    }

    /// The default is the one an operator gets by saying nothing, so it is the
    /// one worth pinning: an unconfigured deployment registers nobody. RFC 7591
    /// §3's "SHOULD allow registration requests with no authorization" is
    /// deliberately not followed by default.
    #[test]
    fn a_deployment_that_said_nothing_registers_nobody() {
        assert_eq!(RegistrationPolicy::default(), RegistrationPolicy::Closed);
        assert_eq!(
            RegistrationPolicy::Closed.admit(&headers(None)),
            Err(Denial::Closed)
        );
        // Not even with a credential, because there is no credential a closed
        // deployment issued.
        assert_eq!(
            RegistrationPolicy::Closed.admit(&headers(Some(&format!("Bearer {TOKEN}")))),
            Err(Denial::Closed)
        );
        assert_eq!(Denial::Closed.status(), StatusCode::FORBIDDEN);
        assert!(
            Denial::Closed.challenge().is_none(),
            "a closed endpoint must not invite a credential that would not help"
        );
    }

    /// RFC 7591 §3 and RFC 6750 §2.1: the gate opens for a bearer credential
    /// this deployment issued, and for nothing else. The last case is the one
    /// that matters — a token that is a prefix, a suffix or a near-miss of a
    /// configured one must be refused like any other stranger.
    #[test]
    fn the_gate_admits_exactly_the_configured_initial_access_tokens() {
        let policy = gated();
        assert_eq!(
            policy.admit(&headers(Some(&format!("Bearer {TOKEN}")))),
            Ok(())
        );
        // RFC 9110 §11.1: the auth-scheme is case-insensitive.
        assert_eq!(
            policy.admit(&headers(Some(&format!("bEaReR {TOKEN}")))),
            Ok(())
        );
        assert_eq!(policy.admit(&headers(None)), Err(Denial::Missing));
        for wrong in [
            "Bearer ",
            "Bearer wrong",
            "Basic 0PIVxTz6ThDcJdxCoWnk8w",
            "Bearer 0PIVxTz6ThDcJdxCoWnk8",
            "Bearer 0PIVxTz6ThDcJdxCoWnk8ww",
            // Two spaces presents a token beginning with a space, which is a
            // different token from the one that was issued.
            "Bearer  0PIVxTz6ThDcJdxCoWnk8w",
            "0PIVxTz6ThDcJdxCoWnk8w",
            "Bearer",
        ] {
            assert!(
                policy.admit(&headers(Some(wrong))).is_err(),
                "{wrong:?} was admitted"
            );
        }
    }

    /// RFC 6750 §2.1's `b64token` is ASCII, so a header carrying anything else
    /// is not a bearer credential at all and is refused like a missing one.
    ///
    /// This is worth pinning because `HeaderValue` and `HeaderValue::to_str`
    /// disagree about what a header may hold: the first accepts obs-text
    /// (`%x80-FF`), so `Bearer é` is a header a client can genuinely send, and
    /// the second refuses it. The endpoint therefore sees no credential, which
    /// is the right answer — but it is `Missing` rather than `Invalid`, and a
    /// fuzz oracle written against the Rust string got that wrong.
    #[test]
    fn a_header_that_is_not_visible_ascii_carries_no_credential() {
        let policy = gated();
        for exotic in [
            format!("Bearer {TOKEN}\u{e9}"),
            format!("Bearer \u{e9}{TOKEN}"),
            "Bearer \u{ff}".to_owned(),
            format!("B\u{e9}arer {TOKEN}"),
        ] {
            let Ok(value) = exotic.parse::<axum::http::HeaderValue>() else {
                continue;
            };
            let mut map = HeaderMap::new();
            map.insert(header::AUTHORIZATION, value);
            assert_eq!(
                policy.admit(&map),
                Err(Denial::Missing),
                "{exotic:?} was read as a presented credential"
            );
        }
    }

    /// RFC 6750 §3: both 401 cases carry `WWW-Authenticate`, and the `error`
    /// attribute appears only when a token was presented and rejected — saying
    /// `invalid_token` to a caller that sent none describes a token that does
    /// not exist.
    #[test]
    fn a_refused_caller_is_told_how_to_authenticate() {
        assert_eq!(Denial::Missing.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(Denial::Invalid.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(Denial::Missing.challenge(), Some("Bearer"));
        assert_eq!(
            Denial::Invalid.challenge(),
            Some(r#"Bearer error="invalid_token""#)
        );
        assert_eq!(Denial::Missing.code(), "invalid_token");
        assert_eq!(Denial::Invalid.code(), "invalid_token");
    }

    /// FAPI 2.0 SP §6.7: a `client_id` must not be mistakable for an end-user
    /// subject identifier. This server's subjects are UUIDs (public) or 43
    /// `base64url` symbols (pairwise); a full stop occurs in neither alphabet,
    /// so the prefix makes the two sets disjoint by construction rather than by
    /// luck.
    #[test]
    fn a_minted_client_id_cannot_be_mistaken_for_a_subject() {
        let id = mint_client_id();
        assert!(id.as_str().starts_with(CLIENT_ID_PREFIX));
        let drawn = &id.as_str()[CLIENT_ID_PREFIX.len()..];
        assert_eq!(drawn.len(), 22, "128 bits is 22 base64url symbols");
        assert!(
            drawn
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "a client_id left the RFC 4648 §5 alphabet: {drawn}"
        );
        assert!(
            uuid_shaped(id.as_str()).is_none(),
            "a client_id must not parse as the UUID a public `sub` is"
        );
        // Unguessable, and never twice the same.
        let ids: std::collections::HashSet<String> = (0..256)
            .map(|_| mint_client_id().as_str().to_owned())
            .collect();
        assert_eq!(ids.len(), 256, "the minter repeated itself");
    }

    /// A crude UUID shape check, written here rather than pulled in so that the
    /// assertion above does not depend on the same parser the subject minter
    /// uses.
    fn uuid_shaped(value: &str) -> Option<()> {
        let groups: Vec<&str> = value.split('-').collect();
        (groups.len() == 5
            && groups
                .iter()
                .all(|g| g.chars().all(|c| c.is_ascii_hexdigit())))
        .then_some(())
    }

    /// RFC 7591 §3.2.1: the response carries the metadata that was *registered*.
    ///
    /// Asserted by feeding the response document straight back into the
    /// validator: if the rendered document produces the same registration, then
    /// what the client was told and what the server stored describe the same
    /// client. A field dropped from the renderer, or one rendered with a
    /// different spelling, breaks this — which is the whole failure mode, since
    /// a client that re-registers from its own response record must get the
    /// same configuration back.
    #[test]
    fn the_response_document_re_registers_as_the_same_client() {
        let capabilities = Capabilities {
            mtls: true,
            ..Capabilities::default()
        };
        let mut document = minimal_document();
        let object = document.as_object_mut().expect("object");
        object.insert("application_type".to_owned(), json!("web"));
        object.insert("subject_type".to_owned(), json!("pairwise"));
        object.insert(
            "sector_identifier_uri".to_owned(),
            json!("https://rp.example/sector.json"),
        );
        object.insert("request_object_signing_alg".to_owned(), json!("ES256"));
        object.insert("id_token_signed_response_alg".to_owned(), json!("PS256"));
        object.insert("dpop_bound_access_tokens".to_owned(), json!(true));
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

        let token = OpaqueToken::generate();
        let rendered =
            client_information(&stored, &tenant(), Some(&token), OffsetDateTime::UNIX_EPOCH);

        let round_tripped = ClientRegistration::from_json(
            &serde_json::to_vec(&rendered).expect("serialise"),
            capabilities,
        )
        .expect("the response document must itself be a valid registration");
        assert_eq!(
            round_tripped, stored.registration,
            "the response describes a different client than the one stored"
        );
    }

    /// The fields the specifications name, and the two that must never appear.
    #[test]
    fn the_response_carries_what_the_specifications_require() {
        let stored = Client {
            tenant: TenantId::new("demo"),
            id: ClientId::new("c.abc"),
            registration: registration(&minimal_document()),
            status: ClientStatus::Active,
            created_at: OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("instant"),
            updated_at: OffsetDateTime::from_unix_timestamp(1_760_000_000).expect("instant"),
        };
        let token = OpaqueToken::generate();
        let body = client_information(&stored, &tenant(), Some(&token), OffsetDateTime::UNIX_EPOCH);

        // RFC 7591 §3.2.1.
        assert_eq!(body["client_id"], json!("c.abc"));
        assert_eq!(body["client_id_issued_at"], json!(1_760_000_000_i64));

        // OIDC Registration §3.2: both of these, or neither.
        assert_eq!(body["registration_access_token"], json!(token.expose()));
        assert_eq!(
            body["registration_client_uri"],
            json!("https://as.example/t/demo/register/c.abc")
        );
        assert!(
            body["registration_client_uri"]
                .as_str()
                .expect("a string")
                .starts_with("https://"),
            "OIDC Registration §3.2: registration_client_uri MUST use https"
        );

        // Provisioned by the server, not asked for by the client (ADR-0002).
        assert_eq!(body["require_pushed_authorization_requests"], json!(true));
        assert_eq!(body["token_endpoint_auth_method"], json!("private_key_jwt"));
        assert_eq!(body["response_types"], json!(["code"]));
        assert_eq!(body["dpop_bound_access_tokens"], json!(true));

        // FAPI 2.0 SP §5.3.2.1 permits no shared-secret client authentication,
        // so there is no secret — and RFC 7591 §3.2.1 makes
        // `client_secret_expires_at` required only *if* one is issued. Sending
        // it as 0 would tell a client it holds a secret that never expires.
        assert!(body.get("client_secret").is_none());
        assert!(body.get("client_secret_expires_at").is_none());

        // RFC 7591 §2: never both key sources.
        assert!(body.get("jwks").is_some());
        assert!(body.get("jwks_uri").is_none());

        // The per-client resource allow-list is policy (`ast-m9c.6`), not
        // registration metadata; echoing it would advertise a settable field.
        assert!(body.get("resources").is_none());
    }

    /// An unset optional is omitted, not sent as `null`: RFC 7591 §2 makes
    /// every metadata field optional, and a strict client reads an explicit
    /// null differently from an absent member.
    #[test]
    fn optional_metadata_the_client_did_not_register_is_absent() {
        let stored = Client {
            tenant: TenantId::new("demo"),
            id: ClientId::new("c.abc"),
            registration: registration(&minimal_document()),
            status: ClientStatus::Active,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let body = client_information(
            &stored,
            &tenant(),
            Some(&OpaqueToken::generate()),
            OffsetDateTime::UNIX_EPOCH,
        );
        for absent in [
            "request_object_signing_alg",
            "backchannel_authentication_request_signing_alg",
            "sector_identifier_uri",
        ] {
            assert!(
                body.get(absent).is_none(),
                "{absent} was rendered for a client that did not register one"
            );
        }
    }

    /// The audit trail is only useful if the policy that was applied survives
    /// into it. `Detail::text` would have redacted `temporarily_unavailable` as
    /// a credential — 23 characters over 15 distinct is exactly what the
    /// scanner looks for — which is why these go through `Detail::label`.
    #[test]
    fn the_policy_name_reaches_the_audit_trail_unredacted() {
        for (policy, expected) in [
            (RegistrationPolicy::Closed, "closed"),
            (RegistrationPolicy::Open, "open"),
            (gated(), "initial_access_token"),
        ] {
            let detail = Detail::new()
                .label("policy", policy.as_str())
                .label("reason", "temporarily_unavailable");
            let rendered: std::collections::BTreeMap<&str, String> = detail
                .iter()
                .map(|(key, value)| {
                    let asterius_domain::audit::DetailValue::Text(text) = value else {
                        panic!("{key} is not text");
                    };
                    (key.as_str(), text.clone())
                })
                .collect();
            assert_eq!(rendered["policy"], expected);
            assert_eq!(
                rendered["reason"], "temporarily_unavailable",
                "the audit trail lost an error code to the credential scanner"
            );
        }
    }

    /// RFC 6749 Appendix A.8: `error_description` is `1*NQSCHAR`, which is
    /// `%x20-21 / %x23-5B / %x5D-7E`. The domain writes `§` in its messages
    /// because that is right for a human; the wire does not get it.
    #[test]
    fn a_description_is_reduced_to_the_characters_the_grammar_permits() {
        assert_eq!(
            nqschar("redirect_uris[0]: scheme must be https (FAPI 2.0 SP §5.3.2.2)"),
            "redirect_uris[0]: scheme must be https (FAPI 2.0 SP 5.3.2.2)"
        );
        // `"` and `\` are excluded by the grammar because they end a
        // `WWW-Authenticate` quoted-string early.
        assert_eq!(nqschar(r#"a "quoted" \ value"#), "a quoted  value");
        // Control characters, including the ones that would split a header.
        assert_eq!(nqschar("one\r\ntwo\ttab\u{0}"), "onetwotab");
        // Idempotent, and a no-op on text that already conforms.
        let plain = "an initial access token is required";
        assert_eq!(nqschar(plain), plain);
        assert_eq!(nqschar(&nqschar(plain)), plain);

        // Every description this module writes itself is already conforming, so
        // the filter never silently rewrites one.
        for denial in [Denial::Closed, Denial::Missing, Denial::Invalid] {
            assert_eq!(nqschar(denial.description()), denial.description());
        }
    }

    /// The whole of [`ClientMetadataError`]'s output, checked against the
    /// grammar rather than against one example — a variant added later that
    /// interpolates something exotic fails here.
    #[test]
    fn every_rejection_the_validator_can_produce_reaches_the_wire_conforming() {
        let documents = [
            json!({}),
            json!({"client_name": "x"}),
            json!({"client_name": "x", "redirect_uris": ["http://rp.example/cb"]}),
            json!({"client_name": "x", "redirect_uris": [], "grant_types": ["implicit"]}),
            json!({"client_name": "x", "token_endpoint_auth_method": "none"}),
            json!({"client_name": "x", "application_type": "toaster"}),
            json!({"client_name": "x", "id_token_signed_response_alg": "RS256"}),
            json!({"client_name": "x", "subject_type": "sideways"}),
            json!({"client_name": "x", "response_types": ["token"]}),
            json!({"client_name": "x", "require_pushed_authorization_requests": false}),
            json!({"client_name": "x", "dpop_bound_access_tokens": false}),
            json!({"client_name": "\u{202e}reversed\u{202c}"}),
            json!({"client_name": "x", "scope": "\u{7f}\u{80}"}),
        ];
        for document in documents {
            let Err(failure) = ClientRegistration::from_json(
                &serde_json::to_vec(&document).expect("serialise"),
                Capabilities::default(),
            ) else {
                continue;
            };
            let rendered = nqschar(&failure.to_string());
            assert!(
                !rendered.is_empty(),
                "a rejection rendered to nothing: {document}"
            );
            assert!(
                rendered.bytes().all(|b| matches!(
                    b,
                    0x20..=0x21 | 0x23..=0x5b | 0x5d..=0x7e
                )),
                "{rendered:?} is not 1*NQSCHAR (RFC 6749 Appendix A.8)"
            );
        }
    }

    /// RFC 7591 §3: `application/json`, and nothing else.
    #[test]
    fn only_json_bodies_are_read() {
        let mut headers = HeaderMap::new();
        assert!(
            !is_json(&headers),
            "a body with no content type is not JSON"
        );
        for good in [
            "application/json",
            "application/json; charset=utf-8",
            "APPLICATION/JSON",
        ] {
            headers.insert(header::CONTENT_TYPE, good.parse().expect("header"));
            assert!(is_json(&headers), "{good} was refused");
        }
        for bad in [
            "application/x-www-form-urlencoded",
            "text/json",
            "application/jsonx",
            "",
        ] {
            headers.insert(header::CONTENT_TYPE, bad.parse().expect("header"));
            assert!(!is_json(&headers), "{bad:?} was accepted");
        }
    }
}
