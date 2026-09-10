//! DPoP at the HTTP boundary: the header, the endpoint URL, the replay store
//! and the `use_dpop_nonce` handshake (RFC 9449 §4.1, §4.3, §5, §8, §10).
//!
//! [`asterius_jose::dpop`] owns what a proof must say. This module owns the
//! three things that can only be decided here:
//!
//! 1. **Which bytes are the proof.** RFC 9449 §4.3 item 1: "There is not more
//!    than one DPoP HTTP request header field." Two headers is not a request
//!    with a spare — it is a request where the server has to choose, and a
//!    server that chooses is a server an attacker can steer between a proof
//!    the front end validated and a proof the back end used.
//! 2. **What `htu` is compared against.** See [`DpopEndpoint::check`]: the URL
//!    comes from the tenant's issuer, never from the request.
//! 3. **When the `jti` is spent.** The proof is checked in full first; only a
//!    proof that would otherwise be accepted costs a row.
//!
//! # What is deliberately absent
//!
//! **`Access-Control-Expose-Headers`.** RFC 9449 §8 notes that a browser-based
//! client cannot read `DPoP-Nonce` unless the server exposes it through CORS.
//! This server emits no CORS headers at any endpoint — `crates/server/tests/
//! transport.rs::no_endpoint_ever_answers_with_cors_headers` is the assertion
//! — and it has no browser-based clients to serve: ADR-0002 admits only
//! confidential clients authenticating with `private_key_jwt` or mTLS, so
//! nothing that reaches these endpoints is a `fetch()` from a page. Adding one
//! CORS header for a client that cannot exist would weaken a rule that
//! currently needs no exceptions.

use asterius_domain::{
    Capabilities, Client, Feature, Kid, ReplayCheck, ReplayGuard, ReplayPurpose, Tenant,
};
use asterius_jose::dpop::{self, DpopError, Expectation, NonceIssuer, NormalisedUri};
use asterius_oidc::metadata::Endpoint;
use axum::Json;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

/// The request header a proof arrives in (RFC 9449 §4.1).
///
/// Lowercase because `HeaderMap` normalises names; RFC 9110 makes field names
/// case-insensitive, so `DPoP`, `DPOP` and `dpop` are one header, and the RFC
/// says so explicitly.
pub const HEADER: &str = "dpop";

/// The response header a nonce is supplied in (RFC 9449 §8, registered §12.8).
pub const NONCE_HEADER: &str = "dpop-nonce";

/// The error code for a proof that did not check out (RFC 9449 §5, §12.2).
pub const INVALID_PROOF: &str = "invalid_dpop_proof";

/// The error code that means "retry with the nonce I just gave you"
/// (RFC 9449 §8, §12.2).
pub const USE_NONCE: &str = "use_dpop_nonce";

/// What an accepted proof established.
#[derive(Debug, Clone)]
pub struct Binding {
    /// The JWK thumbprint the issued token is to be bound to (RFC 9449 §6.1).
    pub jkt: Kid,
    /// The nonce to put on the response, when this deployment issues them.
    ///
    /// RFC 9449 §8.2 offers two ways to hand a client its next nonce: a 400
    /// with `use_dpop_nonce`, which costs a round trip, or a `DPoP-Nonce`
    /// header on the *successful* response, which costs nothing. We do the
    /// second on every accepted request. Combined with the issuer's one-window
    /// lookback it means a well-behaved client sees `use_dpop_nonce` once —
    /// on its very first request — and never again, because it always holds a
    /// nonce minted no longer ago than its own previous request.
    pub next_nonce: Option<String>,
}

/// Why a request carrying a DPoP header was refused.
///
/// Opaque on purpose. The client learns an RFC 6749 §5.2 error object and, for
/// the nonce case, a fresh nonce; it does not learn which of RFC 9449 §4.3's
/// twelve checks its proof failed, because that is a description of this
/// server's state that an unauthenticated caller has not earned. The detail
/// goes to the log, where an operator can act on it.
#[derive(Debug)]
pub struct Refusal {
    code: &'static str,
    description: &'static str,
    status: StatusCode,
    nonce: Option<String>,
    /// For the log only. Never rendered.
    ///
    /// Boxed: this type is the `Err` half of every function below, and a
    /// `DpopError` carries the strings its `Display` needs. Paying for them on
    /// the success path — which is every request that works — would be the
    /// wrong trade.
    detail: Option<Box<DpopError>>,
}

impl Refusal {
    /// The OAuth error code this will be reported with.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The HTTP status this will be reported with.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// The nonce that will accompany it, if any.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// Why, for a log line. Absent when the refusal was not about the proof's
    /// contents.
    #[must_use]
    pub fn detail(&self) -> Option<&DpopError> {
        self.detail.as_deref()
    }

    /// A refusal for a request that carried no proof where one was required.
    ///
    /// RFC 9449 §5.2: with `dpop_bound_access_tokens` set, "the authorization
    /// server MUST reject token requests from the client that do not contain
    /// the DPoP header". The code is `invalid_dpop_proof` rather than
    /// `invalid_request`: the request is well formed, and what is missing is
    /// the proof.
    #[must_use]
    pub const fn missing_proof() -> Self {
        Self {
            code: INVALID_PROOF,
            description: "this client must present a DPoP proof",
            status: StatusCode::BAD_REQUEST,
            nonce: None,
            detail: None,
        }
    }

    fn multiple_headers() -> Self {
        Self {
            code: INVALID_PROOF,
            description: "more than one DPoP header was presented",
            status: StatusCode::BAD_REQUEST,
            nonce: None,
            detail: None,
        }
    }

    /// A refusal for a request this server could not finish processing.
    ///
    /// Public so that a caller composing this with its own storage calls can
    /// reach it *deliberately*. There is no `From<DomainError>`: mapping every
    /// storage failure to a retryable answer through `?` would make it easy to
    /// convert an error that is not one, and this is the one refusal that tells
    /// a client its request might succeed if it tries again.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            // RFC 6749 §5.2 has no code for "our store is down", and saying
            // `invalid_dpop_proof` would tell a client with a perfectly good
            // proof to go and fix it. `temporarily_unavailable` is what the
            // rest of this server says when storage fails, and it is the only
            // answer that leads a client to retry rather than to give up.
            code: "temporarily_unavailable",
            description: "the request could not be processed",
            status: StatusCode::SERVICE_UNAVAILABLE,
            nonce: None,
            detail: None,
        }
    }

    fn from_error(error: DpopError, nonce: Option<String>) -> Self {
        let wants_nonce = error.wants_nonce();
        Self {
            code: error.code(),
            description: if wants_nonce {
                "a DPoP nonce is required; retry with the one supplied"
            } else {
                "the DPoP proof did not check out"
            },
            status: StatusCode::BAD_REQUEST,
            // Only a nonce failure gets one. Attaching a fresh nonce to every
            // rejection would turn this endpoint into a nonce oracle for
            // requests that never had a valid proof.
            nonce: if wants_nonce { nonce } else { None },
            detail: Some(Box::new(error)),
        }
    }

    /// Renders this as an RFC 6749 §5.2 error object.
    ///
    /// `no-store` for the same reason every other error here carries it: RFC
    /// 9449 §8.2 asks that "responses that include the `DPoP-Nonce` HTTP header
    /// should be uncacheable ... to prevent the response from being used to
    /// serve a subsequent request and a stale nonce value from being used as a
    /// result."
    #[must_use]
    pub fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(json!({ "error": self.code, "error_description": self.description })),
        )
            .into_response();
        let headers = response.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
        if let Some(nonce) = self.nonce
            && let Ok(value) = HeaderValue::from_str(&nonce)
        {
            headers.insert(NONCE_HEADER, value);
        }
        response
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        Self::into_response(self)
    }
}

/// Checks DPoP proofs for one deployment.
///
/// Holds no tenant: the tenant is part of every call, because one process
/// serves all of them and the nonce is bound to the tenant's issuer.
pub struct DpopEndpoint {
    replay: Arc<dyn ReplayGuard>,
    nonces: Option<NonceIssuer>,
    max_age: Duration,
}

impl std::fmt::Debug for DpopEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DpopEndpoint")
            .field("nonces", &self.nonces.is_some())
            .field("max_age", &self.max_age)
            .finish_non_exhaustive()
    }
}

/// What a proof's `htu` is compared against (RFC 9449 §4.3 item 8).
///
/// An endpoint of the registry, and optionally one path segment under it: the
/// Grant Management API addresses a *resource* rather than an endpoint (Grant
/// Management ID1 §6.3), so its URL is the endpoint plus a `grant_id`.
///
/// A type rather than two parameters because the pair is one fact — "the URL
/// this request was made to, as this server derives it" — and because the
/// derivation must stay in this module: [`DpopEndpoint::check`] explains at
/// length why the URL is never taken from the request.
#[derive(Debug, Clone, Copy)]
pub struct ProofTarget<'a> {
    /// The path under the issuer this request was made to.
    base: Base<'a>,
    /// One path segment under it, when the request addresses a resource.
    segment: Option<&'a str>,
}

/// Where a target's path comes from.
///
/// Two sources, because this server has two documents. Almost every endpoint
/// is in the registry the OP metadata is rendered from; the SSF management
/// endpoints are not, because SSF 1.0 §7.1 advertises them in the
/// transmitter's own document instead, and putting them in the OP registry
/// would publish them in a document that does not define them.
#[derive(Debug, Clone, Copy)]
enum Base<'a> {
    /// An endpoint of [`Endpoint`], and therefore of the discovery document.
    Registry(Endpoint),
    /// A path this server mounts outside the registry, owned by the module
    /// that mounts it. Still not taken from the request: the caller passes a
    /// constant, and the URL is built from the tenant's issuer as ever.
    Mounted(&'a str),
}

impl<'a> ProofTarget<'a> {
    /// The endpoint's own URL, which is what every endpoint but one is
    /// addressed at.
    #[must_use]
    pub const fn at(endpoint: Endpoint) -> Self {
        Self {
            base: Base::Registry(endpoint),
            segment: None,
        }
    }

    /// A resource under the endpoint, at `endpoint.url()` + `/` + `segment`.
    #[must_use]
    pub const fn under(endpoint: Endpoint, segment: &'a str) -> Self {
        Self {
            base: Base::Registry(endpoint),
            segment: Some(segment),
        }
    }

    /// A path this server mounts that is not in the endpoint registry
    /// (`ast-0ju.3`).
    ///
    /// `path` is a constant belonging to the module that mounts the route —
    /// [`crate::http::ssf::CONFIGURATION_PATH`] is the only one today — so the
    /// URL a proof is compared against is the URL the router matched, and
    /// neither is derived from anything the caller sent.
    #[must_use]
    pub const fn at_path(path: &'a str) -> Self {
        Self {
            base: Base::Mounted(path),
            segment: None,
        }
    }

    /// The URL, built from the tenant's issuer and nothing the caller sent.
    fn url(self, issuer: &asterius_domain::Issuer) -> String {
        let base = match self.base {
            Base::Registry(endpoint) => endpoint.url(issuer),
            Base::Mounted(path) => format!("{}{path}", issuer.as_str()),
        };
        match self.segment {
            None => base,
            Some(segment) => format!("{base}/{segment}"),
        }
    }
}

impl DpopEndpoint {
    /// A checker over a replay store, with or without server nonces.
    ///
    /// `nonces` is `Some` exactly when [`asterius_domain::Feature::DpopNonce`]
    /// is on. RFC 9449 §8 and FAPI 2.0 SP §5.3.2.1 item 10 both make the
    /// mechanism optional, so it is a flag; §11.3's rule against a downgrade is
    /// what makes it all-or-nothing once it is on (see
    /// [`asterius_jose::dpop::NonceRule`]).
    #[must_use]
    pub fn new(replay: Arc<dyn ReplayGuard>, nonces: Option<NonceIssuer>) -> Self {
        Self {
            replay,
            nonces,
            max_age: dpop::DEFAULT_MAX_AGE,
        }
    }

    /// A checker for a deployment, from its capabilities.
    ///
    /// The "nonces if and only if [`Feature::DpopNonce`]" decision lives here
    /// rather than at the composition root, so that a second endpoint wired up
    /// later cannot make it differently. RFC 9449 §11.3 is what makes a
    /// divergence dangerous rather than merely inconsistent: an endpoint that
    /// stopped requiring the nonce would be the downgrade the nonce exists to
    /// prevent.
    ///
    /// `secret` is the HMAC key the nonces are derived from. `None` generates a
    /// per-process one, which is correct for a single replica and wrong for
    /// several — see [`NonceIssuer`]. Nothing is generated at all when the flag
    /// is off, so a deployment that does not use nonces does not hold a key for
    /// them.
    ///
    /// # Errors
    ///
    /// Returns [`asterius_jose::JoseError`] if a secret has to be generated and
    /// the CSPRNG is unavailable — a reason not to start, rather than to carry
    /// on with a predictable nonce.
    pub fn for_capabilities(
        replay: Arc<dyn ReplayGuard>,
        capabilities: &Capabilities,
        secret: Option<&[u8]>,
    ) -> Result<Self, asterius_jose::JoseError> {
        let nonces = if capabilities.is_enabled(Feature::DpopNonce) {
            Some(match secret {
                Some(secret) => NonceIssuer::from_secret(secret),
                None => NonceIssuer::generate()?,
            })
        } else {
            None
        };
        Ok(Self::new(replay, nonces))
    }

    /// Narrows how old a proof may be. Clamped by the JOSE layer.
    #[must_use]
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Whether this client must present a proof (RFC 9449 §5.2).
    ///
    /// `dpop_bound_access_tokens` is a promise the client made at registration
    /// — "I always use DPoP" — and the RFC turns it into a server-side
    /// obligation, because a client that can silently stop using DPoP is a
    /// client whose tokens an attacker can arrange to be bearer tokens.
    #[must_use]
    pub const fn required_for(client: &Client) -> bool {
        client.registration.token_binding.is_dpop_bound()
    }

    /// Checks the proof on a request, if there is one.
    ///
    /// Returns `Ok(None)` when the request carries no `DPoP` header at all.
    /// Whether that is acceptable is the caller's decision and depends on the
    /// client ([`DpopEndpoint::required_for`]), which is not known until after
    /// client authentication — so this function reports the absence rather than
    /// judging it.
    ///
    /// # Where `htu` is compared against, and why not the request
    ///
    /// The expected URL is built from `tenant.issuer` and `endpoint`, which is
    /// byte-for-byte what the metadata document advertises and therefore what
    /// the client used. It is emphatically **not** built from `Host`, from
    /// `Forwarded`, or from the request target.
    ///
    /// That is the whole point. `htu` exists to stop a proof captured at one
    /// endpoint being replayed at another (RFC 9449 §11). If the value it were
    /// compared against came from a header, an attacker who can set that header
    /// — anyone, on the way in, before the proxy is trusted — could make any
    /// `htu` match by simply asking for it, and the check would compare an
    /// attacker's claim against the same attacker's claim.
    ///
    /// # Errors
    ///
    /// Returns a [`Refusal`] the caller renders. The `jti` is claimed last, so
    /// a proof rejected for any other reason has not consumed one — otherwise
    /// anyone who can reach this endpoint could burn a key's identifiers with
    /// proofs that were never going to be accepted.
    pub async fn check(
        &self,
        tenant: &Tenant,
        endpoint: Endpoint,
        method: &Method,
        headers: &HeaderMap,
        now: OffsetDateTime,
    ) -> Result<Option<Binding>, Refusal> {
        self.check_for(
            tenant,
            ProofTarget::at(endpoint),
            method,
            headers,
            None,
            now,
        )
        .await
    }

    /// The same check, for a proof that accompanies an access token.
    ///
    /// RFC 9449 §4.3 item 12: "if presented to a protected resource in
    /// conjunction with an access token, ensure that the value of the `ath`
    /// claim equals the hash of that access token". `bound_to` is that token,
    /// exactly as it arrived on the wire — the hash is over the string the
    /// client sent, so anything that re-encoded it would compute a digest of
    /// something nobody presented.
    ///
    /// It is a separate entry point rather than an argument on [`check`]
    /// because the two callers are different animals. At the token endpoint
    /// there is no access token yet and §4.2 requires no `ath`; at a protected
    /// resource there is one and §4.3 requires it. Passing `None` here would
    /// be a way to turn the resource-server rule off, so the token endpoint
    /// does not get to pass it at all.
    ///
    /// [`check`]: DpopEndpoint::check
    ///
    /// # Errors
    ///
    /// A [`Refusal`], as [`check`] — including one for a proof whose `ath` is
    /// missing or names another token.
    pub async fn check_with_access_token(
        &self,
        tenant: &Tenant,
        endpoint: Endpoint,
        method: &Method,
        headers: &HeaderMap,
        bound_to: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Binding>, Refusal> {
        self.check_for(
            tenant,
            ProofTarget::at(endpoint),
            method,
            headers,
            Some(bound_to),
            now,
        )
        .await
    }

    /// The same check, for a resource *under* an endpoint.
    ///
    /// Grant Management ID1 §6.3 builds the resource URL by appending a
    /// `grant_id` to the grant management endpoint, so the URL a client makes
    /// its proof over is not the endpoint's own — and RFC 9449 §4.3 item 8
    /// compares `htu` against "the HTTP URI used for the request, without
    /// query and fragment parts", which includes that path segment.
    ///
    /// `target` names the segment the *router* matched, not a header: this is
    /// still not built from `Host` or from the request target, for the reason
    /// [`check`] gives. What it buys is that a proof captured for one grant
    /// cannot be replayed against another — with the endpoint's bare URL it
    /// could, because every grant under it would share one `htu`.
    ///
    /// The segment is appended as the router decoded it. A client that
    /// percent-encoded something in it made its proof over the encoded form
    /// and will find the two disagree; a `grant_id` is a UUID, so there is
    /// nothing there to encode.
    ///
    /// [`check`]: DpopEndpoint::check
    ///
    /// # Errors
    ///
    /// A [`Refusal`], as [`check_with_access_token`].
    ///
    /// [`check_with_access_token`]: DpopEndpoint::check_with_access_token
    pub async fn check_with_access_token_under(
        &self,
        tenant: &Tenant,
        target: ProofTarget<'_>,
        method: &Method,
        headers: &HeaderMap,
        bound_to: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Binding>, Refusal> {
        self.check_for(tenant, target, method, headers, Some(bound_to), now)
            .await
    }

    async fn check_for(
        &self,
        tenant: &Tenant,
        target: ProofTarget<'_>,
        method: &Method,
        headers: &HeaderMap,
        bound_to: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Option<Binding>, Refusal> {
        let Some(raw) = single_header(headers)? else {
            return Ok(None);
        };

        // Built here, from the issuer. See the note above.
        let url = target.url(&tenant.issuer);
        let Ok(uri) = NormalisedUri::parse(&url) else {
            // Unreachable with a valid issuer, and a configuration fault rather
            // than the client's if it ever happens. Refusing is the only safe
            // reading: the alternative is to compare `htu` against something
            // this server could not normalise.
            tracing::error!(tenant = %tenant.id, %url, "this endpoint's own URL will not normalise");
            return Err(Refusal::unavailable());
        };

        let issuer = tenant.issuer.as_str();
        let mut expectation = Expectation::new(method.as_str(), &uri).with_max_age(self.max_age);
        if let Some(nonces) = &self.nonces {
            expectation = expectation.requiring_nonce(nonces, issuer);
        }
        // RFC 9449 §4.3 item 12. The token as it arrived, not a re-encoding of
        // it: `ath` hashes the bytes the client sent.
        if let Some(access_token) = bound_to {
            expectation = expectation.with_access_token(access_token);
        }

        let proof = dpop::check(raw, &expectation, now)
            .map_err(|error| Refusal::from_error(error, self.fresh_nonce(issuer, now)))?;

        // Last, and only for a proof that is otherwise good. RFC 9449 §11.1:
        // the `jti` is what makes a captured proof single-use, and the store is
        // shared because a per-process cache would be single use per replica.
        // The subject is the thumbprint, which is what the port's documentation
        // specifies: two clients that pick the same `jti` are unrelated events,
        // and a shared namespace would let one burn the other's identifiers.
        match self
            .replay
            .claim(
                &tenant.id,
                ReplayPurpose::DpopProof,
                proof.jkt.as_str(),
                &proof.jti,
                proof.replay_expires_at,
            )
            .await
        {
            Ok(ReplayCheck::FirstUse) => Ok(Some(Binding {
                jkt: proof.jkt,
                next_nonce: self.fresh_nonce(issuer, now),
            })),
            Ok(ReplayCheck::Replay) => Err(Refusal {
                code: INVALID_PROOF,
                description: "this DPoP proof has already been used",
                status: StatusCode::BAD_REQUEST,
                nonce: None,
                detail: None,
            }),
            // An unavailable replay store is not permission to accept a replay.
            Err(failure) => {
                tracing::error!(%failure, tenant = %tenant.id, "the DPoP replay store is unavailable");
                Err(Refusal::unavailable())
            }
        }
    }

    /// The nonce a client should use next, when this deployment issues them.
    fn fresh_nonce(&self, audience: &str, now: OffsetDateTime) -> Option<String> {
        self.nonces
            .as_ref()
            .map(|issuer| issuer.issue(audience, now))
    }

    /// Attaches a `DPoP-Nonce` header to a successful response (RFC 9449 §8.2).
    ///
    /// A no-op when this deployment issues no nonces, so a caller does not have
    /// to know whether it does.
    pub fn supply_nonce(response: &mut Response, binding: &Binding) {
        if let Some(nonce) = &binding.next_nonce
            && let Ok(value) = HeaderValue::from_str(nonce)
        {
            response.headers_mut().insert(NONCE_HEADER, value);
        }
    }
}

/// Reconciles a PAR request's two ways of pinning a DPoP key (RFC 9449 §10.1).
///
/// A pushed authorization request may carry `dpop_jkt` in its body, or a `DPoP`
/// header whose key's thumbprint means the same thing, or both. The RFC
/// requires an authorization server that supports PAR and DPoP to accept both
/// spellings, and to reject the request when they disagree — a request that
/// names two keys does not have a key.
///
/// # Errors
///
/// Returns a [`Refusal`] when the two disagree.
pub fn reconcile_par_key(
    from_header: Option<&Kid>,
    from_parameter: Option<&str>,
) -> Result<Option<String>, Refusal> {
    dpop::reconcile_pinned_key(from_header, from_parameter).map_err(|error| Refusal {
        code: INVALID_PROOF,
        description: "dpop_jkt does not match the key in the DPoP header",
        status: StatusCode::BAD_REQUEST,
        nonce: None,
        detail: Some(Box::new(error)),
    })
}

/// Whether the proof at the token endpoint is for the key the code was bound to.
///
/// RFC 9449 §10, and FAPI 2.0 SP §5.3.2.1 item 12, which makes supporting it
/// mandatory for a DPoP deployment. `pinned` is what the pushed authorization
/// request stored on the request; `presented` is the thumbprint from the proof.
///
/// # Errors
///
/// Returns a [`Refusal`] when a request pinned a key and the token request does
/// not present it — including when it presents no proof at all.
pub fn check_pinned_key(pinned: Option<&str>, presented: Option<&Kid>) -> Result<(), Refusal> {
    if dpop::matches_pinned_key(pinned, presented) {
        return Ok(());
    }
    Err(Refusal {
        // RFC 9449 §10 says only "MUST reject". `invalid_dpop_proof` is the
        // honest code: the proof is well formed and is for the wrong key, which
        // is a fact about the proof.
        code: INVALID_PROOF,
        description: "the DPoP key does not match the one this request was bound to",
        status: StatusCode::BAD_REQUEST,
        nonce: None,
        detail: None,
    })
}

/// The one `DPoP` header, or none.
///
/// RFC 9449 §4.3 item 1. A second header is refused rather than resolved,
/// because every way of resolving it — first, last, longest — is a rule an
/// attacker can aim at when this server and something in front of it happen to
/// have picked different ones.
fn single_header(headers: &HeaderMap) -> Result<Option<&str>, Refusal> {
    let mut values = headers.get_all(HEADER).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Refusal::multiple_headers());
    }
    // §4.1: the value is `token68`, which is a subset of visible ASCII. A
    // header this server cannot read as a string is not a proof, and there is
    // nothing to be gained by guessing an encoding for it.
    first
        .to_str()
        .map(Some)
        .map_err(|_| Refusal::from_error(DpopError::MissingKey, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{DomainError, TenantId};

    #[derive(Debug)]
    struct NeverAsked;

    #[async_trait::async_trait]
    impl ReplayGuard for NeverAsked {
        async fn claim(
            &self,
            _: &TenantId,
            _: ReplayPurpose,
            _: &str,
            _: &str,
            _: OffsetDateTime,
        ) -> Result<ReplayCheck, DomainError> {
            panic!("the replay store was reached by a request with no usable proof");
        }
    }

    /// The audience a nonce is bound to: a tenant's issuer.
    const AUDIENCE: &str = "https://as.example/t/demo";

    /// A deployment with `Feature::DpopNonce` on and nothing else.
    fn nonce_capabilities() -> Capabilities {
        Capabilities {
            dpop_nonce: true,
            request_object: true,
            ..Capabilities::default()
        }
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(HEADER, HeaderValue::from_str(value).expect("header value"));
        }
        map
    }

    #[test]
    fn no_dpop_header_is_an_absence_and_not_a_failure() {
        assert_eq!(single_header(&HeaderMap::new()).expect("no header"), None);
    }

    /// RFC 9449 §4.3 item 1.
    #[test]
    fn two_dpop_headers_are_refused_without_either_being_looked_at() {
        let refusal = single_header(&headers(&["one", "two"])).expect_err("refused");
        assert_eq!(refusal.code(), INVALID_PROOF);
        assert_eq!(refusal.status(), StatusCode::BAD_REQUEST);
        assert_eq!(refusal.nonce(), None);
    }

    #[test]
    fn one_dpop_header_is_read_as_a_string() {
        assert_eq!(
            single_header(&headers(&["a.b.c"])).expect("one header"),
            Some("a.b.c")
        );
    }

    /// A nonce is attached to a nonce failure and to nothing else: a rejection
    /// that always carried one would be a nonce oracle for requests that never
    /// had a valid proof.
    #[test]
    fn only_a_nonce_failure_is_handed_a_nonce() {
        let nonce = Some("a-nonce".to_owned());
        assert_eq!(
            Refusal::from_error(DpopError::NonceRequired, nonce.clone()).nonce(),
            Some("a-nonce")
        );
        assert_eq!(
            Refusal::from_error(DpopError::NonceStale, nonce.clone()).nonce(),
            Some("a-nonce")
        );
        assert_eq!(
            Refusal::from_error(DpopError::MethodMismatch, nonce).nonce(),
            None
        );
    }

    #[test]
    fn a_nonce_failure_asks_the_client_to_retry_rather_than_blaming_its_key() {
        let refusal = Refusal::from_error(DpopError::NonceRequired, Some("n".to_owned()));
        assert_eq!(refusal.code(), USE_NONCE);
        assert_eq!(refusal.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_missing_proof_is_reported_as_a_missing_proof() {
        assert_eq!(Refusal::missing_proof().code(), INVALID_PROOF);
    }

    /// RFC 9449 §10: a code bound to a key is redeemable only with that key,
    /// and in particular not without a proof at all.
    #[test]
    fn a_pinned_key_must_be_presented_at_the_token_endpoint() {
        let pinned = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
        let key = Kid::new(pinned);
        let other = Kid::new("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I");

        assert!(check_pinned_key(Some(pinned), Some(&key)).is_ok());
        assert!(check_pinned_key(None, Some(&key)).is_ok());
        assert!(check_pinned_key(None, None).is_ok());
        assert_eq!(
            check_pinned_key(Some(pinned), Some(&other))
                .expect_err("refused")
                .code(),
            INVALID_PROOF
        );
        assert_eq!(
            check_pinned_key(Some(pinned), None)
                .expect_err("refused")
                .code(),
            INVALID_PROOF
        );
    }

    /// RFC 9449 §10.1: both spellings are supported, and disagreement is a
    /// rejection.
    #[test]
    fn a_par_request_may_pin_its_key_either_way_but_not_two_ways_at_once() {
        let key = Kid::new("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        let other = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

        assert_eq!(reconcile_par_key(None, None).expect("neither"), None);
        assert_eq!(
            reconcile_par_key(Some(&key), None).expect("header only"),
            Some(key.as_str().to_owned())
        );
        assert_eq!(
            reconcile_par_key(None, Some(other)).expect("parameter only"),
            Some(other.to_owned())
        );
        assert_eq!(
            reconcile_par_key(Some(&key), Some(key.as_str())).expect("agreeing"),
            Some(key.as_str().to_owned())
        );
        assert_eq!(
            reconcile_par_key(Some(&key), Some(other))
                .expect_err("disagreeing")
                .code(),
            INVALID_PROOF
        );
    }

    /// The store must not be reached by a request that has no proof to check.
    #[tokio::test]
    async fn a_request_with_no_proof_never_reaches_the_replay_store() {
        let checker = DpopEndpoint::new(Arc::new(NeverAsked), None);
        let tenant = Tenant {
            id: TenantId::new("demo"),
            issuer: asterius_domain::Issuer::parse("https://as.example/t/demo").expect("issuer"),
            default_resource: "https://api.example/".to_owned(),
            custom_host: None,
            display_name: "demo".to_owned(),
            status: asterius_domain::TenantStatus::Active,
            refresh: asterius_domain::RefreshPolicy::default(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let outcome = checker
            .check(
                &tenant,
                Endpoint::Token,
                &Method::POST,
                &HeaderMap::new(),
                OffsetDateTime::UNIX_EPOCH,
            )
            .await;
        assert!(matches!(outcome, Ok(None)));
    }

    /// Two replicas, one configured secret (`ast-a05.11`). This is the whole
    /// reason the key is configurable: a client handed a nonce by one replica
    /// must be able to spend it at the other, or `use_dpop_nonce` stops being
    /// a once-per-client event and becomes a per-request coin flip.
    #[test]
    fn two_endpoints_sharing_a_secret_accept_each_other_s_nonces() {
        let capabilities = nonce_capabilities();
        let secret = [0x11_u8; 32];

        let one = DpopEndpoint::for_capabilities(
            Arc::new(NeverAsked),
            &capabilities,
            Some(secret.as_slice()),
        )
        .expect("an endpoint over a supplied secret");
        let other = DpopEndpoint::for_capabilities(
            Arc::new(NeverAsked),
            &capabilities,
            Some(secret.as_slice()),
        )
        .expect("an endpoint over the same secret");

        let nonce = one
            .fresh_nonce(AUDIENCE, OffsetDateTime::UNIX_EPOCH)
            .expect("the flag is on, so a nonce is issued");
        assert!(
            other
                .nonces
                .as_ref()
                .expect("the flag is on, so nonces exist")
                .accepts(&nonce, AUDIENCE, OffsetDateTime::UNIX_EPOCH)
        );
    }

    /// The default, documented rather than desired: with no secret configured
    /// each process mints its own, so a second replica rejects the first's
    /// nonces. Harmless per RFC 9449 §8 — the client is told to retry — but a
    /// round trip on every request that lands on the wrong replica.
    #[test]
    fn two_endpoints_without_a_secret_reject_each_other_s_nonces() {
        let capabilities = nonce_capabilities();

        let one = DpopEndpoint::for_capabilities(Arc::new(NeverAsked), &capabilities, None)
            .expect("an endpoint over a generated secret");
        let other = DpopEndpoint::for_capabilities(Arc::new(NeverAsked), &capabilities, None)
            .expect("an endpoint over its own generated secret");

        let nonce = one
            .fresh_nonce(AUDIENCE, OffsetDateTime::UNIX_EPOCH)
            .expect("the flag is on, so a nonce is issued");
        assert!(
            !other
                .nonces
                .as_ref()
                .expect("the flag is on, so nonces exist")
                .accepts(&nonce, AUDIENCE, OffsetDateTime::UNIX_EPOCH)
        );
    }

    /// A secret is material for a flag that is off, so none is held.
    #[test]
    fn a_supplied_secret_is_not_held_when_the_flag_is_off() {
        let endpoint = DpopEndpoint::for_capabilities(
            Arc::new(NeverAsked),
            &Capabilities::default(),
            Some([0x11_u8; 32].as_slice()),
        )
        .expect("an endpoint with no nonces");

        assert!(endpoint.nonces.is_none());
    }
}
