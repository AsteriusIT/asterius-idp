//! The `authorization_code` grant (RFC 6749 §4.1.3, OIDC Core §3.1.3).
//!
//! Redeems a code for an access token and, when the grant carries `openid`, an
//! ID token. Every binding recorded when the code was issued (`ast-gxh.4`) is
//! checked here, and this is the only place they are checked: the code is a
//! bearer credential travelling through a browser, so the checks are what
//! stand between a stolen one and a token.
//!
//! # The code is spent before it is judged
//!
//! [`PgCodeRepository::redeem`] consumes the code in the statement that reads
//! it, so a request that then fails PKCE has still burned it. That is
//! deliberate and it is the safe direction. An attacker holding a stolen code
//! but not the `code_verifier` gets exactly one attempt; brute-forcing the
//! verifier would need a code that survives a wrong guess, and this one does
//! not. It also means the timing of the checks below cannot leak anything
//! reusable, because there is nothing left to reuse (threat model, A1/A2 on
//! `ast-gxh.3`).
//!
//! Burning is not revoking. A first use that fails a check kills the code and
//! leaves the grant alone; only a *second* use revokes, because only a second
//! use proves the code reached somebody it should not have.
//!
//! # Why the checks are in this order
//!
//! Ownership before content: a code that belongs to another client is refused
//! before its `redirect_uri` or verifier is looked at, so a client cannot use
//! the token endpoint to ask questions about a code it does not hold. Every
//! refusal below is the same `invalid_grant` with the same description, so the
//! order is not observable from outside — it is about what the server does,
//! not about what it says.

use asterius_domain::entities::client::GrantType;
use asterius_domain::entities::grant::GrantStatus;
use asterius_domain::keys::Signer;
use asterius_domain::ports::SessionRepository;
use asterius_domain::{Client, DomainError, Grant, Kid, Tenant};
use asterius_oidc::form::Parameters;
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::{AccessToken, Audience, Authentication, Confirmation};
use asterius_oidc::tokens::id_token::IdToken;
use asterius_oidc::{code, pkce};
use asterius_store_pg::{PgCodeRepository, PgGrantRepository, PgUserRepository, Redemption};
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use time::OffsetDateTime;

use crate::http::dpop;
use crate::http::token::{GrantHandler, not_issued, refused};

/// What every refusal in this file says.
///
/// One constant for all of them. RFC 6749 §5.2 defines `invalid_grant` as
/// covering a code that is "invalid, expired, revoked, does not match the
/// redirection URI used in the authorization request, or was issued to another
/// client" — five distinct facts behind one code, and the specification chose
/// that. Saying which one applies would tell somebody holding a stolen code
/// whether it was the code or the verifier that was wrong.
const INVALID_GRANT: &str = "the authorization code cannot be redeemed";

/// Redeems authorization codes.
///
/// Built per request rather than once, because two of its fields are
/// per-request: the instant the request arrived, and the DPoP key that came
/// with it. [`crate::http::protocol`] constructs it inside the token endpoint,
/// where both are already in hand.
pub struct AuthorizationCode<'a> {
    /// Codes for this tenant.
    pub codes: &'a PgCodeRepository,
    /// Grants for this tenant.
    pub grants: &'a PgGrantRepository,
    /// Sessions for this tenant, for `auth_time`, `acr` and `amr`.
    pub sessions: &'a dyn SessionRepository,
    /// Users for this tenant, read only to resolve the claims the grant
    /// covers (OIDC Core §5.4, §5.5). Nothing here writes a user.
    pub users: &'a PgUserRepository,
    /// Signs both tokens.
    pub signer: &'a dyn Signer,
    /// The thumbprint of the DPoP proof presented with this request.
    ///
    /// `None` when the request carried no proof, which for this grant is a
    /// refusal rather than a mode: FAPI 2.0 SP §5.3.2.1 item 4 admits no
    /// unbound access token, so there is no token this handler could issue.
    pub proof_key: Option<&'a Kid>,
    /// When the request arrived. One instant for every check and both tokens,
    /// so `iat`, `exp` and the code's expiry are judged against one clock
    /// reading rather than several.
    pub now: OffsetDateTime,
}

impl std::fmt::Debug for AuthorizationCode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The proof key is a public thumbprint and the repositories hold a
        // pool, but neither is worth carrying into a log line, and `now` is
        // the only field that says anything about this particular request.
        f.debug_struct("AuthorizationCode")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// What the session the grant was made in contributes to the tokens.
///
/// The two travel together because they come from one row and mean nothing
/// apart: `auth_time`, `acr` and `amr` say *when and how* the person
/// authenticated, and `sid` names the session they did it in.
struct SessionFacts {
    authentication: Authentication,
    /// The session's public identifier, never its lookup digest.
    sid: String,
}

/// What one redemption contributes to its ID token.
///
/// A struct rather than five more parameters, because four of the five are
/// values this redemption computed a moment earlier and the fifth — `released`
/// — is the one a reader has to be able to see is *the grant's*. A signature
/// long enough that its arguments are matched by position is a signature in
/// which the request's claims could be passed instead.
struct IdTokenParts<'a> {
    /// The authority the tokens are minted from.
    claimed: &'a asterius_domain::ClaimedGrant,
    /// `auth_time`, `acr`, `amr` and `sid`.
    session: &'a SessionFacts,
    /// The signed access token, for OIDC Core §3.1.3.6's `at_hash`.
    access_token: &'a str,
    /// `nonce`, echoed byte-exact when the authorization request carried one.
    nonce: Option<&'a str>,
    /// The claims the grant covers, from `claims::resolve_for_grant`.
    released: serde_json::Map<String, serde_json::Value>,
}

/// Why a redemption stopped.
enum Failure {
    /// The client can act on it: an RFC 6749 §5.2 code and its description.
    Client(&'static str, &'static str),
    /// The deployment is at fault. Rendered by [`not_issued`], which logs it.
    Server(DomainError),
    /// A DPoP refusal, which already knows how to render itself (RFC 9449 §7
    /// has its own `WWW-Authenticate` shape).
    Dpop(dpop::Refusal),
}

impl From<DomainError> for Failure {
    fn from(error: DomainError) -> Self {
        Self::Server(error)
    }
}

/// The refusal every failed binding check produces.
const fn invalid_grant() -> Failure {
    Failure::Client("invalid_grant", INVALID_GRANT)
}

#[async_trait::async_trait]
impl GrantHandler for AuthorizationCode<'_> {
    fn grant(&self) -> GrantType {
        GrantType::AuthorizationCode
    }

    async fn handle(&self, tenant: &Tenant, client: &Client, params: &Parameters) -> Response {
        match self.redeem(tenant, client, params).await {
            Ok(response) => response,
            Err(Failure::Client(code, description)) => refused(code, description),
            Err(Failure::Server(error)) => not_issued(tenant, client, &error),
            Err(Failure::Dpop(refusal)) => refusal.into_response(),
        }
    }
}

impl AuthorizationCode<'_> {
    /// The redemption itself, with failures as `Err` so the checks read in
    /// order rather than as a staircase of early returns.
    async fn redeem(
        &self,
        tenant: &Tenant,
        client: &Client,
        params: &Parameters,
    ) -> Result<Response, Failure> {
        // RFC 6749 §4.1.3: `code` is REQUIRED. Absent is `invalid_request`
        // (§5.2, "missing a required parameter"); present but not the shape a
        // code has is `invalid_grant`, because that is a statement about a
        // credential rather than about the form.
        let presented = params
            .get("code")
            .map_err(|_| Failure::Client("invalid_request", "code was sent more than once"))?
            .ok_or(Failure::Client("invalid_request", "code is required"))?;
        let digest = code::digest_of(presented).map_err(|_| invalid_grant())?;

        let binding = match self.codes.redeem(&digest, self.now).await? {
            Redemption::Redeemed(binding) => binding,
            // One answer for two facts, deliberately. `NotFound` is a code
            // that never existed or has expired — the repository merges those
            // two as well, because whether a code was ever real is not
            // something the token endpoint should confirm. `Replayed` is a
            // second use, and by the time it is returned `redeem` has already
            // revoked the grant and the refresh tokens minted from the first
            // use (RFC 6749 §4.1.2, RFC 9700 §4.1.2), so there is nothing to
            // undo here either. Distinguishing them in the response would tell
            // whoever holds a stolen code whether the honest client has been
            // here first.
            Redemption::NotFound | Redemption::Replayed => return Err(invalid_grant()),
        };

        // OIDC Core §3.1.3.2: the code must have been issued to the client now
        // presenting it. First, so that nothing below tells an authenticated
        // client anything about another client's code.
        if binding.client_id != client.id.as_str() {
            return Err(invalid_grant());
        }

        Self::check_redirect_uri(client, params, &binding.redirect_uri)?;

        // RFC 7636 §4.6. `pkce::redeem` parses the verifier and compares in
        // constant time; a malformed verifier and a wrong one are one answer.
        let challenge = asterius_oidc::pkce::CodeChallenge::parse(
            Some(&binding.code_challenge),
            Some(pkce::S256),
        )
        .map_err(|_| {
            // The challenge was validated at PAR, so a stored one that
            // no longer parses is a corrupted row, not a bad request.
            Failure::Server(DomainError::invalid(
                "code_challenge",
                "the stored code challenge is not a valid S256 challenge",
            ))
        })?;
        let verifier = params.get("code_verifier").map_err(|_| {
            Failure::Client("invalid_request", "code_verifier was sent more than once")
        })?;
        pkce::redeem(&challenge, verifier).map_err(|_| invalid_grant())?;

        let jkt = self.check_dpop(binding.dpop_jkt.as_deref())?;

        // The grant carries the scopes, resources and subject; the claim
        // carries the authority to mint from it. Both are needed, and `claim`
        // is what stamps `claimed_at` — the grant stops being `Pending` here,
        // at the moment a credential is actually taken from it.
        let grant = self
            .grants
            .find(&binding.grant_id)
            .await?
            .ok_or_else(invalid_grant)?;
        // A grant revoked or expired between the authorization response and
        // this request. The code was still live, so this is the check that
        // catches it.
        if !matches!(
            grant.status(self.now),
            GrantStatus::Pending | GrantStatus::Active
        ) {
            return Err(invalid_grant());
        }
        let claimed = self.grants.claim(&binding.grant_id, self.now).await?;

        let session = self.authentication(&grant).await?;

        // RFC 9068 §3: an access token must name a resource. `of_grant` is
        // `None` until resource indicators land (`ast-gxh.7`), and the tenant's
        // configured default is what fills it — chosen by an operator rather
        // than invented at signing time.
        let audience = match Audience::of_grant(&grant) {
            Some(audience) => audience,
            None => Audience::new([tenant.default_resource.as_str()]).map_err(|_| {
                Failure::Server(DomainError::invalid(
                    "default_resource",
                    "this tenant's default resource is not a usable audience",
                ))
            })?,
        };

        let confirmation = Confirmation::dpop(jkt).map_err(|_| {
            Failure::Server(DomainError::invalid(
                "cnf",
                "the DPoP thumbprint is not a usable confirmation",
            ))
        })?;

        let access = AccessToken::new(
            &tenant.issuer,
            &grant,
            &claimed,
            audience,
            confirmation,
            JwtId::generate(),
            self.now,
        )
        .authenticated_by(session.authentication.clone())
        .build()
        .map_err(|e| Failure::Server(DomainError::invalid("access_token", e.to_string())))?;

        let access_token = self
            .signer
            .sign(
                &tenant.id,
                access.required_algorithm(),
                access.typ(),
                access.claims(),
            )
            .await?;

        // OIDC Core §3.1.3.3: an ID token accompanies the response only when
        // the grant is an OpenID Connect one. `openid` is on the grant rather
        // than on the request, because the scope was settled at consent.
        let id_token = if grant.scopes.contains("openid") {
            let parts = IdTokenParts {
                claimed: &claimed,
                session: &session,
                access_token: access_token.as_str(),
                nonce: binding.nonce.as_deref(),
                // From the grant, never from the request. See `released_claims`.
                released: self.released_claims(&grant).await?,
            };
            Some(self.sign_id_token(tenant, client, parts).await?)
        } else {
            None
        };

        Ok(Self::response(
            &grant,
            access_token.as_str(),
            id_token.as_deref(),
        ))
    }

    /// OIDC Core §3.1.3.2 and threat model A1/G1 on `ast-a05.2`.
    ///
    /// Two comparisons, because they answer different questions. The first is
    /// the specification's: the value must be *identical* to the one the
    /// authorization request carried, which is a byte comparison against what
    /// PAR stored and nothing else — no parsing, no normalisation, no loopback
    /// exception, because a code was issued for one exact string.
    ///
    /// The second consults the registered set again. RFC 9126 §2.4 would let an
    /// authorization server trust a `redirect_uri` because the client
    /// authenticated; ADR-0005 declines that relaxation *on every request*, and
    /// this is the request where a registration edited between the
    /// authorization response and the redemption would otherwise slip through.
    fn check_redirect_uri(
        client: &Client,
        params: &Parameters,
        issued_for: &str,
    ) -> Result<(), Failure> {
        let presented = params
            .get("redirect_uri")
            .map_err(|_| {
                Failure::Client("invalid_request", "redirect_uri was sent more than once")
            })?
            // PAR records a `redirect_uri` on every request it accepts, so
            // RFC 6749 §4.1.3's "REQUIRED, if the redirect_uri parameter was
            // included in the authorization request" is always required here.
            .ok_or(Failure::Client(
                "invalid_request",
                "redirect_uri is required",
            ))?;

        if presented != issued_for {
            return Err(invalid_grant());
        }
        // A native client's registered loopback URI varies only by port
        // (RFC 8252 §7.3), which is why the application type is passed rather
        // than assumed.
        let application_type = client.registration.application_type;
        if !client
            .registration
            .redirect_uris
            .iter()
            .any(|registered| registered.matches(presented, application_type))
        {
            return Err(invalid_grant());
        }
        Ok(())
    }

    /// RFC 9449 §10 and FAPI 2.0 SP §5.3.2.1 items 4 and 12.
    ///
    /// Two rules that meet here. A code pinned to a `dpop_jkt` at PAR is
    /// redeemable only with a proof for that key — including, explicitly, not
    /// with no proof at all. And every access token this server issues is
    /// sender-constrained, so a proof is required even for a code that was
    /// pinned to nothing: there is no unbound token to fall back to.
    fn check_dpop<'k>(&'k self, pinned: Option<&str>) -> Result<&'k Kid, Failure> {
        dpop::check_pinned_key(pinned, self.proof_key).map_err(Failure::Dpop)?;
        // `check_pinned_key` is satisfied by a code that pinned nothing and a
        // request that proved nothing. This is the other half.
        self.proof_key.ok_or_else(|| {
            Failure::Client(
                "invalid_grant",
                "a DPoP proof is required to redeem an authorization code",
            )
        })
    }

    /// `auth_time`, `acr` and `amr`, from the session the grant was made in.
    ///
    /// Not optional, and not defaulted. OIDC Core §2 makes `auth_time` a
    /// statement about when the user actually authenticated; inventing one
    /// from the grant's own timestamps would produce a claim a relying party
    /// uses for step-up decisions and that this server cannot stand behind. A
    /// grant whose session has gone is a server-side inconsistency, so it is
    /// reported as one rather than papered over.
    async fn authentication(&self, grant: &Grant) -> Result<SessionFacts, Failure> {
        let digest = grant.session.as_ref().ok_or_else(|| {
            Failure::Server(DomainError::invalid(
                "grant",
                "an authorization_code grant names no session",
            ))
        })?;
        let session = self.sessions.find(digest.as_str()).await?.ok_or_else(|| {
            Failure::Server(DomainError::invalid(
                "session",
                "the session this grant was made in no longer exists",
            ))
        })?;

        Ok(SessionFacts {
            authentication: Authentication {
                authenticated_at: session.authenticated_at,
                acr: session.acr.clone(),
                amr: session
                    .amr
                    .iter()
                    .map(|method| method.as_str().to_owned())
                    .collect(),
            },
            // Not `id_digest`: that is the lookup key and it is rewritten on
            // every rotation. See `Session::public_sid` (`ast-o4u.5`).
            sid: session.public_sid.clone(),
        })
    }

    /// The claims this grant releases into its ID token.
    ///
    /// Read from the grant and from the user row, and from nothing else. The
    /// authorization request is not consulted: it says what a client asked
    /// for, and an hour and a consent screen separate that from what this
    /// token may carry.
    ///
    /// A grant with no user, or whose user is gone, is a server-side
    /// inconsistency and is reported as one — the same treatment
    /// [`Self::authentication`] gives a vanished session. Releasing nothing
    /// instead would mint an authentication assertion about somebody this
    /// server can no longer describe.
    async fn released_claims(
        &self,
        grant: &Grant,
    ) -> Result<serde_json::Map<String, serde_json::Value>, Failure> {
        let id = grant.user.ok_or_else(|| {
            Failure::Server(DomainError::invalid(
                "grant",
                "an authorization_code grant names no user",
            ))
        })?;
        let user = self.users.find(id).await?.ok_or_else(|| {
            Failure::Server(DomainError::invalid(
                "user",
                "the user this grant was made for no longer exists",
            ))
        })?;
        let resolved = asterius_oidc::claims::resolve_for_grant(&user, grant).map_err(|error| {
            // The request was validated at PAR and re-serialised canonically
            // onto the grant, so a stored one that no longer parses is a
            // damaged row rather than a bad request.
            Failure::Server(DomainError::invalid("claims", error.to_string()))
        })?;
        Ok(resolved.id_token)
    }

    /// Builds and signs the ID token.
    ///
    /// The access token is signed first and handed in whole, because OIDC Core
    /// §3.1.3.6's `at_hash` is over the *signed* token and is computed under
    /// the ID token's own `alg`. The algorithm is the client's registered
    /// `id_token_signed_response_alg`, carried into the signer rather than left
    /// to whichever key it would otherwise reach for — a tenant with no key of
    /// that algorithm refuses (`ast-a05.12`, `ast-a05.14`).
    ///
    /// `sid` is the session's `public_sid`, never its `id_digest`: the digest
    /// is the lookup key the session store takes, and it is rewritten on every
    /// rotation, while OIDC Back-Channel Logout 1.0 §2.4 needs a value a
    /// relying party can still recognise afterwards (`ast-o4u.5`).
    async fn sign_id_token(
        &self,
        tenant: &Tenant,
        client: &Client,
        parts: IdTokenParts<'_>,
    ) -> Result<String, Failure> {
        let IdTokenParts {
            claimed,
            session,
            access_token,
            nonce,
            released,
        } = parts;
        let mut builder = IdToken::new(
            &tenant.issuer,
            claimed,
            client.registration.id_token_signed_response_alg,
            session.authentication.clone(),
            access_token,
            self.now,
        );
        // OIDC Core §3.1.3.7 item 11: echoed byte-exact, and only when the
        // authorization request carried one.
        if let Some(nonce) = nonce {
            builder = builder.with_nonce(nonce);
        }
        builder = builder.for_session(
            asterius_oidc::tokens::id_token::Session::new(&asterius_domain::SessionId::new(
                session.sid.clone(),
            ))
            .map_err(|e| Failure::Server(DomainError::invalid("sid", e.to_string())))?,
        );
        // `releasing` takes a plain map, so `IdToken::build` re-checks it
        // against `ClaimName::SERVER_ISSUED` rather than trusting that it came
        // from `claims::resolve`.
        builder = builder.releasing(released);
        let unsigned = builder
            .build()
            .map_err(|e| Failure::Server(DomainError::invalid("id_token", e.to_string())))?;

        let signed = self
            .signer
            .sign(
                &tenant.id,
                unsigned.required_algorithm(),
                unsigned.typ(),
                unsigned.claims(),
            )
            .await?;
        Ok(signed.as_str().to_owned())
    }

    /// RFC 6749 §5.1 and OIDC Core §3.1.3.3.
    ///
    /// `Cache-Control` is not set here: the token endpoint applies it to every
    /// response, so that it cannot be the one thing a grant forgets.
    fn response(grant: &Grant, access_token: &str, id_token: Option<&str>) -> Response {
        let mut body = json!({
            "access_token": access_token,
            // RFC 9449 §5: a DPoP-bound access token is `DPoP`, not `Bearer`,
            // and a client that sends it as a bearer token must be refused by
            // the resource server. Certificate-bound tokens are `Bearer`
            // (RFC 8705 §3.1) and are `ast-a05.7`; this handler binds to DPoP
            // and nothing else, so the value is constant.
            "token_type": "DPoP",
            "expires_in": AccessToken::DEFAULT_LIFETIME.whole_seconds(),
            // RFC 6749 §5.1 makes `scope` optional when it is identical to
            // what was requested. The token request for this grant carries no
            // scope at all, so there is nothing for a client to compare
            // against and it is always sent — the granted set is what a client
            // needs to know, and consent may have narrowed it.
            "scope": grant.scopes.iter().cloned().collect::<Vec<_>>().join(" "),
        });
        if let Some(id_token) = id_token
            && let Some(object) = body.as_object_mut()
        {
            object.insert("id_token".to_owned(), json!(id_token));
        }
        (axum::http::StatusCode::OK, Json(body)).into_response()
    }
}
