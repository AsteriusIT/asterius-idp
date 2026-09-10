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
use asterius_oidc::tokens::access::{AccessToken, Confirmation};
use asterius_oidc::{code, pkce};
use asterius_store_pg::{
    NewRefreshToken, PgCodeRepository, PgGrantRepository, PgRefreshTokenRepository,
    PgUserRepository, Redemption,
};
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use time::OffsetDateTime;

use crate::http::dpop;
use crate::http::issuance;
use crate::http::issuance::{INVALID_TARGET, TARGET_REFUSED};
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
    /// Refresh tokens for this tenant, written only when the grant carries
    /// `offline_access` (OIDC Core §11).
    pub refresh_tokens: &'a PgRefreshTokenRepository,
    /// Sessions for this tenant, for `auth_time`, `acr` and `amr`.
    pub sessions: &'a dyn SessionRepository,
    /// This tenant's registered resource servers (RFC 8707), which decide what
    /// the issued token may be audienced at.
    pub resource_servers: &'a dyn asterius_domain::ResourceServerRepository,
    /// Users for this tenant, read only to resolve the claims the grant
    /// covers (OIDC Core §5.4, §5.5). Nothing here writes a user.
    pub users: &'a PgUserRepository,
    /// Signs both tokens.
    pub signer: &'a dyn Signer,
    /// How long this tenant's access tokens live (`ast-5c6`).
    ///
    /// Resolved once per request by [`crate::http::protocol`] and handed down,
    /// rather than read here: the two grants this endpoint dispatches to must
    /// mint under the same numbers, and one read is what makes that so.
    pub lifetimes: asterius_domain::TokenLifetimes,
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
    /// What this request's `resource` parameters decide about the token
    /// (RFC 8707 §2.2, RFC 9068 §3).
    ///
    /// The subset rule and the registry live in [`issuance::targeting`]; what
    /// is decided here is only that a refusal is `invalid_target` and not
    /// `invalid_grant` — a client that named an audience this server will not
    /// honour has not presented a bad code, and telling it `invalid_grant`
    /// would send it to re-run an authorization that was never the problem.
    async fn targeting(
        &self,
        tenant: &Tenant,
        client: &Client,
        grant: &Grant,
        params: &Parameters,
    ) -> Result<issuance::Targeting, Failure> {
        let requested = asterius_oidc::token::requested_resources(params)
            .map_err(|_| Failure::Client(INVALID_TARGET, TARGET_REFUSED))?;
        issuance::targeting(self.resource_servers, tenant, client, grant, &requested)
            .await
            .map_err(|error| match error {
                issuance::TargetingError::InvalidTarget => {
                    Failure::Client(INVALID_TARGET, TARGET_REFUSED)
                }
                issuance::TargetingError::Storage(error) => Failure::Server(error),
            })
    }

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

        let session = issuance::session_facts(self.sessions, &grant).await?;

        let targeting = self.targeting(tenant, client, &grant, params).await?;

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
            targeting.audience,
            confirmation,
            JwtId::generate(),
            self.now,
        )
        .authenticated_by(session.authentication.clone())
        // RFC 8707 §2: the token says what the resources it is audienced at
        // understand, which is the grant's scopes unless a resource server
        // narrows them.
        .restricted_to_scopes(targeting.scopes)
        // RFC 9068 §2.2.3.1's private claim, and the one thing that lets this
        // deployment's own resource servers find the authorization a token was
        // minted under: UserInfo (`ast-1sk.3`) resolves claims from the grant
        // and nothing else, and introspection (`ast-1sk.1`) reports
        // `grant_id`. Without it, both would have to guess among the grants a
        // person holds for one client, and a wrong guess releases the claims
        // of an authorization this token was not minted from.
        //
        // It is a correlator — RFC 9068 §6 — and the builder keeps it off by
        // default for that reason. Turning it on here is a deployment-wide
        // decision, and making it a tenant option is follow-up work — which a
        // deployment whose resource servers are all third parties will want.
        .with_grant_id()
        .for_lifetime(self.lifetimes.access_token())
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
            let parts = issuance::IdTokenParts {
                claimed: &claimed,
                session: &session,
                access_token: access_token.as_str(),
                nonce: binding.nonce.as_deref(),
                // From the grant, never from the request. See
                // `issuance::released_claims`.
                released: issuance::released_claims(self.users, &grant).await?,
            };
            Some(issuance::sign_id_token(self.signer, tenant, client, parts, self.now).await?)
        } else {
            None
        };

        // OIDC Core §11: `offline_access` is what asks for a refresh token,
        // and the scope is on the *grant* rather than on this request because
        // it was settled at consent. A code flow without it gets an access
        // token and nothing else, which is the ordinary case and the one that
        // leaves no long-lived credential behind to steal.
        let refresh_token = if grant.scopes.contains("offline_access") {
            Some(self.issue_refresh_token(tenant, &grant, jkt).await?)
        } else {
            None
        };

        Ok(Self::response(
            &grant,
            access_token.as_str(),
            id_token.as_deref(),
            refresh_token.as_deref(),
            self.lifetimes.access_token(),
        ))
    }

    /// Mints the refresh token an `offline_access` grant earns.
    ///
    /// The value is generated here, handed to the client once, and never
    /// stored: what reaches the database is its SHA-256 (`ast-a05.5`). The two
    /// deadlines come from the tenant's policy and are computed against
    /// `self.now`, the same instant every other check in this redemption used.
    ///
    /// It is bound to the DPoP key this redemption proved. FAPI 2.0 forbids a
    /// bearer refresh token and the schema says so with a `CHECK`, so there is
    /// no path here that could write one.
    async fn issue_refresh_token(
        &self,
        tenant: &Tenant,
        grant: &Grant,
        jkt: &Kid,
    ) -> Result<String, Failure> {
        let policy = tenant.refresh;
        let absolute_expires_at = self.now + policy.absolute_lifetime;
        let minted = asterius_oidc::refresh::MintedRefreshToken::generate();

        self.refresh_tokens
            .issue(
                minted.digest(),
                &NewRefreshToken {
                    grant: grant.id.clone(),
                    client: grant.client.clone(),
                    // The granted set, not the request's: a refresh token is
                    // the authority to come back later, and it comes back for
                    // what the user approved. Narrowing happens at the refresh
                    // itself (RFC 6749 §6), where it is the client's choice.
                    scopes: grant.scopes.clone(),
                    dpop_jkt: jkt.as_str().to_owned(),
                    absolute_expires_at,
                    idle_expires_at: policy
                        .idle_lifetime
                        // Capped at the absolute deadline, which the schema
                        // also refuses to store the other way round.
                        .map(|idle| (self.now + idle).min(absolute_expires_at)),
                },
                self.now,
            )
            .await?;

        Ok(minted.expose().to_owned())
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

    /// RFC 6749 §5.1 and OIDC Core §3.1.3.3.
    ///
    /// `Cache-Control` is not set here: the token endpoint applies it to every
    /// response, so that it cannot be the one thing a grant forgets.
    fn response(
        grant: &Grant,
        access_token: &str,
        id_token: Option<&str>,
        refresh_token: Option<&str>,
        access_token_lifetime: time::Duration,
    ) -> Response {
        let mut body = json!({
            "access_token": access_token,
            // RFC 9449 §5: a DPoP-bound access token is `DPoP`, not `Bearer`,
            // and a client that sends it as a bearer token must be refused by
            // the resource server. Certificate-bound tokens are `Bearer`
            // (RFC 8705 §3.1) and are `ast-a05.7`; this handler binds to DPoP
            // and nothing else, so the value is constant.
            "token_type": "DPoP",
            // The lifetime this token was actually signed with, not a
            // constant: `ast-5c6` found the two able to disagree, and a client
            // that renews on `expires_in` would then renew after its token had
            // already died.
            "expires_in": access_token_lifetime.whole_seconds(),
            // RFC 6749 §5.1 makes `scope` optional when it is identical to
            // what was requested. The token request for this grant carries no
            // scope at all, so there is nothing for a client to compare
            // against and it is always sent — the granted set is what a client
            // needs to know, and consent may have narrowed it.
            "scope": grant.scopes.iter().cloned().collect::<Vec<_>>().join(" "),
        });
        // RFC 9396 §6: "The AS […] SHOULD return the `authorization_details`
        // […] in the token response." What the *grant* holds, not what the
        // request asked for: consent may have refused, and a client that read
        // its own request back would believe it had an authorization it does
        // not. Present exactly when the grant carries elements, because a
        // client that sees the member treats the capability as exercised.
        if !grant.authorization_details.is_empty()
            && let Some(object) = body.as_object_mut()
        {
            object.insert(
                "authorization_details".to_owned(),
                json!(grant.authorization_details),
            );
        }
        if let Some(id_token) = id_token
            && let Some(object) = body.as_object_mut()
        {
            object.insert("id_token".to_owned(), json!(id_token));
        }
        // RFC 6749 §5.1 makes `refresh_token` OPTIONAL, and it is present
        // exactly when the grant carries `offline_access` (OIDC Core §11).
        if let Some(refresh_token) = refresh_token
            && let Some(object) = body.as_object_mut()
        {
            object.insert("refresh_token".to_owned(), json!(refresh_token));
        }
        (axum::http::StatusCode::OK, Json(body)).into_response()
    }
}
