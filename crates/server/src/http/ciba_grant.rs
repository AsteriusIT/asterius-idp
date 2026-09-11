//! The `urn:openid:params:grant-type:ciba` grant (CIBA Core 1.0 §10.1,
//! §10.1.1, §11).
//!
//! The other end of a backchannel authentication: the client polls here with
//! the `auth_req_id` it was acknowledged with (§7.3), in poll mode until a
//! person has answered, in ping mode once — after this server has told it the
//! answer is ready (§10.2) — and then gets tokens.
//!
//! # The shape is the device grant's, because the flow is
//!
//! A credential held by a machine, an approval given elsewhere by a person,
//! a clock, and a token endpoint that is polled. §11's error codes are RFC
//! 8628 §3.5's with one addition, and this handler is
//! [`crate::http::device_code`] with that addition:
//!
//! * `authorization_pending` — nobody has answered yet. Keep polling.
//! * `slow_down` — polled inside the interval; add five seconds and carry on.
//!   The stored interval is raised by the same five *for this request*, so a
//!   client that obeys is not told again at the rate it was just asked to use.
//! * `invalid_request` — polled inside the interval *again*, after every
//!   `slow_down` §11 lets this server give
//!   ([`ciba::MAX_SLOW_DOWNS`]). The client "MUST stop polling".
//! * `access_denied` — somebody said no. Stop.
//! * `expired_token` — nobody answered in time. Stop.
//!
//! Everything else is `invalid_grant`: an unknown `auth_req_id`, one that
//! belongs to another client, and one that has already been redeemed
//! (§10.1.1: after the tokens are issued it "is no longer valid") are one
//! answer, for the reason [`crate::http::authorization_code`] gives about a
//! code that is "invalid, expired, revoked... or was issued to another
//! client".
//!
//! # Ownership is checked before the state is acted on
//!
//! §10.1: the OP "MUST check whether the `auth_req_id` was issued to this
//! Client". That is decided before anything is spent, and before the state is
//! even read — otherwise any authenticated client of the tenant could poll
//! another's request and learn whether a person had approved it.
//!
//! # An `auth_req_id` is spent once
//!
//! [`PgCibaRequestRepository::redeem`] is one statement that checks and
//! spends, so two token requests carrying the same `auth_req_id` cannot both
//! be served.
//!
//! # Push clients
//!
//! §11 answers a push client's poll with `unauthorized_client`. This server
//! registers no push client — [`asterius_domain::TokenDeliveryMode`] has no
//! `push` — so the dispatch in [`crate::http::token`] never reaches here for
//! one, and there is no branch to write.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::client::GrantType;
use asterius_domain::entities::grant::GrantStatus;
use asterius_domain::keys::Signer;
use asterius_domain::ports::SessionRepository;
use asterius_domain::{Client, DomainError, Grant, GrantId, Tenant};
use asterius_oidc::ciba::{self, TokenRequestError};
use asterius_oidc::form::Parameters;
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::AccessToken;
use asterius_store_pg::{
    CibaPoll, NewRefreshToken, PgCibaRequestRepository, PgGrantRepository,
    PgRefreshTokenRepository, PgUserRepository, RedeemedCiba,
};
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use time::OffsetDateTime;

use crate::http::authorization_code::AuthorizationCode;
use crate::http::issuance;
use crate::http::issuance::{INVALID_TARGET, TARGET_REFUSED};
use crate::http::token::{GrantHandler, not_issued, refused};

/// What every refusal that is not one of §11's named ones says.
const INVALID_GRANT: &str = "the auth_req_id cannot be redeemed";

/// Redeems backchannel authentication requests.
///
/// Built per request, like the other grant handlers, because two of its
/// fields are facts about *this* request: the instant it arrived and the key
/// it proved possession of.
pub struct CibaGrant<'a> {
    /// Backchannel authentication requests for this tenant.
    pub ciba_requests: &'a PgCibaRequestRepository,
    /// Grants for this tenant.
    pub grants: &'a PgGrantRepository,
    /// Refresh tokens for this tenant, written only when the grant carries
    /// `offline_access` (OIDC Core §11).
    pub refresh_tokens: &'a PgRefreshTokenRepository,
    /// Sessions for this tenant, for `auth_time`, `acr` and `amr`.
    pub sessions: &'a dyn SessionRepository,
    /// This tenant's registered resource servers (RFC 8707).
    pub resource_servers: &'a dyn asterius_domain::ResourceServerRepository,
    /// Users for this tenant, read only to resolve the claims the grant
    /// covers.
    pub users: &'a PgUserRepository,
    /// The application roles this token asserts (`ast-095`).
    pub roles: &'a asterius_store_pg::PgApplicationRoles,
    /// Signs both tokens.
    pub signer: &'a dyn Signer,
    /// Where issuances and refusals are recorded.
    pub audit: &'a dyn AuditSink,
    /// Whether this tenant offers Grant Management (Grant Management ID1
    /// §6.2).
    pub grant_management: bool,
    /// Whether this tenant's access tokens carry the `grant_id` claim.
    pub grant_id_claim: bool,
    /// How long this tenant's access tokens live (`ast-5c6`).
    pub lifetimes: asterius_domain::TokenLifetimes,
    /// What this request proved possession of. "Neither" is a refusal, as it
    /// is for every other grant (FAPI 2.0 SP §5.3.2.1 item 4).
    pub constraint: issuance::SenderConstraint<'a>,
    /// When the request arrived. One instant for every check and both tokens.
    pub now: OffsetDateTime,
}

impl<'a> CibaGrant<'a> {
    /// The CIBA grant, built from the borrows the code grant already holds.
    ///
    /// The same construction [`crate::http::device_code::DeviceCode::sharing`]
    /// uses, for the same reason: the repositories, the signer, the tenant's
    /// numbers, the key this request proved and the instant it arrived must be
    /// *identical* across the grants one request could turn out to be.
    #[must_use]
    pub fn sharing(
        code: &AuthorizationCode<'a>,
        ciba_requests: &'a PgCibaRequestRepository,
        audit: &'a dyn AuditSink,
    ) -> Self {
        Self {
            ciba_requests,
            grants: code.grants,
            refresh_tokens: code.refresh_tokens,
            sessions: code.sessions,
            resource_servers: code.resource_servers,
            users: code.users,
            roles: code.roles,
            signer: code.signer,
            audit,
            grant_management: code.grant_management,
            grant_id_claim: code.grant_id_claim,
            lifetimes: code.lifetimes,
            constraint: code.constraint,
            now: code.now,
        }
    }
}

impl std::fmt::Debug for CibaGrant<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CibaGrant")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Why a redemption stopped.
enum Failure {
    /// The client can act on it: an RFC 6749 §5.2 or CIBA §11 code and its
    /// description.
    Client(&'static str, &'static str),
    /// The deployment is at fault. Rendered by [`not_issued`], which logs it.
    Server(DomainError),
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

/// Whether a refusal is one of the two "keep polling" answers, which are the
/// ordinary traffic of this grant and not worth a trail entry each.
const fn is_routine(code: &str) -> bool {
    matches!(code.as_bytes(), b"authorization_pending" | b"slow_down")
}

#[async_trait::async_trait]
impl GrantHandler for CibaGrant<'_> {
    fn grant(&self) -> GrantType {
        GrantType::Ciba
    }

    async fn handle(&self, tenant: &Tenant, client: &Client, params: &Parameters) -> Response {
        let digest = ciba::token_request(params)
            .map(|request| request.auth_req_id_digest)
            .ok();
        match self.redeem(tenant, client, params).await {
            Ok((response, grant)) => {
                self.record(
                    tenant,
                    client,
                    Outcome::Success,
                    Some(&grant),
                    digest.as_deref(),
                    None,
                )
                .await;
                response
            }
            Err(Failure::Client(code, description)) => {
                if !is_routine(code) {
                    self.record(
                        tenant,
                        client,
                        Outcome::Failure,
                        None,
                        digest.as_deref(),
                        Some(code),
                    )
                    .await;
                }
                refused(code, description)
            }
            Err(Failure::Server(error)) => not_issued(tenant, client, &error),
        }
    }
}

impl CibaGrant<'_> {
    /// The redemption itself, with failures as `Err` so the checks read in
    /// order. A success carries the grant, for the trail.
    async fn redeem(
        &self,
        tenant: &Tenant,
        client: &Client,
        params: &Parameters,
    ) -> Result<(Response, Grant), Failure> {
        // §10.1: `auth_req_id` is REQUIRED. Absent or repeated is
        // `invalid_request`; present but not a value this server mints is
        // `invalid_grant`, because that is a statement about a credential
        // rather than about the form (§11).
        let request = ciba::token_request(params).map_err(|error| {
            Failure::Client(
                error.code(),
                match error {
                    TokenRequestError::MissingAuthReqId => "auth_req_id is required",
                    TokenRequestError::DuplicateAuthReqId => "auth_req_id was sent more than once",
                    TokenRequestError::Malformed => INVALID_GRANT,
                },
            )
        })?;
        let digest = request.auth_req_id_digest;

        // Before the spend, not after it. The confirmation is decided from
        // the registration and what this request proved, so it costs nothing
        // to decide first — and deciding it after `spent` would let a poll
        // that forgot its DPoP proof burn the one redemption the request has
        // (§10.1.1) and leave the client with a refusal and no way back.
        let confirmation = self
            .constraint
            .confirmation(client)
            .map_err(Self::unbound)?;

        let redeemed = self.spent(client, &digest).await?;

        let grant = self
            .grants
            .find(&redeemed.grant_id)
            .await?
            .ok_or_else(invalid_grant)?;
        // A grant revoked or expired between the approval and this poll. The
        // request was still live, so this is the check that catches it.
        if !matches!(
            grant.status(self.now),
            GrantStatus::Pending | GrantStatus::Active
        ) {
            return Err(invalid_grant());
        }
        let claimed = self.grants.claim(&redeemed.grant_id, self.now).await?;

        let session = issuance::session_facts(self.sessions, &grant).await?;
        // OIDC Back-Channel Logout 1.0 §2.3, as at the code grant: a client
        // that obtained an ID token in this person's session is a relying
        // party that has to be told when it ends.
        issuance::remember_participant(self.sessions, &grant, self.now).await;
        let targeting = self.targeting(tenant, client, &grant, params).await?;
        let held = issuance::held_roles(self.roles, &grant).await?;

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
        .restricted_to_scopes(targeting.scopes)
        .with_grant_id_when(self.grant_id_claim)
        .with_roles(&held)
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

        // §10.1.1: "a successful token response as defined in OpenID Connect
        // Core §3.1.3.3". §7.1 made `openid` mandatory in the request, so an
        // ID token always accompanies the response. There is no `nonce`: this
        // flow has no authorization request to have carried one.
        let id_token = if grant.scopes.contains("openid") {
            let parts = issuance::IdTokenParts {
                claimed: &claimed,
                session: &session,
                access_token: access_token.as_str(),
                nonce: None,
                released: issuance::released_claims(self.users, &grant, client, &held).await?,
            };
            Some(issuance::sign_id_token(self.signer, tenant, client, parts, self.now).await?)
        } else {
            None
        };

        let refresh_token = if grant.scopes.contains("offline_access") {
            Some(self.issue_refresh_token(tenant, client, &grant).await?)
        } else {
            None
        };

        let response = Self::response(
            &grant,
            issuance::token_type(client),
            access_token.as_str(),
            id_token.as_deref(),
            refresh_token.as_deref(),
            self.lifetimes.access_token(),
        );
        Ok((response, grant))
    }

    /// One poll, and the spend if it is time (§10.1, §11).
    ///
    /// Its own function because the "keep waiting" answers are the ordinary
    /// case here and reading them beside the issuance would bury the one path
    /// that mints anything.
    async fn spent(&self, client: &Client, digest: &str) -> Result<RedeemedCiba, Failure> {
        let polled = self
            .ciba_requests
            .poll(
                digest,
                client.id.as_str(),
                ciba::SLOW_DOWN_INCREMENT,
                ciba::POLL_CEILING,
                self.now,
            )
            .await?
            .ok_or_else(invalid_grant)?;

        // §10.1: "issued to this Client", decided before the state is read.
        // The store stamped nothing for a stranger; this is what refuses it.
        if polled.client_id != client.id.as_str() {
            return Err(invalid_grant());
        }

        match polled.state {
            CibaPoll::Approved => {}
            CibaPoll::Pending => {
                return Err(Failure::Client(
                    "authorization_pending",
                    "the authorization request is still pending",
                ));
            }
            CibaPoll::SlowDown { .. } => {
                return Err(Failure::Client(
                    "slow_down",
                    "polling too frequently: increase the interval by five seconds",
                ));
            }
            CibaPoll::TooFast => {
                return Err(Failure::Client(
                    "invalid_request",
                    "polling too frequently after repeated slow_down responses: stop polling",
                ));
            }
            CibaPoll::Denied => {
                return Err(Failure::Client(
                    "access_denied",
                    "the end user denied the authorization request",
                ));
            }
            CibaPoll::Expired => {
                return Err(Failure::Client(
                    "expired_token",
                    "the auth_req_id has expired",
                ));
            }
            // Indistinguishable from unknown, on purpose: only the client
            // that already holds the tokens can provoke it, and distinguishing
            // it confirms a value was ever real.
            CibaPoll::Spent => return Err(invalid_grant()),
        }

        // The spend. One statement, so two requests racing on one approved
        // request cannot both be served.
        let redeemed = self
            .ciba_requests
            .redeem(digest, self.now)
            .await?
            .ok_or_else(invalid_grant)?;
        // Re-checked after the spend as well as before it: a bug that mints a
        // token for the wrong client is one this must not carry.
        if redeemed.client_id != client.id.as_str() {
            return Err(invalid_grant());
        }
        Ok(redeemed)
    }

    /// What this request's `resource` parameters decide about the token.
    async fn targeting(
        &self,
        tenant: &Tenant,
        client: &Client,
        grant: &Grant,
        params: &Parameters,
    ) -> Result<issuance::Targeting, Failure> {
        let requested = asterius_oidc::token::requested_resources(params)
            .map_err(|_| Failure::Client(INVALID_TARGET, TARGET_REFUSED))?;
        issuance::targeting(
            self.resource_servers,
            tenant,
            client,
            grant,
            &requested,
            issuance::ImplicitResources {
                grant_management: self.grant_management,
                ssf: false,
            },
        )
        .await
        .map_err(|error| match error {
            issuance::TargetingError::InvalidTarget => {
                Failure::Client(INVALID_TARGET, TARGET_REFUSED)
            }
            issuance::TargetingError::Storage(error) => Failure::Server(error),
        })
    }

    /// Mints the refresh token an `offline_access` grant earns, bound to what
    /// this request proved possession of.
    async fn issue_refresh_token(
        &self,
        tenant: &Tenant,
        client: &Client,
        grant: &Grant,
    ) -> Result<String, Failure> {
        let binding = self
            .constraint
            .refresh_binding(client)
            .map_err(Self::unbound)?;
        let policy = tenant.refresh;
        let absolute_expires_at = self.now + policy.absolute_lifetime;
        let minted = asterius_oidc::refresh::MintedRefreshToken::generate();

        self.refresh_tokens
            .issue(
                minted.digest(),
                &NewRefreshToken {
                    grant: grant.id.clone(),
                    client: grant.client.clone(),
                    scopes: grant.scopes.clone(),
                    binding,
                    absolute_expires_at,
                    idle_expires_at: policy
                        .idle_lifetime
                        .map(|idle| (self.now + idle).min(absolute_expires_at)),
                },
                self.now,
            )
            .await?;

        Ok(minted.expose().to_owned())
    }

    /// What a redemption that could not be bound to anything answers.
    fn unbound(error: issuance::ConstraintError) -> Failure {
        match error {
            issuance::ConstraintError::ProofRequired => Failure::Client(
                "invalid_grant",
                "a DPoP proof is required to redeem an auth_req_id",
            ),
            issuance::ConstraintError::CertificateRequired => Failure::Client(
                "invalid_request",
                "this client's tokens are bound to a client certificate, and none was presented",
            ),
            issuance::ConstraintError::TwoBindingsOffered => Failure::Client(
                "invalid_request",
                "this client binds its tokens to a certificate; a DPoP proof must not be sent",
            ),
            issuance::ConstraintError::Unusable(error) => Failure::Server(error),
        }
    }

    /// Writes one entry to the trail.
    ///
    /// [`EventType::TOKEN_ISSUED`] with the grant type in the detail, as the
    /// other grants do, and for an agent (`ast-lh3.1`) the actor is
    /// [`Actor::Agent`] with `agent_owner` beside it — see
    /// [`crate::http::client_credentials`] for why the owner is on every
    /// entry. The `auth_req_id` is fingerprinted from its digest, so the
    /// acknowledgement, the decision and the redemption of one request can be
    /// followed through the trail without the trail holding the credential.
    async fn record(
        &self,
        tenant: &Tenant,
        client: &Client,
        outcome: Outcome,
        grant: Option<&Grant>,
        auth_req_id_digest: Option<&str>,
        error: Option<&'static str>,
    ) {
        let agent = client.registration.agent.as_ref();
        let actor = agent.map_or_else(
            || Actor::Client(client.id.clone()),
            |profile| Actor::Agent {
                client: client.id.clone(),
                on_behalf_of: profile.owner().to_string(),
            },
        );
        let mut detail = Detail::new().label("grant_type", "ciba");
        if let Some(profile) = agent {
            detail = detail.text("agent_owner", profile.owner().to_string());
        }
        if let Some(digest) = auth_req_id_digest {
            detail = detail.credential("auth_req_id", digest);
        }
        if let Some(error) = error {
            detail = detail.label("error", error);
        }
        let mut event = AuditEvent::new(
            tenant.id.clone(),
            EventType::TOKEN_ISSUED,
            outcome,
            actor,
            self.now,
        )
        .client(client.id.clone())
        .detail(detail);
        if let Some(grant) = grant {
            event = event.grant(GrantId::new(grant.id.as_str().to_owned()));
            if let Some(user) = grant.user {
                event = event.subject(user.as_uuid().to_string());
            }
        }

        if let Err(failure) = self.audit.record(event).await {
            tracing::error!(
                %failure,
                tenant = %tenant.id,
                client = %client.id,
                "a CIBA token request was not written to the audit trail"
            );
        }
    }

    /// RFC 6749 §5.1 and OIDC Core §3.1.3.3.
    fn response(
        grant: &Grant,
        token_type: &str,
        access_token: &str,
        id_token: Option<&str>,
        refresh_token: Option<&str>,
        access_token_lifetime: time::Duration,
    ) -> Response {
        let mut body = json!({
            "access_token": access_token,
            "token_type": token_type,
            "expires_in": access_token_lifetime.whole_seconds(),
            "scope": grant.scopes.iter().cloned().collect::<Vec<_>>().join(" "),
        });
        if let Some(id_token) = id_token {
            body["id_token"] = json!(id_token);
        }
        if let Some(refresh_token) = refresh_token {
            body["refresh_token"] = json!(refresh_token);
        }
        (axum::http::StatusCode::OK, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §11's two "carry on" answers are the ordinary traffic of a polling
    /// grant and are not written to the trail; everything terminal is.
    #[test]
    fn only_the_two_keep_polling_answers_are_routine() {
        assert!(is_routine("authorization_pending"));
        assert!(is_routine("slow_down"));
        for terminal in [
            "invalid_grant",
            "invalid_request",
            "access_denied",
            "expired_token",
        ] {
            assert!(!is_routine(terminal), "{terminal} must be audited");
        }
    }
}
