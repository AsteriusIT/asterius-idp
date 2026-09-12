//! The `client_credentials` grant (RFC 6749 §4.4, RFC 9068 §2.2).
//!
//! A client asks for a token about itself. There is no authorization request,
//! no browser, no consent screen and no resource owner: the client's own
//! registration is the whole of the authorization, and client authentication
//! is the whole of the proof. Resource servers, admin automation, SSF
//! receivers, AuthZEN policy enforcement points and agents acting on their own
//! behalf all arrive here.
//!
//! # This grant is a new frontier, and that is worth saying plainly
//!
//! Every other grant this endpoint serves can point at a person who agreed to
//! something. This one cannot. A token minted here exists because a client
//! holds a key, so the blast radius of that key is now "everything the token
//! may reach" rather than "the ability to complete a flow a user started".
//! Three things follow, and they are the three checks below:
//!
//! * **The registration is the authorization.** The grant has to be registered
//!   (RFC 6749 §5.2's `unauthorized_client`, decided before this file runs),
//!   the scopes have to be registered, and the audience has to be one this
//!   tenant registers. Nothing here is widened by anything in the request.
//! * **The token is sender-constrained.** FAPI 2.0 SP §5.3.2.1 item 4 admits
//!   no unbound access token, and a client-only token is exactly the one worth
//!   stealing from a log: it needs no user, so a bearer copy of it would work
//!   from anywhere. A request with no DPoP proof is refused (RFC 9449 §5.2).
//! * **It is revocable.** FAPI 2.0 SP §6.8 item 4 asks that credentials be
//!   linked to the authorization behind them, and this server's whole
//!   revocation story goes through [`asterius_domain::Grant`]. So a grant row
//!   is written here — client-only, already claimed — and the token carries
//!   its `grant_id`. Without it the token would be the one credential nothing
//!   could withdraw.
//!
//! # What a client-only token does not get
//!
//! **A refresh token.** RFC 6749 §4.4.3: "A refresh token SHOULD NOT be
//! included." A client that can authenticate can simply ask again, so the only
//! thing a refresh token would add here is a long-lived credential to steal.
//!
//! **An ID token, or `openid`.** OIDC Core makes an ID token an assertion
//! about an end user's authentication, and there is no end user. `openid` and
//! `offline_access` are therefore not part of what this grant can issue: they
//! are dropped from the default scope set and refused if asked for by name.
//! That is not decoration. A client-only token carrying `openid` would be
//! presented at UserInfo, where the grant behind it has no `sub` to answer
//! with — an internal inconsistency reported as a server fault instead of the
//! plain "this token is not for that endpoint" a client can act on.
//!
//! **A `sub` of its own.** RFC 9068 §2.2 puts the `client_id` in `sub` for a
//! grant with no resource owner, and [`AccessToken`] does that on its own from
//! a [`asterius_domain::ClaimedGrant`] whose subject is `None`.

use asterius_domain::audit::trail::{self, keys};
use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::client::GrantType;
use asterius_domain::keys::Signer;
use asterius_domain::{Client, DomainError, Grant, Tenant};
use asterius_oidc::form::Parameters;
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::AccessToken;
use asterius_store_pg::PgGrantRepository;
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::collections::BTreeSet;
use time::OffsetDateTime;

use crate::http::dpop;
use crate::http::issuance;
use crate::http::issuance::{INVALID_TARGET, TARGET_REFUSED};
use crate::http::token::{GrantHandler, not_issued, refused};

/// The scopes that mean "a person is involved", which is what this grant does
/// not have.
///
/// `openid` makes a request an OpenID Connect authentication request (OIDC
/// Core §3.1.2.1) and `offline_access` asks for a refresh token (OIDC Core
/// §11) — one of which this grant cannot assert and the other of which RFC
/// 6749 §4.4.3 says not to issue. They are excluded from the set a client-only
/// token may carry, whether or not the client registered them for its other
/// grants.
const USER_FACING_SCOPES: [&str; 2] = ["openid", "offline_access"];

/// Issues client-only access tokens.
///
/// Built per request rather than once, for the reason
/// [`crate::http::authorization_code::AuthorizationCode`] is: two of its
/// fields are facts about *this* request — the instant it arrived and the DPoP
/// key it proved — and [`GrantHandler::handle`] receives neither.
pub struct ClientCredentials<'a> {
    /// Grants for this tenant. Written, not read: this grant creates the
    /// authority it mints from.
    pub grants: &'a PgGrantRepository,
    /// This tenant's registered resource servers (RFC 8707), which decide what
    /// the issued token may be audienced at.
    pub resource_servers: &'a dyn asterius_domain::ResourceServerRepository,
    /// Signs the access token.
    pub signer: &'a dyn Signer,
    /// The trail. Every request is recorded, successful or not.
    pub audit: &'a dyn AuditSink,
    /// Whether this tenant offers Grant Management, which is what makes the
    /// grant management endpoint an audience a token may be minted for
    /// (Grant Management ID1 §6.2).
    pub grant_management: bool,
    /// Whether this tenant offers the SSF management API, which is what makes
    /// the stream configuration endpoint an audience a token may be minted for
    /// (SSF 1.0 §8, `ast-0ju.3`).
    ///
    /// Only this grant carries the flag: a receiver is a registered client
    /// acting on its own behalf, and every other grant passes `false` — see
    /// [`issuance::ImplicitResources`].
    pub ssf: bool,
    /// Whether this tenant's access tokens carry the `grant_id` claim
    /// (`TenantSettings::grant_id_in_access_token`).
    pub grant_id_claim: bool,
    /// How long this tenant's access tokens live (`ast-5c6`).
    pub lifetimes: asterius_domain::TokenLifetimes,
    /// What this request proved possession of: a DPoP key, a client
    /// certificate, or neither.
    ///
    /// "Neither" is a refusal rather than a mode: FAPI 2.0 SP §5.3.2.1 item 4
    /// admits no unbound access token, so there is no token this handler could
    /// issue without one. Which of the two binds the token is the client's
    /// registered `TokenBinding` — see [`issuance::SenderConstraint`].
    pub constraint: issuance::SenderConstraint<'a>,
    /// The pre-issuance policy check for an agent (`ast-lh3.10`).
    ///
    /// Consulted only for a client that carries an
    /// [`asterius_domain::entities::agent::AgentProfile`]; every other client
    /// reaching this grant — a resource server, an SSF receiver, a PEP — takes
    /// the path it always took, at the latency it always had.
    pub agent_policy: crate::http::agent_issuance::AgentPolicy<'a>,
    /// When the request arrived. One instant for the grant's stamps and the
    /// token's `iat` and `exp`, so they are judged against one clock reading.
    pub now: OffsetDateTime,
}

impl std::fmt::Debug for ClientCredentials<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredentials")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Why an issuance stopped.
enum Failure {
    /// The client can act on it: an RFC 6749 §5.2 code and its description.
    Client(&'static str, &'static str),
    /// The deployment is at fault. Rendered by [`not_issued`], which logs it.
    Server(DomainError),
    /// A DPoP refusal, which already knows how to render itself (RFC 9449 §5.2
    /// and §7 have their own shape).
    Dpop(dpop::Refusal),
}

impl From<DomainError> for Failure {
    fn from(error: DomainError) -> Self {
        Self::Server(error)
    }
}

#[async_trait::async_trait]
impl GrantHandler for ClientCredentials<'_> {
    fn grant(&self) -> GrantType {
        GrantType::ClientCredentials
    }

    async fn handle(&self, tenant: &Tenant, client: &Client, params: &Parameters) -> Response {
        match self.issue(tenant, client, params).await {
            Ok((response, grant)) => {
                self.record(tenant, client, Outcome::Success, Some(&grant))
                    .await;
                response
            }
            Err(failure) => {
                // Recorded before it is rendered, so that a refusal cannot be
                // the one outcome the trail does not have. There is no grant to
                // name: on every failure path either none was created or the
                // creation is what failed.
                self.record(tenant, client, Outcome::Failure, None).await;
                match failure {
                    Failure::Client(code, description) => refused(code, description),
                    Failure::Server(error) => not_issued(tenant, client, &error),
                    Failure::Dpop(refusal) => refusal.into_response(),
                }
            }
        }
    }
}

impl ClientCredentials<'_> {
    /// The issuance itself, with failures as `Err` so the checks read in order.
    ///
    /// The order is the order of the things that can be wrong with the
    /// request, cheapest and most local first: the proof, then the scopes the
    /// registration allows, then the audience the tenant registers. Nothing
    /// below consults the request again after the audience is settled.
    async fn issue(
        &self,
        tenant: &Tenant,
        client: &Client,
        params: &Parameters,
    ) -> Result<(Response, Grant), Failure> {
        // RFC 9449 §5.2: with a deployment that issues only sender-constrained
        // tokens, "the authorization server MUST reject token requests from the
        // client that do not contain the DPoP header" — and RFC 8705 §3 is the
        // other way to satisfy that. First, because it is the one check that
        // does not depend on anything the client sent in the body.
        let confirmation = self.constraint.confirmation(client).map_err(|error| {
            match error {
                // The DPoP refusal renders RFC 9449 §7's own
                // `WWW-Authenticate` shape, which is what tells a client
                // *which* proof it failed to send.
                issuance::ConstraintError::ProofRequired => {
                    Failure::Dpop(dpop::Refusal::missing_proof())
                }
                issuance::ConstraintError::CertificateRequired => Failure::Client(
                    "invalid_request",
                    "this client's tokens are bound to a client certificate, and none was \
                     presented",
                ),
                issuance::ConstraintError::TwoBindingsOffered => Failure::Client(
                    "invalid_request",
                    "this client binds its tokens to a certificate; a DPoP proof must not be \
                     sent",
                ),
                issuance::ConstraintError::Unusable(error) => Failure::Server(error),
            }
        })?;

        let scopes = Self::scopes(client, params)?;
        let lifetimes = self.lifetimes(client);

        // The grant is assembled before it is stored, because the audience
        // resolution below reads it. `user`, `subject` and `session` stay
        // `None`: RFC 9068 §2.2's second `sub` arm is reached by *not* having a
        // subject, and inventing one here would put a value in `sub` that no
        // resource server could resolve to anybody.
        let mut grant = Grant::new(tenant.id.clone(), client.id.clone(), self.now);
        grant.scopes = scopes;
        // Grant Management ID1 §5.6 calls a grant `active` once a credential
        // has been claimed from it. This one is created *because* a credential
        // is being taken, so it is claimed at birth — and a `Pending` row here
        // would be collected by the sweep that deletes abandoned grants while
        // its token was still live.
        grant.claimed_at = Some(self.now);
        // The row exists to be revoked and audited, and there is nothing to
        // revoke once the only credential minted from it has expired. Giving it
        // the token's own deadline keeps `Grant::status` honest about that
        // without a sweep having to decide it.
        grant.expires_at = Some(self.now + lifetimes.access_token());

        let targeting = self.targeting(tenant, client, &grant, params).await?;
        // What the audience resolution settled on, recorded on the row: the
        // trail should say what the token was minted *at*, not what the client
        // might have been allowed to ask for.
        grant.resources = targeting.audience.values().map(str::to_owned).collect();

        // `ast-lh3.10`: the last check before an authority is created, and the
        // first one that reads the tenant's rules rather than the
        // registration. It is here — after the scopes, the lifetimes and the
        // audience are settled and before `claim` — so that the policy is
        // asked about the token that would really be signed, and so that a
        // deny leaves no claimed grant behind.
        self.agent_policy
            .permits(
                tenant,
                client,
                &grant,
                &grant.resources.iter().cloned().collect(),
                GrantType::ClientCredentials,
                self.now,
            )
            .await
            .map_err(|refusal| Failure::Client(refusal.code, refusal.description))?;

        // `claim` is the only constructor of the authority to mint, and it
        // refuses a grant that is not issuable. Taken from the assembled grant
        // rather than from a second read of the row: the row is this request's
        // own and nothing else can have touched it.
        let claimed = grant
            .claim(self.now)
            .map_err(|error| Failure::Server(DomainError::invalid("grant", error.to_string())))?;

        let access = AccessToken::new(
            &tenant.issuer,
            &grant,
            &claimed,
            targeting.audience,
            confirmation,
            JwtId::generate(),
            self.now,
        )
        // RFC 8707 §2: the token says what the resources it is audienced at
        // understand, which is the grant's scopes unless a resource server
        // narrows them.
        .restricted_to_scopes(targeting.scopes.clone())
        // RFC 9068 §2.2.3.1's private claim, and what `/revoke` (`ast-1sk.2`)
        // reaches this token through. A client-only token that did not carry it
        // would be the one credential this server cannot withdraw.
        .with_grant_id_when(self.grant_id_claim)
        .for_lifetime(lifetimes.access_token())
        // Deliberately no `authenticated_by`: RFC 9068 §2.2.1's `auth_time`,
        // `acr` and `amr` describe how a *person* authenticated, and asserting
        // anything there about a client would be a claim a relying party uses
        // for step-up decisions and this server cannot stand behind.
        .build()
        .map_err(|e| Failure::Server(DomainError::invalid("access_token", e.to_string())))?;

        // The row goes in before the token is signed, so there is no window in
        // which a client holds a credential naming a grant that does not exist.
        // The other order fails safe — an unused claimed grant is a row nothing
        // points at — and this one does not need to.
        self.grants.create(&grant).await?;

        let access_token = self
            .signer
            .sign(
                &tenant.id,
                access.required_algorithm(),
                access.typ(),
                access.claims(),
            )
            .await?;

        Ok((
            Self::response(
                issuance::token_type(client),
                access_token.as_str(),
                &targeting.scopes,
                lifetimes.access_token(),
            ),
            grant,
        ))
    }

    /// What this request may be issued for (RFC 6749 §3.3, §4.4.2).
    ///
    /// `scope` is OPTIONAL on a client credentials request, and §3.3 leaves an
    /// omitted one to the authorization server. The choice here is the client's
    /// registered set less [`USER_FACING_SCOPES`], and a named scope must be a
    /// subset of that.
    ///
    /// The subset rule itself is [`asterius_oidc::refresh::requested_scopes`],
    /// which is RFC 6749 §3.3's rule rather than anything specific to a
    /// refresh: absent means the whole set, a subset narrows, and anything else
    /// fails the request outright instead of being trimmed to what is
    /// permitted. Sharing it is what keeps "narrowing is allowed, widening is
    /// not" one implementation rather than two that can disagree.
    fn scopes(client: &Client, params: &Parameters) -> Result<BTreeSet<String>, Failure> {
        let permitted: BTreeSet<String> = client
            .registration
            .scopes
            .iter()
            .filter(|scope| !USER_FACING_SCOPES.contains(&scope.as_str()))
            .cloned()
            .collect();

        let requested = params
            .get("scope")
            .map_err(|_| Failure::Client("invalid_request", "scope was sent more than once"))?;

        let scopes =
            asterius_oidc::refresh::requested_scopes(requested, &permitted).map_err(|_| {
                Failure::Client(
                    "invalid_scope",
                    "the requested scope exceeds what this client may be issued",
                )
            })?;

        // `ast-lh3.1`. A scope the tenant marked as needing human approval is
        // exactly what this grant cannot supply: there is nobody at the other
        // end of a client credentials request, and no earlier authorization for
        // this token to inherit one from. It is refused here rather than
        // silently dropped, because a client that asked for a scope and got a
        // token without it has no way to tell.
        if let Some(agent) = &client.registration.agent
            && let Some(scope) =
                agent.scope_needing_human_approval(scopes.iter().map(String::as_str))
        {
            tracing::debug!(
                client = %client.id,
                %scope,
                "an agent asked for a scope that requires human approval"
            );
            return Err(Failure::Client(
                "invalid_scope",
                "this scope requires a person to approve it, and this grant has none",
            ));
        }

        Ok(scopes)
    }

    /// The lifetimes this issuance uses.
    ///
    /// The tenant's (`ast-5c6`), bounded below by the agent profile's ceiling
    /// (`ast-lh3.1`). The minimum of the two and never the agent's alone: a
    /// profile may shorten an agent's token and may not lengthen it past what
    /// the tenant validated.
    fn lifetimes(&self, client: &Client) -> asterius_domain::TokenLifetimes {
        client
            .registration
            .agent
            .as_ref()
            .map_or(self.lifetimes, |agent| agent.cap(self.lifetimes))
    }

    /// What this request's `resource` parameters decide about the token
    /// (RFC 8707 §2.2, RFC 9068 §3).
    ///
    /// The same resolution the authorization-code grant uses, reached through
    /// the same [`issuance::targeting`]: the client's own allow-list, else the
    /// tenant's `default_resource`, filtered by the registry either way. The
    /// grant handed to it is this request's own and authorizes no resource of
    /// its own, which is what makes the defaults apply — there is no earlier
    /// authorization for a client-only token to have narrowed.
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
                ssf: self.ssf,
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

    /// Writes one entry to the trail.
    ///
    /// [`EventType::TOKEN_ISSUED`] with the grant type in the detail, rather
    /// than a type of its own: what an operator asks of this trail is "which
    /// tokens did this client get, and when", and a run of refusals against one
    /// client is a key being tried. Both answers want one type and two
    /// outcomes.
    ///
    /// For an agent (`ast-lh3.1`) the actor is [`Actor::Agent`] and not
    /// [`Actor::Client`], and the detail carries `agent_owner` — the account
    /// the agent acts for. That is the whole point of the entry: an agent's
    /// actions are only attributable if every token it was issued names the
    /// human answerable for it, and a trail that recorded the `client_id` alone
    /// would leave an investigator to join it against a table whose row may
    /// since have been deleted.
    ///
    /// `agent_id` is not a second field: it is the actor's own identifier,
    /// which [`Actor::Agent`] already carries and every reader already reads.
    ///
    /// The resources the token was audienced at and the types of its
    /// `authorization_details` are recorded under the trail's own keys
    /// (`asterius_domain::audit::trail::keys`, `ast-lh3.9`): an agent that
    /// reached a resource it should not have is found by the first, and a
    /// summary of types — never the details, which hold the payment — is
    /// what the second says.
    async fn record(
        &self,
        tenant: &Tenant,
        client: &Client,
        outcome: Outcome,
        grant: Option<&Grant>,
    ) {
        let agent = client.registration.agent.as_ref();
        let actor = agent.map_or_else(
            || Actor::Client(client.id.clone()),
            |profile| Actor::Agent {
                client: client.id.clone(),
                on_behalf_of: profile.owner().to_string(),
            },
        );
        let mut detail = Detail::new().label("grant_type", "client_credentials");
        if let Some(profile) = agent {
            // `text` and not `label`: the value is a UUID rather than a
            // compile-time constant. It survives `redact` unchanged — a UUID
            // is hyphen-separated groups of at most twelve characters, and the
            // scanner looks for unbroken runs of twenty-two — which the audit
            // test asserts rather than assumes.
            detail = detail.text(keys::AGENT_OWNER, profile.owner().to_string());
        }
        if let Some(grant) = grant {
            if let Some(resource) =
                trail::resource_summary(grant.resources.iter().map(String::as_str))
            {
                detail = detail.text(keys::RESOURCE, resource);
            }
            if let Some(types) = trail::authorization_details_summary(&grant.authorization_details)
            {
                detail = detail.text(keys::AUTHORIZATION_DETAILS, types);
            }
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
            event = event.grant(grant.id.clone());
        }
        // No `subject`: there is nobody this event is about but the client,
        // which the actor already names.

        if let Err(error) = self.audit.record(event).await {
            tracing::error!(
                %error,
                tenant = %tenant.id,
                client = %client.id,
                "a client credentials request was not written to the audit trail"
            );
        }
    }

    /// RFC 6749 §5.1.
    ///
    /// `Cache-Control` is not set here: the token endpoint applies it to every
    /// response, so that it cannot be the one thing a grant forgets.
    ///
    /// No `refresh_token`, ever — RFC 6749 §4.4.3 — and no `id_token`: there is
    /// no authentication of a person to assert.
    fn response(
        token_type: &str,
        access_token: &str,
        scopes: &BTreeSet<String>,
        access_token_lifetime: time::Duration,
    ) -> Response {
        let mut body = json!({
            "access_token": access_token,
            // See [`issuance::token_type`].
            "token_type": token_type,
            // The lifetime this token was actually signed with, not a constant.
            "expires_in": access_token_lifetime.whole_seconds(),
        });
        // RFC 6749 §5.1 makes `scope` REQUIRED when the issued scope differs
        // from the requested one, and this grant's default — the registration
        // less the user-facing scopes — routinely does. It is sent whenever
        // there is one, so a client never has to infer it. An empty set is an
        // absent member rather than an empty string, matching the token's own
        // `scope` claim, which RFC 9068 §2.2.3 omits in the same case.
        if !scopes.is_empty()
            && let Some(object) = body.as_object_mut()
        {
            object.insert(
                "scope".to_owned(),
                json!(scopes.iter().cloned().collect::<Vec<_>>().join(" ")),
            );
        }
        (axum::http::StatusCode::OK, Json(body)).into_response()
    }
}
