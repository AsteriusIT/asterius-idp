//! The `urn:ietf:params:oauth:grant-type:token-exchange` grant (RFC 8693).
//!
//! An agent presents a token it holds and asks for a narrower one that records
//! it as the party acting. Everything about this grant is a subtraction: the
//! scopes shrink, the audience shrinks, the lifetime shrinks, and the one thing
//! that *grows* is the `act` chain, which is the record of who is answerable.
//!
//! [`asterius_oidc::token_exchange`] holds the parts that are decidable without
//! a database — §2.1's request, §4.1's chain, §4.4's `may_act`. What lives here
//! is everything that needs this deployment: the key set that says whether we
//! issued the subject token, the grant row that says whether it is still
//! authority, and the client policy that says whether this agent may delegate
//! at all.
//!
//! # The subject token has to be *this* server's, and still alive
//!
//! §2.1 lets a subject token be anything the AS understands. This one
//! understands its own, and only while they are authority:
//!
//! 1. it verifies against this tenant's published keys, with the `typ` its
//!    kind requires (RFC 9068 §2.1 — an ID token cannot be presented as an
//!    access token, and neither can be presented as a DPoP proof);
//! 2. it is inside its `exp` (the verifier's check);
//! 3. its `jti` is not on the revocation denylist (`ast-1sk.2`);
//! 4. the grant it names is still `active` — which is what makes an exchanged
//!    token die with the authorization behind it rather than outliving it.
//!
//! Any of those failing is `invalid_grant` and never says which: the four are
//! the same answer to a client — "that token is not one you can exchange" —
//! and telling them apart turns this endpoint into an oracle for whether a
//! stolen token has been revoked yet.
//!
//! # Who may exchange a token
//!
//! An access token this server issues is sender-constrained (ADR-0002), so the
//! party that can prove possession of its key is the party that holds it. That
//! proof is the default authorization to exchange it: the DPoP key on *this*
//! request must be the one in the subject token's `cnf.jkt`.
//!
//! The alternative is a token minted for one client and handed to another,
//! which is a bearer credential in everything but name. It is permitted only
//! where the client the token was minted for carries `exchangeable` in its
//! agent policy — an operator's explicit decision, recorded on the client the
//! decision is about.
//!
//! # Delegation, and the one case that is not
//!
//! §5 draws the line: delegation keeps both parties visible, impersonation
//! makes the actor indistinguishable from the subject. This server delegates
//! by default — the issued token carries `act`, and a resource server can
//! always see that an agent is behind the request — and impersonates only for
//! a client whose agent policy says `impersonation: true`.
//!
//! That default is the security property. An operator who turns impersonation
//! on has decided that their resource servers cannot tell an agent from the
//! person it acts for, and `docs/threat-model.md` records what that costs.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::agent::AgentLimits;
use asterius_domain::entities::client::{GrantType, TokenBinding};
use asterius_domain::keys::{KeyStore, Signer};
use asterius_domain::{
    Client, ClientId, ClientRepository, DomainError, Grant, GrantId, GrantStatus, SubjectId, Tenant,
};
use asterius_oidc::form::Parameters;
use asterius_oidc::token_exchange::{self, ExchangeRequest, SubjectTokenType};
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::AccessToken;
use asterius_store_pg::PgGrantRepository;
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use time::{Duration, OffsetDateTime};

use crate::http::access_token;
use crate::http::dpop;
use crate::http::issuance;
use crate::http::issuance::{INVALID_TARGET, TARGET_REFUSED};
use crate::http::token::{GrantHandler, not_issued, refused};

/// The scopes an exchanged token never carries.
///
/// `openid` makes a request an authentication request (OIDC Core §3.1.2.1) and
/// this grant authenticates nobody — there is no ID token here to be the
/// assertion. `offline_access` asks for a refresh token, and §2.2.1's optional
/// `refresh_token` is the one member of the response this server does not
/// send: a credential that renews a delegation while nobody is watching is
/// exactly §5's warning.
const NOT_DELEGATED_SCOPES: [&str; 2] = ["openid", "offline_access"];

/// What every refusal that concerns the subject token says.
///
/// One constant for expired, revoked, not ours, not bound to the caller and
/// naming a dead grant. See the module documentation: they are one answer.
const SUBJECT_REFUSED: &str = "the subject token cannot be exchanged";

/// Issues delegated access tokens (RFC 8693).
///
/// Built per request, for the reason [`crate::http::client_credentials`] is:
/// the clock reading and the proven DPoP key are facts about *this* request,
/// and [`GrantHandler::handle`] receives neither.
pub struct TokenExchange<'a> {
    /// This tenant's clients — read to find the policy of the client the
    /// subject token was minted for, which is the only thing that can permit a
    /// token to be exchanged by somebody else.
    pub clients: &'a dyn ClientRepository,
    /// Grants for this tenant: the parent is read, the child is written.
    pub grants: &'a PgGrantRepository,
    /// This tenant's registered resource servers (RFC 8707).
    pub resource_servers: &'a dyn asterius_domain::ResourceServerRepository,
    /// This deployment's keys, for deciding whether we issued the subject
    /// token. The same handle UserInfo verifies with, so the two cannot hold
    /// different opinions about which keys are current.
    pub keys: &'a dyn KeyStore,
    /// Signs the issued access token.
    pub signer: &'a dyn Signer,
    /// The trail. Every exchange is recorded with its whole chain.
    pub audit: &'a dyn AuditSink,
    /// Whether this tenant offers Grant Management, which decides whether its
    /// endpoint is an audience a token may be minted for.
    pub grant_management: bool,
    /// Whether this tenant's access tokens carry `grant_id`.
    pub grant_id_claim: bool,
    /// This tenant's token lifetimes (`ast-5c6`).
    pub lifetimes: asterius_domain::TokenLifetimes,
    /// What this request proved possession of.
    pub constraint: issuance::SenderConstraint<'a>,
    /// When the request arrived.
    pub now: OffsetDateTime,
}

impl<'a> TokenExchange<'a> {
    /// This grant, on another grant's repositories, clock reading and proven
    /// key.
    ///
    /// The same construction [`crate::http::device_code::DeviceCode::sharing`]
    /// uses, for the same reason: two handlers assembled side by side from
    /// separate argument lists can be handed different repositories, a
    /// different `now` or a different proof key, and nothing would say so.
    /// What this grant needs beyond the code grant's borrows is the client
    /// registry, this deployment's keys and the trail.
    #[must_use]
    pub fn sharing(
        code: &crate::http::authorization_code::AuthorizationCode<'a>,
        clients: &'a dyn ClientRepository,
        keys: &'a dyn KeyStore,
        audit: &'a dyn AuditSink,
    ) -> Self {
        Self {
            clients,
            keys,
            audit,
            grants: code.grants,
            resource_servers: code.resource_servers,
            signer: code.signer,
            grant_management: code.grant_management,
            grant_id_claim: code.grant_id_claim,
            lifetimes: code.lifetimes,
            constraint: code.constraint,
            now: code.now,
        }
    }
}

impl std::fmt::Debug for TokenExchange<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenExchange")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Why an exchange stopped.
enum Failure {
    /// The client can act on it: an RFC 6749 §5.2 or RFC 8693 §2.2.2 code.
    Client(&'static str, &'static str),
    /// The deployment is at fault.
    Server(DomainError),
    /// A DPoP refusal, which renders RFC 9449 §7's own shape.
    Dpop(dpop::Refusal),
}

impl From<DomainError> for Failure {
    fn from(error: DomainError) -> Self {
        Self::Server(error)
    }
}

/// `invalid_grant` about the subject token, in the one wording it ever has.
const fn subject_refused() -> Failure {
    Failure::Client("invalid_grant", SUBJECT_REFUSED)
}

/// What the subject token contributed to the exchange.
///
/// Assembled from the token and, for an access token, from the grant behind
/// it. It is the *ceiling*: nothing below may exceed any member of it.
struct Ceiling {
    /// The `sub` the issued token will carry — the same principal, because an
    /// exchange changes who is *acting*, never who is acted for.
    subject: Option<SubjectId>,
    /// The local account, when the subject token's grant named one.
    user: Option<asterius_domain::UserId>,
    /// The grant the subject token was minted from, when there is one.
    parent: Option<GrantId>,
    /// The scopes the exchanged token may not exceed.
    scopes: BTreeSet<String>,
    /// The RFC 8707 resources the exchanged token may not exceed. Empty means
    /// "the subject named none", and the actor's own defaults then apply.
    resources: BTreeSet<String>,
    /// The delegation chain already recorded, current actor first (§4.1).
    chain: Vec<Value>,
    /// What is left of the subject token's life. The issued token gets no more.
    remaining: Duration,
}

#[async_trait::async_trait]
impl GrantHandler for TokenExchange<'_> {
    fn grant(&self) -> GrantType {
        GrantType::TokenExchange
    }

    async fn handle(&self, tenant: &Tenant, client: &Client, params: &Parameters) -> Response {
        match self.issue(tenant, client, params).await {
            Ok(issued) => {
                self.record(
                    tenant,
                    client,
                    Outcome::Success,
                    Some(&issued.grant),
                    &issued.chain,
                    issued.subject.as_ref(),
                )
                .await;
                issued.response
            }
            Err(failure) => {
                // Recorded before it is rendered: a refusal of a delegation is
                // the entry an investigator most wants, and it must not be the
                // one outcome the trail does not have.
                self.record(tenant, client, Outcome::Failure, None, &[], None)
                    .await;
                match failure {
                    Failure::Client(code, description) => refused(code, description),
                    Failure::Server(error) => not_issued(tenant, client, &error),
                    Failure::Dpop(refusal) => refusal.into_response(),
                }
            }
        }
    }
}

/// A completed exchange, and what the trail needs to describe it.
struct Issued {
    response: Response,
    grant: GrantId,
    chain: Vec<Value>,
    subject: Option<SubjectId>,
}

impl TokenExchange<'_> {
    /// The exchange itself, with failures as `Err` so the checks read in order.
    async fn issue(
        &self,
        tenant: &Tenant,
        client: &Client,
        params: &Parameters,
    ) -> Result<Issued, Failure> {
        // ADR-0002 and RFC 9449 §5.2. Checked before anything the client sent
        // is read, and restricted to DPoP: an exchanged token is a delegation
        // travelling between processes, and the binding that follows it there
        // is the one the holder can prove per request. A certificate-bound
        // client is refused rather than served, because §2.2.1's `token_type`
        // for what it would get is not what this grant advertises.
        if client.registration.token_binding != TokenBinding::Dpop {
            return Err(Failure::Client(
                "invalid_request",
                "token exchange issues DPoP-bound tokens; this client's tokens are bound to a \
                 certificate",
            ));
        }
        let confirmation = self.constraint.confirmation(client).map_err(|error| {
            match error {
                issuance::ConstraintError::ProofRequired => {
                    Failure::Dpop(dpop::Refusal::missing_proof())
                }
                // Unreachable for a DPoP-bound client, and mapped rather than
                // panicked: the registration decides, and it said DPoP above.
                issuance::ConstraintError::CertificateRequired
                | issuance::ConstraintError::TwoBindingsOffered => Failure::Client(
                    "invalid_request",
                    "this client's tokens are bound to a DPoP key",
                ),
                issuance::ConstraintError::Unusable(error) => Failure::Server(error),
            }
        })?;

        let request = token_exchange::parse(params)
            .map_err(|error| Failure::Client(error.code(), describe(&error)))?;

        let subject = self.subject(tenant, client, &request).await?;

        // §4.1 and the agent policy's `max_delegation_depth`, or §5's
        // impersonation for a client an operator opted in.
        let limits = client
            .registration
            .agent
            .as_ref()
            .map_or_else(AgentLimits::default, |profile| profile.limits().clone());
        let chain = if limits.impersonation() {
            // §5: no `act`. The issued token is indistinguishable from one
            // minted for the subject, which is the whole meaning of the flag.
            subject.chain.clone()
        } else {
            token_exchange::extend_chain(
                &subject.chain,
                client.id.as_str(),
                limits.max_delegation_depth(),
            )
            .map_err(|error| match error {
                token_exchange::DelegationError::TooDeep => Failure::Client(
                    "invalid_request",
                    "the delegation chain is deeper than this client's policy permits",
                ),
                // `Malformed` and anything a later build adds: a chain this
                // server did not write is a fact about a row, never described
                // to the client that happened to present it.
                _ => Failure::Server(DomainError::invalid(
                    "actor_chain",
                    "the stored chain is not a chain",
                )),
            })?
        };

        let scopes = Self::scopes(client, &limits, &subject, request.scope)?;
        let lifetime = self.lifetime(client, &subject)?;

        let mut grant = Grant::new(tenant.id.clone(), client.id.clone(), self.now);
        grant.user = subject.user;
        grant.subject = subject.subject.clone();
        grant.scopes = scopes;
        grant.resources = subject.resources.clone();
        grant.actor_chain = chain.clone();
        grant.parent = subject.parent.clone();
        // Claimed at birth: the row exists because a credential is being taken
        // from it, and a `Pending` grant here would be collected by the sweep
        // that deletes abandoned ones while its token was still live.
        grant.claimed_at = Some(self.now);
        grant.expires_at = Some(self.now + lifetime);

        let targeting = self
            .targeting(tenant, client, &grant, &request, &limits)
            .await?;
        grant.resources = targeting.audience.values().map(str::to_owned).collect();

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
        .restricted_to_scopes(targeting.scopes.clone())
        .with_grant_id_when(self.grant_id_claim)
        .for_lifetime(lifetime)
        .build()
        .map_err(|e| Failure::Server(DomainError::invalid("access_token", e.to_string())))?;

        // The row before the signature, so there is no window in which a
        // client holds a token naming a grant that does not exist.
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

        Ok(Issued {
            response: Self::response(access_token.as_str(), &targeting.scopes, lifetime),
            grant: grant.id,
            chain,
            subject: subject.subject,
        })
    }

    /// Reads, verifies and resolves the subject token (§2.1, §4.4).
    async fn subject(
        &self,
        tenant: &Tenant,
        client: &Client,
        request: &ExchangeRequest<'_>,
    ) -> Result<Ceiling, Failure> {
        let verified = match request.subject_token_type {
            // `jwt` (§3) is the generic spelling. This server's JWTs of that
            // description are its access tokens, which is what it tries — an
            // ID token presented under it fails the `typ` check and gets the
            // one refusal every subject-token failure gets.
            SubjectTokenType::AccessToken | SubjectTokenType::Jwt => {
                access_token::verify(tenant, self.keys, request.subject_token, self.now).await
            }
            SubjectTokenType::IdToken => {
                access_token::verify_id_token(tenant, self.keys, request.subject_token, self.now)
                    .await
            }
        }
        .map_err(|error| match error {
            access_token::Rejected::Token(_) => subject_refused(),
            access_token::Rejected::Unavailable(error) => Failure::Server(error),
        })?;

        // §4.4, before anything else the token says is used: a `may_act` that
        // does not name this actor is a token this client may not act with,
        // whatever else is true of it.
        if !token_exchange::may_act_authorizes(verified.claims.get("may_act"), client.id.as_str()) {
            return Err(subject_refused());
        }

        let expires_at = verified
            .claims
            .get("exp")
            .and_then(Value::as_i64)
            .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
            .ok_or_else(subject_refused)?;
        let remaining = expires_at - self.now;
        if remaining <= Duration::ZERO {
            return Err(subject_refused());
        }

        let subject = verified
            .claim_str("sub")
            .map(|sub| SubjectId::new(sub.to_owned()));

        match request.subject_token_type {
            SubjectTokenType::IdToken => {
                // An ID token is issued *to* a client, and §5's rule is that
                // the actor must be a party the token was for: a client
                // exchanging an ID token must be one of its audiences.
                if !audienced_at(&verified.claims, client.id.as_str()) {
                    return Err(subject_refused());
                }
                // An ID token authorizes nothing (OIDC Core §2 makes it an
                // assertion about an authentication), so the ceiling it sets
                // on scope is empty and the issued token carries none. It is
                // a token that says who is acting for whom, and nothing more.
                Ok(Ceiling {
                    subject,
                    user: None,
                    parent: None,
                    scopes: BTreeSet::new(),
                    resources: BTreeSet::new(),
                    chain: Vec::new(),
                    remaining,
                })
            }
            SubjectTokenType::AccessToken | SubjectTokenType::Jwt => {
                self.exchangeable_access_token(client, &verified, subject, remaining)
                    .await
            }
        }
    }

    /// The access-token half of [`Self::subject`]: may this caller exchange
    /// this token, and what authority is behind it.
    async fn exchangeable_access_token(
        &self,
        client: &Client,
        verified: &asterius_jose::verify::Verified,
        subject: Option<SubjectId>,
        remaining: Duration,
    ) -> Result<Ceiling, Failure> {
        // `ast-1sk.2`: a token whose `jti` was denylisted is revoked, however
        // valid its signature still is.
        let jti = verified.claim_str("jti").ok_or_else(subject_refused)?;
        if self.grants.is_denylisted(jti).await? {
            return Err(subject_refused());
        }

        self.may_exchange(client, verified).await?;

        // The authorization behind the token, which is what the exchanged
        // token narrows. Required: a token this server cannot trace to a grant
        // is one it cannot bound, and issuing a delegation from it would put a
        // credential in the world whose ceiling nobody can read.
        let parent = verified
            .claim_str("grant_id")
            .and_then(|raw| uuid::Uuid::parse_str(raw).ok())
            .map(GrantId::new)
            .ok_or_else(subject_refused)?;
        let parent = self
            .grants
            .find(&parent)
            .await?
            .ok_or_else(subject_refused)?;
        if parent.status(self.now) != GrantStatus::Active {
            return Err(subject_refused());
        }

        Ok(Ceiling {
            subject: subject.or_else(|| parent.subject.clone()),
            user: parent.user,
            parent: Some(parent.id),
            scopes: parent.scopes,
            resources: parent.resources,
            chain: parent.actor_chain,
            remaining,
        })
    }

    /// Whether this caller may exchange this token at all.
    ///
    /// Possession, proved the way the token itself says: the DPoP key on this
    /// request must be the one in `cnf.jkt`. The exception is a token minted
    /// for a client whose agent policy marks it `exchangeable`, which is an
    /// operator's decision to let that client's tokens travel.
    async fn may_exchange(
        &self,
        client: &Client,
        verified: &asterius_jose::verify::Verified,
    ) -> Result<(), Failure> {
        let bound_to = verified
            .claims
            .get("cnf")
            .and_then(|cnf| cnf.get("jkt"))
            .and_then(Value::as_str)
            .ok_or_else(subject_refused)?;
        if self
            .constraint
            .proof_key
            .is_some_and(|key| key.as_str() == bound_to)
        {
            return Ok(());
        }

        // Not the caller's key. The only remaining way is the policy of the
        // client the token was minted for — read from that client, because it
        // is a statement about *its* tokens and not about whoever is asking.
        let holder = verified
            .claim_str("client_id")
            .ok_or_else(subject_refused)?;
        if holder == client.id.as_str() {
            // The caller's own token, presented without the key it is bound
            // to. There is no policy that makes that acceptable: it is the
            // definition of a token that has left its holder.
            return Err(subject_refused());
        }
        let holder = ClientId::new(holder);
        let permitted = self
            .clients
            .find(&holder)
            .await?
            .and_then(|holder| holder.registration.agent.clone())
            .is_some_and(|profile| profile.limits().exchangeable());
        if permitted {
            Ok(())
        } else {
            Err(subject_refused())
        }
    }

    /// What the exchanged token may carry (§2.1's `scope`, RFC 6749 §3.3).
    ///
    /// The ceiling is an intersection of three sets and never a union: what
    /// the subject token was granted, what this client is registered for, and
    /// what its agent policy permits. A requested scope narrows further; a
    /// requested scope outside the ceiling is `invalid_scope` rather than
    /// something quietly dropped, because a client that asked for a scope and
    /// got a token without it has no way to tell.
    fn scopes(
        client: &Client,
        limits: &AgentLimits,
        subject: &Ceiling,
        requested: Option<&str>,
    ) -> Result<BTreeSet<String>, Failure> {
        let permitted: BTreeSet<String> = subject
            .scopes
            .iter()
            .filter(|scope| client.registration.scopes.contains(*scope))
            .filter(|scope| {
                limits
                    .scopes()
                    .is_none_or(|allowed| allowed.contains(*scope))
            })
            .filter(|scope| !NOT_DELEGATED_SCOPES.contains(&scope.as_str()))
            .cloned()
            .collect();

        let scopes =
            asterius_oidc::refresh::requested_scopes(requested, &permitted).map_err(|_| {
                Failure::Client(
                    "invalid_scope",
                    "the requested scope exceeds what the subject token carries",
                )
            })?;

        // `ast-lh3.1`. A scope the tenant marked as needing human approval is
        // one an agent may not hold on its own, and a delegation is precisely
        // an agent holding it while nobody is at the keyboard. The human
        // approved that scope for the client the subject token was minted for,
        // which is not a decision about this agent.
        if let Some(profile) = &client.registration.agent
            && let Some(scope) =
                profile.scope_needing_human_approval(scopes.iter().map(String::as_str))
        {
            tracing::debug!(
                client = %client.id,
                %scope,
                "an agent asked to be delegated a scope that requires human approval"
            );
            return Err(Failure::Client(
                "invalid_scope",
                "this scope requires a person to approve it, and a delegation has none",
            ));
        }

        Ok(scopes)
    }

    /// How long the exchanged token lives.
    ///
    /// The smallest of three: the tenant's access token lifetime, this agent's
    /// own ceiling (`ast-lh3.1`), and what is left of the subject token. The
    /// last is the one this grant adds — a delegation that outlives the token
    /// it was derived from is a way to extend a credential by exchanging it in
    /// a loop.
    fn lifetime(&self, client: &Client, subject: &Ceiling) -> Result<Duration, Failure> {
        let lifetimes = client
            .registration
            .agent
            .as_ref()
            .map_or(self.lifetimes, |agent| agent.cap(self.lifetimes));
        let lifetime = lifetimes.access_token().min(subject.remaining);
        if lifetime <= Duration::ZERO {
            return Err(subject_refused());
        }
        Ok(lifetime)
    }

    /// The `aud` of the exchanged token (§2.1's `audience`/`resource`, §2.2.2).
    ///
    /// [`issuance::targeting`] holds the RFC 8707 rules, and the grant handed
    /// to it carries the subject token's own resources — so "a token request
    /// cannot reach past its own authorization" is what makes this narrowing
    /// rather than re-targeting. The agent policy's audience allow-list is
    /// applied on top, because a tenant that bounded where its agents' tokens
    /// may go meant it for the tokens they obtain by exchange too.
    async fn targeting(
        &self,
        tenant: &Tenant,
        client: &Client,
        grant: &Grant,
        request: &ExchangeRequest<'_>,
        limits: &AgentLimits,
    ) -> Result<issuance::Targeting, Failure> {
        let targeting = issuance::targeting(
            self.resource_servers,
            tenant,
            client,
            grant,
            &request.targets,
            self.grant_management,
        )
        .await
        .map_err(|error| match error {
            issuance::TargetingError::InvalidTarget => {
                Failure::Client(INVALID_TARGET, TARGET_REFUSED)
            }
            issuance::TargetingError::Storage(error) => Failure::Server(error),
        })?;

        if let Some(allowed) = limits.audiences()
            && !targeting
                .audience
                .values()
                .all(|value| allowed.contains(value))
        {
            return Err(Failure::Client(INVALID_TARGET, TARGET_REFUSED));
        }
        Ok(targeting)
    }

    /// RFC 8693 §2.2.1.
    ///
    /// `issued_token_type` is REQUIRED and is what tells a client what it got
    /// — the parameter that makes the response self-describing rather than
    /// something to infer from `token_type`. `token_type` is `DPoP` because
    /// that is what this grant binds (RFC 9449 §5), and there is no
    /// `refresh_token`.
    fn response(access_token: &str, scopes: &BTreeSet<String>, lifetime: Duration) -> Response {
        let mut body = json!({
            "access_token": access_token,
            "issued_token_type": token_exchange::ACCESS_TOKEN,
            "token_type": "DPoP",
            "expires_in": lifetime.whole_seconds(),
        });
        // §2.2.1 makes `scope` REQUIRED "if the scope of the issued security
        // token is identical to the scope requested by the client then this
        // parameter is OPTIONAL" — so it is sent whenever there is one, and an
        // empty set is an absent member rather than an empty string.
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

    /// Writes one entry to the trail, with the whole chain.
    ///
    /// [`EventType::TOKEN_EXCHANGED`], and the chain is the point of it: an
    /// entry naming only the agent that asked answers "who called" and not
    /// "who is answerable", and the second question is the one a delegation
    /// exists to make answerable. The actors are recorded outermost first, the
    /// same order §4.1 renders them in, so the trail and the token agree.
    async fn record(
        &self,
        tenant: &Tenant,
        client: &Client,
        outcome: Outcome,
        grant: Option<&GrantId>,
        chain: &[Value],
        subject: Option<&SubjectId>,
    ) {
        let profile = client.registration.agent.as_ref();
        let actor = profile.map_or_else(
            || Actor::Client(client.id.clone()),
            |profile| Actor::Agent {
                client: client.id.clone(),
                on_behalf_of: profile.owner().to_string(),
            },
        );
        let mut detail = Detail::new().label("grant_type", "token_exchange");
        if let Some(profile) = profile {
            detail = detail.text("agent_owner", profile.owner().to_string());
        }
        if profile.is_some_and(|profile| profile.limits().impersonation()) {
            // The one exchange with no `act` to record. Named in the trail
            // because a delegation nobody can see in the token is a delegation
            // the trail is the only witness to (§5).
            detail = detail.label("delegation", "impersonation");
        }
        let mut event = AuditEvent::new(
            tenant.id.clone(),
            EventType::TOKEN_EXCHANGED,
            outcome,
            actor,
            self.now,
        )
        .client(client.id.clone())
        .actor_chain(chain_actors(chain))
        .detail(detail);
        if let Some(grant) = grant {
            event = event.grant(grant.clone());
        }
        if let Some(subject) = subject {
            event = event.subject(subject.as_str().to_owned());
        }

        if let Err(error) = self.audit.record(event).await {
            tracing::error!(
                %error,
                tenant = %tenant.id,
                client = %client.id,
                "a token exchange was not written to the audit trail"
            );
        }
    }
}

/// The `act` chain as audit actors, outermost first.
///
/// An entry that is not a client this server can name is dropped rather than
/// rendered as text: the trail's actor list is what a query filters on, and a
/// row holding something that only looks like a client id would answer "which
/// agents acted for this user" with an identifier nobody can resolve.
fn chain_actors(chain: &[Value]) -> Vec<Actor> {
    chain
        .iter()
        .filter_map(|actor| actor.get("client_id").and_then(Value::as_str))
        .map(ClientId::new)
        .map(Actor::Client)
        .collect()
}

/// Whether `claims` names `client_id` in its `aud` (OIDC Core §2).
fn audienced_at(claims: &Value, client_id: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(one)) => one == client_id,
        Some(Value::Array(many)) => many.iter().any(|value| value.as_str() == Some(client_id)),
        _ => false,
    }
}

/// What a client is told about a request this server would not read.
///
/// A constant per variant, never the value that caused it: the parameters were
/// chosen by whoever sent the request, and echoing one would make this
/// endpoint a reflector.
const fn describe(error: &token_exchange::ExchangeError) -> &'static str {
    use token_exchange::ExchangeError as E;
    match error {
        E::Duplicated(_) => "a parameter was sent more than once",
        E::MissingSubjectToken => "subject_token is required",
        E::SubjectTokenTooLarge => "the subject_token is too large",
        E::MissingSubjectTokenType => "subject_token_type is required",
        E::UnsupportedSubjectTokenType => "that subject_token_type cannot be exchanged here",
        E::UnsupportedRequestedTokenType => "this grant issues access tokens",
        E::ActorTokenRefused => {
            "actor_token is not accepted; the actor is the authenticated client"
        }
        E::Target => TARGET_REFUSED,
        // A refusal a later build adds and this rendering has not learnt: the
        // client gets the general statement rather than nothing at all.
        _ => "this request cannot be exchanged",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_id_token_audienced_at_the_actor_is_one_it_may_present() {
        // Arrange: OIDC Core §2 allows `aud` to be a string or an array.
        let single = json!({ "aud": "c.agent" });
        let many = json!({ "aud": ["c.other", "c.agent"] });

        // Act, Assert.
        assert!(audienced_at(&single, "c.agent"));
        assert!(audienced_at(&many, "c.agent"));
    }

    #[test]
    fn an_id_token_for_somebody_else_is_not_one_the_actor_may_present() {
        // Arrange: RFC 8693 §5 — the actor must be a party the token was for.
        for claims in [
            json!({ "aud": "c.other" }),
            json!({ "aud": ["c.other"] }),
            json!({ "aud": 7 }),
            json!({}),
        ] {
            // Act, Assert.
            assert!(
                !audienced_at(&claims, "c.agent"),
                "{claims} was read as an audience"
            );
        }
    }

    #[test]
    fn the_audit_chain_holds_the_actors_the_token_does_in_the_same_order() {
        // Arrange: §4.1's order — current actor first.
        let chain = vec![
            json!({ "client_id": "c.second" }),
            json!({ "client_id": "c.first" }),
        ];

        // Act.
        let actors = chain_actors(&chain);

        // Assert.
        assert_eq!(actors.len(), 2);
        assert_eq!(actors[0].kind(), "client");
        assert_eq!(actors[0], Actor::Client(ClientId::new("c.second")));
        assert_eq!(actors[1], Actor::Client(ClientId::new("c.first")));
    }

    #[test]
    fn a_chain_entry_that_names_no_client_is_dropped_from_the_trail() {
        // Arrange: a row this server did not write — an actor identified by
        // something that is not a `client_id` string.
        let chain = vec![json!({ "sub": "someone" }), json!({ "client_id": 7 })];

        // Act.
        let actors = chain_actors(&chain);

        // Assert.
        assert!(actors.is_empty());
    }

    #[test]
    fn every_refusal_of_a_malformed_request_is_a_constant() {
        // Arrange: the values a client chose must never come back.
        let reflected = "https://attacker.example/<script>";
        let errors = [
            token_exchange::ExchangeError::Duplicated(reflected.to_owned()),
            token_exchange::ExchangeError::MissingSubjectToken,
            token_exchange::ExchangeError::SubjectTokenTooLarge,
            token_exchange::ExchangeError::MissingSubjectTokenType,
            token_exchange::ExchangeError::UnsupportedSubjectTokenType,
            token_exchange::ExchangeError::UnsupportedRequestedTokenType,
            token_exchange::ExchangeError::ActorTokenRefused,
            token_exchange::ExchangeError::Target,
        ];

        // Act, Assert.
        for error in &errors {
            assert!(
                !describe(error).contains(reflected),
                "a refusal echoed the request"
            );
        }
    }
}
