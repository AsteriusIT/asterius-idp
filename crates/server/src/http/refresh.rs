//! The `refresh_token` grant (RFC 6749 §6, OIDC Core §12).
//!
//! Exchanges a refresh token for a fresh access token, and — when the grant is
//! an OpenID Connect one — a fresh ID token. It is the only grant here that
//! runs with nobody present: the browser is gone, the consent screen was weeks
//! ago, and what stands in their place is this file.
//!
//! # Two things must be true, and a third a tenant may ask for
//!
//! FAPI 2.0 SP §5.3.2.1 requires the client to authenticate *and* the request
//! to carry a DPoP proof, so a stolen refresh token is worth nothing without
//! the client's credentials. That is RFC 9700 §4.14's "sender-constrained or
//! rotation" answered with the first option, which is the one that does not
//! break a client that loses a response.
//!
//! The third — pinning the token to the DPoP key it was *issued* to — is the
//! tenant's `bind_to_dpop_key`, and it is off by default because RFC 9449 §5
//! says a refresh token issued to a confidential client is not bound to the
//! proof key, every client here being confidential. `check_key_binding` below
//! is that rule and the option that overrides it.
//!
//! # Why the token does not rotate
//!
//! FAPI 2.0 SP §5.3.2.1 item 9: an authorization server "shall not use refresh
//! token rotation except in extraordinary circumstances". This is not a
//! simplification and it is not a shortcut. Rotation exists to detect the
//! replay of a *bearer* refresh token — you learn a token was stolen because
//! the thief used it and the honest client's next use fails. A
//! sender-constrained token cannot be replayed by anybody who lacks the key,
//! so rotation detects nothing that is not already impossible, while
//! introducing the failure everyone who has run it knows: a client that loses
//! one HTTP response loses the authorization, and the user is asked to log in
//! again for no reason at all.
//!
//! The migration mode ([`Rotation::Migration`]) is Note 1's exception, and it
//! is deliberately awkward to hold. It exists for one situation — moving off a
//! server that rotated, where clients in the field will discard any refresh
//! token they did not just receive — it is time-boxed by a grace window an
//! operator must name, and it is meant to be switched off again. It is
//! implemented here because a migration that cannot be performed is a
//! migration that does not happen, not because rotation is a hardening
//! measure.
//!
//! # What every refusal says
//!
//! One `invalid_grant` with one description, whatever failed: an unknown
//! token, an expired one, one belonging to another client, one presented with
//! the wrong key, one whose grant has been revoked. RFC 6749 §5.2 puts all of
//! those behind one code, and the reason is the same one the authorization
//! code grant gives: somebody holding a stolen token must not be able to ask
//! this endpoint which of their guesses was close.
//!
//! `invalid_scope` is the exception, and it is the specification's: §6 gives
//! scope its own code, and a scope failure is a fact about the *request* a
//! legitimate client sent rather than about the credential it holds.

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::entities::client::GrantType;
use asterius_domain::entities::grant::GrantStatus;
use asterius_domain::entities::tenant::Rotation;
use asterius_domain::keys::Signer;
use asterius_domain::ports::SessionRepository;
use asterius_domain::{Client, DomainError, Grant, Kid, RefreshPolicy, Tenant};
use asterius_oidc::form::Parameters;
use asterius_oidc::refresh::{self, MintedRefreshToken};
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::{AccessToken, Confirmation};
use asterius_store_pg::{
    NewRefreshToken, PgGrantRepository, PgRefreshTokenRepository, PgUserRepository, Presentation,
    RefreshBinding, RefreshTokenRecord,
};
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::collections::BTreeSet;
use time::OffsetDateTime;

use crate::http::issuance;
use crate::http::issuance::{INVALID_TARGET, TARGET_REFUSED};
use crate::http::token::{GrantHandler, not_issued, refused};

/// What every refusal in this file says.
///
/// One constant for all of them, for the reason RFC 6749 §5.2 gathers five
/// distinct facts under `invalid_grant`: naming which one applies tells
/// whoever holds a stolen token whether it was the token, the client or the
/// key that was wrong.
const INVALID_GRANT: &str = "the refresh token cannot be redeemed";

/// Redeems refresh tokens.
///
/// Built per request rather than once, for the reason
/// [`crate::http::authorization_code::AuthorizationCode`] is: two of its
/// fields are facts about *this* request — the instant it arrived and the DPoP
/// key it proved — and [`GrantHandler::handle`] receives neither.
pub struct RefreshToken<'a> {
    /// Refresh tokens for this tenant.
    pub tokens: &'a PgRefreshTokenRepository,
    /// Grants for this tenant, consulted for revocation and for what the
    /// tokens may say.
    pub grants: &'a PgGrantRepository,
    /// Sessions for this tenant, for `auth_time`, `acr` and `amr`.
    pub sessions: &'a dyn SessionRepository,
    /// Users for this tenant, read only to resolve the claims the grant covers.
    pub users: &'a PgUserRepository,
    /// This tenant's registered resource servers (RFC 8707): a refresh is a
    /// token request, so it may name a `resource` and is audienced by the same
    /// rules as the redemption before it.
    pub resource_servers: &'a dyn asterius_domain::ResourceServerRepository,
    /// The application roles this token asserts (`ast-095`).
    ///
    /// Read at issuance rather than frozen onto the grant, so a role withdrawn
    /// since the authorization is not asserted by the next token minted from
    /// it.
    pub roles: &'a asterius_store_pg::PgApplicationRoles,
    /// Signs both tokens.
    pub signer: &'a dyn Signer,
    /// The trail. Every refresh is recorded, successful or not.
    pub audit: &'a dyn AuditSink,
    /// Whether this tenant offers Grant Management, which is what makes the
    /// grant management endpoint an audience a token may be minted for
    /// (Grant Management ID1 §6.2).
    pub grant_management: bool,
    /// Whether this tenant's access tokens carry the `grant_id` claim
    /// (`TenantSettings::grant_id_in_access_token`).
    pub grant_id_claim: bool,
    /// How long this tenant's access tokens live (`ast-5c6`).
    ///
    /// The same value the code grant mints under: a refresh that renewed a
    /// token for longer than the authorization that started it would be a way
    /// to escape the setting by asking twice.
    pub lifetimes: asterius_domain::TokenLifetimes,
    /// What this request proved possession of: a DPoP key, a client
    /// certificate, or neither.
    ///
    /// "Neither" is a refusal rather than a mode: FAPI 2.0 SP §5.3.2.1 item 4
    /// admits no unbound access token, so there is no token this handler could
    /// issue without one. Which of the two binds the token is the client's
    /// registered `TokenBinding` — see [`issuance::SenderConstraint`].
    pub constraint: issuance::SenderConstraint<'a>,
    /// When the request arrived. One instant for every deadline and both
    /// tokens, so `iat`, `exp` and the two refresh-token expiries are judged
    /// against one clock reading rather than several.
    pub now: OffsetDateTime,
}

impl<'a> RefreshToken<'a> {
    /// A refresh handler over the same repositories, clock reading and proven
    /// key as the code grant beside it.
    ///
    /// The same construction — and the same argument — as
    /// [`crate::http::device_code::DeviceCode::sharing`]: everything except
    /// the audit sink is a value the token endpoint resolved once per request,
    /// and two grants judging one request against two clock readings or two
    /// proven keys is the class of bug `ast-5c6` was. Copying them here rather
    /// than listing them again at the call site is what makes that identity
    /// structural.
    #[must_use]
    pub fn sharing(
        code: &super::authorization_code::AuthorizationCode<'a>,
        audit: &'a dyn AuditSink,
    ) -> Self {
        Self {
            tokens: code.refresh_tokens,
            grants: code.grants,
            sessions: code.sessions,
            users: code.users,
            resource_servers: code.resource_servers,
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

impl std::fmt::Debug for RefreshToken<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshToken")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Why a refresh stopped.
enum Failure {
    /// The client can act on it: an RFC 6749 §5.2 code and its description.
    Client(&'static str, &'static str),
    /// The deployment is at fault. Rendered by [`not_issued`], which logs it.
    ///
    /// There is no DPoP variant here, unlike the authorization-code grant.
    /// That grant has a proof failure of its own to render — a code pinned to
    /// one `dpop_jkt` presented with another, which RFC 9449 §7 gives a
    /// `WWW-Authenticate` shape. A refresh has no pinned-at-issuance value to
    /// contradict: the proof itself was checked at the endpoint edge before
    /// this handler ran, and a key that does not match the *token* is an
    /// `invalid_grant` like every other failed binding.
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

#[async_trait::async_trait]
impl GrantHandler for RefreshToken<'_> {
    fn grant(&self) -> GrantType {
        GrantType::RefreshToken
    }

    async fn handle(&self, tenant: &Tenant, client: &Client, params: &Parameters) -> Response {
        match self.refresh(tenant, client, params).await {
            Ok(response) => response,
            Err(failure) => {
                // Recorded before it is rendered, so that a refusal cannot be
                // the one outcome the trail does not have. `grant` is unknown
                // on most failure paths — that is what failing means here — so
                // the event carries the client and the tenant and nothing it
                // would have to guess at.
                self.record(tenant, client, Outcome::Failure, None, None)
                    .await;
                match failure {
                    Failure::Client(code, description) => refused(code, description),
                    Failure::Server(error) => not_issued(tenant, client, &error),
                }
            }
        }
    }
}

impl RefreshToken<'_> {
    /// The refresh itself, with failures as `Err` so the checks read in order.
    async fn refresh(
        &self,
        tenant: &Tenant,
        client: &Client,
        params: &Parameters,
    ) -> Result<Response, Failure> {
        let policy = tenant.refresh;

        // RFC 6749 §6: `refresh_token` is REQUIRED. Absent is
        // `invalid_request` (§5.2, "missing a required parameter"); present
        // but not the shape a refresh token has is `invalid_grant`, because
        // that is a statement about a credential rather than about the form.
        let presented = params
            .get("refresh_token")
            .map_err(|_| {
                Failure::Client("invalid_request", "refresh_token was sent more than once")
            })?
            .ok_or(Failure::Client(
                "invalid_request",
                "refresh_token is required",
            ))?;
        let digest = refresh::digest_of(presented).map_err(|_| invalid_grant())?;

        // Before the lookup, because it costs nothing and because a request
        // that proved nothing has no token this handler could issue whatever
        // the digest turns out to name.
        let confirmation = self
            .constraint
            .confirmation(client)
            .map_err(Self::unbound)?;

        let record = match self
            .tokens
            .redeem(
                &digest,
                self.now,
                policy.grace(),
                // The idle deadline this use buys. The repository caps it at
                // the row's own absolute deadline, which is the schema's
                // `CHECK` said once more where it can be enforced.
                policy.idle_lifetime.map(|idle| self.now + idle),
            )
            .await?
        {
            Presentation::Accepted(record) => *record,
            Presentation::Rejected => return Err(invalid_grant()),
        };

        // RFC 6749 §6: the token was issued to a client, and only that client
        // may present it. First, so that nothing below tells an authenticated
        // client anything about another client's token.
        if record.client != client.id {
            return Err(invalid_grant());
        }

        self.check_binding(&policy, &record)?;

        let grant = self
            .grants
            .find(&record.grant)
            .await?
            .ok_or_else(invalid_grant)?;
        // A grant revoked or expired since the token was issued. The token's
        // own `revoked_at` catches the ordinary case — the revocation cascade
        // stamps both in one transaction — and this catches an expiry, which
        // is computed rather than stored and so reaches no row.
        if !matches!(grant.status(self.now), GrantStatus::Active) {
            return Err(invalid_grant());
        }

        // RFC 6749 §6, and the reason `record.scopes` is the comparison rather
        // than `grant.scopes`: a token already narrowed once must not widen
        // back on the next refresh.
        let requested = params
            .get("scope")
            .map_err(|_| Failure::Client("invalid_request", "scope was sent more than once"))?;
        let effective = refresh::requested_scopes(requested, &record.scopes).map_err(|error| {
            tracing::debug!(%error, client = %client.id, tenant = %tenant.id, "a refresh named a scope it does not hold");
            // RFC 6749 §5.2's own code for this, and the one refusal here that
            // is not `invalid_grant`: it is a fact about the request rather
            // than about the credential, so saying so tells an attacker
            // nothing they did not send.
            Failure::Client("invalid_scope", "the requested scope exceeds the granted scope")
        })?;

        // RFC 8707 §2.2 applies to every token request, and a refresh is one:
        // the resources named here must be a subset of what the authorization
        // authorized, and a refresh that names none is audienced the way the
        // redemption before it was.
        let targets = asterius_oidc::token::requested_resources(params)
            .map_err(|_| Failure::Client(INVALID_TARGET, TARGET_REFUSED))?;

        let (access_token, id_token) = self
            .mint(tenant, client, &grant, confirmation, &effective, &targets)
            .await?;

        let returned = self
            .refresh_token_to_return(&policy, presented, &digest, &record, &effective)
            .await?;

        self.record(
            tenant,
            client,
            Outcome::Success,
            Some(&grant),
            Some(&record),
        )
        .await;

        Ok(Self::response(
            &effective,
            issuance::token_type(client),
            &access_token,
            &returned,
            id_token.as_deref(),
            self.lifetimes.access_token(),
        ))
    }

    /// Mints the access token, and the ID token when the refresh is still an
    /// OpenID Connect one.
    ///
    /// Both are minted from a **narrowed copy** of the grant rather than from
    /// the grant itself. `AccessToken` reads `scope` off the grant it is
    /// given, so handing it the stored one would issue a token broader than
    /// the request that asked for it — which is exactly the failure RFC 6749
    /// §6's narrowing exists to make possible, arriving by the back door.
    ///
    /// The claim comes first and is not optional: `PgGrantRepository::claim`
    /// is the only constructor of the authority both builders demand, so
    /// "issue a token from a revoked grant" does not run.
    async fn mint(
        &self,
        tenant: &Tenant,
        client: &Client,
        grant: &Grant,
        confirmation: Confirmation,
        effective: &BTreeSet<String>,
        targets: &BTreeSet<String>,
    ) -> Result<(String, Option<String>), Failure> {
        let session = self.session_facts(grant).await?;
        let claimed = self.grants.claim(&grant.id, self.now).await?;
        let narrowed = Grant {
            scopes: effective.clone(),
            ..grant.clone()
        };

        // RFC 8707 §2.2 and RFC 9068 §3, from the narrowed grant: the audience
        // is what this request named, or what the authorization authorized, and
        // the scopes are narrowed again by what those resource servers
        // understand.
        let targeting = issuance::targeting(
            self.resource_servers,
            tenant,
            client,
            &narrowed,
            targets,
            issuance::ImplicitResources {
                grant_management: self.grant_management,
                // A user-delegated token is never audienced at the SSF
                // management API; see `issuance::ImplicitResources`.
                ssf: false,
            },
        )
        .await
        .map_err(|error| match error {
            issuance::TargetingError::InvalidTarget => {
                Failure::Client(INVALID_TARGET, TARGET_REFUSED)
            }
            issuance::TargetingError::Storage(error) => Failure::Server(error),
        })?;

        // Read once for both tokens of this response; see the code grant. A
        // refresh reads it afresh every time on purpose (`ast-095`): a token
        // refreshed after a role was withdrawn must not still assert it.
        let held = issuance::held_roles(self.roles, &narrowed).await?;

        let access = AccessToken::new(
            &tenant.issuer,
            &narrowed,
            &claimed,
            targeting.audience,
            confirmation,
            JwtId::generate(),
            self.now,
        )
        .authenticated_by(session.authentication.clone())
        .for_lifetime(self.lifetimes.access_token())
        .with_grant_id_when(self.grant_id_claim)
        // `ast-095`: the tenant's shared roles under `roles`, this client's own
        // under `resource_access.<client_id>.roles`. The builder narrows them
        // to this client; see `AccessToken::with_roles`.
        .with_roles(&held)
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

        // OIDC Core §12.2: an ID token MAY be returned from a refresh, and
        // when it is, its `sub` MUST be the one the original ID token carried.
        // That holds here because both come from the same grant and the same
        // session row — "the same `sub` and `auth_time`" is not a rule this
        // code applies, it is the only thing it can produce.
        let id_token = if effective.contains("openid") {
            let parts = issuance::IdTokenParts {
                claimed: &claimed,
                session: &session,
                access_token: access_token.as_str(),
                // §12.2: no new `nonce`. See `IdTokenParts::nonce`.
                nonce: None,
                released: issuance::released_claims(self.users, &narrowed, client, &held).await?,
            };
            Some(
                issuance::sign_id_token(self.signer, tenant, client, parts, self.now)
                    .await
                    .map_err(Failure::Server)?,
            )
        } else {
            None
        };

        Ok((access_token.as_str().to_owned(), id_token))
    }

    /// RFC 9449 §5, and the tenant's `bind_to_dpop_key`.
    ///
    /// §5 binds a refresh token to the proof key when it is issued to a
    /// *public* client, and says that tokens "issued to confidential clients
    /// are not bound to the DPoP proof public key because they are already
    /// sender-constrained with a different existing mechanism". Every client
    /// here is confidential — `TokenEndpointAuthMethod` has no `none` — so the
    /// default is off and this check does not run: the client authenticated,
    /// and the key it proves is the key its *new* access token is bound to.
    ///
    /// That is what lets a client roll its DPoP key without losing its
    /// authorizations, and it is not a hypothetical: the OpenID Foundation's
    /// `fapi2-security-profile-final-refresh-token` module mints a fresh DPoP
    /// key for the refresh request precisely to check that a confidential
    /// client may. `ast-1h1` is the first run of that module, where this server
    /// refused it with `invalid_grant`.
    ///
    /// A tenant that turns the option on gets the stricter reading — the token
    /// is pinned to the key it was issued to — and pays for it with a client
    /// that may never roll that key.
    /// A certificate binding is not the tenant's to switch off, and that is
    /// the one place the two methods differ. RFC 8705 §3 gives no reading of a
    /// `cnf` whose `x5t#S256` a server declines to check: a token bound to a
    /// certificate that need not be presented is a bearer token carrying a
    /// claim about itself. The price is the mirror image of the freedom above
    /// — a certificate-bound client that rotates its certificate cannot redeem
    /// the refresh tokens issued under the old one, and has to be
    /// re-authorized. A deployment that rotates certificates often should bind
    /// its clients by DPoP instead.
    fn check_binding(
        &self,
        policy: &RefreshPolicy,
        record: &RefreshTokenRecord,
    ) -> Result<(), Failure> {
        match &record.binding {
            RefreshBinding::Dpop(jkt) => {
                if !policy.bind_to_dpop_key {
                    return Ok(());
                }
                if self.constraint.proof_key.map(Kid::as_str) != Some(jkt.as_str()) {
                    return Err(invalid_grant());
                }
                Ok(())
            }
            RefreshBinding::Certificate(thumbprint) => {
                if !self.constraint.presents(thumbprint) {
                    return Err(invalid_grant());
                }
                Ok(())
            }
        }
    }

    /// What a refresh that could not be bound to anything answers.
    ///
    /// `invalid_grant` for the missing proof, because that is what this
    /// endpoint has always said and RFC 6749 §5.2 gathers failed bindings
    /// there; `invalid_request` for the two certificate cases, which are facts
    /// about the request's transport rather than about the credential.
    fn unbound(error: issuance::ConstraintError) -> Failure {
        match error {
            issuance::ConstraintError::ProofRequired => Failure::Client(
                "invalid_grant",
                "a DPoP proof is required to redeem a refresh token",
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

    /// `auth_time`, `acr` and `amr` — and the session-lifetime policy.
    ///
    /// OIDC Core §11 is explicit that `offline_access` is access "when the
    /// user is not present", so a grant that carries it outlives the browser
    /// session it was made in and a vanished session is not a refusal. A grant
    /// *without* it is bound to that session, and a session that has ended is
    /// an authorization that has ended with it — `invalid_grant`, which is
    /// what a client should see when the user has logged out.
    ///
    /// Either way the facts are ones the server recorded, never derived from
    /// the grant's timestamps: `auth_time` says when the person authenticated,
    /// and a refresh six weeks later must not quietly claim they did so today.
    /// Once the session is gone they come from the copy the grant took of it at
    /// the authorization (`ast-dlk`), which is why `offline_access` can now
    /// mean what OIDC Core §11 says it means.
    ///
    /// `sid: None` is how [`issuance::session_facts`] reports that it fell back
    /// to that copy, and it is the whole of the distinction this function
    /// makes: a grant without `offline_access` gets `invalid_grant` there,
    /// because for it a session that has ended is an authorization that has
    /// ended too.
    async fn session_facts(&self, grant: &Grant) -> Result<issuance::SessionFacts, Failure> {
        let offline = grant.scopes.contains("offline_access");
        let facts = match issuance::session_facts(self.sessions, grant).await {
            Ok(facts) => facts,
            Err(_) if !offline => return Err(invalid_grant()),
            Err(error) => {
                // Entitled to outlive the session, but nothing recorded the
                // authentication: a grant created before `ast-dlk` added the
                // columns, whose session has since been purged. Refusing is
                // still the honest answer — an `auth_time` this server does
                // not hold is not one to invent — and the log says which case
                // it was, because it is the one that ages out on its own.
                tracing::warn!(
                    %error,
                    grant = %grant.id,
                    "an offline_access grant outlived the session its auth_time came from"
                );
                return Err(Failure::Server(error));
            }
        };

        // A live session answered, so the facts are the current ones —
        // including a step-up that moved them since (`ast-2vk.7`). Otherwise
        // they came from the grant's copy, which only a grant entitled to
        // outlive its session may be served from: for any other, a session
        // that has ended is an authorization that has ended with it, and the
        // client should see RFC 6749 §5.2's `invalid_grant` rather than a
        // token.
        if facts.sid.is_none() && !offline {
            return Err(invalid_grant());
        }
        Ok(facts)
    }

    /// The value the client gets back, and what that costs the database.
    ///
    /// [`Rotation::None`] — the default and the FAPI 2.0 position — returns
    /// the presented value unchanged and writes nothing beyond the idle
    /// deadline the redemption already pushed. The server never held the value
    /// to begin with, only its digest; what makes returning it possible is
    /// that the client just sent it.
    ///
    /// [`Rotation::Migration`] mints a replacement and stamps the presented
    /// token superseded, in one transaction. The stamp uses `coalesce`, so a
    /// client retrying inside the grace window does not push the window out —
    /// which is the property that makes it a *window* rather than a lease the
    /// holder of a stolen token can renew.
    async fn refresh_token_to_return(
        &self,
        policy: &RefreshPolicy,
        presented: &str,
        digest: &str,
        record: &RefreshTokenRecord,
        scopes: &BTreeSet<String>,
    ) -> Result<String, Failure> {
        let Rotation::Migration { .. } = policy.rotation else {
            return Ok(presented.to_owned());
        };

        let minted = MintedRefreshToken::generate();
        // The replacement inherits the absolute deadline rather than starting
        // a new one. Rotation must not be a way to extend a lifetime: a token
        // refreshed every hour under a thirty-day policy would otherwise live
        // for ever, which is the absolute deadline not existing.
        let replacement = NewRefreshToken {
            grant: record.grant.clone(),
            client: record.client.clone(),
            scopes: scopes.clone(),
            // The replacement inherits the binding as well: a rotation must
            // not be a way to move a credential from one holder to another.
            binding: record.binding.clone(),
            absolute_expires_at: record.absolute_expires_at,
            idle_expires_at: policy
                .idle_lifetime
                .map(|idle| (self.now + idle).min(record.absolute_expires_at)),
        };

        self.tokens
            .supersede(digest, minted.digest(), &replacement, self.now)
            .await?;
        Ok(minted.expose().to_owned())
    }

    /// Writes the trail entry for one refresh, successful or not.
    ///
    /// Never fails the request. A refresh that worked and whose audit write
    /// did not is a worse outcome than either alone, but refusing a legitimate
    /// client because a log is unavailable is not the trade this endpoint
    /// makes; the failure is logged at error level, where it is the loudest
    /// thing in the file.
    async fn record(
        &self,
        tenant: &Tenant,
        client: &Client,
        outcome: Outcome,
        grant: Option<&Grant>,
        record: Option<&RefreshTokenRecord>,
    ) {
        let mut detail = Detail::new().label("grant_type", "refresh_token");
        if let Some(record) = record {
            // A superseded token still being presented is the signal that says
            // a migration is not finished, so it is a field rather than a line
            // in a message.
            detail = detail.label(
                "superseded_token_presented",
                if record.superseded { "true" } else { "false" },
            );
        }

        let mut event = AuditEvent::new(
            tenant.id.clone(),
            EventType::TOKEN_REFRESHED,
            outcome,
            Actor::Client(client.id.clone()),
            self.now,
        )
        .client(client.id.clone())
        .detail(detail);
        if let Some(grant) = grant {
            event = event.grant(grant.id.clone());
            if let Some(subject) = &grant.subject {
                event = event.subject(subject.to_string());
            }
        }

        if let Err(error) = self.audit.record(event).await {
            tracing::error!(
                %error,
                tenant = %tenant.id,
                client = %client.id,
                "a refresh was not written to the audit trail"
            );
        }
    }

    /// RFC 6749 §5.1.
    ///
    /// `Cache-Control` is not set here: the token endpoint applies it to every
    /// response, so that it cannot be the one thing a grant forgets.
    fn response(
        scopes: &BTreeSet<String>,
        token_type: &str,
        access_token: &str,
        refresh_token: &str,
        id_token: Option<&str>,
        access_token_lifetime: time::Duration,
    ) -> Response {
        let mut body = json!({
            "access_token": access_token,
            // See [`issuance::token_type`].
            "token_type": token_type,
            // The lifetime this token was actually signed with, not a
            // constant: `ast-5c6` found the two able to disagree, and a client
            // that renews on `expires_in` would then renew after its token had
            // already died.
            "expires_in": access_token_lifetime.whole_seconds(),
            // RFC 6749 §5.1 makes `scope` optional when it is identical to
            // what was requested, and §6 makes a refresh request's `scope`
            // optional. Always sent, because "identical to what was requested"
            // is not something a client that sent nothing can evaluate, and
            // the effective set is exactly what it needs to know.
            "scope": scopes.iter().cloned().collect::<Vec<_>>().join(" "),
            // RFC 6749 §6: "the authorization server MAY issue a new refresh
            // token". Under the default policy this is the same value the
            // client just sent — deliberately, and see the module header for
            // why that is the compliant answer rather than the lazy one.
            "refresh_token": refresh_token,
        });
        if let Some(id_token) = id_token
            && let Some(object) = body.as_object_mut()
        {
            object.insert("id_token".to_owned(), json!(id_token));
        }
        (axum::http::StatusCode::OK, Json(body)).into_response()
    }
}
