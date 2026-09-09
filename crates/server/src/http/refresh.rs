//! The `refresh_token` grant (RFC 6749 §6, OIDC Core §12).
//!
//! Exchanges a refresh token for a fresh access token, and — when the grant is
//! an OpenID Connect one — a fresh ID token. It is the only grant here that
//! runs with nobody present: the browser is gone, the consent screen was weeks
//! ago, and what stands in their place is this file.
//!
//! # Three things must be true, not one
//!
//! FAPI 2.0 SP §5.3.2.1 requires the client to authenticate *and* the request
//! to carry a DPoP proof, and this deployment adds the third: the tenant's
//! `bind_refresh_to_dpop_key` pins the token to the key it was issued to. So a
//! stolen refresh token is worth nothing without the client's credentials, and
//! with them it is still worth nothing without the client's DPoP private key.
//! That is RFC 9700 §4.14's "sender-constrained or rotation" answered with the
//! first option, which is the one that does not break a client that loses a
//! response.
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
    RefreshTokenRecord,
};
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::collections::BTreeSet;
use time::OffsetDateTime;

use crate::http::issuance;
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
    /// Signs both tokens.
    pub signer: &'a dyn Signer,
    /// The trail. Every refresh is recorded, successful or not.
    pub audit: &'a dyn AuditSink,
    /// The thumbprint of the DPoP proof presented with this request.
    ///
    /// `None` is a refusal rather than a mode: FAPI 2.0 SP §5.3.2.1 item 4
    /// admits no unbound access token, so there is no token this handler could
    /// issue without one.
    pub proof_key: Option<&'a Kid>,
    /// When the request arrived. One instant for every deadline and both
    /// tokens, so `iat`, `exp` and the two refresh-token expiries are judged
    /// against one clock reading rather than several.
    pub now: OffsetDateTime,
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
        // with no proof has no token this handler could issue whatever the
        // digest turns out to name.
        let jkt = self.proof_key.ok_or_else(|| {
            Failure::Client(
                "invalid_grant",
                "a DPoP proof is required to redeem a refresh token",
            )
        })?;

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

        Self::check_key_binding(&policy, &record, jkt)?;

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

        let (access_token, id_token) = self.mint(tenant, client, &grant, jkt, &effective).await?;

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
            &access_token,
            &returned,
            id_token.as_deref(),
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
        jkt: &Kid,
        effective: &BTreeSet<String>,
    ) -> Result<(String, Option<String>), Failure> {
        let session = self.session_facts(grant).await?;
        let claimed = self.grants.claim(&grant.id, self.now).await?;
        let narrowed = Grant {
            scopes: effective.clone(),
            ..grant.clone()
        };

        let confirmation = Confirmation::dpop(jkt).map_err(|_| {
            Failure::Server(DomainError::invalid(
                "cnf",
                "the DPoP thumbprint is not a usable confirmation",
            ))
        })?;

        let access = AccessToken::new(
            &tenant.issuer,
            &narrowed,
            &claimed,
            issuance::audience(tenant, &narrowed)?,
            confirmation,
            JwtId::generate(),
            self.now,
        )
        .authenticated_by(session.authentication.clone())
        .with_grant_id()
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
                released: issuance::released_claims(self.users, &narrowed).await?,
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

    /// RFC 9449 §5, and the tenant's `bind_refresh_to_dpop_key`.
    ///
    /// The specification requires the binding for public clients and leaves it
    /// open for confidential ones, which have authenticated anyway. The tenant
    /// option is which of the two readings this deployment takes, and the
    /// strict one is the default.
    ///
    /// When the option is off, the check is skipped and the *new* access token
    /// is bound to the key presented with this request rather than to the one
    /// the refresh token remembers — which is §5's own rule for a confidential
    /// client, and is what lets a client roll its DPoP key without losing its
    /// authorizations.
    fn check_key_binding(
        policy: &RefreshPolicy,
        record: &RefreshTokenRecord,
        presented: &Kid,
    ) -> Result<(), Failure> {
        if !policy.bind_to_dpop_key {
            return Ok(());
        }
        // A row with no thumbprint cannot exist — the schema's
        // `refresh_tokens_are_sender_constrained` refuses one — so `None` here
        // is a hand-edited row, and the safe reading of a binding that is
        // missing is that it does not match.
        if record.dpop_jkt.as_deref() != Some(presented.as_str()) {
            return Err(invalid_grant());
        }
        Ok(())
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
    /// Either way the facts come from the session row, never from the grant's
    /// timestamps: `auth_time` says when the person authenticated, and a
    /// refresh six weeks later must not quietly claim they did so today.
    async fn session_facts(&self, grant: &Grant) -> Result<issuance::SessionFacts, Failure> {
        match issuance::session_facts(self.sessions, grant).await {
            Ok(facts) => Ok(facts),
            Err(error) if grant.scopes.contains("offline_access") => {
                // The grant is entitled to outlive the session, but this
                // server still cannot assert an `auth_time` it no longer
                // holds. `ast-uwv.3` was expected to close this and did not:
                // the consent memory it delivered is derived from the grants
                // rather than stored beside them, and a derivation has nowhere
                // to keep an `auth_time`. Closing it means recording the
                // authentication facts on the grant itself and reading them
                // here when the session is gone — a change to the grant model.
                // Until then the honest answer is to refuse rather than to
                // invent a claim, and the log says which it was.
                tracing::warn!(
                    %error,
                    grant = %grant.id,
                    "an offline_access grant outlived the session its auth_time came from"
                );
                Err(Failure::Server(error))
            }
            Err(_) => Err(invalid_grant()),
        }
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
            dpop_jkt: record
                .dpop_jkt
                .clone()
                // Unreachable while the schema's `CHECK` stands; see
                // `check_key_binding`.
                .ok_or_else(|| {
                    Failure::Server(DomainError::invalid(
                        "refresh_token",
                        "a stored refresh token is not sender-constrained",
                    ))
                })?,
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
        access_token: &str,
        refresh_token: &str,
        id_token: Option<&str>,
    ) -> Response {
        let mut body = json!({
            "access_token": access_token,
            // RFC 9449 §5: a DPoP-bound access token is `DPoP`, not `Bearer`.
            "token_type": "DPoP",
            "expires_in": AccessToken::DEFAULT_LIFETIME.whole_seconds(),
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
