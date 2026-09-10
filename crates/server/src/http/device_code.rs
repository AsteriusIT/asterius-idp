//! The `urn:ietf:params:oauth:grant-type:device_code` grant (RFC 8628 §3.4).
//!
//! The other end of the device flow: the device polls here until a person has
//! answered in a browser, and then gets tokens.
//!
//! # Polling is the protocol, so the answers to it are the protocol
//!
//! Unlike every other grant this endpoint serves, most requests to this one
//! are *expected* to fail. §3.5 gives four error codes and each is a
//! statement about the flow rather than about the request:
//!
//! * `authorization_pending` — nobody has answered yet. Keep polling.
//! * `slow_down` — you asked again before the interval was up; add five
//!   seconds and keep polling. The stored interval is raised by the same five
//!   seconds *for this device code*, so a client that obeys is not punished
//!   again at the rate it was just told to use.
//! * `access_denied` — somebody said no. Stop.
//! * `expired_token` — nobody answered in time. Stop.
//!
//! Everything else is `invalid_grant`: an unknown device code, one that
//! belongs to another client, and one that has already been redeemed are one
//! answer, for the reason [`crate::http::authorization_code`] gives about a
//! code that is "invalid, expired, revoked... or was issued to another
//! client".
//!
//! # Ownership is checked before the state is acted on
//!
//! The client that authenticated must be the client the device code was
//! issued to, and that is decided before anything is spent. Otherwise any
//! authenticated client of the tenant could poll another's device code and
//! read the progress of a flow it has nothing to do with — or redeem it.
//!
//! # A device code is spent once
//!
//! [`PgDeviceCodeRepository::redeem`] is one statement that checks and spends,
//! so two token requests carrying the same device code cannot both be served.
//! RFC 8628 §3.4 defers to RFC 6749 §4.1.3 for the request, and single use is
//! the property that makes a device code no more dangerous than the
//! authorization code it stands in for.

use asterius_domain::entities::client::GrantType;
use asterius_domain::entities::grant::GrantStatus;
use asterius_domain::keys::Signer;
use asterius_domain::ports::SessionRepository;
use asterius_domain::{Client, DomainError, Grant, Tenant};
use asterius_oidc::device;
use asterius_oidc::form::Parameters;
use asterius_oidc::tokens::JwtId;
use asterius_oidc::tokens::access::AccessToken;
use asterius_store_pg::{
    NewRefreshToken, PgDeviceCodeRepository, PgGrantRepository, PgRefreshTokenRepository,
    PgUserRepository, Poll,
};
use axum::Json;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use time::OffsetDateTime;

use crate::http::authorization_code::AuthorizationCode;
use crate::http::issuance;
use crate::http::issuance::{INVALID_TARGET, TARGET_REFUSED};
use crate::http::token::{GrantHandler, not_issued, refused};

/// What every refusal that is not one of §3.5's four says.
const INVALID_GRANT: &str = "the device code cannot be redeemed";

/// Redeems device codes.
///
/// Built per request, like the other grant handlers, because two of its fields
/// are facts about *this* request: the instant it arrived and the key it
/// proved possession of.
pub struct DeviceCode<'a> {
    /// Device authorizations for this tenant.
    pub device_codes: &'a PgDeviceCodeRepository,
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
    /// Signs both tokens.
    pub signer: &'a dyn Signer,
    /// Whether this tenant offers Grant Management, which is what makes the
    /// grant management endpoint an audience a token may be minted for
    /// (Grant Management ID1 §6.2).
    pub grant_management: bool,
    /// Whether this tenant's access tokens carry the `grant_id` claim
    /// (`TenantSettings::grant_id_in_access_token`).
    pub grant_id_claim: bool,
    /// How long this tenant's access tokens live (`ast-5c6`).
    pub lifetimes: asterius_domain::TokenLifetimes,
    /// What this request proved possession of: a DPoP key, a client
    /// certificate, or neither. "Neither" is a refusal, as it is for every
    /// other grant (FAPI 2.0 SP §5.3.2.1 item 4).
    pub constraint: issuance::SenderConstraint<'a>,
    /// When the request arrived. One instant for every check and both tokens.
    pub now: OffsetDateTime,
}

impl<'a> DeviceCode<'a> {
    /// The device grant, built from the borrows the code grant already holds.
    ///
    /// The two differ in one thing: what is redeemed. Everything else — the
    /// repositories, the signer, the tenant's numbers, the key this request
    /// proved and the instant it arrived — must be *identical* between them,
    /// because the token endpoint resolves each of those once per request and
    /// two grants judging one request against two clock readings is the class
    /// of bug `ast-5c6` was. Copying them here rather than listing them again
    /// at the call site is what makes that identity structural.
    #[must_use]
    pub fn sharing(code: &AuthorizationCode<'a>, device_codes: &'a PgDeviceCodeRepository) -> Self {
        Self {
            device_codes,
            grants: code.grants,
            refresh_tokens: code.refresh_tokens,
            sessions: code.sessions,
            resource_servers: code.resource_servers,
            users: code.users,
            signer: code.signer,
            grant_management: code.grant_management,
            grant_id_claim: code.grant_id_claim,
            lifetimes: code.lifetimes,
            constraint: code.constraint,
            now: code.now,
        }
    }
}

impl std::fmt::Debug for DeviceCode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCode")
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Why a redemption stopped.
enum Failure {
    /// The client can act on it: an RFC 6749 §5.2 (or RFC 8628 §3.5) code and
    /// its description.
    Client(&'static str, &'static str),
    /// The deployment is at fault. Rendered by [`not_issued`], which logs it.
    ///
    /// There is no DPoP variant here, unlike the authorization-code grant.
    /// RFC 9449 §10.1's `dpop_jkt` pins a *code* to a key at the pushed
    /// request, and this flow has no pushed request and no browser: the only
    /// DPoP rule that applies is "the token must be bound to something", which
    /// [`issuance::SenderConstraint`] answers as a client error.
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
impl GrantHandler for DeviceCode<'_> {
    fn grant(&self) -> GrantType {
        GrantType::DeviceCode
    }

    async fn handle(&self, tenant: &Tenant, client: &Client, params: &Parameters) -> Response {
        match self.redeem(tenant, client, params).await {
            Ok(response) => response,
            Err(Failure::Client(code, description)) => refused(code, description),
            Err(Failure::Server(error)) => not_issued(tenant, client, &error),
        }
    }
}

impl DeviceCode<'_> {
    /// The redemption itself, with failures as `Err` so the checks read in
    /// order.
    async fn redeem(
        &self,
        tenant: &Tenant,
        client: &Client,
        params: &Parameters,
    ) -> Result<Response, Failure> {
        // RFC 8628 §3.4: `device_code` is REQUIRED. Absent is
        // `invalid_request`; present but not the shape a device code has is
        // `invalid_grant`, because that is a statement about a credential
        // rather than about the form.
        let presented = params
            .get("device_code")
            .map_err(|_| Failure::Client("invalid_request", "device_code was sent more than once"))?
            .ok_or(Failure::Client(
                "invalid_request",
                "device_code is required",
            ))?;
        let digest = device::device_code_digest_of(presented).map_err(|_| invalid_grant())?;

        let redeemed = self.spent(client, &digest).await?;

        let grant = self
            .grants
            .find(&redeemed.grant_id)
            .await?
            .ok_or_else(invalid_grant)?;
        // A grant revoked or expired between the approval and this poll. The
        // device code was still live, so this is the check that catches it.
        if !matches!(
            grant.status(self.now),
            GrantStatus::Pending | GrantStatus::Active
        ) {
            return Err(invalid_grant());
        }
        let claimed = self.grants.claim(&redeemed.grant_id, self.now).await?;

        let session = issuance::session_facts(self.sessions, &grant).await?;
        // OIDC Back-Channel Logout 1.0 §2.3, as in `authorization_code`: a
        // device that obtained an ID token in this person's session is a
        // relying party that has to be told when it ends.
        issuance::remember_participant(self.sessions, &grant, self.now).await;
        let targeting = self.targeting(tenant, client, &grant, params).await?;
        let confirmation = self
            .constraint
            .confirmation(client)
            .map_err(Self::unbound)?;

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

        // OIDC Core §3.1.3.3, as at the code grant: an ID token accompanies
        // the response only when the grant carries `openid`. There is no
        // `nonce`, because this flow has no authorization request to have
        // carried one — the device never spoke to a browser.
        let id_token = if grant.scopes.contains("openid") {
            let parts = issuance::IdTokenParts {
                claimed: &claimed,
                session: &session,
                access_token: access_token.as_str(),
                nonce: None,
                released: issuance::released_claims(self.users, &grant).await?,
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

        Ok(Self::response(
            &grant,
            issuance::token_type(client),
            access_token.as_str(),
            id_token.as_deref(),
            refresh_token.as_deref(),
            self.lifetimes.access_token(),
        ))
    }

    /// One poll, and the spend if it is time (RFC 8628 §3.4, §3.5).
    ///
    /// Its own function because the four "keep waiting" answers are the
    /// ordinary case here and reading them beside the issuance would bury the
    /// one path that mints anything. Every refusal below is the client's, and
    /// every one of them is a statement §3.5 defines.
    async fn spent(
        &self,
        client: &Client,
        digest: &str,
    ) -> Result<asterius_store_pg::RedeemedDevice, Failure> {
        let polled = self
            .device_codes
            .poll(digest, device::SLOW_DOWN_INCREMENT, self.now)
            .await?
            .ok_or_else(invalid_grant)?;

        // Before the state is acted on: another client's device code is not a
        // device code as far as this request is concerned.
        if polled.client_id != client.id.as_str() {
            return Err(invalid_grant());
        }

        match polled.state {
            Poll::Approved => {}
            // §3.5. The three terminal ones stop the device;
            // `authorization_pending` and `slow_down` tell it to carry on.
            Poll::Pending => {
                return Err(Failure::Client(
                    "authorization_pending",
                    "the authorization request is still pending",
                ));
            }
            Poll::SlowDown { .. } => {
                return Err(Failure::Client(
                    "slow_down",
                    "polling too frequently: increase the interval by five seconds",
                ));
            }
            Poll::Denied => {
                return Err(Failure::Client(
                    "access_denied",
                    "the authorization request was refused",
                ));
            }
            Poll::Expired => {
                return Err(Failure::Client(
                    "expired_token",
                    "the device code has expired",
                ));
            }
            // A second redemption. One answer with an unknown device code, so
            // that nothing here confirms a code was ever real.
            Poll::Spent => return Err(invalid_grant()),
        }

        // The spend. One statement, so two requests racing on one approved
        // device code cannot both be served.
        let redeemed = self
            .device_codes
            .redeem(digest, self.now)
            .await?
            .ok_or_else(invalid_grant)?;
        // Re-checked after the spend as well as before it: the row could have
        // been approved for another client only through a bug, and a bug that
        // mints a token for the wrong client is one this must not carry.
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
            self.grant_management,
        )
        .await
        .map_err(|error| match error {
            issuance::TargetingError::InvalidTarget => {
                Failure::Client(INVALID_TARGET, TARGET_REFUSED)
            }
            issuance::TargetingError::Storage(error) => Failure::Server(error),
        })
    }

    /// Mints the refresh token an `offline_access` grant earns.
    ///
    /// The same shape the code grant issues: the value is handed to the client
    /// once and reaches the database as a digest, and it is bound to what this
    /// request proved possession of.
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
                "a DPoP proof is required to redeem a device code",
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
