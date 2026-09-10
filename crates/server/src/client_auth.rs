//! Authenticating a client, end to end.
//!
//! One authenticator, shared by every endpoint that requires client
//! authentication: token, PAR, introspection, revocation, device authorization
//! and CIBA backchannel. Six endpoints with one implementation, because six
//! implementations would be six chances to forget the replay check.
//!
//! # What this composes
//!
//! The rules live in [`asterius_oidc::client_auth`], where they are pure
//! functions over a claims object and are tested as such. The cryptography
//! lives in [`asterius_jose`]. The keys come from
//! [`asterius_jose::client_keys::ClientKeyCache`], which fetches them through
//! the guarded outbound path of ADR-0006. This module is the wiring, and its
//! only real content is the *order* the pieces run in:
//!
//! 1. Which method was presented — before looking at any credential, because
//!    "you sent two" is not a question about either of them.
//! 2. Who the assertion claims to be, read from an **unverified** token. This
//!    is unavoidable: the `sub` is how we know whose keys to fetch. Nothing
//!    else is read from it, and nothing is decided on it.
//! 3. Whether that client exists, is enabled, and authenticates this way.
//! 4. The signature, against keys resolved for that client.
//! 5. The assertion's claims (`asterius_oidc::client_auth::check_assertion`).
//! 6. The `jti`, last.
//!
//! Step 6 is last on purpose. Claiming a `jti` consumes it, so doing it before
//! the other checks would let anyone who can reach this endpoint burn a
//! client's identifiers with assertions that were never going to be accepted.
//!
//! # Timing
//!
//! A failure must not reveal whether the `client_id` exists. When the client
//! is unknown, disabled, or registered for another method, this module still
//! performs a signature verification against a throwaway key before returning.
//!
//! That equalises the *cryptographic* work, which is the dominant and most
//! measurable cost. It does not equalise everything, and the gap is recorded
//! rather than papered over: a known client whose keys are not cached triggers
//! an outbound fetch, which is far slower than any local path. So the
//! observable signal is not "does this client exist" but "is this client's key
//! set cached", which an attacker can also produce for a client they already
//! know exists. See `docs/threat-model.md`.

use asterius_domain::{
    Client, ClientId, ClientRepository, ClientUsageRecorder, DomainError, ReplayCheck, ReplayGuard,
    ReplayPurpose, SigningAlgorithm, Tenant, TenantId, TokenEndpointAuthMethod,
};
use asterius_jose::client_keys::ClientKeyCache;
use asterius_jose::verify::{Policy, TypRule};
use asterius_jose::{SigningKey, VerifyingKey, jws, verify};
use asterius_oidc::client_auth::{
    Assertion, AssertionRules, Attempt, ClientAuthError, Method, check_assertion,
};
use std::sync::Arc;
use time::OffsetDateTime;

/// `typ` values accepted on a client assertion.
///
/// RFC 7523 defines none, so most clients send nothing or `JWT`. RFC 8725
/// §3.11 would prefer an explicit type and registers
/// `client-authentication+jwt` for exactly this; accepting it lets a client
/// that has moved to explicit typing keep working, without requiring it of one
/// that has not. Anything else is refused — an access token presented as a
/// client assertion is not a spelling difference.
const ASSERTION_TYP: TypRule =
    TypRule::OptionalOneOf(&["JWT", "client-authentication+jwt", "jwt-bearer"]);

/// Authenticates clients.
///
/// Holds no tenant: the tenant is part of every call, because one process
/// serves all of them.
pub struct ClientAuthenticator {
    keys: Arc<ClientKeyCache>,
    replay: Arc<dyn ReplayGuard>,
    /// Where "this client was used" is written (`ast-cu3`).
    ///
    /// Here rather than at the three call sites, because this is the one
    /// function both the token endpoint and PAR reach: a client is used
    /// exactly when it authenticates, and putting the write anywhere else
    /// would be two definitions of the same fact.
    ///
    /// `None` is a deployment that does not record it — every test that
    /// exercises authentication without a database — and it costs only the
    /// retention rule that reads the column, which is opt-in per tenant
    /// anyway.
    usage: Option<Arc<dyn ClientUsageRecorder>>,
    /// A key nothing signs with, used to spend the same cryptographic effort
    /// on a client that does not exist as on one that does. Generated once:
    /// generating per request would itself be a timing signal, and a slower
    /// one than the verification it is hiding.
    decoy: VerifyingKey,
}

impl std::fmt::Debug for ClientAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientAuthenticator")
            .finish_non_exhaustive()
    }
}

impl ClientAuthenticator {
    /// Builds an authenticator.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Storage`] if the decoy key cannot be generated,
    /// which means the process has no working CSPRNG and should not start.
    pub fn new(
        keys: Arc<ClientKeyCache>,
        replay: Arc<dyn ReplayGuard>,
    ) -> Result<Self, DomainError> {
        let decoy = SigningKey::generate(SigningAlgorithm::EdDsa)
            .and_then(|key| key.verifying_key())
            .map_err(|e| DomainError::Storage(Box::new(e)))?;
        Ok(Self {
            keys,
            replay,
            usage: None,
            decoy,
        })
    }

    /// Records every successful authentication through `usage`.
    ///
    /// A builder rather than a fourth constructor argument, following
    /// `ClientKeyCache::sharing_backoff`: a deployment that does not wire one
    /// still authenticates clients, and the three call sites do not change.
    #[must_use]
    pub fn recording_use(mut self, usage: Arc<dyn ClientUsageRecorder>) -> Self {
        self.usage = Some(usage);
        self
    }

    /// Authenticates the client behind `attempt`.
    ///
    /// `clients` is the repository for `tenant` — the caller has already
    /// resolved the tenant, so passing a repository scoped to a different one
    /// is not expressible here.
    ///
    /// # Errors
    ///
    /// Returns a [`ClientAuthError`] whose [`code`] and [`status`] are what the
    /// endpoint should render. No variant distinguishes "no such client" from
    /// "wrong key".
    ///
    /// [`code`]: ClientAuthError::code
    /// [`status`]: ClientAuthError::status
    pub async fn authenticate(
        &self,
        tenant: &Tenant,
        clients: &dyn ClientRepository,
        attempt: &Attempt<'_>,
        rules: &AssertionRules,
        now: OffsetDateTime,
    ) -> Result<Client, ClientAuthError> {
        match attempt.method()? {
            Method::PrivateKeyJwt => {}
            // RFC 8705 is `ast-m9c.3`. Refusing it as an unregistered method is
            // honest: a client that presents a certificate here has not
            // authenticated, and saying so is better than a 501 that leaves it
            // unclear whether the credential was even looked at.
            Method::Mtls => return Err(ClientAuthError::WrongMethodForClient),
        }

        let assertion = attempt
            .assertion
            .ok_or(ClientAuthError::IncompleteAssertion)?;

        // Parsed, not trusted. The only thing read here is who the token says
        // it is from, because that is how we know whose keys to ask for.
        let unverified =
            jws::parse(assertion).map_err(|_| ClientAuthError::AssertionNotVerified)?;
        let claimed: serde_json::Value = serde_json::from_slice(unverified.unverified_payload())
            .map_err(|_| ClientAuthError::AssertionNotVerified)?;
        let claimed_client = claimed
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .ok_or(ClientAuthError::AssertionNotVerified)?;

        // RFC 7521 §4.2 lets a request carry `client_id` as well. If it does
        // and the two disagree, the request names two clients — refused before
        // either is looked up, since there is no correct one to pick.
        if attempt.client_id.is_some_and(|id| id != claimed_client) {
            return Err(ClientAuthError::ClientIdMismatch);
        }

        let client_id = ClientId::new(claimed_client);
        let client = match clients.find(&client_id).await {
            Ok(Some(client)) if client.is_active() => client,
            // Unknown, or disabled. One answer for both.
            Ok(_) => {
                self.spend_a_verification(assertion);
                return Err(ClientAuthError::UnknownClient);
            }
            // A storage failure is not "no such client". Saying `UnknownClient`
            // here would tell a client its registration is gone during an
            // outage it should simply retry after.
            Err(_) => return Err(ClientAuthError::KeysUnavailable),
        };

        if client.registration.token_endpoint_auth_method != TokenEndpointAuthMethod::PrivateKeyJwt
        {
            self.spend_a_verification(assertion);
            return Err(ClientAuthError::WrongMethodForClient);
        }

        let key_set = self
            .keys
            .resolve(
                &tenant.id,
                &client_id,
                &client.registration.jwks,
                unverified.kid().as_ref(),
                now,
            )
            .await
            .map_err(|_| ClientAuthError::KeysUnavailable)?;

        // The signature, and everything RFC 8725 asks of the envelope: size,
        // `crit`, an allow-listed algorithm, `exp` in the future, and the
        // FAPI 2.0 SP §5.3.2.1 item 13 skew window on `iat`/`nbf`.
        //
        // `expected_audience` is deliberately *not* set. The generic check
        // accepts `aud` as an array, which RFC 7519 §4.1.3 permits and FAPI
        // 2.0 SP §5.3.2.1 item 8 does not; the stricter string-only rule is
        // applied below by `check_assertion`. Setting both would leave the
        // laxer one deciding.
        let policy = Policy::new(ASSERTION_TYP, SigningAlgorithm::ALL.to_vec());
        let verified = verify(assertion, &policy, &key_set, now)
            .map_err(|_| ClientAuthError::AssertionNotVerified)?;

        // Now that the signature holds, the claims are the client's.
        let Assertion { jti, expires_at } =
            check_assertion(&verified.claims, client_id.as_str(), rules, now)?;

        // Last. Everything above can reject an assertion without consuming a
        // `jti` the client may legitimately want to reuse after fixing its
        // request.
        match self
            .replay
            .claim(
                &tenant.id,
                ReplayPurpose::ClientAssertion,
                client_id.as_str(),
                &jti,
                expires_at,
            )
            .await
        {
            Ok(ReplayCheck::FirstUse) => {
                self.note_use(&tenant.id, &client_id, now).await;
                Ok(client)
            }
            Ok(ReplayCheck::Replay) => Err(ClientAuthError::ReplayedAssertion),
            // An unavailable replay store is not permission to accept a replay.
            Err(_) => Err(ClientAuthError::KeysUnavailable),
        }
    }

    /// Notes that a client authenticated, for `ast-cu3`'s idle-client sweep.
    ///
    /// A failure is logged and swallowed. The client has authenticated: the
    /// assertion verified, the `jti` was claimed, and refusing it now because
    /// a bookkeeping write failed would turn a slow `UPDATE` into an outage at
    /// the token endpoint. The cost of a lost write is that one sweep may
    /// consider a live client idle, which is why the window that reads this is
    /// a number of days an operator chose.
    async fn note_use(&self, tenant: &TenantId, client_id: &ClientId, now: OffsetDateTime) {
        let Some(usage) = self.usage.as_ref() else {
            return;
        };
        if let Err(failure) = usage.record_use(tenant, client_id, now).await {
            tracing::warn!(
                %failure,
                %tenant,
                client = %client_id,
                "could not record that a client authenticated"
            );
        }
    }

    /// Verifies `assertion` against a key that cannot have signed it.
    ///
    /// The result is discarded — it is always a failure. What is wanted is the
    /// time: a caller probing for valid `client_id` values should not be able
    /// to tell "no such client" from "wrong signature" by how quickly it is
    /// refused.
    fn spend_a_verification(&self, assertion: &str) {
        let decoy = self.decoy.clone();
        let policy = Policy::new(ASSERTION_TYP, SigningAlgorithm::ALL.to_vec());
        let resolver = move |_: Option<&asterius_domain::Kid>| vec![decoy.clone()];
        let _ = verify(assertion, &policy, &resolver, OffsetDateTime::UNIX_EPOCH);
    }
}
