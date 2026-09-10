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
use asterius_oidc::mtls::ClientCertificate;
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
    /// The PKI-method trust anchors, per tenant (RFC 8705 §2.1).
    ///
    /// Empty unless the deployment loaded any, and empty means no tenant can
    /// use `tls_client_auth`. That is the same posture as the feature flag:
    /// nothing about mTLS happens because a default allowed it.
    trust_anchors: crate::mtls::TenantTrustAnchors,
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
            trust_anchors: crate::mtls::TenantTrustAnchors::default(),
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

    /// Gives the authenticator the tenants' PKI-method trust anchors.
    ///
    /// Called by the composition root only when `[features] mtls` is on. An
    /// authenticator without them refuses `tls_client_auth` outright, which is
    /// what makes the flag and the behaviour one switch rather than two.
    #[must_use]
    pub fn with_trust_anchors(mut self, anchors: crate::mtls::TenantTrustAnchors) -> Self {
        self.trust_anchors = anchors;
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
            Method::Mtls => {
                let certificate = attempt
                    .certificate
                    .ok_or(ClientAuthError::WrongMethodForClient)?;
                return self
                    .authenticate_mtls(tenant, clients, attempt, certificate, now)
                    .await;
            }
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

    /// RFC 8705 §2: authenticates a client by the certificate it presented.
    ///
    /// The order mirrors the assertion path, and for the same reasons.
    ///
    /// 1. **Who does the request say it is?** RFC 8705 §2 is explicit: "the
    ///    client MUST use the `client_id` request parameter". There is nothing
    ///    inside a certificate that names a client of *this* server, so a
    ///    request without it names nobody.
    /// 2. **Does that client exist, and does it authenticate this way?**
    /// 3. **Then, and only then, the certificate**, by whichever of §2.1 and
    ///    §2.2 the client registered for. The two are not alternatives that get
    ///    tried in turn: a `tls_client_auth` client is never authenticated by a
    ///    self-signed certificate it happens to have published, and a
    ///    `self_signed_tls_client_auth` client is never authenticated by a name
    ///    in a certificate some CA issued.
    ///
    /// No `jti` is consumed, because there is no assertion: a certificate is
    /// not a one-time credential. Replay of the *request* is what
    /// sender-constrained tokens and PKCE address, not this.
    async fn authenticate_mtls(
        &self,
        tenant: &Tenant,
        clients: &dyn ClientRepository,
        attempt: &Attempt<'_>,
        certificate: &ClientCertificate,
        now: OffsetDateTime,
    ) -> Result<Client, ClientAuthError> {
        let Some(client_id) = attempt.client_id else {
            return Err(ClientAuthError::UnknownClient);
        };
        let client_id = ClientId::new(client_id);
        let client = match clients.find(&client_id).await {
            Ok(Some(client)) if client.is_active() => client,
            // Unknown, or disabled. One answer for both, as on the assertion
            // path — the difference is which `client_id` values exist.
            Ok(_) => return Err(ClientAuthError::UnknownClient),
            Err(_) => return Err(ClientAuthError::KeysUnavailable),
        };

        let authenticated = self
            .check_certificate(tenant, &client_id, client, certificate, now)
            .await?;
        // The same fact the assertion path records, written in the same place:
        // a client is used exactly when it authenticates, and mTLS is a second
        // way to do that rather than a second definition of "used" (`ast-cu3`).
        self.note_use(&tenant.id, &client_id, now).await;
        Ok(authenticated)
    }

    /// Which of RFC 8705's two certificate checks applies, and its answer.
    ///
    /// Split from [`Self::authenticate_mtls`] so that "the client
    /// authenticated" is decided in one expression and recorded in one place,
    /// rather than at each of the three arms below.
    async fn check_certificate(
        &self,
        tenant: &Tenant,
        client_id: &ClientId,
        client: Client,
        certificate: &ClientCertificate,
        now: OffsetDateTime,
    ) -> Result<Client, ClientAuthError> {
        match client.registration.token_endpoint_auth_method {
            TokenEndpointAuthMethod::PrivateKeyJwt => Err(ClientAuthError::WrongMethodForClient),
            TokenEndpointAuthMethod::TlsClientAuth => {
                // RFC 8705 §2.1. The chain first: the name in a certificate
                // nobody vouched for is a name its holder chose.
                let Some(anchors) = self.trust_anchors.for_tenant(&tenant.id) else {
                    // A tenant with no anchors configured cannot use the PKI
                    // method. Falling back to any other root would let a CA
                    // this tenant never named mint its clients.
                    return Err(ClientAuthError::WrongMethodForClient);
                };
                if !anchors.accepts(certificate, &[], now) {
                    return Err(ClientAuthError::AssertionNotVerified);
                }
                // Then the name, which `ClientMetadata::validate` guarantees
                // exists for this method — but the guarantee is re-checked
                // rather than assumed, because a row written before that rule
                // existed would otherwise be a client any valid certificate
                // authenticates.
                let Some(expected) = &client.registration.tls_client_auth_subject else {
                    return Err(ClientAuthError::WrongMethodForClient);
                };
                if certificate.matches(expected) {
                    Ok(client)
                } else {
                    Err(ClientAuthError::AssertionNotVerified)
                }
            }
            TokenEndpointAuthMethod::SelfSignedTlsClientAuth => {
                // RFC 8705 §2.2. No chain, no anchors, no name: the whole of
                // the check is that this is a certificate the client itself
                // published.
                let key_set = self
                    .keys
                    .resolve(&tenant.id, client_id, &client.registration.jwks, None, now)
                    .await
                    .map_err(|_| ClientAuthError::KeysUnavailable)?;
                if certificate.is_one_of(key_set.leaf_certificates().iter().map(String::as_str)) {
                    Ok(client)
                } else {
                    Err(ClientAuthError::AssertionNotVerified)
                }
            }
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
