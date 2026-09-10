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
//! # Two audiences for one refusal
//!
//! What the client is told and what the operator is told are different
//! documents, and this module writes both (`ast-4j1`).
//!
//! The client gets [`ClientAuthError`], which RFC 6749 §5.2 renders as
//! `invalid_client` and nothing else. That coarseness is the security
//! property: which check failed is a fact about this server's state, and an
//! unauthenticated caller that could tell "no such client" from "wrong key"
//! has an oracle for which client ids exist.
//!
//! The operator gets a `warn` record and an audit event, both naming the
//! internal reason. Before this existed they got neither — a client that could
//! not authenticate produced a 401 and not one line at any log level, so a BFF
//! posting a PAR with no `client_assertion` at all was indistinguishable, from
//! the server's side, from one that never called. Every refusal now passes
//! through [`ClientAuthenticator::report`], which is why [`Refusal`] exists as
//! a type rather than the checks returning `ClientAuthError` directly.
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

use asterius_domain::audit::{Actor, AuditEvent, AuditSink, Detail, EventType, Outcome};
use asterius_domain::{
    Client, ClientId, ClientRepository, ClientUsageRecorder, DomainError, JwksSource, ReplayCheck,
    ReplayGuard, ReplayPurpose, SigningAlgorithm, Tenant, TenantId, TokenEndpointAuthMethod,
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

/// A refusal, in this server's own words rather than the client's (`ast-4j1`).
///
/// The two are deliberately different documents. The client gets
/// [`ClientAuthError`], which is coarse on purpose — RFC 6749 §5.2 gives it one
/// code, and the reasons this server refuses are facts about its own state
/// that an unauthenticated caller has not earned. The operator gets this,
/// which says which of a dozen things went wrong and what the two sides of the
/// comparison were.
///
/// Before this existed the operator got neither: a client that failed to
/// authenticate produced a 401 and not one log record at any level, so a BFF
/// posting a PAR with no `client_assertion` at all was indistinguishable, from
/// the server's side, from one that never called.
///
/// # What may go in `detail`
///
/// Anything the *server* knows and the client already knows too: the audience
/// it sent, the `kid` it named, the method it is registered for. Never the
/// credential — not the assertion, not a fragment of it, not its signature.
/// The formatter would redact a JWT-shaped value anyway
/// (`crate::observability::redact`), but relying on the net rather than not
/// jumping is how a `Debug` dump of some future struct ends up in a log file.
#[derive(Debug)]
struct Refusal {
    /// What the client is told.
    error: ClientAuthError,
    /// A stable, greppable label for the internal reason. Stable because an
    /// operator building an alert on "how often does audience mismatch happen"
    /// should not have that alert broken by a reworded sentence.
    reason: &'static str,
    /// The specifics, when there are any worth having.
    detail: Option<String>,
    /// The client the request named, when it named one intelligibly.
    client_id: Option<ClientId>,
    /// The `kid` the assertion header named, when it had one.
    kid: Option<String>,
}

impl Refusal {
    /// A refusal with nothing but its reason, derived from the error.
    fn new(error: ClientAuthError) -> Self {
        Self {
            reason: reason_for(&error),
            error,
            detail: None,
            client_id: None,
            kid: None,
        }
    }

    /// Adds the specifics.
    fn because(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Names the client the request was made on behalf of.
    fn by(mut self, client_id: &ClientId) -> Self {
        self.client_id = Some(client_id.clone());
        self
    }

    /// Names the `kid` the assertion header carried.
    fn with_kid(mut self, kid: Option<&asterius_domain::Kid>) -> Self {
        self.kid = kid.map(|kid| kid.as_str().to_owned());
        self
    }
}

impl From<ClientAuthError> for Refusal {
    fn from(error: ClientAuthError) -> Self {
        Self::new(error)
    }
}

/// The internal label for a failure.
///
/// Deliberately not `ClientAuthError`'s `Display`: that text is written for a
/// human reading a spec and changes when somebody improves a sentence, and
/// these are identifiers an operator greps and alerts on. `_` rather than an
/// exhaustive match because `ClientAuthError` is `#[non_exhaustive]`; a variant
/// added upstream is still logged, just without a name of its own.
fn reason_for(error: &ClientAuthError) -> &'static str {
    match error {
        ClientAuthError::MultipleMethods => "more_than_one_method_presented",
        ClientAuthError::NoMethod => "no_client_authentication_presented",
        ClientAuthError::IncompleteAssertion => "assertion_and_type_not_both_present",
        ClientAuthError::UnsupportedAssertionType => "unsupported_client_assertion_type",
        ClientAuthError::ClientIdMismatch => "client_id_does_not_match_assertion_sub",
        ClientAuthError::AssertionNotVerified => "assertion_signature_or_envelope_rejected",
        ClientAuthError::MalformedClaim(_) => "assertion_claim_missing_or_malformed",
        ClientAuthError::WrongSubject => "assertion_iss_or_sub_is_not_the_client",
        ClientAuthError::WrongAudience => "aud_is_not_this_issuer",
        ClientAuthError::LifetimeTooLong => "assertion_lifetime_too_long",
        ClientAuthError::Expired => "assertion_expired",
        ClientAuthError::ReplayedAssertion => "assertion_jti_replayed",
        ClientAuthError::UnknownClient => "unknown_or_disabled_client",
        ClientAuthError::WrongMethodForClient => "client_registered_for_another_method",
        ClientAuthError::KeysUnavailable => "client_keys_unavailable",
        _ => "client_authentication_refused",
    }
}

/// How a client's keys are published, for a log line that has to explain why
/// resolving them failed.
///
/// The distinction is the whole diagnosis in the case ADR-0006 creates: a
/// client whose `jwks_uri` points at a loopback host can never authenticate,
/// because the SSRF guard refuses to dereference it, and the only fix is
/// inline `jwks`. "Keys unavailable" alone does not tell an operator which of
/// those two worlds they are in.
const fn jwks_source_of(source: &JwksSource) -> &'static str {
    match source {
        JwksSource::Inline(_) => "inline jwks",
        JwksSource::Uri(_) => "jwks_uri (dereferenced through the ADR-0006 outbound guard)",
    }
}

/// The `aud` an assertion carried, rendered for a refusal record.
///
/// Rendered rather than printed: `aud` is a client-supplied claim, and the
/// three shapes it arrives in — the right string, an array holding the right
/// string, something else entirely — need to be *distinguishable* in the log,
/// because the array case is the one FAPI 2.0 SP §5.3.2.1 item 8 refuses even
/// when its contents are correct, and an operator who cannot see the brackets
/// will read the line as a contradiction.
///
/// Truncated: the claim comes from a signature-verified token, but the client
/// still chose its length, and a log line is not a place to be generous about
/// that.
fn audience_of(claims: &serde_json::Value) -> String {
    const MAX: usize = 200;
    let rendered = claims
        .get("aud")
        .map_or_else(|| "no aud claim at all".to_owned(), ToString::to_string);
    if rendered.len() <= MAX {
        rendered
    } else {
        format!("{}… ({} bytes)", &rendered[..MAX], rendered.len())
    }
}

/// The refusal record for a claim rule that a signature-verified assertion
/// broke.
///
/// Separate from the check itself because two of the variants deserve a
/// sentence the generic label cannot give them, and because a `match` inside a
/// closure inside the main path is how that path stopped fitting on a screen.
fn claim_refusal(
    error: &ClientAuthError,
    client_id: &ClientId,
    kid: Option<&asterius_domain::Kid>,
    rules: &AssertionRules,
    claims: &serde_json::Value,
) -> Refusal {
    let refusal = Refusal::new(error.clone()).by(client_id).with_kid(kid);
    match error {
        // The one worth spelling out in full: FAPI 2.0 SP §5.3.2.1 item 8
        // accepts the issuer identifier as a JSON *string* and nothing else,
        // so a client sending the token endpoint URL — which OIDC Core §9 used
        // to allow, and which a great deal of client software still does — or
        // a one-element array gets the same `invalid_client` as one with a
        // broken key. Both sides of the comparison go in the record, because
        // this is the failure an integrator cannot possibly diagnose from the
        // response.
        ClientAuthError::WrongAudience => refusal.because(format!(
            "expected aud to be the JSON string \"{}\"; the assertion carried {}",
            rules.audiences.accepted().join("\" or \""),
            audience_of(claims)
        )),
        ClientAuthError::WrongSubject => refusal.because(
            "RFC 7523 §3: iss and sub must both be the client_id the signature was verified \
             against",
        ),
        _ => refusal,
    }
}

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
    /// Where a *refused* authentication is written down (`ast-4j1`).
    ///
    /// Here for the reason `usage` is here: this is the one function all six
    /// endpoints reach, so "a client failed to authenticate" has one
    /// definition and one writer rather than six. `None` is a deployment
    /// without a trail — every test that exercises authentication without a
    /// database — and it costs the audit row, never the log line, which is
    /// written unconditionally.
    audit: Option<Arc<dyn AuditSink>>,
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
            audit: None,
            decoy,
            trust_anchors: crate::mtls::TenantTrustAnchors::default(),
        })
    }

    /// The client key cache this authenticator resolves keys through.
    ///
    /// Exposed for the one other caller that verifies a JWT a *client* signed:
    /// the pushed request endpoint, unwrapping a signed request object
    /// (`ast-gxh.9`). It is the same cache rather than a second one on
    /// purpose — a second would keep its own copy of every `jwks_uri`, its own
    /// backoff, and its own opinion about which of a client's keys are
    /// current, and the two would disagree exactly during a rotation.
    #[must_use]
    pub fn client_keys(&self) -> &Arc<ClientKeyCache> {
        &self.keys
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

    /// Writes every *refused* authentication to `audit` (`ast-4j1`).
    ///
    /// A builder rather than a fourth constructor argument, following
    /// `recording_use` above and for the same reason: a deployment that does
    /// not wire one still authenticates clients, and the call sites do not
    /// change.
    #[must_use]
    pub fn auditing(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(audit);
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
        match self.decide(tenant, clients, attempt, rules, now).await {
            Ok(client) => Ok(client),
            Err(refusal) => {
                // One place, so that no endpoint can refuse a client quietly
                // and no future variant can be added without a trail.
                self.report(tenant, &refusal, now).await;
                Err(refusal.error)
            }
        }
    }

    /// Whether this request authenticates a client, and if not, why not.
    ///
    /// Split from [`Self::authenticate`] purely so that every `return Err`
    /// below passes through one reporting point. The order of the checks, and
    /// the reasons for it, are the module documentation's.
    async fn decide(
        &self,
        tenant: &Tenant,
        clients: &dyn ClientRepository,
        attempt: &Attempt<'_>,
        rules: &AssertionRules,
        now: OffsetDateTime,
    ) -> Result<Client, Refusal> {
        match attempt.method()? {
            Method::PrivateKeyJwt => {}
            Method::Mtls => {
                let certificate = attempt.certificate.ok_or_else(|| {
                    Refusal::new(ClientAuthError::WrongMethodForClient)
                        .because("a certificate method was selected without a certificate")
                })?;
                return self
                    .authenticate_mtls(tenant, clients, attempt, certificate, now)
                    .await;
            }
        }

        let assertion = attempt
            .assertion
            .ok_or_else(|| Refusal::new(ClientAuthError::IncompleteAssertion))?;

        // Parsed, not trusted. The only thing read here is who the token says
        // it is from, because that is how we know whose keys to ask for.
        let unverified = jws::parse(assertion).map_err(|error| {
            Refusal::new(ClientAuthError::AssertionNotVerified)
                .because(format!("the assertion is not a well-formed JWS: {error}"))
        })?;
        let claimed: serde_json::Value = serde_json::from_slice(unverified.unverified_payload())
            .map_err(|error| {
                Refusal::new(ClientAuthError::AssertionNotVerified)
                    .because(format!("the assertion payload is not JSON: {error}"))
                    .with_kid(unverified.kid().as_ref())
            })?;
        let claimed_client = claimed
            .get("sub")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Refusal::new(ClientAuthError::AssertionNotVerified)
                    .because("the assertion has no `sub`, so it names no client")
                    .with_kid(unverified.kid().as_ref())
            })?;

        // RFC 7521 §4.2 lets a request carry `client_id` as well. If it does
        // and the two disagree, the request names two clients — refused before
        // either is looked up, since there is no correct one to pick.
        if attempt.client_id.is_some_and(|id| id != claimed_client) {
            return Err(Refusal::new(ClientAuthError::ClientIdMismatch).because(format!(
                "the client_id form parameter is {:?} and the assertion's sub is {claimed_client:?}",
                attempt.client_id.unwrap_or_default()
            )));
        }

        let client_id = ClientId::new(claimed_client);
        let kid = unverified.kid();
        let client = self
            .assertion_client(tenant, clients, &client_id, kid.as_ref(), assertion)
            .await?;

        let key_set = self
            .keys
            .resolve(
                &tenant.id,
                &client_id,
                &client.registration.jwks,
                kid.as_ref(),
                now,
            )
            .await
            .map_err(|error| {
                Refusal::new(ClientAuthError::KeysUnavailable)
                    .by(&client_id)
                    .with_kid(kid.as_ref())
                    .because(format!(
                        "the client's keys could not be resolved from its {}: {error}",
                        jwks_source_of(&client.registration.jwks)
                    ))
            })?;

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
        let verified = verify(assertion, &policy, &key_set, now).map_err(|error| {
            // The jose error names the envelope rule that failed — an
            // algorithm outside the allow-list, a `typ` that is not a client
            // assertion, an `exp` in the past, an `iat` beyond the FAPI skew
            // window, or no key that verified. That is exactly the set of
            // things an integrator gets wrong and cannot see from
            // `invalid_client`.
            Refusal::new(ClientAuthError::AssertionNotVerified)
                .by(&client_id)
                .with_kid(kid.as_ref())
                .because(format!(
                    "{error}; the client publishes {} usable key(s) via its {}",
                    key_set.keys().len(),
                    jwks_source_of(&client.registration.jwks)
                ))
        })?;

        // Now that the signature holds, the claims are the client's.
        let Assertion { jti, expires_at } =
            check_assertion(&verified.claims, client_id.as_str(), rules, now).map_err(|error| {
                claim_refusal(&error, &client_id, kid.as_ref(), rules, &verified.claims)
            })?;

        // Last. Everything above can reject an assertion without consuming a
        // `jti` the client may legitimately want to reuse after fixing its
        // request.
        self.spend_the_jti(tenant, &client_id, &jti, expires_at, now)
            .await?;
        Ok(client)
    }

    /// Consumes an assertion's `jti`, which is what makes it single-use.
    ///
    /// Called only once every other check has passed, so that a request
    /// refused for any other reason leaves the client's identifier spendable —
    /// otherwise anyone able to reach the endpoint could burn a client's
    /// `jti`s with assertions that were never going to be accepted.
    async fn spend_the_jti(
        &self,
        tenant: &Tenant,
        client_id: &ClientId,
        jti: &str,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), Refusal> {
        match self
            .replay
            .claim(
                &tenant.id,
                ReplayPurpose::ClientAssertion,
                client_id.as_str(),
                jti,
                expires_at,
            )
            .await
        {
            Ok(ReplayCheck::FirstUse) => {
                self.note_use(&tenant.id, client_id, now).await;
                Ok(())
            }
            Ok(ReplayCheck::Replay) => Err(Refusal::new(ClientAuthError::ReplayedAssertion)
                .by(client_id)
                .because(
                    "this jti has already been spent inside its validity window; RFC 7523 §3 \
                     item 7 makes an assertion single-use, so each request needs a fresh one",
                )),
            // An unavailable replay store is not permission to accept a replay.
            Err(error) => Err(Refusal::new(ClientAuthError::KeysUnavailable)
                .by(client_id)
                .because(format!(
                    "the replay guard is unavailable, and an assertion cannot be accepted \
                     without it: {error}"
                ))),
        }
    }

    /// The active client this assertion names, if it is one that authenticates
    /// this way.
    ///
    /// Both refusals here spend a decoy verification first, for the reason the
    /// module documentation gives: how long "no such client" takes must not
    /// differ from how long "wrong key" takes.
    async fn assertion_client(
        &self,
        tenant: &Tenant,
        clients: &dyn ClientRepository,
        client_id: &ClientId,
        kid: Option<&asterius_domain::Kid>,
        assertion: &str,
    ) -> Result<Client, Refusal> {
        let client = match clients.find(client_id).await {
            Ok(Some(client)) if client.is_active() => client,
            // Unknown, or disabled. One answer for both.
            Ok(_) => {
                self.spend_a_verification(assertion);
                return Err(Refusal::new(ClientAuthError::UnknownClient)
                    .by(client_id)
                    .with_kid(kid)
                    .because(format!(
                        "no active client with this client_id is registered in tenant {}; a \
                         client registered in another tenant does not exist at this issuer",
                        tenant.id
                    )));
            }
            // A storage failure is not "no such client". Saying `UnknownClient`
            // here would tell a client its registration is gone during an
            // outage it should simply retry after.
            Err(error) => {
                return Err(Refusal::new(ClientAuthError::KeysUnavailable)
                    .by(client_id)
                    .because(format!("the client repository failed: {error}")));
            }
        };

        if client.registration.token_endpoint_auth_method != TokenEndpointAuthMethod::PrivateKeyJwt
        {
            self.spend_a_verification(assertion);
            return Err(Refusal::new(ClientAuthError::WrongMethodForClient)
                .by(client_id)
                .because(format!(
                    "the request presented a private_key_jwt assertion but the client is \
                     registered for {}",
                    client.registration.token_endpoint_auth_method.as_str()
                )));
        }

        Ok(client)
    }

    /// Records a refusal: a log line always, an audit row when there is a
    /// trail to write to (`ast-4j1`).
    ///
    /// `warn` rather than `info`: this is a client that is not working, which
    /// is either an integration nobody has finished or somebody trying
    /// credentials, and both are worth an operator's attention. `warn` also
    /// clears the default filter — `asterius=info` — so the line appears in
    /// `docker compose logs` without anybody setting `RUST_LOG` first, which
    /// is the difference between this being useful and this being a field in a
    /// struct.
    ///
    /// A failed audit write does not fail the request: the request has already
    /// failed. It is logged at `error`, because a trail that silently stops
    /// being written is worse than one that was never configured.
    ///
    /// # Why writing a row per refusal is affordable
    ///
    /// This is an unauthenticated path, so "one audit row per failure" is a
    /// write an attacker can ask for. It is bounded upstream rather than here:
    /// the per-endpoint limiter of `ast-p2l.3` runs before the endpoint does
    /// any work, and it records its own throttling once per bucket per window
    /// precisely so that a flood cannot make the trail grow with it. Bounding
    /// it a second time here would mean a refusal that is sometimes recorded,
    /// which is the property that makes a trail useless.
    async fn report(&self, tenant: &Tenant, refusal: &Refusal, now: OffsetDateTime) {
        tracing::warn!(
            tenant = %tenant.id,
            client_id = refusal.client_id.as_ref().map_or("<none>", ClientId::as_str),
            reason = refusal.reason,
            detail = refusal.detail.as_deref().unwrap_or(""),
            kid = refusal.kid.as_deref().unwrap_or(""),
            error_code = refusal.error.code(),
            "client authentication failed"
        );

        let Some(audit) = self.audit.as_ref() else {
            return;
        };
        let actor = refusal
            .client_id
            .clone()
            .map_or(Actor::System, Actor::Client);
        let mut detail = Detail::new().label("reason", refusal.reason);
        if let Some(specifics) = refusal.detail.as_deref() {
            detail = detail.text("detail", specifics);
        }
        if let Some(kid) = refusal.kid.as_deref() {
            detail = detail.text("kid", kid);
        }
        let mut event = AuditEvent::new(
            tenant.id.clone(),
            EventType::CLIENT_AUTH_FAILED,
            Outcome::Failure,
            actor,
            now,
        )
        .detail(detail.label("error", refusal.error.code()));
        if let Some(client_id) = refusal.client_id.clone() {
            event = event.client(client_id);
        }
        if let Err(failure) = audit.record(event).await {
            tracing::error!(%failure, tenant = %tenant.id, "could not record a client authentication failure");
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
    ) -> Result<Client, Refusal> {
        let Some(client_id) = attempt.client_id else {
            return Err(Refusal::new(ClientAuthError::UnknownClient).because(
                "RFC 8705 §2 requires the client_id request parameter alongside a certificate, \
                 and this request carried none",
            ));
        };
        let client_id = ClientId::new(client_id);
        let client = match clients.find(&client_id).await {
            Ok(Some(client)) if client.is_active() => client,
            // Unknown, or disabled. One answer for both, as on the assertion
            // path — the difference is which `client_id` values exist.
            Ok(_) => {
                return Err(Refusal::new(ClientAuthError::UnknownClient)
                    .by(&client_id)
                    .because(format!(
                        "no active client with this client_id is registered in tenant {}",
                        tenant.id
                    )));
            }
            Err(error) => {
                return Err(Refusal::new(ClientAuthError::KeysUnavailable)
                    .by(&client_id)
                    .because(format!("the client repository failed: {error}")));
            }
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
    ) -> Result<Client, Refusal> {
        match client.registration.token_endpoint_auth_method {
            TokenEndpointAuthMethod::PrivateKeyJwt => {
                Err(Refusal::new(ClientAuthError::WrongMethodForClient)
                    .by(client_id)
                    .because(
                        "the request presented a certificate but the client is registered for \
                         private_key_jwt",
                    ))
            }
            TokenEndpointAuthMethod::TlsClientAuth => {
                // RFC 8705 §2.1. The chain first: the name in a certificate
                // nobody vouched for is a name its holder chose.
                let Some(anchors) = self.trust_anchors.for_tenant(&tenant.id) else {
                    // A tenant with no anchors configured cannot use the PKI
                    // method. Falling back to any other root would let a CA
                    // this tenant never named mint its clients.
                    return Err(Refusal::new(ClientAuthError::WrongMethodForClient)
                        .by(client_id)
                        .because(
                            "the client is registered for tls_client_auth but this tenant has no \
                             PKI trust anchors configured",
                        ));
                };
                if !anchors.accepts(certificate, &[], now) {
                    return Err(Refusal::new(ClientAuthError::AssertionNotVerified)
                        .by(client_id)
                        .because(
                            "RFC 8705 §2.1: the certificate does not chain to any of this \
                             tenant's trust anchors",
                        ));
                }
                // Then the name, which `ClientMetadata::validate` guarantees
                // exists for this method — but the guarantee is re-checked
                // rather than assumed, because a row written before that rule
                // existed would otherwise be a client any valid certificate
                // authenticates.
                let Some(expected) = &client.registration.tls_client_auth_subject else {
                    return Err(Refusal::new(ClientAuthError::WrongMethodForClient)
                        .by(client_id)
                        .because(
                            "the registration names no tls_client_auth subject, so no \
                             certificate can match it",
                        ));
                };
                if certificate.matches(expected) {
                    Ok(client)
                } else {
                    Err(Refusal::new(ClientAuthError::AssertionNotVerified)
                        .by(client_id)
                        .because(
                            "RFC 8705 §2.1: the certificate chains correctly but its subject is \
                             not the one this client registered",
                        ))
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
                    .map_err(|error| {
                        Refusal::new(ClientAuthError::KeysUnavailable)
                            .by(client_id)
                            .because(format!(
                                "the client's certificates could not be resolved from its {}: \
                                 {error}",
                                jwks_source_of(&client.registration.jwks)
                            ))
                    })?;
                if certificate.is_one_of(key_set.leaf_certificates().iter().map(String::as_str)) {
                    Ok(client)
                } else {
                    Err(Refusal::new(ClientAuthError::AssertionNotVerified)
                        .by(client_id)
                        .because(format!(
                            "RFC 8705 §2.2: the certificate is not one of the {} the client \
                             published in its JWK Set",
                            key_set.leaf_certificates().len()
                        )))
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
