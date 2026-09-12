//! Authorization server metadata, and the endpoint registry it is built from.
//!
//! RFC 8414 §2 says metadata must reflect actual behaviour. The usual way that
//! stops being true is undramatic: an endpoint is added and the document is not
//! updated, or a feature is switched off and its key stays. Both are silent,
//! and both are only discovered by a client that trusted the document.
//!
//! So there is one list. [`Endpoint`] knows its path, its metadata key and the
//! feature flag that gates it; the router mounts exactly
//! [`Endpoint::enabled`], and the document advertises exactly the same. An
//! endpoint cannot be advertised without being routed, or routed without being
//! advertised, because both come from the same iterator.
//!
//! ## Why some endpoints answer 501
//!
//! OIDC Discovery §3 makes `authorization_endpoint`, `token_endpoint` and
//! `jwks_uri` REQUIRED. A document omitting them is not a smaller document, it
//! is an invalid one, and a conformance suite will say so. But most of those
//! endpoints have not been implemented yet.
//!
//! Advertising them and answering **501 Not Implemented** is the honest
//! resolution: the document is valid and describes the intended shape, the
//! route exists so the parity test passes, and a client gets a truthful answer
//! rather than a 404 that says "no such endpoint here" when the truth is "not
//! yet". Each story replaces its own 501 with a real handler.

use asterius_domain::{Capabilities, Feature, Issuer, SigningAlgorithm};
use serde_json::{Value, json};

/// A protocol endpoint this server can expose.
///
/// The set is closed. Adding a variant is what makes an endpoint exist, and it
/// makes it exist in the router and in the document at the same time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Endpoint {
    /// RFC 6749 §3.1. PAR-only: it accepts `client_id` and `request_uri`.
    Authorization,
    /// RFC 9126 §2.
    PushedAuthorizationRequest,
    /// RFC 6749 §3.2.
    Token,
    /// OIDC Discovery §3, `jwks_uri`.
    Jwks,
    /// OIDC Core §5.3.
    UserInfo,
    /// RFC 7662 §2.
    Introspection,
    /// RFC 7009 §2.
    Revocation,
    /// RFC 7591 §3.
    Registration,
    /// OIDC RP-Initiated Logout §2.
    EndSession,
    /// RFC 8628 §3.1. Gated on [`Feature::DeviceFlow`].
    DeviceAuthorization,
    /// CIBA Core 1.0 §7. Gated on [`Feature::Ciba`].
    BackchannelAuthentication,
    /// Grant Management §4. Gated on [`Feature::GrantManagement`].
    GrantManagement,
    /// AuthZEN 1.0 §4. Gated on [`Feature::Authzen`].
    AccessEvaluation,
    /// Authorization API 1.0 §7 — the boxcar. Gated on [`Feature::Authzen`].
    ///
    /// Its own registry entry rather than a second verb on
    /// [`Self::AccessEvaluation`]: §10.1 gives it a path of its own, §12 gives
    /// it a metadata member of its own, and a PEP's access token is audienced
    /// at the URL it will be presented to. One entry, so the path the router
    /// mounts, the URL the document advertises and the audience the token must
    /// carry cannot come apart (`ast-o0t.3`).
    AccessEvaluations,
}

impl Endpoint {
    /// Every endpoint, in the order metadata lists them.
    pub const ALL: [Self; 14] = [
        Self::Authorization,
        Self::PushedAuthorizationRequest,
        Self::Token,
        Self::Jwks,
        Self::UserInfo,
        Self::Introspection,
        Self::Revocation,
        Self::Registration,
        Self::EndSession,
        Self::DeviceAuthorization,
        Self::BackchannelAuthentication,
        Self::GrantManagement,
        Self::AccessEvaluation,
        Self::AccessEvaluations,
    ];

    /// The path, relative to the tenant.
    ///
    /// Tenancy is stripped by the middleware before routing (`ast-83p.10`), so
    /// this is what the router mounts *and* what is appended to the issuer to
    /// build the advertised URL. One string, both jobs, no chance of them
    /// disagreeing.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Authorization => "/authorize",
            Self::PushedAuthorizationRequest => "/par",
            Self::Token => "/token",
            Self::Jwks => "/jwks",
            Self::UserInfo => "/userinfo",
            Self::Introspection => "/introspect",
            Self::Revocation => "/revoke",
            Self::Registration => "/register",
            Self::EndSession => "/logout",
            Self::DeviceAuthorization => "/device_authorization",
            Self::BackchannelAuthentication => "/bc-authorize",
            Self::GrantManagement => "/grants",
            Self::AccessEvaluation => "/access/v1/evaluation",
            Self::AccessEvaluations => "/access/v1/evaluations",
        }
    }

    /// The metadata member that carries this endpoint's URL.
    #[must_use]
    pub const fn metadata_key(self) -> &'static str {
        match self {
            Self::Authorization => "authorization_endpoint",
            Self::PushedAuthorizationRequest => "pushed_authorization_request_endpoint",
            Self::Token => "token_endpoint",
            Self::Jwks => "jwks_uri",
            Self::UserInfo => "userinfo_endpoint",
            Self::Introspection => "introspection_endpoint",
            Self::Revocation => "revocation_endpoint",
            Self::Registration => "registration_endpoint",
            Self::EndSession => "end_session_endpoint",
            Self::DeviceAuthorization => "device_authorization_endpoint",
            Self::BackchannelAuthentication => "backchannel_authentication_endpoint",
            Self::GrantManagement => "grant_management_endpoint",
            Self::AccessEvaluation => "access_evaluation_endpoint",
            Self::AccessEvaluations => "access_evaluations_endpoint",
        }
    }

    /// The feature that must be on for this endpoint to exist, if any.
    #[must_use]
    pub const fn required_feature(self) -> Option<Feature> {
        match self {
            Self::DeviceAuthorization => Some(Feature::DeviceFlow),
            Self::BackchannelAuthentication => Some(Feature::Ciba),
            Self::GrantManagement => Some(Feature::GrantManagement),
            Self::AccessEvaluation | Self::AccessEvaluations => Some(Feature::Authzen),
            // RFC 7591. Follows `[registration] mode`, narrowed per tenant by
            // the stored registration policy (`ast-m9c.6`): a tenant that
            // registers nobody neither advertises the endpoint nor answers at
            // it, which is the parity `ast-o0t.3` asserts.
            Self::Registration => Some(Feature::DynamicClientRegistration),
            _ => None,
        }
    }

    /// Whether a client authenticates at this endpoint.
    ///
    /// The set RFC 8705 §5 gives an `mtls_endpoint_aliases` member: the
    /// aliases exist so a client using mTLS reaches an interface that asks for
    /// its certificate, and only an endpoint that authenticates the client has
    /// any use for one. `/authorize` and `/logout` are browser destinations,
    /// `/jwks` and `/userinfo` authenticate nobody or a *token*, and
    /// `/register` authenticates an initial access token rather than a client
    /// that exists yet.
    ///
    /// Written as a match over every variant rather than a list, so a new
    /// endpoint has to answer the question before it compiles.
    #[must_use]
    pub const fn is_client_authenticated(self) -> bool {
        match self {
            Self::Token
            | Self::PushedAuthorizationRequest
            | Self::Introspection
            | Self::Revocation
            | Self::DeviceAuthorization
            | Self::BackchannelAuthentication => true,
            Self::Authorization
            | Self::Jwks
            | Self::UserInfo
            | Self::Registration
            | Self::EndSession
            | Self::GrantManagement
            | Self::AccessEvaluation
            | Self::AccessEvaluations => false,
        }
    }

    /// Whether this build serves this endpoint at all, flags aside.
    ///
    /// True everywhere, now that `ast-lh3.4` has mounted the backchannel
    /// authentication endpoint — and the method stays, with its match written
    /// out, because it is the hinge the module's opening argument turns on. A
    /// 501 is a truthful answer for an endpoint OIDC Discovery §3 makes
    /// REQUIRED: the document is invalid without the member, so the choice is
    /// between advertising a URL that answers "not yet" and publishing a
    /// document a conformance suite refuses.
    ///
    /// An *optional* endpoint has no such excuse, which is why
    /// `backchannel_authentication_endpoint` answered `false` here until it
    /// had a handler: CIBA Core 1.0 §4 makes it and
    /// `backchannel_token_delivery_modes_supported` REQUIRED together, so a
    /// document carrying the URL alone is not a smaller CIBA document but an
    /// invalid one, and a client that found the URL would send a `login_hint`
    /// and a signed request to a 501. The next optional endpoint registered
    /// here before it is built answers `false` for the same reason.
    ///
    /// The property this buys is the parity between what is routed and what is
    /// advertised: both read this one answer, rather than two lists that could
    /// disagree.
    #[must_use]
    pub const fn has_a_handler(self) -> bool {
        match self {
            Self::Authorization
            | Self::PushedAuthorizationRequest
            | Self::Token
            | Self::Jwks
            | Self::UserInfo
            | Self::Introspection
            | Self::Revocation
            | Self::Registration
            | Self::EndSession
            | Self::DeviceAuthorization
            | Self::BackchannelAuthentication
            | Self::GrantManagement
            | Self::AccessEvaluation
            | Self::AccessEvaluations => true,
        }
    }

    /// Whether this endpoint belongs in the PDP metadata document
    /// (Authorization API 1.0 §9.1.1) rather than in the OP's own.
    ///
    /// Two documents read one registry. `/.well-known/authzen-configuration`
    /// defines `access_evaluation_endpoint` and its boxcar sibling and nothing
    /// else: a member RFC 8414 defines has no meaning there, and a PEP reading
    /// the PDP document would be reading an OP it never asked about.
    ///
    /// Written as a match over every variant, like
    /// [`Endpoint::is_client_authenticated`], so that the next endpoint has to
    /// say which document describes it before it compiles.
    #[must_use]
    pub const fn in_pdp_metadata(self) -> bool {
        match self {
            Self::AccessEvaluation => true,
            Self::Authorization
            | Self::PushedAuthorizationRequest
            | Self::Token
            | Self::Jwks
            | Self::UserInfo
            | Self::Introspection
            | Self::Revocation
            | Self::Registration
            | Self::EndSession
            | Self::DeviceAuthorization
            | Self::BackchannelAuthentication
            | Self::GrantManagement => false,
        }
    }

    /// Whether this deployment exposes this endpoint.
    #[must_use]
    pub fn is_enabled(self, capabilities: &Capabilities) -> bool {
        self.has_a_handler()
            && self
                .required_feature()
                .is_none_or(|feature| capabilities.is_enabled(feature))
    }

    /// The endpoints this deployment exposes.
    pub fn enabled(capabilities: &Capabilities) -> impl Iterator<Item = Self> + '_ {
        Self::ALL
            .into_iter()
            .filter(|endpoint| endpoint.is_enabled(capabilities))
    }

    /// The absolute URL, for the metadata document.
    #[must_use]
    pub fn url(self, issuer: &Issuer) -> String {
        format!("{}{}", issuer.as_str(), self.path())
    }
}

/// The grant types this deployment supports.
///
/// `authorization_code`, `refresh_token` and `client_credentials` are always
/// present; the rest follow their flags.
///
/// The three unconditional ones are the three [`GrantType`]s with no
/// `required_feature`, and each has a handler at the token endpoint. That
/// parity is the property this list exists to keep: `client_credentials` was
/// removed from it while the endpoint answered 501 for the grant, because a
/// discovery document is read once, at registration time, by a client that
/// cannot check. It went back in with the handler (`ast-a05.8`), and
/// `crates/server/tests/client_credentials.rs` asserts both halves.
///
/// [`GrantType`]: asterius_domain::entities::client::GrantType
#[must_use]
pub fn grant_types(capabilities: &Capabilities) -> Vec<&'static str> {
    let mut grants = vec!["authorization_code", "refresh_token", "client_credentials"];
    if capabilities.token_exchange {
        grants.push("urn:ietf:params:oauth:grant-type:token-exchange");
    }
    if capabilities.device_flow {
        grants.push("urn:ietf:params:oauth:grant-type:device_code");
    }
    // CIBA Core 1.0 §4 lists the grant among the OP's CIBA metadata, next to
    // the endpoint a client would take it to. So it follows the endpoint, not
    // the flag: while `ast-lh3.4` is unbuilt there is nowhere to send a
    // backchannel authentication request, and a `grant_types_supported` naming
    // the grant would be read — once, at registration time, by a client that
    // cannot check — as a promise that it works. Registration still refuses the
    // grant when the flag is off (`GrantType::required_feature`); what a
    // deployment with the flag on gets is a validated, stored CIBA client and
    // nothing advertised.
    if Endpoint::BackchannelAuthentication.is_enabled(capabilities) {
        grants.push("urn:openid:params:grant-type:ciba");
    }
    grants
}

/// The client authentication methods this deployment accepts.
///
/// `private_key_jwt` always; the mTLS methods only behind the flag. There is no
/// `client_secret_*` and no `none` (ADR-0002), so the shortest this list gets
/// is one entry.
#[must_use]
pub fn token_endpoint_auth_methods(capabilities: &Capabilities) -> Vec<&'static str> {
    let mut methods = vec!["private_key_jwt"];
    if capabilities.mtls {
        methods.push("tls_client_auth");
        methods.push("self_signed_tls_client_auth");
    }
    methods
}

/// The response modes this server delivers, from the one enum that decides.
///
/// RFC 8414 §2 asks the document to reflect actual behaviour;
/// [`crate::authorize::ResponseMode`] is that behaviour, since it is what the
/// pushed authorization request endpoint parses and what the delivery site
/// matches on. Adding a variant there adds it here, in the declaration order.
fn response_modes() -> Vec<&'static str> {
    crate::authorize::ResponseMode::ALL
        .into_iter()
        .map(crate::authorize::ResponseMode::as_str)
        .collect()
}

fn algorithms() -> Vec<&'static str> {
    SigningAlgorithm::ALL
        .iter()
        .map(|alg| alg.as_str())
        .collect()
}

/// The claims a client may see, from the two places that can produce one.
///
/// OIDC Discovery §3's `claims_supported`, assembled rather than written out:
/// [`ID_TOKEN_CLAIMS`] is what [`crate::tokens::id_token`] asserts about the
/// exchange, and [`crate::claims::claims_from_user_columns`] is what
/// [`crate::claims::resolve`] can produce about the person for *any* user.
///
/// What is deliberately absent is the rest of the
/// [`ClaimSet`](asterius_domain::ClaimSet): `name`, `nickname` and the other
/// §5.4 claims are released on request, but only to a user who happens to have
/// them stored, and a tenant's static document is in no position to say who
/// does. The list used to name two of them, and the OpenID Foundation suite
/// duly asked for both and got neither (`ast-8p1`). See
/// [`crate::claims::claims_from_user_columns`] for why a short list is the
/// honest one and a long list is not.
///
/// `preferred_username` is the one that came back, and it came back with
/// something that serves it (`ast-pew`, `ast-2vk.8`): the sign-up page of
/// OpenID Connect Prompt Create 1.0 §3 asks for a display name and stores it
/// under that claim, and the account pages let a person change it. It is not
/// projected from `users.username` — the login identifier is unique and stable
/// and is not a display preference, and OIDC Core §5.1 is explicit that an RP
/// "MUST NOT rely upon this value being unique" — so what is advertised is a
/// claim this deployment produces, for the users who chose one. Discovery §3
/// asks for "the Claim Names of the Claims that the OpenID Provider MAY be able
/// to supply values for", and Core §5.3.2 says a claim that is not available is
/// omitted; an account with no display name simply has none, which is the
/// ordinary case that member describes.
fn claims_supported() -> Vec<&'static str> {
    let mut names = ID_TOKEN_CLAIMS.to_vec();
    names.extend(crate::claims::claims_from_user_columns());
    names.push(SELF_CHOSEN_CLAIM);
    names
}

/// The one §5.4 claim this deployment writes for a user rather than reads out
/// of a column: OIDC Core §5.1's `preferred_username`.
///
/// A constant so that [`claims_supported`] and the test that pins it name the
/// same string, and so that a reader looking for "why is this one different"
/// finds the answer beside it rather than inside a list.
const SELF_CHOSEN_CLAIM: &str = "preferred_username";

/// The claims this server puts in an ID token about the exchange itself.
///
/// In the order OIDC Core §2 lists them, then the two this server adds:
/// `at_hash` (§3.1.3.6) and `sid`.
///
/// `sid` is Back-Channel Logout 1.0 §2.1, and it is here on purpose. It is a
/// registered JWT claim, it is emitted precisely because
/// `backchannel_logout_session_supported` is advertised, and a logout token
/// that could not name the session it ends would make the feature useless.
/// The conformance suite's `CheckForUnexpectedClaimsInIdToken` flags it as a
/// name it does not know — its own message allows for "extensions the test
/// suite is unaware of", and its `ValidateIdTokenStandardClaims` list simply
/// predates Back-Channel Logout. The claim stays; the WARNING is the suite's
/// gap, not this server's (`ast-8p1`).
pub(crate) const ID_TOKEN_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "azp",
    "at_hash",
    "sid",
];

/// Builds the provider metadata document for one tenant.
///
/// `acr` is the tenant's authentication-context ladder, and it is a parameter
/// rather than a constant for the same reason `capabilities` is: RFC 8414 §2
/// requires the document to reflect actual behaviour, and the only thing that
/// knows which `acr` values this deployment can actually produce is the policy
/// the authorization endpoint consults.
///
/// `authorization_details_types` is the same argument again, for RFC 9396 §9.1:
/// the types a tenant has registered are rows in a table, and a document that
/// advertised a type nothing had registered would be telling clients to send a
/// value the pushed request endpoint refuses. An empty slice contributes no
/// member at all rather than an empty array — a client that sees the member
/// present treats rich authorization requests as available.
///
/// The same document serves OIDC Discovery §3 and RFC 8414 §2 — §5 of RFC 8414
/// says the two are compatible, and serving one set of bytes at both locations
/// is the only way they cannot drift.
#[must_use]
pub fn provider_metadata(
    issuer: &Issuer,
    capabilities: &Capabilities,
    acr: &asterius_domain::AcrPolicy,
    authorization_details_types: &[String],
    grant_management: crate::grant_management::Policy,
) -> Value {
    let mut document = json!({
        // OIDC Discovery §4.3: a client checks that this is identical to the
        // URL it used. It is the canonical form and nothing may reformat it.
        "issuer": issuer.as_str(),

        // ADR-0002: code is the only response type, because there is no
        // implicit and no hybrid flow.
        "response_types_supported": ["code"],
        // OAuth 2.0 Multiple Response Type Encoding Practices §2.1, rendered
        // from the enum the pushed-request validator parses, never written out
        // here: a document that advertised a mode `/authorize` refuses would
        // send clients to an `invalid_request`, and one that omitted a mode it
        // accepts would hide it (`ast-iko`). `fragment` is absent because
        // `ResponseMode` has no such variant — there is no implicit and no
        // hybrid flow (ADR-0002).
        "response_modes_supported": response_modes(),
        "grant_types_supported": grant_types(capabilities),
        "subject_types_supported": ["public", "pairwise"],

        // ADR-0003. The same closed list everywhere it appears.
        "id_token_signing_alg_values_supported": algorithms(),
        "token_endpoint_auth_signing_alg_values_supported": algorithms(),
        "request_object_signing_alg_values_supported": algorithms(),
        "userinfo_signing_alg_values_supported": algorithms(),
        "dpop_signing_alg_values_supported": algorithms(),

        "token_endpoint_auth_methods_supported": token_endpoint_auth_methods(capabilities),
        "introspection_endpoint_auth_methods_supported":
            token_endpoint_auth_methods(capabilities),
        "revocation_endpoint_auth_methods_supported": token_endpoint_auth_methods(capabilities),

        // RFC 7636 §4.2 and FAPI 2.0 SP §5.3.2.1: S256 only. `plain` is not a
        // value this server accepts, so it is not a value it advertises.
        // MCP Authorization requires this member to be present.
        "code_challenge_methods_supported": ["S256"],

        // RFC 9126 §5. Always true: PAR is the only way in (ADR-0002).
        "require_pushed_authorization_requests": true,
        // RFC 9207 §3.
        "authorization_response_iss_parameter_supported": true,

        // The `request_uri` values this server accepts come only from PAR, so
        // the client-supplied form is not supported (RFC 9126 §3).
        "request_uri_parameter_supported": false,
        // RFC 9101 §4 and OIDC Core §6.1, and `false` unless the deployment
        // switched `Feature::RequestObject` on. RFC 8414 §2 makes this
        // document a description of actual behaviour: a `true` here from a
        // deployment whose pushed request endpoint answers
        // `request_not_supported` is an invitation to send a parameter that
        // cannot work, and a `false` from one that accepts request objects
        // hides a signature path from the clients that want it (`ast-gxh.9`).
        "request_parameter_supported":
            capabilities.is_enabled(Feature::RequestObject),
        // OIDC Discovery §3, and true because `authorize::validate` parses the
        // parameter into `AuthorizationRequest::claims` and `claims::resolve`
        // acts on what it parsed — the essential `acr` path is the one that
        // changes the response, and `end_to_end` walks it from the push to the
        // ID token. The default for this member is `false`, so leaving it out
        // would have been a client-visible lie about a parameter this server
        // honours (`ast-1sk.5`).
        "claims_parameter_supported": true,

        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "claims_supported": claims_supported(),
        // `claims_locales_supported` is deliberately absent. OIDC Discovery §3
        // makes it OPTIONAL, and the honest value is the set of language tags
        // a tenant's stored claims actually carry: `ClaimsLocales` resolves a
        // preference against the `#tag` suffixes in a user's `ClaimSet`, so
        // the answer is a query over deployment data, not a constant. No
        // tenant carries a localised claim yet, which leaves two truthful
        // renderings — an empty array or no member — and one untruthful one, a
        // written-out list of tags nothing would match. Between the first two,
        // omission is what §3 provides for; an empty array reads as "asked and
        // answered none", which is a different claim about the deployment than
        // "not advertised". Compute it here the day a tenant stores a tagged
        // claim (`ast-1sk.5`).
        // OpenID Connect Prompt Create 1.0 §4. Rendered from the same policy
        // the pushed-request validator consults, never written out here: a
        // tenant that advertised `create` while refusing it would be telling
        // clients to send a value it rejects (`ast-gxh.8`).
        //
        // The policy is built from this tenant's effective capabilities rather
        // than passed in, so that the document and `protocol::authorization_policy`
        // read one fact — `Feature::SelfRegistration` — instead of two that
        // could disagree (`ast-2vk.8`).
        "prompt_values_supported":
            crate::authorize::AuthorizationPolicy::new(
                capabilities.is_enabled(asterius_domain::Feature::SelfRegistration),
            )
            .prompt_values_supported(),
        // RFC 8414 §2 and OIDC Discovery §3: rendered from the tenant's own
        // ladder, never written out here. This member used to name
        // `urn:mace:incommon:iap:silver` — a value from the specification's
        // example that this server could not produce, has never produced, and
        // would have refused as `unmet_authentication_requirements` the moment
        // a client believed the document and asked for it (`ast-2vk.7`).
        "acr_values_supported": acr.supported_values(),
        // OIDC Discovery §3, rendered from the catalogue rather than written
        // out here. A document that advertised a language this build has no
        // words for would be inviting clients to send a `ui_locales` this
        // server answers in English (`ast-ndk.5`), and one that omitted a
        // language it does render hides it from the clients that would ask.
        "ui_locales_supported": asterius_domain::Locale::SUPPORTED_TAGS,

        // Back-channel logout only. There is no front-channel logout and no
        // session management iframe (ast-o4u.4).
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
    });

    let object = document
        .as_object_mut()
        .expect("the literal above is an object");

    // Every enabled endpoint, and only those. A disabled feature contributes no
    // key at all rather than a key with a null or an empty string, because a
    // client that sees the member present treats the capability as present.
    for endpoint in Endpoint::enabled(capabilities) {
        object.insert(
            endpoint.metadata_key().to_owned(),
            json!(endpoint.url(issuer)),
        );
    }

    if !authorization_details_types.is_empty() {
        // RFC 9396 §9.1: "authorization_details_types_supported: A JSON array
        // containing the authorization details types the AS supports."
        object.insert(
            "authorization_details_types_supported".to_owned(),
            json!(authorization_details_types),
        );
    }
    if capabilities.grant_management {
        // Grant Management §7.1: advertising the actions is what tells a client
        // it may send `grant_management_action`, and — for §6.1's `query` and
        // `revoke` — that it may address a grant over HTTP at all. Rendered
        // from `ADVERTISED_ACTIONS`, which splices in the enum the validator
        // parses rather than respelling it, for the reason
        // `response_modes_supported` gives: a document that advertised an
        // action `/par` refuses would send clients to an `invalid_request`.
        //
        // The two API actions are advertised alongside
        // `grant_management_endpoint`, which the endpoint registry above puts
        // in this document under the same flag — so a client that reads
        // `query` here has a URL to send it to.
        object.insert(
            "grant_management_actions_supported".to_owned(),
            json!(crate::grant_management::ADVERTISED_ACTIONS),
        );
        // §7.1: "`grant_management_action_required`: BOOLEAN. Indicates the
        // AS requires the `grant_management_action` parameter." Present
        // whenever the feature is, with its actual value: a client reading
        // `false` learns the parameter is optional here, which is a different
        // thing from a document that does not mention it.
        object.insert(
            "grant_management_action_required".to_owned(),
            json!(grant_management.action_required),
        );
    }
    // CIBA Core 1.0 §4, and gated on the *endpoint* rather than on the flag:
    // §4 makes `backchannel_authentication_endpoint` and
    // `backchannel_token_delivery_modes_supported` REQUIRED together, so they
    // appear together or not at all. Until `ast-lh3.4` mounts a handler,
    // [`Endpoint::has_a_handler`] answers `false` for the endpoint and this
    // block is unreachable however the flag is set — which is the whole of
    // "nothing CIBA is advertised while nothing CIBA is routed", in one place.
    if Endpoint::BackchannelAuthentication.is_enabled(capabilities) {
        // Poll and ping only — push delivers the token to a client-controlled
        // URL, which FAPI does not profile
        // ([`asterius_domain::TokenDeliveryMode`], the same enum client
        // registration parses `backchannel_token_delivery_mode` into).
        object.insert(
            "backchannel_token_delivery_modes_supported".to_owned(),
            json!(
                asterius_domain::TokenDeliveryMode::ALL
                    .map(asterius_domain::TokenDeliveryMode::as_str)
            ),
        );
        // §4: "`backchannel_user_code_parameter_supported` ... whether the OP
        // supports the `user_code` parameter". False, and stated rather than
        // omitted: §7.1.2's code is "a secret ... known only to the user but
        // verifiable by the OP", and this deployment has no per-user secret to
        // verify one against. A client reading `false` here knows not to send
        // one; the endpoint refuses one anyway (`invalid_user_code`), because
        // a client that sent a code believes the person will be challenged and
        // a server that dropped it would put an unchallenged approval in front
        // of them.
        object.insert(
            "backchannel_user_code_parameter_supported".to_owned(),
            json!(false),
        );
        // §4: "`backchannel_authentication_request_signing_alg_values_supported`
        // ... the JWS signing algorithms supported for signed authentication
        // requests" (§7.1.1). The same closed list ADR-0003 gives everywhere
        // else, because a signed authentication request is verified by the
        // same verifier a request object is and there is no algorithm one
        // would take that the other would not. `none` is absent for the reason
        // it is absent from every list here: `SigningAlgorithm` cannot parse
        // it, so it cannot be registered and cannot be accepted.
        object.insert(
            "backchannel_authentication_request_signing_alg_values_supported".to_owned(),
            json!(algorithms()),
        );
    }
    if capabilities.mtls {
        // RFC 8705 §5 and FAPI 2.0 SP §5.2.2.1.1. Built from the same
        // `Endpoint::enabled` iterator the router mounts and the rest of this
        // document is rendered from, rather than written out: an alias is a
        // second URL for an endpoint, and a second URL for an endpoint that
        // does not exist is the one kind of drift this whole module is shaped
        // to prevent. It also means the device-authorization and CIBA aliases
        // appear exactly when their flags put those endpoints on the server,
        // with nothing here to remember.
        let aliases: serde_json::Map<String, Value> = Endpoint::enabled(capabilities)
            .filter(|endpoint| endpoint.is_client_authenticated())
            .map(|endpoint| {
                (
                    endpoint.metadata_key().to_owned(),
                    json!(endpoint.url(issuer)),
                )
            })
            .collect();
        object.insert("mtls_endpoint_aliases".to_owned(), Value::Object(aliases));
        object.insert(
            "tls_client_certificate_bound_access_tokens".to_owned(),
            json!(true),
        );
    }

    document
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::{AcrPolicy, ClaimSet, TenantId, User, UserId, UserStatus};
    use time::OffsetDateTime;

    /// [`provider_metadata`] with the Grant Management posture every test but
    /// the Grant Management ones is indifferent to.
    ///
    /// A helper rather than a fifth argument repeated twenty times: §7.1's
    /// `grant_management_action_required` is a property of one feature, and a
    /// test about `response_modes_supported` should not have to state an
    /// opinion about it.
    fn metadata_of(
        issuer: &Issuer,
        capabilities: &Capabilities,
        acr: &asterius_domain::AcrPolicy,
        authorization_details_types: &[String],
    ) -> Value {
        provider_metadata(
            issuer,
            capabilities,
            acr,
            authorization_details_types,
            crate::grant_management::Policy::new(capabilities.grant_management, false),
        )
    }

    /// Grant Management ID1 §7.1: `grant_management_actions_supported` and
    /// `grant_management_action_required`, and neither of them when the
    /// deployment does not offer the feature.
    #[test]
    fn the_grant_management_metadata_follows_the_flag_and_the_tenant() {
        let off = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );
        assert!(off.get("grant_management_actions_supported").is_none());
        assert!(off.get("grant_management_action_required").is_none());

        let capabilities = Capabilities {
            grant_management: true,
            ..Capabilities::default()
        };
        let optional = metadata_of(&issuer(), &capabilities, &AcrPolicy::default(), &[]);
        assert_eq!(
            optional["grant_management_actions_supported"],
            json!(["query", "revoke", "create", "merge", "replace"]),
            "§6.1's two API actions, then the three the validator parses"
        );
        assert_eq!(optional["grant_management_action_required"], json!(false));

        let required = provider_metadata(
            &issuer(),
            &capabilities,
            &AcrPolicy::default(),
            &[],
            crate::grant_management::Policy::new(true, true),
        );
        assert_eq!(required["grant_management_action_required"], json!(true));
    }

    /// A tenant cannot demand a parameter it also ignores: §7.1 is a statement
    /// about Grant Management, so with the feature off the document says
    /// nothing at all rather than saying "required".
    #[test]
    fn a_tenant_with_the_feature_off_cannot_advertise_a_required_action() {
        let document = provider_metadata(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
            crate::grant_management::Policy::new(false, true),
        );
        assert!(document.get("grant_management_action_required").is_none());
    }

    /// RFC 8414 §2 and OIDC Discovery §3: the document must reflect actual
    /// behaviour. `response_modes_supported` is the set
    /// [`crate::authorize::ResponseMode::parse`] accepts, and nothing else —
    /// advertising a mode the pushed-request validator refuses tells a client
    /// to send a value it will be rejected for, and omitting one it accepts
    /// hides a mode the client is entitled to use (`ast-iko`).
    #[test]
    fn response_modes_supported_is_what_authorize_accepts() {
        let document = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );

        let advertised = document["response_modes_supported"]
            .as_array()
            .expect("the member is an array")
            .iter()
            .map(|value| value.as_str().expect("a string").to_owned())
            .collect::<Vec<_>>();

        for mode in &advertised {
            crate::authorize::ResponseMode::parse(mode).unwrap_or_else(|_| {
                panic!("the document advertises `{mode}`, which /authorize refuses")
            });
        }
        for mode in crate::authorize::ResponseMode::ALL {
            assert!(
                advertised.iter().any(|value| value == mode.as_str()),
                "/authorize accepts `{}`, which the document does not advertise",
                mode.as_str()
            );
        }
    }

    /// RFC 8414 §2: metadata reflects actual behaviour. `acr_values_supported`
    /// is the tenant's ladder and nothing else — a value in this member that
    /// the authorization endpoint would refuse as
    /// `unmet_authentication_requirements` is a document that lies.
    #[test]
    fn acr_values_supported_is_the_tenants_ladder_and_only_that() {
        let policy = AcrPolicy::new(vec![
            asterius_domain::AcrLevel::new(
                "urn:example:weak",
                [asterius_domain::AuthenticationMethod::Password],
            )
            .expect("a level"),
            asterius_domain::AcrLevel::new(
                "urn:example:strong",
                [asterius_domain::AuthenticationMethod::Passkey],
            )
            .expect("a level"),
        ])
        .expect("a policy");

        let document = metadata_of(&issuer(), &Capabilities::default(), &policy, &[]);

        assert_eq!(
            document["acr_values_supported"],
            json!(["urn:example:strong", "urn:example:weak"]),
            "the document must publish the ladder, strongest first"
        );
    }

    /// RFC 9396 §9.1: `authorization_details_types_supported` is the tenant's
    /// registry and nothing else, and a tenant that has registered none does
    /// not advertise the member at all — a client that sees it present treats
    /// rich authorization requests as available.
    #[test]
    fn authorization_details_types_supported_is_the_tenants_registry() {
        let registered = [
            "payment_initiation".to_owned(),
            "account_information".to_owned(),
        ];
        let document = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &registered,
        );
        assert_eq!(
            document["authorization_details_types_supported"],
            json!(["payment_initiation", "account_information"])
        );

        let none = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );
        assert!(
            none.get("authorization_details_types_supported").is_none(),
            "a tenant that registered no type must not advertise the member"
        );
    }

    /// A tenant that has configured no contexts advertises none. An empty list
    /// is the honest answer; the specification's example value is not.
    #[test]
    fn a_tenant_with_no_ladder_advertises_no_acr_values() {
        let document = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::empty(),
            &[],
        );

        assert_eq!(document["acr_values_supported"], json!([]));
    }

    fn issuer() -> Issuer {
        Issuer::parse("https://as.example/t/demo").expect("test issuer")
    }

    fn all_features() -> Capabilities {
        Capabilities {
            mtls: true,
            grant_management: true,
            ciba: true,
            device_flow: true,
            token_exchange: true,
            ssf: true,
            dynamic_client_registration: true,
            self_registration: true,
            authzen: true,
            dpop_nonce: true,
            request_object: true,
        }
    }

    // ---- the registry ----------------------------------------------------

    #[test]
    fn every_endpoint_has_a_distinct_path_and_a_distinct_metadata_key() {
        let mut paths = std::collections::BTreeSet::new();
        let mut keys = std::collections::BTreeSet::new();
        for endpoint in Endpoint::ALL {
            assert!(
                endpoint.path().starts_with('/'),
                "{endpoint:?} path is not absolute"
            );
            assert!(
                paths.insert(endpoint.path()),
                "duplicate path {}",
                endpoint.path()
            );
            assert!(
                keys.insert(endpoint.metadata_key()),
                "duplicate key {}",
                endpoint.metadata_key()
            );
            assert!(
                endpoint.metadata_key().ends_with("_endpoint")
                    || endpoint.metadata_key() == "jwks_uri",
                "{} is not an endpoint member name",
                endpoint.metadata_key()
            );
        }
    }

    /// The point of the registry: what is advertised is what is routed.
    #[test]
    fn the_document_advertises_exactly_the_enabled_endpoints() {
        for capabilities in [Capabilities::default(), all_features()] {
            let document = metadata_of(&issuer(), &capabilities, &AcrPolicy::default(), &[]);
            let object = document.as_object().expect("object");

            for endpoint in Endpoint::ALL {
                let present = object.contains_key(endpoint.metadata_key());
                assert_eq!(
                    present,
                    endpoint.is_enabled(&capabilities),
                    "{:?} advertised={present} but enabled={}",
                    endpoint,
                    endpoint.is_enabled(&capabilities)
                );
            }
        }
    }

    #[test]
    fn an_endpoint_url_is_the_issuer_plus_the_path_it_is_mounted_at() {
        let issuer = issuer();
        let document = metadata_of(
            &issuer,
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );
        assert_eq!(
            document["jwks_uri"],
            json!("https://as.example/t/demo/jwks")
        );
        assert_eq!(
            document["token_endpoint"],
            json!("https://as.example/t/demo/token")
        );
        // Every advertised URL starts with the issuer, so a client that
        // resolves them relative to the issuer cannot be sent elsewhere.
        for endpoint in Endpoint::enabled(&Capabilities::default()) {
            let url = document[endpoint.metadata_key()].as_str().expect("string");
            assert!(url.starts_with(issuer.as_str()), "{url} escapes the issuer");
        }
    }

    // ---- required members ------------------------------------------------

    /// OIDC Discovery §3 marks these REQUIRED. A document without them is not
    /// a smaller document, it is an invalid one.
    #[test]
    fn every_required_openid_member_is_present() {
        let document = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );
        for member in [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "response_types_supported",
            "subject_types_supported",
            "id_token_signing_alg_values_supported",
        ] {
            assert!(
                document.get(member).is_some(),
                "missing required member {member}"
            );
        }
    }

    /// OIDC Discovery §4.3: a client compares this byte-for-byte with the URL
    /// it fetched from, so nothing may reformat it.
    #[test]
    fn the_issuer_is_reproduced_exactly() {
        for raw in [
            "https://as.example/t/demo",
            "https://as.example",
            "https://as.example:8443/t/x",
        ] {
            let issuer = Issuer::parse(raw).expect("issuer");
            let document = metadata_of(
                &issuer,
                &Capabilities::default(),
                &AcrPolicy::default(),
                &[],
            );
            assert_eq!(document["issuer"], json!(issuer.as_str()));
        }
    }

    /// The profile's fixed answers. Each of these being wrong is a downgrade.
    #[test]
    fn the_profile_constants_are_what_the_profile_requires() {
        let document = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );
        assert_eq!(document["response_types_supported"], json!(["code"]));
        assert_eq!(
            document["code_challenge_methods_supported"],
            json!(["S256"])
        );
        assert_eq!(
            document["require_pushed_authorization_requests"],
            json!(true)
        );
        assert_eq!(
            document["authorization_response_iss_parameter_supported"],
            json!(true)
        );
        assert_eq!(document["request_uri_parameter_supported"], json!(false));
        assert_eq!(
            document["token_endpoint_auth_methods_supported"],
            json!(["private_key_jwt"])
        );
    }

    /// ADR-0003: the same three algorithms wherever an algorithm list appears,
    /// and RS256 and none in none of them.
    #[test]
    fn every_algorithm_list_is_the_allow_list() {
        let document = metadata_of(&issuer(), &all_features(), &AcrPolicy::default(), &[]);
        let object = document.as_object().expect("object");
        let lists: Vec<&String> = object
            .keys()
            .filter(|key| key.ends_with("_alg_values_supported"))
            .collect();
        assert!(
            lists.len() >= 5,
            "expected several algorithm lists, found {lists:?}"
        );

        for key in lists {
            assert_eq!(object[key], json!(["EdDSA", "ES256", "PS256"]), "{key}");
            let rendered = object[key].to_string();
            assert!(!rendered.contains("RS256"), "{key} advertises RS256");
            assert!(!rendered.contains("none"), "{key} advertises none");
        }
    }

    /// RFC 9101 and RFC 8414 §2: the document says whether the `request`
    /// parameter works here, and it is the same flag the pushed request
    /// endpoint reads (`ast-gxh.9`).
    ///
    /// The `request_uri` half is `false` in both postures and not a flag at
    /// all: RFC 9126 §3 forbids `request_uri` *in* a pushed request, and PAR
    /// is the only way in (ADR-0002), so there is no posture in which a
    /// client-supplied `request_uri` is accepted.
    #[test]
    fn the_request_parameter_is_advertised_exactly_when_the_flag_is_on() {
        // Arrange
        let on = Capabilities {
            request_object: true,
            ..Capabilities::default()
        };

        // Act
        let without = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );
        let with = metadata_of(&issuer(), &on, &AcrPolicy::default(), &[]);

        // Assert
        assert_eq!(without["request_parameter_supported"], json!(false));
        assert_eq!(with["request_parameter_supported"], json!(true));
        assert_eq!(without["request_uri_parameter_supported"], json!(false));
        assert_eq!(with["request_uri_parameter_supported"], json!(false));
    }

    /// RFC 9449 §5.1 defines exactly one metadata parameter, and its presence
    /// is how a client learns that this server does DPoP at all.
    ///
    /// Called out separately from the sweep above because that test would keep
    /// passing if this member were deleted: it checks the shape of every list
    /// whose name ends in `_alg_values_supported`, not that this particular one
    /// exists. RFC 8414 §2 makes metadata a description of actual behaviour, so
    /// a server that validates DPoP proofs and does not say so is as wrong as
    /// one that says so and does not.
    ///
    /// Note that RFC 9449 defines *no* metadata for the nonce mechanism (§8)
    /// and none for whether tokens are DPoP-bound — `dpop_bound_access_tokens`
    /// is client registration metadata (§5.2), which lives on the client, not
    /// here.
    #[test]
    fn dpop_support_is_advertised_the_one_way_rfc_9449_defines() {
        for capabilities in [Capabilities::default(), all_features()] {
            let document = metadata_of(&issuer(), &capabilities, &AcrPolicy::default(), &[]);
            assert_eq!(
                document["dpop_signing_alg_values_supported"],
                json!(["EdDSA", "ES256", "PS256"]),
                "the advertised DPoP algorithms are not the allow-list"
            );
            // The nonce flag changes no metadata member, because there is none
            // to change. A client discovers the requirement by being told
            // `use_dpop_nonce` and retrying, which is what RFC 9449 §8
            // specifies.
            assert!(
                document.get("dpop_nonce_supported").is_none(),
                "invented a metadata member RFC 9449 does not define"
            );
            assert!(document.get("dpop_bound_access_tokens").is_none());
        }
    }

    // ---- flags -----------------------------------------------------------

    /// Toggling one flag flips exactly the documented keys and nothing else.
    #[test]
    fn each_flag_controls_exactly_the_members_it_owns() {
        let expectations: [(Feature, &[&str]); 5] = [
            (Feature::DeviceFlow, &["device_authorization_endpoint"]),
            // CIBA Core 1.0 §4 makes the endpoint and the delivery modes
            // REQUIRED together, so the flag owns the whole block rather than
            // a URL (`ast-lh3.4`). `grant_types_supported` is not listed
            // because the member exists in both documents — the *grant* inside
            // it is the CIBA test's assertion, not this one's.
            (
                Feature::Ciba,
                &[
                    "backchannel_authentication_endpoint",
                    "backchannel_token_delivery_modes_supported",
                    "backchannel_user_code_parameter_supported",
                    "backchannel_authentication_request_signing_alg_values_supported",
                ],
            ),
            (
                Feature::GrantManagement,
                &[
                    "grant_management_endpoint",
                    "grant_management_actions_supported",
                    // §7.1. Present with its actual value whenever the feature
                    // is: a client reading `false` learns the parameter is
                    // optional here, which is not what a missing member says.
                    "grant_management_action_required",
                ],
            ),
            // §7's boxcar is the same API in an array, so one flag carries
            // both URLs: a document naming one and not the other would send a
            // PEP to boxcar by hand (`ast-pj0.2`).
            (
                Feature::Authzen,
                &["access_evaluation_endpoint", "access_evaluations_endpoint"],
            ),
            (
                Feature::Mtls,
                &[
                    "mtls_endpoint_aliases",
                    "tls_client_certificate_bound_access_tokens",
                ],
            ),
        ];

        let off = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );
        let off_keys: std::collections::BTreeSet<&String> =
            off.as_object().expect("object").keys().collect();

        for (feature, owned) in expectations {
            let mut capabilities = Capabilities::default();
            match feature {
                Feature::DeviceFlow => capabilities.device_flow = true,
                Feature::Ciba => capabilities.ciba = true,
                Feature::GrantManagement => capabilities.grant_management = true,
                Feature::Authzen => capabilities.authzen = true,
                Feature::Mtls => capabilities.mtls = true,
                _ => unreachable!("the table above covers the endpoint-bearing flags"),
            }

            let on = metadata_of(&issuer(), &capabilities, &AcrPolicy::default(), &[]);
            let on_object = on.as_object().expect("object");
            let added: std::collections::BTreeSet<&String> = on_object
                .keys()
                .filter(|key| !off_keys.contains(*key))
                .collect();
            let expected: std::collections::BTreeSet<String> =
                owned.iter().map(|key| (*key).to_owned()).collect();
            let added_owned: std::collections::BTreeSet<String> =
                added.into_iter().cloned().collect();

            assert_eq!(added_owned, expected, "{feature} added the wrong members");
        }
    }

    /// RFC 8705 §5: an alias is a second URL for an endpoint. It must name an
    /// endpoint this deployment has and advertises, or a client using mTLS is
    /// sent to a URL that answers 404 — and it must cover every advertised
    /// endpoint where a client authenticates, or such a client has nowhere to
    /// present its certificate.
    #[test]
    fn every_mtls_alias_names_an_advertised_client_authenticated_endpoint() {
        // Arrange: mTLS plus the two flags that add client-authenticated
        // endpoints, so the parity is tested where it can actually break.
        let capabilities = Capabilities {
            mtls: true,
            device_flow: true,
            ciba: true,
            ..Capabilities::default()
        };

        // Act
        let document = metadata_of(&issuer(), &capabilities, &AcrPolicy::default(), &[]);
        let aliases = document["mtls_endpoint_aliases"]
            .as_object()
            .expect("RFC 8705 §5 makes this an object");

        // Assert
        let expected: std::collections::BTreeSet<String> = Endpoint::enabled(&capabilities)
            .filter(|endpoint| endpoint.is_client_authenticated())
            .map(|endpoint| endpoint.metadata_key().to_owned())
            .collect();
        let found: std::collections::BTreeSet<String> = aliases.keys().cloned().collect();
        assert_eq!(found, expected);

        for (key, url) in aliases {
            assert_eq!(
                url, &document[key],
                "the alias for {key} names a URL the document does not"
            );
            assert!(
                document.get(key).is_some(),
                "{key} is aliased but not advertised"
            );
        }
    }

    /// An endpoint a flag switches off has no alias either: the alias would be
    /// the only member of the document naming a route the router never mounts.
    #[test]
    fn an_endpoint_behind_an_off_flag_gets_no_mtls_alias() {
        // Arrange
        let capabilities = Capabilities {
            mtls: true,
            ..Capabilities::default()
        };

        // Act
        let document = metadata_of(&issuer(), &capabilities, &AcrPolicy::default(), &[]);
        let aliases = document["mtls_endpoint_aliases"]
            .as_object()
            .expect("object");

        // Assert
        for absent in [
            "device_authorization_endpoint",
            "backchannel_authentication_endpoint",
        ] {
            assert!(!aliases.contains_key(absent), "{absent} was aliased");
        }
        assert!(aliases.contains_key("token_endpoint"));
        assert!(aliases.contains_key("pushed_authorization_request_endpoint"));
    }

    #[test]
    fn a_disabled_feature_contributes_no_member_at_all() {
        let document = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );
        let object = document.as_object().expect("object");
        for absent in [
            "device_authorization_endpoint",
            "backchannel_authentication_endpoint",
            "grant_management_endpoint",
            "access_evaluation_endpoint",
            "mtls_endpoint_aliases",
        ] {
            // Absent, not null and not empty: a client that sees the member
            // present treats the capability as present.
            assert!(
                object.get(absent).is_none(),
                "{absent} is present when disabled"
            );
        }
    }

    #[test]
    fn grant_types_follow_their_flags() {
        assert_eq!(
            grant_types(&Capabilities::default()),
            ["authorization_code", "refresh_token", "client_credentials"]
        );
        let all = grant_types(&all_features());
        assert!(all.contains(&"urn:ietf:params:oauth:grant-type:token-exchange"));
        assert!(all.contains(&"urn:ietf:params:oauth:grant-type:device_code"));
    }

    /// RFC 8628 §4: "`device_authorization_endpoint` ... the URL of the
    /// authorization server's device authorization endpoint". Advertised with
    /// the grant it belongs to, and with neither of them present when the
    /// tenant has the flag off — the two halves a device client reads before it
    /// can start anything.
    #[test]
    fn the_device_flow_advertises_its_endpoint_and_its_grant_together() {
        // Arrange
        let capabilities = Capabilities {
            device_flow: true,
            ..Capabilities::default()
        };

        // Act
        let on = metadata_of(&issuer(), &capabilities, &AcrPolicy::default(), &[]);
        let off = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );

        // Assert
        assert_eq!(
            on["device_authorization_endpoint"],
            json!(Endpoint::DeviceAuthorization.url(&issuer()))
        );
        assert!(
            on["grant_types_supported"]
                .as_array()
                .expect("array")
                .contains(&json!("urn:ietf:params:oauth:grant-type:device_code")),
            "the endpoint is advertised without the grant that reaches it: {on}"
        );
        assert!(off.get("device_authorization_endpoint").is_none());
        assert!(
            !off["grant_types_supported"]
                .as_array()
                .expect("array")
                .contains(&json!("urn:ietf:params:oauth:grant-type:device_code")),
            "the device grant is advertised with the flag off: {off}"
        );
    }

    /// CIBA Core 1.0 §4: an OP that supports CIBA advertises
    /// `backchannel_authentication_endpoint` and
    /// `backchannel_token_delivery_modes_supported`, which the specification
    /// makes REQUIRED *together* — so they appear together or not at all, and
    /// the grant that reaches the endpoint appears with them.
    ///
    /// The route side of the same statement is
    /// `crates/server/tests/discovery.rs`.
    #[test]
    fn the_ciba_flag_publishes_the_whole_of_ciba_or_none_of_it() {
        // Arrange
        let members = [
            "backchannel_authentication_endpoint",
            "backchannel_token_delivery_modes_supported",
            "backchannel_user_code_parameter_supported",
            "backchannel_authentication_request_signing_alg_values_supported",
        ];
        let on = Capabilities {
            ciba: true,
            ..Capabilities::default()
        };

        // Act
        let published = metadata_of(&issuer(), &on, &AcrPolicy::default(), &[]);
        let withheld = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );

        // Assert
        for member in members {
            assert!(
                published.get(member).is_some(),
                "{member} is missing from a document that offers CIBA: {published}"
            );
            // Absent, not null and not empty: a client that sees the member
            // present treats the capability as present.
            assert!(
                withheld.get(member).is_none(),
                "{member} is advertised with the flag off"
            );
        }
        assert_eq!(
            published["backchannel_authentication_endpoint"],
            json!(Endpoint::BackchannelAuthentication.url(&issuer()))
        );
        // FAPI-CIBA: push is not one of them, at the endpoint or in the
        // document.
        assert_eq!(
            published["backchannel_token_delivery_modes_supported"],
            json!(["poll", "ping"])
        );
        assert!(
            published["grant_types_supported"]
                .as_array()
                .expect("array")
                .contains(&json!("urn:openid:params:grant-type:ciba")),
            "the endpoint is advertised without the grant that reaches it: {published}"
        );
        assert!(
            !withheld["grant_types_supported"]
                .as_array()
                .expect("array")
                .contains(&json!("urn:openid:params:grant-type:ciba")),
            "the CIBA grant is advertised with no endpoint to take it to"
        );
    }

    /// "Advertised means routed" has no exception left: every endpoint in the
    /// registry has a handler, and the next one added without one has to say
    /// so here before it can be advertised.
    #[test]
    fn every_registered_endpoint_has_a_handler() {
        for endpoint in Endpoint::ALL {
            assert!(endpoint.has_a_handler(), "{endpoint:?}");
        }
    }

    /// ADR-0002: no `client_secret_*` method, and never `none`.
    #[test]
    fn no_client_secret_authentication_method_is_ever_advertised() {
        for capabilities in [Capabilities::default(), all_features()] {
            let methods = token_endpoint_auth_methods(&capabilities);
            for forbidden in [
                "client_secret_basic",
                "client_secret_post",
                "client_secret_jwt",
                "none",
            ] {
                assert!(!methods.contains(&forbidden), "{forbidden} advertised");
            }
            assert!(methods.contains(&"private_key_jwt"));
        }
    }

    #[test]
    fn mtls_methods_appear_only_behind_the_flag() {
        assert_eq!(
            token_endpoint_auth_methods(&Capabilities::default()),
            ["private_key_jwt"]
        );
        let mtls = Capabilities {
            mtls: true,
            ..Capabilities::default()
        };
        assert_eq!(
            token_endpoint_auth_methods(&mtls),
            [
                "private_key_jwt",
                "tls_client_auth",
                "self_signed_tls_client_auth"
            ]
        );
    }

    // ---- claims_supported ------------------------------------------------

    /// The finding that opened `ast-8p1`, as a test.
    ///
    /// The OpenID Foundation suite reads `claims_supported`, asks for every
    /// standard claim it names through the `claims` parameter, and fails the
    /// server for each one that comes back in neither the ID token nor the
    /// UserInfo response. The document named `name` and `preferred_username`;
    /// both live only in a user's [`ClaimSet`], so a user who has neither got
    /// neither, and the promise was the defect rather than the resolver.
    ///
    /// The user here has no stored claims at all, which is the point: what a
    /// tenant-wide document promises has to hold for the emptiest account the
    /// schema permits, because the document is written before anyone knows
    /// which account will authenticate.
    ///
    /// [`SELF_CHOSEN_CLAIM`] is the one exception, and it is an exception
    /// stated here rather than a hole. `preferred_username` is a *chosen*
    /// name: the sign-up page asks for one and the account pages change one,
    /// so this deployment produces it — but an account that never chose one has
    /// none, and OIDC Core §5.3.2 says a claim that is not available is
    /// omitted. Discovery §3 licenses exactly that reading: the member lists
    /// the names an OP "MAY be able to supply values for", with the note that
    /// "this might not be an exhaustive list". The claim below is what keeps
    /// the exception from becoming a promise nobody keeps:
    /// [`the_chosen_name_resolves_for_an_account_that_chose_one`] asserts the
    /// converse, and `e2e/fixtures/seed.sql` gives the conformance user a
    /// display name so the suite that reported `ast-8p1` asks for a claim this
    /// deployment can answer.
    #[test]
    fn every_identity_claim_advertised_resolves_for_a_user_with_no_stored_claims() {
        // Arrange.
        let user = User {
            tenant: TenantId::new("demo"),
            id: UserId::generate(),
            username: "ada".to_owned(),
            email: Some("ada@example.test".to_owned()),
            email_verified: true,
            status: UserStatus::Active,
            claims: ClaimSet::new(),
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let identity: Vec<&str> = claims_supported()
            .into_iter()
            .filter(|name| !ID_TOKEN_CLAIMS.contains(name) && *name != SELF_CHOSEN_CLAIM)
            .collect();
        assert!(
            !identity.is_empty(),
            "a document that promises no identity claim at all is not the fix"
        );
        let requested = crate::claims::ClaimsRequest::from_json(&json!({
            "userinfo": identity
                .iter()
                .map(|name| ((*name).to_owned(), Value::Null))
                .collect::<serde_json::Map<String, Value>>(),
        }))
        .expect("the advertised names are requestable");

        // Act: the grant's scopes are empty, so the `claims` parameter is the
        // only thing under test.
        let resolved = crate::claims::resolve(
            &user,
            &std::collections::BTreeSet::new(),
            &requested,
            &crate::claims::ClaimsLocales::default(),
        );

        // Assert.
        let missing: Vec<&&str> = identity
            .iter()
            .filter(|name| {
                !resolved.userinfo.contains_key(**name) && !resolved.id_token.contains_key(**name)
            })
            .collect();
        assert!(
            missing.is_empty(),
            "advertised but not delivered: {missing:?}"
        );
    }

    /// The other half of the exception above: the claim is advertised because
    /// an account that chose a display name gets it, through the ordinary
    /// resolver and with no special case anywhere in it.
    ///
    /// If this stops holding, the member has to come out of the document
    /// again — that is what `ast-8p1` was.
    #[test]
    fn the_chosen_name_resolves_for_an_account_that_chose_one() {
        // Arrange: one claim in the bag, which is what the sign-up page of
        // `ast-2vk.8` writes.
        let mut claims = ClaimSet::new();
        claims.insert(
            asterius_domain::ClaimName::parse(SELF_CHOSEN_CLAIM).expect("a claim name"),
            asterius_domain::Claim::new(
                Value::String("Ada L.".to_owned()),
                asterius_domain::ClaimSource::Local,
            )
            .expect("a claim"),
        );
        let user = User {
            tenant: TenantId::new("demo"),
            id: UserId::generate(),
            username: "ada".to_owned(),
            email: Some("ada@example.test".to_owned()),
            email_verified: true,
            status: UserStatus::Active,
            claims,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        };
        let requested = crate::claims::ClaimsRequest::from_json(&json!({
            "userinfo": { SELF_CHOSEN_CLAIM: Value::Null },
        }))
        .expect("the advertised name is requestable");

        // Act.
        let resolved = crate::claims::resolve(
            &user,
            &std::collections::BTreeSet::new(),
            &requested,
            &crate::claims::ClaimsLocales::default(),
        );

        // Assert: the chosen name, and not the login identifier (`ast-pew`).
        assert_eq!(
            resolved.userinfo.get(SELF_CHOSEN_CLAIM),
            Some(&Value::String("Ada L.".to_owned()))
        );
    }

    /// `sid` is advertised on purpose, and the ID token builder's own test
    /// checks the converse — that it emits nothing this list omits.
    #[test]
    fn sid_is_advertised_because_the_id_token_carries_one() {
        assert!(claims_supported().contains(&"sid"));
    }

    /// OIDC Core §5.4's scope-released claims are advertised only where a
    /// column backs them (`ast-1sk.5`).
    ///
    /// `claims_from_scopes()` is the whole of §5.4, and the tempting reading of
    /// Discovery §3's "MAY be able to supply values for" is that publishing all
    /// of it costs nothing. It does not read that way to a conformance suite,
    /// which treats every advertised name as a request it is entitled to make:
    /// `preferred_username` was removed for exactly that (`ast-8p1`) and came
    /// back only once something wrote it (`ast-2vk.8`). What the document
    /// publishes is therefore the intersection of §5.4 with the columns every
    /// user row has, plus that one claim, plus the ID token's own.
    #[test]
    fn a_scope_claim_is_advertised_only_when_this_server_can_produce_it() {
        // Arrange.
        let advertised = claims_supported();
        let mut producible = crate::claims::claims_from_user_columns();
        producible.push(SELF_CHOSEN_CLAIM);
        producible.sort_unstable();

        // Act.
        let mut from_scopes: Vec<&str> = crate::claims::claims_from_scopes()
            .into_iter()
            .filter(|name| advertised.contains(name))
            .collect();
        from_scopes.sort_unstable();

        // Assert.
        assert_eq!(from_scopes, producible);
        assert!(advertised.contains(&"sub"), "`sub` is always supplied");
    }

    /// `ast-pew`: what is advertised is the *chosen* name, never the login
    /// identifier. A `preferred_username` projected from `users.username`
    /// would answer a question about display with a fact about
    /// authentication, and `claims::claims_from_user_columns` is where that
    /// would show up.
    #[test]
    fn preferred_username_is_not_a_user_column() {
        assert!(
            !crate::claims::claims_from_user_columns().contains(&SELF_CHOSEN_CLAIM),
            "the login identifier is not a display preference"
        );
        assert!(claims_supported().contains(&SELF_CHOSEN_CLAIM));
    }

    /// The `claims` parameter is advertised because `authorize::validate`
    /// honours it; `authorize`'s own
    /// `the_claims_parameter_is_parsed_and_a_reserved_name_in_it_is_ignored`
    /// and `end_to_end`'s
    /// `an_essential_acr_travels_from_the_push_into_the_id_token` are the two
    /// ends of that wire (`ast-1sk.5`).
    #[test]
    fn the_claims_parameter_is_advertised() {
        // Arrange & Act.
        let document = metadata_of(
            &issuer(),
            &Capabilities::default(),
            &AcrPolicy::default(),
            &[],
        );

        // Assert.
        assert_eq!(document["claims_parameter_supported"], json!(true));
    }

    /// OIDC Discovery §3 makes `claims_locales_supported` OPTIONAL, and the
    /// member is omitted rather than rendered empty while no tenant stores a
    /// language-tagged claim. The reasoning is at the member in
    /// `provider_metadata`; this test is what stops a later edit from turning
    /// omission into an empty array without revisiting it (`ast-1sk.5`).
    #[test]
    fn claims_locales_supported_is_omitted_rather_than_advertised_empty() {
        // Arrange & Act.
        let document = metadata_of(&issuer(), &all_features(), &AcrPolicy::default(), &[]);

        // Assert.
        assert!(document.get("claims_locales_supported").is_none());
    }
}
