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
}

impl Endpoint {
    /// Every endpoint, in the order metadata lists them.
    pub const ALL: [Self; 13] = [
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
            Self::BackchannelAuthentication => "/backchannel_authorize",
            Self::GrantManagement => "/grants",
            Self::AccessEvaluation => "/access/v1/evaluation",
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
        }
    }

    /// The feature that must be on for this endpoint to exist, if any.
    #[must_use]
    pub const fn required_feature(self) -> Option<Feature> {
        match self {
            Self::DeviceAuthorization => Some(Feature::DeviceFlow),
            Self::BackchannelAuthentication => Some(Feature::Ciba),
            Self::GrantManagement => Some(Feature::GrantManagement),
            Self::AccessEvaluation => Some(Feature::Authzen),
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
            | Self::AccessEvaluation => false,
        }
    }

    /// Whether this deployment exposes this endpoint.
    #[must_use]
    pub fn is_enabled(self, capabilities: &Capabilities) -> bool {
        self.required_feature()
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
    if capabilities.ciba {
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
/// What is deliberately absent is the [`ClaimSet`](asterius_domain::ClaimSet):
/// `name`, `preferred_username` and the rest of OIDC Core §5.4 are released on
/// request, but only to a user who happens to have them stored, and a tenant's
/// static document is in no position to say who does. The list used to name
/// two of them, and the OpenID Foundation suite duly asked for both and got
/// neither (`ast-8p1`). See [`crate::claims::claims_from_user_columns`] for why a
/// short list is the honest one and a long list is not.
fn claims_supported() -> Vec<&'static str> {
    let mut names = ID_TOKEN_CLAIMS.to_vec();
    names.extend(crate::claims::claims_from_user_columns());
    names
}

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
        "prompt_values_supported":
            crate::authorize::AuthorizationPolicy::default().prompt_values_supported(),
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
        // it may send `grant_management_action`. Rendered from the enum the
        // validator parses rather than written out, for the reason
        // `response_modes_supported` gives: a document that advertised an
        // action `/par` refuses would send clients to an `invalid_request`.
        object.insert(
            "grant_management_actions_supported".to_owned(),
            json!(
                crate::grant_management::Action::ALL.map(crate::grant_management::Action::as_str)
            ),
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
    if capabilities.ciba {
        // CIBA Core 1.0 §4. Poll and ping only — push delivers the token to a
        // client-controlled URL, which FAPI does not profile.
        object.insert(
            "backchannel_token_delivery_modes_supported".to_owned(),
            json!(["poll", "ping"]),
        );
        object.insert(
            "backchannel_user_code_parameter_supported".to_owned(),
            json!(false),
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
            json!(["create", "merge", "replace"]),
            "the advertised actions are the ones the validator parses"
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
            (
                Feature::Ciba,
                &[
                    "backchannel_authentication_endpoint",
                    "backchannel_token_delivery_modes_supported",
                    "backchannel_user_code_parameter_supported",
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
            (Feature::Authzen, &["access_evaluation_endpoint"]),
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
        assert!(all.contains(&"urn:openid:params:grant-type:ciba"));
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
            .filter(|name| !ID_TOKEN_CLAIMS.contains(name))
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
    /// `preferred_username` was removed for exactly that (`ast-8p1`,
    /// `ast-2vk.8`) and does not come back until something serves it. What the
    /// document publishes is therefore the intersection of §5.4 with the
    /// columns every user row has, plus the ID token's own claims.
    #[test]
    fn a_scope_claim_is_advertised_only_when_a_user_column_backs_it() {
        // Arrange.
        let advertised = claims_supported();
        let columns = crate::claims::claims_from_user_columns();

        // Act.
        let from_scopes: Vec<&str> = crate::claims::claims_from_scopes()
            .into_iter()
            .filter(|name| advertised.contains(name))
            .collect();

        // Assert.
        assert_eq!(from_scopes, columns);
        assert!(!advertised.contains(&"preferred_username"));
        assert!(advertised.contains(&"sub"), "`sub` is always supplied");
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
