//! The client screen's resources: the inventory, one client's registration
//! document, and the two bodies the console posts.
//!
//! # The console cannot register a client `POST /register` would refuse
//!
//! That is `ast-f7m.5`'s first acceptance criterion, and it is met by there
//! being **one validator and no second opinion here**. Nothing in this module
//! decides what an acceptable client is: [`ClientRegistration::from_json`]
//! does, exactly as it does for RFC 7591 dynamic registration, and the router
//! hands it the request body unaltered. There is no allow-list of grant types
//! here, no redirect-URI rule, no algorithm check — those all live in
//! `asterius_domain::ClientMetadata::validate`, and a copy of any of them here
//! would be a second definition that drifts from the first in whichever
//! direction nobody is looking.
//!
//! Two things a document must satisfy are *not* in the document and so cannot
//! be in that call:
//!
//! * **`sector_identifier_uri` must be backed** (OIDC Registration §5). That
//!   needs an outbound fetch, so it goes through
//!   [`asterius_domain::ClientAdministration::verify_sector`], whose one
//!   implementation calls the same function `POST /register` calls.
//! * **`id_token_signed_response_alg` must be signable by this tenant today.**
//!   That is a fact about key rows, and [`asterius_domain::keys::signs_with`]
//!   is where both endpoints ask it. [`check_signable`] is this module's
//!   two-line adapter from that answer to an error a console renders.
//!
//! # What is rendered, and what is not
//!
//! [`document`] renders a registration in RFC 7591 §2's spelling, so what the
//! edit form GETs is a document it can PUT back unchanged — the round trip is
//! asserted below and fuzzed (`admin_client_request`), because a console that
//! could not save an unedited client would corrupt one on every visit.
//!
//! No credential is rendered anywhere here, and none can be: [`Client`] holds
//! no secret. This server issues no `client_secret` at all (FAPI 2.0 SP
//! §5.3.2.1 permits only `private_key_jwt` and mTLS), and a registration access
//! token exists only as a digest in a column no port on this path returns.
//!
//! # What is deliberately absent
//!
//! * **`resources` and `authorization_details_types` editing.** RFC 8707
//!   resource indicators and the per-client RAR allow-list are policy, not
//!   registration metadata: `ClientRegistration::resources` says so, and
//!   `ast-m9c.6` owns the per-tenant policy model. `authorization_details_types`
//!   is rendered because the validator accepts it in a document, and
//!   `resources` is rendered read-only because it is not settable at all.
//! * **The agent profile.** `ast-lh3.1` has not landed; there is no column, no
//!   type and nothing to edit.
//! * **Initial access token issuance.** Moved out, to
//!   [`crate::initial_access_tokens`] (`ast-cu3`). What stays here is the
//!   deployment's *gate* — whether `POST /register` answers anybody at all and
//!   on how many configured credentials — which is a fact about the process and
//!   not about a tenant's rows.

use asterius_domain::keys::{PublicKeyRecord, SigningAlgorithm, signs_with};
use asterius_domain::{Client, ClientMetadataError, ClientStatus, JwksSource, RedirectUri};
use serde_json::{Value, json};

use crate::error::AdminError;

/// One client, as the inventory renders it.
///
/// Deliberately narrower than [`document`]: a list is scanned, and the columns
/// that answer "which client is this, and is it serving" are the name, the
/// identifier, the status and how it authenticates. The redirect URIs are
/// included because they are what an operator recognises a client by when two
/// carry the same display name, and because the search below matches on them.
#[must_use]
pub fn summarise(client: &Client) -> Value {
    let registration = &client.registration;
    json!({
        "client_id": client.id.as_str(),
        "client_name": registration.client_name,
        "application_type": registration.application_type.as_str(),
        "status": client.status.as_str(),
        "token_endpoint_auth_method": registration.token_endpoint_auth_method.as_str(),
        "grant_types": registration
            .grant_types
            .iter()
            .map(|grant| grant.as_str())
            .collect::<Vec<_>>(),
        "redirect_uris": registration
            .redirect_uris
            .iter()
            .map(RedirectUri::as_str)
            .collect::<Vec<_>>(),
        "subject_type": registration.subject_type.as_str(),
        "jwks_source": jwks_source(&registration.jwks),
        "created_at": client.created_at.unix_timestamp(),
        "updated_at": client.updated_at.unix_timestamp(),
    })
}

/// Where a client's keys come from, as one word.
///
/// The console shows it in the inventory because the two have different
/// operational consequences — an inline JWK Set is rotated by editing this
/// client, a `jwks_uri` is rotated by the client's own key server — and an
/// operator answering "why did this client stop authenticating" needs to know
/// which conversation to have.
fn jwks_source(source: &JwksSource) -> &'static str {
    match source {
        JwksSource::Inline(_) => "jwks",
        JwksSource::Uri(_) => "jwks_uri",
    }
}

/// One client's whole registration, in RFC 7591 §2's spelling.
///
/// This is both what the edit form reads and what a successful write answers
/// with, and it is rendered from the **stored** client in both cases: RFC 7591
/// §3.2.1 requires "all registered metadata about this client, including any
/// fields provisioned by the authorization server itself", and this profile
/// provisions several — `require_pushed_authorization_requests` is always true
/// (ADR-0002), `response_types` is derived from `grant_types`, and the auth
/// method and ID token algorithm have defaults that are not RFC 7591 §2's. A
/// screen that echoed the administrator's request back would show a client that
/// does not exist.
///
/// Written by hand rather than derived, for the reason
/// `asterius_server::http::register::client_information` gives: adding a field
/// to [`asterius_domain::ClientRegistration`] should be a decision about what
/// is shown, not an automatic consequence of a struct changing.
///
/// Two members here are not RFC 7591 metadata and are marked as such by being
/// documented rather than by being hidden: `status`, which only an
/// administrator may set, and `resources`, which nobody may set from a document
/// yet (`ast-m9c.6`) and which is rendered so that an operator can see what a
/// client is allowed to ask for.
#[must_use]
pub fn document(client: &Client) -> Value {
    let registration = &client.registration;
    let mut rendered = json!({
        "client_id": client.id.as_str(),
        "client_id_issued_at": client.created_at.unix_timestamp(),
        "updated_at": client.updated_at.unix_timestamp(),
        "status": client.status.as_str(),

        "client_name": registration.client_name,
        "application_type": registration.application_type.as_str(),
        "token_endpoint_auth_method": registration.token_endpoint_auth_method.as_str(),
        "redirect_uris": registration
            .redirect_uris
            .iter()
            .map(RedirectUri::as_str)
            .collect::<Vec<_>>(),
        "post_logout_redirect_uris": registration.registered_post_logout_redirect_uris(),
        "grant_types": registration
            .grant_types
            .iter()
            .map(|grant| grant.as_str())
            .collect::<Vec<_>>(),
        "response_types": registration.response_types(),
        // RFC 6749 §3.3: the order of scope values is not significant. They are
        // stored in a set and come back sorted, which is what the form shows
        // and what it will send back.
        "scope": registration
            .scopes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        "id_token_signed_response_alg": registration.id_token_signed_response_alg.as_str(),
        "subject_type": registration.subject_type.as_str(),
        "require_pushed_authorization_requests":
            asterius_domain::ClientRegistration::REQUIRE_PUSHED_AUTHORIZATION_REQUESTS,
        "dpop_bound_access_tokens": registration.token_binding.is_dpop_bound(),
        "tls_client_certificate_bound_access_tokens":
            registration.token_binding.is_certificate_bound(),
        "authorization_details_types": registration
            .authorization_details_types
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        "use_mtls_endpoint_aliases": registration.use_mtls_endpoint_aliases,
        // Not settable from a document (`ast-m9c.6` owns the per-client
        // audience allow-list); shown because an operator debugging an
        // `invalid_target` needs to see it.
        "resources": registration
            .resources
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    });

    let object = rendered
        .as_object_mut()
        .expect("the document above is a JSON object");

    // RFC 7591 §2: `jwks` and `jwks_uri` must never both appear. A stored
    // registration can hold only one, so this reproduces that rather than
    // deciding it again.
    match &registration.jwks {
        JwksSource::Inline(keys) => object.insert("jwks".to_owned(), keys.clone()),
        JwksSource::Uri(uri) => object.insert("jwks_uri".to_owned(), json!(uri)),
    };

    // Omitted rather than null when the client registered none: an absent
    // member and a null one mean different things to a strict reader, and
    // RFC 7591 §2 makes every metadata field optional.
    if let Some(alg) = registration.request_object_signing_alg {
        object.insert("request_object_signing_alg".to_owned(), json!(alg.as_str()));
    }
    if let Some(alg) = registration.backchannel_authentication_request_signing_alg {
        object.insert(
            "backchannel_authentication_request_signing_alg".to_owned(),
            json!(alg.as_str()),
        );
    }
    if let Some(uri) = &registration.sector_identifier_uri {
        object.insert("sector_identifier_uri".to_owned(), json!(uri));
    }

    rendered
}

/// The search term in `q`, as the operator typed it.
///
/// The admin API's other query parameters need no decoding — a cursor is
/// `base64url` and a limit is digits, which is why [`crate::router`]'s
/// `query_value` hands back the raw substring — but a search box holds prose:
/// "Billing portal" arrives as `Billing%20portal`, and matching that against a
/// stored name would find nothing while looking as though the search worked.
///
/// So this is the one place in this crate that decodes, and it decodes exactly
/// what a browser's `application/x-www-form-urlencoded` serialisation produces
/// (WHATWG URL §5.2, which `encodeURIComponent` and a `GET` form both follow):
/// `+` is a space, `%XX` is a byte. Anything else is passed through as itself.
///
/// **It cannot fail.** A term is not a credential, an identifier or a path
/// segment — it is fed to [`matches`], which does a case-insensitive substring
/// comparison and nothing else — so a malformed escape is not worth a 400 that
/// an operator would read as "your search is invalid". A stray `%` stays a `%`
/// and matches a stored `%`; invalid UTF-8 becomes the replacement character,
/// which matches nothing, which is the right answer for bytes that are not
/// text.
// fuzz-target: admin_client_request
#[must_use]
pub fn search_term(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                    .ok()
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok());
                if let Some(byte) = hex {
                    decoded.push(byte);
                    index += 3;
                } else {
                    // Not an escape after all. The `%` is itself, and the two
                    // bytes after it are read as themselves on the next turns.
                    decoded.push(b'%');
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// Whether `client` is one the operator was searching for.
///
/// Substring, case-insensitive, over the three fields an operator has to hand:
/// the identifier they copied out of a log, the name they gave the client, and
/// a callback URL they were sent by whoever integrated it. Nothing cleverer,
/// and in particular no ranking: a list of tens of clients is scanned, not
/// searched, and a rank order that put the wrong row first would be worse than
/// an unordered one.
///
/// An empty query matches everything, so a console with an empty box shows the
/// inventory rather than nothing.
#[must_use]
pub fn matches(client: &Client, query: &str) -> bool {
    let needle = query.trim().to_lowercase();
    if needle.is_empty() {
        return true;
    }
    let registration = &client.registration;
    client.id.as_str().to_lowercase().contains(&needle)
        || registration.client_name.to_lowercase().contains(&needle)
        || registration
            .redirect_uris
            .iter()
            .any(|uri| uri.as_str().to_lowercase().contains(&needle))
}

/// The status an administrator asked for, if they asked for one.
///
/// `status` is not RFC 7591 metadata: a client cannot suspend itself and cannot
/// un-suspend itself, so the member is read here rather than by the validator,
/// which ignores members it does not know.
///
/// `None` means the body said nothing, and the two callers read that
/// differently on purpose. A creation takes [`ClientStatus::Active`] — a client
/// created disabled would be a form of "saved" that does not work. An update
/// keeps what is stored, because the alternative is that a console built
/// against an older server silently reactivates a client somebody suspended
/// during an incident.
///
/// # Errors
///
/// [`AdminError::Invalid`] if `status` is present and is not one of the two
/// values [`ClientStatus::parse`] knows. Refused rather than defaulted: an
/// administrator who typed `suspended` meant `disabled`, and quietly storing
/// `active` would be the one outcome they did not ask for.
// fuzz-target: admin_client_request
pub fn requested_status(body: &[u8]) -> Result<Option<ClientStatus>, AdminError> {
    // The same bytes the validator will read, parsed a second time for one
    // member. Two parses rather than one wrapper type, so that what reaches
    // `ClientRegistration::from_json` is the request body exactly as it
    // arrived — a wrapper would mean re-serialising the document, and the thing
    // validated would then be this crate's rendering of the request rather than
    // the request.
    //
    // Through `Value` and not through a `#[derive(Deserialize)]` struct,
    // because serde will happily build a struct of optional fields out of a
    // JSON *array* — `[]` would parse as "no status given" rather than as the
    // nonsense it is, and the request would then be refused later by the
    // validator for a reason that does not name the real problem.
    let document: Value = serde_json::from_slice(body)
        .map_err(|_| AdminError::Invalid("the request body is not valid JSON".to_owned()))?;
    let object = document
        .as_object()
        .ok_or_else(|| AdminError::Invalid("the request body is not a JSON object".to_owned()))?;

    match object.get("status") {
        None | Some(Value::Null) => Ok(None),
        Some(named) => named
            .as_str()
            .and_then(ClientStatus::parse)
            .map(Some)
            .ok_or_else(|| {
                AdminError::Invalid(
                    "status: must be \"active\" or \"disabled\" (omit it to leave it unchanged)"
                        .to_owned(),
                )
            }),
    }
}

/// Refuses a client this tenant could never issue an ID token to.
///
/// The rule is [`signs_with`], in the domain, which is where
/// `POST /register`'s `unsignable` asks the same question. A client registered
/// against an algorithm with no active signing key authenticates and then fails
/// at the token endpoint, which is a support ticket rather than an error
/// message; refusing at the form is `ast-f7m.5`'s "the console cannot create a
/// client DCR would refuse" applied to the one check that is not in the
/// document.
///
/// # Errors
///
/// [`AdminError::Invalid`] naming the algorithm and the remedy — rotating a key
/// for it — because the operator reading this is the person who can do that.
pub fn check_signable(
    records: &[PublicKeyRecord],
    algorithm: SigningAlgorithm,
) -> Result<(), AdminError> {
    if signs_with(records, algorithm) {
        return Ok(());
    }
    Err(AdminError::Invalid(format!(
        "id_token_signed_response_alg: this tenant has no active {} signing key, \
         so it could never issue this client an ID token — rotate a {} key first",
        algorithm.as_str(),
        algorithm.as_str()
    )))
}

/// A registration document the validator refused, as an admin API refusal.
///
/// The sentence is the validator's own, and it is safe to render: every variant
/// of [`ClientMetadataError`] is fixed text naming a field, never a value from
/// the document (see its own documentation for why that matters at an endpoint
/// reachable before authentication). Carrying it through unchanged is what
/// makes the console show the administrator the same reason a dynamic
/// registration client would have been given, which is the point of sharing the
/// validator at all.
#[must_use]
pub fn refusal(error: &ClientMetadataError) -> AdminError {
    AdminError::Invalid(format!("{}: {error}", error.code()))
}

/// The dynamic registration gate, as this deployment is configured.
///
/// # Why there is no "issue an initial access token" button
///
/// This is the **deployment's** posture, read from the configuration file: the
/// mode an operator chose and how many initial access tokens the process was
/// started with. A tenant's own credentials are rows, are listed at
/// `GET /initial-access-tokens`, and are not counted here — a tenant
/// administrator learning how many tokens the deployment holds learns something
/// about a neighbour's arrangements, which is why that route is
/// [`crate::rbac::Reach::Deployment`] and this document says nothing about
/// tenants.
///
/// What an operator *can* be told, and is, is whether the endpoint admits
/// anybody at all and on how many configured credentials. Both are facts about
/// configuration; neither is a secret. The count is a count and never the
/// digests: a digest is a stable per-token identifier, and publishing it in a
/// console would let anyone who later sees a token confirm which deployment it
/// belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationGate {
    /// `closed`, `initial_access_token` or `open` — the label the policy
    /// already carries into the audit trail, so the console and the trail
    /// cannot describe the same deployment differently.
    pub mode: &'static str,
    /// How many initial access tokens are configured. Zero under any mode but
    /// `initial_access_token`.
    pub configured_tokens: usize,
}

/// The gate, as the console renders it.
#[must_use]
pub fn registration_document(gate: RegistrationGate) -> Value {
    json!({
        "mode": gate.mode,
        "configured_tokens": gate.configured_tokens,
        // Stated rather than implied: an operator looking at this screen is
        // deciding whether a leaked configuration file is a credential
        // compromise, and the answer is "the file is, the database is not".
        "tokens_stored_hashed": true,
        // True since `ast-cu3`: `POST /initial-access-tokens` mints a token for
        // the tenant the request was routed to, with the quota that tenant's
        // registration policy sets. Carried in the document rather than only in
        // the console's copy so that a client of this API asking whether it can
        // mint one gets an answer instead of guessing from a route list.
        "console_issuance": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use asterius_domain::keys::{KeyPurpose, KeyState, Kid};
    use asterius_domain::{
        Capabilities, ClientId, ClientRegistration, ClientStatus, TenantId, keys::PublicKeyRecord,
    };
    use time::OffsetDateTime;

    /// A registration document that this profile accepts.
    fn valid_document() -> Value {
        json!({
            "client_name": "Billing portal",
            "redirect_uris": ["https://app.example.test/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "scope": "openid profile",
            "jwks_uri": "https://app.example.test/jwks.json",
        })
    }

    fn client_from(document: &Value, status: ClientStatus) -> Client {
        let registration =
            ClientRegistration::from_json(document.to_string().as_bytes(), Capabilities::default())
                .expect("the fixture is a valid registration document");
        Client {
            tenant: TenantId::new("demo"),
            id: ClientId::new("c.MdRoIVGvcOSTLKrPu4RBrw"),
            registration,
            status,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn key(algorithm: SigningAlgorithm, state: KeyState) -> PublicKeyRecord {
        PublicKeyRecord {
            tenant: TenantId::new("demo"),
            kid: Kid::new("k-1"),
            algorithm,
            purpose: KeyPurpose::Signing,
            state,
            public_jwk: json!({"kty": "OKP"}),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    /// **The edit form's whole premise.** What the console GETs must be
    /// something it can PUT back, or opening a client and saving it unchanged
    /// would rewrite it — or be refused, which is worse, because the operator
    /// would then have to guess which member this server dropped.
    ///
    /// Asserted against the validator rather than against a snapshot: the round
    /// trip that matters is "the document re-validates to the same
    /// registration", not "the JSON has these bytes".
    #[test]
    fn a_rendered_registration_validates_back_to_the_same_registration() {
        // Arrange
        let client = client_from(&valid_document(), ClientStatus::Active);

        // Act
        let rendered = document(&client);
        let round_tripped =
            ClientRegistration::from_json(rendered.to_string().as_bytes(), Capabilities::default())
                .expect("the rendered document must be a valid registration document");

        // Assert
        assert_eq!(round_tripped, client.registration);
    }

    /// An inline JWK Set survives the round trip too, and never appears beside
    /// a `jwks_uri`: RFC 7591 §2 forbids both members at once, and a document
    /// carrying both is refused by the validator — so rendering both would make
    /// every client with inline keys unsaveable.
    #[test]
    fn a_client_with_inline_keys_renders_jwks_and_not_jwks_uri() {
        // Arrange
        let mut raw = valid_document();
        let object = raw.as_object_mut().expect("object");
        object.remove("jwks_uri");
        object.insert(
            "jwks".to_owned(),
            json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "public", "use": "sig"}]}),
        );
        let client = client_from(&raw, ClientStatus::Active);

        // Act
        let rendered = document(&client);

        // Assert
        assert!(rendered.get("jwks").is_some(), "{rendered}");
        assert!(rendered.get("jwks_uri").is_none(), "{rendered}");
        assert!(
            ClientRegistration::from_json(rendered.to_string().as_bytes(), Capabilities::default())
                .is_ok(),
            "a client with inline keys could not be saved unchanged"
        );
    }

    /// The status an administrator can see is the status they can send back.
    #[test]
    fn the_rendered_status_is_one_the_request_parser_accepts() {
        for status in [ClientStatus::Active, ClientStatus::Disabled] {
            // Arrange
            let client = client_from(&valid_document(), status);

            // Act
            let rendered = document(&client);
            let parsed = requested_status(rendered.to_string().as_bytes()).expect("parses");

            // Assert
            assert_eq!(parsed, Some(status));
        }
    }

    /// A body that says nothing about the status leaves the decision to the
    /// caller, which is what keeps a console built against an older server from
    /// reactivating a client somebody suspended.
    #[test]
    fn a_body_with_no_status_member_asks_for_no_change() {
        // Arrange
        let body = valid_document().to_string();

        // Act
        let parsed = requested_status(body.as_bytes()).expect("parses");

        // Assert
        assert_eq!(parsed, None);
    }

    /// A status outside the closed set is refused rather than defaulted: the
    /// nearest wrong answer to "suspended" is "active", which is the opposite
    /// of what was asked for.
    #[test]
    fn a_status_this_server_does_not_know_is_refused() {
        for rejected in ["suspended", "ACTIVE", "", "enabled", "true"] {
            // Arrange
            let body = json!({"status": rejected}).to_string();

            // Act / Assert
            assert!(
                requested_status(body.as_bytes()).is_err(),
                "accepted status {rejected:?}"
            );
        }
    }

    /// Arbitrary bytes are a request body; parsing one is a refusal, not a
    /// panic.
    #[test]
    fn a_body_that_is_not_a_json_object_is_refused() {
        for body in [&b""[..], b"[]", b"null", b"{", b"\xff\xfe"] {
            assert!(requested_status(body).is_err(), "accepted {body:?}");
        }
    }

    /// The one check that is not in the document: a client whose ID tokens this
    /// tenant could not sign is refused at the form. `POST /register` refuses
    /// the same document for the same reason, through the same domain
    /// function.
    #[test]
    fn a_client_this_tenant_could_not_sign_for_is_refused() {
        // Arrange
        let no_active_key = [key(SigningAlgorithm::EdDsa, KeyState::Pending)];

        // Act
        let refused = check_signable(&no_active_key, SigningAlgorithm::EdDsa);

        // Assert
        let AdminError::Invalid(message) = refused.expect_err("a pending key cannot sign") else {
            panic!("the refusal must be one a console can render");
        };
        assert!(
            message.contains("id_token_signed_response_alg") && message.contains("EdDSA"),
            "{message}"
        );
        assert!(
            check_signable(
                &[key(SigningAlgorithm::EdDsa, KeyState::Active)],
                SigningAlgorithm::EdDsa
            )
            .is_ok()
        );
    }

    /// The search is what an operator has to hand: an id from a log, the name
    /// they typed, or a callback somebody sent them.
    #[test]
    fn the_search_matches_the_identifier_the_name_and_a_callback() {
        // Arrange
        let client = client_from(&valid_document(), ClientStatus::Active);

        // Act / Assert
        for query in [
            "c.MdRo",
            "billing",
            "BILLING",
            "app.example.test",
            "  portal ",
        ] {
            assert!(matches(&client, query), "missed {query:?}");
        }
        for query in ["payments", "https://other.example"] {
            assert!(!matches(&client, query), "matched {query:?}");
        }
    }

    /// A search box holds prose, and a browser sends prose percent-encoded.
    /// Matching the encoded form against a stored name would find nothing while
    /// looking as though the search had worked.
    #[test]
    fn a_search_term_arrives_decoded() {
        // Arrange / Act / Assert
        assert_eq!(search_term("Billing%20portal"), "Billing portal");
        assert_eq!(search_term("Billing+portal"), "Billing portal");
        assert_eq!(search_term("caf%C3%A9"), "café");
        assert_eq!(search_term("plain"), "plain");
    }

    /// A malformed escape is not a refusal: a term is compared as a substring
    /// and nothing else, so a stray `%` is a `%` and matches a stored one.
    #[test]
    fn a_malformed_escape_is_read_as_itself_rather_than_refused() {
        // Arrange / Act / Assert
        assert_eq!(search_term("100%"), "100%");
        assert_eq!(search_term("%zz"), "%zz");
        assert_eq!(search_term("%2"), "%2");
        assert_eq!(search_term(""), "");
    }

    /// An empty box shows the inventory rather than nothing.
    #[test]
    fn an_empty_query_matches_every_client() {
        // Arrange
        let client = client_from(&valid_document(), ClientStatus::Active);

        // Act / Assert
        assert!(matches(&client, ""));
        assert!(matches(&client, "   "));
    }

    /// The gate is described by its mode and a count. A digest is a stable
    /// identifier for a live credential and is never rendered.
    #[test]
    fn the_registration_gate_reports_a_count_and_never_a_digest() {
        // Arrange
        let gate = RegistrationGate {
            mode: "initial_access_token",
            configured_tokens: 2,
        };

        // Act
        let rendered = registration_document(gate);

        // Assert
        assert_eq!(rendered["mode"], json!("initial_access_token"));
        assert_eq!(rendered["configured_tokens"], json!(2));
        assert_eq!(rendered["console_issuance"], json!(true));
        assert_eq!(rendered["tokens_stored_hashed"], json!(true));
    }

    /// The inventory row carries no member the detail document would have
    /// hidden — there is nothing secret in a client — but it must carry the
    /// identifier, which is what every other route is aimed with.
    #[test]
    fn an_inventory_row_names_the_client_it_is_about() {
        // Arrange
        let client = client_from(&valid_document(), ClientStatus::Disabled);

        // Act
        let row = summarise(&client);

        // Assert
        assert_eq!(row["client_id"], json!("c.MdRoIVGvcOSTLKrPu4RBrw"));
        assert_eq!(row["status"], json!("disabled"));
        assert_eq!(row["jwks_source"], json!("jwks_uri"));
    }
}
