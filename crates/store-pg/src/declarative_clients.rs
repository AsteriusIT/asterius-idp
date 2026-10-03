//! FAPI application metadata on the declarative management transaction.
//!
//! Server composition verifies sector documents before invoking management;
//! this adapter repeats typed profile, tenant capability and signability checks
//! under the transaction rather than accepting unvalidated column mutations.
use crate::{clients::PgClientRepository, error::to_domain_error};
use asterius_domain::declarative::{Error, Identity, Kind};
use asterius_domain::{
    Capabilities, Client, ClientComplianceProfile, ClientId, ClientRegistration,
    ClientSecretUpdate, ClientStatus, JwksSource, RedirectUri, ResourceIdentifier, TenantId,
    TenantSettings,
};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row as _};
use std::collections::BTreeSet;
use time::OffsetDateTime;

const APPLICATION_FIELDS: &[&str] = &[
    "client_name",
    "compliance_profile",
    "application_type",
    "token_endpoint_auth_method",
    "redirect_uris",
    "post_logout_redirect_uris",
    "grant_types",
    "response_types",
    "scope",
    "jwks",
    "jwks_uri",
    "id_token_signed_response_alg",
    "subject_type",
    "require_pushed_authorization_requests",
    "dpop_bound_access_tokens",
    "tls_client_certificate_bound_access_tokens",
    "authorization_details_types",
    "use_mtls_endpoint_aliases",
    "roles_in_id_token",
    "managed_groups_claim",
    "command_endpoint",
    "resources",
    "request_object_signing_alg",
    "authorization_signed_response_alg",
    "response_modes",
    "backchannel_authentication_request_signing_alg",
    "userinfo_signed_response_alg",
    "introspection_signed_response_alg",
    "id_token_encrypted_response_alg",
    "id_token_encrypted_response_enc",
    "userinfo_encrypted_response_alg",
    "userinfo_encrypted_response_enc",
    "sector_identifier_uri",
    "backchannel_token_delivery_mode",
    "backchannel_client_notification_endpoint",
    "backchannel_user_code_parameter",
    "backchannel_logout_uri",
    "backchannel_logout_session_required",
    "tls_client_auth_subject_dn",
    "tls_client_auth_san_dns",
    "tls_client_auth_san_uri",
    "tls_client_auth_san_ip",
    "tls_client_auth_san_email",
];

fn identity_check(identity: &Identity) -> Result<(), Error> {
    identity.validate()?;
    if identity.kind != Kind::Application {
        return Err(Error::Invalid);
    }
    Ok(())
}

async fn effective_capabilities(
    connection: &mut PgConnection,
    tenant: &TenantId,
    capabilities: Capabilities,
) -> Result<(Capabilities, TenantSettings), Error> {
    let row = sqlx::query("select settings from tenants where tenant_id=$1 for share")
        .bind(tenant.as_str())
        .fetch_optional(connection)
        .await
        .map_err(|error| Error::Storage(to_domain_error(error)))?
        .ok_or(Error::NotFound)?;
    let settings: Value = row
        .try_get("settings")
        .map_err(|error| Error::Storage(to_domain_error(error)))?;
    let options = TenantSettings::from_json(settings.get("options")).map_err(|_| Error::Invalid)?;
    Ok((options.effective_capabilities(capabilities), options))
}

fn parse_registration(
    spec: &Value,
    capabilities: Capabilities,
) -> Result<ClientRegistration, Error> {
    let object = spec.as_object().ok_or(Error::Invalid)?;
    if object
        .keys()
        .any(|field| !APPLICATION_FIELDS.contains(&field.as_str()))
        || object
            .get("compliance_profile")
            .is_some_and(|profile| profile != "fapi")
    {
        return Err(Error::Invalid);
    }
    let encoded = serde_json::to_vec(spec).map_err(|_| Error::Invalid)?;
    let mut registration =
        ClientRegistration::from_json(&encoded, capabilities).map_err(|_| Error::Invalid)?;
    if registration.agent.is_some() {
        return Err(Error::Invalid);
    }
    let values = object
        .get("resources")
        .and_then(Value::as_array)
        .ok_or(Error::Invalid)?;
    let mut resources = BTreeSet::new();
    for resource in values {
        let resource = resource.as_str().ok_or(Error::Invalid)?;
        ResourceIdentifier::parse(resource).map_err(|_| Error::Invalid)?;
        resources.insert(resource.to_owned());
    }
    registration.resources = resources;
    Ok(registration)
}

async fn registration(
    connection: &mut PgConnection,
    tenant: &TenantId,
    spec: &Value,
    capabilities: Capabilities,
) -> Result<ClientRegistration, Error> {
    let (capabilities, options) = effective_capabilities(connection, tenant, capabilities).await?;
    let registration = parse_registration(spec, capabilities)?;
    options
        .registration()
        .evaluate(&registration)
        .map_err(|_| Error::Invalid)?;
    if registration.subject_type == asterius_domain::SubjectType::Ephemeral
        && !options.allows_ephemeral_subjects()
    {
        return Err(Error::Invalid);
    }
    let resources = &registration.resources;
    let requested: Vec<String> = resources.iter().cloned().collect();
    let registered = sqlx::query("select identifier from resource_servers where tenant_id=$1 and identifier=any($2) for key share")
        .bind(tenant.as_str()).bind(&requested).fetch_all(&mut *connection).await
        .map_err(|error| Error::Storage(to_domain_error(error)))?;
    if registered.len() != requested.len() {
        return Err(Error::Invalid);
    }
    for (_, algorithm) in registration.server_signed_algorithms() {
        if let Some(algorithm) = algorithm {
            let key = sqlx::query("select kid from signing_keys where tenant_id=$1 and alg=$2 and purpose='sig' and state='active' for share")
                .bind(tenant.as_str()).bind(algorithm.as_str()).fetch_optional(&mut *connection).await
                .map_err(|error| Error::Storage(to_domain_error(error)))?;
            if key.is_none() {
                return Err(Error::Invalid);
            }
        }
    }
    Ok(registration)
}

pub(crate) async fn normalise(
    connection: &mut PgConnection,
    tenant: &TenantId,
    spec: &Value,
    capabilities: Capabilities,
) -> Result<Value, Error> {
    let registration = registration(connection, tenant, spec, capabilities).await?;
    let now = OffsetDateTime::UNIX_EPOCH;
    let client = Client {
        tenant: tenant.clone(),
        id: ClientId::new("canonical"),
        registration,
        status: ClientStatus::Active,
        created_at: now,
        updated_at: now,
    };
    Ok(document(&client))
}

pub(crate) async fn read(
    connection: &mut PgConnection,
    identity: &Identity,
    capabilities: Capabilities,
) -> Result<Value, Error> {
    identity_check(identity)?;
    let (capabilities, _) =
        effective_capabilities(connection, &identity.tenant, capabilities).await?;
    let client = PgClientRepository::find_on_connection(
        connection,
        &identity.tenant,
        capabilities,
        &ClientId::new(&identity.keys[0]),
    )
    .await
    .map_err(Error::Storage)?
    .ok_or(Error::NotFound)?;
    if client.registration.compliance_profile != ClientComplianceProfile::Fapi
        || client.registration.agent.is_some()
    {
        return Err(Error::Unsupported);
    }
    Ok(document(&client))
}

pub(crate) async fn create(
    connection: &mut PgConnection,
    tenant: &TenantId,
    spec: &Value,
    capabilities: Capabilities,
) -> Result<Identity, Error> {
    let registration = registration(connection, tenant, spec, capabilities).await?;
    let now = OffsetDateTime::now_utc();
    let client = Client {
        tenant: tenant.clone(),
        id: ClientId::mint(),
        registration,
        status: ClientStatus::Active,
        created_at: now,
        updated_at: now,
    };
    PgClientRepository::create_on_connection(connection, tenant, capabilities, &client)
        .await
        .map_err(Error::Storage)?;
    Ok(Identity {
        tenant: tenant.clone(),
        kind: Kind::Application,
        keys: vec![client.id.as_str().to_owned()],
    })
}

pub(crate) async fn replace(
    connection: &mut PgConnection,
    identity: &Identity,
    spec: &Value,
    capabilities: Capabilities,
) -> Result<(), Error> {
    identity_check(identity)?;
    let registration = registration(connection, &identity.tenant, spec, capabilities).await?;
    let mut client = PgClientRepository::find_on_connection(
        connection,
        &identity.tenant,
        capabilities,
        &ClientId::new(&identity.keys[0]),
    )
    .await
    .map_err(Error::Storage)?
    .ok_or(Error::NotFound)?;
    if client.registration.compliance_profile != ClientComplianceProfile::Fapi
        || client.registration.agent.is_some()
    {
        return Err(Error::Unsupported);
    }
    client.registration = registration;
    PgClientRepository::replace_on_connection(
        connection,
        &identity.tenant,
        capabilities,
        &client,
        ClientSecretUpdate::Keep,
    )
    .await
    .map_err(Error::Storage)?;
    let resources: Vec<String> = client.registration.resources.iter().cloned().collect();
    sqlx::query("update clients set resources=$3 where tenant_id=$1 and client_id=$2")
        .bind(identity.tenant.as_str())
        .bind(client.id.as_str())
        .bind(resources)
        .execute(connection)
        .await
        .map_err(|error| Error::Storage(to_domain_error(error)))?;
    Ok(())
}

pub(crate) async fn delete(
    connection: &mut PgConnection,
    identity: &Identity,
) -> Result<(), Error> {
    identity_check(identity)?;
    let changed = sqlx::query("delete from clients where tenant_id=$1 and client_id=$2")
        .bind(identity.tenant.as_str())
        .bind(&identity.keys[0])
        .execute(&mut *connection)
        .await
        .map_err(|error| Error::Storage(to_domain_error(error)))?;
    if changed.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    crate::cutoffs::withdraw(
        connection,
        &identity.tenant,
        crate::cutoffs::Principal::Client(&identity.keys[0]),
        OffsetDateTime::now_utc(),
    )
    .await
    .map_err(Error::Storage)
}

fn document(client: &Client) -> Value {
    let registration = &client.registration;
    let mut rendered = json!({
        "compliance_profile": registration.compliance_profile.as_str(),

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
            registration.compliance_profile.requires_par(),
        "dpop_bound_access_tokens": registration.token_binding.is_dpop_bound(),
        "tls_client_certificate_bound_access_tokens":
            registration.token_binding.is_certificate_bound(),
        "authorization_details_types": registration
            .authorization_details_types
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        "use_mtls_endpoint_aliases": registration.use_mtls_endpoint_aliases,
        // `ast-mqt`. Always rendered, including when false, because the edit
        // form carries it as a checkbox: a member the form could not see would
        // be one it silently cleared on the next save.
        "roles_in_id_token": registration.roles_in_id_token.is_issued(),
        "managed_groups_claim": registration.managed_groups_claim.is_issued(),
        "command_endpoint": registration.command_endpoint.as_ref().map(RedirectUri::as_str),
        // Not settable from a registration document; shown because an
        // operator debugging an `invalid_target` needs to see it and because
        // the dedicated admin policy operation returns this same document.
        "resources": registration
            .resources
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    });

    let object = rendered
        .as_object_mut()
        .expect("the document above is a JSON object");

    optional_registration_metadata(object, registration);
    if let Some(subject) = &registration.tls_client_auth_subject {
        object.insert(subject.field().to_owned(), json!(subject.value()));
    }
    if let Some(uri) = &registration.backchannel_logout_uri {
        object.insert("backchannel_logout_uri".to_owned(), json!(uri.as_str()));
    }
    object.insert(
        "backchannel_logout_session_required".to_owned(),
        json!(registration.backchannel_logout_session_required),
    );

    rendered
}

/// Add optional RFC 7591 metadata only when the stored registration has it.
fn optional_registration_metadata(
    object: &mut serde_json::Map<String, Value>,
    registration: &ClientRegistration,
) {
    // RFC 7591 §2: `jwks` and `jwks_uri` must never both appear. A stored
    // registration can hold only one, so this reproduces that rather than
    // deciding it again.
    match &registration.jwks {
        JwksSource::None => None,
        JwksSource::Inline(keys) => object.insert("jwks".to_owned(), keys.clone()),
        JwksSource::Uri(uri) => object.insert("jwks_uri".to_owned(), json!(uri)),
    };

    // Omitted rather than null when the client registered none: an absent
    // member and a null one mean different things to a strict reader, and
    // RFC 7591 §2 makes every metadata field optional.
    if let Some(alg) = registration.request_object_signing_alg {
        object.insert("request_object_signing_alg".to_owned(), json!(alg.as_str()));
    }
    if let Some(alg) = registration.authorization_signed_response_alg {
        object.insert(
            "authorization_signed_response_alg".to_owned(),
            json!(alg.as_str()),
        );
    }
    if let Some(modes) = &registration.response_modes {
        object.insert("response_modes".to_owned(), json!(modes));
    }
    if let Some(alg) = registration.backchannel_authentication_request_signing_alg {
        object.insert(
            "backchannel_authentication_request_signing_alg".to_owned(),
            json!(alg.as_str()),
        );
    }
    if let Some(alg) = registration.userinfo_signed_response_alg {
        object.insert(
            "userinfo_signed_response_alg".to_owned(),
            json!(alg.as_str()),
        );
    }
    for (enabled, prefix) in [
        (registration.encrypt_id_token, "id_token"),
        (registration.encrypt_userinfo, "userinfo"),
    ] {
        if enabled {
            object.insert(
                format!("{prefix}_encrypted_response_alg"),
                json!("RSA-OAEP-256"),
            );
            object.insert(format!("{prefix}_encrypted_response_enc"), json!("A256GCM"));
        }
    }
    if let Some(alg) = registration.introspection_signed_response_alg {
        object.insert(
            "introspection_signed_response_alg".to_owned(),
            json!(alg.as_str()),
        );
    }
    if let Some(uri) = &registration.sector_identifier_uri {
        object.insert("sector_identifier_uri".to_owned(), json!(uri));
    }
    // CIBA Core 1.0 §4, on the same terms as `POST /register` renders it
    // (`ast-lh3.7`): the console shows a client the way its own record reads
    // back, and a member the operator cannot see is one they cannot check.
    if let Some(mode) = registration.backchannel_token_delivery_mode {
        object.insert(
            "backchannel_token_delivery_mode".to_owned(),
            json!(mode.as_str()),
        );
    }
    if let Some(url) = &registration.backchannel_client_notification_endpoint {
        object.insert(
            "backchannel_client_notification_endpoint".to_owned(),
            json!(url),
        );
    }
    if registration.backchannel_user_code_parameter {
        object.insert("backchannel_user_code_parameter".to_owned(), json!(true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_application_round_trip_preserves_resources_and_public_keys() {
        let metadata = json!({"client_name":"Billing", "redirect_uris":["https://rp.example/cb"], "jwks":{"keys":[{"kty":"OKP"}]}});
        let mut registration = ClientRegistration::from_json(
            &serde_json::to_vec(&metadata).expect("metadata"),
            Capabilities::default(),
        )
        .expect("valid FAPI registration");
        registration
            .resources
            .insert("https://api.example/".to_owned());
        let now = OffsetDateTime::UNIX_EPOCH;
        let client = Client {
            tenant: TenantId::new("acme"),
            id: ClientId::mint(),
            registration,
            status: ClientStatus::Active,
            created_at: now,
            updated_at: now,
        };
        let rendered = document(&client);
        assert_eq!(rendered["resources"], json!(["https://api.example/"]));
        assert!(rendered.get("client_id").is_none());
        assert!(rendered.get("registration_access_token").is_none());
        assert!(
            rendered
                .as_object()
                .expect("document")
                .keys()
                .all(|field| APPLICATION_FIELDS.contains(&field.as_str()))
        );
        let reconstructed =
            parse_registration(&rendered, Capabilities::default()).expect("rendered registration");
        assert_eq!(reconstructed.client_name, client.registration.client_name);
        assert_eq!(reconstructed.jwks, client.registration.jwks);
        assert_eq!(
            reconstructed.token_binding,
            client.registration.token_binding
        );
        assert_eq!(reconstructed.resources, client.registration.resources);
    }
    #[test]
    fn private_key_and_secret_metadata_cannot_enter_controller_state() {
        let mut spec = json!({"client_name":"Billing", "redirect_uris":["https://rp.example/cb"], "jwks":{"keys":[{"kty":"OKP","d":"private"}]}, "resources":[]});
        assert!(parse_registration(&spec, Capabilities::default()).is_err());
        spec["jwks"] = json!({"keys":[{"kty":"OKP"}]});
        spec["client_secret"] = json!("never-state");
        assert!(parse_registration(&spec, Capabilities::default()).is_err());
    }

    #[test]
    fn resource_parser_canonicalises_duplicates_and_rejects_non_resource_identity() {
        let mut spec = json!({"client_name":"Billing", "redirect_uris":["https://rp.example/cb"], "jwks":{"keys":[{"kty":"OKP"}]}, "resources":["https://api.example/", "https://api.example/"]});
        assert_eq!(
            parse_registration(&spec, Capabilities::default())
                .expect("deduplicated resources")
                .resources
                .len(),
            1
        );
        spec["resources"] = json!(["not-an-absolute-resource"]);
        assert!(parse_registration(&spec, Capabilities::default()).is_err());
    }
}
