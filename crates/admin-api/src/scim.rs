//! SCIM 2.0 discovery documents and wire errors (RFC 7643 §§5–7, RFC 7644 §4).
//!
//! Resource catalogues remain empty until the Users and Groups provisioning
//! handlers are complete. Discovery must never advertise incomplete resources.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AdminError;
use asterius_domain::ScimUserState;
use time::format_description::well_known::Rfc3339;

/// SCIM media type required by RFC 7644 §3.1.
pub const MEDIA_TYPE: &str = "application/scim+json";
const LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const CONFIG: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// Identifies SCIM routes for their wire error envelope.
#[must_use]
pub fn is_route(id: &str) -> bool {
    matches!(
        id,
        crate::SCIM_CONFIG_ID
            | crate::SCIM_SCHEMAS_ID
            | crate::SCIM_RESOURCE_TYPES_ID
            | crate::SCIM_USER_READ_ID
            | crate::SCIM_USER_CREATE_ID
            | crate::SCIM_USERS_LIST_ID
    )
}

fn response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, axum::Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// SCIM's common error shape. No storage or token detail reaches `detail`.
#[must_use]
pub fn error_response(error: &AdminError) -> Response {
    let detail = match error.status() {
        StatusCode::UNAUTHORIZED => "Provisioning authentication is required",
        StatusCode::FORBIDDEN => "Provisioning access is denied",
        StatusCode::TOO_MANY_REQUESTS => "Too many provisioning requests",
        StatusCode::SERVICE_UNAVAILABLE => "Provisioning is temporarily unavailable",
        _ => "Invalid provisioning request",
    };
    let mut response = response(
        error.status(),
        json!({ "schemas": [ERROR], "status": error.status().as_u16().to_string(), "detail": detail }),
    );
    if error.status() == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(r#"DPoP error="invalid_token""#),
        );
    }
    if let AdminError::Throttled {
        retry_after_seconds,
    } = error
        && let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string())
    {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn list(resources: &[Value], total: u64, start_index: u32) -> Value {
    json!({
        "schemas": [LIST],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

/// A tenant User with only account profile and lifecycle fields. Credentials,
/// passkeys, claims and roles do not cross this boundary.
///
/// # Errors
///
/// Fails closed if persisted timestamps cannot be represented as RFC 3339.
fn user_document(state: &ScimUserState, base: &str) -> Result<Value, AdminError> {
    let user = &state.user;
    let created = user
        .created_at
        .format(&Rfc3339)
        .map_err(|_| AdminError::Unavailable)?;
    let modified = user
        .updated_at
        .format(&Rfc3339)
        .map_err(|_| AdminError::Unavailable)?;
    let mut body = json!({
        "schemas": [USER],
        "id": user.id.as_uuid().to_string(),
        "userName": user.username,
        "active": user.can_authenticate(),
        "meta": {
            "resourceType": "User",
            "created": created,
            "lastModified": modified,
            "version": format!("W/\"{}\"", state.revision),
            "location": format!("{base}/Users/{}", user.id.as_uuid()),
        },
    });
    if let Some(email) = &user.email {
        body["emails"] = json!([{"value": email, "type": "work", "primary": true}]);
    }
    if let Some(external_id) = &state.external_id {
        body["externalId"] = json!(external_id);
    }
    Ok(body)
}

/// A SCIM User response, including `Location` after creation.
///
/// # Errors
///
/// Fails closed if persisted timestamps or the resource URI cannot be represented.
pub fn user_response(
    state: &ScimUserState,
    base: &str,
    status: StatusCode,
) -> Result<Response, AdminError> {
    let mut response = response(status, user_document(state, base)?);
    let etag = HeaderValue::from_str(&format!("W/\"{}\"", state.revision))
        .map_err(|_| AdminError::Unavailable)?;
    response.headers_mut().insert(header::ETAG, etag);
    if status == StatusCode::CREATED {
        let location = format!("{base}/Users/{}", state.user.id.as_uuid());
        let value = HeaderValue::from_str(&location).map_err(|_| AdminError::Unavailable)?;
        response.headers_mut().insert(header::LOCATION, value);
    }
    Ok(response)
}

/// A bounded SCIM offset page with a separately counted tenant total.
///
/// # Errors
///
/// Fails closed if a persisted timestamp cannot be represented.
pub fn users_list_response(
    users: &[ScimUserState],
    total: u64,
    start_index: u32,
    base: &str,
) -> Result<Response, AdminError> {
    let resources = users
        .iter()
        .map(|user| user_document(user, base))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(response(
        StatusCode::OK,
        list(&resources, total, start_index),
    ))
}

/// The writable account subset. Unknown attributes are refused instead of
/// being silently dropped, especially `password`, `roles` and extensions.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedUser {
    pub schemas: Vec<String>,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(default, rename = "externalId")]
    pub external_id: Option<String>,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(default)]
    pub emails: Vec<RequestedEmail>,
}

const fn default_active() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedEmail {
    pub value: String,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default)]
    pub primary: bool,
}

/// The first supported SCIM filter shape. The literal is decoded by JSON's
/// string parser, so escaped quotes cannot break the expression boundary.
///
/// # Errors
///
/// Returns a 400 for unsupported expressions or an oversized literal.
pub fn username_eq_filter(raw: &str) -> Result<String, AdminError> {
    let (attribute, literal) = raw
        .split_once(" eq ")
        .ok_or_else(|| AdminError::Invalid("unsupported SCIM filter".to_owned()))?;
    if attribute != "userName" {
        return Err(AdminError::Invalid("unsupported SCIM filter".to_owned()));
    }
    let value: String = serde_json::from_str(literal)
        .map_err(|_| AdminError::Invalid("invalid SCIM filter literal".to_owned()))?;
    if value.len() > crate::users::MAX_USERNAME_LEN {
        return Err(AdminError::Invalid("SCIM filter is too long".to_owned()));
    }
    Ok(value)
}

impl RequestedUser {
    /// Client-controlled stable key, bounded before it reaches the database.
    pub fn accepted_external_id(&self) -> Result<Option<&str>, AdminError> {
        match self.external_id.as_deref() {
            Some(value)
                if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) =>
            {
                Err(AdminError::Invalid("invalid SCIM externalId".to_owned()))
            }
            other => Ok(other),
        }
    }

    /// Maps the protocol document into the existing account admission path.
    /// No SCIM input can set `email_verified` or a credential.
    ///
    /// # Errors
    ///
    /// Refuses unsupported extensions, multiple addresses and bad email types.
    pub fn account(&self) -> Result<crate::users::RequestedAccount, AdminError> {
        if self.schemas != [USER] {
            return Err(AdminError::Invalid(
                "unsupported SCIM User schema".to_owned(),
            ));
        }
        if self.emails.len() > 1 {
            return Err(AdminError::Invalid(
                "one primary email is supported".to_owned(),
            ));
        }
        if let Some(email) = self.emails.first()
            && email.kind.as_deref().is_some_and(|kind| kind != "work")
        {
            return Err(AdminError::Invalid(
                "only work email is supported".to_owned(),
            ));
        }
        Ok(crate::users::RequestedAccount {
            username: self.user_name.clone(),
            email: self.emails.first().map(|email| email.value.clone()),
            email_verified: false,
            password: None,
            claims: None,
        })
    }
}

/// Renders one registered discovery operation. Users and Groups will be added
/// to these catalogues when their handlers are complete (`ast-s36.13.2` and `.3`).
#[must_use]
pub fn discovery_response(id: &str, base: &str) -> Response {
    let body = match id {
        crate::SCIM_CONFIG_ID => json!({
            "schemas": [CONFIG],
            "patch": {"supported": false},
            "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": false, "maxResults": 200},
            "changePassword": {"supported": false},
            "sort": {"supported": false},
            "etag": {"supported": false},
            "authenticationSchemes": [{
                "type": "oauth2",
                "name": "OAuth 2.0 DPoP",
                "description": "Tenant-bound client credentials token with DPoP proof and admin.scim:read scope",
                "specUri": "https://www.rfc-editor.org/rfc/rfc9449",
                "primary": true,
            }],
            "meta": {"resourceType": "ServiceProviderConfig", "location": format!("{base}/ServiceProviderConfig")},
        }),
        crate::SCIM_SCHEMAS_ID | crate::SCIM_RESOURCE_TYPES_ID => list(&[], 0, 1),
        _ => return error_response(&AdminError::NotFound),
    };
    response(StatusCode::OK, body)
}
