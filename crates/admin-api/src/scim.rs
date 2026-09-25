//! SCIM 2.0 discovery documents, User wire shapes, and errors.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AdminError;
use asterius_domain::{ScimUserState, UserStatus};
use time::format_description::well_known::Rfc3339;

/// SCIM media type required by RFC 7644 §3.1.
pub const MEDIA_TYPE: &str = "application/scim+json";
const LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const CONFIG: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
const RESOURCE_TYPE: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";

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
            | crate::SCIM_USER_REPLACE_ID
            | crate::SCIM_USER_DELETE_ID
            | crate::SCIM_USER_PATCH_ID
            | crate::SCIM_GROUPS_LIST_ID
            | crate::SCIM_GROUP_CREATE_ID
            | crate::SCIM_GROUP_READ_ID
            | crate::SCIM_GROUP_REPLACE_ID
            | crate::SCIM_GROUP_PATCH_ID
            | crate::SCIM_GROUP_DELETE_ID
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
        StatusCode::PRECONDITION_REQUIRED => "If-Match is required",
        StatusCode::PRECONDITION_FAILED => "SCIM resource version changed",
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
    /// Returned by GET; ignored on PUT as a read-only SCIM attribute.
    #[serde(default)]
    pub id: Option<String>,
    /// Returned by GET; ignored on PUT as a read-only SCIM attribute.
    #[serde(default)]
    pub meta: Option<Value>,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(default, rename = "externalId")]
    pub external_id: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub emails: Vec<RequestedEmail>,
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

/// The bounded RFC 7644 `PatchOp` envelope accepted for approved User fields.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchRequest {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchOperation {
    pub op: String,
    pub path: Option<String>,
    pub value: Option<Value>,
}

/// The in-memory result of applying every operation before one conditional write.
#[derive(Debug)]
pub struct PatchedUser {
    pub username: String,
    pub email: Option<String>,
    pub external_id: Option<String>,
    pub status: UserStatus,
}

impl PatchRequest {
    /// Applies supported operations in order; an error leaves the account untouched.
    pub fn apply(self, held: &ScimUserState) -> Result<PatchedUser, AdminError> {
        if self.schemas != [PATCH] || self.operations.is_empty() || self.operations.len() > 20 {
            return Err(AdminError::Invalid(
                "invalid SCIM PatchOp envelope".to_owned(),
            ));
        }
        let mut result = PatchedUser {
            username: held.user.username.clone(),
            email: held.user.email.clone(),
            external_id: held.external_id.clone(),
            status: held.user.status,
        };
        for operation in self.operations {
            let remove = operation.op.eq_ignore_ascii_case("remove");
            if !remove
                && !operation.op.eq_ignore_ascii_case("add")
                && !operation.op.eq_ignore_ascii_case("replace")
            {
                return Err(AdminError::Invalid(
                    "unsupported SCIM patch operation".to_owned(),
                ));
            }
            match operation.path {
                Some(path) => apply_attribute(&mut result, &path, operation.value, remove)?,
                None if !remove => {
                    let Value::Object(attributes) = operation.value.ok_or_else(|| {
                        AdminError::Invalid("SCIM patch value is required".to_owned())
                    })?
                    else {
                        return Err(AdminError::Invalid(
                            "SCIM patch value must be an object".to_owned(),
                        ));
                    };
                    for (path, value) in attributes {
                        apply_attribute(&mut result, &path, Some(value), false)?;
                    }
                }
                None => {
                    return Err(AdminError::Invalid(
                        "SCIM remove requires a path".to_owned(),
                    ));
                }
            }
        }
        Ok(result)
    }
}

fn apply_attribute(
    result: &mut PatchedUser,
    path: &str,
    value: Option<Value>,
    remove: bool,
) -> Result<(), AdminError> {
    let value = if remove {
        None
    } else {
        Some(value.ok_or_else(|| AdminError::Invalid("SCIM patch value is required".to_owned()))?)
    };
    if path.eq_ignore_ascii_case("userName") {
        if remove {
            return Err(AdminError::Invalid("userName cannot be removed".to_owned()));
        }
        result.username = serde_json::from_value(
            value.ok_or_else(|| AdminError::Invalid("userName is required".to_owned()))?,
        )
        .map_err(|_| AdminError::Invalid("userName must be a string".to_owned()))?;
    } else if path.eq_ignore_ascii_case("active") {
        if remove {
            return Err(AdminError::Invalid("active cannot be removed".to_owned()));
        }
        let active: bool = serde_json::from_value(
            value.ok_or_else(|| AdminError::Invalid("active is required".to_owned()))?,
        )
        .map_err(|_| AdminError::Invalid("active must be boolean".to_owned()))?;
        result.status = if active {
            UserStatus::Active
        } else {
            UserStatus::Disabled
        };
    } else if path.eq_ignore_ascii_case("externalId") {
        result.external_id = value
            .map(|value| {
                serde_json::from_value(value)
                    .map_err(|_| AdminError::Invalid("externalId must be a string".to_owned()))
            })
            .transpose()?;
    } else if path.eq_ignore_ascii_case("emails") {
        let emails: Vec<RequestedEmail> = value
            .map(|value| {
                serde_json::from_value(value)
                    .map_err(|_| AdminError::Invalid("emails must be an array".to_owned()))
            })
            .transpose()?
            .unwrap_or_default();
        if emails.len() > 1
            || emails
                .first()
                .and_then(|email| email.kind.as_deref())
                .is_some_and(|kind| kind != "work")
        {
            return Err(AdminError::Invalid(
                "one work email is supported".to_owned(),
            ));
        }
        result.email = emails.into_iter().next().map(|email| email.value);
    } else if path.eq_ignore_ascii_case("emails[type eq \"work\"].value") {
        result.email = value
            .map(|value| {
                serde_json::from_value(value)
                    .map_err(|_| AdminError::Invalid("email must be a string".to_owned()))
            })
            .transpose()?;
    } else {
        return Err(AdminError::Invalid(
            "unsupported SCIM patch path".to_owned(),
        ));
    }
    Ok(())
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

/// Parses the monotonic resource version issued in `ETag`/`meta.version`.
///
/// # Errors
///
/// Missing preconditions are 428; malformed or wildcard values are 400.
pub fn expected_revision(headers: &HeaderMap) -> Result<i64, AdminError> {
    let value = headers
        .get(header::IF_MATCH)
        .ok_or(AdminError::PreconditionRequired)?
        .to_str()
        .map_err(|_| AdminError::Invalid("invalid If-Match".to_owned()))?;
    let digits = value
        .strip_prefix("W/\"")
        .or_else(|| value.strip_prefix('"'))
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(|| AdminError::Invalid("invalid If-Match".to_owned()))?;
    let revision = digits
        .parse::<i64>()
        .map_err(|_| AdminError::Invalid("invalid If-Match".to_owned()))?;
    if revision < 1 {
        return Err(AdminError::Invalid("invalid If-Match".to_owned()));
    }
    Ok(revision)
}

impl RequestedUser {
    /// Client-controlled stable key, bounded before it reaches the database.
    pub fn accepted_external_id(&self) -> Result<Option<&str>, AdminError> {
        accept_external_id(self.external_id.as_deref())
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

/// Checks the client-owned identifier used by POST, PUT and PATCH.
pub fn accept_external_id(value: Option<&str>) -> Result<Option<&str>, AdminError> {
    match value {
        Some(value)
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) =>
        {
            Err(AdminError::Invalid("invalid SCIM externalId".to_owned()))
        }
        other => Ok(other),
    }
}

/// Renders the currently implemented User resource and global capabilities.
#[must_use]
pub fn discovery_response(id: &str, base: &str) -> Response {
    let body = match id {
        crate::SCIM_CONFIG_ID => json!({
            "schemas": [CONFIG],
            "patch": {"supported": true},
            "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": true, "maxResults": 200},
            "changePassword": {"supported": false},
            "sort": {"supported": false},
            "etag": {"supported": true},
            "authenticationSchemes": [{
                "type": "oauth2",
                "name": "OAuth 2.0 DPoP",
                "description": "Tenant-bound client credentials token with DPoP proof and admin.scim:read or admin.scim:write scope",
                "specUri": "https://www.rfc-editor.org/rfc/rfc9449",
                "primary": true,
            }],
            "meta": {"resourceType": "ServiceProviderConfig", "location": format!("{base}/ServiceProviderConfig")},
        }),
        crate::SCIM_SCHEMAS_ID => list(&[user_schema(), crate::scim_groups::schema()], 2, 1),
        crate::SCIM_RESOURCE_TYPES_ID => list(
            &[
                json!({
                    "schemas": [RESOURCE_TYPE],
                    "id": "User",
                    "name": "User",
                    "description": "Tenant account provisioning profile",
                    "endpoint": "/Users",
                    "schema": USER,
                    "meta": {"resourceType": "ResourceType"},
                }),
                crate::scim_groups::resource_type(),
            ],
            2,
            1,
        ),
        _ => return error_response(&AdminError::NotFound),
    };
    response(StatusCode::OK, body)
}

fn user_schema() -> Value {
    json!({
        "schemas": [SCHEMA],
        "id": USER,
        "name": "User",
        "description": "Tenant account profile; credentials and roles are administered separately",
        "attributes": [
            {"name":"id","type":"string","multiValued":false,"required":true,
             "caseExact":true,"mutability":"readOnly","returned":"always","uniqueness":"server"},
            {"name":"userName","type":"string","multiValued":false,"required":true,
             "caseExact":true,"mutability":"readWrite","returned":"always","uniqueness":"server"},
            {"name":"externalId","type":"string","multiValued":false,"required":false,
             "caseExact":true,"mutability":"readWrite","returned":"default","uniqueness":"server"},
            {"name":"active","type":"boolean","multiValued":false,"required":false,
             "mutability":"readWrite","returned":"default"},
            {"name":"emails","type":"complex","multiValued":true,"required":false,
             "mutability":"readWrite","returned":"default","subAttributes":[
                 {"name":"value","type":"string","multiValued":false,"required":true,
                  "caseExact":false,"mutability":"readWrite","returned":"default"},
                 {"name":"type","type":"string","multiValued":false,"required":false,
                  "canonicalValues":["work"],"caseExact":false,"mutability":"readWrite","returned":"default"},
                 {"name":"primary","type":"boolean","multiValued":false,"required":false,
                  "mutability":"readWrite","returned":"default"}
             ]},
            {"name":"meta","type":"complex","multiValued":false,"required":false,
             "mutability":"readOnly","returned":"default","subAttributes":[
                 {"name":"resourceType","type":"string","multiValued":false,"required":false,
                  "caseExact":true,"mutability":"readOnly","returned":"default"},
                 {"name":"created","type":"dateTime","multiValued":false,"required":false,
                  "mutability":"readOnly","returned":"default"},
                 {"name":"lastModified","type":"dateTime","multiValued":false,"required":false,
                  "mutability":"readOnly","returned":"default"},
                 {"name":"version","type":"string","multiValued":false,"required":false,
                  "caseExact":true,"mutability":"readOnly","returned":"default"},
                 {"name":"location","type":"reference","multiValued":false,"required":false,
                  "referenceTypes":["uri"],"mutability":"readOnly","returned":"default"}
             ]}
        ],
        "meta": {"resourceType":"Schema"},
    })
}
