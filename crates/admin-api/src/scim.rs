//! SCIM 2.0 discovery documents and wire errors (RFC 7643 §§5–7, RFC 7644 §4).
//!
//! Resource catalogues remain empty until the Users and Groups provisioning
//! handlers exist. Discovery must never advertise an endpoint that returns 404.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::AdminError;

/// SCIM media type required by RFC 7644 §3.1.
pub const MEDIA_TYPE: &str = "application/scim+json";
const LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
const CONFIG: &str = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";

/// Identifies the three discovery routes for their wire error envelope.
#[must_use]
pub fn is_discovery(id: &str) -> bool {
    matches!(
        id,
        crate::SCIM_CONFIG_ID | crate::SCIM_SCHEMAS_ID | crate::SCIM_RESOURCE_TYPES_ID
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

fn list(resources: Vec<Value>) -> Value {
    json!({
        "schemas": [LIST],
        "totalResults": resources.len(),
        "startIndex": 1,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

/// Renders one registered discovery operation. Users and Groups will be added
/// to these catalogues with their handlers (`ast-s36.13.2` and `.3`).
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
        crate::SCIM_SCHEMAS_ID | crate::SCIM_RESOURCE_TYPES_ID => list(Vec::new()),
        _ => return error_response(&AdminError::NotFound),
    };
    response(StatusCode::OK, body)
}
