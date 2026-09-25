//! SCIM Group wire contract over client-owned managed groups.

use asterius_domain::{ScimGroupState, UserId};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::{AdminError, scim};

pub const GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
const RESOURCE_TYPE: &str = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
const LIST: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedGroup {
    pub schemas: Vec<String>,
    #[serde(default, rename = "id")]
    _id: Option<String>,
    #[serde(default, rename = "meta")]
    _meta: Option<Value>,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(default, rename = "externalId")]
    pub external_id: Option<String>,
    #[serde(default)]
    pub members: Vec<Member>,
}

impl RequestedGroup {
    pub fn validate(&self, base: &str) -> Result<Vec<UserId>, AdminError> {
        if self.schemas != [GROUP] {
            return Err(AdminError::Invalid(
                "unsupported SCIM Group schema".to_owned(),
            ));
        }
        scim::accept_external_id(self.external_id.as_deref())?;
        members(&self.members, base)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub value: String,
    #[serde(default, rename = "$ref")]
    pub reference: Option<String>,
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    #[serde(default, rename = "display")]
    _display: Option<String>,
}

fn members(members: &[Member], base: &str) -> Result<Vec<UserId>, AdminError> {
    if members.len() > 1_000 {
        return Err(AdminError::Invalid(
            "too many SCIM group members".to_owned(),
        ));
    }
    members
        .iter()
        .map(|member| {
            let id = Uuid::parse_str(&member.value)
                .map_err(|_| AdminError::Invalid("invalid SCIM member value".to_owned()))?;
            if member.kind.as_deref().is_some_and(|kind| kind != "User")
                || member
                    .reference
                    .as_deref()
                    .is_some_and(|reference| reference != format!("{base}/Users/{id}"))
            {
                return Err(AdminError::Invalid(
                    "SCIM member reference is outside this tenant".to_owned(),
                ));
            }
            Ok(UserId::new(id))
        })
        .collect()
}

/// The bounded exact Group filter this resource implements.
pub fn display_name_eq_filter(raw: &str) -> Result<String, AdminError> {
    let (attribute, literal) = raw
        .split_once(" eq ")
        .ok_or_else(|| AdminError::Invalid("unsupported SCIM filter".to_owned()))?;
    if !attribute.eq_ignore_ascii_case("displayName") {
        return Err(AdminError::Invalid("unsupported SCIM filter".to_owned()));
    }
    let value: String = serde_json::from_str(literal)
        .map_err(|_| AdminError::Invalid("invalid SCIM filter literal".to_owned()))?;
    if value.len() > 200 {
        return Err(AdminError::Invalid("SCIM filter is too long".to_owned()));
    }
    Ok(value)
}

#[derive(Debug)]
pub struct PatchedGroup {
    pub display_name: String,
    pub external_id: Option<String>,
    pub members: Vec<UserId>,
}

/// Applies supported RFC 7644 Group changes in memory before one CAS write.
pub fn apply_patch(
    request: scim::PatchRequest,
    held: &ScimGroupState,
    base: &str,
) -> Result<PatchedGroup, AdminError> {
    if request.schemas != [PATCH] || request.operations.is_empty() || request.operations.len() > 20
    {
        return Err(AdminError::Invalid(
            "invalid SCIM PatchOp envelope".to_owned(),
        ));
    }
    let mut result = PatchedGroup {
        display_name: held.group.metadata.display_name().to_owned(),
        external_id: held.external_id.clone(),
        members: held.members.clone(),
    };
    for operation in request.operations {
        let remove = operation.op.eq_ignore_ascii_case("remove");
        let add = operation.op.eq_ignore_ascii_case("add");
        if !remove && !add && !operation.op.eq_ignore_ascii_case("replace") {
            return Err(AdminError::Invalid(
                "unsupported SCIM patch operation".to_owned(),
            ));
        }
        match operation.path {
            Some(path) => apply_attribute(&mut result, &path, operation.value, remove, add, base)?,
            None if !remove => {
                let Value::Object(attributes) = operation.value.ok_or_else(|| {
                    AdminError::Invalid("SCIM patch value is required".to_owned())
                })?
                else {
                    return Err(AdminError::Invalid(
                        "SCIM patch value must be an object".to_owned(),
                    ));
                };
                for (name, value) in attributes {
                    apply_attribute(&mut result, &name, Some(value), false, add, base)?;
                }
            }
            _ => {
                return Err(AdminError::Invalid(
                    "unsupported SCIM patch path".to_owned(),
                ));
            }
        }
    }
    scim::accept_external_id(result.external_id.as_deref())?;
    Ok(result)
}

fn apply_attribute(
    result: &mut PatchedGroup,
    path: &str,
    value: Option<Value>,
    remove: bool,
    add: bool,
    base: &str,
) -> Result<(), AdminError> {
    if path.eq_ignore_ascii_case("displayName") {
        if remove {
            return Err(AdminError::Invalid(
                "displayName cannot be removed".to_owned(),
            ));
        }
        result.display_name = serde_json::from_value(
            value.ok_or_else(|| AdminError::Invalid("displayName value is required".to_owned()))?,
        )
        .map_err(|_| AdminError::Invalid("displayName must be a string".to_owned()))?;
    } else if path.eq_ignore_ascii_case("externalId") {
        result.external_id = if remove {
            None
        } else {
            Some(
                serde_json::from_value(value.ok_or_else(|| {
                    AdminError::Invalid("externalId value is required".to_owned())
                })?)
                .map_err(|_| AdminError::Invalid("externalId must be a string".to_owned()))?,
            )
        };
    } else if path.eq_ignore_ascii_case("members") {
        let changed = if remove {
            Vec::new()
        } else {
            parse_member_value(
                value.ok_or_else(|| AdminError::Invalid("members value is required".to_owned()))?,
                base,
            )?
        };
        if add {
            result.members.extend(changed);
        } else {
            result.members = changed;
        }
    } else if remove && path.starts_with("members[value eq \"") && path.ends_with("\"]") {
        let literal = &path[18..path.len() - 2];
        let id = Uuid::parse_str(literal)
            .map_err(|_| AdminError::Invalid("invalid SCIM member filter".to_owned()))?;
        result.members.retain(|user| *user.as_uuid() != id);
    } else {
        return Err(AdminError::Invalid(
            "unsupported SCIM patch path".to_owned(),
        ));
    }
    Ok(())
}

fn parse_member_value(value: Value, base: &str) -> Result<Vec<UserId>, AdminError> {
    let requested: Vec<Member> = if value.is_array() {
        serde_json::from_value(value)
    } else {
        serde_json::from_value(value).map(|member| vec![member])
    }
    .map_err(|_| AdminError::Invalid("invalid SCIM members value".to_owned()))?;
    members(&requested, base)
}

fn response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, axum::Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(scim::MEDIA_TYPE),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn document(state: &ScimGroupState, base: &str) -> Result<Value, AdminError> {
    let group = &state.group;
    let created = group
        .created_at
        .format(&Rfc3339)
        .map_err(|_| AdminError::Unavailable)?;
    let modified = group
        .updated_at
        .format(&Rfc3339)
        .map_err(|_| AdminError::Unavailable)?;
    let mut body = json!({
        "schemas": [GROUP],
        "id": group.id.as_uuid().to_string(),
        "displayName": group.metadata.display_name(),
        "members": state.members.iter().map(|user| json!({
            "value": user.as_uuid().to_string(),
            "$ref": format!("{base}/Users/{}", user.as_uuid()),
            "type": "User",
        })).collect::<Vec<_>>(),
        "meta": {
            "resourceType": "Group", "created": created, "lastModified": modified,
            "version": format!("W/\"{}\"", group.revision),
            "location": format!("{base}/Groups/{}", group.id.as_uuid()),
        },
    });
    if let Some(external_id) = &state.external_id {
        body["externalId"] = json!(external_id);
    }
    Ok(body)
}

pub fn group_response(
    state: &ScimGroupState,
    base: &str,
    status: StatusCode,
) -> Result<Response, AdminError> {
    let mut response = response(status, document(state, base)?);
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("W/\"{}\"", state.group.revision))
            .map_err(|_| AdminError::Unavailable)?,
    );
    if status == StatusCode::CREATED {
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_str(&format!("{base}/Groups/{}", state.group.id.as_uuid()))
                .map_err(|_| AdminError::Unavailable)?,
        );
    }
    Ok(response)
}

pub fn groups_list_response(
    states: &[ScimGroupState],
    total: u64,
    start_index: u32,
    base: &str,
) -> Result<Response, AdminError> {
    let resources = states
        .iter()
        .map(|state| document(state, base))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(response(
        StatusCode::OK,
        json!({
            "schemas": [LIST], "totalResults": total, "startIndex": start_index,
            "itemsPerPage": resources.len(), "Resources": resources,
        }),
    ))
}

/// The subset of Group attributes the provisioning interface actually serves.
pub fn schema() -> Value {
    json!({
        "schemas": [SCHEMA], "id": GROUP, "name": "Group",
        "description": "Client-owned managed group without application roles",
        "attributes": [
            {"name":"id","type":"string","multiValued":false,"required":true,
             "caseExact":true,"mutability":"readOnly","returned":"always","uniqueness":"server"},
            {"name":"displayName","type":"string","multiValued":false,"required":true,
             "caseExact":true,"mutability":"readWrite","returned":"always","uniqueness":"none"},
            {"name":"externalId","type":"string","multiValued":false,"required":false,
             "caseExact":true,"mutability":"readWrite","returned":"default","uniqueness":"server"},
            {"name":"members","type":"complex","multiValued":true,"required":false,
             "mutability":"readWrite","returned":"default","subAttributes":[
                {"name":"value","type":"string","multiValued":false,"required":true,
                 "caseExact":true,"mutability":"readWrite","returned":"default"},
                {"name":"$ref","type":"reference","multiValued":false,"required":false,
                 "referenceTypes":["User"],"mutability":"readOnly","returned":"default"},
                {"name":"type","type":"string","multiValued":false,"required":false,
                 "canonicalValues":["User"],"mutability":"readOnly","returned":"default"}
             ]},
            {"name":"meta","type":"complex","multiValued":false,"required":false,
             "mutability":"readOnly","returned":"default"}
        ],
        "meta":{"resourceType":"Schema"},
    })
}

pub fn resource_type() -> Value {
    json!({
        "schemas": [RESOURCE_TYPE], "id":"Group", "name":"Group",
        "description":"Client-owned managed group provisioning profile",
        "endpoint":"/Groups", "schema":GROUP,
        "meta":{"resourceType":"ResourceType"},
    })
}
