//! Strict wire requests and validation for the additive management contract.
use asterius_domain::declarative::{Error, Kind};
use axum::http::{HeaderMap, header};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Create {
    pub kind: Kind,
    pub external_key: String,
    pub spec: Value,
    #[serde(default = "protected")]
    pub deletion_protection: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Replace {
    pub spec: Value,
    #[serde(default = "protected")]
    pub deletion_protection: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Plan {
    pub spec: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Membership {
    group_id: uuid::Uuid,
    user_id: uuid::Uuid,
}

const fn protected() -> bool {
    true
}

pub(crate) fn expected(headers: &HeaderMap) -> Result<String, crate::AdminError> {
    let raw = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or(crate::AdminError::PreconditionRequired)?;
    let revision = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| {
            crate::AdminError::Invalid("If-Match requires the exact strong ETag".to_owned())
        })?;
    if revision.len() != 64
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(crate::AdminError::Invalid(
            "If-Match requires the exact strong ETag".to_owned(),
        ));
    }
    Ok(revision.to_owned())
}

pub(crate) fn normalise(kind: Kind, spec: &Value) -> Result<Value, crate::AdminError> {
    let invalid = || crate::AdminError::Invalid("invalid declarative specification".to_owned());
    match kind {
        Kind::Resource => {
            let identifier = spec["identifier"].as_str().ok_or_else(invalid)?;
            let mut metadata = spec.clone();
            metadata
                .as_object_mut()
                .ok_or_else(invalid)?
                .remove("identifier");
            let requested: crate::resource_servers::Document =
                serde_json::from_value(metadata).map_err(|_| invalid())?;
            let resource = crate::resource_servers::parse(identifier, requested)?;
            Ok(crate::resource_servers::render(&resource))
        }
        Kind::Group => {
            let requested: crate::groups::RequestedGroup =
                serde_json::from_value(spec.clone()).map_err(|_| invalid())?;
            let metadata = requested.metadata()?;
            Ok(json!({"name":metadata.name().as_str(),"display_name":metadata.display_name()}))
        }
        Kind::Membership => {
            let requested: Membership =
                serde_json::from_value(spec.clone()).map_err(|_| invalid())?;
            Ok(
                json!({"group_id":requested.group_id.to_string(),"user_id":requested.user_id.to_string()}),
            )
        }
        Kind::Policy => asterius_domain::policy::RuleSet::from_json(spec)
            .map(|rules| rules.to_json())
            .map_err(|_| invalid()),
        Kind::Tenant | Kind::Application => Ok(spec.clone()), // Validated with runtime policy by the adapter and composition gate.
    }
}

pub(crate) fn is_route(id: &str) -> bool {
    id.starts_with("declarative.")
}

pub(crate) fn response(
    document: &asterius_domain::declarative::Document,
) -> Result<axum::response::Response, crate::AdminError> {
    use axum::response::IntoResponse as _;
    let mut response = axum::Json(document).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    let etag = axum::http::HeaderValue::from_str(&format!("\"{}\"", document.revision))
        .map_err(|_| crate::AdminError::Unavailable)?;
    response.headers_mut().insert(header::ETAG, etag);
    Ok(response)
}

pub(crate) fn refusal(error: Error) -> crate::AdminError {
    crate::AdminError::Declarative(error)
}

pub(crate) fn authorize(
    principal: &crate::auth::Principal,
    kind: Kind,
    target: &asterius_domain::TenantId,
    writing: bool,
    creating: bool,
) -> Result<(), crate::AdminError> {
    use crate::rbac::{Authority, Reach};
    if !matches!(principal, crate::auth::Principal::Automation { .. }) {
        return Err(crate::AdminError::Forbidden);
    }
    let reach = if kind == Kind::Tenant && creating {
        Reach::Deployment
    } else {
        Reach::Tenant
    };
    if !principal
        .held()
        .satisfies(Authority::new(reach, kind.read_scope()), target)
        || (writing
            && !principal
                .held()
                .satisfies(Authority::new(reach, kind.write_scope()), target))
    {
        return Err(crate::AdminError::Forbidden);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conditional_writes_refuse_wildcards_and_weak_etags() {
        let mut headers = HeaderMap::new();
        for value in ["*", "W/\"abc\"", "\"abc\""] {
            headers.insert(header::IF_MATCH, value.parse().expect("header"));
            assert!(expected(&headers).is_err());
        }
        headers.insert(
            header::IF_MATCH,
            format!("\"{}\"", "a".repeat(64)).parse().expect("header"),
        );
        assert_eq!(expected(&headers).expect("etag"), "a".repeat(64));
    }
    #[test]
    fn unknown_metadata_and_membership_fields_fail_closed() {
        assert!(
            normalise(
                Kind::Group,
                &json!({"name":"group","display_name":"Group","owner":"attacker"})
            )
            .is_err()
        );
        assert!(normalise(Kind::Membership, &json!({"group_id":"no","user_id":"no"})).is_err());
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use crate::{auth::Principal, rbac::Held};
    fn service(tenant: Option<&str>, scopes: Vec<&str>) -> Principal {
        Principal::Automation {
            subject: "controller".to_owned(),
            held: Held::Scopes {
                tenant: tenant
                    .map(|tenant| asterius_domain::TenantId::parse(tenant).expect("tenant")),
                scopes: scopes.into_iter().map(str::to_owned).collect(),
            },
        }
    }
    #[test]
    fn session_scope_alone_cannot_access_any_kind() {
        let principal = service(Some("acme"), vec!["admin.session:read"]);
        let target = asterius_domain::TenantId::parse("acme").expect("tenant");
        for kind in [
            Kind::Tenant,
            Kind::Application,
            Kind::Resource,
            Kind::Group,
            Kind::Membership,
            Kind::Policy,
        ] {
            assert!(authorize(&principal, kind, &target, false, false).is_err());
        }
    }
    #[test]
    fn kind_scopes_require_matching_reach_and_write_permission() {
        let target = asterius_domain::TenantId::parse("acme").expect("tenant");
        let reader = service(Some("acme"), vec!["admin.groups:read"]);
        assert!(authorize(&reader, Kind::Group, &target, false, false).is_ok());
        assert!(authorize(&reader, Kind::Group, &target, true, false).is_err());
        let other = service(
            Some("other"),
            vec!["admin.groups:read", "admin.groups:write"],
        );
        assert!(authorize(&other, Kind::Group, &target, true, false).is_err());
        let local = service(
            Some("acme"),
            vec!["admin.tenants:read", "admin.tenants:write"],
        );
        assert!(authorize(&local, Kind::Tenant, &target, true, true).is_err());
        let deployment = service(None, vec!["admin.tenants:read", "admin.tenants:write"]);
        assert!(authorize(&deployment, Kind::Tenant, &target, true, true).is_ok());
    }
}
