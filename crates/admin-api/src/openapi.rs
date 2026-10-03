//! The `OpenAPI` 3.1 document, generated from the route registry.
//!
//! # Generated, never maintained beside the code
//!
//! This repository has both patterns and knows what each costs. `docs/
//! configuration.md` (`ast-p2l.7`) and `docs/fuzzing.md` (`ast-p2l.5`) are
//! generated and a test fails when the checked-in copy is stale. Against that,
//! `response_modes_supported` and `grant_types_supported` were maintained by
//! hand — and produced `ast-iko` and `ast-bnc`, where discovery advertised
//! things the server does not do. A document describing an *admin* API has the
//! same failure mode with a worse blast radius: a route whose declared
//! authority and documented authority disagree is a security control nobody
//! can audit from the outside.
//!
//! So every path, verb, `operationId`, security requirement, parameter and
//! response below comes from [`crate::registry`]. There is no list here to
//! keep in step, and a test named `the_checked_in_document_is_current` fails the
//! build if `docs/admin-api-openapi.json` no longer matches what the code
//! generates.
//!
//! # Why the required authority is *in* the document
//!
//! Because "which role does this route need?" is the question an operator
//! reviewing the admin surface actually has, and the honest place to answer it
//! is the machine-readable description rather than a wiki. Each operation
//! carries `x-asterius-reach` and `x-asterius-scope`, taken from the same
//! [`crate::rbac::Authority`] the request path enforces — so the document
//! cannot describe an authority the router does not apply.

use serde_json::{Map, Value, json};

use crate::operations::{Effect, Operation};
use crate::rbac::Reach;

/// The command that rewrites the checked-in copy.
pub const REGENERATE_COMMAND: &str =
    "cargo run --quiet --bin asterius -- --admin-openapi > docs/admin-api-openapi.json";

/// Where the document is served.
pub const PATH: &str = "/openapi.json";

/// Builds the document from the registry.
///
/// Pretty-printed with a trailing newline, because it is checked in and a
/// diff of one enormous line is a diff nobody reviews.
#[must_use]
pub fn document() -> String {
    let mut rendered = serde_json::to_string_pretty(&value()).unwrap_or_else(|_| "{}".to_owned());
    rendered.push('\n');
    rendered
}

/// The document as JSON.
#[must_use]
pub fn value() -> Value {
    let mut paths = Map::new();
    for operation in crate::registry() {
        let item = paths
            .entry(operation.full_path())
            .or_insert_with(|| json!({}));
        if let Some(item) = item.as_object_mut() {
            item.insert(
                operation.method().as_openapi_key().to_owned(),
                operation_object(operation),
            );
        }
    }

    json!({
        // 3.1.0 rather than 3.0: it is the version aligned with JSON Schema
        // 2020-12, which is what `webhooks`-free tooling now expects, and the
        // one that lets a schema be a plain JSON Schema document.
        "openapi": "3.1.0",
        "info": {
            "title": "Asterius Admin API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": DESCRIPTION,
        },
        "servers": [{
            "url": "{issuer}",
            "description":
                "A tenant's issuer. The admin API is mounted beneath it, so a \
                 deployment-scoped call is made at the reserved tenant's issuer \
                 (ADR-0010).",
            "variables": { "issuer": { "default": "https://as.example" } },
        }],
        "paths": Value::Object(paths),
        "components": {
            "securitySchemes": {
                "consoleSession": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": asterius_domain::entities::session::COOKIE_NAME,
                    "description":
                        "The first-party session cookie (ADR-0009). Every \
                         state-changing request must also carry X-CSRF-Token, \
                         whose value is the `csrf_token` of GET \
                         /admin/api/v1/session.",
                },
                "adminToken": {
                    "type": "http",
                    "scheme": "DPoP",
                    "description":
                        "A DPoP-bound access token (RFC 9449 §7.1), presented \
                         with a DPoP proof header. Token calls are not subject \
                         to the CSRF check and are subject to the proof \
                         instead.",
                },
            },
            "schemas": {
                "Error": error_schema(),
                "Page": page_schema(),
                "AcrPolicy": acr_policy_schema(),
                "SessionPolicy": session_policy_schema(),
                "TenantRateLimits": rate_limits_schema(),
            },
            "parameters": {
                "cursor": {
                    "name": "cursor",
                    "in": "query",
                    "required": false,
                    "description":
                        "An opaque cursor from a previous response's \
                         next_cursor. Not a row key: its shape may change.",
                    "schema": { "type": "string" },
                },
                "limit": {
                    "name": "limit",
                    "in": "query",
                    "required": false,
                    "description": "Rows per page. Clamped to the server maximum.",
                    "schema": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": crate::pagination::MAX_LIMIT,
                        "default": crate::pagination::DEFAULT_LIMIT,
                    },
                },
            },
        },
        // Applied to every operation, and repeated per operation so that a
        // reader of one path item does not have to know about this default.
        "security": [{ "consoleSession": [] }, { "adminToken": [] }],
    })
}

const DESCRIPTION: &str = "\
The first-party administration API. Two authentication modes: the console, \
which is a same-origin application holding the IdP session cookie and no OAuth \
token of any kind (ADR-0009); and automation, which holds a DPoP-bound access \
token. Every operation declares the authority it requires in x-asterius-reach \
and x-asterius-scope, taken from the same declaration the router enforces. \
State-changing operations are never mounted on GET: SameSite=Lax does not \
protect a top-level GET, so the registry's types make a mutating GET \
unexpressible.";

fn operation_object(operation: &Operation) -> Value {
    let parameters = operation_parameters(operation);
    let mut object = json!({
        "operationId": operation.id(),
        "summary": operation.summary(),
        "x-asterius-reach": reach_name(operation.authority().reach()),
        "x-asterius-scope": operation.authority().scope(),
        "security": if crate::scim::is_route(operation.id()) {
            json!([{ "adminToken": [operation.authority().scope()] }])
        } else {
            json!([{ "consoleSession": [] }, { "adminToken": [operation.authority().scope()] }])
        },
        "responses": responses(operation),
    });

    simulation_documentation(operation, &mut object);

    if operation.id() == crate::TENANT_SETTINGS_UPDATE_ID {
        object["requestBody"] = json!({
            "required": true,
            "content": { "application/json": { "schema": {
                "type": "object",
                "required": ["authorization_code_lifetime_seconds", "access_token_lifetime_seconds"],
                "properties": {
                    "authorization_code_lifetime_seconds": {"type": "integer", "minimum": 1, "maximum": 60},
                    "access_token_lifetime_seconds": {"type": "integer", "minimum": 1, "maximum": 900},
                    "acr_policy": {"$ref": "#/components/schemas/AcrPolicy"},
                    "session_policy": {"$ref": "#/components/schemas/SessionPolicy"},
                    "rate_limits": {"$ref": "#/components/schemas/TenantRateLimits"},
                    "ida_frameworks": {"type": "array", "maxItems": 16, "uniqueItems": true, "items": {"type": "string", "maxLength": 128}},
                    "allow_ephemeral_subjects": {"type": "boolean"}
                },
                "description": "Omitted policies retain stored values. Updates are tenant-scoped and audited. Assurance replicas refresh within 30 seconds; session and rate-limit enforcement read committed settings directly."
            }}}
        });
    }
    if operation.id() == crate::TENANT_SETTINGS_READ_ID {
        object["responses"]["200"]["content"]["application/json"]["schema"] = json!({
            "type": "object", "properties": { "acr_policy": {"$ref": "#/components/schemas/AcrPolicy"},
                    "session_policy": {"$ref": "#/components/schemas/SessionPolicy"},
                    "rate_limits": {"$ref": "#/components/schemas/TenantRateLimits"},
                    "ida_frameworks": {"type": "array", "items": {"type": "string"}},
                    "allow_ephemeral_subjects": {"type": "boolean"} }
        });
    }
    declarative_documentation(operation, &mut object);
    client_resources_documentation(operation, &mut object);
    kubernetes_documentation(operation, &mut object);
    conditional_documentation(operation, &mut object);
    temporary_entitlement_documentation(operation, &mut object);
    invitation_documentation(operation, &mut object);
    theme_documentation(operation, &mut object);
    if let Some(request_body) = group_request_body(operation) {
        object["requestBody"] = request_body;
    }

    if let Some(fields) = object.as_object_mut() {
        if !parameters.is_empty() {
            fields.insert("parameters".to_owned(), Value::Array(parameters));
        }
        if operation.needs_idempotency_key() {
            // Documented as a required header rather than as prose, because a
            // client generator that does not emit it produces a client whose
            // retries create duplicates.
            fields.insert("x-asterius-idempotent".to_owned(), Value::Bool(true));
            if let Some(Value::Array(parameters)) = fields.get_mut("parameters") {
                parameters.push(idempotency_parameter());
            } else {
                fields.insert(
                    "parameters".to_owned(),
                    Value::Array(vec![idempotency_parameter()]),
                );
            }
        }
    }

    object
}

fn simulation_documentation(operation: &Operation, object: &mut Value) {
    if operation.id() == crate::POLICY_SIMULATE_ID {
        object["security"] = json!([{ "consoleSession": [] }, { "adminToken": [
            "admin.policies:read", "admin.users:read", "admin.clients:read", "admin.resource_servers:read"
        ] }]);
        object["x-asterius-additional-scopes"] = json!([
            "admin.users:read",
            "admin.clients:read",
            "admin.resource_servers:read"
        ]);
        object["requestBody"] = json!({"required": true, "content": {"application/json": {"schema": {
            "type": "object", "additionalProperties": false,
            "required": ["user_id", "client_id", "resource_id", "resource_type", "action", "expected_policy_revision"],
            "properties": {
                "user_id": {"type": "string", "format": "uuid"},
                "client_id": {"type": "string", "minLength": 1, "maxLength": 256},
                "resource_id": {"type": "string", "minLength": 1, "maxLength": 256},
                "resource_type": {"type": "string", "minLength": 1, "maxLength": 256},
                "action": {"type": "string", "minLength": 1, "maxLength": 256},
                "expected_policy_revision": {"type": ["string", "null"], "description": "SHA-256 revision from GET /policies; null requires no stored policy."},
                "enforcement_action": {"type":"string","enum": crate::policies::conditional_simulation::ACTIONS,"default":"access_evaluation","description":"Server enforcement boundary, separate from resource action."},
                "hypothetical_trusted_context": trusted_examples_schema(),
                "hypothetical_policy": {"type": "object"}, "hypothetical_context": {"type": "object"}
            },
            "description": "Bounded 128 KiB inspection. All references must exist in the routed tenant. Policy, descriptive context and explicitly labelled trusted examples may be hypothetical; directory facts remain server resolved. No selected user transaction means assurance, authentication age and network evidence are absent. Audited before lookup; never grants access or issues a token."
        }}}});
        object["responses"]["409"] =
            error_response("Stored policy revision changed; refresh the snapshot.");
        object["responses"]["400"] = error_response("Invalid simulation request.");
        object["responses"]["404"] =
            error_response("A referenced record is absent from the routed tenant.");
        let mut schema = policy_trial_schema();
        schema["required"] = json!(["decision", "simulation"]);
        schema["properties"]["simulation"] = json!({"type": "object", "required": ["enforced", "current_policy_revision", "provenance"], "properties": {
            "enforced": {"const": false}, "current_policy_revision": {"type": ["string", "null"]},
            "conditional": conditional_simulation_schema(),
            "provenance": {"type": "object", "properties": {
                "subject": {"const": "tenant_user_and_client"}, "resource": {"const": "tenant_resource_registry"},
                "groups_roles_grants": {"const": "server_resolved"},
                "trusted_transaction_evidence": {"const": "explicit_fact_sources"},
                "policy": {"enum": ["stored", "hypothetical"]}, "context_properties": {"enum": ["absent", "hypothetical"]}
            }}
        }});
        object["responses"]["200"]["content"]["application/json"]["schema"] = schema;
    }
}

fn trusted_examples_schema() -> Value {
    let missing = json!({"type":"object","additionalProperties":false,"required":["availability"],"properties":{"availability":{"enum":["absent","stale","unavailable","invalid"]}}});
    let fact = |value: Value| json!({"oneOf":[missing,{"type":"object","additionalProperties":false,"required":["availability","value"],"properties":{"availability":{"const":"known"},"value":value}}]});
    json!({"type":"object","additionalProperties":false,"maxProperties":5,"description":"Administrative what-if examples only. Cannot override groups, roles or grants or assert a production source. Missing states never carry a value.","properties":{
        "assurance":fact(json!({"type":"string","minLength":1,"maxLength":256,"description":"An attainable level in this tenant's current ACR ladder; unsupported values are invalid evidence."})),
        "authentication_age":fact(json!({"type":"integer","minimum":0,"maximum":604_800})),
        "application_sensitivity":fact(json!({"enum":["standard","sensitive","critical"]})),
        "device_compliance":fact(json!({"enum":["compliant","non_compliant","unknown"]})),
        "network_zone":fact(json!({"type":"array","maxItems":64,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.-]+$"}}))
    }})
}

fn conditional_simulation_schema() -> Value {
    json!({"type":"object","description":"Inspection only: reports active restrictions and report-only results, without returning fact values, policy literals or directory contents.","properties":{
        "enforcement_action":{"enum":crate::policies::conditional_simulation::ACTIONS},
        "legacy_would_permit":{"type":"boolean"},"active_would_permit":{"type":"boolean"},
        "policy_revision":{"type":"string"},"evaluated_policy_revision":{"type":["string","null"]},"acr_revision":{"type":"string"},"client_revision":{"type":"string"},
        "facts":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["name","availability","source","hypothetical"],"properties":{"name":{"type":"string"},"availability":{"enum":["known","absent","stale","unavailable","invalid"]},"source":{"type":"string"},"hypothetical":{"type":"boolean"}}}},
        "scopes":{"type":"array","items":{"type":"object","properties":{"id":{"type":"string"},"mode":{"enum":["active","report_only"]},"would_decision":{"type":"boolean"},"required_facts":{"type":"array","items":{"type":"string"}},"missing_required_evidence":{"type":"boolean"},"assurance_remedy":{"type":["string","null"]},"conditions":{"type":"array"}}}}
    }})
}

fn operation_parameters(operation: &Operation) -> Vec<Value> {
    let mut parameters: Vec<Value> = Vec::new();
    for placeholder in path_parameters(operation.path()) {
        parameters.push(json!({
            "name": placeholder,
            "in": "path",
            "required": true,
            "schema": { "type": "string" },
        }));
    }
    if crate::declarative::is_route(operation.id()) {
        if !matches!(
            operation.id(),
            "declarative.create" | "declarative.read" | "declarative.resolve"
        ) {
            parameters.push(json!({"name":"If-Match","in":"header","required":true,"schema":{"type":"string","pattern":"^\"[0-9a-f]{64}\"$"}}));
        }
        if operation.id() == "declarative.resolve" {
            parameters.push(json!({"name":"kind","in":"query","required":true,"schema":{"type":"string","enum":["tenant","application","resource","group","membership","policy"]}}));
            parameters.push(json!({"name":"external_key","in":"query","required":true,"schema":{"type":"string","minLength":1,"maxLength":512}}));
        }
    }
    if operation.id() == crate::POLICY_UPDATE_ID {
        parameters.push(json!({"name":"If-Match","in":"header","required":false,"schema":{"type":"string"},"description":"Quoted canonical sha256 revision from GET /policies. Required when adding, modifying or removing conditional scopes; use If-None-Match: * only for a first publication."}));
        parameters.push(json!({"name":"If-None-Match","in":"header","required":false,"schema":{"type":"string","const":"*"},"description":"Explicitly expects no existing policy. Mutually exclusive with If-Match."}));
    }
    if operation.is_paginated() {
        parameters.push(json!({ "$ref": "#/components/parameters/cursor" }));
        parameters.push(json!({ "$ref": "#/components/parameters/limit" }));
    }
    if matches!(
        operation.id(),
        crate::USERS_LIST_ID | crate::CLIENTS_LIST_ID
    ) {
        let orders = if operation.id() == crate::USERS_LIST_ID {
            json!(["username", "-username"])
        } else {
            json!(["id", "-id", "name", "-name"])
        };
        parameters.push(json!({
            "name": "sort", "in": "query", "required": false,
            "description": "Server order applied before pagination. Reuse the same search and order with each cursor.",
            "schema": { "type": "string", "enum": orders },
        }));
        parameters.push(json!({
            "name": "q", "in": "query", "required": false,
            "description": "Directory search applied before pagination.",
            "schema": { "type": "string" },
        }));
    }
    if is_audit_query(operation) {
        for (name, description) in crate::audit::PARAMETERS {
            parameters.push(json!({
                "name": name,
                "in": "query",
                "required": false,
                "description": description,
                "schema": { "type": "string", "maxLength": crate::audit::MAX_VALUE_LEN },
            }));
        }
    }
    if operation.id() == crate::GROUPS_LIST_ID {
        parameters.push(json!({
            "name": "q",
            "in": "query",
            "required": false,
            "description": "A literal case-insensitive substring of the machine or display name.",
            "schema": {"type": "string", "maxLength": asterius_domain::GroupMetadata::MAX_DISPLAY_BYTES},
        }));
    }
    if matches!(
        operation.id(),
        crate::SCIM_USERS_LIST_ID | crate::SCIM_GROUPS_LIST_ID
    ) {
        parameters.extend([
            json!({"name":"startIndex","in":"query","required":false,
                "description":"One-based index; at most 10001.",
                "schema":{"type":"integer","minimum":1,"maximum":10001,"default":1}}),
            json!({"name":"count","in":"query","required":false,
                "description":"Requested results; zero returns only totalResults.",
                "schema":{"type":"integer","minimum":0,"maximum":200,"default":100}}),
            json!({"name":"filter","in":"query","required":false,
                "description":"Only one equality filter is supported: userName for Users, displayName for Groups.",
                "schema":{"type":"string"}}),
        ]);
    }

    parameters
}

fn conditional_documentation(operation: &Operation, object: &mut Value) {
    if matches!(
        operation.id(),
        crate::CONDITIONAL_SETTINGS_READ_ID | crate::CONDITIONAL_SETTINGS_UPDATE_ID
    ) {
        object["responses"]["200"]["content"]["application/json"]["schema"] = json!({"type":"object","required":["sensitivity","revision"],"additionalProperties":false,"properties":{"sensitivity":{"enum":[null,"standard","sensitive","critical"]},"revision":{"type":["string","null"],"format":"uuid"}}});
        if operation.id() == crate::CONDITIONAL_SETTINGS_UPDATE_ID {
            object["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"required":["sensitivity","expected_revision"],"properties":{"sensitivity":{"enum":[null,"standard","sensitive","critical"]},"expected_revision":{"type":["string","null"],"format":"uuid"}},"description":"Administrative application classification. Both keys required; null revision expects no saved settings. Exact UUID CAS; stale updates are 409. This source is independent of dynamic client registration and PEP attributes."}}}});
            object["responses"]["409"] =
                error_response("The saved classification revision changed.");
        }
    }
    if operation.id() == crate::POLICY_UPDATE_ID {
        object["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
            "type":"object","additionalProperties":false,"required":["version","rules"],
            "properties":{
                "version":{"const":1},"rules":{"type":"array","maxItems":128,"items":{"type":"object"}},
                "conditional_scopes":{"type":"array","maxItems":64,"items":{
                    "type":"object","additionalProperties":false,"required":["mode","id","clients","actions","rules"],
                    "properties":{
                        "mode":{"enum":["active","report_only"]},"id":{"type":"string","minLength":1,"maxLength":128},
                        "clients":{"type":"array","minItems":1,"maxItems":64,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":256}},
                        "actions":{"type":"array","minItems":1,"maxItems":32,"uniqueItems":true,"items":{"enum":["authorize","authorization_code","refresh_token","device_code","ciba","token_exchange","client_credentials","jwt_bearer","access_evaluation"]}},
                        "required_facts":{"type":"array","maxItems":32,"uniqueItems":true,"items":{"enum":["assurance","authentication_age","application_sensitivity","network_zone","device_compliance","groups","roles","grants"]}},
                        "rules":{"type":"array","maxItems":128,"items":{"type":"object"}},
                        "assurance_remedy":{"type":["string","null"],"maxLength":256},
                        "network_zones":{"type":"object","maxProperties":64,"additionalProperties":{"type":"array","minItems":1,"maxItems":16,"uniqueItems":true,"items":{"type":"string","description":"Explicit IPv4 or IPv6 CIDR"}}}
                    }
                }}
            },
            "description":"64 KiB whole policy; at most 128 rules across base and conditional scopes. Conditional selectors reference registered clients and supported server enforcement actions, with no overlap. Every referenced trusted fact is mandatory before ANY/NOT. New predicates are closed and available only inside conditional scopes: application_sensitivity, network_zone, authentication_age_at_most (60..86400 seconds), device_compliance. Unknown/stale sources deny active scopes; report_only emits diagnostics. Named zones must be defined; assurance remedies must be configured attainable ACR levels. Never derives trusted facts from PEP properties."
        }}}});
        object["responses"]["409"] = error_response(
            "Policy revision changed, or conditional publication lacks an exact precondition.",
        );
    }
}

fn invitation_documentation(operation: &Operation, object: &mut Value) {
    match operation.id() {
        crate::INVITATIONS_CREATE_ID => {
            object["requestBody"] = json!({
                "required": true,
                "content": {"application/json": {"schema": {
                    "type": "object", "additionalProperties": false,
                    "required": ["invitations"],
                    "properties": {"invitations": {
                        "type": "array", "minItems": 1, "maxItems": 50,
                        "items": {"type": "object", "additionalProperties": false,
                            "required": ["email", "expires_at"],
                            "properties": {
                                "email": {"type": "string", "format": "email"},
                                "username": {"type": "string"},
                                "expires_at": {"type": "integer", "description": "Unix seconds; one minute to 24 hours from now"},
                                "role": {"type": "string", "enum": ["tenant_admin", "user_support", "security_auditor"]},
                                "group_ids": {"type": "array", "items": {"type": "string", "format": "uuid"}}
                            }
                        }
                    }}
                }}}
            });
        }
        crate::INVITATION_RESEND_ID => {
            object["requestBody"] = json!({
                "required": true,
                "content": {"application/json": {"schema": {
                    "type": "object", "additionalProperties": false,
                    "required": ["expires_at"],
                    "properties": {"expires_at": {"type": "integer", "description": "Unix seconds; one minute to 24 hours from now"}}
                }}}
            });
        }
        _ => {}
    }
}

fn client_resources_documentation(operation: &Operation, object: &mut Value) {
    if operation.id() != crate::CLIENT_RESOURCES_UPDATE_ID {
        return;
    }
    object["requestBody"] = json!({
        "required": true,
        "content": { "application/json": { "schema": {
            "type": "object",
            "additionalProperties": false,
            "required": ["resources"],
            "properties": {
                "resources": {
                    "type": "array",
                    "items": {"type": "string", "format": "uri"},
                    "description": "The exact RFC 8707 resource indicators this client may request. Every value must already be registered in this tenant; an empty array authorizes no resource."
                }
            }
        }}}
    });
}

fn kubernetes_documentation(operation: &Operation, object: &mut Value) {
    if operation.id() == crate::KUBERNETES_PROFILE_UPDATE_ID {
        object["requestBody"] = json!({"required": true, "content": {"application/json": {"schema": {
            "type": "object", "additionalProperties": false,
            "required": ["cluster_id", "namespace", "group_ids", "revision"],
            "properties": {
                "cluster_id": {"type": "string", "maxLength": 63, "pattern": "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"},
                "namespace": {"type": "string", "maxLength": 63, "pattern": "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"},
                "group_ids": {"type": "array", "maxItems": 100, "uniqueItems": true, "items": {"type": "string", "format": "uuid"}, "description": "Exact tenant-managed group allow-list; empty releases none"},
                "revision": {"type": "integer", "minimum": 0, "description": "Saved revision; zero creates a new profile"}
            }
        }}}});
    }
}

fn theme_documentation(operation: &Operation, object: &mut Value) {
    if operation.id() == crate::THEME_UPDATE_ID {
        object["requestBody"] = json!({
            "required": true,
            "content": {"application/json": {"schema": asterius_domain::Theme::schema_document()}},
        });
    }
    if operation.id() == crate::THEME_READ_ID {
        object["responses"]["200"]["content"]["application/json"]["schema"] = json!({
            "type": "object",
            "required": ["theme", "schema"],
            "properties": {
                "theme": asterius_domain::Theme::schema_document(),
                "schema": {"type": "object"}
            }
        });
    }
    if operation.id() == crate::THEME_LOGO_UPLOAD_ID {
        let upload = json!({
            "schema": {
                "type": "string",
                "format": "binary",
                "maxLength": crate::theme_image::MAX_UPLOAD_BYTES,
            }
        });
        object["requestBody"] = json!({
            "required": true,
            "description": "PNG, JPEG or WebP bytes. The server identifies the format from the bytes, bounds dimensions before decoding, and stores a metadata-free PNG.",
            "content": {
                "image/png": upload,
                "image/jpeg": upload,
                "image/webp": upload
            }
        });
    }
}

fn group_request_body(operation: &Operation) -> Option<Value> {
    if operation.id() == crate::GROUP_DELETE_ID {
        return Some(json!({
            "required": true,
            "content": {"application/json": {"schema": {
                "type": "object", "additionalProperties": false,
                "required": ["revision"],
                "properties": {"revision": {"type": "integer", "minimum": 1}},
            }}},
        }));
    }
    if !matches!(
        operation.id(),
        crate::GROUP_CREATE_ID | crate::GROUP_UPDATE_ID
    ) {
        return None;
    }
    let mut required = vec!["name", "display_name"];
    let mut properties = json!({
        "name": {"type": "string", "minLength": 1, "maxLength": asterius_domain::GroupName::MAX_LEN},
        "display_name": {"type": "string", "minLength": 1, "maxLength": asterius_domain::GroupMetadata::MAX_DISPLAY_BYTES},
    });
    if operation.id() == crate::GROUP_UPDATE_ID {
        required.push("revision");
        properties["revision"] = json!({"type": "integer", "minimum": 1});
    }
    Some(json!({
        "required": true,
        "content": {"application/json": {"schema": {
            "type": "object", "additionalProperties": false,
            "required": required, "properties": properties,
        }}},
    }))
}

fn rate_limits_schema() -> Value {
    let maximum = json!({"type": "integer", "minimum": 1, "maximum": u32::MAX});
    let mut properties = Map::new();
    properties.insert(
        "login".to_owned(),
        json!({
            "type": "object", "additionalProperties": false,
            "properties": {"per_address": maximum, "per_account": maximum}
        }),
    );
    for endpoint in asterius_domain::LimitedEndpoint::ALL {
        let mut buckets = json!({"per_address": maximum, "per_client": maximum});
        if endpoint.as_str() == "backchannel" {
            buckets["per_subject"] = maximum.clone();
        }
        properties.insert(
            endpoint.as_str().to_owned(),
            json!({
                "type": "object", "additionalProperties": false, "properties": buckets
            }),
        );
    }
    json!({"type": "object", "additionalProperties": false, "properties": properties,
        "description": "Overrides may only lower enabled deployment maxima. Omission preserves stored overrides; an empty object resets inheritance. Windows stay deployment-owned. GET also exposes rate_limit_bounds and effective_rate_limits, mapping the same groups/buckets to max and window_seconds. Shared counters retain existing concurrent check/charge semantics."})
}

fn session_policy_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["idle_seconds", "absolute_seconds"],
        "properties": {
            "idle_seconds": {"type": "integer", "minimum": 60, "maximum": 43200, "default": 3600},
            "absolute_seconds": {"type": "integer", "minimum": 60, "maximum": 43200, "default": 43200}
        },
        "description": "Idle must not exceed absolute. Omission preserves policy. Current policy constrains existing sessions; browser activity renews only idle time and never extends issuance absolute expiry. Session lookup reads committed policy on every replica."
    })
}

/// The bounded, attainable authentication ladder persisted for a tenant.
fn acr_policy_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false, "required": ["levels"],
        "properties": {
            "amr_in_id_token": {"type": "boolean", "default": true},
            "levels": {"type": "array", "maxItems": 32, "items": {
                "type": "object", "additionalProperties": false, "required": ["value", "amr"],
                "properties": {
                    "value": {"type": "string", "minLength": 1, "maxLength": 255, "pattern": "^[!-~]+$"},
                    "amr": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string", "enum": ["pwd", "swk", "user"]}}
                }
            }}
        },
        "description": "Weakest first; names must be unique. User verification requires a passkey. Reserved passkey contexts cannot be weakened; hardware-protected contexts are unavailable. Empty levels disable ACR assertions, not administrator passkey requirements."
    })
}

/// The two reads of the trail take the same filters (`ast-lh3.9`).
fn is_audit_query(operation: &Operation) -> bool {
    matches!(
        operation.id(),
        crate::AUDIT_EVENTS_LIST_ID | crate::AUDIT_EVENTS_EXPORT_ID
    )
}

fn idempotency_parameter() -> Value {
    json!({
        "name": "Idempotency-Key",
        "in": "header",
        "required": true,
        "description":
            "A caller-chosen key, unique per creation. A repeat is refused \
             with 409 rather than executed a second time.",
        "schema": {
            "type": "string",
            "minLength": crate::idempotency::MIN_LEN,
            "maxLength": crate::idempotency::MAX_LEN,
        },
    })
}

fn policy_trial_schema() -> Value {
    let condition = json!({
        "type": "object",
        "required": ["path", "kind", "matched", "missing"],
        "properties": {
            "path": {"type": "string"}, "kind": {"type": "string"},
            "matched": {"type": "boolean"}, "missing": {"type": "boolean"}
        }
    });
    let rule = json!({
        "type": "object",
        "required": ["id", "effect", "applicable", "matched", "conditions"],
        "properties": {
            "id": {"type": "string", "maxLength": 256},
            "effect": {"type": "string", "enum": ["permit", "deny"]},
            "applicable": {"type": "boolean"}, "matched": {"type": "boolean"},
            "conditions": {"type": "array", "maxItems": 256, "items": condition}
        }
    });
    let diagnostics = json!({
        "type": "object",
        "description": "Tenant-authorized administrator trace only; absent from public AuthZEN responses. No input values or policy literals. At most 128 rules and 256 condition nodes across all rules; truncated marks omitted nodes. policy_revision is a SHA-256 digest of the exact canonical document; policy_updated_at is Unix nanoseconds as a decimal string. enforcement_point identifies the administrative trial. No trace is retained.",
        "required": ["policy_revision", "policy_updated_at", "enforcement_point", "rules", "truncated"],
        "properties": {
            "policy_revision": {"type": ["string", "null"]},
            "policy_updated_at": {"type": ["string", "null"]},
            "enforcement_point": {"type": "string"}, "truncated": {"type": "boolean"},
            "rules": {"type": "array", "maxItems": 128, "items": rule}
        }
    });
    json!({
        "type": "object", "required": ["decision"],
        "properties": {
            "decision": {"type": "boolean"}, "context": {"type": "object"},
            "diagnostics": diagnostics
        }
    })
}

fn audit_detail_schema() -> Value {
    let mut snapshot = policy_trial_schema()["properties"]["diagnostics"].clone();
    snapshot["description"] = json!(
        "Redacted bounded boolean evidence of the actual evaluated policy; cached issuance retains its original revision. Expires independently after seven days. No tokens, context input values or policy literals."
    );
    json!({
        "type": "object", "required": ["id", "hash", "diagnostic"],
        "properties": {
            "id": {"type": "integer", "minimum": 1}, "hash": {"type": "string"},
            "request_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
            "session_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "grant_id": {"type": "string", "format": "uuid"},
            "diagnostic": {
                "type": "object", "required": ["status"],
                "properties": {
                    "status": {"type": "string", "enum": ["recorded", "expired", "unavailable", "not_recorded", "opaque"]},
                    "expires_at": {"type": "string", "format": "date-time"}, "snapshot": snapshot,
                    "reason": {"type": "string", "enum": ["integrity_mismatch"]}
                },
                "description": "Snapshot and expires_at are present only for recorded evidence. Other statuses explain missing evidence; no current-policy reconstruction."
            }
        }
    })
}

fn responses(operation: &Operation) -> Value {
    if operation.id() == crate::SCIM_BULK_ID {
        return json!({
            "401": error_response("Provisioning authentication is required."),
            "403": error_response("The token lacks admin.scim:write."),
            "429": error_response("A rate limit was reached."),
            "501": {"description": "SCIM Bulk is unsupported.",
                "content": {"application/scim+json": {"schema": {"type": "object"}}}},
        });
    }
    // A `POST` that creates answers 201; a probe answers 200, because it
    // created nothing and has no `Location` to give (`ast-f7m.9`).
    let success = if operation.id() != crate::INVITATION_RESEND_ID
        && operation.method() == crate::operations::Method::Post
        && operation.effect() == Effect::Mutates
    {
        "201"
    } else {
        "200"
    };

    let content = if operation.is_paginated() {
        json!({
            "application/json": { "schema": { "$ref": "#/components/schemas/Page" } }
        })
    } else if operation.id() == crate::AUDIT_EVENTS_EXPORT_ID {
        json!({
            crate::audit::NDJSON: {
                "schema": {
                    "type": "string",
                    "description": format!(
                        "One JSON object per line, newest first, at most {} lines.",
                        asterius_domain::audit::query::EXPORT_MAX_RECORDS
                    ),
                }
            }
        })
    } else if operation.id() == crate::POLICY_TRY_ID {
        json!({"application/json": {"schema": policy_trial_schema()}})
    } else if operation.id() == crate::AUDIT_EVENT_READ_ID {
        json!({"application/json": {"schema": audit_detail_schema()}})
    } else {
        json!({ "application/json": { "schema": { "type": "object" } } })
    };

    let mut answers = json!({
        success: { "description": "The operation succeeded.", "content": content },
        "401": error_response("No credential, or one that no longer resolves."),
        "403": error_response(
            "Authenticated, without the declared authority — or, for the \
             console, without this session's X-CSRF-Token.",
        ),
        "429": error_response("A rate limit was reached. Retry-After says when."),
        "503": error_response("Something below the API failed."),
    });

    if let Some(fields) = answers.as_object_mut()
        && operation.effect() == Effect::Mutates
    {
        fields.insert(
            "409".to_owned(),
            error_response(
                "The request conflicts with the current state, or its \
                 Idempotency-Key has already been used.",
            ),
        );
    }
    if let Some(fields) = answers.as_object_mut()
        && matches!(
            operation.id(),
            crate::GROUPS_LIST_ID
                | crate::GROUP_CREATE_ID
                | crate::GROUP_READ_ID
                | crate::GROUP_UPDATE_ID
                | crate::GROUP_DELETE_ID
                | crate::GROUP_MEMBERS_LIST_ID
                | crate::GROUP_MEMBER_ADD_ID
                | crate::GROUP_MEMBER_REMOVE_ID
                | crate::USER_GROUPS_LIST_ID
        )
    {
        fields.insert(
            "400".to_owned(),
            error_response("The metadata, revision, limit or cursor is invalid."),
        );
        fields.insert(
            "404".to_owned(),
            error_response("The group or user does not exist in the routed tenant."),
        );
    }

    if operation.id() == crate::AUDIT_EVENT_READ_ID {
        answers["404"] = error_response(
            "The event does not exist in the routed tenant; evidence is looked up only after this check.",
        );
        answers[success]["headers"] = json!({"X-Asterius-Request-ID": {"description": "Fresh server-generated support reference, independent of any caller AuthZEN echo.", "schema": {"type": "string", "pattern": "^[0-9a-f]{32}$"}}});
    }
    answers
}

fn error_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": { "schema": { "$ref": "#/components/schemas/Error" } }
        },
    })
}

fn error_schema() -> Value {
    json!({
        "type": "object",
        "required": ["error"],
        "properties": {
            "error": {
                "type": "object",
                "required": ["code", "message"],
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "A closed vocabulary a client may switch on.",
                    },
                    "message": {
                        "type": "string",
                        "description":
                            "For a person reading a log. Never carries a \
                             credential or a session identifier.",
                    },
                },
            },
        },
    })
}

fn page_schema() -> Value {
    json!({
        "type": "object",
        "required": ["items", "next_cursor"],
        "properties": {
            "items": { "type": "array", "items": { "type": "object" } },
            "next_cursor": {
                "type": ["string", "null"],
                "description":
                    "Pass back as `cursor` for the next page. Null on the \
                     last page; always present, so a client may loop on it.",
            },
        },
    })
}

const fn reach_name(reach: Reach) -> &'static str {
    match reach {
        Reach::Tenant => "tenant",
        Reach::AutomationTenant => "automation_tenant",
        Reach::Deployment => "deployment",
        Reach::Authenticated => "authenticated",
    }
}

/// The `{name}` placeholders in an axum path, in order.
fn path_parameters(path: &str) -> Vec<&str> {
    path.split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .collect()
}

fn declarative_documentation(operation: &Operation, object: &mut Value) {
    if !crate::declarative::is_route(operation.id()) {
        return;
    }
    object["security"] = json!([{"adminToken":[]}]);
    object["x-service-only"] = json!(true);
    object["x-kind-scopes"] = json!({
        "tenant":["admin.tenants:read","admin.tenants:write"],
        "application":["admin.clients:read","admin.clients:write"],
        "resource":["admin.resource_servers:read","admin.resource_servers:write"],
        "group":["admin.groups:read","admin.groups:write"],
        "membership":["admin.memberships:read","admin.memberships:write"],
        "policy":["admin.policies:read","admin.policies:write"]
    });
    object["description"] = json!(
        "Requires admin.session:read plus the addressed kind's read scope; mutation additionally requires kind write scope. Tenant create requires deployment reach. Ownership comes only from verified issuer/client credentials. The import ID is unpadded base64url of [tenant,kind,identity], or [tenant,membership,groupUUID,userUUID]. If-Match uses the exact strong 64-hex ETag. POST create retries use durable external_key, not Idempotency-Key. Plan/read/import never return credentials."
    );
    for (status, code) in [
        (
            "409",
            "owner_conflict / delete_protected / logical_key_conflict / dependency_conflict",
        ),
        ("412", "revision_conflict"),
        ("428", "precondition_required"),
    ] {
        object["responses"][status] = json!({"description":code,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Error"}}}});
    }
    if matches!(
        operation.id(),
        "declarative.create" | "declarative.replace" | "declarative.plan"
    ) {
        let mut properties = json!({"spec":{"type":"object","description":"Kind-specific domain-validated desired document; maximum shared request body limit is 64 KiB. Application fields are public FAPI registration metadata plus resources; generated client secrets and private JWK material are rejected. Tenant fields: tenant_id, issuer, display_name, default_resource, custom_host, options."}});
        let required = if operation.id() == "declarative.create" {
            properties["kind"] = json!({"type":"string","enum":["tenant","application","resource","group","membership","policy"]});
            properties["external_key"] = json!({"type":"string","minLength":1,"maxLength":512});
            json!(["kind", "external_key", "spec"])
        } else {
            json!(["spec"])
        };
        if operation.id() != "declarative.plan" {
            properties["deletion_protection"] = json!({"type":"boolean","default":true});
        }
        object["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"required":required,"properties":properties}}}});
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate. A document maintained beside the code is a document that is
    /// wrong from the first route somebody adds, and an *admin* API's
    /// description being wrong is a security control nobody can audit.
    #[test]
    fn the_checked_in_document_is_current() {
        // Arrange
        const CHECKED_IN: &str = include_str!("../../../docs/admin-api-openapi.json");

        // Act
        let generated = document();

        // Assert
        assert_eq!(
            CHECKED_IN, generated,
            "docs/admin-api-openapi.json is stale. Regenerate it:\n    {REGENERATE_COMMAND}"
        );
    }

    #[test]
    fn the_document_declares_openapi_3_1() {
        assert_eq!(value()["openapi"], json!("3.1.0"));
    }

    /// The contract test that matters: every route the router serves appears
    /// in the document, under its own verb, with its declared authority.
    #[test]
    fn every_registered_operation_appears_with_its_declared_authority() {
        // Arrange
        let document = value();

        // Act / Assert
        for operation in crate::registry() {
            let item =
                &document["paths"][operation.full_path()][operation.method().as_openapi_key()];
            assert!(
                !item.is_null(),
                "{} {} is missing from the document",
                operation.method().as_str(),
                operation.full_path()
            );
            assert_eq!(item["operationId"], json!(operation.id()));
            assert_eq!(
                item["x-asterius-reach"],
                json!(reach_name(operation.authority().reach())),
                "{} documents an authority the router does not apply",
                operation.id()
            );
            assert_eq!(
                item["x-asterius-scope"],
                json!(operation.authority().scope())
            );
        }
    }

    /// The other direction: nothing is documented that is not served. A
    /// document naming an endpoint that does not exist is `ast-iko` again.
    #[test]
    fn nothing_is_documented_that_the_registry_does_not_serve() {
        // Arrange
        let document = value();
        let served: std::collections::BTreeSet<_> = crate::registry()
            .iter()
            .map(|operation| {
                (
                    operation.full_path(),
                    operation.method().as_openapi_key().to_owned(),
                )
            })
            .collect();

        // Act / Assert
        let paths = document["paths"].as_object().expect("a paths object");
        for (path, item) in paths {
            for verb in item.as_object().expect("a path item").keys() {
                assert!(
                    served.contains(&(path.clone(), verb.clone())),
                    "{verb} {path} is documented and not served"
                );
            }
        }
    }

    #[test]
    fn every_operation_documents_the_two_refusals_the_rbac_test_asserts() {
        // Arrange
        let document = value();

        // Act / Assert
        for operation in crate::registry() {
            let item =
                &document["paths"][operation.full_path()][operation.method().as_openapi_key()];
            for status in ["401", "403"] {
                assert!(
                    !item["responses"][status].is_null(),
                    "{} does not document {status}",
                    operation.id()
                );
            }
        }
    }

    #[test]
    fn a_paginated_read_documents_its_cursor_and_limit() {
        // Arrange
        let document = value();
        let paginated = crate::registry()
            .iter()
            .find(|operation| operation.is_paginated())
            .expect("the registry has at least one paginated read");

        // Act
        let parameters = document["paths"][paginated.full_path()]
            [paginated.method().as_openapi_key()]["parameters"]
            .clone();

        // Assert
        let rendered = parameters.to_string();
        assert!(rendered.contains("parameters/cursor"), "{rendered}");
        assert!(rendered.contains("parameters/limit"), "{rendered}");
    }

    #[test]
    fn a_post_documents_a_required_idempotency_key() {
        // Arrange
        let document = value();
        let creation = crate::registry()
            .iter()
            .find(|operation| operation.needs_idempotency_key())
            .expect("the registry has at least one POST");

        // Act
        let parameters = document["paths"][creation.full_path()]
            [creation.method().as_openapi_key()]["parameters"]
            .to_string();

        // Assert
        assert!(parameters.contains("Idempotency-Key"), "{parameters}");
    }

    /// ADR-0009: no OAuth token reaches the browser, so the console's scheme
    /// is a cookie and never an `Authorization` header.
    #[test]
    fn the_console_scheme_is_a_cookie_and_the_token_scheme_is_dpop() {
        // Arrange
        let schemes = &value()["components"]["securitySchemes"];

        // Act / Assert
        assert_eq!(schemes["consoleSession"]["in"], json!("cookie"));
        assert_eq!(
            schemes["consoleSession"]["name"],
            json!(asterius_domain::entities::session::COOKIE_NAME)
        );
        assert_eq!(schemes["adminToken"]["scheme"], json!("DPoP"));
    }

    #[test]
    fn path_placeholders_become_required_path_parameters() {
        assert_eq!(path_parameters("/tenants/{id}/keys"), ["id"]);
        assert!(path_parameters("/tenants").is_empty());
    }
}

fn temporary_entitlement_documentation(operation: &Operation, object: &mut Value) {
    if !operation.id().starts_with("temporary_entitlements.") {
        return;
    }
    object["security"] = json!([{"consoleSession":[]}]);
    object["description"] = json!(
        "Console-only, exact resource owner server user. Existing admin.app_roles scope remains mandatory. Posted editor/actor/authentication evidence is refused. Configuration binding is immutable; UUID CAS revisions invalidate old requests and activations. Timestamps are authoritative Unix seconds. Ordinary account request/approval routes use their own session and CSRF token, never these admin credentials."
    );
    object["responses"]["409"] =
        error_response("Configuration/eligibility CAS or immutable idempotency payload conflicts.");
    let mut schema = json!({"type":"object","additionalProperties":false});
    match operation.id() {
        crate::TEMPORARY_ENTITLEMENT_CREATE_ID | crate::TEMPORARY_ENTITLEMENT_UPDATE_ID => {
            schema["properties"] = json!({
                "owner_user_id":{"type":"string","format":"uuid","description":"Must equal verified Console user; binding immutable."},
                "client_id":{"type":"string","minLength":1,"maxLength":2048},"resource":{"type":"string","format":"uri"},"role_name":{"type":"string","minLength":1,"maxLength":64},
                "permissions":{"type":"array","minItems":1,"maxItems":64,"uniqueItems":true,"items":{"type":"string"}},
                "approver_user_ids":{"type":"array","minItems":1,"maxItems":16,"uniqueItems":true,"items":{"type":"string","format":"uuid"}},
                "requester_acr":{"type":"string","minLength":1,"maxLength":256},"approver_acr":{"type":"string","minLength":1,"maxLength":256},
                "max_duration_seconds":{"type":"integer","minimum":1,"maximum":3600,"default":900},"max_eligibility_seconds":{"type":"integer","minimum":1,"maximum":2592000,"default":86400},"enabled":{"type":"boolean"}
            });
            schema["required"] = json!([
                "owner_user_id",
                "client_id",
                "resource",
                "role_name",
                "permissions",
                "approver_user_ids",
                "requester_acr",
                "approver_acr",
                "max_duration_seconds",
                "max_eligibility_seconds",
                "enabled"
            ]);
            if operation.id() == crate::TEMPORARY_ENTITLEMENT_UPDATE_ID {
                schema["properties"]["expected_revision"] =
                    json!({"type":"string","format":"uuid"});
                schema["required"]
                    .as_array_mut()
                    .expect("required is the array constructed above")
                    .push(json!("expected_revision"));
            }
        }
        crate::TEMPORARY_ENTITLEMENT_ELIGIBILITY_SET_ID => {
            schema["properties"] = json!({"user_id":{"type":"string","format":"uuid"},"not_before":{"type":"integer"},"expires_at":{"type":"integer"},"expected_revision":{"type":["string","null"],"format":"uuid"}});
            schema["required"] =
                json!(["user_id", "not_before", "expires_at", "expected_revision"]);
        }
        crate::TEMPORARY_ENTITLEMENT_ELIGIBILITY_REMOVE_ID => {
            schema["properties"] = json!({"expected_revision":{"type":"string","format":"uuid"}});
            schema["required"] = json!(["expected_revision"]);
        }
        crate::TEMPORARY_ENTITLEMENT_REVOKE_ID => {
            schema["properties"] = json!({"activation_id":{"type":"string","format":"uuid","description":"Must equal addressed activation."},"reason":{"type":"string","minLength":1,"maxLength":1024,"description":"UTF-8 byte bound; control characters refused."},"idempotency_key":{"type":"string","format":"uuid","description":"Authoritative lifecycle replay key, atomically bound to actor/operation/exact payload and original response. Generic admin header is validated, never consumed before this transaction."}});
            schema["required"] = json!(["activation_id", "reason", "idempotency_key"]);
        }
        _ => return,
    }
    object["requestBody"] =
        json!({"required":true,"content":{"application/json":{"schema":schema}}});
}
