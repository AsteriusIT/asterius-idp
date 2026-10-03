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
                "OutboundScimConnector": outbound_scim_connector_schema(),
                "OutboundScimCredential": outbound_scim_credential_schema(),
                "OutboundScimAssignment": outbound_scim_assignment_schema(),
                "OutboundScimLifecycleReceipt": outbound_scim_lifecycle_receipt_schema(),
                "OutboundScimAssignmentPreview": outbound_scim_assignment_preview_schema(),
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
    outbound_scim_documentation(operation, &mut object);
    governance_documentation(operation, &mut object);
    declarative_documentation(operation, &mut object);
    client_resources_documentation(operation, &mut object);
    kubernetes_documentation(operation, &mut object);
    conditional_documentation(operation, &mut object);
    temporary_entitlement_documentation(operation, &mut object);
    temporary_kubernetes_documentation(operation, &mut object);
    kubernetes_online_documentation(operation, &mut object);
    managed_device_documentation(operation, &mut object);
    invitation_documentation(operation, &mut object);
    agent_task_documentation(operation, &mut object);
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
    if matches!(
        operation.id(),
        "governance.ownership.list"
            | "governance.review.list"
            | "governance.review.items"
            | "governance.reviewers"
    ) {
        parameters.push(json!({"name":"after","in":"query","required":false,"schema":{"type":"string","format":"uuid"},"description":"Exact last row UUID from the previous page; rows are ordered by UUID within this tenant."}));
        parameters.push(json!({"name":"limit","in":"query","required":false,"schema":{"type":"integer","minimum":1,"maximum":100,"default":50},"description":"Rows per page; values outside one to one hundred are refused."}));
    }

    outbound_scim_parameters(operation, &mut parameters);
    task_view_parameters(operation, &mut parameters);
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

fn outbound_scim_parameters(operation: &Operation, parameters: &mut Vec<Value>) {
    if operation.id().starts_with("outbound_scim.") {
        for parameter in parameters.iter_mut() {
            parameter["schema"] = outbound_scim_uuid_schema();
            parameter["schema"]["pattern"] =
                json!("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
        }
        if matches!(
            operation.id(),
            "outbound_scim.list" | "outbound_scim.assignments" | "outbound_scim.reconcile"
        ) {
            parameters.push(json!({"name":"after","in":"query","required":false,"schema":outbound_scim_uuid_schema(),"description":"UUID keyset cursor: use the exact last returned row UUID, or the reconcile response after UUID."}));
        }
        if matches!(
            operation.id(),
            "outbound_scim.list" | "outbound_scim.assignments"
        ) {
            parameters.push(json!({"name":"limit","in":"query","required":false,"schema":{"type":"integer","minimum":1,"maximum":100,"default":50},"description":"Values outside 1..100 are refused. No opaque cursor or offset is accepted."}));
        }
    }
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

fn task_ceiling_schema() -> Value {
    json!({"type":"object","additionalProperties":false,
        "required":["scopes","resources","actions","resource_ceilings","max_delegation_depth"],
        "properties":{
            "scopes":{"type":"array","maxItems":64,"uniqueItems":true,"items":{"type":"string"}},
            "resources":{"type":"array","maxItems":64,"uniqueItems":true,"items":{"type":"string","format":"uri"}},
            "actions":{"type":"array","maxItems":32,"items":{"type":"object","additionalProperties":false,"required":["resource","actions"],"properties":{"resource":{"type":"string","format":"uri"},"actions":{"type":"array","uniqueItems":true,"items":{"type":"string"}}}}},
            "resource_ceilings":{"type":"array","maxItems":64,"items":{"type":"object","additionalProperties":false,"required":["resource","scopes","maximum_token_ttl_seconds"],"properties":{"resource":{"type":"string","format":"uri"},"scopes":{"type":"array","maxItems":64,"uniqueItems":true,"items":{"type":"string"}},"maximum_token_ttl_seconds":{"type":"integer","minimum":0,"maximum":300}}}},
            "max_delegation_depth":{"type":"integer","minimum":1,"maximum":8}
        },"description":"A ceiling, never a request-specific authorization. Resource-specific scope/TTL bounds apply separately; unknown, expired or withdrawn authority yields empty permissions."})
}

fn agent_task_documentation(operation: &Operation, object: &mut Value) {
    if !matches!(
        operation.id(),
        crate::AGENT_TASKS_LIST_ID | crate::AGENT_TASK_READ_ID
    ) {
        return;
    }
    let task = json!({"type":"object","additionalProperties":false,
    "required":["task_id","root_grant_id","owner_user_id","initiating_client_id","approval_revision","label","approved_at","expires_at","revoked_at","state"],
    "properties":{
        "task_id":{"type":"string","format":"uuid"},"root_grant_id":{"type":"string","format":"uuid"},"owner_user_id":{"type":"string","format":"uuid"},
        "initiating_client_id":{"type":"string"},"approval_revision":{"type":"integer","minimum":1},"label":{"type":"string"},
        "approved_at":{"type":"string","format":"date-time"},"expires_at":{"type":"string","format":"date-time"},"revoked_at":{"type":["string","null"],"format":"date-time"},
        "state":{"type":"string","enum":["active","expired","withdrawn","principal_unavailable","ancestor_unavailable"]}
    }});
    let schema = if operation.id() == crate::AGENT_TASKS_LIST_ID {
        json!({"type":"object","additionalProperties":false,"required":["items","next_cursor","observed_at"],"properties":{
            "items":{"type":"array","maxItems":50,"items":task},"next_cursor":{"type":["string","null"],"format":"uuid"},"observed_at":{"type":"string","format":"date-time"}}})
    } else {
        json!({"type":"object","additionalProperties":false,"required":["task","approved_ceiling","current_issuance_ceiling","current_grant_types","maximum_new_token_ttl_seconds","observed_at","lineage","next_cursor","conditional_decision"],"properties":{
        "task":task,"approved_ceiling":task_ceiling_schema(),"current_issuance_ceiling":task_ceiling_schema(),
        "current_grant_types":{"type":"array","items":{"type":"string"}},"maximum_new_token_ttl_seconds":{"type":"integer","minimum":0,"maximum":300},
        "observed_at":{"type":"string","format":"date-time"},"next_cursor":{"type":["string","null"],"format":"uuid"},
        "conditional_decision":{"const":"not_evaluated"},"lineage":{"type":"array","maxItems":50,"items":{
            "type":"object","additionalProperties":false,
            "required":["grant_id","parent_grant_id","client_id","depth","ancestry","expires_at","revoked_at","state","recorded_ceiling","current_issuance_ceiling"],
            "properties":{
                "grant_id":{"type":"string","format":"uuid"},"parent_grant_id":{"type":["string","null"],"format":"uuid"},
                "client_id":{"type":"string"},"depth":{"type":"integer","minimum":0,"maximum":9},
                "ancestry":{"type":"array","maxItems":10,"items":{"type":"string","format":"uuid"}},
                "expires_at":{"type":["string","null"],"format":"date-time"},"revoked_at":{"type":["string","null"],"format":"date-time"},
                "state":{"type":"string","enum":["active","expired","withdrawn","principal_unavailable","ancestor_unavailable"]},
                "recorded_ceiling":task_ceiling_schema(),"current_issuance_ceiling":task_ceiling_schema()
            }
        }}}})
    };
    object["responses"]["200"]["content"]["application/json"]["schema"] = schema;
    object["description"] = json!(
        "Tenant-local public identifiers only, no user names, emails, raw credentials or private JTIs. No-store current read-only snapshot independent of recorded audit. Withdrawal uses the existing owner-bound grant endpoint and admin.grants:write, with offline signed-expiry limits."
    );
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
        Reach::ConsoleTenant => "console_tenant",
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

fn outbound_scim_uuid_schema() -> Value {
    json!({"type":"string","format":"uuid","not":{"const":"00000000-0000-0000-0000-000000000000"}})
}
fn outbound_scim_optional_uuid_schema() -> Value {
    json!({"oneOf":[outbound_scim_uuid_schema(),{"type":"null"}]})
}
fn outbound_scim_optional_etag_schema() -> Value {
    json!({"oneOf":[{"type":"string","maxLength":128,"pattern":"^W/\"[1-9][0-9]*\"$","description":"Saved weak target ETag; bounded positive i64 revision, never wildcard."},{"type":"null"}]})
}
fn outbound_scim_failure_schema() -> Value {
    json!({"enum":[null,"paused","credential_unavailable","credential_binding_mismatch","authentication_refused","target_unavailable","ownership_mismatch","target_absent","target_version_changed","source_protected","source_projection_invalid","user_dependencies_pending","snapshot_bound_exceeded","lease_superseded"]})
}
fn outbound_scim_credential_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["reference","generation","target_issuer","target_client"],"properties":{
        "reference":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"},"generation":outbound_scim_uuid_schema(),
        "target_issuer":{"type":"string","format":"uri","maxLength":2048,"description":"Canonical HTTPS issuer of the distinct, operator-approved target tenant."},
        "target_client":{"type":"string","minLength":1,"maxLength":2048}
    },"description":"SOURCE-tenant-filtered deployment descriptor only. Contains no private key, file path, assertion, access token or DPoP secret."})
}
fn outbound_scim_connector_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["id","revision","target_issuer","target_client","credential_ref","credential_generation","enabled","allow_reviewed_delete"],"properties":{
        "id":outbound_scim_uuid_schema(),"revision":outbound_scim_uuid_schema(),
        "target_issuer":{"type":"string","format":"uri","maxLength":2048},"target_client":{"type":"string","minLength":1,"maxLength":2048},
        "credential_ref":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"},"credential_generation":outbound_scim_uuid_schema(),
        "enabled":{"type":"boolean"},"allow_reviewed_delete":{"type":"boolean"}
    },"description":"Current configuration revision; target issuer/client stay pinned while any assignment history exists. Credential reference authority depends on the complete source/destination context."})
}
fn outbound_scim_assignment_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["id","kind","source","generation","selected","target","observed_etag","retired","state","failure_code","dirty"],"properties":{
        "id":outbound_scim_uuid_schema(),"kind":{"enum":["user","group"]},"source":outbound_scim_uuid_schema(),"generation":outbound_scim_uuid_schema(),
        "selected":{"type":"boolean"},"target":outbound_scim_optional_uuid_schema(),"observed_etag":outbound_scim_optional_etag_schema(),"retired":{"type":"boolean"},
        "state":{"enum":["pending","waiting_dependencies","applied","paused","conflict","dead_letter","deleted"]},"failure_code":outbound_scim_failure_schema(),"dirty":{"type":"boolean"}
    },"description":"Public IDs and fixed diagnostics only; no personal-data snapshot, signing material or raw peer error. Unselection retains mapping authority until explicitly verified archival."})
}
fn outbound_scim_lifecycle_receipt_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["id","kind","completed","replacement","failure_code","cancelled"],"properties":{
        "id":outbound_scim_uuid_schema(),"kind":{"enum":["archive","delete","recreate"]},"completed":{"type":"boolean"},"replacement":outbound_scim_optional_uuid_schema(),
        "failure_code":outbound_scim_failure_schema(),"cancelled":{"type":"boolean"}
    },"description":"Durable explicit approval result. Completed retries are no-ops; replacement is the fresh local assignment UUID, not permission to adopt another remote UUID."})
}
fn outbound_scim_assignment_preview_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["assignment","generation","desired_revision","action","target","target_version"],"properties":{
        "assignment":outbound_scim_uuid_schema(),"generation":outbound_scim_uuid_schema(),"desired_revision":outbound_scim_uuid_schema(),
        "action":{"enum":["recover_deprovision","unchanged_absent","create","unchanged","disable","empty_group","update"]},
        "target":outbound_scim_optional_uuid_schema(),"target_version":outbound_scim_optional_etag_schema()
    },"description":"Observed ownership/drift from authenticated GET only. This response never establishes a mapping, mutates a target, or authorizes a future write."})
}
fn outbound_scim_page_schema(name: &str, bound: usize) -> Value {
    json!({"type":"object","additionalProperties":false,"required":["items"],"properties":{"items":{"type":"array","maxItems":bound,"items":{"$ref":format!("#/components/schemas/{name}")}}}})
}
fn outbound_scim_documentation(operation: &Operation, object: &mut Value) {
    if !operation.id().starts_with("outbound_scim.") {
        return;
    }
    object["security"] = json!([{"consoleSession":[]}]);
    object["x-console-only"] = json!(true);
    object["x-fresh-phishing-resistant-write"] =
        json!(operation.authority().scope().ends_with(":write"));
    object["x-candidate-contract-review"] = json!(
        "ast-dd1y.6.2 Proposed; delivery/shared enablement awaits review and real first-target acceptance"
    );
    object["description"] = json!(
        "Same-realm human administration only; tokens and foreign reserved administrators cannot act for this tenant. Writes require current active tenant administrator, fresh console proof, CSRF and declared scope. Only configured SOURCE-tenant-bound deployment credentials can be selected. No posted actor, private key, filesystem path, token or personal-data snapshot is accepted. Pausing fences subsequent admissions but cannot cancel a remote request already dispatched. Target mappings require immutable ownership and version checks; missing mapped UUIDs do not authorize automatic recreation."
    );
    let revision = json!({"type":"object","additionalProperties":false,"required":["expected_revision"],"properties":{"expected_revision":outbound_scim_uuid_schema()}});
    let request = match operation.id() {
        "outbound_scim.create" | "outbound_scim.configure" => {
            let creating = operation.id() == "outbound_scim.create";
            let mut required = vec![
                "target_issuer",
                "target_client",
                "credential_ref",
                "credential_generation",
                "enabled",
                "allow_reviewed_delete",
            ];
            if !creating {
                required.push("expected_revision");
            }
            Some(
                json!({"type":"object","additionalProperties":false,"required":required,"properties":{
                "expected_revision":if creating{json!({"type":"null"})}else{outbound_scim_uuid_schema()},
                "target_issuer":{"type":"string","format":"uri","maxLength":2048,"description":"Canonical, operator-approved distinct HTTPS issuer; no userinfo/query/fragment/IP/localhost/redirect aliases."},
                "target_client":{"type":"string","minLength":1,"maxLength":2048},"credential_ref":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"},
                "credential_generation":outbound_scim_uuid_schema(),"enabled":if creating{json!({"const":false})}else{json!({"type":"boolean"})},"allow_reviewed_delete":{"type":"boolean"}
            },"description":"Create mints its UUID server-side and starts disabled; max100 live connectors per source tenant. Enable requires exact authenticated preview within five minutes. Credential rotation needs pause/configure/preview/enable. Target principal remains pinned by retained history."}),
            )
        }
        "outbound_scim.select" => Some(
            json!({"type":"object","additionalProperties":false,"required":["expected_revision","kind","sources"],"properties":{"expected_revision":outbound_scim_uuid_schema(),"kind":{"enum":["user","group"]},"sources":{"type":"array","minItems":1,"maxItems":100,"uniqueItems":true,"items":outbound_scim_uuid_schema()}},"description":"Select explicit current local sources; inbound SCIM ownership is refused. Max100 non-retired assignments per kind, including quiescing assignments. Group direct active selected User projection is separately bounded to100 members."}),
        ),
        "outbound_scim.lifecycle" => Some(
            json!({"type":"object","additionalProperties":false,"required":["expected_revision","expected_generation","kind","target","etag","confirmed"],"properties":{"expected_revision":outbound_scim_uuid_schema(),"expected_generation":outbound_scim_uuid_schema(),"kind":{"enum":["archive","delete","recreate"]},"target":outbound_scim_optional_uuid_schema(),"etag":outbound_scim_optional_etag_schema(),"confirmed":{"const":true}},"allOf":[{"if":{"properties":{"kind":{"const":"delete"}}},"then":{"properties":{"target":outbound_scim_uuid_schema(),"etag":{"type":"string","maxLength":128,"pattern":"^W/\"[1-9][0-9]*\"$"}}}},{"oneOf":[{"properties":{"target":{"type":"null"},"etag":{"type":"null"}}},{"properties":{"target":outbound_scim_uuid_schema(),"etag":{"type":"string"}}}]}],"description":"Exact connector/generation/target/ETag CAS and explicit human confirmation. Five-minute database-clock approval; each mutation rechecks admission. Archive fences inactive/empty owned target or safe never-created absence. DELETE additionally requires enabled policy and a disabled/empty owned saved UUID; admitted same-UUID404 may recover only that delete receipt. Recreate verifies absence or fences inactive/empty old incarnation and queues a fresh generation while retaining history."}),
        ),
        "outbound_scim.unselect"
        | "outbound_scim.reconcile"
        | "outbound_scim.preview"
        | "outbound_scim.dry_run" => Some(revision),
        _ => None,
    };
    if let Some(schema) = request {
        object["requestBody"] =
            json!({"required":true,"content":{"application/json":{"schema":schema}}});
    }
    let response = match operation.id() {
        "outbound_scim.list" => outbound_scim_page_schema("OutboundScimConnector", 100),
        "outbound_scim.credentials" => outbound_scim_page_schema("OutboundScimCredential", 100),
        "outbound_scim.assignments" | "outbound_scim.select" => {
            outbound_scim_page_schema("OutboundScimAssignment", 100)
        }
        "outbound_scim.lifecycle_read" => {
            outbound_scim_page_schema("OutboundScimLifecycleReceipt", 25)
        }
        "outbound_scim.lifecycle" => {
            json!({"$ref":"#/components/schemas/OutboundScimLifecycleReceipt"})
        }
        "outbound_scim.dry_run" => {
            json!({"$ref":"#/components/schemas/OutboundScimAssignmentPreview"})
        }
        "outbound_scim.preview" => {
            json!({"type":"object","additionalProperties":false,"required":["connector","revision","filter_supported","etag_supported"],"properties":{"connector":outbound_scim_uuid_schema(),"revision":outbound_scim_uuid_schema(),"filter_supported":{"const":true},"etag_supported":{"const":true}},"description":"Authenticated GET verified filter/ETag and exact reserved-incarnation capability; receipt authorizes enablement only for this revision/credential generation within five minutes."})
        }
        "outbound_scim.reconcile" => {
            json!({"type":"object","additionalProperties":false,"required":["after"],"properties":{"after":outbound_scim_optional_uuid_schema()},"description":"At most25 jobs queued. Continue with the returned after UUID; null means the final page. Queue acknowledgement is not target delivery."})
        }
        "outbound_scim.unselect" => {
            json!({"type":"object","additionalProperties":false,"required":["accepted"],"properties":{"accepted":{"const":true}}})
        }
        _ => json!({"$ref":"#/components/schemas/OutboundScimConnector"}),
    };
    if let Some(responses) = object["responses"].as_object_mut() {
        responses.retain(|status, _| !status.starts_with('2'));
    }
    object["responses"]["200"] = json!({"description":"Current tenant-scoped result; queued commands are not target completion","content":{"application/json":{"schema":response}}});
    for (status, description) in [
        ("400", "Malformed, oversized or closed-profile input"),
        ("401", "Authentication or fresh console step-up required"),
        ("403", "Same-realm human authority, scope or CSRF refused"),
        ("404", "Source-tenant connector or assignment absent"),
        (
            "409",
            "Configuration/generation/version conflict, ownership refusal, paused peer, approval expiry or bounded catalogue refusal",
        ),
        ("503", "Deployment registry/runtime or storage unavailable"),
    ] {
        object["responses"][status] = error_response(description);
    }
}

fn governance_documentation(operation: &Operation, object: &mut Value) {
    if operation.id() == "governance.findings" {
        governance_reports_documentation(object);
        return;
    }
    if !operation.id().starts_with("governance.") {
        return;
    }
    object["security"] = json!([{"consoleSession":[]}]);
    object["x-console-only"] = json!(true);
    object["x-fresh-phishing-resistant-write"] =
        json!(operation.authority().scope().ends_with(":write"));
    object["description"] = json!(
        "Human identity must belong to the addressed tenant. Owner/reviewer configuration never grants administrative authority. Writes additionally require current active tenant-administrator authority, fresh phishing-resistant console proof and normal CSRF protection. Reasons and historical snapshots remain private. Decisions do not change access until explicit application. Stale or externally managed sources are refused; independent standing and temporary sources remain intact. Notification transport is disabled."
    );
    let uuid = json!({"type":"string","format":"uuid","not":{"const":"00000000-0000-0000-0000-000000000000"}});
    let schema = match operation.id() {
        "governance.ownership.configure" => {
            let targets:Vec<Value>=[("membership",vec!["group_id","user_id"]),("user_tenant_role",vec!["user_id","name"]),("user_client_role",vec!["user_id","client_id","name"]),("group_tenant_role",vec!["group_id","name"]),("group_client_role",vec!["group_id","client_id","name"])].into_iter().map(|(kind,keys)|{
                let mut properties=serde_json::Map::new();properties.insert("kind".into(),json!({"const":kind}));
                let mut required=vec!["kind"];for key in keys{required.push(key);properties.insert(key.into(),match key {"name"=>json!({"type":"string","pattern":"^[a-z0-9][a-z0-9._:-]{0,63}$"}),"client_id"=>json!({"type":"string","minLength":1,"maxLength":2048}),_=>uuid.clone()});}
                json!({"type":"object","additionalProperties":false,"required":required,"properties":properties})
            }).collect();
            Some(
                json!({"type":"object","additionalProperties":false,"required":["target","owner_user_id","reviewers","enabled"],"properties":{"target":{"oneOf":targets},"owner_user_id":uuid,"reviewers":{"type":"array","minItems":1,"maxItems":20,"uniqueItems":true,"items":uuid},"enabled":{"type":"boolean"},"expected_revision":{"type":["string","null"],"format":"uuid"}},"description":"Omitted/null revision expects no saved ownership. Existing ownership requires its exact current revision; stale writes return 409."}),
            )
        }
        "governance.review.start" => Some(
            json!({"type":"object","additionalProperties":false,"required":["ownership_ids","reviewer_id","due_at"],"properties":{"ownership_ids":{"type":"array","minItems":1,"maxItems":200,"uniqueItems":true,"items":uuid},"reviewer_id":uuid,"due_at":{"type":"string","format":"date-time"}},"description":"Deadline must be future and within ninety days of database time. Every selected source must exist and its configured reviewer must remain eligible. Group snapshots refuse more than one hundred affected users or incomplete provenance."}),
        ),
        "governance.review.decide" => Some(
            json!({"type":"object","additionalProperties":false,"required":["decision","reason"],"properties":{"decision":{"enum":["retain","remove"]},"reason":{"type":"string","minLength":1,"maxLength":1000}},"description":"An assigned reviewer records one immutable decision and printable nonempty reason. This command does not mutate access."}),
        ),
        "governance.review.apply" | "governance.review.cancel" => {
            Some(json!({"type":"object","additionalProperties":false,"maxProperties":0}))
        }
        _ => None,
    };
    if let Some(schema) = schema {
        object["requestBody"] = json!({"required":!matches!(operation.id(),"governance.review.apply"|"governance.review.cancel"),"content":{"application/json":{"schema":schema}}});
    }
}

fn governance_reports_documentation(object: &mut Value) {
    object["security"] = json!([{"consoleSession":[]}]);
    object["x-console-only"] = json!(true);
    object["description"] = json!(
        "Read-only tenant evidence and review proposals. Each page uses its own repeatable-read snapshot; empty pages with next require continuation. Inactivity is retained-session evidence, not proof of upstream deletion. Source registration is not reachability. Local recovery candidates are preserved. Historical retention counts only with exact ownership, row generation and complete current context. Removal always requires a separately authorized lifecycle command."
    );
    object["parameters"] = json!([
        {"name":"section","in":"query","schema":{"enum":["accounts","ownership","assignments","temporary_entitlements","administrative_roles"],"default":"accounts"}},
        {"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":50,"default":25}},
        {"name":"after","in":"query","schema":{"type":"string","maxLength":16384},"description":"Opaque versioned keyset cursor bound to the tenant and category; do not construct or reuse across categories."}
    ]);
    object["responses"]["200"]["content"]["application/json"]["schema"] = json!({
        "type":"object","additionalProperties":false,
        "required":["section","observed_at","thresholds","items","next","scanned","read_only"],
        "properties":{
            "section":{"enum":["accounts","ownership","assignments","temporary_entitlements","administrative_roles"]},
            "observed_at":{"type":"string","format":"date-time"},
            "thresholds":{"type":"object","additionalProperties":false,"required":["inactivity_days","membership_review_days","privilege_review_days"],"properties":{"inactivity_days":{"const":90},"membership_review_days":{"const":365},"privilege_review_days":{"const":90}}},
            "items":{"type":"array","maxItems":50,"items":{"type":"object","additionalProperties":false,"required":["key","reasons","evidence","proposals"],"properties":{
                "key":{"type":"string","maxLength":8192},
                "reasons":{"type":"array","uniqueItems":true,"items":{"enum":["missing_owner","inactive_owner","owner_authority_unavailable","reviewer_unavailable","missing_ownership","disconnected_source","upstream_deleted","upstream_absent","inactive_account","no_recent_observed_activity","unknown_activity","stale_membership","unreviewed_privilege","stale_review","overdue_review","unapplied_decision","protected_recovery_account","source_health_unknown"]}},
                "evidence":{"type":"object","description":"Server-selected current public source identifiers/statuses, timestamps, revisions and historical-versus-current review context. Contains no credentials, raw external directory identifiers or complete activity-history claim. Evidence is not a lifecycle command."},
                "proposals":{"type":"array","items":{"enum":["inspect_provisioning_source","assign_current_owner","review_account_lifecycle","review_membership_source","start_independent_review","inspect_review_application","preserve_recovery_access"]}}
            }}},
            "next":{"type":["string","null"],"maxLength":16384},"scanned":{"type":"integer","minimum":0,"maximum":100},"read_only":{"const":true}
        }
    });
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

fn task_view_parameters(operation: &Operation, parameters: &mut Vec<Value>) {
    if matches!(
        operation.id(),
        crate::AGENT_TASKS_LIST_ID | crate::AGENT_TASK_READ_ID
    ) {
        parameters.push(json!({"name":"cursor","in":"query","required":false,
            "schema":{"type":"string","format":"uuid"},
            "description":"Canonical UUID keyset cursor from the previous bounded page"}));
        parameters.push(json!({"name":"limit","in":"query","required":false,
            "schema":{"type":"integer","minimum":1,"maximum":50,"default":25},
            "description":"Out-of-range values, duplicates and unknown query names fail"}));
        if operation.id() == crate::AGENT_TASKS_LIST_ID {
            parameters.push(json!({"name":"owner","in":"query","required":false,"schema":{"type":"string","format":"uuid"}}));
            parameters.push(json!({"name":"agent","in":"query","required":false,"schema":{"type":"string","minLength":1,"maxLength":256}}));
        }
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
                "max_duration_seconds":{"type":"integer","minimum":1,"maximum":3600,"default":900},"max_eligibility_seconds":{"type":"integer","minimum":1,"maximum":2_592_000,"default":86400},"enabled":{"type":"boolean"}
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

fn managed_device_documentation(operation: &Operation, object: &mut Value) {
    let id = operation.id();
    if !matches!(
        id,
        crate::DEVICE_SOURCES_LIST_ID
            | crate::DEVICE_SOURCE_CREATE_ID
            | crate::DEVICE_SOURCE_UPDATE_ID
            | crate::DEVICES_LIST_ID
            | crate::DEVICE_REMOVE_ID
            | crate::DEVICE_ENROLL_ID
            | crate::DEVICE_POSTURE_ID
    ) {
        return;
    }
    object["description"] = json!(
        "Managed-device-relay/v1. Device possession uses an independently authenticated pinned proxy TLS hop and dedicated tenant device CA; this is distinct from OAuth client mTLS. No arbitrary browser field, public token device claim, session proof or another grant can establish device authority. Latest posture is bounded to 300 seconds and rechecked under the publication fence through final signing. Source/enrollment generations fence disable, renewal and removal; removal erases identifying attributes. Software PKI is not hardware attestation."
    );
    object["responses"]["400"] = error_response("Closed bounded device input validation failed.");
    object["responses"]["404"] =
        error_response("No current matching record/relay authority in the exact routed tenant.");
    object["responses"]["409"] =
        error_response("Exact revision or monotonic observation sequence conflict.");
    let uuid = json!({"type":"string","format":"uuid"});
    let client = json!({"type":"string","minLength":1,"maxLength":256});
    let schema = match id {
        crate::DEVICE_SOURCE_CREATE_ID | crate::DEVICE_SOURCE_UPDATE_ID => {
            let update = id == crate::DEVICE_SOURCE_UPDATE_ID;
            let required = if update {
                json!(["client_id", "expected_revision"])
            } else {
                json!(["client_id"])
            };
            let revision = if update { uuid } else { json!({"type":"null"}) };
            json!({"type":"object","additionalProperties":false,"required":required,"properties":{
                "client_id":client,"enabled":{"type":"boolean","default":false},"expected_revision":revision
            }})
        }
        crate::DEVICE_REMOVE_ID => {
            json!({"type":"object","additionalProperties":false,"required":["expected_revision"],"properties":{"expected_revision":uuid}})
        }
        crate::DEVICE_ENROLL_ID => {
            object["security"] =
                json!([{"adminToken":[asterius_domain::managed_devices::ENROLLMENT_SCOPE]}]);
            json!({"type":"object","additionalProperties":false,"required":["user_id","leaf_sha256","allowed_client_ids"],"properties":{
                "user_id":uuid,"leaf_sha256":{"type":"string","pattern":"^[a-f0-9]{64}$","writeOnly":true},
                "allowed_client_ids":{"type":"array","maxItems":64,"uniqueItems":true,"items":client}
            },"description":"The current exact source client needs a private successful client-credentials issuance receipt. User/task/workload/delegated tokens and deployment-wide authority are refused; caller cannot choose a device UUID or generation."})
        }
        crate::DEVICE_POSTURE_ID => {
            object["security"] =
                json!([{"adminToken":[asterius_domain::managed_devices::POSTURE_SCOPE]}]);
            json!({"type":"object","additionalProperties":false,"required":["profile","source_generation","observations"],"properties":{
                "profile":{"const":asterius_domain::managed_devices::PROFILE},"source_generation":{"type":"integer","minimum":1},
                "observations":{"type":"array","minItems":1,"maxItems":32,"items":{"type":"object","additionalProperties":false,"required":["device_id","enrollment_generation","sequence","observed_at","expires_at","posture"],"properties":{
                    "device_id":uuid,"enrollment_generation":{"type":"integer","minimum":1},"sequence":{"type":"integer","minimum":0},"observed_at":{"type":"integer"},"expires_at":{"type":"integer"},
                    "posture":{"type":"object","additionalProperties":false,"properties":{"managed":{"type":["boolean","null"]},"compliant":{"type":["boolean","null"]},"disk_encrypted":{"type":["boolean","null"]},"risk":{"type":["string","null"],"enum":["low","medium","high","unknown",null]}}}
                }}}
            },"description":"At most 8192 bytes, 32 distinct device UUIDs; all generations/sequences must be current. Whole batch commits atomically. Observations older than 300 seconds or over five seconds ahead are refused; expiry and authority are rechecked after lock waits."})
        }
        _ => return,
    };
    object["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":schema}},"description":"At most 8192 bytes (1024 for removal). Private credentials/certificates are never returned."});
}

fn kubernetes_online_documentation(operation: &Operation, object: &mut Value) {
    if !matches!(
        operation.id(),
        crate::KUBERNETES_ONLINE_READ_ID
            | crate::KUBERNETES_ONLINE_UPDATE_ID
            | crate::KUBERNETES_REVIEW_ID
    ) {
        return;
    }
    object["description"] = json!(
        "Opt-in primary-backed online Kubernetes authentication. Exact current human public-subject confidential ES256 profile, stable public SID and original signed-token digest bind one grant. Metadata changes terminally disable the mode and invalidate its UUID revision. Online and JIT modes cannot be enabled together. No incoming identity fields establish authority, no session heartbeat occurs, and no bearer token is stored. The complete review deadline is three seconds; errors and late results never release an identity. Kubernetes 1.35 still has a global ten-second success cache plus up to thirty seconds of detached upstream lookup: conservative source-derived revocation bound is forty seconds plus measured scheduling/transport margin, not instant revocation."
    );
    let profile = json!({"type":"object","additionalProperties":false,"required":["reviewer_client_id","revision","enabled"],"properties":{
        "reviewer_client_id":{"type":"string","minLength":1,"maxLength":2048},
        "revision":{"type":"string","format":"uuid"},"enabled":{"type":"boolean"}
    }});
    if operation.id() == crate::KUBERNETES_REVIEW_ID {
        object["security"] =
            json!([{"adminToken":[asterius_domain::kubernetes_online::REVIEW_SCOPE]}]);
        object["description"] = json!(format!(
            "{} Dedicated same-tenant reviewer only: DPoP, private-key JWT and exclusive client_credentials registration are required, together with the private exact successful CC issuance receipt. Console and deployment-wide credentials are refused. The route selects the tenant and human client; requested audiences cannot select either.",
            object["description"].as_str().unwrap_or_default()
        ));
        object["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
            "type":"object","additionalProperties":false,"required":["apiVersion","kind","spec"],"description":"At most 65536 UTF-8 bytes; duplicate JSON members rejected. Only absent or exact zero-value metadata/status are accepted and ignored.",
            "properties":{"apiVersion":{"const":"authentication.k8s.io/v1"},"kind":{"const":"TokenReview"},
                "metadata":{"type":"object","additionalProperties":false,"properties":{"creationTimestamp":{"type":"null"}}},
                "status":{"type":"object","additionalProperties":false,"required":["user"],"properties":{"user":{"type":"object","additionalProperties":false}}},
                "spec":{"type":"object","additionalProperties":false,"required":["token","audiences"],"properties":{
                    "token":{"type":"string","minLength":1,"maxLength":16384,"pattern":"^[!-~]+$","writeOnly":true},
                    "audiences":{"type":"array","minItems":1,"maxItems":16,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":2048}}
                }}
            }
        }}}});
        object["responses"]["200"]["description"] = json!(
            "Closed TokenReview v1. A refusal has authenticated:false without user or audiences. A positive response releases only the validated stable username, at most 100 distinct current-and-issued groups and the route audience; no spec/token/extra/email."
        );
    } else {
        object["responses"]["200"]["content"]["application/json"]["schema"] = profile;
        if operation.id() == crate::KUBERNETES_ONLINE_UPDATE_ID {
            object["responses"]["409"] = error_response(
                "Exact profile revision conflict or mutually exclusive JIT mode enabled.",
            );
            object["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
                "type":"object","additionalProperties":false,"required":["reviewer_client_id","enabled"],"properties":{
                    "reviewer_client_id":{"type":"string","minLength":1,"maxLength":2048},"enabled":{"type":"boolean"},
                    "expected_revision":{"type":["string","null"],"format":"uuid","description":"Omitted/null expects no saved profile. Existing configuration requires its exact current revision."}
                }
            }}}});
        }
    }
}

fn temporary_kubernetes_documentation(operation: &Operation, object: &mut Value) {
    if !operation.id().starts_with("temporary_kubernetes.") {
        return;
    }
    object["description"] = json!(
        "Current complete projection is limited to one immutable owner-approved controller/entitlement/current public-subject Kubernetes profile. No actor, username, role or namespace is accepted from the controller. Subjects use the exact stable public subject and distinct asterius-jit mapping-revision prefix; pending, revoked, stale, disabled and expired approvals contribute no authority. A snapshot is limited to 100 subjects and refuses overflow; its RFC3339 database observed_at and exclusive deadlines bound freshness. Healthy reconciliation bounds revocation latency. During controller failure, signed temporary-only ID provenance and activation-capped exp bound residual access; ordinary tokens retain their separate baseline username and cannot reuse stale JIT bindings. Owner GET additionally returns a structured AuthenticationConfiguration example for the exact reviewed tuple; legacy OIDC flags cannot implement this mapping."
    );
    object["responses"]["409"] =
        error_response("Binding revision conflict or complete projection exceeds bound.");
    if operation.id() == crate::TEMPORARY_KUBERNETES_PROJECT_ID {
        object["security"] = json!([{"adminToken":[]}]);
    } else {
        object["security"] = json!([{"consoleSession":[]}]);
    }
    if operation.id() == crate::TEMPORARY_KUBERNETES_BINDING_WRITE_ID {
        object["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
            "type":"object","additionalProperties":false,"required":["controller_client_id","expected_revision","enabled"],
            "properties":{"controller_client_id":{"type":"string","minLength":1,"maxLength":200},"expected_revision":{"type":["string","null"],"format":"uuid"},"enabled":{"type":"boolean"}}
        }}}});
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
    fn outbound_provisioning_contract_is_console_only_closed_and_exactly_scoped() {
        let document = value();
        let create = &document["paths"][crate::OUTBOUND_SCIM_CREATE.full_path()]["post"];
        assert_eq!(create["security"], json!([{"consoleSession":[]}]));
        assert_eq!(create["x-fresh-phishing-resistant-write"], json!(true));
        assert!(create["responses"].get("201").is_none());
        let command = &create["requestBody"]["content"]["application/json"]["schema"];
        assert_eq!(command["additionalProperties"], json!(false));
        assert_eq!(command["properties"]["enabled"]["const"], json!(false));
        for forbidden in ["id", "actor", "key_file", "private_key", "access_token"] {
            assert!(command["properties"].get(forbidden).is_none());
        }
        let lifecycle = &document["paths"][crate::OUTBOUND_SCIM_LIFECYCLE.full_path()]["post"]["requestBody"]
            ["content"]["application/json"]["schema"];
        assert_eq!(lifecycle["properties"]["confirmed"]["const"], json!(true));
        for required in ["expected_revision", "expected_generation", "target", "etag"] {
            assert!(
                lifecycle["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!(required))
            );
        }
        let receipts = &document["paths"][crate::OUTBOUND_SCIM_LIFECYCLE_READ.full_path()]["get"];
        assert_eq!(
            receipts["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["items"]
                ["maxItems"],
            json!(25)
        );
        assert!(receipts.get("requestBody").is_none());
    }

    #[test]
    fn governance_findings_are_console_only_readonly_and_bounded() {
        let document = value();
        let route = &document["paths"][crate::GOVERNANCE_FINDINGS.full_path()]["get"];
        assert_eq!(route["x-console-only"], json!(true));
        assert!(route.get("requestBody").is_none());
        let schema = &route["responses"]["200"]["content"]["application/json"]["schema"];
        assert_eq!(schema["properties"]["read_only"]["const"], json!(true));
        assert_eq!(schema["properties"]["items"]["maxItems"], json!(50));
        assert_eq!(schema["properties"]["scanned"]["maximum"], json!(100));
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
