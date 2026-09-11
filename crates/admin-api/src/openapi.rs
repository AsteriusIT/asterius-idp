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
    let mut parameters: Vec<Value> = Vec::new();
    for placeholder in path_parameters(operation.path()) {
        parameters.push(json!({
            "name": placeholder,
            "in": "path",
            "required": true,
            "schema": { "type": "string" },
        }));
    }
    if operation.is_paginated() {
        parameters.push(json!({ "$ref": "#/components/parameters/cursor" }));
        parameters.push(json!({ "$ref": "#/components/parameters/limit" }));
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

    let mut object = json!({
        "operationId": operation.id(),
        "summary": operation.summary(),
        "x-asterius-reach": reach_name(operation.authority().reach()),
        "x-asterius-scope": operation.authority().scope(),
        "security": [{ "consoleSession": [] }, { "adminToken": [operation.authority().scope()] }],
        "responses": responses(operation),
    });

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

fn responses(operation: &Operation) -> Value {
    let success = if operation.method() == crate::operations::Method::Post {
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
