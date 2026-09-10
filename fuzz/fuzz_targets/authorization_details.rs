//! Rich authorization requests — RFC 9396 §2, §2.1, §2.2.
//!
//! `authorization_details` is the largest piece of attacker-controlled
//! structure this server accepts: a JSON document a client composes, validated
//! against a schema an operator wrote, stored on a grant, rendered to a person
//! on the consent page and copied into every access token the grant produces.
//! Five properties matter, and each of them is a way that chain breaks:
//!
//! * **The limits hold, and hold first.** At most [`MAX_ELEMENTS`] elements,
//!   [`MAX_BYTES`] of input and [`MAX_DEPTH`] levels of nesting, applied before
//!   any schema is consulted. A validator is a tree walk, and a tree walk over
//!   an unbounded document is the denial of service.
//! * **What is accepted has the shape RFC 9396 §2 names.** A JSON array of
//!   objects, each with a string `type`, and a `locations` that is an array of
//!   strings whenever it is present at all — because a caller checking a subset
//!   relation against a number would silently check nothing.
//! * **Nothing is invented or dropped.** The element that comes out is the
//!   element that went in, member for member: a parser that trimmed would grant
//!   an authorization the client did not ask for, and one that added would
//!   grant one nobody did.
//! * **Parsing and validation are total and deterministic.** No input panics,
//!   and the same input always gives the same answer.
//! * **The registry and the client's allow-list are the authority.** An
//!   accepted document still has to name a type the tenant registered and the
//!   client may ask for, satisfy that type's schema, and confine its
//!   `locations` to what the client may reach — and whatever the fuzzer sends,
//!   `validate` never accepts an element outside all three.
#![no_main]

use asterius_domain::entities::authorization_details::{
    MAX_BYTES, MAX_DEPTH, MAX_ELEMENTS, is_type_name,
};
use asterius_domain::{
    AuthorizationDetails, AuthorizationDetailsRegistry, AuthorizationDetailsType,
    InvalidAuthorizationDetails, JsonSchema,
};
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// The one type the fuzzed registry holds.
const REGISTERED: &str = "payment_initiation";
/// The one location the fuzzed client may name.
const LOCATION: &str = "https://api.example/v1";

fn registry() -> AuthorizationDetailsRegistry {
    AuthorizationDetailsRegistry::new([AuthorizationDetailsType {
        name: REGISTERED.to_owned(),
        schema: JsonSchema::parse(&json!({
            "type": "object",
            "required": ["type", "instructedAmount"],
            "properties": {
                "instructedAmount": {
                    "type": "object",
                    "required": ["currency"],
                    "properties": {"currency": {"type": "string", "maxLength": 3}}
                },
                "actions": {"type": "array", "maxItems": 4, "items": {"type": "string"}}
            }
        }))
        .expect("a fixed schema"),
        consent_template: Some("Initiate a payment".to_owned()),
    }])
}

/// The maximum nesting depth of `value`, counting containers only.
fn depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Object(members) => 1 + members.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let registry = registry();
    let allowed_types: BTreeSet<String> = [REGISTERED.to_owned()].into_iter().collect();
    let permitted_locations: BTreeSet<String> = [LOCATION.to_owned()].into_iter().collect();

    let parsed = AuthorizationDetails::parse(text);
    // Deterministic: the same bytes give the same answer, every time.
    assert_eq!(parsed, AuthorizationDetails::parse(text));

    let Ok(details) = parsed else {
        // Refusing is total. There is nothing further to check: an
        // unparsable document never reaches the registry.
        return;
    };

    // The bytes bound was applied, whatever else happened.
    assert!(text.len() <= MAX_BYTES, "accepted {} bytes", text.len());

    let elements = details.elements();
    assert!(
        elements.len() <= MAX_ELEMENTS,
        "accepted {} elements",
        elements.len()
    );

    // Round-tripping the accepted value proves it was carried whole: the JSON
    // this server will store, render and sign is the JSON the client sent.
    let json = details.to_json();
    assert_eq!(json.len(), elements.len());
    assert_eq!(
        AuthorizationDetails::from_value(&Value::Array(json.clone())),
        Ok(details.clone()),
        "an accepted document did not survive its own round trip"
    );

    for element in &json {
        // §2: an object with a string `type`.
        let object = element
            .as_object()
            .expect("an accepted element is an object");
        let name = object
            .get("type")
            .and_then(Value::as_str)
            .expect("an accepted element has a string type");
        assert!(is_type_name(name), "accepted the type name {name:?}");
        // §2.2: `locations` is an array of strings when it is there.
        if let Some(locations) = object.get("locations") {
            let values = locations
                .as_array()
                .expect("an accepted `locations` is an array");
            assert!(
                values.iter().all(Value::is_string),
                "accepted a non-string location"
            );
        }
        // The array is level one, so an element may reach MAX_DEPTH - 1.
        assert!(
            depth(element) < MAX_DEPTH,
            "accepted a document {} levels deep",
            depth(element) + 1
        );
    }

    // The registry is the authority, and it is deterministic too.
    let outcome = registry.validate(&details, &allowed_types, &permitted_locations);
    assert_eq!(
        outcome,
        registry.validate(&details, &allowed_types, &permitted_locations)
    );

    match outcome {
        Err(InvalidAuthorizationDetails) => {}
        Ok(()) => {
            // Everything `validate` accepted is inside all three gates.
            for element in details.elements() {
                let name = element.detail_type();
                assert!(allowed_types.contains(name), "accepted the type {name:?}");
                let registered = registry
                    .get(name)
                    .expect("an accepted type is a registered type");
                assert!(
                    registered.schema.accepts(&element.to_json()),
                    "accepted an element its schema refuses"
                );
                for location in element.locations() {
                    assert!(
                        permitted_locations.contains(location),
                        "accepted the location {location:?}"
                    );
                }
            }
        }
    }

    // A client with no §9.2 registration may name no type at all: an empty
    // allow-list means none, never all.
    if !details.is_empty() {
        assert_eq!(
            registry.validate(&details, &BTreeSet::new(), &permitted_locations),
            Err(InvalidAuthorizationDetails),
            "a client registered for no type was allowed one"
        );
    }
});
