//! Rich Authorization Requests: the `authorization_details` parameter
//! (RFC 9396).
//!
//! `scope` is a set of bare words, and a word cannot say "transfer at most
//! 30 EUR from this IBAN to that one". RFC 9396 §1 exists for that gap: the
//! client sends a JSON array of objects, each naming a `type` that both ends
//! have agreed on, and the authorization server decides — and shows the user —
//! what that object actually authorises.
//!
//! # What this module is responsible for
//!
//! Everything between "attacker-controlled bytes arrived on a pushed
//! authorization request" and "a typed value the rest of the server may act
//! on". Concretely:
//!
//! 1. **Limits before meaning.** [`AuthorizationDetails::parse`] refuses on
//!    size, element count and nesting depth *before* any element is looked at,
//!    let alone validated against a schema. A validator is a tree walk, and a
//!    tree walk over an unbounded document is the denial of service; refusing
//!    first is the only order that cannot be talked out of.
//! 2. **The shape RFC 9396 §2 names.** A JSON array, of objects, each with a
//!    `type` that is a string. Nothing else is an `authorization_details`, and
//!    everything else is `invalid_authorization_details`.
//! 3. **The registry.** §2.1 says the types are "defined by the API designers"
//!    — so a type is a per-tenant registration (a name, a schema, a consent
//!    template), and a `type` this deployment never heard of is refused rather
//!    than passed through. An unregistered type reaching a grant would be an
//!    authorization nobody could describe to the user and no resource server
//!    could interpret.
//!
//! # Why the schema validator is written here
//!
//! [`Schema`] is a deliberate subset of JSON Schema — `type`, `required`,
//! `properties`, `additionalProperties`, `enum`, `maxLength`, `items`,
//! `maxItems` — and not a dependency. Three reasons, in order of weight:
//!
//! * This crate is the centre of the hexagon and may not reach a network. The
//!   general-purpose validators resolve `$ref` against remote URLs, which is a
//!   server-side request forgery primitive driven by a document an operator
//!   pasted into a table.
//! * The subset is total and allocation-free per keyword, so it fuzzes to
//!   fixpoint quickly (`fuzz_targets/authorization_details.rs`) where a full
//!   implementation would not.
//! * An operator writing a schema this validator does not understand gets a
//!   refusal at registration time, which is a smaller surprise than a keyword
//!   that is silently ignored and admits a document it was written to refuse.
//!
//! The cost is real and worth stating: a schema using `pattern`, `$ref`,
//! `oneOf`, `minimum` or the other keywords is refused, so an operator must
//! express the constraint within the subset or not at all.
//!
//! # What is *not* decided here
//!
//! Whether a client may ask for a type (its RFC 9396 §9.2
//! `authorization_details_types`) and whether a `locations` value is a resource
//! this deployment serves are both checks against something outside this
//! module — the client registration and the RFC 8707 resource registry — so
//! they are made by the callers that hold those, with the same error code.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

/// The most elements one `authorization_details` may carry (RFC 9396 §2).
///
/// The specification sets no bound, so this one is ours. Each element is
/// schema-validated, persisted on the grant, rendered on the consent page and
/// copied into every access token for the life of the authorization; sixteen
/// distinct authorizations is already far more than a person can meaningfully
/// read and agree to in one sitting.
pub const MAX_ELEMENTS: usize = 16;

/// The largest `authorization_details` document this server will parse.
///
/// Applied to the raw bytes, before `serde_json` sees them. The pushed
/// authorization request endpoint has its own 16 KiB body bound; this is the
/// share of it one parameter may take.
pub const MAX_BYTES: usize = 8 * 1024;

/// The deepest an element may nest, counting the array itself as level one.
///
/// Serde's recursion limit is far higher, and every consumer of this value —
/// the schema walk, the consent renderer, the JSON written to a `jsonb` column
/// — recurses. Eight is past any authorization detail anybody has published
/// and shallow enough that the deepest possible walk is cheap.
pub const MAX_DEPTH: usize = 8;

/// The longest a registered type name may be.
///
/// A type name is an identifier two parties agreed on out of band, and it is
/// carried in every access token that mentions it.
pub const MAX_TYPE_LEN: usize = 128;

/// The most types one tenant may register.
///
/// The registry is read on the request path, like the resource server one.
pub const MAX_REGISTERED_TYPES: usize = 128;

/// RFC 9396 §5's error for an `authorization_details` this server will not
/// honour.
///
/// One variant, like [`crate::InvalidTarget`], and for the same reason: "too
/// deep", "not registered here" and "not on your client's list" are three
/// different facts, and a client able to tell them apart could enumerate a
/// tenant's registered types with a series of pushed requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the authorization_details parameter is not one this client may be authorized for")]
pub struct InvalidAuthorizationDetails;

impl InvalidAuthorizationDetails {
    /// The OAuth error code (RFC 9396 §5).
    pub const CODE: &'static str = "invalid_authorization_details";
}

// ---------------------------------------------------------------------------
// The parsed parameter
// ---------------------------------------------------------------------------

/// One element of `authorization_details` (RFC 9396 §2).
///
/// Construction is the proof: the only way to obtain one is through
/// [`AuthorizationDetails::parse`] or [`AuthorizationDetails::from_value`], so
/// a value of this type is a JSON object, within the depth bound, whose `type`
/// is a string.
///
/// The whole object is kept, not just the members §2.2 names. §2.2's fields are
/// "common data fields" that a type *may* use, and everything else is the
/// type's own vocabulary — dropping it would mean granting an authorization the
/// client did not ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDetail(Map<String, Value>);

impl AuthorizationDetail {
    /// The `type` member. RFC 9396 §2 makes it REQUIRED and a string.
    #[must_use]
    pub fn detail_type(&self) -> &str {
        self.0
            .get("type")
            .and_then(Value::as_str)
            .expect("an AuthorizationDetail is only built with a string `type`")
    }

    /// The RFC 9396 §2.2 `locations`, as the strings they must be.
    ///
    /// An absent `locations` is an empty iterator, which is the same thing to
    /// every caller: "this element names no resource server". A `locations`
    /// that is present but not an array of strings never reaches here — it is
    /// refused at parse time, because §2.2 defines it as "an array of strings"
    /// and a caller checking a subset relation against a number would silently
    /// check nothing.
    pub fn locations(&self) -> impl Iterator<Item = &str> {
        self.0
            .get("locations")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
    }

    /// The element as JSON, for the grant, the token and the wire.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Object(self.0.clone())
    }

    /// The element's members, for a schema walk or a consent renderer.
    #[must_use]
    pub const fn members(&self) -> &Map<String, Value> {
        &self.0
    }
}

/// A validated `authorization_details` parameter.
///
/// Empty is a legitimate value — a client that sent `[]` asked for no rich
/// authorization — and is indistinguishable downstream from having sent
/// nothing. Nothing needs to tell them apart: RFC 9396 §2 gives an empty array
/// no meaning beyond the absence of elements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorizationDetails(Vec<AuthorizationDetail>);

impl AuthorizationDetails {
    /// Parses the `authorization_details` request parameter.
    ///
    /// RFC 9396 §2: "The `authorization_details` authorization request
    /// parameter […] is a JSON array of objects. Each JSON object contains the
    /// data to specify the authorization requirements for a certain type of
    /// resource." §2: "`type`: […] REQUIRED. […] The value of the `type` field
    /// determines the allowable contents of the object".
    ///
    /// The order of the checks is the security property. Byte length, then
    /// element count, then depth, then shape — each of them bounds the work the
    /// next one does, and none of them can be reached by a document that failed
    /// an earlier one.
    ///
    /// # Errors
    ///
    /// [`InvalidAuthorizationDetails`] for anything that is not a bounded JSON
    /// array of objects each carrying a string `type` and, if present, a
    /// `locations` that is an array of strings.
    // fuzz-target: authorization_details
    pub fn parse(raw: &str) -> Result<Self, InvalidAuthorizationDetails> {
        // (1) Bytes, before serde. A document this server will refuse must cost
        // it a length comparison and not a parse.
        if raw.len() > MAX_BYTES {
            return Err(InvalidAuthorizationDetails);
        }
        let value: Value = serde_json::from_str(raw).map_err(|_| InvalidAuthorizationDetails)?;
        Self::from_value(&value)
    }

    /// The same checks, for a document that is already parsed JSON.
    ///
    /// Used when a stored request or a stored grant is read back: a row is held
    /// to the shape it was written with, because a store is not a trusted input
    /// (see the `docs/threat-model.md` row on edited grants).
    ///
    /// # Errors
    ///
    /// [`InvalidAuthorizationDetails`], as [`Self::parse`].
    pub fn from_value(value: &Value) -> Result<Self, InvalidAuthorizationDetails> {
        // (2) An array, and a short one. §2: "is a JSON array of objects".
        let Some(elements) = value.as_array() else {
            return Err(InvalidAuthorizationDetails);
        };
        if elements.len() > MAX_ELEMENTS {
            return Err(InvalidAuthorizationDetails);
        }

        let mut details = Vec::with_capacity(elements.len());
        for element in elements {
            // (3) Depth, before the element is read for meaning. The array
            // itself is level one, so an element has MAX_DEPTH - 1 to spend.
            if depth_exceeds(element, MAX_DEPTH - 1) {
                return Err(InvalidAuthorizationDetails);
            }
            // (4) Shape. §2 makes `type` REQUIRED and a string; §2.2 makes
            // `locations` an array of strings when it is there at all.
            let Some(object) = element.as_object() else {
                return Err(InvalidAuthorizationDetails);
            };
            match object.get("type") {
                Some(Value::String(name)) if is_type_name(name) => {}
                _ => return Err(InvalidAuthorizationDetails),
            }
            if let Some(locations) = object.get("locations")
                && !locations
                    .as_array()
                    .is_some_and(|values| values.iter().all(Value::is_string))
            {
                return Err(InvalidAuthorizationDetails);
            }
            details.push(AuthorizationDetail(object.clone()));
        }
        Ok(Self(details))
    }

    /// The elements, in the order the client sent them.
    ///
    /// Order is preserved rather than sorted: RFC 9396 §2 gives none, but a
    /// consent page that reordered what it was given would show the user a
    /// different document from the one the client composed.
    #[must_use]
    pub fn elements(&self) -> &[AuthorizationDetail] {
        &self.0
    }

    /// Whether the client asked for no rich authorization at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The distinct types named, for a client allow-list comparison.
    #[must_use]
    pub fn types(&self) -> BTreeSet<&str> {
        self.0
            .iter()
            .map(AuthorizationDetail::detail_type)
            .collect()
    }

    /// Every `locations` value across every element, deduplicated.
    #[must_use]
    pub fn locations(&self) -> BTreeSet<&str> {
        self.0
            .iter()
            .flat_map(AuthorizationDetail::locations)
            .collect()
    }

    /// The elements as JSON, for the grant column, the token claim and the
    /// token response.
    #[must_use]
    pub fn to_json(&self) -> Vec<Value> {
        self.0.iter().map(AuthorizationDetail::to_json).collect()
    }
}

/// Whether `value` nests deeper than `budget` further levels.
///
/// Written as an explicit budget rather than a returned depth so that the walk
/// stops at the bound: a document nested a million deep must cost
/// [`MAX_DEPTH`] frames to refuse, not a million. The recursion is bounded by
/// `budget`, which is why this is not the stack overflow it looks like.
fn depth_exceeds(value: &Value, budget: usize) -> bool {
    match value {
        Value::Array(items) => {
            budget == 0 || items.iter().any(|item| depth_exceeds(item, budget - 1))
        }
        Value::Object(members) => {
            budget == 0
                || members
                    .values()
                    .any(|member| depth_exceeds(member, budget - 1))
        }
        _ => false,
    }
}

/// Whether `name` may be a `type` value or a registered type name.
///
/// Printable ASCII without space, bounded. RFC 9396 §2 says only "string", but
/// a type name ends up in an access token claim, on a consent page and in a log
/// line; control characters and bidi overrides in any of those three are a
/// problem that has nothing to do with authorization.
#[must_use]
pub fn is_type_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TYPE_LEN
        && name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
}

// ---------------------------------------------------------------------------
// The schema subset
// ---------------------------------------------------------------------------

/// A schema an operator registered was not one this server understands.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaError {
    /// A keyword outside the supported subset.
    ///
    /// Refused rather than ignored: a schema whose `pattern` is silently
    /// dropped admits every document it was written to refuse, and the operator
    /// has no way to notice.
    #[error("the schema keyword `{0}` is not supported")]
    UnsupportedKeyword(String),
    /// A keyword with a value of the wrong shape.
    #[error("the schema keyword `{0}` has a value this validator cannot use")]
    Malformed(&'static str),
    /// A `type` naming something that is not a JSON type.
    #[error("`{0}` is not a JSON type")]
    UnknownType(String),
    /// A schema that nests deeper than [`MAX_DEPTH`].
    #[error("a schema nests at most {MAX_DEPTH} levels")]
    TooDeep,
}

/// The keywords [`Schema`] understands.
///
/// Named here so that the error message, the documentation and the parser
/// cannot drift apart.
pub const SUPPORTED_KEYWORDS: &[&str] = &[
    "type",
    "required",
    "properties",
    "additionalProperties",
    "enum",
    "maxLength",
    "items",
    "maxItems",
    "title",
    "description",
];

/// The JSON types [`Schema`] can assert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonType {
    Object,
    Array,
    String,
    Number,
    Integer,
    Boolean,
    Null,
}

impl JsonType {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "object" => Some(Self::Object),
            "array" => Some(Self::Array),
            "string" => Some(Self::String),
            "number" => Some(Self::Number),
            "integer" => Some(Self::Integer),
            "boolean" => Some(Self::Boolean),
            "null" => Some(Self::Null),
            _ => None,
        }
    }

    fn matches(self, value: &Value) -> bool {
        match self {
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
            Self::String => value.is_string(),
            Self::Number => value.is_number(),
            // A JSON Schema `integer` is a number with no fractional part, not
            // a distinct JSON type.
            Self::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
            Self::Boolean => value.is_boolean(),
            Self::Null => value.is_null(),
        }
    }
}

/// A validating subset of JSON Schema (see the module documentation).
///
/// Built once, when a registry row is read, and then applied per request. An
/// unconstrained schema — `{}` — accepts every value, which is the JSON Schema
/// meaning and the right default for a type whose operator has not described it
/// yet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Schema {
    types: Option<Vec<JsonType>>,
    required: Vec<String>,
    properties: BTreeMap<String, Schema>,
    /// `false` is JSON Schema's "no members beyond `properties`", which is what
    /// the "unknown members" question comes down to for one type. Absent means
    /// `true`, as in JSON Schema.
    additional_properties: bool,
    enumeration: Option<Vec<Value>>,
    max_length: Option<usize>,
    items: Option<Box<Schema>>,
    max_items: Option<usize>,
}

impl Schema {
    /// Reads a schema document.
    ///
    /// # Errors
    ///
    /// [`SchemaError`] for a keyword outside [`SUPPORTED_KEYWORDS`], a
    /// supported keyword with an unusable value, or a document deeper than
    /// [`MAX_DEPTH`].
    pub fn parse(document: &Value) -> Result<Self, SchemaError> {
        Self::parse_at(document, MAX_DEPTH)
    }

    fn parse_at(document: &Value, budget: usize) -> Result<Self, SchemaError> {
        if budget == 0 {
            return Err(SchemaError::TooDeep);
        }
        let Some(members) = document.as_object() else {
            return Err(SchemaError::Malformed("schema"));
        };
        let mut schema = Self {
            additional_properties: true,
            ..Self::default()
        };
        for (keyword, value) in members {
            match keyword.as_str() {
                // Annotations. Carried by real schemas, assert nothing, and
                // refusing them would make every published example unusable.
                "title" | "description" => {}
                "type" => schema.types = Some(parse_types(value)?),
                "required" => {
                    schema.required = value
                        .as_array()
                        .ok_or(SchemaError::Malformed("required"))?
                        .iter()
                        .map(|name| {
                            name.as_str()
                                .map(ToOwned::to_owned)
                                .ok_or(SchemaError::Malformed("required"))
                        })
                        .collect::<Result<_, _>>()?;
                }
                "properties" => {
                    let members = value
                        .as_object()
                        .ok_or(SchemaError::Malformed("properties"))?;
                    for (name, sub) in members {
                        schema
                            .properties
                            .insert(name.clone(), Self::parse_at(sub, budget - 1)?);
                    }
                }
                "additionalProperties" => {
                    schema.additional_properties = value
                        .as_bool()
                        .ok_or(SchemaError::Malformed("additionalProperties"))?;
                }
                "enum" => {
                    let values = value.as_array().ok_or(SchemaError::Malformed("enum"))?;
                    schema.enumeration = Some(values.clone());
                }
                "maxLength" => schema.max_length = Some(bound(value, "maxLength")?),
                "items" => schema.items = Some(Box::new(Self::parse_at(value, budget - 1)?)),
                "maxItems" => schema.max_items = Some(bound(value, "maxItems")?),
                other => return Err(SchemaError::UnsupportedKeyword(other.to_owned())),
            }
        }
        Ok(schema)
    }

    /// Whether `value` satisfies this schema.
    ///
    /// The walk follows the *schema*, whose depth [`Schema::parse`] has already
    /// bounded, so a document nested deeper than the schema is simply not
    /// described by it. The document's own depth is bounded separately, by
    /// [`AuthorizationDetails::parse`], before this is ever called.
    #[must_use]
    pub fn accepts(&self, value: &Value) -> bool {
        if let Some(types) = &self.types
            && !types.iter().any(|kind| kind.matches(value))
        {
            return false;
        }
        if let Some(allowed) = &self.enumeration
            && !allowed.contains(value)
        {
            return false;
        }
        if let Some(max) = self.max_length
            && let Some(text) = value.as_str()
            // JSON Schema counts characters, not bytes; a byte count would
            // refuse a compliant document written in a non-Latin script.
            && text.chars().count() > max
        {
            return false;
        }
        if let Some(items) = value.as_array() {
            if let Some(max) = self.max_items
                && items.len() > max
            {
                return false;
            }
            if let Some(schema) = &self.items
                && !items.iter().all(|item| schema.accepts(item))
            {
                return false;
            }
        }
        if let Some(members) = value.as_object() {
            if !self.required.iter().all(|name| members.contains_key(name)) {
                return false;
            }
            if !self.additional_properties
                && members
                    .keys()
                    .any(|name| !self.properties.contains_key(name))
            {
                return false;
            }
            for (name, sub) in &self.properties {
                if let Some(member) = members.get(name)
                    && !sub.accepts(member)
                {
                    return false;
                }
            }
        }
        true
    }
}

fn parse_types(value: &Value) -> Result<Vec<JsonType>, SchemaError> {
    match value {
        Value::String(name) => JsonType::parse(name)
            .map(|kind| vec![kind])
            .ok_or_else(|| SchemaError::UnknownType(name.clone())),
        Value::Array(names) => names
            .iter()
            .map(|name| {
                let name = name.as_str().ok_or(SchemaError::Malformed("type"))?;
                JsonType::parse(name).ok_or_else(|| SchemaError::UnknownType(name.to_owned()))
            })
            .collect(),
        _ => Err(SchemaError::Malformed("type")),
    }
}

fn bound(value: &Value, keyword: &'static str) -> Result<usize, SchemaError> {
    value
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(SchemaError::Malformed(keyword))
}

// ---------------------------------------------------------------------------
// The per-tenant registry
// ---------------------------------------------------------------------------

/// One registered authorization details type (RFC 9396 §2.1).
///
/// Deliberately not `#[non_exhaustive]`, like the other entities: the store
/// adapter builds these from rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDetailsType {
    /// The `type` value a client sends, compared byte for byte. RFC 9396 §2
    /// gives no normalisation, and inventing one here would let two spellings
    /// match a registration a resource server does not.
    pub name: String,
    /// What an element of this type must look like.
    pub schema: Schema,
    /// The sentence shown to the user on the consent page.
    ///
    /// `None` is an operator who registered a type without describing it, and
    /// the consent page says so in as many words rather than falling back to
    /// the raw JSON. RFC 9396 §12 is explicit that the user has to be able to
    /// understand what they are agreeing to; a JSON blob on a consent screen is
    /// a prompt nobody reads, and it is attacker-composed text.
    pub consent_template: Option<String>,
}

/// One tenant's registered authorization details types.
///
/// Built from a repository listing and consulted per request, exactly like
/// [`crate::ResourceRegistry`].
#[derive(Debug, Clone, Default)]
pub struct AuthorizationDetailsRegistry(BTreeMap<String, AuthorizationDetailsType>);

impl AuthorizationDetailsRegistry {
    /// Collects a listing into a registry, keeping at most
    /// [`MAX_REGISTERED_TYPES`] entries.
    #[must_use]
    pub fn new<I: IntoIterator<Item = AuthorizationDetailsType>>(types: I) -> Self {
        Self(
            types
                .into_iter()
                .take(MAX_REGISTERED_TYPES)
                .map(|kind| (kind.name.clone(), kind))
                .collect(),
        )
    }

    /// The registered type called `name`, if there is one.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&AuthorizationDetailsType> {
        self.0.get(name)
    }

    /// RFC 9396 §9.1's `authorization_details_types_supported`.
    ///
    /// The registry, and nothing else: RFC 8414 §2 requires metadata to reflect
    /// actual behaviour, and a type advertised but not registered is a type
    /// every client would be refused for asking about.
    #[must_use]
    pub fn supported_types(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }

    /// Checks a parsed parameter against this tenant's registry and this
    /// client's allow-list.
    ///
    /// * `details` — what the client pushed, already shape- and limit-checked.
    /// * `allowed_types` — the client's RFC 9396 §9.2
    ///   `authorization_details_types`. Empty means *none*, not *all*: a client
    ///   that has not been registered for a type must not be able to name one,
    ///   which is the same reading [`crate::ResourceRegistry`] takes of an empty
    ///   `resources`.
    /// * `permitted_locations` — the resource indicators this client may name in
    ///   §2.2 `locations`, already intersected with what the tenant registered
    ///   by the caller that holds the resource registry.
    ///
    /// # Errors
    ///
    /// [`InvalidAuthorizationDetails`] when a type is unregistered or not on the
    /// client's list, when an element fails its type's schema, or when a
    /// `locations` value is not one this client may name.
    pub fn validate(
        &self,
        details: &AuthorizationDetails,
        allowed_types: &BTreeSet<String>,
        permitted_locations: &BTreeSet<String>,
    ) -> Result<(), InvalidAuthorizationDetails> {
        for element in details.elements() {
            let name = element.detail_type();
            // The client's list first, then the registry: a client that may not
            // ask for a type learns nothing about whether it exists.
            if !allowed_types.contains(name) {
                return Err(InvalidAuthorizationDetails);
            }
            let Some(registered) = self.get(name) else {
                return Err(InvalidAuthorizationDetails);
            };
            if !registered.schema.accepts(&element.to_json()) {
                return Err(InvalidAuthorizationDetails);
            }
            // RFC 9396 §2.2: `locations` is "the location of the resource server
            // […] typically the URI the client uses to access the resource". A
            // location this client may not be issued a token for is an
            // authorization it could never exercise, and honouring it would put
            // a resource server it does not have on the consent page.
            for location in element.locations() {
                if !permitted_locations.contains(location) {
                    return Err(InvalidAuthorizationDetails);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn details(raw: &Value) -> Result<AuthorizationDetails, InvalidAuthorizationDetails> {
        AuthorizationDetails::parse(&raw.to_string())
    }

    /// RFC 9396 §2: "The `authorization_details` […] is a JSON array of
    /// objects."
    #[test]
    fn anything_that_is_not_an_array_of_objects_is_refused() {
        for wrong in [
            json!({"type": "payment"}),
            json!("payment"),
            json!(7),
            json!(null),
            json!([["type"]]),
            json!([null]),
            json!(["payment"]),
        ] {
            assert_eq!(
                details(&wrong),
                Err(InvalidAuthorizationDetails),
                "accepted {wrong}"
            );
        }
    }

    /// RFC 9396 §2: "`type`: […] REQUIRED."
    #[test]
    fn an_element_without_a_string_type_is_refused() {
        for wrong in [
            json!([{}]),
            json!([{"type": 1}]),
            json!([{"type": null}]),
            json!([{"type": ["payment"]}]),
            json!([{"type": ""}]),
            json!([{"type": "with space"}]),
            json!([{"type": "\u{7f}"}]),
            // The second element is as much an element as the first.
            json!([{"type": "payment"}, {"actions": ["read"]}]),
        ] {
            assert_eq!(
                details(&wrong),
                Err(InvalidAuthorizationDetails),
                "accepted {wrong}"
            );
        }
    }

    /// RFC 9396 §2.2: "`locations`: An array of strings".
    #[test]
    fn a_locations_that_is_not_an_array_of_strings_is_refused() {
        for wrong in [
            json!([{"type": "payment", "locations": "https://api.example/"}]),
            json!([{"type": "payment", "locations": [7]}]),
            json!([{"type": "payment", "locations": {}}]),
        ] {
            assert_eq!(
                details(&wrong),
                Err(InvalidAuthorizationDetails),
                "accepted {wrong}"
            );
        }
    }

    /// The acceptance criterion: at most 16 elements.
    #[test]
    fn more_than_sixteen_elements_is_refused() {
        let element = json!({"type": "payment"});
        let at_bound = vec![element.clone(); MAX_ELEMENTS];
        assert!(details(&json!(at_bound)).is_ok());
        let over = vec![element; MAX_ELEMENTS + 1];
        assert_eq!(details(&json!(over)), Err(InvalidAuthorizationDetails));
    }

    /// The acceptance criterion: at most 8 KiB, refused on the bytes before the
    /// document is parsed.
    #[test]
    fn more_than_eight_kibibytes_is_refused_before_parsing() {
        let filler = "a".repeat(MAX_BYTES);
        let raw = json!([{"type": "payment", "note": filler}]).to_string();
        assert!(raw.len() > MAX_BYTES);
        assert_eq!(
            AuthorizationDetails::parse(&raw),
            Err(InvalidAuthorizationDetails)
        );
        // And a document that is not valid JSON at all is refused on length
        // alone, which is how we know serde never saw it.
        let garbage = "[".repeat(MAX_BYTES + 1);
        assert_eq!(
            AuthorizationDetails::parse(&garbage),
            Err(InvalidAuthorizationDetails)
        );
    }

    /// The acceptance criterion: depth at most 8, counting the array itself.
    #[test]
    fn nesting_deeper_than_eight_is_refused() {
        // Depth counts containers: the array is level 1 and the element object
        // level 2, so an element may carry six further arrays or objects. A
        // scalar leaf is not a level — there is nothing under it to walk.
        let mut value = json!("leaf");
        for _ in 0..6 {
            value = json!([value]);
        }
        let at_bound = json!([{"type": "payment", "deep": value.clone()}]);
        assert!(
            details(&at_bound).is_ok(),
            "refused a document at the bound"
        );

        let over = json!([{"type": "payment", "deep": json!([value])}]);
        assert_eq!(details(&over), Err(InvalidAuthorizationDetails));
    }

    /// A document nested far past the bound costs the bound, not its own depth:
    /// the walk stops at the budget.
    #[test]
    fn a_pathologically_deep_document_is_refused() {
        let raw = format!(
            "[{{\"type\":\"payment\",\"d\":{}{}}}]",
            "[".repeat(512),
            "]".repeat(512)
        );
        assert_eq!(
            AuthorizationDetails::parse(&raw),
            Err(InvalidAuthorizationDetails)
        );
    }

    /// RFC 9396 §2: the object is carried whole — its type-specific members are
    /// the authorization, and dropping one would grant something else.
    #[test]
    fn an_accepted_element_keeps_every_member() {
        let parsed = details(&json!([
            {"type": "payment", "instructedAmount": {"currency": "EUR", "amount": "30"}},
            {"type": "account"}
        ]))
        .expect("two well-formed elements");
        assert_eq!(parsed.elements().len(), 2);
        assert_eq!(parsed.elements()[0].detail_type(), "payment");
        assert_eq!(parsed.elements()[1].detail_type(), "account");
        assert_eq!(
            parsed.to_json()[0]["instructedAmount"]["currency"],
            json!("EUR")
        );
        assert_eq!(
            parsed.types(),
            ["account", "payment"].into_iter().collect::<BTreeSet<_>>()
        );
    }

    /// RFC 9396 §2.2 `locations`, gathered for the subset test its caller runs.
    #[test]
    fn locations_are_gathered_across_elements() {
        let parsed = details(&json!([
            {"type": "payment", "locations": ["https://api.example/"]},
            {"type": "account", "locations": ["https://api.example/", "https://other.example/"]}
        ]))
        .expect("two well-formed elements");
        assert_eq!(
            parsed.locations(),
            ["https://api.example/", "https://other.example/"]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
    }

    // --- the schema subset -------------------------------------------------

    fn schema(document: &Value) -> Schema {
        Schema::parse(document).expect("a supported schema")
    }

    /// A keyword outside the subset is refused at registration rather than
    /// ignored at validation.
    #[test]
    fn an_unsupported_keyword_is_refused_rather_than_ignored() {
        for keyword in ["pattern", "$ref", "oneOf", "minimum", "allOf", "not"] {
            let document = json!({ keyword: "anything" });
            assert_eq!(
                Schema::parse(&document),
                Err(SchemaError::UnsupportedKeyword(keyword.to_owned())),
                "silently accepted {keyword}"
            );
        }
    }

    /// An empty schema constrains nothing, which is JSON Schema's own meaning.
    #[test]
    fn an_empty_schema_accepts_everything() {
        let schema = schema(&json!({}));
        for value in [json!({}), json!([1]), json!("text"), json!(null)] {
            assert!(schema.accepts(&value), "refused {value}");
        }
    }

    /// `required` and `properties`, which is what a type definition is made of.
    #[test]
    fn required_members_and_their_types_are_enforced() {
        let schema = schema(&json!({
            "type": "object",
            "required": ["type", "instructedAmount"],
            "properties": {
                "instructedAmount": {
                    "type": "object",
                    "required": ["currency"],
                    "properties": {"currency": {"type": "string", "maxLength": 3}}
                }
            }
        }));
        assert!(schema.accepts(&json!({
            "type": "payment",
            "instructedAmount": {"currency": "EUR"}
        })));
        // Missing the required member.
        assert!(!schema.accepts(&json!({"type": "payment"})));
        // Present, but the nested requirement is not met.
        assert!(!schema.accepts(&json!({
            "type": "payment",
            "instructedAmount": {"amount": "30"}
        })));
        // Present, right shape, but too long for `maxLength`.
        assert!(!schema.accepts(&json!({
            "type": "payment",
            "instructedAmount": {"currency": "EURO"}
        })));
    }

    /// The acceptance criterion: "unknown extra members allowed only if the
    /// schema permits", which is `additionalProperties`.
    #[test]
    fn unknown_members_are_admitted_only_when_the_schema_permits_them() {
        let open = schema(&json!({"type": "object", "properties": {"type": {"type": "string"}}}));
        let closed = schema(&json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"type": {"type": "string"}}
        }));
        let element = json!({"type": "payment", "surprise": "extra"});
        assert!(open.accepts(&element));
        assert!(!closed.accepts(&element));
        assert!(closed.accepts(&json!({"type": "payment"})));
    }

    /// `enum`, `items` and `maxItems`, which is how `actions` gets described.
    #[test]
    fn arrays_are_bounded_and_their_items_constrained() {
        let schema = schema(&json!({
            "type": "object",
            "properties": {
                "actions": {
                    "type": "array",
                    "maxItems": 2,
                    "items": {"enum": ["read", "write"]}
                }
            }
        }));
        assert!(schema.accepts(&json!({"type": "payment", "actions": ["read"]})));
        assert!(!schema.accepts(&json!({"type": "payment", "actions": ["read", "delete"]})));
        assert!(!schema.accepts(&json!({
            "type": "payment", "actions": ["read", "write", "read"]
        })));
    }

    /// `maxLength` counts characters, not bytes: a byte count would refuse a
    /// compliant document written in a non-Latin script.
    #[test]
    fn max_length_counts_characters() {
        let schema = schema(&json!({"type": "string", "maxLength": 3}));
        assert!(schema.accepts(&json!("écu")));
        assert!(!schema.accepts(&json!("euro")));
    }

    /// A schema an operator nests past the bound is refused rather than walked.
    #[test]
    fn a_schema_deeper_than_the_bound_is_refused() {
        let mut document = json!({"type": "string"});
        for _ in 0..MAX_DEPTH + 2 {
            document = json!({"type": "object", "properties": {"next": document}});
        }
        assert_eq!(Schema::parse(&document), Err(SchemaError::TooDeep));
    }

    // --- the registry ------------------------------------------------------

    fn registry() -> AuthorizationDetailsRegistry {
        AuthorizationDetailsRegistry::new([AuthorizationDetailsType {
            name: "payment_initiation".to_owned(),
            schema: schema(&json!({
                "type": "object",
                "required": ["type", "instructedAmount"],
                "properties": {"instructedAmount": {"type": "object"}}
            })),
            consent_template: Some("Initiate a payment".to_owned()),
        }])
    }

    fn names(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    /// The acceptance criterion: a type not registered, or not allowed for the
    /// client, is `invalid_authorization_details`.
    #[test]
    fn an_unregistered_or_unpermitted_type_is_refused() {
        let registry = registry();
        let element = details(&json!([{
            "type": "payment_initiation",
            "instructedAmount": {"currency": "EUR"}
        }]))
        .expect("a well-formed element");

        // Registered and permitted: accepted.
        assert_eq!(
            registry.validate(&element, &names(&["payment_initiation"]), &BTreeSet::new()),
            Ok(())
        );
        // Registered, but this client may not ask for it.
        assert_eq!(
            registry.validate(&element, &BTreeSet::new(), &BTreeSet::new()),
            Err(InvalidAuthorizationDetails)
        );
        // Permitted for the client, but this tenant registered no such type.
        let unknown = details(&json!([{"type": "account_information"}])).expect("well-formed");
        assert_eq!(
            registry.validate(&unknown, &names(&["account_information"]), &BTreeSet::new()),
            Err(InvalidAuthorizationDetails)
        );
    }

    /// The acceptance criterion: each element is validated against its type's
    /// schema.
    #[test]
    fn an_element_failing_its_types_schema_is_refused() {
        let registry = registry();
        let missing = details(&json!([{"type": "payment_initiation"}])).expect("well-formed");
        assert_eq!(
            registry.validate(&missing, &names(&["payment_initiation"]), &BTreeSet::new()),
            Err(InvalidAuthorizationDetails)
        );
    }

    /// The acceptance criterion: `locations` is a subset of what the client may
    /// be issued a token for.
    #[test]
    fn a_location_outside_the_permitted_set_is_refused() {
        let registry = registry();
        let element = details(&json!([{
            "type": "payment_initiation",
            "instructedAmount": {"currency": "EUR"},
            "locations": ["https://api.example/"]
        }]))
        .expect("well-formed");
        assert_eq!(
            registry.validate(
                &element,
                &names(&["payment_initiation"]),
                &names(&["https://api.example/"])
            ),
            Ok(())
        );
        assert_eq!(
            registry.validate(
                &element,
                &names(&["payment_initiation"]),
                &names(&["https://other.example/"])
            ),
            Err(InvalidAuthorizationDetails)
        );
    }

    /// RFC 9396 §9.1: the advertised list is the registry and nothing else.
    #[test]
    fn supported_types_are_exactly_the_registered_ones() {
        assert_eq!(registry().supported_types(), vec!["payment_initiation"]);
        assert!(
            AuthorizationDetailsRegistry::default()
                .supported_types()
                .is_empty()
        );
    }

    /// A registry is bounded like the resource server one: a tenant with a
    /// runaway table does not turn every push into a long walk.
    #[test]
    fn a_registry_is_bounded() {
        let many = (0..MAX_REGISTERED_TYPES + 10).map(|n| AuthorizationDetailsType {
            name: format!("type-{n}"),
            schema: Schema::default(),
            consent_template: None,
        });
        assert_eq!(
            AuthorizationDetailsRegistry::new(many)
                .supported_types()
                .len(),
            MAX_REGISTERED_TYPES
        );
    }
}
