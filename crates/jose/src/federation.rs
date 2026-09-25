//! Bounded, offline OpenID Federation 1.1 trust-chain validation.
//!
//! Fetching, caching and registration are separate trust boundaries. This
//! validator accepts only a complete chain supplied by its caller.
//! No caller can obtain leaf metadata through this API before all signatures
//! have been checked back to a tenant-pinned trust anchor.

use crate::{ClientKeySet, Unverified, client_keys::keys_from_jwk_set, jws};
use asterius_domain::{Issuer, Kid, TenantId};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use time::OffsetDateTime;

mod policy;

/// Bounds a compact Entity Statement before base64 decoding or JSON parsing.
pub const MAX_STATEMENT_BYTES: usize = 65_536;
/// Bounds the number of hops, including leaf and trust-anchor configurations.
pub const MAX_CHAIN_STATEMENTS: usize = 8;
/// Bounds an operator-pinned trust-anchor JWK Set.
pub const MAX_ANCHOR_JWKS_BYTES: usize = 32_768;

/// Why an offered chain cannot establish trust. Never includes JWT contents.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// An input exceeds its fixed resource budget.
    #[error("Federation trust-chain resource limit exceeded")]
    TooLarge,
    /// Structure, identity, timestamp or key metadata is invalid.
    #[error("invalid Federation trust chain: {0}")]
    Invalid(&'static str),
    /// A signature did not verify under the key the chain delegates.
    #[error("Federation Entity Statement signature is invalid")]
    Signature,
    /// A valid-looking extension needs a separate implementation boundary.
    #[error("unsupported Federation chain feature: {0}")]
    Unsupported(&'static str),
}

/// A trust anchor explicitly pinned for one tenant. Construct this from
/// operator-controlled configuration, never from an unverified statement.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    tenant: TenantId,
    entity_id: Issuer,
    keys: ClientKeySet,
}

impl TrustAnchor {
    /// Entity Identifier fixed by operator configuration.
    #[must_use]
    pub fn entity_id(&self) -> &str {
        self.entity_id.as_str()
    }

    /// Validates the pinned JWK Set before it can be used as a trust root.
    pub fn new(tenant: TenantId, entity_id: Issuer, jwks: &Value) -> Result<Self, ChainError> {
        let bytes = serde_json::to_vec(jwks).map_err(|_| ChainError::Invalid("anchor JWKS"))?;
        if bytes.len() > MAX_ANCHOR_JWKS_BYTES {
            return Err(ChainError::TooLarge);
        }
        let keys = keys_from_jwk_set(jwks).map_err(|_| ChainError::Invalid("anchor JWKS"))?;
        if keys.is_empty()
            || keys
                .keys()
                .iter()
                .any(|key| key.kid().is_none_or(|kid| kid.as_str().is_empty()))
        {
            return Err(ChainError::Invalid("anchor keys need nonempty kid values"));
        }
        Ok(Self {
            tenant,
            entity_id,
            keys,
        })
    }

    /// Validates a complete chain ordered leaf first, trust anchor last.
    /// This API never fetches or trusts a key named by an unverified URL.
    pub fn validate(
        &self,
        tenant: &TenantId,
        compact_statements: &[&str],
        now: OffsetDateTime,
    ) -> Result<VerifiedChain, ChainError> {
        if tenant != &self.tenant {
            return Err(ChainError::Invalid("tenant mismatch"));
        }
        if !(3..=MAX_CHAIN_STATEMENTS).contains(&compact_statements.len()) {
            return Err(ChainError::Invalid("incomplete or overlong chain"));
        }
        let mut statements = compact_statements
            .iter()
            .map(|raw| Statement::parse(raw, now))
            .collect::<Result<Vec<_>, _>>()?;
        let last = statements.len() - 1;

        if statements[0].claims.iss != statements[0].claims.sub {
            return Err(ChainError::Invalid("leaf is not an Entity Configuration"));
        }
        if statements[last].claims.iss != self.entity_id.as_str()
            || statements[last].claims.sub != self.entity_id.as_str()
        {
            return Err(ChainError::Invalid(
                "chain ends at a different trust anchor",
            ));
        }
        let mut issuers = HashSet::new();
        for (index, statement) in statements.iter().enumerate() {
            if index > 0 && index < last && statement.claims.iss == statement.claims.sub {
                return Err(ChainError::Invalid(
                    "a subordinate statement is self-issued",
                ));
            }
            // The last subordinate statement and the trust anchor's own
            // configuration have the same issuer by design. Any earlier
            // repeated issuer is a cycle in the path from leaf to anchor.
            if index < last && !issuers.insert(statement.claims.iss.as_str()) {
                return Err(ChainError::Invalid("entity cycle in trust chain"));
            }
            if index < last && statement.claims.iss != statements[index + 1].claims.sub {
                return Err(ChainError::Invalid("issuer and next subject disagree"));
            }
        }
        let first_superior = &statements[1].claims.iss;
        if !statements[0]
            .claims
            .authority_hints
            .as_ref()
            .is_some_and(|hints| hints.iter().any(|hint| hint == first_superior))
        {
            return Err(ChainError::Invalid(
                "leaf does not name its immediate superior",
            ));
        }

        // Verify from the pinned anchor downward. A subordinate statement's
        // JWKS becomes usable only after its own signature was authenticated.
        verify_with(&statements[last], &self.keys)?;
        let anchor_keys = statement_keys(&statements[last])?;
        verify_with(&statements[last], &anchor_keys)?;
        for index in (0..last).rev() {
            let parent_keys = statement_keys(&statements[index + 1])?;
            verify_with(&statements[index], &parent_keys)?;
        }
        // Federation §10.2 separately requires the leaf self-signature to
        // validate against the keys in its own Entity Configuration.
        let leaf_keys = statement_keys(&statements[0])?;
        verify_with(&statements[0], &leaf_keys)?;

        let expires_at = statements
            .iter()
            .map(|statement| statement.claims.exp)
            .min()
            .ok_or(ChainError::Invalid("empty chain"))?;
        let metadata = policy::resolve(&statements)?;
        let relying_party = metadata
            .get("openid_relying_party")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()
            .map_err(|_| ChainError::Invalid("resolved RP metadata"))?;
        let leaf = statements.remove(0);
        Ok(VerifiedChain {
            leaf_entity_id: leaf.claims.iss,
            anchor_entity_id: self.entity_id.as_str().to_owned(),
            expires_at,
            metadata,
            relying_party,
        })
    }

    /// Validates a fetched chain and the intermediate Entity Configurations
    /// used to discover its fetch endpoints. Configurations are ordered from
    /// the leaf's immediate superior up to (but excluding) the trust anchor.
    pub fn validate_with_intermediates(
        &self,
        tenant: &TenantId,
        compact_statements: &[&str],
        intermediate_configurations: &[&str],
        now: OffsetDateTime,
    ) -> Result<VerifiedChain, ChainError> {
        if intermediate_configurations.len() + 3 != compact_statements.len() {
            return Err(ChainError::Invalid("intermediate configuration count"));
        }
        let verified = self.validate(tenant, compact_statements, now)?;
        for (offset, raw) in intermediate_configurations.iter().enumerate() {
            let index = offset + 1;
            let configuration = Statement::parse(raw, now)?;
            let delegation = Statement::parse(compact_statements[index + 1], now)?;
            if configuration.claims.iss != configuration.claims.sub
                || configuration.claims.sub != delegation.claims.sub
            {
                return Err(ChainError::Invalid("intermediate configuration identity"));
            }
            if !configuration
                .claims
                .authority_hints
                .as_ref()
                .is_some_and(|hints| hints.contains(&delegation.claims.iss))
            {
                return Err(ChainError::Invalid("intermediate authority hint"));
            }
            let delegated_keys = statement_keys(&delegation)?;
            verify_with(&configuration, &delegated_keys)?;
            let self_keys = statement_keys(&configuration)?;
            verify_with(&configuration, &self_keys)?;
        }
        Ok(verified)
    }
}

/// Metadata that passed every signature, path and lifetime check.
#[derive(Debug, Clone)]
pub struct VerifiedChain {
    leaf_entity_id: String,
    anchor_entity_id: String,
    expires_at: i64,
    metadata: Value,
    relying_party: Option<FederationRelyingPartyMetadata>,
}

/// The trusted OpenID RP metadata available to a later registration boundary.
/// The registration flow still must validate URLs, keys and grant compatibility.
#[derive(Debug, Clone, Deserialize)]
pub struct FederationRelyingPartyMetadata {
    /// Redirect URIs offered by the RP.
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    /// Response types offered by the RP.
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    /// Grant types offered by the RP.
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    /// Federation registration modes offered by the RP.
    #[serde(default)]
    pub client_registration_types: Option<Vec<String>>,
    /// Client authentication method requested by the RP.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// RP signing keys, if carried by resolved metadata.
    #[serde(default)]
    pub jwks: Option<Value>,
    /// Reference to RP signing keys, if present.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Reference to signed RP keys, if present.
    #[serde(default)]
    pub signed_jwks_uri: Option<String>,
    /// Other resolved RP metadata, retained for later registration checks.
    #[serde(flatten)]
    pub other: serde_json::Map<String, Value>,
}

impl VerifiedChain {
    /// The leaf Entity Identifier.
    #[must_use]
    pub fn leaf_entity_id(&self) -> &str {
        &self.leaf_entity_id
    }

    /// The configured trust anchor that closed the chain.
    #[must_use]
    pub fn anchor_entity_id(&self) -> &str {
        &self.anchor_entity_id
    }

    /// The earliest expiration of any statement in the chain, in Unix seconds.
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Resolved leaf metadata after superior overrides, constraints and policy.
    #[must_use]
    pub fn metadata(&self) -> &Value {
        &self.metadata
    }

    /// Typed RP metadata, present only when the verified and resolved leaf
    /// declares the `openid_relying_party` Entity Type.
    #[must_use]
    pub fn relying_party_metadata(&self) -> Option<&FederationRelyingPartyMetadata> {
        self.relying_party.as_ref()
    }
}

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    iat: i64,
    exp: i64,
    jwks: Value,
    #[serde(default)]
    authority_hints: Option<Vec<String>>,
    #[serde(default)]
    metadata: Option<Value>,
    #[serde(flatten)]
    other: serde_json::Map<String, Value>,
}

#[derive(Debug)]
struct Statement {
    token: Unverified,
    claims: Claims,
}

impl Statement {
    fn parse(raw: &str, now: OffsetDateTime) -> Result<Self, ChainError> {
        if raw.len() > MAX_STATEMENT_BYTES {
            return Err(ChainError::TooLarge);
        }
        let token = jws::parse(raw).map_err(|_| ChainError::Invalid("compact JWS"))?;
        if token.claimed_typ() != Some("entity-statement+jwt") {
            return Err(ChainError::Invalid("entity statement typ"));
        }
        let kid = token.kid().ok_or(ChainError::Invalid("missing kid"))?;
        if kid.as_str().is_empty() {
            return Err(ChainError::Invalid("empty kid"));
        }
        let header: Value = serde_json::from_slice(token.raw_header())
            .map_err(|_| ChainError::Invalid("JWS header"))?;
        let members = header
            .as_object()
            .ok_or(ChainError::Invalid("JWS header is not an object"))?;
        if members
            .keys()
            .any(|name| !matches!(name.as_str(), "alg" | "typ" | "kid"))
        {
            return Err(ChainError::Unsupported("JWS header extension"));
        }
        let raw_claims: Value = serde_json::from_slice(token.unverified_payload())
            .map_err(|_| ChainError::Invalid("Entity Statement claims"))?;
        let claim_members = raw_claims.as_object().ok_or(ChainError::Invalid(
            "Entity Statement claims are not an object",
        ))?;
        if ["metadata", "authority_hints"]
            .into_iter()
            .any(|field| claim_members.get(field).is_some_and(Value::is_null))
        {
            return Err(ChainError::Invalid("null Entity Statement claim"));
        }
        let claims: Claims = serde_json::from_slice(token.unverified_payload())
            .map_err(|_| ChainError::Invalid("Entity Statement claims"))?;
        valid_entity_id(&claims.iss)?;
        valid_entity_id(&claims.sub)?;
        if claims.iat >= now.unix_timestamp()
            || claims.exp <= now.unix_timestamp()
            || claims.exp <= claims.iat
        {
            return Err(ChainError::Invalid("Entity Statement lifetime"));
        }
        if claims.other.contains_key("crit")
            || claims.other.contains_key("trust_marks")
            || claims.other.contains_key("trust_mark_issuers")
            || claims.other.contains_key("trust_mark_owners")
            || claims.other.contains_key("trust_anchor_hints")
            || claims.other.contains_key("ref")
            || claims.other.contains_key("delegation")
        {
            return Err(ChainError::Unsupported("critical claim or trust mark"));
        }
        if let Some(source) = claims.other.get("source_endpoint") {
            let source = source
                .as_str()
                .ok_or(ChainError::Invalid("source_endpoint"))?;
            let url =
                url::Url::parse(source).map_err(|_| ChainError::Invalid("source_endpoint"))?;
            if claims.iss == claims.sub
                || url.scheme() != "https"
                || url.host().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(ChainError::Invalid("source_endpoint"));
            }
        }
        if let Some(hints) = &claims.authority_hints {
            if claims.iss != claims.sub || hints.is_empty() {
                return Err(ChainError::Invalid(
                    "authority hints on a non-configuration",
                ));
            }
            for hint in hints {
                valid_entity_id(hint)?;
            }
        }
        if let Some(metadata) = &claims.metadata {
            let members = metadata
                .as_object()
                .ok_or(ChainError::Invalid("metadata is not an object"))?;
            if members.values().any(|value| !value.is_object()) {
                return Err(ChainError::Invalid("entity-type metadata is not an object"));
            }
            if members.values().any(|value| {
                value
                    .as_object()
                    .is_some_and(|fields| fields.values().any(Value::is_null))
            }) {
                return Err(ChainError::Invalid("null metadata value"));
            }
        }
        Ok(Self { token, claims })
    }
}

fn valid_entity_id(raw: &str) -> Result<(), ChainError> {
    if raw.len() > 2048 {
        return Err(ChainError::TooLarge);
    }
    let canonical = Issuer::parse(raw).map_err(|_| ChainError::Invalid("entity identifier"))?;
    if canonical.as_str() != raw {
        return Err(ChainError::Invalid("noncanonical entity identifier"));
    }
    Ok(())
}

fn statement_keys(statement: &Statement) -> Result<ClientKeySet, ChainError> {
    keys_from_jwk_set(&statement.claims.jwks).map_err(|_| ChainError::Invalid("statement JWKS"))
}

fn verify_with(statement: &Statement, keys: &ClientKeySet) -> Result<(), ChainError> {
    let kid: Kid = statement
        .token
        .kid()
        .ok_or(ChainError::Invalid("missing kid"))?;
    let candidates = keys
        .keys()
        .iter()
        .filter(|key| key.kid() == Some(&kid))
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Err(ChainError::Invalid("kid is absent or ambiguous in JWKS"));
    }
    statement
        .token
        .clone()
        .verify(candidates[0].key())
        .map_err(|_| ChainError::Signature)?;
    Ok(())
}
