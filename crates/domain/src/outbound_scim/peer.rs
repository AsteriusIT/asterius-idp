//! Bounded peer metadata/token parsing; credential bytes never enter diagnostics.

use super::{FailureCode, MAX_RESPONSE_BYTES};
use crate::Secret;
use serde::Deserialize;

#[derive(Deserialize)]
struct TokenDocument {
    #[serde(deserialize_with = "secret_string")]
    access_token: Secret<String>,
    token_type: String,
    expires_in: u32,
    scope: Option<String>,
}
fn secret_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Secret<String>, D::Error> {
    String::deserialize(deserializer).map(Secret::new)
}

pub struct PeerToken {
    pub access_token: Secret<String>,
    pub expires_in: u32,
}
impl std::fmt::Debug for PeerToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerToken")
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

// fuzz-target: outbound_scim_peer
pub fn parse_peer_token(bytes: &[u8]) -> Result<PeerToken, FailureCode> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(FailureCode::AuthenticationRefused);
    }
    let document: TokenDocument =
        serde_json::from_slice(bytes).map_err(|_| FailureCode::AuthenticationRefused)?;
    if !document.token_type.eq_ignore_ascii_case("DPoP")
        || document.expires_in == 0
        || document.expires_in > 3600
        || document.access_token.expose().is_empty()
        || document.access_token.expose().len() > 16 * 1024
        || document.scope.as_deref().is_some_and(|scopes| {
            !["admin.scim:read", "admin.scim:write"]
                .iter()
                .all(|required| {
                    scopes
                        .split_ascii_whitespace()
                        .any(|scope| scope == *required)
                })
        })
    {
        return Err(FailureCode::AuthenticationRefused);
    }
    Ok(PeerToken {
        access_token: document.access_token,
        expires_in: document.expires_in,
    })
}

pub const INCARNATION_PROTECTION_SCHEMA: &str =
    "urn:asterius:params:scim:schemas:extension:OutboundIncarnations:2.0:ServiceProviderConfig";

// fuzz-target: outbound_scim_peer
pub fn parse_peer_capabilities(bytes: &[u8]) -> Result<(), FailureCode> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(FailureCode::SourceProjectionInvalid);
    }
    let document: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| FailureCode::SourceProjectionInvalid)?;
    let schemas = document
        .get("schemas")
        .and_then(serde_json::Value::as_array);
    if schemas.is_none_or(|schemas| {
        schemas.len() != 2
            || !schemas.iter().any(|schema| {
                schema.as_str()
                    == Some("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig")
            })
            || !schemas
                .iter()
                .any(|schema| schema.as_str() == Some(INCARNATION_PROTECTION_SCHEMA))
    }) || document
        .pointer("/filter/supported")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
        || document
            .pointer("/filter/maxResults")
            .and_then(serde_json::Value::as_u64)
            .is_none_or(|max| max < 2)
        || document
            .pointer("/etag/supported")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || document.get(INCARNATION_PROTECTION_SCHEMA)
            != Some(&serde_json::json!({
                "supported":true,"namespace":"urn:asterius:outbound:","maxRetiredPerClientKind":10000,"automaticExpiry":false,"reservedUserDeleteReleasesEmail":true
            }))
    {
        return Err(FailureCode::SourceProjectionInvalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bearer_or_missing_scope_or_unbounded_token_lifetime_is_refused() {
        for document in [
            serde_json::json!({"access_token":"private","token_type":"Bearer","expires_in":60}),
            serde_json::json!({"access_token":"private","token_type":"DPoP","expires_in":3601}),
            serde_json::json!({"access_token":"private","token_type":"DPoP","expires_in":60,"scope":"admin.scim:read"}),
        ] {
            assert!(parse_peer_token(&serde_json::to_vec(&document).unwrap()).is_err());
        }
        let token =
            parse_peer_token(br#"{"access_token":"private","token_type":"DPoP","expires_in":60}"#)
                .unwrap();
        assert!(!format!("{token:?}").contains("private"));
    }
    #[test]
    fn discovery_without_versioned_writes_or_exact_scim_schema_cannot_enable_peer() {
        let good = serde_json::json!({"schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig", INCARNATION_PROTECTION_SCHEMA],"filter":{"supported":true,"maxResults":200},"etag":{"supported":true},INCARNATION_PROTECTION_SCHEMA:{"supported":true,"namespace":"urn:asterius:outbound:","maxRetiredPerClientKind":10000,"automaticExpiry":false,"reservedUserDeleteReleasesEmail":true}});
        assert!(parse_peer_capabilities(&serde_json::to_vec(&good).unwrap()).is_ok());
        let mut bad = good.clone();
        bad["etag"]["supported"] = serde_json::json!(false);
        assert!(parse_peer_capabilities(&serde_json::to_vec(&bad).unwrap()).is_err());
        let mut reordered = good.clone();
        reordered["schemas"].as_array_mut().unwrap().reverse();
        assert!(parse_peer_capabilities(&serde_json::to_vec(&reordered).unwrap()).is_ok());
        let mut absent = good.clone();
        absent
            .as_object_mut()
            .unwrap()
            .remove(INCARNATION_PROTECTION_SCHEMA);
        assert!(parse_peer_capabilities(&serde_json::to_vec(&absent).unwrap()).is_err());
        let mut old_peer = good.clone();
        old_peer[INCARNATION_PROTECTION_SCHEMA]
            .as_object_mut()
            .unwrap()
            .remove("reservedUserDeleteReleasesEmail");
        assert!(parse_peer_capabilities(&serde_json::to_vec(&old_peer).unwrap()).is_err());
        let mut retaining_peer = good.clone();
        retaining_peer[INCARNATION_PROTECTION_SCHEMA]["reservedUserDeleteReleasesEmail"] =
            serde_json::json!(false);
        assert!(parse_peer_capabilities(&serde_json::to_vec(&retaining_peer).unwrap()).is_err());
        let mut bad = good;
        bad["schemas"] = serde_json::json!([]);
        assert!(parse_peer_capabilities(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}
