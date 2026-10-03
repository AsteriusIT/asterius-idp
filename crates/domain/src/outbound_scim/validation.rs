//! Canonical identity pins before any deployment-registry or network lookup.

use super::ResourceKind;
use crate::{DomainError, TenantId};
use uuid::Uuid;

/// Both generations participate in every immutable identity. Recreating a
/// selection cannot recover an object from a previous incarnation by alias.
#[must_use]
pub fn resource_identity(
    tenant: &TenantId,
    connector: Uuid,
    kind: ResourceKind,
    source: Uuid,
    generation: Uuid,
) -> (String, String) {
    let kind = match kind {
        ResourceKind::User => "user",
        ResourceKind::Group => "group",
    };
    (
        format!(
            "ast-{}-{}-{}-{}",
            kind,
            connector.simple(),
            source.simple(),
            generation.simple()
        ),
        format!(
            "urn:asterius:outbound:{}:{}:{}:{}:{}",
            tenant.as_str(),
            connector,
            kind,
            source,
            generation
        ),
    )
}

/// The returned URL is canonical and immutable. DNS/address vetting is still
/// mandatory for every request; validating a name is not an SSRF decision.
// fuzz-target: outbound_scim_identity
pub fn canonical_issuer(input: &str) -> Result<url::Url, DomainError> {
    let parsed = url::Url::parse(input)
        .map_err(|_| DomainError::invalid("target_issuer", "invalid HTTPS issuer"))?;
    if input.len() > 2048
        || parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || input.ends_with('/')
        || (parsed.as_str() != input
            && !(parsed.path() == "/" && parsed.as_str().strip_suffix('/') == Some(input)))
        || !matches!(parsed.host(), Some(url::Host::Domain(host)) if host != "localhost" && !host.ends_with(".localhost"))
    {
        return Err(DomainError::invalid(
            "target_issuer",
            "requires a canonical fixed HTTPS issuer",
        ));
    }
    Ok(parsed)
}

/// UUID spelling must agree with SQL/JSON identity keys and remote paths.
pub fn canonical_uuid(input: &str) -> Result<Uuid, DomainError> {
    let value = Uuid::parse_str(input)
        .map_err(|_| DomainError::invalid("target_id", "invalid canonical UUID"))?;
    if value.to_string() != input {
        return Err(DomainError::invalid("target_id", "invalid canonical UUID"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incarnation_changes_every_immutable_identity() {
        let tenant = TenantId::new("source");
        let original = resource_identity(
            &tenant,
            Uuid::from_u128(1),
            ResourceKind::User,
            Uuid::from_u128(2),
            Uuid::from_u128(3),
        );
        let recreated = resource_identity(
            &tenant,
            Uuid::from_u128(1),
            ResourceKind::User,
            Uuid::from_u128(2),
            Uuid::from_u128(4),
        );
        assert_ne!(original, recreated);
        assert!(original.0.len() <= 200);
        assert!(original.1.len() <= 256);
    }

    #[test]
    fn resource_kind_is_part_of_the_external_ownership_namespace() {
        let tenant = TenantId::new("source");
        let user = resource_identity(
            &tenant,
            Uuid::from_u128(1),
            ResourceKind::User,
            Uuid::from_u128(2),
            Uuid::from_u128(3),
        );
        let group = resource_identity(
            &tenant,
            Uuid::from_u128(1),
            ResourceKind::Group,
            Uuid::from_u128(2),
            Uuid::from_u128(3),
        );
        assert_ne!(user.0, group.0);
        assert_ne!(user.1, group.1);
    }

    #[test]
    fn issuer_refuses_alias_spellings_and_untrusted_url_components() {
        assert!(canonical_issuer("https://idp.example/t/target").is_ok());
        assert!(canonical_issuer("https://idp.example").is_ok());
        for invalid in [
            "http://idp.example/t/target",
            "https://user@idp.example/t/target",
            "https://idp.example/t/target/",
            "https://idp.example/t/target?x=1",
            "https://idp.example/t/target#x",
            "https://IDP.example/t/target",
            "https://127.0.0.1/t/target",
            "https://localhost/t/target",
        ] {
            assert!(canonical_issuer(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn uuid_spelling_cannot_create_a_second_authority_key() {
        let id = Uuid::from_u128(0xabcdef);
        assert_eq!(canonical_uuid(&id.to_string()).expect("canonical"), id);
        assert!(canonical_uuid(&id.simple().to_string()).is_err());
        assert!(canonical_uuid(&id.to_string().to_uppercase()).is_err());
    }
}
