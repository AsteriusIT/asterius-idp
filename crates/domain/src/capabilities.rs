//! The feature-flag registry, and the single struct that answers "what is this
//! deployment able to do?".

use serde::{Deserialize, Serialize};

/// An optional capability that a deployment may switch on.
///
/// Every flag here is FAPI-compatible: there is no flag that weakens the
/// baseline, by [ADR-0002](../../../docs/adr/0002-fapi-2-0-as-the-only-mode.md),
/// and no `compat.rs256`, by
/// [ADR-0003](../../../docs/adr/0003-signing-algorithm-set.md). A flag that
/// changed that would need to supersede those records first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Feature {
    /// mTLS client authentication and certificate-bound tokens (RFC 8705).
    Mtls,
    /// Grant Management for OAuth 2.0 (Implementer's Draft).
    GrantManagement,
    /// CIBA Core 1.0 backchannel authentication (poll and ping).
    Ciba,
    /// Device Authorization Grant (RFC 8628).
    DeviceFlow,
    /// Token Exchange (RFC 8693) with delegation chains.
    TokenExchange,
    /// Shared Signals Framework transmitter and CAEP/RISC events.
    Ssf,
    /// AuthZEN Authorization API 1.0 policy decision point.
    Authzen,
    /// Server-issued DPoP nonces (RFC 9449 §8).
    DpopNonce,
}

impl Feature {
    /// Every flag, in a stable order. `/readyz` and the admin API iterate this.
    pub const ALL: [Self; 8] = [
        Self::Mtls,
        Self::GrantManagement,
        Self::Ciba,
        Self::DeviceFlow,
        Self::TokenExchange,
        Self::Ssf,
        Self::Authzen,
        Self::DpopNonce,
    ];

    /// The configuration key for this flag, as written in `asterius.toml`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mtls => "mtls",
            Self::GrantManagement => "grant_management",
            Self::Ciba => "ciba",
            Self::DeviceFlow => "device_flow",
            Self::TokenExchange => "token_exchange",
            Self::Ssf => "ssf",
            Self::Authzen => "authzen",
            Self::DpopNonce => "dpop_nonce",
        }
    }

    /// The flag a configuration key names, or `None` for a key this build does
    /// not know.
    ///
    /// The inverse of [`Feature::as_str`], and deliberately strict: a stored
    /// setting naming `compat_rs256` is refused rather than ignored, because a
    /// silently dropped flag is a setting an operator believes is in force.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|flag| flag.as_str() == key)
    }
}

impl std::fmt::Display for Feature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What this deployment can do.
///
/// This is the single source of truth for optional behaviour. Metadata
/// generation, route mounting and `/readyz` all read *this* struct rather than
/// consulting configuration separately, so an advertised capability and a
/// mounted route cannot drift apart — a parity test in `ast-o0t.3` asserts it.
///
/// Everything is off unless switched on. A security product should require the
/// operator to say yes, and an operator reading `/readyz` should see exactly the
/// surface they asked for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "a flag registry is a set of booleans by definition; the alternative \
              clippy suggests (a state enum) cannot express independent flags, and \
              the field names are the TOML keys operators write"
)]
pub struct Capabilities {
    /// mTLS client authentication and certificate-bound tokens (RFC 8705).
    pub mtls: bool,
    /// Grant Management for OAuth 2.0 (Implementer's Draft).
    pub grant_management: bool,
    /// CIBA Core 1.0 backchannel authentication (poll and ping).
    pub ciba: bool,
    /// Device Authorization Grant (RFC 8628).
    pub device_flow: bool,
    /// Token Exchange (RFC 8693) with delegation chains.
    pub token_exchange: bool,
    /// Shared Signals Framework transmitter and CAEP/RISC events.
    pub ssf: bool,
    /// AuthZEN Authorization API 1.0 policy decision point.
    pub authzen: bool,
    /// Server-issued DPoP nonces (RFC 9449 §8).
    pub dpop_nonce: bool,
}

impl Capabilities {
    /// Whether one flag is on.
    #[must_use]
    pub const fn is_enabled(&self, feature: Feature) -> bool {
        match feature {
            Feature::Mtls => self.mtls,
            Feature::GrantManagement => self.grant_management,
            Feature::Ciba => self.ciba,
            Feature::DeviceFlow => self.device_flow,
            Feature::TokenExchange => self.token_exchange,
            Feature::Ssf => self.ssf,
            Feature::Authzen => self.authzen,
            Feature::DpopNonce => self.dpop_nonce,
        }
    }

    /// Switches one flag off.
    ///
    /// There is no `enable`, and that is the point: a tenant may narrow what
    /// the deployment serves ([`crate::TenantSettings::effective_capabilities`])
    /// and may not widen it, so the only mutation this type offers is the safe
    /// direction.
    pub const fn disable(&mut self, feature: Feature) {
        match feature {
            Feature::Mtls => self.mtls = false,
            Feature::GrantManagement => self.grant_management = false,
            Feature::Ciba => self.ciba = false,
            Feature::DeviceFlow => self.device_flow = false,
            Feature::TokenExchange => self.token_exchange = false,
            Feature::Ssf => self.ssf = false,
            Feature::Authzen => self.authzen = false,
            Feature::DpopNonce => self.dpop_nonce = false,
        }
    }

    /// The flags that are on, in [`Feature::ALL`] order.
    pub fn enabled(&self) -> impl Iterator<Item = Feature> + '_ {
        Feature::ALL.into_iter().filter(|f| self.is_enabled(*f))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_is_off_by_default() {
        let caps = Capabilities::default();
        assert_eq!(caps.enabled().count(), 0);
        assert!(Feature::ALL.iter().all(|f| !caps.is_enabled(*f)));
    }

    /// `Feature::as_str` and the struct field it maps to must agree, or an
    /// operator's `asterius.toml` key will silently do nothing. This checks the
    /// mapping by round-tripping each flag through its own configuration key.
    #[test]
    fn every_feature_maps_to_its_own_config_key() {
        for feature in Feature::ALL {
            let toml = format!("{} = true", feature.as_str());
            let caps: Capabilities = toml::from_str(&toml)
                .unwrap_or_else(|e| panic!("key {} is not a field: {e}", feature.as_str()));
            assert!(
                caps.is_enabled(feature),
                "{feature} did not switch itself on"
            );
            assert_eq!(
                caps.enabled().collect::<Vec<_>>(),
                vec![feature],
                "{feature} switched on something else"
            );
        }
    }

    #[test]
    fn feature_all_covers_every_field() {
        // Serialising an all-on struct is the cheapest way to notice a field
        // that was added without a matching `Feature` variant.
        let json = serde_json::to_value(Capabilities {
            mtls: true,
            grant_management: true,
            ciba: true,
            device_flow: true,
            token_exchange: true,
            ssf: true,
            authzen: true,
            dpop_nonce: true,
        })
        .expect("serialise");
        let fields = json.as_object().expect("object");
        assert_eq!(
            fields.len(),
            Feature::ALL.len(),
            "Capabilities has {} fields but Feature::ALL lists {}",
            fields.len(),
            Feature::ALL.len()
        );
        for feature in Feature::ALL {
            assert!(
                fields.contains_key(feature.as_str()),
                "no field for {feature}"
            );
        }
    }

    #[test]
    fn unknown_flags_are_rejected() {
        let err = toml::from_str::<Capabilities>("compat_rs256 = true").unwrap_err();
        assert!(err.to_string().contains("compat_rs256"), "{err}");
    }
}
