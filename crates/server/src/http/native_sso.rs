//! Native SSO device secret issuance and digest binding (draft-07 §3).

use asterius_domain::{DomainError, Grant};
use asterius_store_pg::PgNativeSso;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

/// Native SSO draft-07 §4.1 actor token type.
pub const DEVICE_SECRET_TYPE: &str = "urn:openid:params:token-type:device-secret";

/// The bearer secret is exposed only in the token response.
pub struct IssuedSecret {
    pub value: String,
    pub ds_hash: String,
}

impl std::fmt::Debug for IssuedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedSecret")
            .field("value", &"<redacted>")
            .field("ds_hash", &self.ds_hash)
            .finish()
    }
}

/// SHA-256 of the exact ASCII secret octets, including no padding.
#[must_use]
pub fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// Reuses a valid secret for this grant, otherwise issues a new one.
/// A malformed or stale presented secret is treated as absent per draft-07 §3.4.
pub async fn issue(
    store: &PgNativeSso,
    grant: &Grant,
    sid: &str,
    presented: Option<&str>,
    now: OffsetDateTime,
) -> Result<IssuedSecret, DomainError> {
    let user = grant
        .user
        .ok_or_else(|| DomainError::invalid("device_sso", "grant has no user"))?;
    if let Some(value) = presented.filter(|value| value.len() == 43 && value.bytes().all(is_b64url))
    {
        let hash = digest(value);
        if store.binding(&hash, now).await?.is_some_and(|binding| {
            binding.source_client == grant.client
                && binding.source_grant == grant.id
                && binding.user == user
                && binding.public_sid == sid
        }) {
            return Ok(IssuedSecret {
                value: value.to_owned(),
                ds_hash: B64.encode(hash),
            });
        }
    }
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random)
        .map_err(|_| DomainError::invalid("device_sso", "OS randomness unavailable"))?;
    let value = B64.encode(random);
    let hash = digest(&value);
    if !store
        .issue(&hash, &grant.client, &grant.id, &user, sid, now)
        .await?
    {
        return Err(DomainError::invalid(
            "device_sso",
            "source session is no longer active",
        ));
    }
    Ok(IssuedSecret {
        value,
        ds_hash: B64.encode(hash),
    })
}

const fn is_b64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}
