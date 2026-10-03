//! Dedicated operator device PKI, independent of OAuth and outbound roots.
//! The immediate trusted TLS terminator must verify key possession, strip the
//! caller's field and forward only the actual verified leaf over a protected hop.
//! DER parsing, enrollment fingerprint matching and chain validation alone do
//! not prove possession. This adapter is not hardware attestation.
use asterius_domain::managed_devices::LeafFingerprint;
use asterius_domain::TenantId;
use axum::http::HeaderMap;
use ipnet::IpNet;
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::OffsetDateTime;

pub const DEFAULT_DEVICE_CERTIFICATE_HEADER: &str = "x-device-client-cert";
const MAX_ANCHOR_BYTES: usize = 256 * 1024;
const MAX_ANCHORS: usize = 32;

/// No roots means no managed-device authority. The header is separate from the
/// OAuth client-authentication field and is interpreted only behind the proxy.
#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub certificate_header: String,
    pub trust_anchors: BTreeMap<TenantId, PathBuf>,
    /// Authenticated TLS from the exact pinned edge proxy to this listener.
    pub proxy_hop: Option<ProxyHopConfig>,
}
impl Default for DeviceConfig {
    fn default() -> Self {
        Self { certificate_header: DEFAULT_DEVICE_CERTIFICATE_HEADER.to_owned(), trust_anchors: BTreeMap::new(), proxy_hop: None }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyHopConfig {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub trust_anchors: PathBuf,
    pub client_fingerprints: Vec<LeafFingerprint>,
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceAnchorError {
    #[error("cannot read managed-device trust bundle")]
    Read(#[from] std::io::Error),
    #[error("managed-device trust bundle is invalid or exceeds its bounds")]
    Invalid,
}

/// Evidence inserted exclusively by the TLS accept adapter after a verified
/// proxy client handshake and exact operator pin match. No HTTP header or
/// configuration boolean can construct this proof.
#[derive(Clone)]
pub struct VerifiedProxyHop {
    expires_at: OffsetDateTime,
}
impl VerifiedProxyHop {
    /// Called only by the rustls acceptor configured with the dedicated client
    /// verifier. Peer certificates exist only after a verified TLS handshake.
    pub(crate) fn from_authenticated_tls(
        connection: &rustls::ServerConnection,
        pins: &[LeafFingerprint],
    ) -> Option<Self> {
        if connection.is_handshaking() { return None; }
        let leaf = connection.peer_certificates()?.first()?;
        let digest = hex::encode(Sha256::digest(leaf.as_ref()));
        if !pins.iter().any(|pin| pin.as_str() == digest) { return None; }
        let (remaining, certificate) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
        let now = OffsetDateTime::now_utc();
        let expires_at = OffsetDateTime::from_unix_timestamp(certificate.validity().not_after.timestamp()).ok()?;
        if !remaining.is_empty() || certificate.validity().not_before.timestamp() > now.unix_timestamp() || expires_at <= now {
            return None;
        }
        Some(Self { expires_at })
    }
}
impl std::fmt::Debug for VerifiedProxyHop {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedProxyHop([authenticated transport])")
    }
}

/// The immediate hop must be authenticated independently of the device leaf.
/// This grouping keeps the transport evidence explicit at the verifier boundary.
pub struct DeviceProxyRequest<'a> {
    pub hop: &'a VerifiedProxyHop,
    pub peer: IpAddr,
    pub headers: &'a HeaderMap,
    pub trusted_proxies: &'a [IpNet],
    pub header_name: &'a str,
}

impl std::fmt::Debug for DeviceProxyRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DeviceProxyRequest")
            .field("hop", &self.hop)
            .field("peer", &self.peer)
            .field("headers", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct DeviceTrustRoots {
    anchors: crate::mtls::TrustAnchors,
    certificates: Vec<CertificateDer<'static>>,
    revision: LeafFingerprint,
}
impl DeviceTrustRoots {
    /// Load a bounded, explicit CA-only operator bundle; do not inherit roots.
    ///
    /// # Errors
    /// Refuses unreadable, empty, oversized, ambiguous or non-CA certificates.
    pub fn load(path: &Path) -> Result<Self, DeviceAnchorError> {
        use std::io::Read as _;
        let file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.take(u64::try_from(MAX_ANCHOR_BYTES + 1).map_err(|_| DeviceAnchorError::Invalid)?).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_ANCHOR_BYTES { return Err(DeviceAnchorError::Invalid); }
        let certificates = CertificateDer::pem_slice_iter(&bytes)
            .collect::<Result<Vec<_>, _>>().map_err(|_| DeviceAnchorError::Invalid)?;
        if certificates.is_empty() || certificates.len() > MAX_ANCHORS {
            return Err(DeviceAnchorError::Invalid);
        }
        let mut roots = Vec::with_capacity(certificates.len());
        for der in certificates {
            if der.len() > asterius_oidc::mtls::MAX_CERTIFICATE_LEN { return Err(DeviceAnchorError::Invalid); }
            let (remaining, certificate) = x509_parser::parse_x509_certificate(&der)
                .map_err(|_| DeviceAnchorError::Invalid)?;
            let ca = certificate.basic_constraints().map_err(|_| DeviceAnchorError::Invalid)?;
            let usage = certificate.key_usage().map_err(|_| DeviceAnchorError::Invalid)?;
            if !remaining.is_empty() || ca.is_none_or(|extension| !extension.value.ca)
                || usage.is_some_and(|extension| !extension.value.key_cert_sign())
            { return Err(DeviceAnchorError::Invalid); }
            webpki::anchor_from_trusted_cert(&der).map_err(|_| DeviceAnchorError::Invalid)?;
            roots.push(der.as_ref().to_vec());
        }
        roots.sort();
        roots.dedup();
        let mut digest = Sha256::new();
        digest.update(b"asterius/managed-device-relay/v1/anchors\0");
        for root in &roots {
            // Every root was bounded at 16KiB, so its length fits u64.
            digest.update(u64::try_from(root.len()).map_err(|_| DeviceAnchorError::Invalid)?.to_be_bytes());
            digest.update(root);
        }
        let revision = LeafFingerprint::parse(&hex::encode(digest.finalize()))
            .map_err(|_| DeviceAnchorError::Invalid)?;
        let certificates = roots.iter().cloned().map(CertificateDer::from).collect();
        Ok(Self { anchors: crate::mtls::TrustAnchors::from_der(roots), certificates, revision })
    }

    pub(crate) fn certificates(&self) -> &[CertificateDer<'static>] { &self.certificates }

    /// This is operator-derived, never a digest supplied by a browser or relay.
    #[must_use]
    pub fn revision(&self) -> &LeafFingerprint { &self.revision }

    /// Verify a trusted proxy's actual leaf with explicit clientAuth/end-entity
    /// usage, lifetime and chain. The source/enrollment/user/app match happens
    /// later on the exact interaction row; this object alone grants no access.
    #[must_use]
    pub fn verify_proxy_leaf(
        &self,
        request: DeviceProxyRequest<'_>,
        now: OffsetDateTime,
    ) -> Option<VerifiedDeviceLeaf> {
        let DeviceProxyRequest { hop, peer, headers, trusted_proxies, header_name } = request;
        // Presence of this private type is established only by the TLS adapter.
        if hop.expires_at <= now { return None; }
        let presented = crate::mtls::device_from_proxy_header(peer, headers, trusted_proxies, header_name)?;
        let (remaining, certificate) = x509_parser::parse_x509_certificate(presented.leaf.as_der()).ok()?;
        let ca = certificate.basic_constraints().ok()?;
        let usage = certificate.extended_key_usage().ok()??;
        if !remaining.is_empty() || certificate.subject() == certificate.issuer()
            || ca.is_some_and(|extension| extension.value.ca) || !usage.value.client_auth
        { return None; }
        let expires_at = OffsetDateTime::from_unix_timestamp(certificate.validity().not_after.timestamp()).ok()?;
        if expires_at <= now || !self.anchors.accepts(&presented.leaf, &presented.intermediates, now) {
            return None;
        }
        let leaf = LeafFingerprint::parse(&hex::encode(presented.leaf.thumbprint())).ok()?;
        Some(VerifiedDeviceLeaf { leaf, anchor: self.revision.clone(), expires_at: expires_at.min(hop.expires_at) })
    }
}

/// Created only by the configured trusted proxy plus dedicated PKI adapter.
/// It conveys verified leaf possession, not posture or an enrolled user.
#[derive(Clone)]
pub struct VerifiedDeviceLeaf {
    leaf: LeafFingerprint,
    anchor: LeafFingerprint,
    expires_at: OffsetDateTime,
}
impl std::fmt::Debug for VerifiedDeviceLeaf {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedDeviceLeaf([private certificate evidence])")
    }
}
impl VerifiedDeviceLeaf {
    /// Explicit fresh request carrier, created only from verified transport.
    #[must_use]
    pub fn request_evidence(&self) -> DeviceRequestEvidence {
        DeviceRequestEvidence {
            certificate: asterius_domain::managed_devices::DeviceCertificateEvidence {
                leaf: self.leaf.clone(), anchor: self.anchor.clone(), expires_at: self.expires_at,
            },
            digest: asterius_domain::sha256_hex(uuid::Uuid::new_v4().as_bytes()),
        }
    }

    #[must_use]
    pub fn leaf(&self) -> &LeafFingerprint { &self.leaf }
    #[must_use]
    pub fn anchor(&self) -> &LeafFingerprint { &self.anchor }
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime { self.expires_at }
}

#[derive(Debug, Clone, Default)]
pub struct TenantDeviceRoots(BTreeMap<TenantId, Arc<DeviceTrustRoots>>);
impl TenantDeviceRoots {
    /// Load every explicitly configured tenant bundle at startup.
    ///
    /// # Errors
    /// A bad configured bundle fails startup instead of silently losing trust.
    pub fn load(config: &DeviceConfig) -> Result<Self, DeviceAnchorError> {
        let hop_revision = config.proxy_hop.as_ref().map(|hop| {
            let roots = DeviceTrustRoots::load(&hop.trust_anchors)?;
            let mut pins: Vec<_> = hop.client_fingerprints.iter().map(LeafFingerprint::as_str).collect();
            pins.sort_unstable();
            pins.dedup();
            if pins.is_empty() || pins.len() > MAX_ANCHORS { return Err(DeviceAnchorError::Invalid); }
            let mut hash = Sha256::new();
            hash.update(b"asterius/device-proxy-hop/v1\0");
            hash.update(roots.revision().as_str());
            for pin in pins { hash.update(pin); }
            Ok(hex::encode(hash.finalize()))
        }).transpose()?;
        if !config.trust_anchors.is_empty() && hop_revision.is_none() { return Err(DeviceAnchorError::Invalid); }
        let roots = config.trust_anchors.iter().map(|(tenant, path)| {
            let mut roots = DeviceTrustRoots::load(path)?;
            if let Some(hop) = &hop_revision {
                let mut hash = Sha256::new();
                hash.update(b"asterius/managed-device-relay/v1/complete-trust\0");
                hash.update(roots.revision().as_str());
                hash.update(hop);
                roots.revision = LeafFingerprint::parse(&hex::encode(hash.finalize()))
                    .map_err(|_| DeviceAnchorError::Invalid)?;
            }
            Ok((tenant.clone(), Arc::new(roots)))
        }).collect::<Result<_, DeviceAnchorError>>()?;
        Ok(Self(roots))
    }
    #[must_use]
    pub fn for_tenant(&self, tenant: &TenantId) -> Option<&Arc<DeviceTrustRoots>> { self.0.get(tenant) }
    #[must_use]
    pub fn revisions(&self) -> Arc<BTreeMap<String, LeafFingerprint>> {
        Arc::new(self.0.iter().map(|(tenant, roots)| (tenant.as_str().to_owned(), roots.revision().clone())).collect())
    }
}

/// Never deserialized; this exact request's TLS evidence and server-owned nonce.
#[derive(Debug, Clone)]
pub struct DeviceRequestEvidence {
    certificate: asterius_domain::managed_devices::DeviceCertificateEvidence,
    digest: String,
}
impl DeviceRequestEvidence {
    pub async fn bind(&self, store: &asterius_store_pg::Store, tenant: &asterius_domain::TenantId, grant: &asterius_domain::Grant, now: OffsetDateTime)
        -> Result<Option<asterius_domain::managed_devices::DeviceBinding>, asterius_domain::DomainError> {
        asterius_store_pg::PgManagedDevices::bind_request_in(store.pool(),tenant,grant,&self.certificate,&self.digest,now).await
    }
    #[must_use]
    pub fn certificate(&self) -> &asterius_domain::managed_devices::DeviceCertificateEvidence { &self.certificate }
}

/// Shared explicit request input for grant handlers; cloning borrows preserves
/// this request's original possession deadline and nonce.
#[derive(Debug, Clone, Copy)]
pub struct DeviceIssuanceContext<'a> {
    pub store: &'a asterius_store_pg::Store,
    pub request: &'a DeviceRequestEvidence,
}
impl DeviceIssuanceContext<'_> {
    pub async fn bind(&self, tenant: &asterius_domain::TenantId, grant: &asterius_domain::Grant, now: OffsetDateTime)
        -> Result<Option<asterius_domain::managed_devices::DeviceBinding>, asterius_domain::DomainError> {
        self.request.bind(self.store,tenant,grant,now).await
    }
}
