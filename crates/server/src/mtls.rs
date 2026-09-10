//! Where a client certificate comes from, and what makes it trustworthy.
//!
//! [`asterius_oidc::mtls`] answers "does this certificate carry the name the
//! client registered?". This module answers the two questions that come before
//! it, and both are about *trust roots* rather than about protocol:
//!
//! 1. **Did this certificate really arrive with this request?** In
//!    `behind_proxy` mode it arrives in a header, and a header is a claim
//!    anybody can make. It is read only when the immediate peer is inside the
//!    configured `trusted_proxies` — the same rule, and the same set, that
//!    decides whether `X-Forwarded-For` is believed
//!    ([`crate::http::forwarded`]). From any other peer the header is dropped
//!    without being parsed.
//! 2. **Does it chain to something this tenant trusts?** RFC 8705 §2.1's PKI
//!    method is only worth anything if somebody vouched for the name in the
//!    certificate. That somebody is a *per-tenant* trust anchor set, because
//!    one process serves several tenants and a CA one tenant trusts must not
//!    be able to mint clients for another.
//!
//! # The new trust roots this introduces
//!
//! Two, and both are recorded in `docs/threat-model.md`:
//!
//! * **The trusted proxy.** In `behind_proxy` mode the proxy decides which
//!   certificate — if any — this server sees, so it can authenticate any
//!   client it likes. It was already trusted for the client's address and
//!   host; this makes it trusted for the client's *identity*. The mitigation
//!   is that nothing else can: a header from outside `trusted_proxies` is not
//!   parsed, and there is a test for that specific spoof.
//! * **The tenant's CAs.** Any certificate a listed CA issues can authenticate
//!   as any client of that tenant that registered a matching name. The
//!   anchors are therefore per tenant and never global, and a tenant with no
//!   anchors file cannot use the PKI method at all — it fails closed rather
//!   than falling back to the deployment's outbound roots, which are for
//!   *server* certificates and would let the public web CAs mint clients.
//!
//! # Why the anchors live in a file
//!
//! A trust anchor set is operator-managed key material with the same lifecycle
//! as the server's own certificate and key, which are also paths in
//! `asterius.toml`. Putting it in a column would mean a migration to rotate a
//! CA and would put the decision "who may mint clients here" behind the admin
//! API, whose own callers this server authenticates. A file the orchestrator
//! mounts keeps it next to the other TLS material an operator already rotates.

use asterius_domain::TenantId;
use asterius_oidc::mtls::{ClientCertificate, MAX_CERTIFICATE_LEN};
use axum::http::HeaderMap;
use ipnet::IpNet;
use rustls::pki_types::{CertificateDer, UnixTime};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The header a reverse proxy puts the client certificate in, by default.
///
/// nginx's `ssl_client_escaped_cert` and `HAProxy`'s
/// `ssl_c_der,base64` are both commonly forwarded under this name. It is
/// configurable because the name is a deployment fact, not a protocol one.
pub const DEFAULT_CERTIFICATE_HEADER: &str = "x-client-cert";

/// The most bytes a certificate header may carry.
///
/// A PEM block is about four thirds of the DER, plus percent-encoding at worst
/// three bytes per character. Four times [`MAX_CERTIFICATE_LEN`] covers the
/// worst case and refuses anything an attacker inflated past it — before any
/// decoding happens, so the work is bounded by this number rather than by the
/// header.
pub const MAX_CERTIFICATE_HEADER_LEN: usize = 4 * MAX_CERTIFICATE_LEN;

/// How this deployment learns about client certificates.
#[derive(Debug, Clone)]
pub struct MtlsConfig {
    /// The header the proxy forwards the certificate in.
    ///
    /// Read only in `behind_proxy` mode, and only from a peer inside
    /// `trusted_proxies`.
    pub certificate_header: String,
    /// Where each tenant's PKI-method trust anchors are.
    ///
    /// A tenant absent from this map has none, and its `tls_client_auth`
    /// clients cannot authenticate. That is the safe direction: the
    /// alternative is a tenant whose certificates are checked against
    /// somebody else's CAs.
    pub trust_anchors: BTreeMap<TenantId, PathBuf>,
}

impl Default for MtlsConfig {
    fn default() -> Self {
        Self {
            certificate_header: DEFAULT_CERTIFICATE_HEADER.to_owned(),
            trust_anchors: BTreeMap::new(),
        }
    }
}

/// Why trust anchors could not be loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AnchorError {
    /// The file could not be read.
    #[error("cannot read the trust anchors at {path}: {source}")]
    Unreadable {
        /// The file named in `asterius.toml`.
        path: String,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The file held no PEM certificates.
    #[error("{0} contains no PEM certificates")]
    Empty(String),
    /// A certificate in the file is not usable as a trust anchor.
    #[error("{path} contains a certificate that is not a usable trust anchor")]
    Unusable {
        /// The file named in `asterius.toml`.
        path: String,
    },
}

/// One tenant's PKI-method trust anchors, loaded and ready to verify against.
///
/// Loaded at boot rather than per request: reading and re-parsing a PEM file on
/// every token request would put a disk read on the authentication path, and a
/// file that changed halfway through a request would make two requests in the
/// same second answer differently.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    /// The DER of each anchor, kept so the `webpki` view can be rebuilt.
    certificates: Vec<CertificateDer<'static>>,
}

impl TrustAnchors {
    /// Loads anchors from a PEM file.
    ///
    /// # Errors
    ///
    /// [`AnchorError`] if the file is unreadable, holds no certificates, or
    /// holds one `webpki` cannot use as an anchor. All three are refused at
    /// boot: an operator who named a file meant the certificates in it to be
    /// trusted, and a deployment that silently trusted a subset of them would
    /// refuse clients for a reason nothing reports.
    pub fn load(path: &Path) -> Result<Self, AnchorError> {
        use rustls::pki_types::pem::PemObject as _;

        let display = path.display().to_string();
        let certificates = CertificateDer::pem_file_iter(path)
            .and_then(std::iter::Iterator::collect::<Result<Vec<_>, _>>)
            .map_err(|source| AnchorError::Unreadable {
                path: display.clone(),
                source: std::io::Error::other(source),
            })?;
        if certificates.is_empty() {
            return Err(AnchorError::Empty(display));
        }
        for certificate in &certificates {
            webpki::anchor_from_trusted_cert(certificate).map_err(|_| AnchorError::Unusable {
                path: display.clone(),
            })?;
        }
        Ok(Self { certificates })
    }

    /// Builds an anchor set from DER, for tests and for callers that already
    /// hold the bytes.
    #[must_use]
    pub fn from_der(certificates: Vec<Vec<u8>>) -> Self {
        Self {
            certificates: certificates.into_iter().map(CertificateDer::from).collect(),
        }
    }

    /// Whether this set trusts nobody.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// RFC 8705 §2.1: whether `certificate` chains to one of these anchors and
    /// may be used for client authentication.
    ///
    /// `intermediates` are the certificates the presenter offered between the
    /// leaf and an anchor. They are inputs to path building, never trusted in
    /// themselves — an attacker who could make one an anchor would only have
    /// to send it.
    ///
    /// `KeyUsage::client_auth` is checked, not assumed: a server certificate
    /// from the same CA is a certificate the CA issued for a different purpose,
    /// and accepting it here would let anybody who runs an HTTPS host under
    /// that CA authenticate as a client.
    #[must_use]
    pub fn accepts(
        &self,
        certificate: &ClientCertificate,
        intermediates: &[ClientCertificate],
        now: time::OffsetDateTime,
    ) -> bool {
        if self.certificates.is_empty() {
            return false;
        }
        let anchors: Vec<rustls::pki_types::TrustAnchor<'_>> = self
            .certificates
            .iter()
            .filter_map(|der| webpki::anchor_from_trusted_cert(der).ok())
            .collect();
        if anchors.is_empty() {
            return false;
        }

        let leaf = CertificateDer::from(certificate.as_der());
        let Ok(end_entity) = webpki::EndEntityCert::try_from(&leaf) else {
            return false;
        };
        let chain: Vec<CertificateDer<'_>> = intermediates
            .iter()
            .map(|cert| CertificateDer::from(cert.as_der()))
            .collect();

        // The same algorithm set the TLS listener uses, taken from the one
        // crypto provider this build has (ADR-0004: aws-lc-rs, never OpenSSL).
        // Naming a second list here would be a second answer to "which
        // signatures does this server accept".
        let algorithms =
            rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;

        let Ok(seconds) = u64::try_from(now.unix_timestamp()) else {
            // Before 1970. Not a time this server runs at, and not a reason to
            // accept a certificate.
            return false;
        };

        end_entity
            .verify_for_usage(
                algorithms.all,
                &anchors,
                &chain,
                UnixTime::since_unix_epoch(std::time::Duration::from_secs(seconds)),
                webpki::KeyUsage::client_auth(),
                // No revocation lists. A deployment that needs revocation
                // configures it at the proxy, which is where an OCSP or CRL
                // fetch belongs — see the note in `docs/threat-model.md`.
                None,
                None,
            )
            .is_ok()
    }
}

/// The certificate a request arrived with, if this server may believe in one.
#[derive(Debug, Clone)]
pub struct PresentedCertificate {
    /// The end-entity certificate the client presented.
    pub leaf: ClientCertificate,
    /// Anything the presenter offered between the leaf and an anchor.
    pub intermediates: Vec<ClientCertificate>,
}

/// Reads the client certificate a trusted proxy forwarded.
///
/// Returns `None` — without parsing anything — when the immediate peer is not
/// inside `trusted_proxies`. That is the whole security property of this
/// function: the header is a claim, and it is believed only from a peer the
/// operator deployed.
///
/// A header that is present, trusted and unparseable is also `None`. A
/// certificate this server cannot read authenticates nobody, and answering
/// "no certificate" is the same outcome by a shorter path.
#[must_use]
// fuzz-target: client_certificate_header
pub fn from_proxy_header(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
    header_name: &str,
) -> Option<PresentedCertificate> {
    if !trusted_proxies.iter().any(|net| net.contains(&peer)) {
        return None;
    }
    let value = headers.get(header_name)?.to_str().ok()?;
    if value.len() > MAX_CERTIFICATE_HEADER_LEN {
        return None;
    }
    let leaf = decode_certificate(value)?;
    Some(PresentedCertificate {
        leaf,
        // A header carries the leaf. A proxy that forwards a chain does it in
        // its own format, and guessing at one would mean accepting a chain
        // this server assembled from a string rather than one the client sent.
        intermediates: Vec::new(),
    })
}

/// Decodes the certificate out of a header value.
///
/// Three spellings are in the field, and all three are the same certificate:
///
/// * percent-encoded PEM (nginx `ssl_client_escaped_cert`),
/// * PEM whose newlines the proxy replaced with `\n` or with spaces, because
///   RFC 9110 §5.5 does not let a field value carry a bare newline,
/// * bare base64 DER (`HAProxy` `ssl_c_der,base64`).
///
/// Accepting all three is not laxity: they differ only in transport encoding,
/// and each decodes to exactly one byte string or to nothing. What is *not*
/// accepted is a value carrying more than one certificate — the first PEM
/// block is taken and the rest ignored, so a header naming two identities
/// yields the one the proxy put first.
fn decode_certificate(value: &str) -> Option<ClientCertificate> {
    use base64::Engine as _;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let decoded = percent_decode(value)?;
    let body = if let Some(start) = decoded.find(BEGIN) {
        let after = &decoded[start + BEGIN.len()..];
        let end = after.find(END)?;
        &after[..end]
    } else {
        decoded.as_str()
    };

    // Whitespace and the escaped newlines a proxy may have substituted. A
    // base64 alphabet has neither, so removing them cannot change which bytes
    // are decoded.
    let compact: String = body
        .split("\\n")
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    if compact.is_empty() || compact.len() > MAX_CERTIFICATE_HEADER_LEN {
        return None;
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(&compact)
        .ok()?;
    ClientCertificate::from_der(der).ok()
}

/// Percent-decoding, bounded and byte-exact.
///
/// Written out rather than taken from a URL library because the input is a
/// header value, not a URL: `+` is a plus sign here and not a space, and a
/// library that decoded it as a space would corrupt base64.
fn percent_decode(value: &str) -> Option<String> {
    if !value.contains('%') {
        return Some(value.to_owned());
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            let high = (hex[0] as char).to_digit(16)?;
            let low = (hex[1] as char).to_digit(16)?;
            // Both digits are 0..16, so the product fits a byte.
            out.push(u8::try_from(high * 16 + low).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The anchors for every tenant that has any, loaded once at boot.
#[derive(Debug, Clone, Default)]
pub struct TenantTrustAnchors(BTreeMap<TenantId, Arc<TrustAnchors>>);

impl TenantTrustAnchors {
    /// Loads every tenant's anchors named in `config`.
    ///
    /// # Errors
    ///
    /// The first [`AnchorError`], with the path that produced it. A named file
    /// that cannot be loaded stops the process: an operator who listed a CA
    /// meant clients to authenticate with it, and a server that started
    /// without it would refuse every one of them for a reason only a debug log
    /// would carry.
    pub fn load(config: &MtlsConfig) -> Result<Self, AnchorError> {
        let mut anchors = BTreeMap::new();
        for (tenant, path) in &config.trust_anchors {
            anchors.insert(tenant.clone(), Arc::new(TrustAnchors::load(path)?));
        }
        Ok(Self(anchors))
    }

    /// Builds a set directly, for tests.
    #[must_use]
    pub fn from_map(anchors: BTreeMap<TenantId, Arc<TrustAnchors>>) -> Self {
        Self(anchors)
    }

    /// This tenant's anchors, or `None` if it has none.
    #[must_use]
    pub fn for_tenant(&self, tenant: &TenantId) -> Option<&Arc<TrustAnchors>> {
        self.0.get(tenant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    /// The smallest thing `ClientCertificate::from_der` accepts, so that the
    /// header tests are about the header and not about X.509.
    fn certificate_der() -> Vec<u8> {
        vec![
            0x30, 0x15, 0x30, 0x0f, 0x02, 0x01, 0x01, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30,
            0x00, 0x30, 0x02, 0x30, 0x00, 0x30, 0x00, 0x03, 0x00,
        ]
    }

    fn encoded() -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(certificate_der())
    }

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(DEFAULT_CERTIFICATE_HEADER),
            HeaderValue::from_str(value).expect("a header value"),
        );
        headers
    }

    fn trusted() -> Vec<IpNet> {
        vec!["10.0.0.0/8".parse().expect("literal")]
    }

    /// The acceptance criterion: a header from an address outside
    /// `trusted_proxies` is not a certificate, whatever it says.
    #[test]
    fn a_certificate_header_from_an_untrusted_address_is_ignored() {
        // Arrange: a perfectly valid certificate, from the wrong peer.
        let headers = headers(&encoded());
        let spoofer: IpAddr = "203.0.113.9".parse().expect("literal");

        // Act
        let presented =
            from_proxy_header(spoofer, &headers, &trusted(), DEFAULT_CERTIFICATE_HEADER);

        // Assert
        assert!(
            presented.is_none(),
            "a header from outside trusted_proxies authenticated a client"
        );
    }

    /// The same header, from the proxy the operator deployed.
    #[test]
    fn a_certificate_header_from_a_trusted_proxy_is_read() {
        // Arrange
        let headers = headers(&encoded());
        let proxy: IpAddr = "10.1.2.3".parse().expect("literal");

        // Act
        let presented = from_proxy_header(proxy, &headers, &trusted(), DEFAULT_CERTIFICATE_HEADER)
            .expect("the proxy is trusted");

        // Assert
        assert_eq!(presented.leaf.as_der(), certificate_der());
        assert!(presented.intermediates.is_empty());
    }

    /// An empty trusted set is the default, and it must trust nobody rather
    /// than everybody.
    #[test]
    fn no_configured_proxy_means_no_header_is_believed() {
        for peer in ["10.1.2.3", "127.0.0.1", "203.0.113.9"] {
            // Arrange
            let peer: IpAddr = peer.parse().expect("literal");

            // Act
            let presented =
                from_proxy_header(peer, &headers(&encoded()), &[], DEFAULT_CERTIFICATE_HEADER);

            // Assert
            assert!(presented.is_none(), "{peer} was believed");
        }
    }

    /// The spellings a proxy sends, all decoding to the same bytes.
    ///
    /// A raw PEM block is not among them and cannot be: RFC 9110 §5.5 forbids
    /// a bare newline in a field value, which is exactly why nginx escapes the
    /// certificate and `HAProxy` sends the base64 alone.
    #[test]
    fn every_forwarded_encoding_decodes_to_the_same_certificate() {
        let base64 = encoded();
        let pem = format!("-----BEGIN CERTIFICATE-----\n{base64}\n-----END CERTIFICATE-----\n");
        let escaped_newlines = pem.replace('\n', "\\n");
        let spaces = pem.replace('\n', " ");
        let percent: String = pem
            .chars()
            .map(|c| match c {
                '\n' => "%0A".to_owned(),
                ' ' => "%20".to_owned(),
                other => other.to_string(),
            })
            .collect();

        for value in [base64, escaped_newlines, spaces, percent] {
            // Act
            let presented = from_proxy_header(
                "10.1.2.3".parse().expect("literal"),
                &headers(&value),
                &trusted(),
                DEFAULT_CERTIFICATE_HEADER,
            );

            // Assert
            assert_eq!(
                presented.map(|p| p.leaf.as_der().to_vec()),
                Some(certificate_der()),
                "{value}"
            );
        }
    }

    /// A header a proxy forwarded is still bytes. Every one of these is a
    /// refusal rather than a panic or a certificate.
    #[test]
    fn a_header_that_is_not_a_certificate_is_refused() {
        for value in [
            "",
            "not base64 at all !!!",
            "%",
            "%zz",
            "%4",
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----",
            &"A".repeat(MAX_CERTIFICATE_HEADER_LEN + 1),
        ] {
            // Arrange
            let Ok(header) = HeaderValue::from_str(value) else {
                continue;
            };
            let mut map = HeaderMap::new();
            map.insert(HeaderName::from_static(DEFAULT_CERTIFICATE_HEADER), header);

            // Act
            let presented = from_proxy_header(
                "10.1.2.3".parse().expect("literal"),
                &map,
                &trusted(),
                DEFAULT_CERTIFICATE_HEADER,
            );

            // Assert
            assert!(presented.is_none(), "{value:?} became a certificate");
        }
    }

    /// A tenant with no anchors cannot use the PKI method. Falling back to any
    /// other trust root would let somebody else's CA mint its clients.
    #[test]
    fn a_tenant_without_anchors_trusts_nobody() {
        // Arrange
        let anchors = TrustAnchors::default();
        let certificate =
            ClientCertificate::from_der(certificate_der()).expect("a parseable certificate");

        // Act
        let accepted = anchors.accepts(&certificate, &[], time::OffsetDateTime::now_utc());

        // Assert
        assert!(anchors.is_empty());
        assert!(!accepted);
    }

    #[test]
    fn anchors_are_looked_up_per_tenant() {
        // Arrange
        let anchors = TenantTrustAnchors::from_map(BTreeMap::from([(
            TenantId::new("demo"),
            Arc::new(TrustAnchors::from_der(vec![certificate_der()])),
        )]));

        // Act & Assert
        assert!(anchors.for_tenant(&TenantId::new("demo")).is_some());
        assert!(
            anchors.for_tenant(&TenantId::new("other")).is_none(),
            "one tenant's CAs were offered to another"
        );
    }
}
