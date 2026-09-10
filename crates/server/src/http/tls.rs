//! The TLS listener configuration.
//!
//! FAPI 2.0 SP §5.2.1 requires TLS 1.2 or later and the BCP 195 recommendations
//! in general; §5.2.2 is the clause that pins the TLS 1.2 cipher suites, to the
//! ones BCP 195 *recommends*, on endpoints not used by web browsers. rustls
//! cannot speak TLS 1.0 or 1.1 at all, which removes an entire class of
//! misconfiguration — but the cipher suite list is still ours to get right, so
//! it is written out explicitly here rather than inherited from a default that
//! may widen.

use rustls::crypto::aws_lc_rs;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, SupportedCipherSuite, SupportedProtocolVersion};
use std::path::Path;
use std::sync::Arc;

/// The only protocol versions offered. TLS 1.0 and 1.1 are not representable.
pub const PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

/// The only cipher suites offered.
///
/// Every entry is AEAD with forward secrecy. No CBC, no static RSA key
/// exchange, no `NULL`, no export grades — the categories BCP 195 §4.2 rules
/// out.
///
/// For TLS 1.2 the list is narrower than "AEAD with forward secrecy": it is
/// exactly the four suites RFC 9325 §4.2 *recommends*. FAPI 2.0 SP §5.2.2 says
/// a server using TLS 1.2 "shall only permit the cipher suites recommended in
/// \[BCP195\]" on endpoints not used by web browsers, while §5.2.3 only requires
/// the wider *allowed* set on browser endpoints — a distinction §5.2.3 NOTE 1
/// makes explicit. One listener carries both the token endpoint and
/// `/authorize`, so the stricter of the two governs the whole socket and
/// ChaCha20-Poly1305, allowed but not recommended, stays out of the TLS 1.2
/// offer. TLS 1.3 is untouched by those clauses and keeps rustls's three
/// suites.
pub const CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS 1.3
    aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
    aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    // TLS 1.2, ECDSA
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    // TLS 1.2, RSA
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

/// Why a TLS listener could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// A certificate or key file could not be read or parsed.
    #[error("cannot read {path}: {source}")]
    Pem {
        /// The file we tried to read.
        path: String,
        /// The underlying I/O or PEM failure.
        #[source]
        source: rustls::pki_types::pem::Error,
    },
    /// The certificate file contained no certificates.
    #[error("{0} contains no PEM certificates")]
    NoCertificates(String),
    /// The key file contained no private key.
    #[error("{0} contains no PEM private key")]
    NoPrivateKey(String),
    /// rustls rejected the certificate and key pair.
    #[error("rustls rejected the certificate or key: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Builds the server's TLS configuration from a certificate chain and key.
///
/// # Errors
///
/// Returns [`TlsError`] if either file is unreadable, empty, or if rustls
/// rejects the pair — typically because the key does not match the leaf
/// certificate.
pub fn server_config(
    certificate: &Path,
    private_key: &Path,
) -> Result<Arc<ServerConfig>, TlsError> {
    let certs = load_certificates(certificate)?;
    let key = load_private_key(private_key)?;

    let provider = Arc::new(rustls::crypto::CryptoProvider {
        cipher_suites: CIPHER_SUITES.to_vec(),
        ..aws_lc_rs::default_provider()
    });

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(PROTOCOL_VERSIONS)?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // HTTP/2 first, HTTP/1.1 as the fallback. Advertised through ALPN so that
    // a client cannot negotiate a protocol the server did not offer.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|source| TlsError::Pem {
            path: path.display().to_string(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsError::Pem {
            path: path.display().to_string(),
            source,
        })?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(path.display().to_string()));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_file(path).map_err(|source| match source {
        rustls::pki_types::pem::Error::NoItemsFound => {
            TlsError::NoPrivateKey(path.display().to_string())
        }
        source => TlsError::Pem {
            path: path.display().to_string(),
            source,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FAPI 2.0 SP §5.2.1: TLS 1.2 is the floor. rustls has no TLS 1.0 or 1.1
    /// implementation, so this asserts the positive half — that both permitted
    /// versions really are offered, and nothing else could be.
    #[test]
    fn only_tls_1_2_and_1_3_are_offered() {
        let versions: Vec<_> = PROTOCOL_VERSIONS.iter().map(|v| v.version).collect();
        assert_eq!(
            versions,
            vec![
                rustls::ProtocolVersion::TLSv1_3,
                rustls::ProtocolVersion::TLSv1_2
            ]
        );
    }

    /// BCP 195 §4.2: no CBC, no static RSA key exchange, no non-AEAD suite.
    /// Naming is the only handle rustls gives us on a suite, and it is a
    /// reliable one — every excluded construction is named in the suite.
    #[test]
    fn every_cipher_suite_is_aead_with_forward_secrecy() {
        assert!(!CIPHER_SUITES.is_empty());
        for suite in CIPHER_SUITES {
            let name = format!("{:?}", suite.suite());
            assert!(!name.contains("CBC"), "{name} uses CBC");
            assert!(!name.contains("_RC4_"), "{name} uses RC4");
            assert!(!name.contains("3DES"), "{name} uses 3DES");
            assert!(!name.contains("_NULL_"), "{name} has no encryption");
            let tls13 = name.starts_with("TLS13_");
            let forward_secret = name.contains("ECDHE") || name.contains("DHE");
            assert!(tls13 || forward_secret, "{name} has no forward secrecy");
            let aead = name.contains("GCM") || name.contains("POLY1305");
            assert!(aead, "{name} is not an AEAD suite");
        }
    }

    /// FAPI 2.0 SP §5.2.2: on endpoints not used by web browsers, a server
    /// using TLS 1.2 "shall only permit the cipher suites recommended in
    /// [BCP195]". BCP 195 (RFC 9325 §4.2) recommends exactly four, all
    /// ECDHE + AES-GCM; ChaCha20-Poly1305 is *allowed* but not *recommended*,
    /// a distinction SP §5.2.3 NOTE 1 spells out. This listener serves the
    /// token endpoint and /authorize on one socket, so the stricter list wins
    /// and the assertion is on the enumeration, not on AEAD-plus-PFS.
    #[test]
    fn the_tls_1_2_suites_are_exactly_the_four_bcp_195_recommends() {
        let offered: Vec<String> = CIPHER_SUITES
            .iter()
            .map(|s| format!("{:?}", s.suite()))
            .filter(|n| !n.starts_with("TLS13_"))
            .collect();

        assert_eq!(
            offered,
            vec![
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_owned(),
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_owned(),
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_owned(),
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_owned(),
            ],
            "the TLS 1.2 offer is not RFC 9325 §4.2's list"
        );
    }

    #[test]
    fn the_suite_list_covers_both_signature_algorithms_we_issue() {
        let names: Vec<String> = CIPHER_SUITES
            .iter()
            .map(|s| format!("{:?}", s.suite()))
            .collect();
        assert!(
            names.iter().any(|n| n.contains("ECDSA")),
            "no ECDSA suite: EC certificates would fail"
        );
        assert!(
            names.iter().any(|n| n.contains("_RSA_")),
            "no RSA suite: RSA certificates would fail"
        );
        assert!(names.iter().filter(|n| n.starts_with("TLS13_")).count() >= 3);
    }

    #[test]
    fn a_missing_certificate_file_is_an_error_not_a_panic() {
        let error = server_config(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        )
        .expect_err("should fail");
        assert!(matches!(error, TlsError::Pem { .. }), "{error}");
    }

    #[test]
    fn an_empty_certificate_file_is_reported_as_empty() {
        let dir = std::env::temp_dir().join(format!("asterius-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let cert = dir.join("empty.pem");
        std::fs::write(&cert, b"not a certificate\n").expect("write");
        let error = server_config(&cert, &cert).expect_err("should fail");
        assert!(matches!(error, TlsError::NoCertificates(_)), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
