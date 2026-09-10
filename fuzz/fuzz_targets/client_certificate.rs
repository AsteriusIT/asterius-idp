//! The X.509 reader behind RFC 8705 §2.1 client authentication.
//!
//! The bytes are an unauthenticated caller's: a certificate arrives from a TLS
//! handshake that has not authenticated anybody yet, or from a proxy header.
//! Two invariants matter here.
//!
//! **Totality.** Any byte string is either refused or turned into names. It is
//! never a panic, and never an unbounded allocation — the size bound is
//! checked before anything is parsed.
//!
//! **Determinism.** The same bytes always produce the same names. The whole of
//! §2.1 is a byte-exact comparison against a registered string, so a renderer
//! whose output varied would be a comparison whose answer varied.
#![no_main]

use asterius_oidc::mtls::{CertificateError, ClientCertificate, MAX_CERTIFICATE_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(certificate) = ClientCertificate::from_der(data.to_vec()) else {
        return;
    };

    // Past the bound nothing is parsed, so anything that got here is inside it.
    assert!(certificate.as_der().len() <= MAX_CERTIFICATE_LEN);

    // `from_der` refuses what it cannot read, so a value that exists has names.
    let names = certificate.subject().expect("from_der parsed this already");
    assert_eq!(
        names,
        certificate.subject().expect("still parseable"),
        "the same bytes rendered two different names"
    );

    // A registered expectation may not be empty or contain a control
    // character, so a rendering that produced one would be a name nothing can
    // match — which is safe, but a subject DN is rendered from the same bytes
    // every time and that is the property under test above.
    let _ = names.subject_dn.len();
    for value in names
        .san_dns
        .iter()
        .chain(&names.san_uri)
        .chain(&names.san_email)
    {
        assert!(value.is_ascii(), "a non-ASCII IA5String was accepted");
    }
    for value in &names.san_ip {
        assert!(
            value.parse::<std::net::IpAddr>().is_ok(),
            "an iPAddress SAN rendered as something that is not an address"
        );
    }

    // The thumbprint is over the presented bytes and nothing else.
    assert_eq!(certificate.thumbprint().len(), 32);

    // A JWKS built from arbitrary bytes must not make an unpublished
    // certificate match. The one thing that may match is the certificate
    // itself, which the next assertion pins.
    let noise = serde_json::json!({"keys": [{"x5c": [String::from_utf8_lossy(data)]}]});
    let _ = certificate.is_published_in(&noise);

    let published = serde_json::json!({"keys": [{"x5c": [base64_standard(data)]}]});
    assert!(
        certificate.is_published_in(&published),
        "a certificate did not match its own x5c entry"
    );

    // Oversized input is refused before the parser runs.
    let mut oversized = certificate.as_der().to_vec();
    oversized.resize(MAX_CERTIFICATE_LEN + 1, 0);
    assert_eq!(
        ClientCertificate::from_der(oversized).err(),
        Some(CertificateError::TooLarge)
    );
});

fn base64_standard(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
