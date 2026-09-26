//! Bounded SAML 2.0 HTTP-Redirect request decoding (Bindings §3.4.4.1).
//!
//! The signature input uses the *original URL-encoded values*, not values
//! decoded and encoded a second time. Query-parameter pollution, unknown
//! parameters, malformed percent escapes and ambiguous raw plus signs are
//! rejected. Parsing here does not confer trust; the routed validator selects
//! an operator-pinned key and verifies the signature before reserving an ID.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::read::DeflateDecoder;
use std::io::Read;

use crate::saml::UntrustedSaml;

const MAX_QUERY_BYTES: usize = 16 * 1024;
const MAX_XML_BYTES: usize = 64 * 1024;
const MAX_COMPRESSED_BYTES: usize = 12 * 1024;
const MAX_SIGNATURE_BYTES: usize = 1024;
const DEFLATE_ENCODING: &[u8] = b"urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// Decoded request plus the exact octets the SP must have signed.
#[derive(Debug)]
pub struct RedirectRequest {
    pub xml: Vec<u8>,
    pub signature: Vec<u8>,
    pub signing_input: Vec<u8>,
    pub relay_state: Option<Vec<u8>>,
}

/// Decodes one raw URI query. The caller must pass only `Uri::query()`, not
/// a form-decoded map or a URL reconstructed by a proxy.
pub fn parse_redirect_query(raw_query: &str) -> Result<RedirectRequest, UntrustedSaml> {
    if raw_query.is_empty()
        || raw_query.len() > MAX_QUERY_BYTES
        || !raw_query
            .bytes()
            .all(|b| (0x21..=0x7e).contains(&b) && b != b'#' && b != b';')
    {
        return Err(UntrustedSaml);
    }
    let mut request = None;
    let mut relay_state = None;
    let mut sig_alg = None;
    let mut signature = None;
    let mut saml_encoding = None;
    for part in raw_query.split('&') {
        let (name, value) = part.split_once('=').ok_or(UntrustedSaml)?;
        if value.is_empty() || value.contains('+') {
            return Err(UntrustedSaml);
        }
        let slot = match name {
            "SAMLRequest" => &mut request,
            "RelayState" => &mut relay_state,
            "SigAlg" => &mut sig_alg,
            "Signature" => &mut signature,
            "SAMLEncoding" => &mut saml_encoding,
            _ => return Err(UntrustedSaml),
        };
        if slot.replace(value).is_some() {
            return Err(UntrustedSaml);
        }
        // Validate even the parameters that are not used in the signature.
        let _ = percent_decode(value)?;
    }
    let request = request.ok_or(UntrustedSaml)?;
    let sig_alg = sig_alg.ok_or(UntrustedSaml)?;
    let signature = signature.ok_or(UntrustedSaml)?;
    if percent_decode(sig_alg)?.as_slice() != RSA_SHA256.as_bytes()
        || saml_encoding
            .is_some_and(|value| percent_decode(value).ok().as_deref() != Some(DEFLATE_ENCODING))
    {
        return Err(UntrustedSaml);
    }
    let relay_state = relay_state.map(percent_decode).transpose()?;
    if relay_state.as_ref().is_some_and(|value| value.len() > 80) {
        return Err(UntrustedSaml);
    }

    let mut signing_input = format!("SAMLRequest={request}").into_bytes();
    if let Some(relay) = raw_relay(raw_query)? {
        signing_input.extend_from_slice(b"&RelayState=");
        signing_input.extend_from_slice(relay.as_bytes());
    }
    signing_input.extend_from_slice(b"&SigAlg=");
    signing_input.extend_from_slice(sig_alg.as_bytes());

    let compressed = STANDARD
        .decode(percent_decode(request)?)
        .map_err(|_| UntrustedSaml)?;
    if compressed.is_empty() || compressed.len() > MAX_COMPRESSED_BYTES {
        return Err(UntrustedSaml);
    }
    let signature = STANDARD
        .decode(percent_decode(signature)?)
        .map_err(|_| UntrustedSaml)?;
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        return Err(UntrustedSaml);
    }
    let mut decoder = DeflateDecoder::new(compressed.as_slice());
    let mut xml = Vec::new();
    decoder
        .by_ref()
        .take((MAX_XML_BYTES + 1) as u64)
        .read_to_end(&mut xml)
        .map_err(|_| UntrustedSaml)?;
    if xml.is_empty() || xml.len() > MAX_XML_BYTES || decoder.total_in() != compressed.len() as u64
    {
        return Err(UntrustedSaml);
    }
    Ok(RedirectRequest {
        xml,
        signature,
        signing_input,
        relay_state,
    })
}

fn raw_relay(query: &str) -> Result<Option<&str>, UntrustedSaml> {
    for part in query.split('&') {
        let (name, value) = part.split_once('=').ok_or(UntrustedSaml)?;
        if name == "RelayState" {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn percent_decode(value: &str) -> Result<Vec<u8>, UntrustedSaml> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(UntrustedSaml);
            }
            let high = (bytes[i + 1] as char).to_digit(16).ok_or(UntrustedSaml)?;
            let low = (bytes[i + 2] as char).to_digit(16).ok_or(UntrustedSaml)?;
            out.push(u8::try_from((high << 4) | low).map_err(|_| UntrustedSaml)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::{SpTrust, TrustedSp, parse_authn_request};
    use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    const QUERY: &str = include_str!("../tests/fixtures/saml_sp/redirect.query");
    const XML: &str = include_str!("../tests/fixtures/saml_sp/redirect.xml");
    const SP_PUBLIC_KEY: &[u8] = include_bytes!("../tests/fixtures/saml_sp/public.der");

    #[test]
    fn signed_sp_redirect_vector_preserves_exact_signature_input_and_relay_state() {
        let query = QUERY.trim_end();
        let parsed = parse_redirect_query(query).expect("valid signed SP redirect vector");
        assert_eq!(parsed.xml, XML.trim_end().as_bytes());
        assert_eq!(
            parsed.relay_state.as_deref(),
            Some(b"continue:/billing?x=1&y=2".as_slice())
        );
        assert_eq!(
            parsed.signing_input.as_slice(),
            query
                .split_once("&Signature=")
                .expect("signature member")
                .0
                .as_bytes(),
        );
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, SP_PUBLIC_KEY)
            .verify(&parsed.signing_input, &parsed.signature)
            .expect("SP signature verifies over original encoded octets");
        let request =
            parse_authn_request(&parsed.xml).expect("signed vector contains an AuthnRequest");
        assert_eq!(request.id, "_sp-request-001");
        assert_eq!(
            request.destination.as_deref(),
            Some("https://idp.example/t/alpha/saml/sso")
        );
        let mut trust = SpTrust::default();
        trust
            .insert(
                "alpha",
                TrustedSp::new("https://sp.example/metadata", "https://sp.example/saml/acs")
                    .expect("pinned SP"),
            )
            .expect("alpha trust");
        assert!(trust.resolve("alpha", &request).is_ok());
        assert!(
            trust.resolve("beta", &request).is_err(),
            "same SP is not trusted in another tenant"
        );
    }

    #[test]
    fn signed_sp_redirect_vector_rejects_relay_tampering_and_query_pollution() {
        let tampered = QUERY.trim_end().replace("billing", "profile");
        let parsed =
            parse_redirect_query(&tampered).expect("tampering keeps the query well formed");
        assert!(
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, SP_PUBLIC_KEY)
                .verify(&parsed.signing_input, &parsed.signature)
                .is_err(),
            "a changed RelayState must invalidate the SP signature"
        );
        assert!(parse_redirect_query(&format!("{}&RelayState=second", QUERY.trim_end())).is_err());
        assert!(parse_redirect_query(&format!("{}&other=ignored", QUERY.trim_end())).is_err());
    }
}
