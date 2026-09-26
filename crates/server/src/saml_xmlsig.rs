//! Narrow SAML `AuthnRequest` XML Signature verification for HTTP-POST.
//!
//! This is deliberately one profile, not a general `XMLDSig` engine:
//! one direct-child enveloped `ds:Signature` after `saml:Issuer`, one
//! `Reference URI="#request-ID"`, enveloped then Exclusive C14N 1.0
//! transforms, SHA-256 digest and RSA-SHA256 signature. The only signed
//! object is the document root from which that one Signature node is removed.
//! No arbitrary ID lookup, `XPath`, external URI, DTD, `KeyInfo`, extra reference
//! or second signature can influence what is accepted. Unsupported documents
//! fail closed. C14N comes from xml-sec's pure XML-only feature; cryptography
//! remains in aws-lc-rs (ADR-0004).

use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use quick_xml::{Reader, events::Event};
use sha2::{Digest, Sha256};
use xml_sec::c14n::{C14nAlgorithm, C14nMode, canonicalize_xml};

use crate::saml::{UntrustedAuthnRequest, UntrustedSaml, parse_authn_request};

const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXCLUSIVE_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const MAX_XML_BYTES: usize = 64 * 1024;

/// A parsed signature and its exact root request, still unverified until the
/// routed tenant's operator-pinned SP key is supplied.
#[derive(Debug)]
pub struct ParsedSignedPost {
    request: UntrustedAuthnRequest,
    signed_info: Vec<u8>,
    signature: Vec<u8>,
}

impl ParsedSignedPost {
    /// Unverified issuer only selects a candidate key inside the routed
    /// tenant. It does not establish identity or authorize a response.
    #[must_use]
    pub fn unverified_issuer(&self) -> &str {
        &self.request.issuer
    }

    /// Fields may be used only for routed tenant policy and pinned-key
    /// selection. They remain unauthenticated until `verify` succeeds.
    #[must_use]
    pub fn unverified_request(&self) -> &UntrustedAuthnRequest {
        &self.request
    }

    /// Verifies `SignedInfo` with the pinned RSA key after the reference digest
    /// has been checked over exactly the unsigned root. Returns the request
    /// only after both checks pass.
    pub fn verify(
        self,
        pinned_public_key_der: &[u8],
    ) -> Result<UntrustedAuthnRequest, UntrustedSaml> {
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, pinned_public_key_der)
            .verify(&self.signed_info, &self.signature)
            .map_err(|_| UntrustedSaml)?;
        Ok(self.request)
    }
}

/// Parses the strict signature shape and verifies its digest over the exact
/// root `AuthnRequest`. The caller still has to use `ParsedSignedPost::verify`
/// with an operator-pinned key before considering any request field trusted.
pub fn parse_signed_post(xml: &[u8]) -> Result<ParsedSignedPost, UntrustedSaml> {
    if xml.is_empty() || xml.len() > MAX_XML_BYTES {
        return Err(UntrustedSaml);
    }
    let (signature_start, signature_end, root_declares_ds) = signature_span(xml)?;
    let mut unsigned = Vec::with_capacity(xml.len());
    unsigned.extend_from_slice(&xml[..signature_start]);
    unsigned.extend_from_slice(&xml[signature_end..]);
    let request = parse_authn_request(&unsigned)?;
    let signature_xml = &xml[signature_start..signature_end];
    let details = parse_signature(signature_xml, &request.id, root_declares_ds)?;

    let c14n = C14nAlgorithm::new(C14nMode::Exclusive1_0, false);
    let canonical_root = canonicalize_xml(&unsigned, &c14n).map_err(|_| UntrustedSaml)?;
    let actual_digest: [u8; 32] = Sha256::digest(&canonical_root).into();
    if actual_digest != details.digest {
        return Err(UntrustedSaml);
    }
    let canonical_info =
        canonicalize_xml(&details.signed_info_xml, &c14n).map_err(|_| UntrustedSaml)?;
    Ok(ParsedSignedPost {
        request,
        signed_info: canonical_info,
        signature: details.signature,
    })
}

/// Finds one direct child `ds:Signature` after Issuer. Its byte span is
/// removed for the enveloped transform; no ID-based node search is used.
fn signature_span(xml: &[u8]) -> Result<(usize, usize, bool), UntrustedSaml> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().check_end_names = true;
    let mut depth = 0usize;
    let mut issuer_ended = false;
    let mut signature_start = None;
    let mut signature_end = None;
    let mut root_declares_ds = false;
    loop {
        let before = usize::try_from(reader.buffer_position()).map_err(|_| UntrustedSaml)?;
        match reader.read_event().map_err(|_| UntrustedSaml)? {
            Event::Start(e) => {
                depth += 1;
                if depth > 16 {
                    return Err(UntrustedSaml);
                }
                if depth == 1 {
                    root_declares_ds = attributes(&e)?
                        .iter()
                        .any(|(key, value)| key == "xmlns:ds" && value == DS_NS);
                }
                if e.name().as_ref() == "ds:Signature" {
                    if depth != 2 || !issuer_ended || signature_start.is_some() {
                        return Err(UntrustedSaml);
                    }
                    let attrs = attributes(&e)?;
                    if attrs.as_slice() != [("xmlns:ds".to_owned(), DS_NS.to_owned())]
                        && !(root_declares_ds && attrs.is_empty())
                    {
                        return Err(UntrustedSaml);
                    }
                    signature_start = Some(before);
                }
                if signature_start.is_some() && depth > 2 && attrs_contain_id(&e)? {
                    return Err(UntrustedSaml);
                }
            }
            Event::Empty(e) => {
                if e.name().as_ref() == "ds:Signature"
                    || (signature_start.is_some() && attrs_contain_id(&e)?)
                {
                    return Err(UntrustedSaml);
                }
            }
            Event::End(e) => {
                if depth == 0 {
                    return Err(UntrustedSaml);
                }
                if depth == 2 && e.name().as_ref().rsplit(':').next() == Some("Issuer") {
                    issuer_ended = true;
                }
                if depth == 2 && e.name().as_ref() == "ds:Signature" {
                    signature_end =
                        Some(usize::try_from(reader.buffer_position()).map_err(|_| UntrustedSaml)?);
                }
                depth -= 1;
            }
            Event::Text(_) => {}
            Event::Eof => break,
            Event::Decl(_)
            | Event::DocType(_)
            | Event::PI(_)
            | Event::Comment(_)
            | Event::CData(_)
            | Event::GeneralRef(_) => return Err(UntrustedSaml),
        }
        if usize::try_from(reader.buffer_position()).map_err(|_| UntrustedSaml)? >= xml.len() {
            break;
        }
    }
    if depth != 0 {
        return Err(UntrustedSaml);
    }
    let start = signature_start.ok_or(UntrustedSaml)?;
    let end = signature_end.ok_or(UntrustedSaml)?;
    if start >= end || end > xml.len() {
        return Err(UntrustedSaml);
    }
    Ok((start, end, root_declares_ds))
}

fn attrs_contain_id(e: &quick_xml::events::BytesStart<'_>) -> Result<bool, UntrustedSaml> {
    for attr in e.attributes() {
        let attr = attr.map_err(|_| UntrustedSaml)?;
        if matches!(attr.key.as_ref(), "ID" | "Id" | "id" | "xml:id") {
            return Ok(true);
        }
    }
    Ok(false)
}

#[derive(Debug)]
struct SignatureDetails {
    digest: [u8; 32],
    signature: Vec<u8>,
    signed_info_xml: Vec<u8>,
}

#[derive(Debug)]
enum Token {
    Start(String, Vec<(String, String)>),
    End(String),
    Text(String),
}

fn parse_signature(
    xml: &[u8],
    request_id: &str,
    root_declares_ds: bool,
) -> Result<SignatureDetails, UntrustedSaml> {
    let (tokens, info_start, info_end) = scan_signature_tokens(xml)?;
    let mut cursor = tokens.iter();
    match cursor.next() {
        Some(Token::Start(name, attrs))
            if name == "ds:Signature"
                && (attrs.as_slice() == [("xmlns:ds".to_owned(), DS_NS.to_owned())]
                    || (root_declares_ds && attrs.is_empty())) => {}
        _ => return Err(UntrustedSaml),
    }
    start(&mut cursor, "ds:SignedInfo", &[])?;
    start(
        &mut cursor,
        "ds:CanonicalizationMethod",
        &[("Algorithm", EXCLUSIVE_C14N)],
    )?;
    end(&mut cursor, "ds:CanonicalizationMethod")?;
    start(
        &mut cursor,
        "ds:SignatureMethod",
        &[("Algorithm", RSA_SHA256)],
    )?;
    end(&mut cursor, "ds:SignatureMethod")?;
    let reference = format!("#{request_id}");
    start(&mut cursor, "ds:Reference", &[("URI", &reference)])?;
    start(&mut cursor, "ds:Transforms", &[])?;
    start(&mut cursor, "ds:Transform", &[("Algorithm", ENVELOPED)])?;
    end(&mut cursor, "ds:Transform")?;
    start(
        &mut cursor,
        "ds:Transform",
        &[("Algorithm", EXCLUSIVE_C14N)],
    )?;
    end(&mut cursor, "ds:Transform")?;
    end(&mut cursor, "ds:Transforms")?;
    start(&mut cursor, "ds:DigestMethod", &[("Algorithm", SHA256_URI)])?;
    end(&mut cursor, "ds:DigestMethod")?;
    start(&mut cursor, "ds:DigestValue", &[])?;
    let digest = decode_base64(text(&mut cursor)?, 32)?;
    end(&mut cursor, "ds:DigestValue")?;
    end(&mut cursor, "ds:Reference")?;
    end(&mut cursor, "ds:SignedInfo")?;
    start(&mut cursor, "ds:SignatureValue", &[])?;
    let signature = decode_base64(text(&mut cursor)?, 1024)?;
    if signature.len() < 256 {
        return Err(UntrustedSaml);
    }
    end(&mut cursor, "ds:SignatureValue")?;
    end(&mut cursor, "ds:Signature")?;
    if cursor.next().is_some() {
        return Err(UntrustedSaml);
    }
    let digest: [u8; 32] = digest.try_into().map_err(|_| UntrustedSaml)?;
    let fragment = xml.get(info_start..info_end).ok_or(UntrustedSaml)?;
    let open_end = fragment
        .iter()
        .position(|byte| *byte == b'>')
        .ok_or(UntrustedSaml)?
        + 1;
    // Exclusive C14N includes only visibly used ancestor namespaces. The
    // strict shape above permits ds: names and no extra SignedInfo namespace
    // attributes, so binding ds on this standalone root is equivalent to
    // the original binding on its Signature parent or AuthnRequest root.
    let mut signed_info_xml = format!("<ds:SignedInfo xmlns:ds=\"{DS_NS}\">").into_bytes();
    signed_info_xml.extend_from_slice(&fragment[open_end..]);
    Ok(SignatureDetails {
        digest,
        signature,
        signed_info_xml,
    })
}

fn scan_signature_tokens(xml: &[u8]) -> Result<(Vec<Token>, usize, usize), UntrustedSaml> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().check_end_names = true;
    let mut tokens = Vec::new();
    let mut depth = 0usize;
    let mut info_start = None;
    let mut info_end = None;
    loop {
        let before = usize::try_from(reader.buffer_position()).map_err(|_| UntrustedSaml)?;
        match reader.read_event().map_err(|_| UntrustedSaml)? {
            Event::Start(e) => {
                depth += 1;
                if depth > 8 {
                    return Err(UntrustedSaml);
                }
                let name = e.name().as_ref().to_owned();
                if name == "ds:SignedInfo" && depth == 2 && info_start.replace(before).is_some() {
                    return Err(UntrustedSaml);
                }
                tokens.push(Token::Start(name, attributes(&e)?));
            }
            Event::Empty(e) => {
                let name = e.name().as_ref().to_owned();
                tokens.push(Token::Start(name.clone(), attributes(&e)?));
                tokens.push(Token::End(name));
            }
            Event::End(e) => {
                let name = e.name().as_ref().to_owned();
                if name == "ds:SignedInfo" && depth == 2 {
                    info_end =
                        Some(usize::try_from(reader.buffer_position()).map_err(|_| UntrustedSaml)?);
                }
                tokens.push(Token::End(name));
                depth = depth.checked_sub(1).ok_or(UntrustedSaml)?;
            }
            Event::Text(e) => {
                let content = e.xml10_content();
                let value = quick_xml::escape::unescape(&content).map_err(|_| UntrustedSaml)?;
                if !value.trim().is_empty() {
                    tokens.push(Token::Text(value.into_owned()));
                }
            }
            Event::Eof => break,
            Event::Decl(_)
            | Event::DocType(_)
            | Event::PI(_)
            | Event::Comment(_)
            | Event::CData(_)
            | Event::GeneralRef(_) => return Err(UntrustedSaml),
        }
        if tokens.len() > 40 {
            return Err(UntrustedSaml);
        }
    }
    if depth != 0 {
        return Err(UntrustedSaml);
    }
    Ok((
        tokens,
        info_start.ok_or(UntrustedSaml)?,
        info_end.ok_or(UntrustedSaml)?,
    ))
}

fn attributes(
    e: &quick_xml::events::BytesStart<'_>,
) -> Result<Vec<(String, String)>, UntrustedSaml> {
    e.attributes()
        .map(|attr| {
            let attr = attr.map_err(|_| UntrustedSaml)?;
            let value = attr
                .normalized_value(quick_xml::XmlVersion::Explicit1_0)
                .map_err(|_| UntrustedSaml)?;
            Ok((attr.key.as_ref().to_owned(), value.into_owned()))
        })
        .collect()
}

fn start<'a>(
    cursor: &mut impl Iterator<Item = &'a Token>,
    name: &str,
    attrs: &[(&str, &str)],
) -> Result<(), UntrustedSaml> {
    let Some(Token::Start(actual_name, actual_attrs)) = cursor.next() else {
        return Err(UntrustedSaml);
    };
    if actual_name != name
        || actual_attrs.len() != attrs.len()
        || !attrs.iter().all(|(key, value)| {
            actual_attrs
                .iter()
                .any(|(actual_key, actual_value)| actual_key == key && actual_value == value)
        })
    {
        return Err(UntrustedSaml);
    }
    Ok(())
}

fn end<'a>(cursor: &mut impl Iterator<Item = &'a Token>, name: &str) -> Result<(), UntrustedSaml> {
    match cursor.next() {
        Some(Token::End(actual)) if actual == name => Ok(()),
        _ => Err(UntrustedSaml),
    }
}

fn text<'a>(cursor: &mut impl Iterator<Item = &'a Token>) -> Result<&'a str, UntrustedSaml> {
    match cursor.next() {
        Some(Token::Text(value)) => Ok(value),
        _ => Err(UntrustedSaml),
    }
}

fn decode_base64(value: &str, max_len: usize) -> Result<Vec<u8>, UntrustedSaml> {
    let encoded: Vec<u8> = value
        .bytes()
        .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .collect();
    let decoded = STANDARD.decode(encoded).map_err(|_| UntrustedSaml)?;
    if decoded.is_empty() || decoded.len() > max_len {
        return Err(UntrustedSaml);
    }
    Ok(decoded)
}
