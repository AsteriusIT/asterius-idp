//! Bounded SAML 2.0 HTTP-POST form decoding (Bindings §3.5.4).
//!
//! Output is explicitly untrusted XML. This module does not parse or verify
//! XML Signature, resolve an ID, select an SP, or reserve a request ID. The
//! validator separately performs those checks before accepting a POST.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::saml::UntrustedSaml;

/// Base64 expands a 64 KiB XML document to at most 87,384 bytes. The form
/// limit also leaves room for percent escapes, RelayState and field names.
pub const MAX_POST_BODY_BYTES: usize = 128 * 1024;
pub const MAX_POST_XML_BYTES: usize = 64 * 1024;
const MAX_RELAY_STATE_BYTES: usize = 80;

/// An untrusted browser form. Neither field authorizes SSO processing.
#[derive(Debug, Clone)]
pub struct UntrustedPostForm {
    pub xml: Vec<u8>,
    pub relay_state: Option<Vec<u8>>,
}

/// Decodes only `SAMLRequest` and optional `RelayState` from one
/// `application/x-www-form-urlencoded` POST. Duplicate and unexpected
/// controls are refused, including `Signature` or `SigAlg` controls from
/// the separate SimpleSign binding, which this endpoint does not implement.
///
/// The SAMLRequest base64 may be line-wrapped as OASIS §3.5.4 permits.
/// Whitespace other than ASCII SP, HTAB, CR and LF is refused.
pub fn parse_post_form(
    content_type: &str,
    body: &[u8],
) -> Result<UntrustedPostForm, UntrustedSaml> {
    if !valid_content_type(content_type)
        || body.is_empty()
        || body.len() > MAX_POST_BODY_BYTES
        || !body.iter().all(|byte| (0x20..=0x7e).contains(byte))
    {
        return Err(UntrustedSaml);
    }

    let mut saml_request = None;
    let mut relay_state = None;
    for field in body.split(|byte| *byte == b'&') {
        let (name, value) = split_field(field)?;
        if value.is_empty() {
            return Err(UntrustedSaml);
        }
        let decoded = form_decode(value)?;
        match name {
            b"SAMLRequest" if saml_request.is_none() => saml_request = Some(decoded),
            b"RelayState" if relay_state.is_none() => relay_state = Some(decoded),
            _ => return Err(UntrustedSaml),
        }
    }

    let mut encoded = saml_request.ok_or(UntrustedSaml)?;
    encoded.retain(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'));
    if encoded.is_empty() || encoded.len() > ((MAX_POST_XML_BYTES + 2) / 3) * 4 {
        return Err(UntrustedSaml);
    }
    let xml = STANDARD.decode(encoded).map_err(|_| UntrustedSaml)?;
    if xml.is_empty() || xml.len() > MAX_POST_XML_BYTES {
        return Err(UntrustedSaml);
    }
    if relay_state.as_ref().is_some_and(|value: &Vec<u8>| {
        value.len() > MAX_RELAY_STATE_BYTES
            || value.iter().any(|byte| *byte < 0x20 || *byte == 0x7f)
    }) {
        return Err(UntrustedSaml);
    }
    Ok(UntrustedPostForm { xml, relay_state })
}

fn valid_content_type(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    let mut parts = value.split(';');
    if !parts.next().is_some_and(|essence| {
        essence
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return false;
    }
    match (parts.next(), parts.next()) {
        (None, None) => true,
        (Some(param), None) => {
            let Some((name, charset)) = param.trim().split_once('=') else {
                return false;
            };
            name.trim().eq_ignore_ascii_case("charset")
                && charset
                    .trim()
                    .trim_matches('"')
                    .eq_ignore_ascii_case("utf-8")
        }
        _ => false,
    }
}

fn split_field(field: &[u8]) -> Result<(&[u8], &[u8]), UntrustedSaml> {
    let equals = field
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or(UntrustedSaml)?;
    Ok((&field[..equals], &field[equals + 1..]))
}

fn form_decode(value: &[u8]) -> Result<Vec<u8>, UntrustedSaml> {
    let mut out = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        match value[index] {
            b'%' => {
                if index + 2 >= value.len() {
                    return Err(UntrustedSaml);
                }
                let high = (value[index + 1] as char)
                    .to_digit(16)
                    .ok_or(UntrustedSaml)?;
                let low = (value[index + 2] as char)
                    .to_digit(16)
                    .ok_or(UntrustedSaml)?;
                out.push(((high << 4) | low) as u8);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    Ok(out)
}
