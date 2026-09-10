//! What a client certificate says, and whether it is the one a client
//! registered.
//!
//! RFC 8705 gives two ways to authenticate a client with a certificate, and
//! they have almost nothing in common:
//!
//! * **§2.1, the PKI method.** Somebody else — a CA the tenant trusts —
//!   vouches for the certificate, and this server compares one *name* inside it
//!   against one name the client registered. The chain is what makes the name
//!   mean anything, and validating it is the transport's job (see
//!   `asterius_server::mtls`), not this module's.
//! * **§2.2, the self-signed method.** Nobody vouches for anything. The
//!   certificate authenticates because it is byte-for-byte one the client
//!   published in its own JWKS, so the comparison is a thumbprint and no name
//!   inside the certificate is read at all.
//!
//! # Why there is an X.509 parser here
//!
//! Only the PKI method needs one, and it needs exactly two things: the subject
//! distinguished name in RFC 4514 string form, and the `subjectAltName`
//! entries. Neither is exposed by rustls or by `rustls-webpki`, which parse
//! certificates for chain building and hand back opaque handles; and ADR-0004
//! puts OpenSSL out of reach. So [`der`] below reads the two fields this
//! server compares and nothing else.
//!
//! That parser takes bytes chosen by an unauthenticated caller, which sets its
//! rules. It borrows rather than copies, does not recurse at all — the nesting
//! it reads is fixed by X.509 and every level is a named function — bounds the
//! number of entries it will collect at each level, returns `None` on anything
//! it does not understand, and has a fuzz target
//! (`fuzz/fuzz_targets/client_certificate.rs`). It decides nothing: a
//! certificate it fails to parse is a certificate that authenticates nobody.
//!
//! # Why the comparison is exact
//!
//! RFC 8705 §2.1 is unusually plain about it:
//!
//! > The authorization server compares the expected value from client
//! > registration to the value presented in the certificate.
//!
//! No normalisation, no case folding, no wildcards, no DN component
//! reordering. Every one of those is a rule under which two different
//! certificates match one registration, and the second of them belongs to
//! somebody else. The subject DN this module renders is therefore a
//! deterministic function of the bytes: same certificate, same string, or no
//! string at all.

use asterius_domain::TlsClientAuthSubject;
use sha2::{Digest, Sha256};

/// The most bytes a client certificate may occupy.
///
/// A certificate arrives before anything about the caller is known — over TLS,
/// or in a header from a proxy — so its size is an attacker's choice until
/// this bound makes it ours. 16 KiB is several times the largest certificate
/// any public CA issues.
pub const MAX_CERTIFICATE_LEN: usize = 16 * 1024;

/// The most `x5c` entries a client's JWKS may contribute to one comparison.
///
/// The JWKS is fetched from a URL the client chose, so the work of comparing
/// thumbprints is bounded here rather than by the client's generosity.
pub const MAX_X5C_ENTRIES: usize = 64;

/// A client certificate, as DER.
///
/// Holds the bytes and nothing derived from them: every accessor re-reads the
/// DER, so there is no cached view that could describe a different certificate
/// from the one whose thumbprint is compared.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientCertificate {
    der: Vec<u8>,
}

impl std::fmt::Debug for ClientCertificate {
    /// The bytes are a credential-shaped value that ends up in error paths, so
    /// the thumbprint stands in for them. It identifies the certificate for an
    /// operator reading a log and cannot be replayed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCertificate")
            .field("thumbprint", &self.thumbprint_b64url())
            .finish()
    }
}

/// Why a presented certificate is not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CertificateError {
    /// Longer than [`MAX_CERTIFICATE_LEN`].
    #[error("the client certificate is too large")]
    TooLarge,
    /// Not a DER `Certificate`, or missing the fields this server compares.
    #[error("the client certificate could not be parsed")]
    Malformed,
}

impl ClientCertificate {
    /// Takes DER bytes as a certificate.
    ///
    /// The bytes are bounded and shape-checked here — an outer `SEQUENCE`
    /// spanning the whole input, containing a `tbsCertificate` this parser can
    /// read — so that a caller holding a [`ClientCertificate`] holds something
    /// the comparison functions can answer about.
    ///
    /// # Errors
    ///
    /// [`CertificateError::TooLarge`] past [`MAX_CERTIFICATE_LEN`], and
    /// [`CertificateError::Malformed`] for anything this parser cannot read.
    // fuzz-target: client_certificate
    pub fn from_der(der: impl Into<Vec<u8>>) -> Result<Self, CertificateError> {
        let der = der.into();
        if der.len() > MAX_CERTIFICATE_LEN {
            return Err(CertificateError::TooLarge);
        }
        if der.is_empty() {
            return Err(CertificateError::Malformed);
        }
        let candidate = Self { der };
        // Parsed once, on the way in. The result is thrown away: what is wanted
        // is the refusal, so that "this is a certificate" is decided in one
        // place rather than at each comparison.
        candidate
            .subject()
            .ok_or(CertificateError::Malformed)
            .map(|_| candidate)
    }

    /// The DER bytes, as presented.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// The SHA-256 thumbprint of the DER (RFC 8705 §3.1's `x5t#S256` input).
    #[must_use]
    pub fn thumbprint(&self) -> [u8; 32] {
        Sha256::digest(&self.der).into()
    }

    /// The thumbprint, base64url without padding.
    ///
    /// The form RFC 8705 §3.1 puts in a `cnf` claim, and the form a log line
    /// names a certificate by.
    #[must_use]
    pub fn thumbprint_b64url(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.thumbprint())
    }

    /// The names this certificate carries, or `None` if it cannot be read.
    #[must_use]
    pub fn subject(&self) -> Option<CertificateNames> {
        der::names(&self.der)
    }

    /// RFC 8705 §2.1: whether this certificate carries the value the client
    /// registered.
    ///
    /// Byte-exact, in the one field the registration named. A certificate that
    /// carries the registered DNS name in its `subject_dn` does not
    /// authenticate a client that registered `tls_client_auth_san_dns`, and
    /// that is deliberate: the client chose which field vouches for it.
    #[must_use]
    pub fn matches(&self, expected: &TlsClientAuthSubject) -> bool {
        let Some(names) = self.subject() else {
            return false;
        };
        match expected {
            TlsClientAuthSubject::SubjectDn(value) => names.subject_dn == *value,
            TlsClientAuthSubject::SanDns(value) => contains(&names.san_dns, value),
            TlsClientAuthSubject::SanUri(value) => contains(&names.san_uri, value),
            TlsClientAuthSubject::SanIp(value) => contains(&names.san_ip, value),
            TlsClientAuthSubject::SanEmail(value) => contains(&names.san_email, value),
        }
    }

    /// RFC 8705 §2.2: whether this certificate is one the client published.
    ///
    /// > The client's certificate is compared to the certificate(s) in the
    /// > client's registered JWK Set.
    ///
    /// The comparison is over the whole DER, by thumbprint. Nothing inside the
    /// certificate is read — not the subject, not the validity dates, not the
    /// key — because in this method the certificate is not vouched for by
    /// anybody: it authenticates only by being the one the client published,
    /// and any weaker comparison (same public key, same subject) would accept a
    /// certificate the client never published.
    ///
    /// `jwks` is the client's JWK Set as fetched or registered. Entries without
    /// an `x5c` are skipped rather than refused: a client may publish signing
    /// keys and a certificate in one set.
    #[must_use]
    pub fn is_published_in(&self, jwks: &serde_json::Value) -> bool {
        let Some(keys) = jwks.get("keys").and_then(serde_json::Value::as_array) else {
            return false;
        };
        // RFC 7517 §4.7: "The certificate containing the public key
        // corresponding to the key used to digitally sign the JWS MUST be the
        // first certificate." The rest of the chain is the issuers, and
        // matching against one of those would authenticate every client the
        // same CA issued.
        self.is_one_of(keys.iter().filter_map(|key| {
            key.get("x5c")
                .and_then(serde_json::Value::as_array)
                .and_then(|chain| chain.first())
                .and_then(serde_json::Value::as_str)
        }))
    }

    /// RFC 8705 §2.2, over leaf certificates already extracted from a JWK Set.
    ///
    /// The form the composed path uses: `asterius_jose`'s key cache keeps each
    /// `x5c` leaf as it was published, so a client whose keys came from a
    /// `jwks_uri` is compared against exactly what that URL served, and an
    /// inline `jwks` takes the same path.
    #[must_use]
    pub fn is_one_of<'a>(&self, leaves: impl Iterator<Item = &'a str>) -> bool {
        use base64::Engine as _;
        let expected = self.thumbprint();
        for (compared, leaf) in leaves.enumerate() {
            if compared >= MAX_X5C_ENTRIES {
                return false;
            }
            // Base64 of a certificate that could not fit the bound is not a
            // certificate this server would have accepted anyway.
            if leaf.len() > MAX_CERTIFICATE_LEN * 2 {
                continue;
            }
            // RFC 7517 §4.7 says base64, not base64url, and with padding —
            // it cites RFC 4648 §4 and DER never has a length that skips it.
            let Ok(der) = base64::engine::general_purpose::STANDARD.decode(leaf) else {
                continue;
            };
            // Constant time is not the property wanted here: a thumbprint is a
            // public value derived from a certificate the client publishes, and
            // an attacker who can vary it can compute the digest itself. What
            // matters is that the whole DER is what is compared.
            if Sha256::digest(&der).as_slice() == expected {
                return true;
            }
        }
        false
    }
}

/// Exact membership. Named so the comparison reads as the rule it is.
fn contains(values: &[String], expected: &str) -> bool {
    values.iter().any(|value| value == expected)
}

/// The names inside a certificate that RFC 8705 §2.1.2 can match on.
///
/// Nothing else is extracted, because nothing else is compared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateNames {
    /// The subject distinguished name, RFC 4514 string form.
    ///
    /// Always present — an empty subject renders as the empty string, which is
    /// a value no registration may hold ([`TlsClientAuthSubject`] refuses an
    /// empty one), so an empty subject matches nothing.
    pub subject_dn: String,
    /// `dNSName` entries, in the order the certificate lists them.
    pub san_dns: Vec<String>,
    /// `uniformResourceIdentifier` entries.
    pub san_uri: Vec<String>,
    /// `iPAddress` entries, rendered as text.
    pub san_ip: Vec<String>,
    /// `rfc822Name` entries.
    pub san_email: Vec<String>,
}

// ---------------------------------------------------------------------------
// DER
// ---------------------------------------------------------------------------

/// Just enough DER to read a subject DN and a `subjectAltName`.
///
/// Not a general X.509 library and not trying to be one. It reads the two
/// fields RFC 8705 §2.1 compares and refuses everything it does not
/// understand; a certificate this module cannot read is a certificate that
/// authenticates nobody, which is the safe direction.
mod der {
    use super::CertificateNames;

    /// The most RDNs, and the most SAN entries, one certificate may contribute.
    const MAX_ENTRIES: usize = 128;

    /// One DER TLV.
    #[derive(Debug, Clone, Copy)]
    struct Tlv<'a> {
        tag: u8,
        value: &'a [u8],
    }

    /// Reads one TLV from the front of `input`, returning it and the rest.
    ///
    /// Definite-length form only: DER forbids the indefinite form, and
    /// accepting it would mean accepting an encoding a signer never produced.
    fn read(input: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
        let (&tag, rest) = input.split_first()?;
        // High-tag-number form (bottom five bits all set) does not appear in
        // any field this parser reads.
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (&first, rest) = rest.split_first()?;
        let (length, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            // 0x80 is the indefinite form; more than four length bytes is a
            // length no certificate has.
            if count == 0 || count > 4 || count > rest.len() {
                return None;
            }
            let (bytes, rest) = rest.split_at(count);
            // DER requires the minimal encoding: a leading zero here is a
            // second spelling of a length, and a parser that accepts two
            // spellings is one whose output depends on which it saw.
            if bytes[0] == 0 {
                return None;
            }
            let mut length = 0usize;
            for byte in bytes {
                length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
            }
            (length, rest)
        };
        if length > rest.len() {
            return None;
        }
        let (value, rest) = rest.split_at(length);
        Some((Tlv { tag, value }, rest))
    }

    /// Reads one TLV that must fill `input` exactly and carry `tag`.
    fn read_exact(input: &[u8], tag: u8) -> Option<&[u8]> {
        let (tlv, rest) = read(input)?;
        (tlv.tag == tag && rest.is_empty()).then_some(tlv.value)
    }

    const SEQUENCE: u8 = 0x30;
    const SET: u8 = 0x31;
    const OID: u8 = 0x06;
    const OCTET_STRING: u8 = 0x04;
    const BIT_STRING: u8 = 0x03;
    const INTEGER: u8 = 0x02;

    /// `id-ce-subjectAltName`, 2.5.29.17.
    const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

    /// The names inside a DER `Certificate`.
    pub(super) fn names(der: &[u8]) -> Option<CertificateNames> {
        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm,
        //                            signature BIT STRING }
        let certificate = read_exact(der, SEQUENCE)?;
        let (tbs, rest) = read(certificate)?;
        if tbs.tag != SEQUENCE {
            return None;
        }
        // The two fields after the TBS are read only to confirm the shape: a
        // blob whose first element happens to be a plausible SEQUENCE is not a
        // certificate.
        let (algorithm, rest) = read(rest)?;
        if algorithm.tag != SEQUENCE {
            return None;
        }
        let (signature, rest) = read(rest)?;
        if signature.tag != BIT_STRING || !rest.is_empty() {
            return None;
        }
        tbs_names(tbs.value)
    }

    /// TBSCertificate ::= SEQUENCE {
    ///   version [0] EXPLICIT Version DEFAULT v1, serialNumber INTEGER,
    ///   signature AlgorithmIdentifier, issuer Name, validity Validity,
    ///   subject Name, subjectPublicKeyInfo SubjectPublicKeyInfo,
    ///   ... , extensions [3] EXPLICIT Extensions OPTIONAL }
    fn tbs_names(tbs: &[u8]) -> Option<CertificateNames> {
        let (first, rest) = read(tbs)?;
        // `version` is `[0]`, and absent on a v1 certificate.
        let rest = if first.tag == 0xa0 {
            let (serial, rest) = read(rest)?;
            if serial.tag != INTEGER {
                return None;
            }
            rest
        } else if first.tag == INTEGER {
            rest
        } else {
            return None;
        };
        let (algorithm, rest) = read(rest)?;
        if algorithm.tag != SEQUENCE {
            return None;
        }
        let (issuer, rest) = read(rest)?;
        if issuer.tag != SEQUENCE {
            return None;
        }
        let (validity, rest) = read(rest)?;
        if validity.tag != SEQUENCE {
            return None;
        }
        let (subject, rest) = read(rest)?;
        if subject.tag != SEQUENCE {
            return None;
        }
        let (spki, mut rest) = read(rest)?;
        if spki.tag != SEQUENCE {
            return None;
        }

        let mut names = CertificateNames {
            subject_dn: distinguished_name(subject.value)?,
            ..CertificateNames::default()
        };

        // The optional trailer: [1] issuerUniqueID, [2] subjectUniqueID,
        // [3] extensions. Only the last is read.
        while !rest.is_empty() {
            let (field, tail) = read(rest)?;
            if field.tag == 0xa3 {
                let extensions = read_exact(field.value, SEQUENCE)?;
                read_subject_alt_name(extensions, &mut names)?;
            }
            rest = tail;
        }
        Some(names)
    }

    /// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
    /// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
    ///                          extnValue OCTET STRING }
    fn read_subject_alt_name(mut extensions: &[u8], names: &mut CertificateNames) -> Option<()> {
        let mut seen = 0usize;
        while !extensions.is_empty() {
            seen += 1;
            if seen > MAX_ENTRIES {
                return None;
            }
            let (extension, rest) = read(extensions)?;
            extensions = rest;
            if extension.tag != SEQUENCE {
                return None;
            }
            let (id, mut tail) = read(extension.value)?;
            if id.tag != OID {
                return None;
            }
            // `critical` is a DEFAULT FALSE BOOLEAN, so it may be absent.
            let (next, after) = read(tail)?;
            if next.tag == 0x01 {
                tail = after;
            }
            let value = read_exact(tail, OCTET_STRING)?;
            if id.value == SUBJECT_ALT_NAME {
                general_names(value, names)?;
            }
        }
        Some(())
    }

    /// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    ///
    /// Only the four forms RFC 8705 §2.1.2 registers a metadata field for are
    /// read. `otherName`, `directoryName` and the rest are skipped: a name this
    /// server cannot express as a registered expectation is a name it must not
    /// match on.
    fn general_names(value: &[u8], names: &mut CertificateNames) -> Option<()> {
        let mut entries = read_exact(value, SEQUENCE)?;
        let mut seen = 0usize;
        while !entries.is_empty() {
            seen += 1;
            if seen > MAX_ENTRIES {
                return None;
            }
            let (entry, rest) = read(entries)?;
            entries = rest;
            match entry.tag {
                // [1] rfc822Name, [2] dNSName, [6] URI — all IA5String, which
                // is ASCII. Anything outside it is refused rather than
                // lossily converted: a name with a replacement character in it
                // is a name that could match a registration it is not.
                0x81 | 0x82 | 0x86 => {
                    let text = ascii(entry.value)?;
                    match entry.tag {
                        0x81 => names.san_email.push(text),
                        0x82 => names.san_dns.push(text),
                        _ => names.san_uri.push(text),
                    }
                }
                // [7] iPAddress, an OCTET STRING of 4 or 16 bytes.
                0x87 => names.san_ip.push(ip_address(entry.value)?),
                _ => {}
            }
        }
        Some(())
    }

    /// IA5String is ASCII by definition. A byte outside it means the
    /// certificate does not say what it appears to say.
    fn ascii(bytes: &[u8]) -> Option<String> {
        bytes
            .is_ascii()
            .then(|| String::from_utf8_lossy(bytes).into_owned())
    }

    /// An `iPAddress` SAN, in the textual form RFC 8705 §2.1.2's
    /// `tls_client_auth_san_ip` carries.
    ///
    /// Rust's `Ipv6Addr` renders the RFC 5952 canonical form (lowercase hex,
    /// one run of zeroes collapsed), which is the form a registration is
    /// expected to hold. A 4-or-16-byte length is the whole validity check
    /// RFC 5280 §4.2.1.6 imposes; a name-constraint pair (8 or 32 bytes) is
    /// not a name and is refused.
    fn ip_address(bytes: &[u8]) -> Option<String> {
        match bytes.len() {
            4 => {
                let octets: [u8; 4] = bytes.try_into().ok()?;
                Some(std::net::Ipv4Addr::from(octets).to_string())
            }
            16 => {
                let octets: [u8; 16] = bytes.try_into().ok()?;
                Some(std::net::Ipv6Addr::from(octets).to_string())
            }
            _ => None,
        }
    }

    /// Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    ///
    /// Rendered per RFC 4514 §2: the RDNs are joined with `,` **in reverse
    /// order** ("the output consists of the string encodings of each
    /// RelativeDistinguishedName … in reverse order"), and the attributes
    /// within one RDN with `+`.
    fn distinguished_name(mut rdns: &[u8]) -> Option<String> {
        let mut rendered: Vec<String> = Vec::new();
        let mut seen = 0usize;
        while !rdns.is_empty() {
            seen += 1;
            if seen > MAX_ENTRIES {
                return None;
            }
            let (rdn, rest) = read(rdns)?;
            rdns = rest;
            if rdn.tag != SET {
                return None;
            }
            rendered.push(relative_name(rdn.value)?);
        }
        rendered.reverse();
        Some(rendered.join(","))
    }

    /// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
    fn relative_name(mut attributes: &[u8]) -> Option<String> {
        let mut rendered: Vec<String> = Vec::new();
        let mut seen = 0usize;
        while !attributes.is_empty() {
            seen += 1;
            if seen > MAX_ENTRIES {
                return None;
            }
            let (attribute, rest) = read(attributes)?;
            attributes = rest;
            if attribute.tag != SEQUENCE {
                return None;
            }
            let (kind, tail) = read(attribute.value)?;
            if kind.tag != OID {
                return None;
            }
            let (value, tail) = read(tail)?;
            if !tail.is_empty() {
                return None;
            }
            rendered.push(format!(
                "{}={}",
                attribute_type(kind.value),
                attribute_value(value.tag, value.value)
            ));
        }
        // A SET is unordered on the wire and DER sorts it by encoding, so the
        // rendering of a multi-valued RDN is already deterministic.
        Some(rendered.join("+"))
    }

    /// The short name RFC 4514 §3 gives an attribute type, or its dotted
    /// decimal form.
    ///
    /// The table is exactly RFC 4514 §3's, with `DC` and `UID` from RFC 4519.
    /// An OID outside it is rendered as `1.2.3.4`, which is what §2.3 requires
    /// — inventing a short name would produce a DN string no other
    /// implementation agrees with, and the registered value has to have come
    /// from somewhere.
    fn attribute_type(oid: &[u8]) -> String {
        match oid {
            [0x55, 0x04, 0x03] => "CN".to_owned(),
            [0x55, 0x04, 0x07] => "L".to_owned(),
            [0x55, 0x04, 0x08] => "ST".to_owned(),
            [0x55, 0x04, 0x0a] => "O".to_owned(),
            [0x55, 0x04, 0x0b] => "OU".to_owned(),
            [0x55, 0x04, 0x06] => "C".to_owned(),
            [0x55, 0x04, 0x09] => "STREET".to_owned(),
            [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC".to_owned(),
            [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01] => "UID".to_owned(),
            _ => dotted(oid),
        }
    }

    /// An OID's dotted decimal form.
    ///
    /// Returns a form no short name collides with. An arc that overflows is
    /// rendered as `?`: it cannot appear in a certificate a CA issued, and the
    /// alternative — refusing the whole DN — would let one absurd attribute
    /// stop a certificate from being *compared*, when the comparison would
    /// have failed anyway.
    fn dotted(oid: &[u8]) -> String {
        let Some((&first, rest)) = oid.split_first() else {
            return String::from("?");
        };
        let mut out = format!("{}.{}", first / 40, first % 40);
        let mut arc: u64 = 0;
        let mut pending = false;
        for byte in rest {
            let Some(shifted) = arc.checked_mul(128) else {
                return String::from("?");
            };
            arc = shifted + u64::from(byte & 0x7f);
            pending = true;
            if byte & 0x80 == 0 {
                out.push('.');
                out.push_str(&arc.to_string());
                arc = 0;
                pending = false;
            }
        }
        // A trailing continuation byte is a truncated OID.
        if pending {
            return String::from("?");
        }
        out
    }

    /// An `AttributeValue`, escaped as RFC 4514 §2.4 requires.
    ///
    /// A string type is rendered as its characters; anything else — and any
    /// string that is not valid UTF-8 — takes §2.4's hex form, `#` followed by
    /// the hex of the whole DER-encoded value. That fallback is what keeps the
    /// rendering total: every attribute value has exactly one rendering.
    fn attribute_value(tag: u8, value: &[u8]) -> String {
        // UTF8String, PrintableString, IA5String, T61String/TeletexString,
        // VisibleString, UniversalString and BMPString are the types a Name
        // carries. Only the first five are byte-oriented; the last two are
        // UCS encodings and take the hex form rather than a lossy conversion.
        let text = match tag {
            0x0c | 0x13 | 0x16 | 0x14 | 0x1a => std::str::from_utf8(value).ok(),
            _ => None,
        };
        let Some(text) = text else {
            return hex_form(tag, value);
        };
        escape(text)
    }

    /// RFC 4514 §2.4's `#` form: the hex of the complete DER TLV.
    fn hex_form(tag: u8, value: &[u8]) -> String {
        let mut out = String::with_capacity(3 + value.len() * 2);
        out.push('#');
        // Re-encoding the header rather than keeping a slice of the original:
        // the length here is this parser's, and a certificate carrying a
        // non-minimal length must not render as one that carries a minimal one.
        let mut header = vec![tag];
        encode_length(value.len(), &mut header);
        for byte in header.iter().chain(value) {
            out.push_str(&format!("{byte:02X}"));
        }
        out
    }

    fn encode_length(length: usize, out: &mut Vec<u8>) {
        if length < 0x80 {
            out.push(u8::try_from(length).unwrap_or(0x7f));
            return;
        }
        let bytes = length.to_be_bytes();
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0x7f));
        out.extend_from_slice(significant);
    }

    /// RFC 4514 §2.4: escape `"`, `+`, `,`, `;`, `<`, `>`, `\` anywhere; `#`
    /// and a space at the start; a space at the end; and the NUL character.
    fn escape(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let chars: Vec<char> = text.chars().collect();
        for (index, character) in chars.iter().enumerate() {
            let first = index == 0;
            let last = index + 1 == chars.len();
            match character {
                '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                    out.push('\\');
                    out.push(*character);
                }
                '#' if first => out.push_str("\\#"),
                ' ' if first || last => out.push_str("\\ "),
                '\u{0}' => out.push_str("\\00"),
                // Other control characters have no §2.4 escape and are legal in
                // a UTF8String, so they are kept as they are. A registration
                // may not contain one ([`TlsClientAuthSubject`] refuses control
                // characters), so such a DN matches nothing.
                _ => out.push(*character),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Builds a DER TLV.
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if value.len() < 0x80 {
            out.push(u8::try_from(value.len()).expect("short"));
        } else {
            let bytes = value.len().to_be_bytes();
            let first = bytes
                .iter()
                .position(|b| *b != 0)
                .expect("a non-zero length");
            out.push(0x80 | u8::try_from(bytes.len() - first).expect("few bytes"));
            out.extend_from_slice(&bytes[first..]);
        }
        out.extend_from_slice(value);
        out
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    /// One `AttributeTypeAndValue` in a SET, as a Name carries it.
    fn rdn(oid: &[u8], tag: u8, value: &str) -> Vec<u8> {
        tlv(0x31, &seq(&[tlv(0x06, oid), tlv(tag, value.as_bytes())]))
    }

    const CN: &[u8] = &[0x55, 0x04, 0x03];
    const O: &[u8] = &[0x55, 0x04, 0x0a];

    /// A certificate with the given subject RDNs and SAN entries.
    ///
    /// Everything this parser does not read — the serial, the algorithm, the
    /// validity, the key, the signature — is a placeholder of the right shape,
    /// because the subject and the SAN are the whole of what is compared.
    fn certificate(subject: &[Vec<u8>], san: &[Vec<u8>]) -> Vec<u8> {
        let mut tbs = vec![
            tlv(0xa0, &tlv(0x02, &[2])),
            tlv(0x02, &[0x01]),
            seq(&[tlv(0x06, &[0x2a])]),
            seq(&[]),
            seq(&[]),
            seq(subject),
            seq(&[seq(&[tlv(0x06, &[0x2a])]), tlv(0x03, &[0x00])]),
        ];
        if !san.is_empty() {
            let extension = seq(&[tlv(0x06, &[0x55, 0x1d, 0x11]), tlv(0x04, &seq(san))]);
            tbs.push(tlv(0xa3, &seq(&[extension])));
        }
        seq(&[
            seq(&tbs),
            seq(&[tlv(0x06, &[0x2a])]),
            tlv(0x03, &[0x00, 0xff]),
        ])
    }

    fn names_of(der: &[u8]) -> CertificateNames {
        ClientCertificate::from_der(der.to_vec())
            .expect("a parseable certificate")
            .subject()
            .expect("names")
    }

    // -----------------------------------------------------------------------
    // RFC 4514: the subject DN string
    // -----------------------------------------------------------------------

    /// RFC 4514 §2: the RDNs appear in reverse order, joined by `,`. This is
    /// the example from §4 in the order a certificate encodes it.
    #[test]
    fn a_subject_dn_renders_its_rdns_in_reverse_order() {
        // Arrange: encoded as DC=example,DC=com is stored — outermost last.
        let der = certificate(
            &[
                rdn(
                    &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19],
                    0x16,
                    "com",
                ),
                rdn(
                    &[0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19],
                    0x16,
                    "example",
                ),
                rdn(O, 0x0c, "Billing"),
                rdn(CN, 0x0c, "billing-client"),
            ],
            &[],
        );

        // Act
        let names = names_of(&der);

        // Assert
        assert_eq!(
            names.subject_dn,
            "CN=billing-client,O=Billing,DC=example,DC=com"
        );
    }

    /// RFC 4514 §2.4. Each of these characters has to come back escaped, or a
    /// DN string round-tripped through a registration would name a different
    /// certificate.
    #[test]
    fn a_subject_dn_escapes_what_rfc_4514_requires() {
        for (raw, expected) in [
            ("Acme, Inc.", "CN=Acme\\, Inc."),
            ("a+b", "CN=a\\+b"),
            ("say \"hi\"", "CN=say \\\"hi\\\""),
            ("back\\slash", "CN=back\\\\slash"),
            ("<tag>", "CN=\\<tag\\>"),
            ("semi;colon", "CN=semi\\;colon"),
            ("#hash", "CN=\\#hash"),
            (" leading", "CN=\\ leading"),
            ("trailing ", "CN=trailing\\ "),
        ] {
            // Arrange
            let der = certificate(&[rdn(CN, 0x0c, raw)], &[]);

            // Act
            let names = names_of(&der);

            // Assert
            assert_eq!(names.subject_dn, expected, "{raw}");
        }
    }

    /// RFC 4514 §2.3: an attribute type with no short name is rendered as a
    /// dotted-decimal OID, and §2.4 puts a value of a type this parser does not
    /// read into the `#` hex form.
    #[test]
    fn an_unknown_attribute_type_renders_as_an_oid_and_a_hex_value() {
        // Arrange: 1.2.840.113549.1.9.1 (emailAddress), value as a BMPString,
        // which is not a byte-oriented string type.
        let oid = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
        let der = certificate(
            &[tlv(0x31, &seq(&[tlv(0x06, oid), tlv(0x1e, &[0x00, 0x41])]))],
            &[],
        );

        // Act
        let names = names_of(&der);

        // Assert
        assert_eq!(names.subject_dn, "1.2.840.113549.1.9.1=#1E020041");
    }

    /// A multi-valued RDN joins with `+` and stays inside one comma-separated
    /// component (RFC 4514 §2.2).
    #[test]
    fn a_multi_valued_rdn_joins_with_a_plus() {
        // Arrange
        let set = tlv(
            0x31,
            &[
                seq(&[tlv(0x06, CN), tlv(0x0c, b"one")]),
                seq(&[tlv(0x06, O), tlv(0x0c, b"two")]),
            ]
            .concat(),
        );

        // Act
        let names = names_of(&certificate(&[set], &[]));

        // Assert
        assert_eq!(names.subject_dn, "CN=one+O=two");
    }

    // -----------------------------------------------------------------------
    // subjectAltName
    // -----------------------------------------------------------------------

    #[test]
    fn the_four_matchable_san_forms_are_read_and_the_rest_are_not() {
        // Arrange
        let der = certificate(
            &[rdn(CN, 0x0c, "billing")],
            &[
                tlv(0x81, b"ops@rp.example"),
                tlv(0x82, b"rp.example"),
                tlv(0x86, b"https://rp.example/id"),
                tlv(0x87, &[192, 0, 2, 1]),
                tlv(
                    0x87,
                    &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                ),
                // [0] otherName: a form with no registered metadata field.
                tlv(0xa0, &seq(&[tlv(0x06, &[0x2a]), tlv(0x0c, b"other")])),
            ],
        );

        // Act
        let names = names_of(&der);

        // Assert
        assert_eq!(names.san_email, vec!["ops@rp.example".to_owned()]);
        assert_eq!(names.san_dns, vec!["rp.example".to_owned()]);
        assert_eq!(names.san_uri, vec!["https://rp.example/id".to_owned()]);
        assert_eq!(
            names.san_ip,
            vec!["192.0.2.1".to_owned(), "2001:db8::1".to_owned()]
        );
    }

    // -----------------------------------------------------------------------
    // RFC 8705 §2.1: the comparison
    // -----------------------------------------------------------------------

    /// The registered value is compared to the certificate exactly, in the one
    /// field the client named.
    #[test]
    fn a_certificate_matches_only_the_field_that_was_registered() {
        // Arrange
        let certificate = ClientCertificate::from_der(certificate(
            &[rdn(CN, 0x0c, "billing")],
            &[tlv(0x82, b"rp.example")],
        ))
        .expect("parseable");

        // Act & Assert
        assert!(certificate.matches(&TlsClientAuthSubject::SubjectDn("CN=billing".to_owned())));
        assert!(certificate.matches(&TlsClientAuthSubject::SanDns("rp.example".to_owned())));
        // The right value in the wrong field authenticates nobody: the client
        // chose which field vouches for it.
        assert!(!certificate.matches(&TlsClientAuthSubject::SanUri("rp.example".to_owned())));
        assert!(!certificate.matches(&TlsClientAuthSubject::SubjectDn("rp.example".to_owned())));
    }

    /// No case folding, no whitespace tolerance, no suffix or wildcard match.
    /// Each of these is a rule under which somebody else's certificate matches.
    #[test]
    fn a_near_miss_does_not_match() {
        // Arrange
        let certificate = ClientCertificate::from_der(certificate(
            &[rdn(CN, 0x0c, "billing")],
            &[tlv(0x82, b"rp.example")],
        ))
        .expect("parseable");

        // Act & Assert
        for near in [
            "RP.example",
            "rp.example.",
            " rp.example",
            "rp.example ",
            "evil-rp.example",
            "rp.example.attacker.test",
            "*.example",
        ] {
            assert!(
                !certificate.matches(&TlsClientAuthSubject::SanDns(near.to_owned())),
                "{near} matched"
            );
        }
        for near in ["cn=billing", "CN=billing,", "CN= billing", "CN=billing "] {
            assert!(
                !certificate.matches(&TlsClientAuthSubject::SubjectDn(near.to_owned())),
                "{near} matched"
            );
        }
    }

    // -----------------------------------------------------------------------
    // RFC 8705 §2.2: the self-signed method
    // -----------------------------------------------------------------------

    #[test]
    fn a_self_signed_certificate_matches_the_x5c_the_client_published() {
        use base64::Engine as _;
        // Arrange
        let der = certificate(&[rdn(CN, 0x0c, "billing")], &[]);
        let certificate = ClientCertificate::from_der(der.clone()).expect("parseable");
        let encoded = base64::engine::general_purpose::STANDARD.encode(&der);
        let jwks = json!({"keys": [
            {"kty": "EC", "kid": "signing-only"},
            {"kty": "EC", "x5c": [encoded]},
        ]});

        // Act & Assert
        assert!(certificate.is_published_in(&jwks));
    }

    /// RFC 7517 §4.7 makes the leaf the first entry. Matching against an issuer
    /// further down the chain would authenticate every client that CA issued.
    #[test]
    fn only_the_first_x5c_entry_is_compared() {
        use base64::Engine as _;
        // Arrange
        let der = certificate(&[rdn(CN, 0x0c, "billing")], &[]);
        let certificate = ClientCertificate::from_der(der.clone()).expect("parseable");
        let other = certificate_bytes_for("somebody-else");
        let jwks = json!({"keys": [{"kty": "EC", "x5c": [
            base64::engine::general_purpose::STANDARD.encode(&other),
            base64::engine::general_purpose::STANDARD.encode(&der),
        ]}]});

        // Act & Assert
        assert!(!certificate.is_published_in(&jwks));
    }

    #[test]
    fn a_certificate_the_client_never_published_does_not_match() {
        use base64::Engine as _;
        // Arrange
        let certificate =
            ClientCertificate::from_der(certificate_bytes_for("billing")).expect("parseable");
        let published = base64::engine::general_purpose::STANDARD
            .encode(certificate_bytes_for("somebody-else"));

        // Act & Assert
        for jwks in [
            json!({}),
            json!({"keys": []}),
            json!({"keys": [{"kty": "EC"}]}),
            json!({"keys": [{"kty": "EC", "x5c": []}]}),
            json!({"keys": [{"kty": "EC", "x5c": ["not base64 !!"]}]}),
            json!({"keys": [{"kty": "EC", "x5c": [published]}]}),
        ] {
            assert!(!certificate.is_published_in(&jwks), "{jwks}");
        }
    }

    fn certificate_bytes_for(name: &str) -> Vec<u8> {
        certificate(&[rdn(CN, 0x0c, name)], &[])
    }

    // -----------------------------------------------------------------------
    // The parser's own rules
    // -----------------------------------------------------------------------

    #[test]
    fn a_certificate_past_the_size_bound_is_refused_before_it_is_parsed() {
        // Arrange
        let oversized = vec![0x30; MAX_CERTIFICATE_LEN + 1];

        // Act
        let error = ClientCertificate::from_der(oversized).expect_err("over the bound");

        // Assert
        assert_eq!(error, CertificateError::TooLarge);
    }

    /// Bytes from an unauthenticated caller. Every one of these must be a
    /// refusal, not a panic and not a certificate.
    #[test]
    fn malformed_der_is_refused_rather_than_guessed_at() {
        let valid = certificate_bytes_for("billing");
        let mut truncated = valid.clone();
        truncated.pop();
        let mut trailing = valid.clone();
        trailing.push(0x00);
        // A length byte claiming more than the input holds.
        let overlong = vec![0x30, 0x7f, 0x02, 0x01, 0x00];
        // The indefinite form, which DER forbids.
        let indefinite = vec![0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00];
        // A non-minimal length: 0x81 0x01 spells a length of one.
        let non_minimal = vec![0x30, 0x82, 0x00, 0x01, 0x00];

        for bytes in [
            vec![],
            vec![0x30],
            vec![0x00],
            vec![0x31, 0x00],
            truncated,
            trailing,
            overlong,
            indefinite,
            non_minimal,
        ] {
            assert_eq!(
                ClientCertificate::from_der(bytes.clone()).err(),
                Some(CertificateError::Malformed),
                "{bytes:02x?}"
            );
        }
    }

    /// The same bytes always render the same DN. A comparison against a
    /// registered string is only meaningful if this holds.
    #[test]
    fn the_rendering_is_a_function_of_the_bytes() {
        // Arrange
        let der = certificate(
            &[rdn(CN, 0x0c, "billing"), rdn(O, 0x0c, "Acme, Inc.")],
            &[tlv(0x82, b"rp.example")],
        );

        // Act
        let first = names_of(&der);
        let second = names_of(&der);

        // Assert
        assert_eq!(first, second);
    }
}
