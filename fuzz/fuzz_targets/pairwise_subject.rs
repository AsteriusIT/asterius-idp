//! Pairwise and public subject identifiers — OIDC Core §8, §8.1.
//!
//! §8.1 permits any algorithm with three properties, and this target is those
//! three properties written as assertions over generated sectors, users and
//! salts:
//!
//! * **The algorithm MUST be deterministic.** The same triple always produces
//!   the same `sub`, however the triple was built.
//! * **Distinct Sector Identifier values MUST result in distinct Subject
//!   Identifier values.** Extended here to the whole input: two different
//!   triples never share a `sub`. The generator concentrates on the case a
//!   plain concatenation gets wrong — `("ab", …)` against `("a", "b…")` — which
//!   is the collision the RFC's own example formula admits and which length
//!   prefixes remove.
//! * **The value MUST NOT be reversible by any party other than the OpenID
//!   Provider.** Checked as far as a fuzzer can: no `sub` contains the sector,
//!   the user id or the salt, and changing only the salt changes the `sub`.
//!
//! It also pins the **encoding**, by recomputing it here from `sha2` and
//! `base64` rather than by calling the code under test. That is the assertion
//! with the longest reach: a `sub` is a relying party's primary key for a
//! person, OIDC Core §8 says it is "never reassigned", and a quiet change to
//! the hashed byte string would reassign every one of them at once.
#![no_main]

use asterius_domain::{PairwiseSalt, SectorIdentifier, SubjectId, UserId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

/// The domain separation prefix, restated rather than imported.
const DOMAIN: &[u8] = b"asterius/pairwise-subject/v1";

/// `BASE64URL(SHA-256(domain ++ len(sector) ++ sector ++ len(user) ++ user ++ salt))`,
/// written out independently of the implementation.
fn expected(sector: &str, user: &[u8; 16], salt: &[u8; 32]) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(&(sector.len() as u64).to_be_bytes());
    input.extend_from_slice(sector.as_bytes());
    input.extend_from_slice(&16_u64.to_be_bytes());
    input.extend_from_slice(user);
    input.extend_from_slice(salt);
    URL_SAFE_NO_PAD.encode(Sha256::digest(&input))
}

/// A structured generator: the fuzzer picks components, not characters.
struct Source<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Source<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn byte(&mut self) -> u8 {
        if self.bytes.is_empty() {
            return 0;
        }
        let byte = self.bytes[self.at % self.bytes.len()];
        self.at = self.at.wrapping_add(1);
        byte
    }

    fn pick<T: Copy>(&mut self, choices: &[T]) -> T {
        choices[usize::from(self.byte()) % choices.len()]
    }

    /// Hosts that are near-misses of each other: prefixes and extensions of one
    /// name, one name split at different points, and the public sentinel.
    ///
    /// A sector is the host component of a URL, so these are the values that
    /// actually reach the derivation. Prefix pairs are the point: they are what
    /// an unprefixed concatenation cannot tell apart.
    fn sector(&mut self) -> SectorIdentifier {
        const HOSTS: [&str; 12] = [
            "",
            "a",
            "ab",
            "abc",
            "rp.example",
            "rp.example.evil",
            "p.example",
            "xn--e1afmkfd.example",
            "[::1]",
            "127.0.0.1",
            "localhost",
            "sector.example",
        ];
        let host = self.pick(&HOSTS);
        SectorIdentifier::stored(host)
            .unwrap_or_else(|e| panic!("{host:?} should be a storable sector: {e}"))
    }

    fn user(&mut self) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        // Most draws differ in one byte from the previous one, which is the
        // case a truncated or mis-sliced input would hide.
        let vary = usize::from(self.byte()) % 16;
        for (index, slot) in bytes.iter_mut().enumerate() {
            *slot = if index == vary { self.byte() } else { 0x11 };
        }
        bytes
    }

    fn salt(&mut self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        let fill = self.byte();
        bytes.fill(fill);
        let vary = usize::from(self.byte()) % 32;
        bytes[vary] = self.byte();
        bytes
    }
}

fuzz_target!(|data: &[u8]| {
    let mut source = Source::new(data);
    let left_sector = source.sector();
    let right_sector = source.sector();
    let left_user = source.user();
    let right_user = source.user();
    let left_salt_bytes = source.salt();
    let right_salt_bytes = source.salt();

    let left_salt = PairwiseSalt::from_bytes(left_salt_bytes);
    let right_salt = PairwiseSalt::from_bytes(right_salt_bytes);
    let left_id = UserId::new(Uuid::from_bytes(left_user));
    let right_id = UserId::new(Uuid::from_bytes(right_user));

    // The production path rebuilds the salt from a decrypted column, so the
    // length check on that path has to agree with the array constructor: 32
    // bytes and nothing else, never stretched, never truncated.
    assert_eq!(
        PairwiseSalt::from_storage(&left_salt_bytes)
            .expect("32 bytes is a salt")
            .derive_subject(&left_sector, left_id)
            .as_str(),
        left_salt.derive_subject(&left_sector, left_id).as_str(),
        "a salt read back from storage derived a different subject"
    );
    if data.len() != PairwiseSalt::LEN {
        assert!(
            PairwiseSalt::from_storage(data).is_err(),
            "{} bytes was accepted as a pairwise salt",
            data.len()
        );
    }

    // --- the sector parser --------------------------------------------------

    // A stored sector is the record of which sector a `sub` belongs to. What it
    // accepts it must accept unchanged, or one host would have two spellings
    // and one person two identities in one place.
    let sector_text = left_sector.as_str().to_owned();
    assert_eq!(
        SectorIdentifier::stored(&sector_text)
            .expect("an accepted sector must re-parse")
            .as_str(),
        sector_text,
        "a sector was rewritten on the way in"
    );
    assert_eq!(left_sector.is_public(), sector_text.is_empty());

    // --- determinism --------------------------------------------------------

    let subject = left_salt.derive_subject(&left_sector, left_id);
    assert_eq!(
        left_salt.derive_subject(&left_sector, left_id).as_str(),
        subject.as_str(),
        "the derivation is not deterministic"
    );

    // --- the encoding, restated ---------------------------------------------

    assert_eq!(
        subject.as_str(),
        expected(&sector_text, &left_user, &left_salt_bytes),
        "the derivation no longer matches the byte string it is specified as; \
         every subject already issued would change"
    );

    // --- the shape ----------------------------------------------------------

    assert_eq!(subject.as_str().len(), 43, "a sub is a 32-byte digest");
    assert!(
        subject
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "a sub left the base64url alphabet: {subject}"
    );

    // --- irreversibility, as far as this can check it -----------------------

    // Long enough that containment means something. A 43-character digest
    // contains most single letters by chance, so the short hosts the generator
    // draws — they are there for the prefix-collision case below — would fail
    // this check without anything having leaked.
    if sector_text.len() >= 6 {
        assert!(
            !subject.as_str().contains(&sector_text),
            "a sub carried its sector: {subject}"
        );
    }
    assert!(
        !subject
            .as_str()
            .contains(&URL_SAFE_NO_PAD.encode(left_salt_bytes)),
        "a sub carried the tenant salt"
    );
    assert!(
        !subject
            .as_str()
            .contains(&Uuid::from_bytes(left_user).to_string()),
        "a sub carried the local account id"
    );

    // --- separation ---------------------------------------------------------

    let other = right_salt.derive_subject(&right_sector, right_id);
    let same_inputs = left_sector == right_sector
        && left_user == right_user
        && left_salt_bytes == right_salt_bytes;
    assert_eq!(
        subject.as_str() == other.as_str(),
        same_inputs,
        "two subjects agreed without their inputs agreeing, or the reverse: \
         sectors {left_sector:?}/{right_sector:?}"
    );

    // A public subject is its own sector, so it never collides with a pairwise
    // one for the same user under the same salt.
    if !left_sector.is_public() {
        let public = left_salt.derive_subject(&SectorIdentifier::public(), left_id);
        assert_ne!(public.as_str(), subject.as_str());
    }

    // Whatever came out is something the rest of the server can carry: OIDC
    // Core §8 caps a `sub` at 255 ASCII characters.
    assert!(SubjectId::new(subject.as_str().to_owned()).as_str().len() <= 255);
});
