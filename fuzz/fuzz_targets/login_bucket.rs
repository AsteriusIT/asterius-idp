//! The login limiter's bucket keys — `ast-2vk.9`.
//!
//! The key is what makes the per-account limit an anti-enumeration measure
//! rather than an enumeration oracle, so the properties are worth stating as
//! assertions over arbitrary input:
//!
//! * **Deterministic.** The same typed identifier always lands in the same
//!   bucket, or a limit can be walked out of by retyping.
//! * **Injective up to normalisation.** Two identifiers share a bucket exactly
//!   when their normalised forms are equal — never by accident, which would
//!   let one person lock another out, and never by case or width, which would
//!   be a free bypass.
//! * **Opaque.** The key carries no part of what was typed. The table is a
//!   list of failed sign-ins; if the key were the identifier, the table would
//!   be a list of accounts worth attacking, readable by anyone who can read
//!   the database.
//! * **Well-shaped.** A fixed prefix and a 64-character hex digest, so the key
//!   is bounded whatever arrives in the form field — a megabyte in `username`
//!   must not become a megabyte-wide primary key.
//! * **Disjoint namespaces.** No identifier, however chosen, can be made to
//!   collide with an address bucket. Otherwise one attacker could spend
//!   another account's budget, or their own address's.
//!
//! The digest is recomputed here from `sha2` rather than taken from the code
//! under test, so the encoding cannot drift quietly: every counter already in
//! the table would move to a new key, silently resetting every live limit.
#![no_main]

use asterius_domain::rate_limit::{account_bucket, ip_bucket, normalise_username};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest as _, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The prefix the key is namespaced with, restated rather than imported.
const PREFIX: &str = "login:account:";

/// `login:account:HEX(SHA-256(normalise(username)))`, written out independently.
fn expected(username: &str) -> String {
    let digest = Sha256::digest(normalise_username(username).as_bytes());
    let mut key = String::from(PREFIX);
    for byte in digest {
        key.push_str(&format!("{byte:02x}"));
    }
    key
}

/// Splits the input into two identifiers, so that pairs — not just single
/// values — reach the injectivity assertion.
fn pair(data: &[u8]) -> (String, String) {
    let cut = data.first().map_or(0, |b| usize::from(*b)) % (data.len().max(1));
    let (left, right) = data.split_at(cut.min(data.len()));
    (
        String::from_utf8_lossy(left).into_owned(),
        String::from_utf8_lossy(right).into_owned(),
    )
}

fuzz_target!(|data: &[u8]| {
    let (left, right) = pair(data);

    // --- determinism and the encoding ---------------------------------------

    let bucket = account_bucket(&left);
    assert_eq!(
        bucket,
        account_bucket(&left),
        "the same identifier landed in two buckets"
    );
    assert_eq!(
        bucket.as_str(),
        expected(&left),
        "the bucket key no longer matches the string it is specified as; \
         every counter in the table would be orphaned"
    );

    // --- shape --------------------------------------------------------------

    let digest = bucket
        .as_str()
        .strip_prefix(PREFIX)
        .expect("an account bucket is namespaced");
    assert_eq!(digest.len(), 64, "a key is a 32-byte digest in hex");
    assert!(
        digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "a key left the hex alphabet: {digest}"
    );

    // --- normalisation ------------------------------------------------------

    let normalised = normalise_username(&left);
    assert_eq!(
        normalise_username(&normalised),
        normalised,
        "normalisation is not idempotent, so a bucket depends on how often it \
         was computed"
    );
    assert_eq!(
        normalised.trim(),
        normalised,
        "a normalised identifier kept its surrounding whitespace"
    );
    // Case folding is what stops `ALICE` from being a bucket of its own.
    assert_eq!(
        account_bucket(&left.to_uppercase()),
        account_bucket(&left.to_lowercase()),
        "case decided which bucket an identifier fell into"
    );
    assert_eq!(
        account_bucket(&format!("  {left}  ")),
        bucket,
        "surrounding whitespace decided which bucket an identifier fell into"
    );

    // --- injectivity --------------------------------------------------------

    assert_eq!(
        account_bucket(&right) == bucket,
        normalise_username(&right) == normalised,
        "two identifiers agreed on a bucket without agreeing on their \
         normalised form, or the reverse: {left:?} against {right:?}"
    );

    // --- opacity ------------------------------------------------------------

    // Six characters, for the reason the pairwise-subject target gives: a
    // 64-character hex string contains most short strings by chance, and a
    // false alarm there would say nothing about a leak.
    if normalised.len() >= 6 && normalised.is_ascii() {
        assert!(
            !digest.contains(&normalised),
            "a bucket key carried the identifier it counts"
        );
    }

    // --- disjoint namespaces ------------------------------------------------

    for address in [
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        assert_ne!(
            ip_bucket(address),
            bucket,
            "an identifier collided with an address bucket"
        );
    }
});
