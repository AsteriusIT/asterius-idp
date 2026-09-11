//! The per-endpoint limiter's bucket keys — `ast-p2l.3`.
//!
//! A `client_id` is a string somebody else chose: it arrives in a request body,
//! it may be a megabyte long, and it may contain any character at all —
//! including the `:` these keys are built out of. So the properties worth
//! stating as assertions over arbitrary input are the ones that keep a chosen
//! id from naming a bucket it has no business naming:
//!
//! * **Deterministic.** The same client always lands in the same bucket, or a
//!   limit is walked out of by resending the same request.
//! * **Injective.** Two client ids share a bucket exactly when they are equal.
//!   Not by accident — that would let one client spend another's budget — and
//!   not by any spelling trick either.
//! * **Well-shaped.** A fixed prefix and a 64-character hex digest, whatever
//!   arrived: a megabyte in `client_id` must not become a megabyte-wide key in
//!   a table every request writes to.
//! * **Namespaced per endpoint.** `/register`'s counter and `/token`'s are
//!   different numbers an operator set separately, so no input may make one
//!   spend the other.
//! * **Disjoint from the address buckets.** `client_id = "x:ip:198.51.100.7"`
//!   must not name the bucket that address is counted in, in either direction.
//! * **Disjoint from the subject buckets** (`ast-5lw`). `/bc-authorize` counts
//!   requests about a *person* as well as requests from a client, and the two
//!   are different budgets: a chosen `client_id` that named a person's bucket
//!   would let a client spend the limit that exists to protect them.
//! * **Disjoint from the audit marker**, which shadows a bucket to keep the
//!   trail to one record per window. If a chosen id could produce a marker key,
//!   deciding "have I already reported this flood" would consume the budget it
//!   is deciding about.
//!
//! The digest is recomputed here from `sha2` rather than taken from the code
//! under test, for the reason the `login_bucket` target gives: if the encoding
//! drifted, every counter already in the table would move to a new key and
//! every live limit would silently reset.
#![no_main]

use asterius_domain::rate_limit::{
    LimitedEndpoint, audited_once_bucket, endpoint_address_bucket, endpoint_client_bucket,
    endpoint_subject_bucket,
};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest as _, Sha256};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `ep:<endpoint>:client:HEX(SHA-256(client_id))`, written out independently.
fn expected(endpoint: LimitedEndpoint, client_id: &str) -> String {
    let digest = Sha256::digest(client_id.as_bytes());
    let mut key = format!("ep:{}:client:", endpoint.as_str());
    for byte in digest {
        key.push_str(&format!("{byte:02x}"));
    }
    key
}

/// Splits the input into two client ids, so that pairs — not just single
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
    let endpoint = LimitedEndpoint::Token;

    // --- determinism and the encoding ---------------------------------------

    let bucket = endpoint_client_bucket(endpoint, &left);
    assert_eq!(
        bucket,
        endpoint_client_bucket(endpoint, &left),
        "the same client landed in two buckets"
    );
    assert_eq!(
        bucket.as_str(),
        expected(endpoint, &left),
        "the bucket key no longer matches the string it is specified as; \
         every counter in the table would be orphaned"
    );

    // --- shape --------------------------------------------------------------

    let prefix = format!("ep:{}:client:", endpoint.as_str());
    let digest = bucket
        .as_str()
        .strip_prefix(&prefix)
        .expect("a client bucket is namespaced");
    assert_eq!(digest.len(), 64, "a key is a 32-byte digest in hex");
    assert!(
        digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "a key left the hex alphabet: {digest}"
    );

    // --- injectivity --------------------------------------------------------

    assert_eq!(
        endpoint_client_bucket(endpoint, &right) == bucket,
        right == left,
        "two client ids agreed on a bucket without being equal, or the \
         reverse: {left:?} against {right:?}"
    );

    // --- namespaces ---------------------------------------------------------

    for other in LimitedEndpoint::ALL {
        assert_eq!(
            endpoint_client_bucket(other, &left) == bucket,
            other == endpoint,
            "one endpoint's counter was spendable from another's"
        );
    }

    for address in [
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        for other in LimitedEndpoint::ALL {
            let by_address = endpoint_address_bucket(other, address);
            assert_ne!(
                by_address, bucket,
                "a client id named an address bucket: {left:?}"
            );
            assert_ne!(
                audited_once_bucket(&by_address),
                bucket,
                "a client id named an audit marker: {left:?}"
            );
        }
    }

    for other in LimitedEndpoint::ALL {
        let by_subject = endpoint_subject_bucket(other, &left);
        assert_ne!(
            by_subject, bucket,
            "a client id named the bucket a person is counted in: {left:?}"
        );
        assert_ne!(
            audited_once_bucket(&by_subject),
            bucket,
            "a client id named a subject bucket's audit marker: {left:?}"
        );
        assert_eq!(
            endpoint_subject_bucket(other, &right) == by_subject,
            right == left,
            "two people agreed on a bucket without being the same person: \
             {left:?} against {right:?}"
        );
    }

    assert_ne!(
        audited_once_bucket(&bucket),
        bucket,
        "a bucket's audit marker is the bucket itself, so reporting a flood \
         would spend the budget it is reporting"
    );
});
