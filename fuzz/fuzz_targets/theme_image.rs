//! `theme_image::accept` — a tenant administrator's logo upload, decoded by a
//! third-party decoder and re-encoded by this server (`ast-ndk.1`).
//!
//! The most exposed parser in that bead, and the only one in the workspace
//! that hands attacker-controlled bytes to code outside it: PNG, JPEG and WebP
//! decoders. The bytes arrive at an authenticated endpoint, which lowers the
//! population and not the consequence — a tenant administrator account is a
//! thing an attacker buys, and what is stored is served to every user of that
//! tenant on the page where they type their password.
//!
//! The properties, each of them something no later step re-checks:
//!
//! * **Acceptance is total.** No byte string panics. A panic here is a 500 at
//!   an authenticated endpoint and, worse, a signal about which decoder path
//!   was reached.
//! * **What comes out is a PNG this server encoded.** Never the uploaded
//!   bytes, whatever they were: the re-encoding is what drops EXIF, `tEXt`,
//!   ICC profiles and anything appended after the image data.
//! * **What comes out is bounded.** No stored image is past
//!   `MAX_STORED_EDGE` on either edge, whatever the header declared, which is
//!   the decompression-bomb property stated on the output side.
//! * **The digest is the digest of what is stored.** Content addressing that
//!   addressed the *upload* would let two different stored images share a name.
//! * **Refusal is stable.** The same bytes are refused with the same status
//!   twice, so a client cannot learn anything by retrying.
#![no_main]

use asterius_admin_api::theme_image::{MAX_STORED_EDGE, accept};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

fuzz_target!(|data: &[u8]| {
    let first = accept(data);
    let second = accept(data);

    match (first, second) {
        (Err(one), Err(other)) => {
            assert_eq!(one, other, "the same bytes were refused two ways");
            assert!(
                matches!(one.status_code(), 400 | 413 | 415),
                "a refusal answered {}",
                one.status_code()
            );
        }
        (Ok(one), Ok(other)) => {
            assert_eq!(one, other, "re-encoding is not deterministic");

            // What is stored is a PNG, whatever arrived.
            assert!(
                one.bytes().starts_with(b"\x89PNG\r\n\x1a\n"),
                "the stored bytes are not a PNG"
            );
            assert!(
                one.width() <= MAX_STORED_EDGE && one.height() <= MAX_STORED_EDGE,
                "a stored image is {}x{}",
                one.width(),
                one.height()
            );
            assert!(
                one.width() > 0 && one.height() > 0,
                "an empty image was stored"
            );

            // The name of the asset is the hash of the asset.
            assert_eq!(
                one.digest(),
                hex::encode(Sha256::digest(one.bytes())),
                "the digest does not name the stored bytes"
            );

            // Content addressing is also a path segment: 64 lowercase hex
            // digits cannot traverse a directory.
            assert_eq!(one.digest().len(), 64);
            assert!(
                one.digest()
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "a digest left the hex alphabet"
            );

            // Nothing that arrived survives verbatim: an uploaded file that is
            // byte-identical to the stored one would mean the re-encoding did
            // not happen.
            if data.len() > 8 {
                assert_ne!(one.bytes(), data, "the upload was stored unchanged");
            }
        }
        _ => panic!("accepting the same bytes twice disagreed"),
    }
});
