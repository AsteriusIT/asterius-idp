//! The logo upload: attacker-controlled bytes in, a re-encoded PNG out.
//!
//! This is the most exposed parser in `ast-ndk.1` and the only one in the bead
//! that hands untrusted bytes to a third-party decoder. It is written to the
//! OWASP File Upload cheat sheet's shape, and every step below exists because
//! skipping it is a documented way to lose a server.
//!
//! # Threat model
//!
//! The uploader is a **tenant administrator**: authenticated, authorised for
//! one tenant, and not trusted. A tenant administrator is exactly the account
//! an attacker buys or phishes when they want a foothold in a multi-tenant
//! product, and the artefact they upload is served to *every user of that
//! tenant* on the page where those users type their password. Four things
//! could go wrong, and each maps to a step here:
//!
//! 1. **Active content served from our origin.** An SVG is an XML document
//!    that runs script; an HTML file renamed `logo.png` is served as whatever
//!    a sniffing browser decides. Answer: the format is decided by *decoding*,
//!    never by the filename or the declared media type; only PNG, JPEG and
//!    WebP decoders are compiled in; and what is stored is this server's own
//!    re-encoding, byte for byte unrelated to what arrived.
//! 2. **A decompression bomb.** A 40 KiB PNG can declare 30000×30000 pixels
//!    and expand to 3.6 GiB of RGBA. A byte limit does not see it. Answer:
//!    [`MAX_PIXELS`] and [`MAX_EDGE`] are checked against the *header*,
//!    before a single row is decoded, and the decoder is additionally given
//!    its own allocation limit.
//! 3. **A memory-safety bug in a decoder.** The workspace is `forbid(unsafe_code)`
//!    but `image`'s dependencies are not, and a decoder is the classic place
//!    for a heap overflow. Answer: only three decoders are built, the input is
//!    bounded to [`MAX_UPLOAD_BYTES`] before any of them sees it, and the
//!    dimensions are bounded before the pixel loop.
//! 4. **Metadata riding along.** EXIF carries GPS coordinates, thumbnails and,
//!    in the field, whole other files; PNG carries arbitrary `tEXt` chunks and
//!    ICC profiles. Answer: re-encoding from raw pixels drops every chunk that
//!    is not pixels — that is what "re-encoded" means here, and
//!    `a_re_encoded_image_carries_no_metadata_chunk` asserts it.
//!
//! What this module deliberately does *not* do: it does not serve the bytes,
//! it does not choose the response headers (`Content-Type`,
//! `X-Content-Type-Options: nosniff` and a `Content-Disposition` belong to the
//! handler), and it does not store anything. It is a pure function, which is
//! also what lets `fuzz_targets/theme_image.rs` drive it.

use std::io::Cursor;

use asterius_domain::entities::theme::ImageFormat;
use image::{DynamicImage, ImageDecoder, ImageEncoder, ImageReader};
use sha2::{Digest, Sha256};

/// The most bytes an upload may carry.
///
/// The product rule (`ast-ndk.1`) is 200 KiB, and it is a bound on what
/// arrives, not on what is stored: the re-encoding is bounded separately by
/// [`MAX_STORED_EDGE`].
pub const MAX_UPLOAD_BYTES: usize = 200 * 1024;

/// The most pixels an uploaded image may declare, before it is decoded.
///
/// Four megapixels is a 2000×2000 logo — already far past anything that
/// renders at 40 pixels tall — and at RGBA it is 16 MiB of decoded buffer,
/// which is a size a request thread can hold without the process noticing.
pub const MAX_PIXELS: u64 = 4_000_000;

/// The longest either edge of an uploaded image may be, before it is decoded.
///
/// A separate bound from [`MAX_PIXELS`] because `1 x 4_000_000` is under the pixel
/// count and is still a pathological buffer for every resampler.
pub const MAX_EDGE: u32 = 2_000;

/// The longest either edge of the *stored* image is.
///
/// The logo renders at a couple of hundred CSS pixels at most, so this is
/// generous at twice that; what it really buys is a bound on the re-encoded
/// size, which is otherwise a function of how compressible the pixels are.
pub const MAX_STORED_EDGE: u32 = 512;

/// Why an upload was refused.
///
/// Each variant maps to one status code at the handler, and the mapping is
/// stated on [`ImageError::status_code`] rather than left to a `match` in a
/// route: an unsupported type is 415, a bomb is 413, and a file that simply
/// does not decode is 400.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ImageError {
    /// More than [`MAX_UPLOAD_BYTES`].
    #[error("an image upload is at most {MAX_UPLOAD_BYTES} bytes")]
    TooManyBytes,
    /// Not one of the three raster formats: an SVG, a PDF, an HTML file, a ZIP.
    #[error("only PNG, JPEG and WebP images are accepted")]
    UnsupportedFormat,
    /// A header declaring more than [`MAX_PIXELS`] or an edge past
    /// [`MAX_EDGE`].
    #[error("an image is at most {MAX_EDGE} pixels on a side and {MAX_PIXELS} pixels in total")]
    TooManyPixels,
    /// The bytes claim a format this server accepts and do not decode as it.
    #[error("that file does not decode as the image it claims to be")]
    Undecodable,
}

impl ImageError {
    /// The HTTP status this refusal is answered with.
    #[must_use]
    pub const fn status_code(self) -> u16 {
        match self {
            // OWASP's answer for a type the endpoint does not accept, and the
            // one the acceptance criterion names for SVG.
            Self::UnsupportedFormat => 415,
            Self::TooManyBytes | Self::TooManyPixels => 413,
            Self::Undecodable => 400,
        }
    }
}

/// An image this server decoded, re-encoded and is willing to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReEncodedImage {
    bytes: Vec<u8>,
    digest: String,
    width: u32,
    height: u32,
}

impl ReEncodedImage {
    /// The bytes to store and serve. Always a PNG; see [`accept`].
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The `sha-256` of [`ReEncodedImage::bytes`], in lowercase hex.
    ///
    /// This is what the theme document names, and it is the identity of the
    /// asset: the digest of what this server produced, never of what was
    /// uploaded, so two administrators uploading the same logo with different
    /// EXIF get one row.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// What the stored bytes are: always [`ImageFormat::Png`] today.
    #[must_use]
    pub const fn format(&self) -> ImageFormat {
        ImageFormat::Png
    }

    /// The stored image's width in pixels.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// The stored image's height in pixels.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }
}

/// Decodes an upload and re-encodes it as a PNG this server produced.
///
/// The order is the whole point, and it is the order OWASP's cheat sheet
/// gives: bound the bytes, decide the format from the bytes themselves, bound
/// the dimensions from the header, and only then decode.
///
/// The declared media type is *not* a parameter. A handler that passed one
/// would eventually trust it, and the only honest answer to "what is this
/// file" is "what did the decoder make of it".
///
/// Everything is re-encoded to PNG, whatever it arrived as. One output format
/// means one encoder to reason about, lossless output for the flat artwork a
/// logo usually is, and a `Content-Type` the serving handler can hard-code
/// instead of deriving from stored data.
///
/// # Errors
///
/// [`ImageError`], which carries the status code the handler answers with.
// fuzz-target: theme_image
pub fn accept(bytes: &[u8]) -> Result<ReEncodedImage, ImageError> {
    if bytes.len() > MAX_UPLOAD_BYTES {
        return Err(ImageError::TooManyBytes);
    }

    // The format comes from the magic bytes. `with_guessed_format` reads the
    // signature and nothing else, and the `match` below is what keeps a format
    // that is compiled in for a dependency's sake from becoming an accepted
    // upload type.
    let reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| ImageError::UnsupportedFormat)?;
    match reader.format() {
        Some(image::ImageFormat::Png | image::ImageFormat::Jpeg | image::ImageFormat::WebP) => {}
        _ => return Err(ImageError::UnsupportedFormat),
    }

    // The bomb check, on the header, before a row is decoded.
    // A format this endpoint accepts whose header does not hold up is
    // `Undecodable` and not `UnsupportedFormat`: the difference is 400 against
    // 415, and telling an administrator their PNG is an unsupported type when
    // it is a truncated PNG sends them looking in the wrong place.
    let mut decoder = reader.into_decoder().map_err(|_| ImageError::Undecodable)?;
    let (width, height) = decoder.dimensions();
    if width == 0
        || height == 0
        || width > MAX_EDGE
        || height > MAX_EDGE
        || u64::from(width) * u64::from(height) > MAX_PIXELS
    {
        return Err(ImageError::TooManyPixels);
    }

    // Belt and braces: the decoder gets an allocation ceiling of its own, so a
    // format whose header lies about its dimensions cannot allocate past what
    // the check above admitted. RGBA is four bytes a pixel, with room for one
    // intermediate buffer.
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_EDGE);
    limits.max_image_height = Some(MAX_EDGE);
    limits.max_alloc = Some(MAX_PIXELS * 8);
    decoder
        .set_limits(limits)
        .map_err(|_| ImageError::TooManyPixels)?;

    let image = DynamicImage::from_decoder(decoder).map_err(|_| ImageError::Undecodable)?;

    // Downscale so that the stored artefact is bounded too. `thumbnail` keeps
    // the aspect ratio and only ever shrinks.
    let image = if image.width() > MAX_STORED_EDGE || image.height() > MAX_STORED_EDGE {
        image.thumbnail(MAX_STORED_EDGE, MAX_STORED_EDGE)
    } else {
        image
    };

    // Re-encode from raw RGBA. This is where every ancillary chunk, every EXIF
    // block and every trailing byte after the image data is dropped: the
    // encoder is handed pixels, and pixels are all it can write.
    let rgba = image.to_rgba8();
    let mut png = Vec::new();
    image::codecs::png::PngEncoder::new(&mut png)
        .write_image(
            rgba.as_raw(),
            rgba.width(),
            rgba.height(),
            image::ExtendedColorType::Rgba8,
        )
        .map_err(|_| ImageError::Undecodable)?;

    let digest = hex::encode(Sha256::digest(&png));
    Ok(ReEncodedImage {
        bytes: png,
        digest,
        width: rgba.width(),
        height: rgba.height(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PNG of the given size, built by the same encoder the code under test
    /// uses — the input to these tests is a *valid* image, and the hostile
    /// inputs below are hand-built byte strings.
    fn png(width: u32, height: u32) -> Vec<u8> {
        let image = DynamicImage::new_rgba8(width, height);
        let mut bytes = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .expect("encoding a blank image cannot fail");
        bytes
    }

    #[test]
    fn a_png_is_accepted_and_comes_back_as_a_png() {
        let accepted = accept(&png(64, 64)).expect("a small PNG is a logo");

        assert_eq!(accepted.format(), ImageFormat::Png);
        assert_eq!(accepted.width(), 64);
        assert_eq!(accepted.height(), 64);
        assert!(accepted.bytes().starts_with(b"\x89PNG\r\n\x1a\n"));
    }

    /// The digest names what is stored, which is not what was uploaded.
    ///
    /// Note what this test does *not* claim: a PNG this server itself encoded
    /// re-encodes to the same bytes, and that is correct — re-encoding is
    /// idempotent on its own output, which is what makes content addressing
    /// work at all. The property is that the digest is computed over the
    /// stored bytes, so a file that carried anything extra gets the identity
    /// of the cleaned version.
    #[test]
    fn the_digest_names_the_stored_bytes_and_not_the_upload() {
        let uploaded = with_trailing_payload(png(32, 32));

        let accepted = accept(&uploaded).expect("valid");

        assert_eq!(
            accepted.digest(),
            hex::encode(Sha256::digest(accepted.bytes())),
            "the digest is over what is stored"
        );
        assert_ne!(
            accepted.digest(),
            hex::encode(Sha256::digest(&uploaded)),
            "the identity of the asset is what we produced, not what we were given"
        );
        assert_eq!(accepted.digest().len(), 64);
    }

    /// The acceptance criterion, in one test: an SVG is 415.
    #[test]
    fn an_svg_is_refused_with_415() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>"#;

        let error = accept(svg).expect_err("SVG is a script container, not a logo");

        assert_eq!(error, ImageError::UnsupportedFormat);
        assert_eq!(error.status_code(), 415);
    }

    /// A format `image` can decode and this endpoint does not accept must be
    /// refused by the `match`, not by the absence of a feature flag: the flags
    /// can be turned on by a dependency asking for them.
    #[test]
    fn a_format_outside_the_three_is_refused_even_if_its_decoder_exists() {
        // A GIF header. GIF is not compiled in and is not in the match either.
        let gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;";

        let error = accept(gif).expect_err("GIF is not one of the three");

        assert_eq!(error.status_code(), 415);
    }

    #[test]
    fn html_renamed_as_an_image_is_refused() {
        let html = b"<!DOCTYPE html><script>alert(document.cookie)</script>";

        let error = accept(html).expect_err("a filename is not a format");

        assert_eq!(error, ImageError::UnsupportedFormat);
    }

    #[test]
    fn an_upload_past_the_byte_bound_is_refused_before_anything_reads_it() {
        let too_big = vec![0u8; MAX_UPLOAD_BYTES + 1];

        let error = accept(&too_big).expect_err("bounded first");

        assert_eq!(error, ImageError::TooManyBytes);
        assert_eq!(error.status_code(), 413);
    }

    /// The decompression bomb: a header that declares far more pixels than the
    /// file could hold. It must be refused on the header, which is the only
    /// way to refuse it *cheaply*.
    /// CRC-32 of a PNG chunk, so that the bomb fixture below is a *valid* PNG
    /// header rather than a corrupt one — a corrupt one would be refused for
    /// the wrong reason and prove nothing about the dimension check.
    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = 0xffff_ffff_u32;
        for byte in bytes {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn a_decompression_bomb_is_refused_on_its_header() {
        // A PNG signature and a well-formed IHDR declaring 30000x30000 RGBA:
        // 3.6 GiB of decoded pixels in a file of 45 bytes. There is no image
        // data at all, and there does not need to be — the point is that
        // nothing past the header is ever read.
        let mut chunk = Vec::from(b"IHDR".as_slice());
        chunk.extend_from_slice(&30_000u32.to_be_bytes());
        chunk.extend_from_slice(&30_000u32.to_be_bytes());
        chunk.extend_from_slice(&[8, 6, 0, 0, 0]);

        let mut bomb = Vec::from(b"\x89PNG\r\n\x1a\n".as_slice());
        bomb.extend_from_slice(&13u32.to_be_bytes());
        bomb.extend_from_slice(&chunk);
        bomb.extend_from_slice(&crc32(&chunk).to_be_bytes());

        let error = accept(&bomb).expect_err("30000x30000 is 3.6 GiB of RGBA");

        // Either refusal is a refusal *of the header*: `TooManyPixels` is this
        // module's own check, and `Undecodable` is the PNG decoder declining
        // to be constructed around dimensions that large. What matters is that
        // neither one allocated a pixel buffer, and that no third answer — an
        // acceptance, or an out-of-memory abort — is possible.
        assert!(
            matches!(error, ImageError::TooManyPixels | ImageError::Undecodable),
            "{error}"
        );
        assert!(
            u64::from(30_000u32) * u64::from(30_000u32) > MAX_PIXELS,
            "the fixture is only a bomb because it is past the bound"
        );
    }

    /// The dimension check itself, on an image that really is what it says.
    ///
    /// The hand-built bomb above proves a header nothing decodes is refused;
    /// this proves the bound is *ours* and applies to a perfectly valid file
    /// one pixel past it.
    #[test]
    fn a_valid_image_past_the_dimension_bound_is_refused_with_413() {
        let oversized = png(MAX_EDGE + 1, MAX_EDGE + 1);

        let error = accept(&oversized).expect_err("past the bound is past the bound");

        assert_eq!(error, ImageError::TooManyPixels);
        assert_eq!(error.status_code(), 413);
    }

    #[test]
    fn an_image_larger_than_the_stored_bound_comes_back_scaled_down() {
        let accepted = accept(&png(1_024, 512)).expect("a large logo is scaled, not refused");

        assert!(accepted.width() <= MAX_STORED_EDGE);
        assert!(accepted.height() <= MAX_STORED_EDGE);
        assert_eq!(
            accepted.width() * 512,
            accepted.height() * 1_024,
            "the aspect ratio survives"
        );
    }

    /// Re-encoding is the whole reason this module exists: the stored bytes
    /// must carry no chunk the encoder did not write.
    /// A PNG with something riding along after the image data: the shape of
    /// every "the file also contained a payload" report.
    fn with_trailing_payload(mut png: Vec<u8>) -> Vec<u8> {
        let payload = b"tEXtComment\0<script>alert(1)</script>";
        png.extend_from_slice(
            &u32::try_from(payload.len() - 4)
                .expect("small")
                .to_be_bytes(),
        );
        png.extend_from_slice(payload);
        png
    }

    #[test]
    fn a_re_encoded_image_carries_no_metadata_chunk() {
        let uploaded = with_trailing_payload(png(16, 16));

        let accepted = accept(&uploaded).expect("the pixels still decode");

        let stored = accepted.bytes();
        assert!(
            !stored.windows(6).any(|window| window == b"tEXtCo"),
            "a text chunk survived the re-encoding"
        );
        assert!(
            !stored.windows(7).any(|window| window == b"<script"),
            "an appended payload survived the re-encoding"
        );
    }

    /// Two uploads of the same picture give the same digest, or content
    /// addressing does not address content.
    #[test]
    fn re_encoding_is_deterministic() {
        let first = accept(&png(48, 48)).expect("valid");
        let second = accept(&png(48, 48)).expect("valid");

        assert_eq!(first.digest(), second.digest());
    }

    #[test]
    fn truncated_bytes_are_refused_rather_than_half_decoded() {
        let mut truncated = png(64, 64);
        truncated.truncate(40);

        let error = accept(&truncated).expect_err("half a PNG is not a PNG");

        assert_eq!(error, ImageError::Undecodable);
        assert_eq!(
            error.status_code(),
            400,
            "a truncated PNG is a bad request, not an unsupported type"
        );
    }

    #[test]
    fn an_empty_upload_is_refused() {
        assert_eq!(
            accept(&[]).expect_err("nothing is not an image"),
            ImageError::UnsupportedFormat
        );
    }
}
