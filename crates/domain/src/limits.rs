//! Size ceilings shared by the crates that parse untrusted input.
//!
//! A ceiling that is written down twice is a ceiling that drifts: one copy is
//! raised for a real need and the other stays put, and the two ends of the
//! same path then disagree about what is acceptable. The values here live in
//! the crate every parsing crate already depends on, so there is one
//! definition and no cross-crate dependency is created to reach it.

/// Largest JWT accepted anywhere: as a token to verify, or as a token-shaped
/// parameter about to be handed to a verifier.
///
/// A client assertion with a long `aud` array and a request object with rich
/// `authorization_details` are the big ones, and both fit comfortably. Beyond
/// this it is not a token, it is a way to make the server do work.
pub const MAX_JWT_BYTES: usize = 8 * 1024;
