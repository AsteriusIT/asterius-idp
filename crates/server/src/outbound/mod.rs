//! Outbound requests: what this server fetches, and where it will not go.
//!
//! Everything the server *serves* is in [`crate::http`]. This is the other
//! direction, and it is a smaller module with a harder problem: the URLs here
//! were chosen by clients, so the question is never "how do I fetch this" but
//! "should I, and to what address".
//!
//! [`ssrf`] answers that as pure functions over a URL and an address, so the
//! rules can be table-tested without a socket. [`jwks`] is the one adapter
//! behind [`asterius_domain::ports::ClientUrlFetcher`], written for a client's
//! `jwks_uri` in `ast-mxc.5`; [`sector`] is a second *caller* of that same
//! adapter — ADR-0006's "one outbound path" — for the
//! `sector_identifier_uri` of `ast-m9c.9`.

pub mod jwks;
pub mod sector;
pub mod ssrf;

pub use jwks::HttpsClientUrlFetcher;
