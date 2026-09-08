//! Outbound requests: what this server fetches, and where it will not go.
//!
//! Everything the server *serves* is in [`crate::http`]. This is the other
//! direction, and it is a smaller module with a harder problem: the URLs here
//! were chosen by clients, so the question is never "how do I fetch this" but
//! "should I, and to what address".
//!
//! [`ssrf`] answers that as pure functions over a URL and an address, so the
//! rules can be table-tested without a socket. [`jwks`] is the one caller, the
//! adapter behind [`asterius_domain::ports::JwksFetcher`] that resolves a
//! client's `jwks_uri` for `ast-mxc.5`.

pub mod jwks;
pub mod ssrf;

pub use jwks::HttpsJwksFetcher;
