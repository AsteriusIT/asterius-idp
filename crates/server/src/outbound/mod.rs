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
//!
//! [`post`] is the same path in the other direction — a body sent to a URL a
//! client registered, for the outbox worker's HTTP deliverer (`ast-0ju.9`) and
//! therefore for back-channel logout and SSF push. It borrows [`jwks`]'s TLS
//! configuration, resolution and connect rather than repeating them, because
//! ADR-0006's "one outbound path" has to mean one *connect* or the second
//! caller is one refactor away from resolving a name twice.

pub mod jwks;
pub mod post;
pub mod sector;
pub mod ssrf;

pub use jwks::HttpsClientUrlFetcher;
pub use post::{HttpsPoster, PostError, PostRequest};
