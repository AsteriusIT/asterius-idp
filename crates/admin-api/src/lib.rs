//! Admin API.
//!
//! A first-party, same-origin API for the React console. It is deliberately
//! *not* an OAuth public client: the console authenticates with the same
//! session cookie as the rest of the first-party surface.
#![forbid(unsafe_code)]
