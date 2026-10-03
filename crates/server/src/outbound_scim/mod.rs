//! Candidate outbound SCIM lifecycle. Operator registry is empty by default.

mod client;
mod credentials;
mod proof;
mod worker;

pub use credentials::{OperatorCredential, ScopedCredentialRegistry};

pub use client::OutboundScimClient;

pub use worker::OutboundScimDeliverer;
