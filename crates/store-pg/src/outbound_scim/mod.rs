//! Candidate scoped catalogue and delivery adapters. No network inside a transaction.

mod administration;
mod jobs;

pub use jobs::PgOutboundScimJobs;

pub use administration::PgOutboundScimAdministration;
