//! Ports: the traits through which protocol code reaches the outside world.
//!
//! Adapters live in `asterius-store-pg`, `asterius-jose` and the server crate.
//! Protocol crates depend on these traits and never on an implementation.

use std::fmt::Debug;
use time::OffsetDateTime;

/// Source of the current time.
///
/// Every expiry, `iat`/`exp` and lifetime check goes through a clock so that
/// tests can pin time instead of sleeping.
pub trait Clock: Debug + Send + Sync + 'static {
    /// The current instant, in UTC.
    fn now(&self) -> OffsetDateTime;
}

/// The real clock, backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_moves_forward() {
        let clock = SystemClock;
        assert!(clock.now() <= clock.now());
    }
}
