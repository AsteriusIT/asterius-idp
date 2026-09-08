//! A wrapper that keeps secret material out of logs and out of memory, and the
//! one comparison that is safe to use on it.

use std::fmt;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize;

/// Holds a value that must never be printed, logged or serialised by accident.
///
/// Two properties, both of which are the point:
///
/// * `Debug` and `Display` print `[REDACTED]`. A `Secret<String>` inside a
///   `#[derive(Debug)]` config struct, a `tracing` field or a panic message
///   therefore cannot leak — the leak has to be written deliberately, by
///   calling [`Secret::expose`], which is easy to grep for and easy to review.
/// * The value is zeroed on drop, so a client secret does not linger in a freed
///   allocation for a core dump or a heap-scraping attacker to find.
/// * There is no `PartialEq`, so `==` on a secret does not compile. `==` on
///   bytes stops at the first difference, which turns "is this the right
///   secret?" into a per-byte oracle for anyone who can time the response.
///   Removing the operator is stronger than reviewing for it: it covers code
///   nobody has written yet, and code that reaches `==` through a generic bound
///   where the operator never appears in the text. [`Secret::ct_eq`] is the
///   only comparison there is; `crates/domain/src/secret_audit.rs` fails the
///   build if the impl ever comes back.
///
/// There is deliberately no `Deref`, no `AsRef` and no `Serialize`.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wraps a value.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Returns the protected value.
    ///
    /// Every call site is a place where a secret enters ordinary code, so name
    /// the reason in a comment when it is not obvious from the next line.
    pub const fn expose(&self) -> &T {
        &self.0
    }

    /// Consumes the wrapper and returns the value, cancelling zeroize-on-drop.
    pub fn into_inner(mut self) -> T
    where
        T: Default,
    {
        // Swap the value out and let the empty husk be dropped (and zeroed) in
        // its place, so the wrapper's Drop cannot clear what we just returned.
        std::mem::take(&mut self.0)
    }
}

impl<T: Zeroize + AsRef<[u8]>> Secret<T> {
    /// Whether the two secrets hold the same bytes, compared in constant time.
    ///
    /// The bound is on the wrapped type, not on `Secret` itself: `Secret` still
    /// exposes no `AsRef`, so this is the only thing that bound buys anyone.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        ct_eq(self.0.as_ref(), other.0.as_ref())
    }
}

/// Compares two byte strings in time that depends on their length but not on
/// their contents.
///
/// Every comparison of a code, a token, a PKCE verifier or a CSRF token goes
/// through here. Leaking the length is deliberate and harmless: these values
/// have a length fixed by the type that issued them, so an attacker learns
/// nothing from it that the specification did not already tell them. Leaking
/// *where* two values first differ is the thing that matters, because it turns
/// one search over the whole value into a short search per byte.
#[must_use]
pub fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<'de, T> serde::Deserialize<'de> for Secret<T>
where
    T: Zeroize + serde::Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[derive(Debug)]
    #[allow(dead_code)]
    struct Config {
        user: String,
        password: Secret<String>,
    }

    #[test]
    fn debug_and_display_are_redacted() {
        let secret = Secret::new(String::from("hunter2"));
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
        assert_eq!(format!("{secret}"), "[REDACTED]");
    }

    #[test]
    fn derived_debug_on_a_containing_struct_does_not_leak() {
        let config = Config {
            user: "asterius".to_owned(),
            password: Secret::new(String::from("hunter2")),
        };
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("hunter2"),
            "leaked through derived Debug: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));
        assert!(
            rendered.contains("asterius"),
            "non-secret fields should still be visible"
        );
    }

    #[test]
    fn expose_returns_the_value() {
        let secret = Secret::new(String::from("hunter2"));
        assert_eq!(secret.expose(), "hunter2");
        assert_eq!(Secret::new(String::from("hunter2")).into_inner(), "hunter2");
    }

    /// A stand-in for a real secret that records whether it was zeroed.
    ///
    /// The crate is `#![forbid(unsafe_code)]`, so we cannot read a freed
    /// allocation back to observe the wipe directly. Recording the call is the
    /// safe equivalent: what we need to know is that `Drop` reaches `zeroize`,
    /// and the `zeroize` crate is responsible for the wipe itself being
    /// compiler-proof.
    #[derive(Default)]
    struct ZeroizeSpy(Rc<Cell<bool>>);

    impl Zeroize for ZeroizeSpy {
        fn zeroize(&mut self) {
            self.0.set(true);
        }
    }

    #[test]
    fn drop_zeroizes_the_value() {
        let zeroed = Rc::new(Cell::new(false));
        drop(Secret::new(ZeroizeSpy(Rc::clone(&zeroed))));
        assert!(zeroed.get(), "Drop did not zeroize the protected value");
    }

    #[test]
    fn into_inner_does_not_zeroize_what_it_hands_back() {
        let zeroed = Rc::new(Cell::new(false));
        let taken = Secret::new(ZeroizeSpy(Rc::clone(&zeroed))).into_inner();
        assert!(!zeroed.get(), "into_inner zeroed the value it returned");
        drop(taken);
    }

    #[test]
    fn a_secret_matches_only_an_identical_secret() {
        let secret = Secret::new(String::from("hunter2"));
        assert!(secret.ct_eq(&Secret::new(String::from("hunter2"))));
        assert!(!secret.ct_eq(&Secret::new(String::from("hunter3"))));
        // A prefix and an extension are the two cases a short-circuiting
        // comparison answers early, so they are the ones worth naming.
        assert!(!secret.ct_eq(&Secret::new(String::from("hunter"))));
        assert!(!secret.ct_eq(&Secret::new(String::from("hunter22"))));
    }

    #[test]
    fn constant_time_comparison_agrees_with_ordinary_equality_on_every_case() {
        // Constant-time is worthless if it is also wrong, so pin the answer
        // against the operator we are refusing to use.
        for (left, right) in [
            (&b""[..], &b""[..]),
            (b"", b"a"),
            (b"a", b""),
            (b"a", b"a"),
            (b"ab", b"aa"),
            (b"aa", b"ab"),
            (b"abc", b"abcd"),
            (b"\x00", b"\x00"),
            (b"\x00a", b"\x00b"),
        ] {
            assert_eq!(
                ct_eq(left, right),
                left == right,
                "disagreed on {left:?} vs {right:?}"
            );
        }
    }

    #[test]
    fn deserialises_from_a_plain_scalar() {
        let secret: Secret<String> = serde_json::from_str("\"hunter2\"").expect("deserialise");
        assert_eq!(secret.expose(), "hunter2");
    }
}
