//! Form parameters, with duplicates still visible.
//!
//! Both endpoints that take a form body — the pushed authorization request
//! endpoint and the token endpoint — are governed by the same sentence.
//! RFC 6749 §3.1 and §3.2 each say request parameters "MUST NOT be included
//! more than once", and RFC 9126 §2.1 inherits it.
//!
//! A `HashMap<String, String>` would have already lost the thing that rule
//! asks us to check, so parsing keeps the pairs as they arrived. That is the
//! whole reason this type exists: a server that silently takes the first
//! value, or the last, is a server whose choice an attacker can rely on — and
//! two intermediaries that choose differently is how one request gets
//! validated as one thing and executed as another.

use std::collections::BTreeMap;

/// A parameter that appeared more than once.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("parameter {0} appeared more than once")]
pub struct Duplicated(pub String);

/// The form parameters of a request, with duplicates still visible.
///
/// A `HashMap<String, String>` would have already lost the thing RFC 6749 §3.1
/// asks us to check, so parsing takes the pairs as they arrived.
#[derive(Debug, Default)]
pub struct Parameters(BTreeMap<String, Vec<String>>);

impl Parameters {
    /// Collects `pairs`, keeping repeats so they can be refused.
    #[must_use]
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, value) in pairs {
            map.entry(key.into()).or_default().push(value.into());
        }
        Self(map)
    }

    /// The single value of `name`, or an error if it appeared twice.
    ///
    /// # Errors
    ///
    /// [`Duplicated`] if the parameter was sent more than once.
    pub fn get(&self, name: &str) -> Result<Option<&str>, Duplicated> {
        match self.0.get(name).map(Vec::as_slice) {
            None | Some([]) => Ok(None),
            Some([one]) => Ok(Some(one.as_str())),
            Some(_) => Err(Duplicated(name.to_owned())),
        }
    }

    /// Whether `name` was present at all, however many times.
    #[must_use]
    pub fn present(&self, name: &str) -> bool {
        self.0.get(name).is_some_and(|values| !values.is_empty())
    }

    /// Every value of a parameter that may legitimately repeat.
    ///
    /// RFC 8707 §2 defines `resource` as repeatable, which is the exception
    /// that makes the general rule worth stating.
    #[must_use]
    pub fn multi(&self, name: &str) -> &[String] {
        self.0.get(name).map_or(&[], Vec::as_slice)
    }
}
