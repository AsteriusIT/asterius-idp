//! Two key-encryption keys, one of them on its way out.
//!
//! Rotating the KEK is not instantaneous: `asterius rewrap-kek` moves the rows
//! over one tenant at a time, and between the moment the first row moves and
//! the moment the last replica has been restarted on the new key, the
//! deployment holds rows under two different keys. A process holding only one
//! of them cannot open the other's rows — the `kek_id` column says so before
//! the AEAD is even asked — and that is the window step 3 to 5 of the rotation
//! runbook warns about: a signer keeps signing from memory ([`CachedSigner`]),
//! but a restart, a staged key or a first `sub` in a sector nobody has visited
//! fails.
//!
//! [`CompositeKek`] closes that window. It is the current key with a fallback:
//!
//! * **Reading** tries the current key and, only if that key refuses the row,
//!   the previous one.
//! * **Writing** is always, without exception, under the current key. There is
//!   no path through this type that seals anything under the previous one, so
//!   configuring a previous key never *adds* rows that depend on it — it only
//!   opens the ones that are already there, and every write moves a row
//!   forward.
//!
//! # The risk this takes on
//!
//! A key an operator has retired stays readable by the process for as long as
//! it is configured. That is the trade, stated plainly: the window of partial
//! unavailability is exchanged for a longer window in which a stolen database
//! dump *plus* a stolen configuration opens rows sealed under either key. It is
//! the operator's job to remove `kek_previous_*` at the end of the rotation,
//! which is why the runbook ends with that step and why every fallback is
//! logged at `warn` — an operator who has forgotten can see it in the logs.
//!
//! [`CachedSigner`]: crate::store::CachedSigner

use super::{Kek, KeyBinding, WrappedKey};
use crate::JoseError;
use std::fmt;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The key-encryption key in use, plus the one it replaced.
///
/// Built at boot from `[keys] kek_*` and `[keys] kek_previous_*`, and handed to
/// everything that stores sealed material, so the fallback is a property of the
/// deployment rather than of one call site remembering to try twice.
pub struct CompositeKek {
    current: Arc<dyn Kek>,
    previous: Arc<dyn Kek>,
}

impl fmt::Debug for CompositeKek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ids only — they are derived from the material and reveal nothing
        // about it — and both of them, because "which two keys is this process
        // holding" is the question an operator mid-rotation is asking.
        f.debug_struct("CompositeKek")
            .field("current", &self.current.id())
            .field("previous", &self.previous.id())
            .finish()
    }
}

impl CompositeKek {
    /// Pairs the key in use with the one being rotated away from.
    ///
    /// # Errors
    ///
    /// Returns [`JoseError::KekUnavailable`] if the two keys are the same one.
    /// A previous key equal to the current one buys nothing and hides a real
    /// mistake — an operator who edited the wrong line of the configuration and
    /// believes a rotation is being covered when it is not — so it is refused
    /// at boot rather than tolerated.
    pub fn new(current: Arc<dyn Kek>, previous: Arc<dyn Kek>) -> Result<Self, JoseError> {
        if current.id() == previous.id() {
            return Err(JoseError::KekUnavailable {
                origin: previous.id().to_owned(),
                reason: "the previous key-encryption key is the one already in use",
            });
        }
        Ok(Self { current, previous })
    }

    /// The key everything is written under.
    #[must_use]
    pub fn current(&self) -> &Arc<dyn Kek> {
        &self.current
    }

    /// The key rows are still being moved off.
    #[must_use]
    pub fn previous(&self) -> &Arc<dyn Kek> {
        &self.previous
    }
}

/// Whether an error from the current key means "this row is not mine".
///
/// Two errors mean that, and they are the two ends of the same question.
/// [`JoseError::KekMismatch`] is the ordinary one: the row names a different
/// `kek_id`, and the current key refused it without touching the ciphertext.
/// [`JoseError::Unwrap`] is the AEAD saying the bytes do not authenticate,
/// which is what an implementation that does not record an id — a KMS adapter
/// keyed by ARN, a future envelope — would return instead.
///
/// Nothing else falls back. A [`JoseError::Wrap`] or a
/// [`JoseError::KekUnavailable`] is the provider or the configuration failing,
/// and retrying that under a second key turns one clear error into two.
const fn is_not_ours(error: &JoseError) -> bool {
    matches!(error, JoseError::Unwrap | JoseError::KekMismatch { .. })
}

#[async_trait::async_trait]
impl Kek for CompositeKek {
    /// The current key's id: it is what every row this process writes carries.
    fn id(&self) -> &str {
        self.current.id()
    }

    /// Seals under the current key. The previous key is never asked.
    async fn wrap(
        &self,
        binding: KeyBinding<'_>,
        plaintext: &[u8],
    ) -> Result<WrappedKey, JoseError> {
        self.current.wrap(binding, plaintext).await
    }

    /// Opens under the current key, falling back to the previous one.
    ///
    /// The fallback is reported at `warn` with the row's identifiers — tenant
    /// and `kid`, or tenant and which secret — because each one is a row the
    /// re-wrap has not reached, and an operator who sees these after the
    /// rotation was declared finished has a rotation that was not finished.
    /// Nothing derived from the plaintext is logged.
    ///
    /// # Errors
    ///
    /// The *current* key's error, always, even when the previous key was tried
    /// and also refused. The current key is the one the deployment is supposed
    /// to be on, so its account of the failure — "this row names another
    /// `kek_id`" — is the one that tells an operator what to do.
    async fn unwrap(
        &self,
        binding: KeyBinding<'_>,
        wrapped: &WrappedKey,
    ) -> Result<Zeroizing<Vec<u8>>, JoseError> {
        let refusal = match self.current.unwrap(binding, wrapped).await {
            Ok(plaintext) => return Ok(plaintext),
            Err(error) if is_not_ours(&error) => error,
            Err(error) => return Err(error),
        };

        match self.previous.unwrap(binding, wrapped).await {
            Ok(plaintext) => {
                tracing::warn!(
                    row = %binding.row(),
                    kek = self.previous.id(),
                    current = self.current.id(),
                    "opened under the previous key-encryption key: this row has not been \
                     re-wrapped yet"
                );
                Ok(plaintext)
            }
            Err(_) => Err(refusal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kek::{KEK_LEN, LocalKek};
    use asterius_domain::TenantId;
    use asterius_domain::keys::{KeyPurpose, Kid, SigningAlgorithm};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const OLD_KEK: [u8; KEK_LEN] = [0x11; KEK_LEN];
    const NEW_KEK: [u8; KEK_LEN] = [0x22; KEK_LEN];

    fn old() -> Arc<LocalKek> {
        Arc::new(LocalKek::from_bytes(&OLD_KEK).expect("a 32-byte key is a valid KEK"))
    }

    fn current() -> Arc<LocalKek> {
        Arc::new(LocalKek::from_bytes(&NEW_KEK).expect("a 32-byte key is a valid KEK"))
    }

    fn tenant() -> TenantId {
        TenantId::new("demo")
    }

    fn kid() -> Kid {
        Kid::new("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
    }

    fn binding<'a>(tenant: &'a TenantId, kid: &'a Kid) -> KeyBinding<'a> {
        KeyBinding::new(tenant, kid, KeyPurpose::Signing, SigningAlgorithm::EdDsa)
    }

    /// A KEK that counts what it is asked to do, over a real one.
    #[derive(Debug)]
    struct Spy {
        inner: Arc<LocalKek>,
        unwraps: AtomicUsize,
        wraps: AtomicUsize,
    }

    impl Spy {
        fn over(inner: Arc<LocalKek>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                unwraps: AtomicUsize::new(0),
                wraps: AtomicUsize::new(0),
            })
        }

        fn unwraps(&self) -> usize {
            self.unwraps.load(Ordering::Relaxed)
        }

        fn wraps(&self) -> usize {
            self.wraps.load(Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl Kek for Spy {
        fn id(&self) -> &str {
            self.inner.id()
        }

        async fn wrap(
            &self,
            binding: KeyBinding<'_>,
            plaintext: &[u8],
        ) -> Result<WrappedKey, JoseError> {
            self.wraps.fetch_add(1, Ordering::Relaxed);
            self.inner.wrap(binding, plaintext).await
        }

        async fn unwrap(
            &self,
            binding: KeyBinding<'_>,
            wrapped: &WrappedKey,
        ) -> Result<Zeroizing<Vec<u8>>, JoseError> {
            self.unwraps.fetch_add(1, Ordering::Relaxed);
            self.inner.unwrap(binding, wrapped).await
        }
    }

    /// The whole point: a row the re-wrap has not reached still opens.
    #[tokio::test]
    async fn a_row_sealed_under_the_previous_key_still_opens() {
        let (tenant, kid) = (tenant(), kid());
        let sealed = old()
            .seal(binding(&tenant, &kid), b"private key")
            .expect("seal under the old key");
        let composite = CompositeKek::new(current(), old()).expect("two distinct keys");

        let opened = composite
            .unwrap(binding(&tenant, &kid), &sealed)
            .await
            .expect("the previous key opens it");

        assert_eq!(opened.as_slice(), b"private key");
    }

    /// The same row without a previous key: unreadable, exactly as before.
    #[tokio::test]
    async fn the_same_row_does_not_open_without_a_previous_key() {
        let (tenant, kid) = (tenant(), kid());
        let sealed = old()
            .seal(binding(&tenant, &kid), b"private key")
            .expect("seal under the old key");

        let opened = current().unwrap(binding(&tenant, &kid), &sealed).await;

        assert!(opened.is_err(), "the current key alone must not open it");
    }

    /// A row already on the current key is never offered to the previous one.
    /// A retired key consulted on every read is a key whose retirement means
    /// nothing.
    #[tokio::test]
    async fn a_row_on_the_current_key_is_never_tried_under_the_previous_one() {
        let (tenant, kid) = (tenant(), kid());
        let current = current();
        let sealed = current
            .seal(binding(&tenant, &kid), b"private key")
            .expect("seal under the current key");
        let spy = Spy::over(old());
        let composite = CompositeKek::new(current, Arc::clone(&spy) as Arc<dyn Kek>)
            .expect("two distinct keys");

        let opened = composite
            .unwrap(binding(&tenant, &kid), &sealed)
            .await
            .expect("the current key opens it");

        assert_eq!(opened.as_slice(), b"private key");
        assert_eq!(spy.unwraps(), 0, "the previous key was consulted");
    }

    /// Nothing is ever written under the previous key.
    #[tokio::test]
    async fn everything_written_is_sealed_under_the_current_key() {
        let (tenant, kid) = (tenant(), kid());
        let spy = Spy::over(old());
        let current = current();
        let composite = CompositeKek::new(
            Arc::clone(&current) as Arc<dyn Kek>,
            Arc::clone(&spy) as Arc<dyn Kek>,
        )
        .expect("two distinct keys");

        let sealed = composite
            .wrap(binding(&tenant, &kid), b"private key")
            .await
            .expect("wrap under the current key");

        assert_eq!(sealed.kek_id(), current.id());
        assert_eq!(composite.id(), current.id());
        assert_eq!(spy.wraps(), 0, "the previous key sealed something");
    }

    /// A row under neither key reports the current key's error, not the
    /// previous key's.
    #[tokio::test]
    async fn a_row_under_a_third_key_reports_the_current_keys_error() {
        let (tenant, kid) = (tenant(), kid());
        let third = LocalKek::from_bytes(&[0x33; KEK_LEN]).expect("a 32-byte key");
        let sealed = third
            .seal(binding(&tenant, &kid), b"private key")
            .expect("seal under a third key");
        let current = current();
        let expected = current.id().to_owned();
        let composite = CompositeKek::new(current, old()).expect("two distinct keys");

        let error = composite
            .unwrap(binding(&tenant, &kid), &sealed)
            .await
            .expect_err("neither key opens it");

        match error {
            JoseError::KekMismatch { available, .. } => assert_eq!(available, expected),
            other => panic!("expected the current key's mismatch, got {other:?}"),
        }
    }

    /// Naming the key already in use as the previous one is refused rather
    /// than silently doing nothing.
    #[test]
    fn the_previous_key_may_not_be_the_current_one() {
        let composite = CompositeKek::new(current(), current());

        assert!(composite.is_err(), "the same key twice was accepted");
    }

    /// Neither key's material reaches a log or a bug report.
    #[test]
    fn debugging_a_composite_kek_prints_ids_only() {
        let composite = CompositeKek::new(current(), old()).expect("two distinct keys");

        let rendered = format!("{composite:?}");

        assert!(rendered.contains(current().id()), "{rendered}");
        assert!(rendered.contains(old().id()), "{rendered}");
    }
}
