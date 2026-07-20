//! The unlocked-key handle and the signing primitive it injects.

use std::sync::Arc;

use dig_keystore::scheme::KeyScheme;
use dig_keystore::SignerHandle;

/// A scheme-parameterized signing primitive: a plain callable that maps a
/// message to a signature and carries no dig-session or dig-identity type.
///
/// This is the shape [`UnlockedIdentity::inject_into`] hands to a consumer, so
/// the consumer's API surface mentions only `&[u8]` in and `K::Signature`
/// (a `chia_bls::Signature` for the BLS schemes) out — never a session or
/// identity type. That is what keeps a consumer such as `dig-wallet-backend`
/// identity-agnostic (see dig_ecosystem #908).
pub type SigningFn<K> = Arc<dyn Fn(&[u8]) -> <K as KeyScheme>::Signature + Send + Sync>;

/// A live, in-memory identity whose secret key has been decrypted and is ready
/// to sign.
///
/// Obtained from [`crate::Session::unlock`] or [`crate::Session::enroll_identity`].
/// The secret bytes live inside the wrapped [`SignerHandle`], which stores them
/// in a `Zeroizing` buffer and wipes them when this value is dropped — so the
/// decrypted key never lingers in freed memory. The type deliberately does not
/// implement `Clone` and its `Debug` impl redacts the secret, so an
/// `UnlockedIdentity` cannot be duplicated into a log line or a debug dump.
///
/// # Boundaries
///
/// An `UnlockedIdentity` must never cross an IPC boundary: it holds raw key
/// material and belongs solely to the user-app process that owns the identity
/// (dig_ecosystem #908). Hand a downstream a [`SigningFn`] via
/// [`inject_into`](Self::inject_into) instead of the handle itself.
pub struct UnlockedIdentity<K: KeyScheme> {
    signer: SignerHandle<K>,
    public_key: K::PublicKey,
}

impl<K: KeyScheme> UnlockedIdentity<K> {
    /// Wrap a freshly unlocked [`SignerHandle`], caching its public key.
    pub(crate) fn new(signer: SignerHandle<K>) -> Self {
        let public_key = signer.public_key().clone();
        Self { signer, public_key }
    }

    /// The public key of this identity.
    ///
    /// For the identity scheme this is byte-identical to
    /// `dig_identity::public_key_bytes(derive_identity_sk(master))`, i.e. the
    /// key anchored in the DID profile — so signatures produced by this handle
    /// verify against the published identity.
    pub fn public_key(&self) -> &K::PublicKey {
        &self.public_key
    }

    /// Sign `msg` with the unlocked secret key.
    pub fn sign(&self, msg: &[u8]) -> K::Signature {
        self.signer.sign(msg)
    }

    /// Produce a standalone [`SigningFn`] primitive that signs with this
    /// identity's key.
    ///
    /// The returned closure owns its own zeroizing copy of the secret, so it
    /// keeps working after this handle is dropped and wipes its copy when the
    /// closure itself is dropped.
    pub fn signing_fn(&self) -> SigningFn<K> {
        let signer = self.signer.clone();
        Arc::new(move |msg: &[u8]| signer.sign(msg))
    }

    /// Inject this identity's signing capability into a consumer as a bare
    /// [`SigningFn`] primitive, returning whatever the consumer builds from it.
    ///
    /// The consumer receives only a callable — never an `UnlockedIdentity`,
    /// a `SignerHandle`, or any identity type — which is how a downstream stays
    /// identity-agnostic while still being able to sign.
    pub fn inject_into<T>(&self, consumer: impl FnOnce(SigningFn<K>) -> T) -> T {
        consumer(self.signing_fn())
    }
}

/// Redacting `Debug`: shows the type name only, never the secret (or even the
/// public key, to avoid accidental correlation in logs).
impl<K: KeyScheme> core::fmt::Debug for UnlockedIdentity<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnlockedIdentity")
            .field("scheme", &K::NAME)
            .field("secret", &"<redacted>")
            .finish()
    }
}
