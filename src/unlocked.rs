//! The unlocked-key handle and the signing primitive it injects.

use std::sync::Arc;

use dig_keystore::scheme::KeyScheme;
use dig_keystore::SignerHandle;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Length of a derived per-profile symmetric key (DEK), in bytes: a 256-bit key
/// for AES-256-GCM / DIGOP1 sealing.
pub const SYMMETRIC_KEY_LEN: usize = 32;

/// HKDF-SHA256 salt for per-profile DEK derivation.
///
/// This value is **byte-identical** to `DEK_SALT` in dig-app's
/// `dig-app-core/src/keystore/secrets.rs`. It MUST NOT change: the DEK derived
/// here has to match the key dig-app already uses to seal every profile blob at
/// rest, or that data becomes permanently unreadable (§5.1 back-compat).
const DEK_SALT: &[u8] = b"dig-app:dek-salt:v1";

/// Version byte prepended to the identity scalar to form the HKDF input keying
/// material (IKM).
///
/// dig-app derives its DEK from `to_sealed_bytes()` — the versioned at-rest
/// layout `version(1) || bls_scalar(32)` — NOT from the bare 32-byte scalar. To
/// reproduce dig-app's DEK byte-for-byte, the IKM here is
/// `IDENTITY_IKM_VERSION || identity_scalar`. This value equals
/// `SEALED_IDENTITY_VERSION` in dig-app's `secrets.rs`.
const IDENTITY_IKM_VERSION: u8 = 2;

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

    /// Derive a per-profile symmetric key (a data-encryption key, "DEK") from
    /// this unlocked identity, bound to `label`.
    ///
    /// The DEK is `HKDF-SHA256(salt = DEK_SALT, ikm = 0x02 || identity_scalar,
    /// info = label)` expanded to 32 bytes. The identity scalar is the raw
    /// secret; it is read into a zeroizing buffer, mixed into the KDF, and never
    /// returned — only the *derived* key by `label` leaves the facade, so the
    /// root secret stays inside (dig_ecosystem #908).
    ///
    /// # Byte-identical to dig-app (§5.1 at-rest back-compat)
    ///
    /// With `label = b"dig-app:profile-dek:v2"` this reproduces, byte-for-byte,
    /// the DEK that dig-app's `dig-app-core/src/keystore/secrets.rs`
    /// (`dek_password`, the `seal_data`/`open_data` key) already uses to seal
    /// every profile blob at rest. The construction is pinned exactly:
    ///
    /// - hash: SHA-256 (`hkdf` 0.12 + `sha2` 0.10, RFC 5869);
    /// - IKM: `0x02 || identity_scalar` — the same 33-byte versioned layout
    ///   dig-app feeds to HKDF (`to_sealed_bytes()`), NOT the bare scalar;
    /// - salt: [`DEK_SALT`] (`b"dig-app:dek-salt:v1"`);
    /// - info: `label` verbatim;
    /// - output: 32 bytes ([`SYMMETRIC_KEY_LEN`]).
    ///
    /// Changing any of these would derive a different DEK and make already-sealed
    /// profile data permanently unreadable, so they are frozen and covered by a
    /// golden-vector test.
    ///
    /// The returned key and all intermediates are wrapped in [`Zeroizing`] and
    /// wiped on drop.
    pub fn derive_symmetric_key(&self, label: &[u8]) -> Zeroizing<[u8; SYMMETRIC_KEY_LEN]> {
        // Assemble IKM = version-byte || identity-scalar in a zeroizing buffer so
        // the copied scalar is wiped when this call returns. The scalar itself
        // never leaves this method.
        let scalar = self.signer.expose_secret();
        let mut ikm = Zeroizing::new(Vec::with_capacity(1 + scalar.len()));
        ikm.push(IDENTITY_IKM_VERSION);
        ikm.extend_from_slice(scalar);

        let hkdf = Hkdf::<Sha256>::new(Some(DEK_SALT), &ikm);
        let mut dek = Zeroizing::new([0u8; SYMMETRIC_KEY_LEN]);
        hkdf.expand(label, &mut *dek)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        dek
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
