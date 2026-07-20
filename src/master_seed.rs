//! The master-SEED unlock path: an unlocked handle over the raw master HD seed.
//!
//! # Why this exists (the impedance mismatch it closes)
//!
//! The 0.2.0 identity path ([`crate::UnlockedIdentity`]) unlocks to the *derived
//! identity scalar* only — it stores `derive_identity_sk(master).to_bytes()` and
//! can never reconstruct the master seed. But `dig-wallet-backend`'s
//! `MasterKey::from_seed_bytes` (the master-HD model, dig_ecosystem #997) needs
//! the **master seed** to derive every profile's wallet keys. The identity
//! scalar cannot reconstruct the seed, so a consumer that wants BOTH the
//! dig-identity key AND a wallet `MasterKey` must persist the seed itself.
//!
//! [`UnlockedMasterSeed`] is that path: it persists the raw 32-byte master seed
//! (encrypted at rest) and, on unlock, exposes ALL of:
//!
//! - [`master_seed`](UnlockedMasterSeed::master_seed) — the raw seed bytes as a
//!   primitive `Zeroizing<[u8; SEED_LEN]>`, ready to feed to wallet-backend's
//!   `MasterKey::from_seed_bytes` (see the layering note below);
//! - [`sign`](UnlockedMasterSeed::sign) /
//!   [`public_key`](UnlockedMasterSeed::public_key) — the dig-identity key
//!   derived from the seed at the canonical path, byte-identical to the 0.2.0
//!   identity path for the same seed;
//! - [`derive_symmetric_key`](UnlockedMasterSeed::derive_symmetric_key) — the
//!   per-profile DEK, **byte-identical** to
//!   [`crate::UnlockedIdentity::derive_symmetric_key`] (§5.1 at-rest back-compat).
//!
//! # Layering (@10 reference-DOWN-only, HARD RULE)
//!
//! dig-session is a `10-primitives` crate; `MasterKey` is a `20-domain`
//! (`dig-wallet-backend`) type. This module therefore **must not** depend on
//! dig-wallet-backend or return a wallet-backend type — that would be an illegal
//! upward `@10 -> @20` edge. The seed is exposed as PRIMITIVE bytes only; the
//! app-tier consumer (dig-app) constructs the `MasterKey` itself via
//! `MasterKey::from_seed_bytes(handle.master_seed())`.
//!
//! # Why the seed round-trips to the SAME master key everywhere
//!
//! Both dig-identity's `master_secret_key_from_seed(seed)` and wallet-backend's
//! `MasterKey::from_seed_bytes(seed)` reduce to `chia_bls::SecretKey::from_seed(seed)`
//! (EIP-2333 KeyGen). Handing the identical seed bytes to both therefore yields
//! the identical master key — which is exactly why the seed (not the derived
//! scalar) is the value that must be persisted and exposed.
//!
//! # Storage scheme
//!
//! The seed is stored under [`dig_keystore::BlsSigning`] purely as a 32-byte
//! encrypted-at-rest byte vault: that scheme persists exactly its 32 secret
//! bytes verbatim and returns them via `expose_secret()`. This path never uses
//! the `BlsSigning` handle's own `sign`/`public_key` (which would derive the
//! *master* key via `from_seed`); the dig-identity key is derived in this crate
//! instead. The `L1WalletBls` scheme is unsuitable here because it stores an
//! already-derived *scalar* (`from_bytes`), not a *seed*.

use std::sync::Arc;

use dig_constants::SYMMETRIC_KEY_LEN;
use dig_identity::{
    derive_identity_sk, master_secret_key_from_seed, public_key_bytes, sign_message,
};
use dig_keystore::{BlsSigning, SignerHandle};
use zeroize::Zeroizing;

use crate::unlocked::derive_symmetric_key_from_scalar;

/// The number of bytes in a DIG master HD seed.
///
/// Fixed at 32 to match dig-app's master-seed model (`SCALAR_LEN`, a 32-byte
/// entropy seed drawn from the CSPRNG) and the `BlsSigning` storage scheme's
/// `SECRET_LEN`. The seed is fed to `chia_bls::SecretKey::from_seed`, which
/// accepts any length ≥ 32; 32 bytes is the DIG canonical size.
pub const SEED_LEN: usize = 32;

/// The number of bytes in a compressed BLS12-381 **G1** identity public key.
pub const IDENTITY_PUBLIC_KEY_LEN: usize = 48;

/// The number of bytes in a BLS12-381 **G2** AugScheme signature.
pub const IDENTITY_SIGNATURE_LEN: usize = 96;

/// A standalone identity-signing primitive: a plain callable mapping a message to
/// a 96-byte G2 signature, carrying no dig-session or dig-identity type.
///
/// This is the bare shape [`UnlockedMasterSeed::signing_fn`] hands a downstream so
/// it can sign while staying identity-agnostic (dig_ecosystem #908). It mirrors
/// [`crate::SigningFn`] but is expressed over raw byte arrays because the
/// master-seed path derives the identity key itself rather than exposing a
/// scheme-parameterized `SignerHandle`.
pub type IdentitySigningFn = Arc<dyn Fn(&[u8]) -> [u8; IDENTITY_SIGNATURE_LEN] + Send + Sync>;

/// A live, in-memory master HD seed whose bytes have been decrypted and are
/// ready to (a) reconstruct the wallet `MasterKey` app-side and (b) derive the
/// dig-identity signing key + profile DEK in-crate.
///
/// Obtained from [`crate::Session::enroll_master_seed`] or
/// [`crate::Session::unlock_master_seed`]. The seed lives inside the wrapped
/// [`SignerHandle`], which stores it in a `Zeroizing` buffer and wipes it when
/// this value is dropped. The type deliberately does not implement `Clone` and
/// its `Debug` impl redacts the secret.
///
/// # Boundaries
///
/// An `UnlockedMasterSeed` must never cross an IPC boundary: it holds the root
/// wallet seed and belongs solely to the user-app process that owns the identity
/// (dig_ecosystem #908). The seed stays user-side; this crate crosses no
/// engine/IPC boundary.
pub struct UnlockedMasterSeed {
    /// The `BlsSigning` handle is used ONLY as a zeroizing 32-byte vault for the
    /// raw seed (`expose_secret()` returns it verbatim). Its own signing key is
    /// never used — the identity key is derived from the seed in this crate.
    seed_handle: SignerHandle<BlsSigning>,
}

impl UnlockedMasterSeed {
    /// Wrap a freshly unlocked seed-storage [`SignerHandle`].
    pub(crate) fn new(seed_handle: SignerHandle<BlsSigning>) -> Self {
        Self { seed_handle }
    }

    /// The raw master HD seed bytes, as a primitive `Zeroizing<[u8; SEED_LEN]>`.
    ///
    /// This is the value an app-tier consumer feeds to wallet-backend's
    /// `MasterKey::from_seed_bytes` to reconstruct the wallet master key
    /// (`MasterKey::from_seed_bytes(handle.master_seed())`). The returned buffer
    /// is `Zeroizing`, so the caller's copy is wiped on drop — it is the caller's
    /// responsibility to keep it zeroizing all the way into `from_seed_bytes`
    /// (whose parameter is itself moved into a `Zeroizing` buffer).
    ///
    /// A primitive byte array is returned (never a wallet-backend type) to keep
    /// dig-session free of any upward `@10 -> @20` dependency edge.
    pub fn master_seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        let raw = self.seed_handle.expose_secret();
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        // The storage scheme guarantees exactly SEED_LEN bytes (`BlsSigning`'s
        // SECRET_LEN); the enroll path only ever writes SEED_LEN bytes.
        seed.copy_from_slice(raw);
        seed
    }

    /// The 48-byte compressed BLS12-381 G1 dig-identity public key derived from
    /// the seed.
    ///
    /// Byte-identical to
    /// `dig_identity::public_key_bytes(derive_identity_sk(master_secret_key_from_seed(seed)))`
    /// and to the 0.2.0 identity path's public key for the same seed — so
    /// signatures produced here verify against the published DID identity.
    pub fn public_key(&self) -> [u8; IDENTITY_PUBLIC_KEY_LEN] {
        // Reconstruct the identity key transiently; it drops at end of scope.
        let seed = self.master_seed();
        let identity_sk = derive_identity_sk(&master_secret_key_from_seed(&*seed));
        public_key_bytes(&identity_sk)
    }

    /// Sign `msg` with the dig-identity key derived from the seed, returning the
    /// 96-byte G2 AugScheme signature.
    ///
    /// The signature verifies under [`public_key`](Self::public_key).
    pub fn sign(&self, msg: &[u8]) -> [u8; IDENTITY_SIGNATURE_LEN] {
        let seed = self.master_seed();
        let identity_sk = derive_identity_sk(&master_secret_key_from_seed(&*seed));
        sign_message(&identity_sk, msg)
    }

    /// Derive a per-profile symmetric key (DEK) bound to `label`.
    ///
    /// **Byte-identical to [`crate::UnlockedIdentity::derive_symmetric_key`]**
    /// for the same underlying identity: the identity scalar is re-derived from
    /// the seed and fed to the SAME frozen HKDF construction
    /// (`HKDF-SHA256(ikm = IDENTITY_IKM_VERSION || identity_scalar,
    /// salt = DEK_SALT, info = label)` → [`SYMMETRIC_KEY_LEN`] bytes). So a
    /// profile blob sealed via the 0.2.0 identity path opens unchanged after a
    /// consumer migrates to the master-seed path (§5.1 at-rest back-compat).
    ///
    /// The returned key and all intermediates are wrapped in [`Zeroizing`].
    pub fn derive_symmetric_key(&self, label: &[u8]) -> Zeroizing<[u8; SYMMETRIC_KEY_LEN]> {
        // Re-derive the identity scalar from the seed, then run the shared,
        // frozen DEK construction. The scalar is captured into a zeroizing
        // buffer so it is wiped when this call returns.
        let seed = self.master_seed();
        let identity_scalar =
            Zeroizing::new(derive_identity_sk(&master_secret_key_from_seed(&*seed)).to_bytes());
        derive_symmetric_key_from_scalar(&*identity_scalar, label)
    }

    /// Produce a standalone signing primitive that signs with this identity's
    /// key — a plain callable carrying no dig-session or identity type.
    ///
    /// The closure owns its own zeroizing copy of the seed, so it keeps working
    /// after this handle is dropped and wipes its copy when the closure itself
    /// is dropped. This is how a downstream stays identity-agnostic while still
    /// being able to sign (dig_ecosystem #908).
    pub fn signing_fn(&self) -> IdentitySigningFn {
        let seed = self.master_seed();
        Arc::new(move |msg: &[u8]| {
            let identity_sk = derive_identity_sk(&master_secret_key_from_seed(&*seed));
            sign_message(&identity_sk, msg)
        })
    }
}

/// Redacting `Debug`: shows the type name only, never the seed.
impl core::fmt::Debug for UnlockedMasterSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnlockedMasterSeed")
            .field("seed", &"<redacted>")
            .finish()
    }
}
