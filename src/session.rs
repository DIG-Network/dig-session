//! The [`Session`] facade: unlock an existing key, or enroll a new identity.

use std::sync::Arc;

use dig_identity::{derive_identity_sk, master_secret_key_from_seed};
use dig_keystore::scheme::KeyScheme;
use dig_keystore::{BackendKey, KdfParams, KeychainBackend, Keystore, L1WalletBls, Password};
use zeroize::Zeroizing;

use crate::{Result, SessionError, UnlockedIdentity};

/// Entry point for turning stored, encrypted key material into a live signer.
///
/// `Session` is a stateless namespace over the compose-only flow
/// `dig_keystore::Keystore::<K>::load -> unlock -> SignerHandle<K>`, plus the
/// enrollment path that derives the canonical dig-identity signing key and
/// persists it. It holds no state of its own; every method is associated.
pub struct Session;

impl Session {
    /// Unlock an existing keystore file into an [`UnlockedIdentity`].
    ///
    /// Generic over the storage scheme `K`: use [`dig_keystore::L1WalletBls`]
    /// for a stored, already-derived key (the identity signing key, wallet
    /// keys) and [`dig_keystore::BlsSigning`] for a seed-derived validator key.
    /// The scheme is verified against the file's magic on load, so unlocking a
    /// file with the wrong scheme fails cleanly rather than yielding a bogus key.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Keystore`] if the file is missing, the password
    /// is wrong, the ciphertext is tampered, or the scheme does not match.
    pub fn unlock<K: KeyScheme>(
        backend: Arc<dyn KeychainBackend>,
        path: BackendKey,
        password: Password,
    ) -> Result<UnlockedIdentity<K>> {
        let keystore = Keystore::<K>::load(backend, path)?;
        let signer = keystore.unlock(password)?;
        Ok(UnlockedIdentity::new(signer))
    }

    /// Enroll a new identity: derive the canonical dig-identity BLS signing key
    /// from `seed`, persist it encrypted under `password`, and return it
    /// unlocked and ready to sign.
    ///
    /// The identity key is derived exactly once, via
    /// [`dig_identity::master_secret_key_from_seed`] followed by
    /// [`dig_identity::derive_identity_sk`] (the hardened path
    /// `m/12381'/8444'/9'/0'`), and the resulting secret key's canonical bytes
    /// are stored. See the module-level note in [`crate`] on why the storage
    /// scheme is [`L1WalletBls`] (faithful `from_bytes` round-trip) rather than
    /// `BlsSigning` (which would re-derive via `from_seed` and produce a
    /// different key).
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::EmptySeed`] if `seed` is empty, or
    /// [`SessionError::Keystore`] if a file already exists at `path` or the
    /// write fails.
    pub fn enroll_identity(
        backend: Arc<dyn KeychainBackend>,
        path: BackendKey,
        password: Password,
        seed: &[u8],
    ) -> Result<UnlockedIdentity<L1WalletBls>> {
        if seed.is_empty() {
            return Err(SessionError::EmptySeed);
        }

        // Derive the canonical identity signing key ONCE, extract its canonical
        // bytes, and drop the transient key material as early as possible.
        //
        // Custody note: `master` and `identity_sk` are `chia_bls::SecretKey`,
        // which — even in the latest chia-bls (0.46) — is a plain
        // `#[derive(Clone)]` wrapper over `blst_scalar` with NO `Zeroize`/`Drop`
        // impl. We therefore cannot wipe those foreign scalars in place; the
        // best we can do is (a) confine them to the smallest possible scope so
        // the compiler drops them the instant we no longer need them, and (b)
        // route every byte buffer WE own through `Zeroizing` so it is wiped on
        // drop. The 32-byte `to_bytes()` array is a stack temporary, so it is
        // wrapped in `Zeroizing` before being copied into the returned `Vec`.
        // A cross-repo follow-up requests `Zeroize` on `chia_bls::SecretKey`
        // (or a zeroizing derivation in dig-identity); see #1327.
        let secret: Zeroizing<Vec<u8>> = {
            let master = master_secret_key_from_seed(seed);
            let identity_sk = derive_identity_sk(&master);
            let canonical_bytes = Zeroizing::new(identity_sk.to_bytes());
            Zeroizing::new(canonical_bytes.to_vec())
            // `master` and `identity_sk` drop here — as early as possible.
        };

        // Persist the already-derived key. `unlock` needs the password again,
        // and `create` consumes it, so clone before the move.
        let unlock_password = Password::new(password.as_bytes());
        let keystore = Keystore::<L1WalletBls>::create(
            backend,
            path,
            password,
            Some(secret),
            KdfParams::DEFAULT,
        )?;
        let signer = keystore.unlock(unlock_password)?;
        Ok(UnlockedIdentity::new(signer))
    }
}
