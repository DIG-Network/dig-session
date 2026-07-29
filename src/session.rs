//! The [`Session`] facade: unlock an existing key, or enroll a new identity.

use std::sync::Arc;

use dig_identity::{derive_identity_sk, master_secret_key_from_seed};
use dig_keystore::scheme::KeyScheme;
use dig_keystore::{BackendKey, KdfParams, KeychainBackend, Keystore, L1WalletBls, Password};
use zeroize::Zeroizing;

use crate::envelope;
use crate::master_seed::{entropy_from_phrase, ENTROPY_LEN};
use crate::{Result, SessionError, UnlockedIdentity, UnlockedMasterSeed};

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

    /// Enroll a new account root from `entropy`: seal the 32 bytes of BIP-39
    /// entropy under `password` in a versioned envelope and return an
    /// [`UnlockedMasterSeed`].
    ///
    /// Unlike [`enroll_identity`](Self::enroll_identity) — which stores the
    /// *derived identity scalar* and can never recover the root — this path
    /// stores the **root itself**, so a consumer can reconstruct the wallet
    /// `MasterKey` (the master-HD model, dig_ecosystem #997), derive the
    /// dig-identity key, and render the 24-word recovery phrase, all from one
    /// value.
    ///
    /// `entropy` is BIP-39 entropy, **not** an HD seed: it is expanded to the
    /// 64-byte seed via `to_seed("")` at every derivation, which is what makes
    /// the resulting phrase restore identically in Sage and every standard Chia
    /// wallet (dig_ecosystem #1759). Any [`ENTROPY_LEN`] CSPRNG bytes are valid
    /// entropy, so a caller may pass fresh randomness directly.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Keystore`] if a blob already exists at `path`
    /// (never silently overwritten) or the write fails.
    pub fn enroll_master_seed(
        backend: Arc<dyn KeychainBackend>,
        path: BackendKey,
        password: Password,
        entropy: &[u8; ENTROPY_LEN],
    ) -> Result<UnlockedMasterSeed> {
        envelope::write_bip39_entropy(&*backend, &path, &password, entropy)?;
        let mut stored = Zeroizing::new([0u8; ENTROPY_LEN]);
        stored.copy_from_slice(entropy);
        Ok(UnlockedMasterSeed::new(stored))
    }

    /// Enroll an account root from an existing 24-word recovery `phrase` — the
    /// restore-on-a-new-machine path.
    ///
    /// The phrase may be any capitalisation with any whitespace between words
    /// (BIP-39 normalised). Restoring the phrase that
    /// [`UnlockedMasterSeed::recovery_phrase`] produced — or one exported from
    /// Sage — reproduces the identical account: same wallet addresses, same
    /// identity key, same per-profile DEKs.
    ///
    /// # Errors
    ///
    /// - [`SessionError::InvalidRecoveryPhrase`] if the phrase is not a valid
    ///   24-word English BIP-39 mnemonic.
    /// - [`SessionError::Keystore`] if a blob already exists at `path` or the
    ///   write fails.
    pub fn enroll_from_recovery_phrase(
        backend: Arc<dyn KeychainBackend>,
        path: BackendKey,
        password: Password,
        phrase: &str,
    ) -> Result<UnlockedMasterSeed> {
        let entropy = entropy_from_phrase(phrase)?;
        Self::enroll_master_seed(backend, path, password, &entropy)
    }

    /// Unlock an existing account root into an [`UnlockedMasterSeed`].
    ///
    /// # Errors
    ///
    /// - [`SessionError::LegacySeedFormat`] if the blob predates the versioned
    ///   envelope. Its 32 bytes are a raw seed, and are **never** reinterpreted
    ///   as BIP-39 entropy — that would silently derive a different wallet. The
    ///   account must be re-enrolled via
    ///   [`enroll_from_recovery_phrase`](Self::enroll_from_recovery_phrase).
    /// - [`SessionError::UnsupportedEnvelopeVersion`] /
    ///   [`SessionError::UnsupportedSeedKind`] for a blob from a newer build.
    /// - [`SessionError::Keystore`] if the blob is missing, the password is
    ///   wrong, or the ciphertext is tampered.
    pub fn unlock_master_seed(
        backend: Arc<dyn KeychainBackend>,
        path: BackendKey,
        password: Password,
    ) -> Result<UnlockedMasterSeed> {
        let entropy = envelope::read_bip39_entropy(&*backend, &path, &password)?;
        Ok(UnlockedMasterSeed::new(entropy))
    }
}
