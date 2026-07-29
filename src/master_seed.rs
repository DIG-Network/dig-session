//! The master-SEED unlock path: an unlocked handle over a DIG account's root
//! HD seed, stored as BIP-39 entropy and re-expanded on demand.
//!
//! # Why this exists (the impedance mismatch it closes)
//!
//! The 0.2.0 identity path ([`crate::UnlockedIdentity`]) unlocks to the *derived
//! identity scalar* only — it stores `derive_identity_sk(master).to_bytes()` and
//! can never reconstruct the master seed. But `dig-wallet-backend`'s
//! `MasterKey::from_seed_bytes` (the master-HD model, dig_ecosystem #997) needs
//! the **master seed** to derive every profile's wallet keys. The identity
//! scalar cannot reconstruct the seed, so a consumer that wants BOTH the
//! dig-identity key AND a wallet `MasterKey` must persist the root itself.
//!
//! # The root is BIP-39 ENTROPY, and the seed is expanded from it
//!
//! A 24-word recovery phrase carries an implicit promise: *any* conforming
//! wallet can restore it. Standard Chia wallets (Sage, the reference client,
//! `chia-wallet-sdk`) honour that promise as
//!
//! ```text
//! phrase --BIP-39--> 32-byte entropy --PBKDF2("mnemonic", 2048)--> 64-byte seed --EIP-2333--> master SecretKey
//! ```
//!
//! Handing the **entropy** to `SecretKey::from_seed` instead of the expanded
//! 64-byte seed skips the PBKDF2 step. It does not fail — it derives a
//! different, entirely plausible wallet, so a user restoring a DIG phrase in
//! Sage would see an empty account with no error at all. dig_ecosystem #1759.
//!
//! This module therefore stores the **32-byte entropy** (which is exactly what
//! a 24-word phrase encodes, and what the phrase can be regenerated from) and
//! re-expands it to the [`MASTER_SEED_LEN`]-byte HD seed at
//! [`master_seed`](UnlockedMasterSeed::master_seed). **Every** derivation —
//! identity, per-profile DEK, wallet — reads that one expanded seed, so no two
//! of them can disagree about the root.
//!
//! [`UnlockedMasterSeed`] exposes:
//!
//! - [`master_seed`](UnlockedMasterSeed::master_seed) — the expanded 64-byte HD
//!   seed, ready to feed to wallet-backend's `MasterKey::from_seed_bytes` (see
//!   the layering note below);
//! - [`recovery_phrase`](UnlockedMasterSeed::recovery_phrase) — the 24 words,
//!   *without* consuming the handle, so a UI can show them and carry on;
//! - [`sign`](UnlockedMasterSeed::sign) /
//!   [`public_key`](UnlockedMasterSeed::public_key) — the dig-identity key at
//!   the canonical hardened path;
//! - [`derive_symmetric_key`](UnlockedMasterSeed::derive_symmetric_key) — the
//!   per-profile DEK, through the frozen `dig-constants` HKDF contract.
//!
//! # Layering (@10 reference-DOWN-only, HARD RULE)
//!
//! dig-session is a `10-primitives` crate; `MasterKey` is a `20-domain`
//! (`dig-wallet-backend`) type. This module therefore **must not** depend on
//! dig-wallet-backend or return a wallet-backend type — that would be an illegal
//! upward `@10 -> @20` edge. The seed is exposed as PRIMITIVE bytes only; the
//! app-tier consumer (dig-app) constructs the `MasterKey` itself via
//! `MasterKey::from_seed_bytes(handle.master_seed().to_vec())`.
//!
//! # Why the seed round-trips to the SAME master key everywhere
//!
//! Both dig-identity's `master_secret_key_from_seed(seed)` and wallet-backend's
//! `MasterKey::from_seed_bytes(seed)` reduce to `chia_bls::SecretKey::from_seed(seed)`
//! (EIP-2333 KeyGen). Handing the identical expanded seed bytes to both
//! therefore yields the identical master key — which is exactly why the seed
//! (not a derived scalar) is the value that must be reconstructible.
//!
//! # Storage
//!
//! The entropy is sealed in a versioned envelope (see [`crate::envelope`]) so a
//! stored blob DECLARES what its 32 bytes mean. A pre-envelope blob — whose 32
//! bytes were a raw master seed — fails closed with
//! [`SessionError::LegacySeedFormat`](crate::SessionError::LegacySeedFormat)
//! rather than being reinterpreted as entropy.

use std::sync::Arc;

use bip39::{Language, Mnemonic};
use dig_constants::SYMMETRIC_KEY_LEN;
use dig_identity::{
    derive_identity_sk, derive_identity_sk_at, master_secret_key_from_seed, public_key_bytes,
    sign_message,
};
use zeroize::Zeroizing;

use crate::unlocked::derive_symmetric_key_from_scalar;
use crate::{Result, SessionError};

/// The number of bytes of BIP-39 entropy behind a DIG account — the value
/// actually stored at rest.
///
/// 32 bytes is precisely the entropy of a **24-word** English BIP-39 mnemonic
/// (256 bits + an 8-bit checksum = 264 bits = 24 × 11), so entropy and phrase
/// convert both ways losslessly and the phrase is the canonical backup.
pub const ENTROPY_LEN: usize = 32;

/// The number of bytes in an expanded BIP-39 master HD seed — the value fed to
/// `chia_bls::SecretKey::from_seed`.
///
/// Fixed at 64 by BIP-39: `PBKDF2-HMAC-SHA512(phrase, "mnemonic" || passphrase,
/// 2048)` emits 512 bits. DIG uses the **empty** passphrase, matching Chia.
pub const MASTER_SEED_LEN: usize = 64;

/// The number of words in a DIG recovery phrase.
pub const RECOVERY_PHRASE_WORDS: usize = 24;

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

/// Reconstruct the 24-word mnemonic that `entropy` encodes.
///
/// Infallible for [`ENTROPY_LEN`] bytes: BIP-39 accepts any 32-byte entropy and
/// computes the checksum itself, so there is no invalid input to report.
///
/// # Custody note
///
/// `bip39::Mnemonic` is a plain `Clone` value over word indices with no
/// `Zeroize`/`Drop` impl (bip39 2.x exposes no `zeroize` feature), so it cannot
/// be wiped in place. Every caller therefore confines it to the smallest
/// possible scope and routes the byte/string buffers *we* own through
/// [`Zeroizing`].
fn mnemonic_from_entropy(entropy: &[u8; ENTROPY_LEN]) -> Mnemonic {
    Mnemonic::from_entropy_in(Language::English, entropy)
        .expect("BIP-39 accepts any 32-byte entropy (24 words); length is a compile-time constant")
}

/// Expand BIP-39 `entropy` into the 64-byte master HD seed, the Chia way:
/// `entropy -> 24 words -> PBKDF2 with an EMPTY passphrase`.
///
/// This is the one function that closes the Sage-parity gap; every derivation in
/// this module goes through it so none can drift.
pub(crate) fn expand_entropy(entropy: &[u8; ENTROPY_LEN]) -> Zeroizing<[u8; MASTER_SEED_LEN]> {
    let mnemonic = mnemonic_from_entropy(entropy);
    // Chia convention: the BIP-39 passphrase is empty. A non-empty passphrase
    // here would silently fork the wallet from every standard client.
    Zeroizing::new(mnemonic.to_seed(""))
}

/// Parse a recovery phrase back into the entropy DIG stores.
///
/// Accepts the forms a user plausibly types: any capitalisation, leading or
/// trailing whitespace, and any run of whitespace (including newlines, as when
/// pasting from a numbered list) between words. Restoring an account is a
/// high-stress moment — being rejected over a capital letter is a trap, not a
/// safety measure, and lowercasing cannot change which English BIP-39 word a
/// token is.
///
/// # Errors
///
/// [`SessionError::InvalidRecoveryPhrase`] if a word is not in the English
/// wordlist, the checksum fails, or the phrase is not
/// [`RECOVERY_PHRASE_WORDS`] words long. The message deliberately names only
/// the *shape* of the failure — never a word of the phrase, which is secret.
pub(crate) fn entropy_from_phrase(phrase: &str) -> Result<Zeroizing<[u8; ENTROPY_LEN]>> {
    // bip39's "normalized" parse handles Unicode normalisation only; case and
    // whitespace shape are ours to forgive.
    let normalized = Zeroizing::new(
        phrase
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>()
            .join(" "),
    );
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, &normalized)
        .map_err(|_| SessionError::InvalidRecoveryPhrase)?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    if entropy.len() != ENTROPY_LEN {
        return Err(SessionError::InvalidRecoveryPhrase);
    }
    let mut out = Zeroizing::new([0u8; ENTROPY_LEN]);
    out.copy_from_slice(&entropy);
    Ok(out)
}

/// A live, in-memory account root whose BIP-39 entropy has been decrypted and is
/// ready to (a) reconstruct the wallet `MasterKey` app-side, (b) derive the
/// dig-identity signing key + profile DEK in-crate, and (c) render the 24-word
/// recovery phrase for the user.
///
/// Obtained from [`crate::Session::enroll_master_seed`],
/// [`crate::Session::enroll_from_recovery_phrase`] or
/// [`crate::Session::unlock_master_seed`]. The entropy lives in a [`Zeroizing`]
/// buffer wiped when this value drops. The type deliberately does not implement
/// `Clone` and its `Debug` impl redacts the secret.
///
/// # Boundaries
///
/// An `UnlockedMasterSeed` must never cross an IPC boundary: it holds the root
/// wallet secret and belongs solely to the user-app process that owns the
/// identity (dig_ecosystem #908). It stays user-side; this crate crosses no
/// engine/IPC boundary.
pub struct UnlockedMasterSeed {
    /// The stored BIP-39 entropy. Wiped on drop. Expanded to the HD seed on
    /// every derivation rather than being cached, so no long-lived copy of the
    /// expanded seed exists.
    entropy: Zeroizing<[u8; ENTROPY_LEN]>,
}

impl UnlockedMasterSeed {
    /// Wrap freshly decrypted BIP-39 entropy.
    pub(crate) fn new(entropy: Zeroizing<[u8; ENTROPY_LEN]>) -> Self {
        Self { entropy }
    }

    /// The expanded 64-byte master HD seed.
    ///
    /// This is the value an app-tier consumer feeds to wallet-backend's
    /// `MasterKey::from_seed_bytes` to reconstruct the wallet master key
    /// (`MasterKey::from_seed_bytes(handle.master_seed().to_vec())`). It is
    /// byte-identical to what Sage and every standard Chia wallet derive from
    /// the same 24 words, so the wallet addresses match.
    ///
    /// The returned buffer is `Zeroizing`, so the caller's copy is wiped on drop
    /// — it is the caller's responsibility to keep it zeroizing all the way into
    /// `from_seed_bytes` (whose parameter is itself moved into a `Zeroizing`
    /// buffer).
    ///
    /// A primitive byte array is returned (never a wallet-backend type) to keep
    /// dig-session free of any upward `@10 -> @20` dependency edge.
    pub fn master_seed(&self) -> Zeroizing<[u8; MASTER_SEED_LEN]> {
        expand_entropy(&self.entropy)
    }

    /// The [`RECOVERY_PHRASE_WORDS`]-word BIP-39 recovery phrase for this
    /// account, space-separated and lowercase.
    ///
    /// Takes `&self`: showing the user their phrase must not cost them their
    /// session, so the handle stays usable afterwards. Typing these words into
    /// Sage — or into
    /// [`Session::enroll_from_recovery_phrase`](crate::Session::enroll_from_recovery_phrase)
    /// on a new machine — reproduces this exact account.
    ///
    /// The returned `String` is [`Zeroizing`], so its heap buffer is wiped on
    /// drop. **Never log it**; `dig-logging`'s BIP-39 redactor is a backstop,
    /// not a licence.
    pub fn recovery_phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(mnemonic_from_entropy(&self.entropy).to_string())
    }

    /// The 48-byte compressed BLS12-381 G1 dig-identity public key derived from
    /// the expanded master seed at the canonical hardened path
    /// `m/12381'/8444'/9'/0'`.
    ///
    /// Byte-identical to
    /// `dig_identity::public_key_bytes(derive_identity_sk(master_secret_key_from_seed(master_seed)))`,
    /// so signatures produced here verify against the published DID identity.
    pub fn public_key(&self) -> [u8; IDENTITY_PUBLIC_KEY_LEN] {
        // Reconstruct the identity key transiently; it drops at end of scope.
        let seed = self.master_seed();
        let identity_sk = derive_identity_sk(&master_secret_key_from_seed(&*seed));
        public_key_bytes(&identity_sk)
    }

    /// Sign `msg` with the dig-identity key derived from the master seed,
    /// returning the 96-byte G2 AugScheme signature.
    ///
    /// The signature verifies under [`public_key`](Self::public_key).
    pub fn sign(&self, msg: &[u8]) -> [u8; IDENTITY_SIGNATURE_LEN] {
        let seed = self.master_seed();
        let identity_sk = derive_identity_sk(&master_secret_key_from_seed(&*seed));
        sign_message(&identity_sk, msg)
    }

    /// Derive a per-profile symmetric key (DEK) bound to `label`.
    ///
    /// The identity scalar is re-derived from the **expanded** master seed and
    /// fed to the frozen HKDF construction shared with every other DEK path
    /// ([`derive_symmetric_key_from_scalar`]):
    /// `HKDF-SHA256(ikm = IDENTITY_IKM_VERSION || identity_scalar,
    /// salt = DEK_SALT, info = label)` → [`SYMMETRIC_KEY_LEN`] bytes. The HKDF is
    /// never duplicated, so all paths stay byte-compatible for one root.
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

    /// The 48-byte compressed BLS12-381 G1 dig-identity public key for the
    /// profile at `profile_ix`, derived from the expanded master seed at
    /// `m/12381'/8444'/9'/{profile_ix}'` via
    /// [`dig_identity::derive_identity_sk_at`].
    ///
    /// # `profile_ix == 0` is byte-identical to [`public_key`](Self::public_key)
    ///
    /// `derive_identity_sk_at(master, 0) == derive_identity_sk(master)`
    /// (adversarial-confirmed in dig-identity 0.5.0), so
    /// `profile_public_key(0) == public_key()` byte-for-byte — the default path is
    /// exactly profile 0. Each `profile_ix` yields a distinct, deterministic key.
    pub fn profile_public_key(&self, profile_ix: u32) -> [u8; IDENTITY_PUBLIC_KEY_LEN] {
        let seed = self.master_seed();
        let profile_sk = derive_identity_sk_at(&master_secret_key_from_seed(&*seed), profile_ix);
        public_key_bytes(&profile_sk)
    }

    /// Sign `msg` with the profile at `profile_ix`'s derived identity key,
    /// returning the 96-byte G2 AugScheme signature.
    ///
    /// The signature verifies under
    /// [`profile_public_key(profile_ix)`](Self::profile_public_key).
    /// `profile_sign(0, msg) == sign(msg)` byte-for-byte.
    pub fn profile_sign(&self, profile_ix: u32, msg: &[u8]) -> [u8; IDENTITY_SIGNATURE_LEN] {
        let seed = self.master_seed();
        let profile_sk = derive_identity_sk_at(&master_secret_key_from_seed(&*seed), profile_ix);
        sign_message(&profile_sk, msg)
    }

    /// Derive the profile at `profile_ix`'s per-profile symmetric key (DEK) bound
    /// to `label`.
    ///
    /// The profile's identity scalar is derived from the expanded master seed via
    /// [`dig_identity::derive_identity_sk_at`] and fed to the SAME frozen HKDF
    /// construction as every other DEK path
    /// ([`derive_symmetric_key_from_scalar`]) — the HKDF is never duplicated, so
    /// all paths stay byte-compatible for the same underlying scalar.
    ///
    /// # `profile_ix == 0` is byte-identical to
    /// [`derive_symmetric_key`](Self::derive_symmetric_key)
    ///
    /// Because `derive_identity_sk_at(master, 0) == derive_identity_sk(master)`,
    /// `profile_derive_symmetric_key(0, label) == derive_symmetric_key(label)`
    /// byte-for-byte. Each `profile_ix` yields a distinct, deterministic DEK.
    ///
    /// The returned key and all intermediates are wrapped in [`Zeroizing`].
    pub fn profile_derive_symmetric_key(
        &self,
        profile_ix: u32,
        label: &[u8],
    ) -> Zeroizing<[u8; SYMMETRIC_KEY_LEN]> {
        // Re-derive the profile scalar from the seed, then run the shared, frozen
        // DEK construction. The scalar is captured into a zeroizing buffer so it
        // is wiped when this call returns.
        let seed = self.master_seed();
        let profile_scalar = Zeroizing::new(
            derive_identity_sk_at(&master_secret_key_from_seed(&*seed), profile_ix).to_bytes(),
        );
        derive_symmetric_key_from_scalar(&*profile_scalar, label)
    }

    /// Produce a standalone signing primitive that signs with this identity's
    /// key — a plain callable carrying no dig-session or identity type.
    ///
    /// The closure owns its own zeroizing copy of the entropy, so it keeps
    /// working after this handle is dropped and wipes its copy when the closure
    /// itself is dropped. This is how a downstream stays identity-agnostic while
    /// still being able to sign (dig_ecosystem #908).
    pub fn signing_fn(&self) -> IdentitySigningFn {
        let entropy = self.entropy.clone();
        Arc::new(move |msg: &[u8]| {
            let seed = expand_entropy(&entropy);
            let identity_sk = derive_identity_sk(&master_secret_key_from_seed(&*seed));
            sign_message(&identity_sk, msg)
        })
    }
}

/// Redacting `Debug`: shows the type name only, never the secret.
impl core::fmt::Debug for UnlockedMasterSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnlockedMasterSeed")
            .field("entropy", &"<redacted>")
            .finish()
    }
}
