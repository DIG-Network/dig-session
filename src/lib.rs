//! # dig-session
//!
//! The DIG **session / keystore layer**: a small, custody-safe facade that
//! turns stored, encrypted key material into a live signer and injects a bare
//! signing primitive into downstream consumers.
//!
//! It composes two lower-level crates and adds no cryptography of its own:
//!
//! - [`dig_keystore`] — encrypted, per-scheme secret-key storage
//!   (`Keystore::<K>::load -> unlock -> SignerHandle<K>`, AES-256-GCM + Argon2id).
//! - [`dig_identity`] — the canonical DIG BLS identity derivation
//!   (`master_secret_key_from_seed` then `derive_identity_sk` at the hardened
//!   path `m/12381'/8444'/9'/0'`).
//!
//! ## What this crate deliberately does NOT do
//!
//! There is **no seal / decap** (recipient message encryption) here. That
//! composition belongs to `dig-message` (the same 10-primitives level); adding
//! it here would duplicate a cross-repo contract and invite byte-drift. This
//! crate's first cut is strictly **unlock / sign / inject**.
//!
//! ## Enrollment stores the derived key with `L1WalletBls`, not `BlsSigning`
//!
//! The identity signing key is a key that dig-identity has *already derived*
//! (via EIP-2333 hardened steps). To reconstruct it on unlock byte-identically,
//! storage must use a scheme that round-trips raw secret-key bytes through
//! `chia_bls::SecretKey::from_bytes` — that is [`L1WalletBls`].
//!
//! [`BlsSigning`] instead treats its stored 32 bytes as a *seed* and runs them
//! through `chia_bls::SecretKey::from_seed` on every unlock. Storing an
//! already-derived key under `BlsSigning` would therefore re-derive a
//! *different* key (the documented dig_ecosystem #64 / #57 pitfall), and the
//! resulting public key would not match the DID-anchored identity key. So the
//! identity path uses `L1WalletBls`; a regression test asserts the unlocked
//! public key equals `dig_identity::public_key_bytes(derive_identity_sk(master))`.
//!
//! [`Session::unlock`] stays generic over the scheme, so `BlsSigning` is still
//! available for seed-derived validator keys.
//!
//! ## Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use dig_session::{Session, FileBackend, BackendKey, Password};
//!
//! # fn main() -> dig_session::Result<()> {
//! let backend = Arc::new(FileBackend::new("/var/lib/dig/keys"));
//! let identity = Session::enroll_identity(
//!     backend,
//!     BackendKey::new("identity"),
//!     Password::from("correct horse battery staple"),
//!     b"BIP-39 seed bytes go here",
//! )?;
//!
//! // Hand a downstream a bare signing primitive — it never sees a session type.
//! let sign = identity.signing_fn();
//! let _sig = sign(b"message");
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod session;
mod unlocked;

pub use error::{Result, SessionError};
pub use session::Session;
pub use unlocked::{SigningFn, UnlockedIdentity};

// Re-export the storage/scheme types a caller needs, so a consumer depends on
// JUST dig-session rather than reaching into dig-keystore directly.
pub use dig_keystore::bls::{PublicKey, SecretKey, Signature};
pub use dig_keystore::scheme::{BlsSigning, KeyScheme, L1WalletBls};
pub use dig_keystore::{BackendKey, FileBackend, KeychainBackend, Password};
