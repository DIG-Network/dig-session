//! Error type for the session facade.

use thiserror::Error;

/// Errors returned by [`crate::Session`] operations.
///
/// Wraps the underlying [`dig_keystore`] failure verbatim (via `#[from]`) so a
/// caller can match on the concrete storage/crypto error without dig-session
/// inventing a parallel error taxonomy, plus the small number of failures that
/// are specific to session enrollment.
#[derive(Debug, Error)]
pub enum SessionError {
    /// A key-storage or decryption failure surfaced by [`dig_keystore`]
    /// (missing file, wrong password, tampered ciphertext, scheme mismatch, …).
    #[error(transparent)]
    Keystore(#[from] dig_keystore::KeystoreError),

    /// Enrollment was asked to derive an identity from empty seed material.
    ///
    /// A caller must supply real BIP-39 seed bytes; deriving an identity key
    /// from an empty seed would silently produce a fixed, guessable key.
    #[error("seed material must be non-empty")]
    EmptySeed,
}

/// Convenience alias for `Result<T, SessionError>`.
pub type Result<T> = std::result::Result<T, SessionError>;
