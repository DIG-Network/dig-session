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

    /// The stored blob predates the versioned seed envelope: its 32 bytes are a
    /// **raw** master seed, not BIP-39 entropy.
    ///
    /// This fails CLOSED on purpose. The two encodings are byte-for-byte
    /// indistinguishable, so reinterpreting the old bytes as entropy would
    /// derive a different, entirely plausible wallet with no error at all — the
    /// user would simply see the wrong (empty) account. The account must be
    /// re-enrolled from its recovery phrase via
    /// [`Session::enroll_from_recovery_phrase`](crate::Session::enroll_from_recovery_phrase).
    #[error(
        "this account was stored under the legacy raw-seed format and cannot be \
         read as BIP-39 entropy; re-enrol it from its 24-word recovery phrase"
    )]
    LegacySeedFormat,

    /// The stored seed envelope declares a layout version this build does not
    /// know. Written by a newer dig-session; refuse rather than guess.
    #[error("unsupported seed-envelope version {0:#04x}; this build is too old to read it")]
    UnsupportedEnvelopeVersion(u8),

    /// The stored seed envelope declares a secret KIND this build does not know.
    /// Refuse rather than fall back to an interpretation that could be wrong.
    #[error("unsupported stored seed kind {0:#04x}; this build is too old to read it")]
    UnsupportedSeedKind(u8),

    /// A supplied recovery phrase is not a valid 24-word English BIP-39
    /// mnemonic (unknown word, failed checksum, or wrong word count).
    ///
    /// The message names only the SHAPE of the failure — never a word of the
    /// phrase, which is secret material.
    #[error(
        "not a valid 24-word English BIP-39 recovery phrase (check the word \
         count, spelling, and order)"
    )]
    InvalidRecoveryPhrase,
}

/// Convenience alias for `Result<T, SessionError>`.
pub type Result<T> = std::result::Result<T, SessionError>;
