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
    /// user would simply see the wrong (empty) account.
    ///
    /// # A consumer MUST handle this variant explicitly (HARD REQUIREMENT)
    ///
    /// A legacy account is **WEDGED**, not merely unreadable, and no amount of
    /// retrying changes that:
    ///
    /// - [`Session::unlock_master_seed`](crate::Session::unlock_master_seed)
    ///   returns this error and never a handle;
    /// - [`Session::enroll_master_seed`](crate::Session::enroll_master_seed) at
    ///   the same key returns `AlreadyExists`, because enrolment refuses to
    ///   overwrite a custody root;
    /// - the pre-envelope releases exposed no `recovery_phrase()`, so the user
    ///   was never shown 24 words, and a legacy raw seed has no phrase that
    ///   means anything under the current scheme.
    ///
    /// So a consumer that merely logs this error leaves the account permanently
    /// and silently without a signer. The required remediation, which the
    /// consumer owns because only it has a UI:
    ///
    /// 1. **Detect** this variant specifically — never a catch-all log line.
    /// 2. **Preserve** the existing blob (copy it aside; do NOT delete it). It
    ///    is password-sealed and may hold value, and its password may live in an
    ///    OS credential store this crate cannot read. Discarding it can destroy
    ///    the only copy of a funded key.
    /// 3. **Tell the user, in the UI**, that the account must be re-created, and
    ///    that the preserved file is their only copy of the old key.
    /// 4. **Re-enrol** at a fresh key (or after moving the old blob aside) via
    ///    [`enroll_master_seed`](crate::Session::enroll_master_seed) or
    ///    [`enroll_from_recovery_phrase`](crate::Session::enroll_from_recovery_phrase),
    ///    then show the new recovery phrase.
    ///
    /// Adopting this version WITHOUT that path is a regression for every
    /// already-enrolled install (dig_ecosystem #1759).
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
