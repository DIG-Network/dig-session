//! The versioned at-rest envelope for stored master-seed material.
//!
//! # Why an envelope exists at all
//!
//! Two DIG generations store **32 bytes** under the same account path, and the
//! bytes are byte-for-byte indistinguishable:
//!
//! | generation | the 32 bytes are | fed to `SecretKey::from_seed` as |
//! |---|---|---|
//! | legacy (≤ dig-session 0.4) | a raw CSPRNG master seed | themselves |
//! | current | BIP-39 **entropy** | `mnemonic.to_seed("")` (64 bytes) |
//!
//! Reinterpreting one as the other does not fail — it silently derives a
//! *different but perfectly plausible* wallet. A user would see an empty
//! account with no error. So the stored blob must **declare** which it is, and
//! a legacy declaration must **fail closed** (see [`Kind`]).
//!
//! # Why `dig_keystore::opaque` rather than a new `KeyScheme`
//!
//! A [`dig_keystore::KeyScheme`] pins a fixed `SECRET_LEN`, so a
//! version-tagged payload does not fit one, and `dig_keystore::format`'s
//! magic allow-list is closed — a scheme defined outside dig-keystore could
//! not be decoded. [`dig_keystore::opaque`] is the sanctioned
//! arbitrary-length door into the *same* audited container (Argon2id +
//! AES-256-GCM + CRC-32, magic `DIGOP1`), so this module gets a versioned
//! payload without changing a foundation crate.
//!
//! # Wire layout of the sealed plaintext
//!
//! ```text
//! byte 0        1        2 .. 34
//! ┌────────┬────────┬──────────────────┐
//! │version │  kind  │ 32 secret bytes  │
//! └────────┴────────┴──────────────────┘
//! ```
//!
//! Additive-only, per §5.1: a future kind (say a 64-byte seed imported from
//! elsewhere) takes a new [`Kind`] discriminant; existing kinds keep their
//! meaning forever.

use dig_keystore::{
    opaque, BackendKey, BlsSigning, KdfParams, KeyScheme, KeychainBackend, KeystoreError, Password,
};
use zeroize::Zeroizing;

use crate::master_seed::ENTROPY_LEN;
use crate::{Result, SessionError};

/// Current envelope version. Bumped only for a layout change, never for a new
/// [`Kind`].
const VERSION_V1: u8 = 0x01;

/// Total sealed-plaintext length: `version || kind || entropy`.
const ENVELOPE_LEN: usize = 2 + ENTROPY_LEN;

/// What the 32 stored bytes MEAN.
///
/// The discriminant is the whole point of the envelope: the bytes alone cannot
/// tell you, and guessing wrong derives the wrong wallet in silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// BIP-39 entropy for a 24-word English mnemonic, re-expanded to the
    /// 64-byte HD seed via `to_seed("")` before any derivation. The only kind
    /// this crate writes.
    Bip39Entropy = 0x01,
}

impl Kind {
    /// Recognize a stored discriminant, rejecting anything this build does not
    /// understand rather than defaulting to a guess.
    fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            x if x == Kind::Bip39Entropy as u8 => Ok(Kind::Bip39Entropy),
            unknown => Err(SessionError::UnsupportedSeedKind(unknown)),
        }
    }
}

/// Seal `entropy` into a versioned envelope and establish it at `path`.
///
/// This is an *establish*, never an *update*: an existing blob at `path` yields
/// [`KeystoreError::AlreadyExists`] and is left byte-for-byte intact, matching
/// `dig_keystore::Keystore::create`.
///
/// # Why `write_new` and not `exists` then `write`
///
/// The two-call form is not one step. A second enrolment beginning inside that
/// window observes an absence, seals, and — because `write` replaces — destroys
/// the established root rather than landing beside it. The caller who was told
/// "enrolled" is then holding a recovery phrase that opens nothing, and for an
/// account root there is by construction no other copy.
///
/// [`KeychainBackend::write_new`] makes the backend the single authority on
/// whether the key was already there. On a backend reporting
/// [`Exclusivity::Atomic`](dig_keystore::Exclusivity::Atomic) — `FileBackend`
/// and `MemoryBackend` — that authority is indivisible and the loss is
/// unreachable. `OsKeychainBackend` reports
/// [`BestEffort`](dig_keystore::Exclusivity::BestEffort), because its
/// credential store offers no create-if-absent primitive; a caller minting
/// concurrently against it must still serialise the mint itself.
///
/// One visible consequence: a colliding enrolment now pays the Argon2id
/// derivation before it is refused, since the collision is detected by the
/// write rather than by a pre-check. That is the cost of having one authority
/// instead of two readings, and it is paid only on the failing path.
pub(crate) fn write_bip39_entropy(
    backend: &dyn KeychainBackend,
    path: &BackendKey,
    password: &Password,
    entropy: &[u8; ENTROPY_LEN],
) -> Result<()> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(ENVELOPE_LEN));
    plaintext.push(VERSION_V1);
    plaintext.push(Kind::Bip39Entropy as u8);
    plaintext.extend_from_slice(entropy);

    let blob = opaque::seal(password, &plaintext, KdfParams::DEFAULT)?;
    backend.write_new(path, &blob)?;
    Ok(())
}

/// Read, decrypt and validate the envelope at `path`, returning the BIP-39
/// entropy it declares.
///
/// # Errors
///
/// - [`SessionError::LegacySeedFormat`] if the blob is a pre-envelope raw-seed
///   keystore file. **The bytes are never reinterpreted as entropy** — the
///   caller is told to re-enrol from a phrase instead.
/// - [`SessionError::UnsupportedEnvelopeVersion`] /
///   [`SessionError::UnsupportedSeedKind`] for a blob written by a newer build.
/// - [`SessionError::Keystore`] for a missing file, wrong password, tampered
///   ciphertext, or a foreign container.
pub(crate) fn read_bip39_entropy(
    backend: &dyn KeychainBackend,
    path: &BackendKey,
    password: &Password,
) -> Result<Zeroizing<[u8; ENTROPY_LEN]>> {
    let blob = backend.read(path)?;

    // Discriminate BEFORE spending ~0.5s on Argon2id, and before any chance of
    // treating legacy bytes as entropy. The legacy path wrote a typed
    // `BlsSigning` keystore file, whose magic is a structural, non-heuristic
    // marker of the old derivation.
    if blob.starts_with(&BlsSigning::MAGIC) {
        return Err(SessionError::LegacySeedFormat);
    }

    let plaintext = opaque::open(password, &blob)?;
    if plaintext.len() != ENVELOPE_LEN {
        return Err(KeystoreError::InvalidPlaintext {
            expected: ENVELOPE_LEN,
            got: plaintext.len(),
        }
        .into());
    }
    if plaintext[0] != VERSION_V1 {
        return Err(SessionError::UnsupportedEnvelopeVersion(plaintext[0]));
    }
    // Validated for its own sake: an unknown kind must abort, not fall through
    // to the entropy interpretation.
    Kind::from_byte(plaintext[1])?;

    let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
    entropy.copy_from_slice(&plaintext[2..]);
    Ok(entropy)
}
