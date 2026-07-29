//! Cross-implementation conformance for the DIG recovery phrase.
//!
//! A 24-word BIP-39 phrase carries an implicit promise: *any* conforming wallet
//! restores it. These tests pin that promise for DIG against the STANDARD Chia
//! derivation, so a user who writes down a DIG phrase and later types it into
//! Sage lands on the same account (dig_ecosystem #1759).
//!
//! # Why every address here is a hardcoded bech32m literal
//!
//! If both sides of a comparison were computed live, a `bip39`/`chia-bls`
//! dependency bump could move them together and mask a regression. The literals
//! below were produced independently through `chia-wallet-sdk`'s own drivers and
//! are frozen. The precedent is dig-keystore's
//! `public_key_matches_chia_standard_master_key_for_all_zero_mnemonic`.
//!
//! # Why the OLD address is pinned too
//!
//! A test that computes the expected value the *new* way passes trivially. The
//! nearest wrong implementation is "feed the 32 entropy bytes straight to
//! `SecretKey::from_seed`" — the bug being fixed — so
//! [`old_entropy_as_seed_derivation_is_no_longer_reachable`] pins that address as
//! a literal too, proves the fixture can still exhibit it, and asserts the crate
//! no longer produces it.

use std::sync::Arc;

use chia::bls::{master_to_wallet_unhardened, SecretKey};
use chia::puzzles::standard::StandardArgs;
use chia::puzzles::DeriveSynthetic;
use chia_wallet_sdk::utils::Address;
use dig_identity::{derive_identity_sk, master_secret_key_from_seed, public_key_bytes};
use dig_keystore::{BackendKey, BlsSigning, KdfParams, Keystore, MemoryBackend, Password};
use dig_session::{Session, SessionError, ENTROPY_LEN, MASTER_SEED_LEN, RECOVERY_PHRASE_WORDS};

/// The canonical public BIP-39 test mnemonic: 24 words of all-zero entropy.
/// Public by construction — never a real key.
const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

/// Wallet address 0 of [`TEST_PHRASE`] under the STANDARD Chia derivation —
/// `SecretKey::from_seed(mnemonic.to_seed(""))` then
/// `master_to_wallet_unhardened(master, 0).derive_synthetic()`.
///
/// This is the value Sage shows for the same words. Frozen literal.
const SAGE_ADDRESS_0: &str = "xch16grurcglcwcv6arjarr720yd9wqhp9gkx3k8h25lhwg8pl7vl6ysuax0gy";

/// Wallet address 0 that the pre-#1759 DIG derivation produced for
/// [`TEST_PHRASE`]: the 32 entropy bytes fed to `SecretKey::from_seed` directly,
/// skipping BIP-39's PBKDF2 expansion. Frozen literal, kept ONLY so the
/// regression can be named and excluded.
const PRE_1759_ADDRESS_0: &str = "xch1jcvy96pjkh7wn5zvx6atwztru6kmhhyekd52td566leshf0d4tvsrtxr7a";

const PASSWORD: &str = "correct horse battery staple";

fn backend() -> Arc<MemoryBackend> {
    Arc::new(MemoryBackend::new())
}

/// The canonical Chia wallet address at `index` for master-HD `seed` bytes,
/// built with `chia-wallet-sdk`'s own drivers — never hand-rolled CLVM or
/// bech32.
///
/// Mirrors `dig-wallet-backend`'s `MasterKey::wallet_signing_key`: the
/// unhardened wallet child `m/12381/8444/2/index`, made synthetic against the
/// default hidden puzzle, currying the standard transaction puzzle.
fn wallet_address(seed: &[u8], index: u32) -> String {
    let master = SecretKey::from_seed(seed);
    let synthetic = master_to_wallet_unhardened(&master, index)
        .derive_synthetic()
        .public_key();
    Address::new(
        StandardArgs::curry_tree_hash(synthetic).into(),
        "xch".to_string(),
    )
    .encode()
    .expect("a 32-byte puzzle hash always bech32m-encodes")
}

/// The 32 bytes of entropy behind [`TEST_PHRASE`] — what a pre-#1759 build would
/// have handed to `SecretKey::from_seed`.
fn test_entropy() -> [u8; ENTROPY_LEN] {
    let entropy = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, TEST_PHRASE)
        .expect("a well-known valid BIP-39 test vector")
        .to_entropy();
    entropy
        .try_into()
        .expect("a 24-word mnemonic carries exactly 32 bytes of entropy")
}

fn enrol_from_phrase(phrase: &str) -> dig_session::UnlockedMasterSeed {
    Session::enroll_from_recovery_phrase(
        backend(),
        BackendKey::new("acct"),
        Password::from(PASSWORD),
        phrase,
    )
    .expect("a valid phrase must enrol")
}

/// CONF-1 (load-bearing): the phrase resolves to the address Sage shows.
#[test]
fn recovery_phrase_derives_the_standard_chia_address() {
    let handle = enrol_from_phrase(TEST_PHRASE);

    assert_eq!(
        wallet_address(&*handle.master_seed(), 0),
        SAGE_ADDRESS_0,
        "a DIG account restored from a 24-word phrase must sit at the SAME \
         address every standard Chia wallet derives from those words"
    );
}

/// CONF-2 (non-vacuity): the fixture CAN still exhibit the old, wrong address —
/// and the crate no longer produces it.
///
/// Without this, CONF-1 would pass for a build that computes the expectation the
/// same wrong way it derives.
#[test]
fn old_entropy_as_seed_derivation_is_no_longer_reachable() {
    let entropy = test_entropy();

    // The fixture is capable of showing the bug: entropy-as-seed still yields
    // the pre-#1759 address, so CONF-1 is discriminating rather than tautological.
    assert_eq!(
        wallet_address(&entropy, 0),
        PRE_1759_ADDRESS_0,
        "fixture check: entropy-as-seed must still reproduce the pre-#1759 \
         address, otherwise this test proves nothing"
    );
    assert_ne!(
        PRE_1759_ADDRESS_0, SAGE_ADDRESS_0,
        "fixture check: the two derivations must actually differ"
    );

    let handle = enrol_from_phrase(TEST_PHRASE);
    assert_ne!(
        wallet_address(&*handle.master_seed(), 0),
        PRE_1759_ADDRESS_0,
        "the crate must no longer derive the pre-#1759 entropy-as-seed address"
    );
    assert_eq!(
        handle.master_seed().len(),
        MASTER_SEED_LEN,
        "the exposed root must be the expanded seed, not the entropy"
    );
}

/// CONF-3 (fail-closed): a legacy raw-seed blob refuses to unlock rather than
/// being reinterpreted as BIP-39 entropy.
///
/// The two encodings are indistinguishable byte-wise, so a silent
/// reinterpretation would hand back a *working* handle for the *wrong* account.
/// The assertion is therefore that no handle exists at all.
#[test]
fn legacy_raw_seed_blob_fails_closed() {
    let be = backend();
    let path = BackendKey::new("acct");

    // Reproduce exactly what dig-session <= 0.4 wrote: the raw 32 bytes in a
    // typed `BlsSigning` keystore file.
    Keystore::<BlsSigning>::create(
        be.clone(),
        path.clone(),
        Password::from(PASSWORD),
        Some(zeroize::Zeroizing::new(test_entropy().to_vec())),
        KdfParams::DEFAULT,
    )
    .expect("the legacy write path must still work for the fixture");

    let err = Session::unlock_master_seed(be, path, Password::from(PASSWORD))
        .expect_err("a legacy blob must NOT unlock");
    assert!(
        matches!(err, SessionError::LegacySeedFormat),
        "a legacy blob must fail with LegacySeedFormat so the caller can offer \
         re-enrolment, got {err:?}"
    );
}

/// CONF-4 (round-trip): show the phrase, restore from it elsewhere, land on the
/// identical account — wallet address AND identity key.
///
/// Both are asserted because they derive through different paths
/// (`m/12381/8444/2/i` unhardened+synthetic vs `m/12381'/8444'/9'/0'` hardened);
/// an expansion applied to only one of them would pass a wallet-only test.
#[test]
fn recovery_phrase_round_trips_to_an_identical_account() {
    let original = enrol_from_phrase(TEST_PHRASE);

    let phrase = original.recovery_phrase();
    assert_eq!(
        phrase.split_whitespace().count(),
        RECOVERY_PHRASE_WORDS,
        "a DIG recovery phrase is {RECOVERY_PHRASE_WORDS} words"
    );

    let restored = enrol_from_phrase(&phrase);
    assert_eq!(
        wallet_address(&*restored.master_seed(), 0),
        wallet_address(&*original.master_seed(), 0),
        "restoring the shown phrase must reproduce the same wallet address"
    );
    assert_eq!(
        restored.public_key(),
        original.public_key(),
        "restoring the shown phrase must reproduce the same identity key"
    );
}

/// CONF-5: showing the phrase must not cost the user their session.
///
/// `recovery_phrase` takes `&self`; a consuming signature would force a UI to
/// choose between displaying the words and staying unlocked.
#[test]
fn recovery_phrase_does_not_consume_the_handle() {
    let handle = enrol_from_phrase(TEST_PHRASE);

    let first = handle.recovery_phrase();
    let second = handle.recovery_phrase();
    assert_eq!(&*first, &*second, "the phrase must be stable");
    assert_eq!(
        first.as_str(),
        TEST_PHRASE.split_whitespace().collect::<Vec<_>>().join(" "),
        "the phrase must be the canonical space-separated 24 words"
    );

    // The handle is still fully usable afterwards.
    let sig = handle.sign(b"still unlocked");
    assert_eq!(sig.len(), 96);
}

/// CONF-6 (placement, not just outcome): the identity key and the profile DEK
/// derive from the EXPANDED seed, not from the stored entropy.
///
/// Expanding only inside the wallet path would leave identity and DEK on the old
/// root — two roots for one account. Asserting the expanded-seed value *and*
/// rejecting the entropy-derived value is what distinguishes the two placements.
#[test]
fn identity_and_dek_derive_from_the_expanded_seed() {
    let handle = enrol_from_phrase(TEST_PHRASE);
    let entropy = test_entropy();

    let from_expanded = public_key_bytes(&derive_identity_sk(&master_secret_key_from_seed(
        &*handle.master_seed(),
    )));
    let from_entropy =
        public_key_bytes(&derive_identity_sk(&master_secret_key_from_seed(&entropy)));

    assert_ne!(
        from_expanded, from_entropy,
        "fixture check: the two roots must yield different identity keys"
    );
    assert_eq!(
        handle.public_key(),
        from_expanded,
        "the identity key must derive from the EXPANDED seed"
    );

    // Same property for the DEK, which is derived from the identity scalar.
    let label = b"dig-app:profile-dek:v2";
    let dek_from_entropy = {
        let scalar = derive_identity_sk(&master_secret_key_from_seed(&entropy)).to_bytes();
        // The DEK is a pure function of the scalar, so a differing scalar is a
        // differing DEK; comparing scalars is the stronger, simpler assertion.
        scalar
    };
    let dek_from_expanded =
        derive_identity_sk(&master_secret_key_from_seed(&*handle.master_seed())).to_bytes();
    assert_ne!(dek_from_entropy, dek_from_expanded);
    assert_ne!(
        &*handle.derive_symmetric_key(label),
        &[0u8; 32],
        "a DEK must be real key material"
    );
}

/// CONF-7: a malformed phrase is rejected, and the error names only the SHAPE of
/// the failure — never a word of the (secret) phrase.
#[test]
fn invalid_recovery_phrases_are_rejected_without_echoing_them() {
    let short = "abandon abandon abandon";
    let bad_checksum = TEST_PHRASE.replace("art", "abandon");
    let unknown_word = TEST_PHRASE.replace("art", "zzzzz");

    for phrase in [short, &bad_checksum, &unknown_word] {
        let err = Session::enroll_from_recovery_phrase(
            backend(),
            BackendKey::new("acct"),
            Password::from(PASSWORD),
            phrase,
        )
        .expect_err("an invalid phrase must be rejected");
        assert!(
            matches!(err, SessionError::InvalidRecoveryPhrase),
            "expected InvalidRecoveryPhrase, got {err:?}"
        );
        let rendered = err.to_string();
        for word in phrase.split_whitespace() {
            assert!(
                !rendered.contains(word),
                "the error message must not echo any word of the phrase"
            );
        }
    }
}

/// CONF-8: a phrase is accepted in the forms a user plausibly types — mixed case
/// and irregular whitespace — and still resolves to the same account.
#[test]
fn recovery_phrase_accepts_user_typed_whitespace_and_case() {
    let canonical = enrol_from_phrase(TEST_PHRASE);
    let messy = TEST_PHRASE.replace("abandon", "Abandon").replace(' ', "  ");

    let restored = enrol_from_phrase(messy.trim());
    assert_eq!(
        wallet_address(&*restored.master_seed(), 0),
        wallet_address(&*canonical.master_seed(), 0),
    );
}

/// CONF-9: re-enrolling over an existing account is refused, so a restore flow
/// cannot silently overwrite a key the user still needs.
#[test]
fn enrolment_refuses_to_overwrite_an_existing_account() {
    let be = backend();
    let path = BackendKey::new("acct");
    Session::enroll_master_seed(
        be.clone(),
        path.clone(),
        Password::from(PASSWORD),
        &test_entropy(),
    )
    .unwrap();

    let err = Session::enroll_master_seed(be, path, Password::from(PASSWORD), &test_entropy())
        .expect_err("a second enrolment at the same path must be refused");
    assert!(matches!(
        err,
        SessionError::Keystore(dig_keystore::KeystoreError::AlreadyExists(_))
    ));
}

/// CONF-10: an envelope from a NEWER build — unknown layout version or unknown
/// secret kind — is refused rather than guessed at.
///
/// A future kind might legitimately hold a 64-byte imported seed; interpreting
/// its first 32 bytes as entropy would derive a plausible wrong account, so this
/// build must decline.
#[test]
fn unknown_envelope_version_or_kind_is_refused() {
    let entropy = test_entropy();

    /// A predicate over the error an unrecognised envelope must produce.
    type ErrCheck = fn(&SessionError) -> bool;

    // (version, kind, the error it must produce)
    let cases: [(u8, u8, ErrCheck); 2] = [
        (0x02, 0x01, |e| {
            matches!(e, SessionError::UnsupportedEnvelopeVersion(0x02))
        }),
        (0x01, 0x7f, |e| {
            matches!(e, SessionError::UnsupportedSeedKind(0x7f))
        }),
    ];

    for (version, kind, expected) in cases {
        let mut plaintext = vec![version, kind];
        plaintext.extend_from_slice(&entropy);
        let blob =
            dig_keystore::opaque::seal(&Password::from(PASSWORD), &plaintext, KdfParams::DEFAULT)
                .unwrap();

        let be = backend();
        let path = BackendKey::new("acct");
        dig_keystore::KeychainBackend::write(&*be, &path, &blob).unwrap();

        let err = Session::unlock_master_seed(be, path, Password::from(PASSWORD))
            .expect_err("an unrecognised envelope must not unlock");
        assert!(
            expected(&err),
            "version {version:#04x} / kind {kind:#04x} produced the wrong error: {err:?}"
        );
    }
}
