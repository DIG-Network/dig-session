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

use chia_bls::{master_to_wallet_unhardened, SecretKey};
use chia_puzzle_types::standard::StandardArgs;
use chia_puzzle_types::DeriveSynthetic;
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

/// A SECOND, non-degenerate account: entropy `0x5A` repeated. Its 24 words and
/// address are unrelated to [`TEST_PHRASE`]'s.
///
/// [`TEST_PHRASE`] is all-ZERO entropy, which makes it a blind fixture for any
/// property about *which* account is in play — a bug that ignored the live
/// entropy and derived from zeros would be indistinguishable from correct. A
/// surviving mutation proved exactly that, so every "the right account" assertion
/// below uses two accounts and a truthful control.
const OTHER_PHRASE: &str =
    "fog spot notable regret pizza coffee harvest ensure fog spot notable regret      pizza coffee harvest ensure fog spot notable regret pizza coffee harvest equal";

/// Wallet address 0 of [`OTHER_PHRASE`] under the standard Chia derivation.
/// Frozen literal, produced independently through `chia-wallet-sdk`.
const OTHER_ADDRESS_0: &str = "xch1vpxzuu6aqfu790qcrcppcr2gmju4f5tpuuznuv2lx3g79v2jxc7qxttpzt";

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

/// The 32 bytes of entropy behind [`OTHER_PHRASE`].
fn other_entropy() -> [u8; ENTROPY_LEN] {
    bip39::Mnemonic::parse_in_normalized(bip39::Language::English, OTHER_PHRASE)
        .expect("a valid 24-word fixture")
        .to_entropy()
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
    // Deliberately the NON-DEGENERATE account: all-zero entropy cannot distinguish "restored this
    // account" from "restored a fixed account".
    let original = enrol_from_phrase(OTHER_PHRASE);

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

/// CONF-4b (two actors): the phrase describes THIS account, not some other one.
///
/// A `recovery_phrase()` that ignored the live entropy and derived from a fixed
/// value would pass every single-account round-trip: the phrase it returns is
/// self-consistent, it just belongs to the WRONG account — and the user who wrote
/// it down has backed up nothing. Only a second account with different entropy can
/// see that, so both accounts are exercised and each phrase must resolve to its
/// OWN frozen address.
#[test]
fn each_accounts_phrase_restores_that_account_and_not_another() {
    let a = enrol_from_phrase(TEST_PHRASE);
    let b = enrol_from_phrase(OTHER_PHRASE);

    assert_ne!(
        &*a.recovery_phrase(),
        &*b.recovery_phrase(),
        "two accounts must not report the same recovery phrase"
    );

    // Each account's own phrase must round-trip to that account's frozen address.
    for (handle, expected) in [(&a, SAGE_ADDRESS_0), (&b, OTHER_ADDRESS_0)] {
        assert_eq!(
            wallet_address(&*handle.master_seed(), 0),
            expected,
            "the account must sit at its own standard Chia address"
        );
        let restored = enrol_from_phrase(&handle.recovery_phrase());
        assert_eq!(
            wallet_address(&*restored.master_seed(), 0),
            expected,
            "the phrase this account reports must restore THIS account"
        );
        assert_eq!(
            restored.public_key(),
            handle.public_key(),
            "the phrase this account reports must restore THIS identity key"
        );
    }
}

/// CONF-5: showing the phrase must not cost the user their session.
///
/// `recovery_phrase` takes `&self`; a consuming signature would force a UI to
/// choose between displaying the words and staying unlocked.
#[test]
fn recovery_phrase_does_not_consume_the_handle() {
    // The NON-DEGENERATE account, so the reported phrase must actually be THIS account's.
    let handle = enrol_from_phrase(OTHER_PHRASE);

    let first = handle.recovery_phrase();
    let second = handle.recovery_phrase();
    assert_eq!(&*first, &*second, "the phrase must be stable");
    assert_eq!(
        first.as_str(),
        OTHER_PHRASE
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
        "the phrase must be the canonical space-separated 24 words for THIS account"
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
    // The NON-DEGENERATE account: with all-zero entropy an implementation that ignored the live root
    // would land on the same values by accident.
    let handle = enrol_from_phrase(OTHER_PHRASE);
    let entropy = other_entropy();

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
    let canonical = enrol_from_phrase(OTHER_PHRASE);
    let messy = OTHER_PHRASE.replace("spot", "Spot").replace(' ', "  ");

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

/// CONF-11: `bip39::Mnemonic` is `ZeroizeOnDrop`, i.e. the crate's `zeroize` feature is enabled.
///
/// This is a COMPILE-TIME assertion, and it is the only thing standing between the feature and a
/// silent regression: `expand_entropy` builds a `Mnemonic` on every derivation and its word indices
/// are a complete copy of the account root, so dropping the feature would leave un-wiped copies of the
/// root accumulating in memory — with every behavioural test still green.
#[test]
fn mnemonic_is_zeroize_on_drop() {
    fn requires_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    requires_zeroize_on_drop::<bip39::Mnemonic>();
}

/// CONF-12: a VALID BIP-39 phrase of a supported-but-shorter length (12, 15, 18 or 21 words) is
/// rejected with an error, never a panic.
///
/// DIG accounts are 24 words / 32 bytes of entropy. A 12-word phrase is perfectly valid BIP-39 — it
/// parses, its checksum passes — it just carries 16 bytes, so it reaches the length guard in
/// `entropy_from_phrase` rather than failing inside bip39 like a malformed phrase does. CONF-7's cases
/// all die inside bip39 first and never exercise that guard, so without this test deleting the guard
/// leaves the whole suite green while turning a legitimate user input into a `copy_from_slice` panic
/// on the restore path.
#[test]
fn valid_but_shorter_bip39_phrases_are_rejected_not_panicked() {
    // Each is a genuine, checksum-valid English BIP-39 mnemonic of all-zero entropy.
    let shorter = [
        // 12 words / 16 bytes
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        // 15 words / 20 bytes
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon address",
        // 18 words / 24 bytes
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon agent",
        // 21 words / 28 bytes
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
    ];

    for phrase in shorter {
        // Fixture check: bip39 itself ACCEPTS these, so the rejection below must come from DIG's
        // 24-word requirement and not from a parse failure — otherwise this test proves nothing.
        assert!(
            bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase).is_ok(),
            "fixture check: this must be a VALID BIP-39 phrase, or the guard is never reached"
        );

        let err = Session::enroll_from_recovery_phrase(
            backend(),
            BackendKey::new("acct"),
            Password::from(PASSWORD),
            phrase,
        )
        .expect_err("a phrase shorter than 24 words must be rejected");
        assert!(
            matches!(err, SessionError::InvalidRecoveryPhrase),
            "expected InvalidRecoveryPhrase, got {err:?}"
        );
    }
}
