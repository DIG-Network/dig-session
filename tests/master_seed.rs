//! Integration tests for the master-SEED unlock path (`UnlockedMasterSeed`),
//! exercised against an in-memory keystore backend.
//!
//! These pin the 0.3.0 additions: that the raw master seed round-trips verbatim
//! (the primitive wallet-backend `MasterKey::from_seed_bytes` expects), that the
//! identity key + DEK derived from the seed are BYTE-IDENTICAL to the 0.2.0
//! identity-scalar path for the same seed (§5.1 at-rest back-compat), and that
//! the custody/redaction guarantees hold on the new handle too.

use std::sync::Arc;

use dig_identity::{
    derive_identity_sk, derive_identity_sk_at, master_secret_key_from_seed, public_key_bytes,
};
use dig_keystore::{BackendKey, MemoryBackend, Password};
use dig_session::{Session, SessionError, ENTROPY_LEN, MASTER_SEED_LEN};
use hkdf::Hkdf;
use sha2::Sha256;

/// A fixed 32 bytes of BIP-39 entropy — what the master-seed path stores at rest.
const ENTROPY: [u8; ENTROPY_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const PASSWORD: &str = "correct horse battery staple";

/// dig-app's profile-DEK HKDF `info` label (`DEK_INFO` in dig-app-core
/// `keystore/secrets.rs`) — mirrored from `dig_constants::PROFILE_DEK_LABEL`.
const DIG_APP_DEK_LABEL: &[u8] = b"dig-app:profile-dek:v2";

/// The profile-0 and profile-1 DEKs for [`ENTROPY`] + [`DIG_APP_DEK_LABEL`], as FROZEN HEX LITERALS.
///
/// Hardcoded on purpose. `dig_app_reference_dek` reconstructs the HKDF independently, but its INPUT
/// scalar still comes from `bip39` + `dig-identity` — so a bump in either would move the reference and
/// the production value together and mask the drift. Only a literal pins the actual bytes, and these
/// bytes ARE the at-rest contract: a change makes every already-sealed profile blob unreadable (§5.1).
const GOLDEN_DEK_PROFILE_0: &str =
    "7bf5db71c6a53f4d52b95ff4408cd2a542ad1f335324a8a26fdb243b846fcf37";
const GOLDEN_DEK_PROFILE_1: &str =
    "eddb892484e73c6046ecdbdd87610f4aba74d4b728addaa7ff20d8c598c729c9";

/// Independently expand [`ENTROPY`] into the 64-byte master HD seed the BIP-39 /
/// Chia way. Deliberately re-derived here from `bip39` rather than calling
/// dig-session's own expansion, so a drift on either side is caught rather than
/// cancelling out (dig_ecosystem #1759).
fn expanded() -> [u8; MASTER_SEED_LEN] {
    bip39::Mnemonic::from_entropy_in(bip39::Language::English, &ENTROPY)
        .expect("32 bytes is valid 24-word BIP-39 entropy")
        .to_seed("")
}

fn backend() -> Arc<MemoryBackend> {
    Arc::new(MemoryBackend::new())
}

/// Independently reconstruct dig-app's DEK from a raw identity scalar, using the
/// literal HKDF construction from dig-app-core `keystore/secrets.rs`. Kept
/// separate from production code so a drift in either side is caught.
fn dig_app_reference_dek(identity_scalar: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(33);
    ikm.push(2u8); // SEALED_IDENTITY_VERSION == to_sealed_bytes() prefix.
    ikm.extend_from_slice(identity_scalar);

    let hkdf = Hkdf::<Sha256>::new(Some(b"dig-app:dek-salt:v1"), &ikm);
    let mut dek = [0u8; 32];
    hkdf.expand(label, &mut dek).unwrap();
    dek
}

#[test]
fn master_seed_returns_the_expanded_bip39_seed() {
    // MS-1: master_seed() exposes the EXPANDED 64-byte BIP-39 seed — the value
    // wallet-backend's `MasterKey::from_seed_bytes` must consume for the account
    // to match Sage — NOT the 32 stored entropy bytes (dig_ecosystem #1759).
    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();

    let seed = handle.master_seed();
    assert_eq!(
        seed.len(),
        MASTER_SEED_LEN,
        "master_seed() must be the 64-byte expanded BIP-39 seed"
    );
    assert_eq!(
        &*seed,
        &expanded(),
        "master_seed() must equal entropy -> 24 words -> to_seed(\"\")"
    );
    assert_ne!(
        &seed[..ENTROPY_LEN],
        &ENTROPY[..],
        "master_seed() must NOT be the raw stored entropy — that is the bug"
    );
}

#[test]
fn master_seed_public_key_matches_dig_identity_canonical() {
    // MS-2: the identity key derived from the seed equals dig-identity's
    // canonical key — the same key the 0.2.0 identity path anchors in the DID.
    let expected = public_key_bytes(&derive_identity_sk(&master_secret_key_from_seed(
        &expanded(),
    )));

    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();

    assert_eq!(
        handle.public_key(),
        expected,
        "master-seed path public key must equal dig_identity::public_key_bytes(derive_identity_sk(master_secret_key_from_seed(seed)))"
    );
}

#[test]
fn master_seed_public_key_equals_identity_scalar_path() {
    // MS-2 (cross-path): the two 0.3.0 unlock paths yield the SAME identity key
    // for the same seed, so a consumer may migrate between them freely.
    let identity_path = Session::enroll_identity(
        backend(),
        BackendKey::new("id"),
        Password::from(PASSWORD),
        &expanded(),
    )
    .unwrap();
    let seed_path = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();

    assert_eq!(
        identity_path.public_key().to_bytes(),
        seed_path.public_key(),
        "the identity-scalar path and the master-seed path must derive the same identity public key"
    );
}

#[test]
fn master_seed_dek_is_byte_identical_to_identity_scalar_path() {
    // MS-3 (the required 0.3.0 golden invariant): DEK(master-seed path) ==
    // DEK(identity-scalar path), byte-for-byte, for the same seed and label — so
    // a profile blob sealed via the 0.2.0 identity path opens unchanged after a
    // consumer migrates to the master-seed path (§5.1 at-rest back-compat).
    let identity_path = Session::enroll_identity(
        backend(),
        BackendKey::new("id"),
        Password::from(PASSWORD),
        &expanded(),
    )
    .unwrap();
    let seed_path = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();

    let dek_identity = identity_path.derive_symmetric_key(DIG_APP_DEK_LABEL);
    let dek_seed = seed_path.derive_symmetric_key(DIG_APP_DEK_LABEL);

    assert_eq!(
        &*dek_identity, &*dek_seed,
        "master-seed DEK must be byte-identical to the identity-scalar-path DEK"
    );

    // And both must equal dig-app's independently-reconstructed reference DEK.
    let scalar = derive_identity_sk(&master_secret_key_from_seed(&expanded())).to_bytes();
    let reference = dig_app_reference_dek(&scalar, DIG_APP_DEK_LABEL);
    assert_eq!(
        &*dek_seed, &reference,
        "master-seed DEK must equal dig-app's profile DEK"
    );
}

#[test]
fn master_seed_dek_golden_vector() {
    // MS-3 (frozen): a FIXED entropy + FIXED label -> the EXACT DEK bytes, pinned as a HEX LITERAL.
    // Any KDF-parameter or root drift fails this comparison and flags a §5.1 break.
    //
    // The independently-reconstructed reference is ALSO asserted, so the test catches both a drift in
    // the frozen bytes (via the literal) and a divergence between dig-session's HKDF and dig-app's
    // (via the reference) — the literal alone could not distinguish those.
    let scalar = derive_identity_sk(&master_secret_key_from_seed(&expanded())).to_bytes();
    let reference = dig_app_reference_dek(&scalar, DIG_APP_DEK_LABEL);
    let expected = hex::decode(GOLDEN_DEK_PROFILE_0).expect("a valid hex literal");
    assert_eq!(
        hex::encode(reference),
        GOLDEN_DEK_PROFILE_0,
        "dig-app's reference DEK drifted from the frozen literal (§5.1 break)"
    );

    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();
    let dek = handle.derive_symmetric_key(DIG_APP_DEK_LABEL);

    assert_eq!(
        &dek[..],
        &expected[..],
        "master-seed DEK must match the frozen literal"
    );
}

#[test]
fn master_seed_signature_verifies_against_public_key() {
    // MS-4: a signature from the seed-derived identity key verifies under its
    // public key.
    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();

    let msg = b"authorize this action";
    let sig = handle.sign(msg);
    let pk = dig_keystore::bls::PublicKey::from_bytes(&handle.public_key()).unwrap();
    assert!(dig_keystore::bls::verify(
        &dig_keystore::bls::Signature::from_bytes(&sig).unwrap(),
        &pk,
        msg
    ));
}

#[test]
fn master_seed_signing_fn_works_after_handle_dropped() {
    // MS-5: the injected primitive owns its own zeroizing seed copy and keeps
    // signing after the handle drops.
    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();
    let pk = dig_keystore::bls::PublicKey::from_bytes(&handle.public_key()).unwrap();

    let sign = handle.signing_fn();
    drop(handle);

    let msg = b"signed by the injected primitive";
    let sig = sign(msg);
    assert!(dig_keystore::bls::verify(
        &dig_keystore::bls::Signature::from_bytes(&sig).unwrap(),
        &pk,
        msg
    ));
}

#[test]
fn enroll_then_unlock_master_seed_roundtrips() {
    // MS-6: unlock_master_seed reopens the persisted seed and reproduces the
    // same seed bytes and identity key.
    let be = backend();
    let path = BackendKey::new("seed");

    let enrolled =
        Session::enroll_master_seed(be.clone(), path.clone(), Password::from(PASSWORD), &ENTROPY)
            .unwrap();
    let enrolled_pk = enrolled.public_key();
    drop(enrolled);

    let reopened = Session::unlock_master_seed(be, path, Password::from(PASSWORD)).unwrap();
    assert_eq!(
        &*reopened.master_seed(),
        &expanded(),
        "reopened seed must equal the enrolled account's expanded seed"
    );
    assert_eq!(
        reopened.public_key(),
        enrolled_pk,
        "reopened identity key must match the enrolled one"
    );
}

#[test]
fn unlock_master_seed_with_wrong_password_fails() {
    // MS-7.
    let be = backend();
    let path = BackendKey::new("seed");
    Session::enroll_master_seed(be.clone(), path.clone(), Password::from(PASSWORD), &ENTROPY)
        .unwrap();

    let err = Session::unlock_master_seed(be, path, Password::from("wrong")).err();
    assert!(matches!(err, Some(SessionError::Keystore(_))));
}

#[test]
fn profile_ix_zero_public_key_equals_default_path() {
    // PROF-1 (0.4.0 byte-identity): profile_public_key(0) == public_key(), because
    // derive_identity_sk_at(master, 0) == derive_identity_sk(master).
    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();
    assert_eq!(
        handle.profile_public_key(0),
        handle.public_key(),
        "profile_public_key(0) must be byte-identical to public_key()"
    );
}

#[test]
fn profile_ix_zero_sign_equals_default_path() {
    // PROF-2: profile_sign(0, m) == sign(m), byte-for-byte.
    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();
    let msg = b"authorize this action";
    assert_eq!(
        handle.profile_sign(0, msg),
        handle.sign(msg),
        "profile_sign(0, m) must be byte-identical to sign(m)"
    );
}

#[test]
fn profile_ix_zero_dek_equals_default_path() {
    // PROF-3 (§5.1 at-rest back-compat): profile_derive_symmetric_key(0, label) ==
    // derive_symmetric_key(label), byte-for-byte.
    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();
    assert_eq!(
        &*handle.profile_derive_symmetric_key(0, DIG_APP_DEK_LABEL),
        &*handle.derive_symmetric_key(DIG_APP_DEK_LABEL),
        "profile_derive_symmetric_key(0, label) must equal derive_symmetric_key(label)"
    );
}

#[test]
fn profile_public_key_matches_dig_identity_canonical_at() {
    // PROF-4: the per-profile key equals dig-identity's canonical derive_identity_sk_at.
    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();
    let master = master_secret_key_from_seed(&expanded());
    for profile_ix in [0u32, 1, 2, 7] {
        let expected = public_key_bytes(&derive_identity_sk_at(&master, profile_ix));
        assert_eq!(
            handle.profile_public_key(profile_ix),
            expected,
            "profile_public_key({profile_ix}) must equal dig_identity canonical derive_identity_sk_at"
        );
    }
}

#[test]
fn profile_ix_one_is_distinct_and_deterministic() {
    // PROF-5: profile 1 differs from profile 0 (distinct keys/DEKs) and is stable
    // across handles for the same seed.
    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();
    let handle2 = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed2"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();

    // Distinct from profile 0.
    assert_ne!(
        handle.profile_public_key(1),
        handle.profile_public_key(0),
        "profile 1 key must differ from profile 0"
    );
    assert_ne!(
        &*handle.profile_derive_symmetric_key(1, DIG_APP_DEK_LABEL),
        &*handle.profile_derive_symmetric_key(0, DIG_APP_DEK_LABEL),
        "profile 1 DEK must differ from profile 0"
    );

    // Deterministic across handles for the same seed.
    assert_eq!(
        handle.profile_public_key(1),
        handle2.profile_public_key(1),
        "profile 1 key must be deterministic for the same seed"
    );
    assert_eq!(
        &*handle.profile_derive_symmetric_key(1, DIG_APP_DEK_LABEL),
        &*handle2.profile_derive_symmetric_key(1, DIG_APP_DEK_LABEL),
        "profile 1 DEK must be deterministic for the same seed"
    );
}

#[test]
fn profile_sign_verifies_against_profile_public_key() {
    // PROF-6: a profile signature verifies under that profile's public key.
    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();
    let msg = b"authorize as profile 3";
    let sig = handle.profile_sign(3, msg);
    let pk = dig_keystore::bls::PublicKey::from_bytes(&handle.profile_public_key(3)).unwrap();
    assert!(dig_keystore::bls::verify(
        &dig_keystore::bls::Signature::from_bytes(&sig).unwrap(),
        &pk,
        msg
    ));
    // And the profile-3 key does NOT verify a profile-1 signature.
    let sig1 = handle.profile_sign(1, msg);
    assert!(!dig_keystore::bls::verify(
        &dig_keystore::bls::Signature::from_bytes(&sig1).unwrap(),
        &pk,
        msg
    ));
}

#[test]
fn profile_dek_golden_vector() {
    // PROF-7 (frozen): FIXED entropy + profile 1 + FIXED label -> the EXACT DEK bytes, pinned as a
    // HEX LITERAL, plus dig-app's independently-reconstructed reference over
    // derive_identity_sk_at(master, 1).
    let scalar = derive_identity_sk_at(&master_secret_key_from_seed(&expanded()), 1).to_bytes();
    let reference = dig_app_reference_dek(&scalar, DIG_APP_DEK_LABEL);
    let expected = hex::decode(GOLDEN_DEK_PROFILE_1).expect("a valid hex literal");
    assert_eq!(
        hex::encode(reference),
        GOLDEN_DEK_PROFILE_1,
        "dig-app's reference profile-1 DEK drifted from the frozen literal (§5.1 break)"
    );
    assert_ne!(
        GOLDEN_DEK_PROFILE_1, GOLDEN_DEK_PROFILE_0,
        "fixture check: profile 1 must derive a DIFFERENT DEK from profile 0"
    );

    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();
    assert_eq!(
        &handle.profile_derive_symmetric_key(1, DIG_APP_DEK_LABEL)[..],
        &expected[..],
        "profile 1 DEK must match the frozen literal"
    );
}

#[test]
fn master_seed_debug_does_not_leak_secret() {
    // MS-8: the Debug impl redacts the seed.
    let handle = Session::enroll_master_seed(
        backend(),
        BackendKey::new("seed"),
        Password::from(PASSWORD),
        &ENTROPY,
    )
    .unwrap();
    let rendered = format!("{handle:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("UnlockedMasterSeed"));
}
