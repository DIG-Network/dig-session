//! Integration tests for the dig-session facade, exercised against an
//! in-memory keystore backend.
//!
//! These double as behaviour documentation for the unlock / enroll / inject
//! flow and pin the custody-critical property that enrollment reproduces the
//! canonical dig-identity key on unlock.

use std::sync::Arc;

use dig_identity::{derive_identity_sk, master_secret_key_from_seed, public_key_bytes};
use dig_keystore::{BackendKey, BlsSigning, KdfParams, Keystore, MemoryBackend, Password};
use dig_session::{Session, SessionError};
use hkdf::Hkdf;
use sha2::Sha256;

const SEED: &[u8] = b"dig-session integration-test seed material";
const PASSWORD: &str = "correct horse battery staple";

fn backend() -> Arc<MemoryBackend> {
    Arc::new(MemoryBackend::new())
}

#[test]
fn enroll_then_unlock_roundtrips_the_same_key() {
    let be = backend();
    let path = BackendKey::new("identity");

    let enrolled =
        Session::enroll_identity(be.clone(), path.clone(), Password::from(PASSWORD), SEED).unwrap();
    let enrolled_pk = enrolled.public_key().to_bytes();
    drop(enrolled);

    let reopened =
        Session::unlock::<dig_session::L1WalletBls>(be, path, Password::from(PASSWORD)).unwrap();
    assert_eq!(
        reopened.public_key().to_bytes(),
        enrolled_pk,
        "unlock must reconstruct the same public key that enrollment produced"
    );
}

#[test]
fn enrolled_public_key_matches_dig_identity_canonical() {
    // The custody-critical regression: storing the derived key under
    // `L1WalletBls` (from_bytes) must reproduce dig-identity's canonical key.
    // If the storage scheme ever reverts to `BlsSigning` (from_seed), the key
    // would be re-derived and this assertion fails.
    let master = master_secret_key_from_seed(SEED);
    let identity_sk = derive_identity_sk(&master);
    let expected = public_key_bytes(&identity_sk);

    let enrolled = Session::enroll_identity(
        backend(),
        BackendKey::new("identity"),
        Password::from(PASSWORD),
        SEED,
    )
    .unwrap();

    assert_eq!(
        enrolled.public_key().to_bytes(),
        expected,
        "enrolled identity key must equal dig_identity::public_key_bytes(derive_identity_sk(master))"
    );
}

#[test]
fn signature_verifies_against_public_key() {
    let enrolled = Session::enroll_identity(
        backend(),
        BackendKey::new("identity"),
        Password::from(PASSWORD),
        SEED,
    )
    .unwrap();

    let msg = b"authorize this action";
    let sig = enrolled.sign(msg);
    assert!(dig_keystore::bls::verify(&sig, enrolled.public_key(), msg));
}

#[test]
fn injected_signing_fn_works_after_handle_dropped() {
    let enrolled = Session::enroll_identity(
        backend(),
        BackendKey::new("identity"),
        Password::from(PASSWORD),
        SEED,
    )
    .unwrap();
    let pk = *enrolled.public_key();

    // inject_into hands the consumer only a bare signing primitive.
    let sign = enrolled.inject_into(|f| f);
    drop(enrolled);

    let msg = b"signed by the injected primitive";
    let sig = sign(msg);
    assert!(dig_keystore::bls::verify(&sig, &pk, msg));
}

#[test]
fn unlock_with_wrong_password_fails() {
    let be = backend();
    let path = BackendKey::new("identity");
    Session::enroll_identity(be.clone(), path.clone(), Password::from(PASSWORD), SEED).unwrap();

    let err = Session::unlock::<dig_session::L1WalletBls>(be, path, Password::from("wrong")).err();
    assert!(matches!(err, Some(SessionError::Keystore(_))));
}

#[test]
fn enroll_with_empty_seed_is_rejected() {
    let err = Session::enroll_identity(
        backend(),
        BackendKey::new("identity"),
        Password::from(PASSWORD),
        b"",
    )
    .err();
    assert!(matches!(err, Some(SessionError::EmptySeed)));
}

#[test]
fn enroll_then_drop_leaves_key_reproducible_without_panic() {
    // Custody hardening (#1327): enroll_identity confines the transient
    // chia_bls::SecretKey scalars to the smallest scope and drops them
    // immediately, routing the owned byte buffers through `Zeroizing`. We
    // cannot assert the wipe of freed foreign scalar memory directly, so we
    // pin the observable contract: enrollment (which now derives inside an
    // inner block that drops the secret keys before returning) still produces
    // and persists the canonical key, and enroll+drop completes without panic.
    let be = backend();
    let path = BackendKey::new("identity");

    let enrolled =
        Session::enroll_identity(be.clone(), path.clone(), Password::from(PASSWORD), SEED).unwrap();
    let enrolled_pk = enrolled.public_key().to_bytes();
    drop(enrolled); // exercise the drop path explicitly

    let expected = public_key_bytes(&derive_identity_sk(&master_secret_key_from_seed(SEED)));
    assert_eq!(
        enrolled_pk, expected,
        "enroll must still reproduce the canonical dig-identity key after lifetime minimization"
    );

    // The persisted key is intact and unlockable after the enroll handle dropped.
    let reopened =
        Session::unlock::<dig_session::L1WalletBls>(be, path, Password::from(PASSWORD)).unwrap();
    assert_eq!(reopened.public_key().to_bytes(), enrolled_pk);
}

#[test]
fn unlock_is_generic_over_bls_signing_scheme() {
    // Session::unlock also serves seed-derived validator keys (BlsSigning).
    let be = backend();
    let path = BackendKey::new("validator");
    Keystore::<BlsSigning>::create(
        be.clone(),
        path.clone(),
        Password::from(PASSWORD),
        None, // generate a fresh seed
        KdfParams::FAST_TEST,
    )
    .unwrap();

    let signer = Session::unlock::<BlsSigning>(be, path, Password::from(PASSWORD)).unwrap();
    let msg = b"validator attestation";
    let sig = signer.sign(msg);
    assert!(dig_keystore::bls::verify(&sig, signer.public_key(), msg));
}

/// The label dig-app passes as HKDF `info` for its profile DEK
/// (`DEK_INFO` in dig-app-core `keystore/secrets.rs`). Deriving with this label
/// MUST reproduce dig-app's DEK byte-for-byte.
const DIG_APP_DEK_LABEL: &[u8] = b"dig-app:profile-dek:v2";

/// Independently reconstruct dig-app's DEK from a raw identity scalar, using the
/// literal HKDF construction from dig-app-core `keystore/secrets.rs`
/// (`dek_password` + `to_sealed_bytes`). This is the reference the facade's
/// `derive_symmetric_key` is checked against — kept deliberately separate from
/// the production code so a drift in either side is caught.
fn dig_app_reference_dek(identity_scalar: &[u8; 32], label: &[u8]) -> [u8; 32] {
    // IKM = SEALED_IDENTITY_VERSION(2) || identity_scalar  (== to_sealed_bytes()).
    let mut ikm = Vec::with_capacity(33);
    ikm.push(2u8);
    ikm.extend_from_slice(identity_scalar);

    let hkdf = Hkdf::<Sha256>::new(Some(b"dig-app:dek-salt:v1"), &ikm);
    let mut dek = [0u8; 32];
    hkdf.expand(label, &mut dek).unwrap();
    dek
}

#[test]
fn derive_symmetric_key_is_byte_identical_to_dig_app_dek() {
    // Custody-critical (§5.1): the DEK derived by the facade MUST equal the DEK
    // dig-app already uses to seal profile blobs at rest. Reproduce dig-app's
    // exact construction from the same identity scalar and assert equality.
    let identity_scalar = derive_identity_sk(&master_secret_key_from_seed(SEED)).to_bytes();
    let expected = dig_app_reference_dek(&identity_scalar, DIG_APP_DEK_LABEL);

    let enrolled = Session::enroll_identity(
        backend(),
        BackendKey::new("identity"),
        Password::from(PASSWORD),
        SEED,
    )
    .unwrap();
    let dek = enrolled.derive_symmetric_key(DIG_APP_DEK_LABEL);

    assert_eq!(
        &*dek, &expected,
        "facade DEK must be byte-identical to dig-app's profile DEK"
    );
}

#[test]
fn derive_symmetric_key_golden_vector() {
    // Frozen golden vector: a FIXED identity scalar + FIXED label -> the EXACT
    // DEK bytes. If any KDF parameter (hash, IKM version prefix, salt, info, or
    // output length) ever changes, this literal comparison fails and flags a
    // §5.1 at-rest break. The scalar below is derive_identity_sk(seed=SEED),
    // which enroll_identity(SEED) stores verbatim.
    const GOLDEN_SCALAR: [u8; 32] = [
        0x35, 0x72, 0x44, 0xb8, 0x58, 0x03, 0x51, 0xab, 0x85, 0x7d, 0x76, 0x55, 0x87, 0xe6, 0x37,
        0x42, 0x41, 0x59, 0x04, 0x2e, 0xd0, 0xa6, 0x5f, 0x49, 0x72, 0xc1, 0xb3, 0x75, 0x7d, 0x97,
        0xc1, 0x2a,
    ];
    const GOLDEN_DEK: [u8; 32] = [
        0x1a, 0xc8, 0x13, 0xe4, 0x91, 0xba, 0x3d, 0x05, 0xf4, 0xbe, 0x28, 0x36, 0xbb, 0xa7, 0x36,
        0xb4, 0xba, 0x0a, 0x2d, 0x74, 0xbd, 0xe4, 0x5a, 0x5b, 0x02, 0x85, 0x9d, 0x8a, 0xcf, 0xb1,
        0xcf, 0x7b,
    ];

    // The scalar constant tracks the real enrolled scalar for SEED.
    let real_scalar = derive_identity_sk(&master_secret_key_from_seed(SEED)).to_bytes();
    assert_eq!(
        real_scalar, GOLDEN_SCALAR,
        "golden scalar must equal derive_identity_sk(SEED) — update the fixture if dig-identity changes"
    );

    let enrolled = Session::enroll_identity(
        backend(),
        BackendKey::new("identity"),
        Password::from(PASSWORD),
        SEED,
    )
    .unwrap();
    let dek = enrolled.derive_symmetric_key(DIG_APP_DEK_LABEL);
    assert_eq!(
        &*dek, &GOLDEN_DEK,
        "DEK must match the frozen golden vector"
    );
}

#[test]
fn derive_symmetric_key_varies_by_label() {
    let enrolled = Session::enroll_identity(
        backend(),
        BackendKey::new("identity"),
        Password::from(PASSWORD),
        SEED,
    )
    .unwrap();
    let a = enrolled.derive_symmetric_key(b"label-a");
    let b = enrolled.derive_symmetric_key(b"label-b");
    assert_ne!(&*a, &*b, "distinct labels must derive distinct keys");
    // Determinism: same label -> same key.
    let a2 = enrolled.derive_symmetric_key(b"label-a");
    assert_eq!(&*a, &*a2, "same label must derive the same key");
}

#[test]
fn debug_does_not_leak_secret() {
    let enrolled = Session::enroll_identity(
        backend(),
        BackendKey::new("identity"),
        Password::from(PASSWORD),
        SEED,
    )
    .unwrap();
    let rendered = format!("{enrolled:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("L1WalletBls"));
}
