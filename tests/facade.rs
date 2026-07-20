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
