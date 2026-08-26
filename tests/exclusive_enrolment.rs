//! Enrolling an account root must be an *establish*, not an *update*.
//!
//! `Session::enroll_master_seed` seals BIP-39 entropy — the account root, from
//! which every wallet address, the identity key and every profile DEK descend.
//! Overwriting an existing one destroys the only copy of a seed whose owner may
//! have no other record, so the write must happen exactly once.
//!
//! Through dig-keystore 0.9 the only way to express that was `exists` followed
//! by `write`, which is not one step: a second enrolment that begins between
//! those two calls observes an absence, seals, and replaces the winner's blob —
//! leaving the caller who was told "enrolled" holding a phrase that no longer
//! opens anything. dig-keystore 0.11 added `KeychainBackend::write_new`, the
//! indivisible create-if-absent, and 0.13 moved `Keystore::create` onto it.
//!
//! # Why the fixture looks like this
//!
//! Both implementations return `AlreadyExists` for a *sequential* second
//! enrolment, so asserting that outcome cannot tell them apart — it is the
//! outcome the broken version also produces. The property is exclusivity under
//! **contention**, and the input that distinguishes it is the interleaving
//! itself: a backend that already holds the key while `exists` still answers
//! `false`, exactly as it would for a caller whose check ran a moment before
//! the winner's write landed.
//!
//! [`RacedBackend`] models that one interleaving deterministically. Only
//! `exists` is made to lie; `write_new` and `write` behave as a real backend's
//! do, and [`enrolment_into_a_vacant_slot_still_succeeds`] is the honest
//! control proving the double is not simply refusing everything.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dig_keystore::{BackendKey, KeychainBackend, KeystoreError, Password};
use dig_session::{Session, SessionError};

const PASSWORD: &str = "correct horse battery staple";
const PATH: &str = "account-root";

/// The entropy the enrolment that *won* the race sealed.
const WINNER_ENTROPY: [u8; 32] = [0xA1; 32];
/// The entropy a second, racing enrolment tries to seal over it.
const LOSER_ENTROPY: [u8; 32] = [0x5C; 32];

/// A backend whose `exists` reports a confident absence for a key it is in fact
/// holding — the observable state of any store during the window between a
/// racing writer's check and its write.
///
/// Every other method is faithful: `write` replaces (as a real backend's does,
/// which is why the pre-check was never sufficient) and `write_new` refuses an
/// occupied slot.
#[derive(Default)]
struct RacedBackend {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl RacedBackend {
    /// Seed the store with the winner's blob, as if that write had just landed.
    fn holding(key: &str, blob: Vec<u8>) -> Self {
        let this = Self::default();
        this.blobs.lock().unwrap().insert(key.to_string(), blob);
        this
    }

    fn blob_at(&self, key: &str) -> Option<Vec<u8>> {
        self.blobs.lock().unwrap().get(key).cloned()
    }
}

impl KeychainBackend for RacedBackend {
    fn read(&self, key: &BackendKey) -> Result<Vec<u8>, KeystoreError> {
        self.blob_at(key.as_str()).ok_or_else(|| {
            KeystoreError::Backend(
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no blob at {}", key.as_str()),
                )
                .into(),
            )
        })
    }

    fn write(&self, key: &BackendKey, data: &[u8]) -> Result<(), KeystoreError> {
        self.blobs
            .lock()
            .unwrap()
            .insert(key.as_str().to_string(), data.to_vec());
        Ok(())
    }

    fn write_new(&self, key: &BackendKey, data: &[u8]) -> Result<(), KeystoreError> {
        let mut blobs = self.blobs.lock().unwrap();
        if blobs.contains_key(key.as_str()) {
            return Err(KeystoreError::AlreadyExists(key.as_str().to_string()));
        }
        blobs.insert(key.as_str().to_string(), data.to_vec());
        Ok(())
    }

    /// The lie under test: a confident absence for a key that is present.
    fn exists(&self, _key: &BackendKey) -> Result<bool, KeystoreError> {
        Ok(false)
    }

    fn delete(&self, key: &BackendKey) -> Result<(), KeystoreError> {
        self.blobs.lock().unwrap().remove(key.as_str());
        Ok(())
    }

    fn list(&self, prefix: &str) -> Result<Vec<BackendKey>, KeystoreError> {
        Ok(self
            .blobs
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .map(|k| BackendKey::new(k.clone()))
            .collect())
    }
}

/// Enrol the winner into a vacant store and hand back the sealed bytes, so the
/// racing enrolment below is tested against a blob a real enrolment produced
/// rather than an invented one.
fn winners_sealed_blob() -> Vec<u8> {
    let backend = Arc::new(RacedBackend::default());
    Session::enroll_master_seed(
        backend.clone(),
        BackendKey::new(PATH.to_string()),
        Password::from(PASSWORD),
        &WINNER_ENTROPY,
    )
    .expect("enrolling into an empty store must succeed");
    backend
        .blob_at(PATH)
        .expect("enrolment must have stored a blob")
}

/// The control. Without this, a `write_new` that refused unconditionally would
/// satisfy the test below while making enrolment impossible.
#[test]
fn enrolment_into_a_vacant_slot_still_succeeds() {
    let backend = Arc::new(RacedBackend::default());

    let seed = Session::enroll_master_seed(
        backend.clone(),
        BackendKey::new(PATH.to_string()),
        Password::from(PASSWORD),
        &WINNER_ENTROPY,
    )
    .expect("a vacant slot must still be enrollable");

    assert_ne!(
        seed.master_seed().as_slice(),
        [0u8; 64].as_slice(),
        "the enrolment must hand back a real derived root"
    );
    assert!(
        backend.blob_at(PATH).is_some(),
        "a successful enrolment must leave a blob behind"
    );
}

/// The regression. `enroll_master_seed` must consult the backend's exclusive
/// create-if-absent primitive, so the backend — not a separate, already-stale
/// `exists` reading — is the single authority on whether the root was there.
#[test]
fn a_racing_enrolment_cannot_overwrite_an_established_root() {
    let winner = winners_sealed_blob();
    let backend = Arc::new(RacedBackend::holding(PATH, winner.clone()));

    let outcome = Session::enroll_master_seed(
        backend.clone(),
        BackendKey::new(PATH.to_string()),
        Password::from(PASSWORD),
        &LOSER_ENTROPY,
    );

    // Asserted FIRST and separately from the error: a fix that reported
    // `AlreadyExists` only *after* replacing the blob would satisfy the error
    // assertion alone while causing exactly the loss this test exists to
    // prevent. The surviving bytes are the property; the error is the report.
    assert_eq!(
        backend.blob_at(PATH).as_deref(),
        Some(winner.as_slice()),
        "the established root's bytes must survive a racing enrolment verbatim"
    );

    assert!(
        matches!(
            outcome,
            Err(SessionError::Keystore(KeystoreError::AlreadyExists(_)))
        ),
        "a racing enrolment must be refused, got {outcome:?}"
    );
}
