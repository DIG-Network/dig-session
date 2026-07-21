# dig-session — normative specification

`dig-session` is the DIG **session / keystore layer**. It composes
[`dig-keystore`] (encrypted secret-key storage) and [`dig-identity`] (canonical
BLS identity derivation) into one curated, custody-safe facade for turning
stored key material into a live signer and injecting a bare signing primitive
into downstream consumers. It performs **no cryptography of its own** — every
cryptographic operation is delegated to those two crates.

This document is normative: an independent reimplementation MUST satisfy every
MUST/MUST NOT below.

## 1. Scope

- **In scope:** unlock an existing key, enroll a new identity, sign, inject a
  signing primitive, and enroll/unlock a master HD seed that exposes the raw seed
  bytes (a primitive) alongside the seed-derived identity key and DEK.
- **Out of scope:** recipient message encryption (seal / decap). That
  composition lives in `dig-message` (same crate level). Implementations of
  `dig-session` MUST NOT add seal/decap; doing so would duplicate a cross-repo
  contract and invite byte-drift.

## 2. Dependencies and layering

- `dig-session` MUST depend only on crates at a strictly lower level:
  `dig-keystore`, `dig-identity`, and `dig-constants` (level 00 foundation), plus
  `chia-bls`, `zeroize`, `hkdf`, `sha2`, and `thiserror`. It MUST NOT depend on
  any same-level (10) or higher crate.
- **`dig-session` MUST NOT depend on `dig-wallet-backend` (a level-20 crate) and
  MUST NOT return a wallet-backend type (e.g. `MasterKey`).** That would be an
  illegal upward `@10 -> @20` edge (CI-lint-forbidden). The master-seed path
  therefore exposes the seed as PRIMITIVE bytes only; the app-tier consumer
  (dig-app) constructs `MasterKey::from_seed_bytes(handle.master_seed())` itself.
- Dependencies MUST be crates.io versions, never `git = …` deps.
- Required published minimums: `dig-keystore >= 0.4`, `dig-identity >= 0.4`,
  `dig-constants >= 0.7`.

## 3. Public API surface

The crate exposes exactly the following curated facade (plus re-exports of the
storage/scheme types a caller needs, so a consumer depends on JUST
`dig-session`):

### 3.1 `Session`

A stateless namespace. All methods are associated functions.

- `Session::unlock::<K: KeyScheme>(backend, path, password) -> Result<UnlockedIdentity<K>>`
  - MUST load the keystore file at `path` via `dig_keystore::Keystore::<K>::load`
    and unlock it with `password` via `Keystore::unlock`, returning the
    resulting `SignerHandle<K>` wrapped in an `UnlockedIdentity<K>`.
  - MUST be generic over the scheme `K`. `L1WalletBls` is used for stored,
    already-derived keys (identity signing key, wallet keys); `BlsSigning` for
    seed-derived validator keys.
  - MUST surface a scheme mismatch, wrong password, missing file, or tampered
    ciphertext as `SessionError::Keystore`.

- `Session::enroll_identity(backend, path, password, seed) -> Result<UnlockedIdentity<L1WalletBls>>`
  - MUST reject empty `seed` with `SessionError::EmptySeed`.
  - MUST derive the identity signing key EXACTLY ONCE, as
    `derive_identity_sk(master_secret_key_from_seed(seed))` — i.e. the hardened
    dig-identity path `m/12381'/8444'/9'/0'`.
  - MUST persist the derived secret key's canonical bytes
    (`chia_bls::SecretKey::to_bytes`) under the **`L1WalletBls`** scheme via
    `dig_keystore::Keystore::create`, so a later `unlock` reconstructs the key
    byte-identically via `chia_bls::SecretKey::from_bytes`.
  - MUST NOT store the derived key under `BlsSigning`. `BlsSigning` treats its
    stored bytes as a *seed* and re-derives via `chia_bls::SecretKey::from_seed`
    on unlock, which would produce a DIFFERENT key (dig_ecosystem #64/#57) whose
    public key does not match the DID-anchored identity key.
  - The returned identity's public key MUST equal
    `dig_identity::public_key_bytes(derive_identity_sk(master_secret_key_from_seed(seed)))`.

- `Session::enroll_master_seed(backend, path, password, seed: &[u8; SEED_LEN]) -> Result<UnlockedMasterSeed>`
  - MUST persist the raw `SEED_LEN`-byte master HD seed verbatim, encrypted under
    `password`, and return it unlocked. Unlike `enroll_identity` (which stores the
    *derived identity scalar* and can never recover the seed), this path stores
    the **seed itself** so a consumer can reconstruct the wallet master key.
  - MUST store the seed under the **`BlsSigning`** scheme used purely as a
    zeroizing 32-byte encrypted byte vault (`expose_secret()` returns the seed
    verbatim); the scheme's own `sign`/`public_key` (which would derive the
    *master* key via `from_seed`) MUST NOT be used — the dig-identity key is
    derived in-crate from the seed.
  - MUST surface a pre-existing file or write failure as `SessionError::Keystore`.

- `Session::unlock_master_seed(backend, path, password) -> Result<UnlockedMasterSeed>`
  - MUST load a file written by `enroll_master_seed` (the `BlsSigning` scheme) and
    unlock it; a scheme mismatch, wrong password, missing file, or tampered
    ciphertext MUST surface as `SessionError::Keystore`.

### 3.2 `UnlockedIdentity<K>`

A live, in-memory identity holding a decrypted `SignerHandle<K>`.

- `public_key(&self) -> &K::PublicKey` — the identity's public key.
- `sign(&self, msg: &[u8]) -> K::Signature` — sign a message.
- `signing_fn(&self) -> SigningFn<K>` — a standalone signing primitive owning
  its own zeroizing copy of the secret; MUST remain usable after the handle is
  dropped.
- `inject_into<T>(&self, consumer: impl FnOnce(SigningFn<K>) -> T) -> T` — hand a
  consumer ONLY a `SigningFn` primitive; the consumer's API MUST NOT mention any
  `dig-session` or `dig-identity` type. This is what keeps a downstream (e.g.
  `dig-wallet-backend`) identity-agnostic (dig_ecosystem #908).

- `derive_symmetric_key(&self, label: &[u8]) -> Zeroizing<[u8; 32]>` — derive a
  per-profile symmetric key (a data-encryption key, "DEK") bound to `label` from
  the unlocked identity. The DEK is returned; the identity scalar MUST NOT leave
  the facade (dig_ecosystem #908 — only the derived key by `label` is exposed).
  - **Construction (frozen, MUST be byte-identical).** The DEK MUST be
    `HKDF-SHA256(salt = "dig-app:dek-salt:v1", IKM = 0x02 || identity_scalar,
    info = label)` expanded to 32 bytes (RFC 5869; `hkdf` 0.12 + `sha2` 0.10):
    - hash: SHA-256;
    - IKM: the byte `0x02` followed by the 32-byte canonical identity scalar
      (`derive_identity_sk(master).to_bytes()`) — i.e. the versioned at-rest
      layout `SEALED_IDENTITY_VERSION || scalar`, NOT the bare scalar;
    - salt: the ASCII bytes `dig-app:dek-salt:v1`;
    - info: `label`, verbatim;
    - output length: 32 bytes.
  - **Source of truth: `dig-constants`.** The salt, IKM version byte, default
    label, and output length above are not local literals — they are the
    `dig-constants` crate's frozen "Profile DEK at-rest byte contract"
    (`DEK_SALT`, `IDENTITY_IKM_VERSION`, `PROFILE_DEK_LABEL`,
    `SYMMETRIC_KEY_LEN`), the single source both this crate and dig-app's
    `dig-app-core/src/keystore/secrets.rs` consume them from (dig_ecosystem
    §4.1/§5.1/NC-5). This crate depends on `dig-constants` from crates.io and
    imports the constants directly rather than redefining them.
  - **Byte-identity invariant (§5.1 at-rest back-compat).** With
    `label = dig_constants::PROFILE_DEK_LABEL` (`b"dig-app:profile-dek:v2"`)
    the result MUST be byte-identical to the DEK dig-app's
    `dig-app-core/src/keystore/secrets.rs` (`dek_password`,
    `seal_data`/`open_data`) already uses to seal every profile blob at rest.
    Any change to the hash, IKM (including the `0x02` version prefix), salt, info
    encoding, or output length would derive a different DEK and make already-sealed
    profile data permanently unreadable, and is therefore FORBIDDEN. Covered by a
    frozen golden vector (C-9, C-10).
  - The DEK and all intermediates MUST be wrapped in `Zeroizing` and wiped on drop.

### 3.3 `UnlockedMasterSeed`

A live, in-memory master HD seed (decrypted) that exposes the raw seed as a
primitive alongside the seed-derived identity key and DEK. Obtained from
`Session::enroll_master_seed` / `Session::unlock_master_seed`. The seed lives in a
`Zeroizing` buffer and is wiped on drop; the type MUST NOT implement `Clone` and
its `Debug` impl MUST redact the seed.

- `SEED_LEN: usize = 32` — the master HD seed length. It equals the byte length
  wallet-backend's `MasterKey::from_seed_bytes` and dig-app's master-seed model
  expect, and the `BlsSigning` storage scheme's secret length.
- `master_seed(&self) -> Zeroizing<[u8; SEED_LEN]>` — the raw master seed bytes,
  a PRIMITIVE. This is the value an app-tier consumer feeds to
  `MasterKey::from_seed_bytes(handle.master_seed())`. It MUST be returned as a
  `Zeroizing` byte array, never a wallet-backend type (see §2 layering).
- `public_key(&self) -> [u8; 48]` — the 48-byte compressed BLS12-381 G1
  dig-identity key derived from the seed. It MUST equal
  `dig_identity::public_key_bytes(derive_identity_sk(master_secret_key_from_seed(seed)))`
  and therefore the 0.2.0 identity path's public key for the same seed.
- `sign(&self, msg: &[u8]) -> [u8; 96]` — sign with the seed-derived identity key;
  the 96-byte G2 signature MUST verify under `public_key()`.
- `signing_fn(&self) -> Arc<dyn Fn(&[u8]) -> [u8; 96] + Send + Sync>` — a
  standalone signing primitive owning its own zeroizing seed copy; MUST remain
  usable after the handle is dropped.
- `derive_symmetric_key(&self, label: &[u8]) -> Zeroizing<[u8; 32]>` — the
  per-profile DEK. It MUST be **byte-identical** to
  `UnlockedIdentity::derive_symmetric_key` (§3.2) for the same underlying identity
  and label: the identity scalar is re-derived from the seed and fed to the SAME
  frozen HKDF construction. This preserves §5.1 at-rest back-compat when a
  consumer migrates from the identity-scalar path to the master-seed path.

#### 3.3.1 Per-profile methods (0.4.0, ADDITIVE)

The master-seed handle additionally exposes per-profile identity operations
derived from the SAME master seed at the hardened path
`m/12381'/8444'/9'/{profile_ix}'` via `dig_identity::derive_identity_sk_at`
(dig-identity 0.5.0). These are a pure additive generalization of the default
methods (§5.1): the default methods ARE profile 0.

- `profile_public_key(&self, profile_ix: u32) -> [u8; 48]` — the 48-byte
  compressed BLS12-381 G1 identity key for `profile_ix`. It MUST equal
  `dig_identity::public_key_bytes(derive_identity_sk_at(master_secret_key_from_seed(seed), profile_ix))`.
- `profile_sign(&self, profile_ix: u32, msg: &[u8]) -> [u8; 96]` — sign with
  `profile_ix`'s derived key; the signature MUST verify under
  `profile_public_key(profile_ix)`.
- `profile_derive_symmetric_key(&self, profile_ix: u32, label: &[u8]) -> Zeroizing<[u8; 32]>`
  — `profile_ix`'s per-profile DEK. The profile scalar is derived via
  `derive_identity_sk_at` and fed to the SAME frozen HKDF construction
  (`derive_symmetric_key_from_scalar`) — the HKDF is NOT duplicated.

**`profile_ix == 0` byte-identity invariant (MUST, §5.1).** Because
`derive_identity_sk_at(master, 0) == derive_identity_sk(master)`, for every seed,
message, and label:
`profile_public_key(0) == public_key()`,
`profile_sign(0, msg) == sign(msg)`, and
`profile_derive_symmetric_key(0, label) == derive_symmetric_key(label)` —
byte-for-byte. Each distinct `profile_ix` yields a distinct, deterministic key
and DEK.

### 3.4 `SigningFn<K>`

`Arc<dyn Fn(&[u8]) -> K::Signature + Send + Sync>` — the injected primitive.

### 3.5 `SessionError` / `Result<T>`

- `SessionError::Keystore(dig_keystore::KeystoreError)` — transparent wrap.
- `SessionError::EmptySeed` — enrollment given empty seed material.

## 4. Custody invariants (MUST)

- **Secret zeroization.** An `UnlockedIdentity` holds its secret inside the
  wrapped `SignerHandle`'s `Zeroizing` buffer; the secret MUST be wiped when the
  handle (and any injected `SigningFn` copy) is dropped.
- **Enrollment-derivation hygiene.** During `enroll_identity`, every secret byte
  buffer the crate OWNS (the derived key's canonical bytes and the transient
  32-byte `to_bytes()` extraction) MUST be wrapped in `Zeroizing` so it is wiped
  on drop. The transient `chia_bls::SecretKey` scalars returned by dig-identity's
  derivation are a foreign type with no `Zeroize`/`Drop` impl (true even at the
  latest chia-bls 0.46) and cannot be wiped in place; they MUST instead be
  confined to the narrowest scope and dropped immediately after byte extraction.
  Fully wiping those scalars is RELIED UPON from upstream (tracked: request
  `Zeroize` on `chia_bls::SecretKey`), not delivered by this crate.
- **No secret in debug output.** `UnlockedIdentity` MUST NOT derive `Debug`; its
  `Debug` impl MUST redact the secret. It MUST NOT implement `Clone`.
- **No IPC crossing.** An `UnlockedIdentity` MUST NOT cross an IPC boundary; it
  belongs solely to the user-app process that owns the identity (dig_ecosystem
  #908). Downstreams receive a `SigningFn`, never the handle.
- **No unsafe.** The crate MUST forbid `unsafe` code (`#![forbid(unsafe_code)]`).

## 5. Conformance tests

An implementation MUST ship tests proving:

- `enroll_identity` then `unlock` reconstruct the same public key. (C-1)
- The enrolled public key equals the dig-identity canonical key — the regression
  guarding against a revert to `BlsSigning`/`from_seed`. (C-2)
- A produced signature verifies against the public key via `chia_bls::verify`. (C-3)
- An injected `SigningFn` still signs after the handle is dropped. (C-4)
- Unlock with the wrong password fails with `SessionError::Keystore`. (C-5)
- Enroll with empty seed fails with `SessionError::EmptySeed`. (C-6)
- `unlock` works generically for `BlsSigning`. (C-7)
- `Debug` output contains no secret material. (C-8)
- `derive_symmetric_key(b"dig-app:profile-dek:v2")` is byte-identical to dig-app's
  independently-reconstructed profile DEK for the same identity scalar. (C-9)
- `derive_symmetric_key` matches a frozen golden vector (fixed scalar + fixed
  label → exact DEK bytes); distinct labels derive distinct keys and the same
  label is deterministic. (C-10)

The master-seed path (§3.3) additionally MUST prove:

- `master_seed()` returns exactly the enrolled `SEED_LEN` seed bytes. (MS-1)
- The seed-derived public key equals the dig-identity canonical key AND the
  identity-scalar path's public key for the same seed. (MS-2)
- `derive_symmetric_key` on the master-seed path is byte-identical to the
  identity-scalar path (and to dig-app's reference DEK) for the same seed and
  label, incl. a frozen golden vector. (MS-3)
- A produced signature verifies against `public_key()`. (MS-4)
- An injected signing primitive still signs after the handle is dropped. (MS-5)
- `enroll_master_seed` then `unlock_master_seed` reproduce the same seed and key. (MS-6)
- `unlock_master_seed` with the wrong password fails with `SessionError::Keystore`. (MS-7)
- `Debug` output contains no seed material. (MS-8)

The per-profile methods (§3.3.1, 0.4.0) additionally MUST prove:

- `profile_public_key(0) == public_key()`, `profile_sign(0, m) == sign(m)`, and
  `profile_derive_symmetric_key(0, label) == derive_symmetric_key(label)`,
  byte-for-byte. (PROF-1, PROF-2, PROF-3)
- `profile_public_key(profile_ix)` equals dig-identity's canonical
  `public_key_bytes(derive_identity_sk_at(master, profile_ix))`. (PROF-4)
- A non-zero profile is distinct from profile 0 and deterministic across handles
  for the same seed. (PROF-5)
- A profile signature verifies under that profile's public key and NOT under
  another profile's. (PROF-6)
- A frozen golden vector for a non-zero profile (fixed seed + profile 1 + fixed
  label → exact DEK bytes over `derive_identity_sk_at`). (PROF-7)

[`dig-keystore`]: https://crates.io/crates/dig-keystore
[`dig-identity`]: https://crates.io/crates/dig-identity
