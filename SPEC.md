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

- **In scope (first cut):** unlock an existing key, enroll a new identity, sign,
  and inject a signing primitive.
- **Out of scope:** recipient message encryption (seal / decap). That
  composition lives in `dig-message` (same crate level). Implementations of
  `dig-session` MUST NOT add seal/decap; doing so would duplicate a cross-repo
  contract and invite byte-drift.

## 2. Dependencies and layering

- `dig-session` MUST depend only on crates at a strictly lower level:
  `dig-keystore` and `dig-identity` (both level 00 foundation), plus `chia-bls`,
  `zeroize`, and `thiserror`. It MUST NOT depend on any level-10 crate.
- Dependencies MUST be crates.io versions, never `git = …` deps.
- Required published minimums: `dig-keystore >= 0.4`, `dig-identity >= 0.4`.

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

### 3.3 `SigningFn<K>`

`Arc<dyn Fn(&[u8]) -> K::Signature + Send + Sync>` — the injected primitive.

### 3.4 `SessionError` / `Result<T>`

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

[`dig-keystore`]: https://crates.io/crates/dig-keystore
[`dig-identity`]: https://crates.io/crates/dig-identity
