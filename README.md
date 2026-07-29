# dig-session

The DIG **session / keystore layer**: a small, custody-safe facade that turns
stored, encrypted key material into a live signer and injects a bare signing
primitive into downstream consumers.

It composes two lower-level crates and adds **no cryptography of its own**:

- [`dig-keystore`](https://crates.io/crates/dig-keystore) — encrypted,
  per-scheme secret-key storage (`Keystore::<K>::load -> unlock -> SignerHandle`).
- [`dig-identity`](https://crates.io/crates/dig-identity) — the canonical DIG BLS
  identity derivation (`m/12381'/8444'/9'/0'`).

## Install

```toml
[dependencies]
dig-session = "0.1"
```

## Use

```rust,no_run
use std::sync::Arc;
use dig_session::{Session, FileBackend, BackendKey, Password};

# fn main() -> dig_session::Result<()> {
let backend = Arc::new(FileBackend::new("/var/lib/dig/keys"));

// Enroll a new identity from BIP-39 seed bytes (derives the canonical
// dig-identity signing key and stores it encrypted).
let identity = Session::enroll_identity(
    backend.clone(),
    BackendKey::new("identity"),
    Password::from("correct horse battery staple"),
    b"seed bytes",
)?;

// Sign directly...
let _sig = identity.sign(b"message");

// ...or hand a downstream a bare signing primitive — it never sees a session type.
let sign = identity.signing_fn();
let _sig = sign(b"message");

// Reopen later.
let identity = Session::unlock::<dig_session::L1WalletBls>(
    backend,
    BackendKey::new("identity"),
    Password::from("correct horse battery staple"),
)?;
# let _ = identity;
# Ok(())
# }
```

## Accounts: one root, a portable recovery phrase

An account's root is 32 bytes of **BIP-39 entropy**. Every derivation — identity,
per-profile DEK, wallet — reads the seed EXPANDED from it
(`entropy -> 24 words -> to_seed("")`), which is the standard Chia derivation, so
a DIG recovery phrase restores the same addresses in Sage and any other
conforming wallet.

```rust,no_run
use std::sync::Arc;
use dig_session::{Session, FileBackend, BackendKey, Password, ENTROPY_LEN};

# fn main() -> dig_session::Result<()> {
let backend = Arc::new(FileBackend::new("/var/lib/dig/keys"));
let path = BackendKey::new("account");
let password = Password::from("correct horse battery staple");

// Create: any 32 CSPRNG bytes are valid BIP-39 entropy.
let entropy = [0u8; ENTROPY_LEN]; // in production: fill from `OsRng`
let account = Session::enroll_master_seed(backend.clone(), path.clone(), password, &entropy)?;

// Show the user their 24 words — this does NOT consume the handle.
let phrase = account.recovery_phrase();

// The expanded 64-byte seed goes to wallet-backend's `MasterKey::from_seed_bytes`.
let seed = account.master_seed();

// Restore on another machine.
let restored = Session::enroll_from_recovery_phrase(
    backend,
    BackendKey::new("account-2"),
    Password::from("correct horse battery staple"),
    &phrase,
)?;
# let _ = (seed, restored);
# Ok(())
# }
```

A blob written before the versioned seed envelope held a *raw* seed rather than
entropy. Because the two are byte-indistinguishable, `unlock_master_seed` fails
closed with `SessionError::LegacySeedFormat` instead of reinterpreting them —
silently deriving a plausible wrong wallet would be far worse than an error.

## Design notes

- **No seal / decap.** Recipient message encryption belongs to `dig-message`,
  not here.
- **Identity keys are stored with `L1WalletBls`, not `BlsSigning`.** The identity
  key is already derived by dig-identity; storage must round-trip it via
  `from_bytes`. `BlsSigning` would re-derive via `from_seed` and yield a
  different key (the dig_ecosystem #64/#57 pitfall).
- **Custody-safe.** `UnlockedIdentity` zeroizes its secret on drop, never
  `Debug`-prints key material, and must never cross an IPC boundary.

See [`SPEC.md`](./SPEC.md) for the normative contract.

## License

GPL-2.0-only.
