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
