# SecNote — Secure Offline Note-Taking App

A fully offline, encrypted note-taking application for Windows with hardware-backed authentication.

[![CI](https://github.com/adikul1023/secnote/actions/workflows/ci.yml/badge.svg)](https://github.com/adikul1023/secnote/actions/workflows/ci.yml)

---

## Features

- **AES-256-GCM encryption** — every note is encrypted with its own key; the vault is encrypted with a master key
- **Windows Hello (TPM) authentication** — no password to remember; biometrics or PIN via the TPM
- **24-word BIP-39 recovery key** — printed on paper for PIN-change or Hello reset scenarios
- **Per-note AAD binding** — each note's ciphertext is cryptographically bound to its UUID; blobs cannot be swapped between notes
- **Argon2id KDF** — 64 MB / 3 iterations for recovery key derivation; GPU brute-force infeasible
- **Atomic saves** — `notes.enc` and `config.json` are written via temp-file + rename; crash-safe
- **Config HMAC-SHA256 integrity** — tamper detection with constant-time comparison
- **Memory locking** — master key page locked via `VirtualLock`; zeroized on drop
- **Auto-lock on idle** — configurable timeout (default 5 min)
- **Vault rollback detection** — monotonic `vault_version` counter protected by HMAC
- **Rate-limited recovery** — exponential backoff (2 s → 60 s) with 10-attempt hard limit

---

## Security Properties

| Property | Implementation |
|---|---|
| Encryption | AES-256-GCM with random 96-bit nonces |
| Key wrapping | AES-256-GCM + AAD role binding |
| Recovery KDF | Argon2id (64 MB, 3 iter, 1 lane) |
| Config integrity | HMAC-SHA256, canonical struct encoding, constant-time verify |
| Memory safety | `zeroize` + `ZeroizeOnDrop` on all key material |
| Auth | Windows Hello (TPM-backed) |
| Save atomicity | `tempfile` in same directory + `persist()` rename |
| Directory safety | Reparse point / symlink detection on data dir and save dir |

**Not protected against:** same-user malware, admin/SYSTEM memory dumps while unlocked, or nation-state memory scraping. This is a local-data threat model.

---

## Requirements

- Windows 10 / 11 (Windows Hello required)
- Rust stable toolchain (`rustup default stable`)

---

## Build

```powershell
git clone https://github.com/adikul1023/secnote.git
cd secnote
cargo build --release
# Binary at: target\release\secure-notes.exe
```

---

## Running Tests

```powershell
cargo test
```

---

## Security Audit

A full adversarial red-team audit was conducted covering 23 vulnerabilities across cryptographic design, storage, memory safety, and logic. All findings have been remediated.

See [VULNERABILITIES.md](VULNERABILITIES.md) for the full report including fix details.

---

## CI

Every push runs:

- `cargo audit` — known CVE check via RustSec
- `cargo deny` — license and source policy
- `cargo clippy -- -D warnings` — lints as hard errors
- `cargo test` — unit tests (AAD binding, nonce uniqueness, HMAC tamper detection, vault size limits)

---

## License

MIT — see [LICENSE](LICENSE)
