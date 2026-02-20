use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::store::notes::AppConfig;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum CryptoError {
    Encrypt,
    Decrypt,
    BadWrappedKeyLen,
    ConfigTampered,
    Kdf,
    Dpapi,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypt => write!(f, "AES-GCM encryption failed"),
            Self::Decrypt => write!(f, "AES-GCM decryption failed — wrong key or corrupted data"),
            Self::BadWrappedKeyLen => write!(f, "Wrapped key has invalid length"),
            Self::ConfigTampered => write!(f, "Config HMAC verification failed — file may be tampered"),
            Self::Kdf => write!(f, "Key derivation failed"),
            Self::Dpapi => write!(f, "Windows DPAPI operation failed — check Windows user account"),
        }
    }
}

impl std::error::Error for CryptoError {}

// ---------------------------------------------------------------------------
// MasterKey — 32 bytes, secret, locked in RAM with VirtualLock
// ---------------------------------------------------------------------------

/// Holds a 32-byte AES-256 master key.
/// The memory page is locked via `VirtualLock` to prevent swap exposure.
/// Zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct MasterKey {
    #[zeroize(skip)] // zeroized manually below
    inner: Box<[u8; 32]>,
}

impl MasterKey {
    /// Create a new MasterKey from raw mutable bytes.
    /// VULN-C5 FIX: The source bytes are zeroized inside this function after
    /// copying into the heap-allocated box, so callers never need to zeroize.
    pub fn new(bytes: &mut [u8; 32]) -> Self {
        let mk = Self {
            inner: Box::new(*bytes),
        };
        bytes.zeroize(); // zeroize caller's stack copy immediately
        let mut mk = mk;
        mk.lock_memory();
        mk
    }

    /// Generate a fresh random MasterKey.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self::new(&mut bytes) // bytes is zeroized inside new()
    }

    /// Call VirtualLock on the heap page containing the key bytes.
    /// VULN-C6 FIX: Logs a warning if VirtualLock fails — key is still
    /// zeroized on drop, but may be swapped.
    fn lock_memory(&mut self) {
        #[cfg(target_os = "windows")]
        unsafe {
            use windows::Win32::System::Memory::VirtualLock;
            let ptr = self.inner.as_mut_ptr() as *mut core::ffi::c_void;
            if VirtualLock(ptr, 32).is_err() {
                // Non-fatal: key will still be zeroized on drop, but the OS
                // may write this page to the pagefile while unlocked.
                eprintln!("[WARN] VirtualLock failed — MasterKey page may be swappable");
            }
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.inner
    }
}

impl Zeroize for MasterKey {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Key wrapping — AES-256-GCM encrypt/decrypt a 32-byte key
// Wire format: nonce(12) || ciphertext(32) || tag(16) = 60 bytes total
//
// VULN-C1 FIX: All wrapping operations now accept an `aad: &[u8]` context
// label. This cryptographically binds each ciphertext to its intended role
// (e.g. "winhello-mk", "recovery-mk", note UUID) so ciphertexts cannot be
// transplanted between fields or notes without detection.
// ---------------------------------------------------------------------------

const NONCE_LEN: usize = 12;
pub const WRAPPED_LEN: usize = NONCE_LEN + 32 + 16; // 60

// Purpose labels — callers must use the correct label or decryption fails.
pub const AAD_WINHELLO_MK:  &[u8] = b"secure-notes-v2:winhello-mk";
pub const AAD_RECOVERY_MK:  &[u8] = b"secure-notes-v2:recovery-mk";

/// Wrap (encrypt) a 32-byte key under `mk`, binding it to `aad`.
/// Uses a fresh random nonce from OsRng — never reuses.
pub fn wrap_key(mk: &MasterKey, plaintext_key: &[u8; 32], aad: &[u8]) -> Vec<u8> {
    let aes_key = Key::<Aes256Gcm>::from_slice(mk.as_bytes());
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let payload = Payload { msg: plaintext_key.as_ref(), aad };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .expect("AES-GCM encryption must not fail on valid key/nonce");
    let mut out = Vec::with_capacity(WRAPPED_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Unwrap (decrypt) a wrapped key. Returns a MasterKey with memory locked.
/// VULN-C2 FIX: The intermediate plaintext Vec is zeroized before being
/// dropped so key bytes do not linger on the heap.
pub fn unwrap_key(mk: &MasterKey, wrapped: &[u8], aad: &[u8]) -> Result<MasterKey, CryptoError> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(CryptoError::BadWrappedKeyLen);
    }
    let nonce = Nonce::from_slice(&wrapped[..NONCE_LEN]);
    let aes_key = Key::<Aes256Gcm>::from_slice(mk.as_bytes());
    let cipher = Aes256Gcm::new(aes_key);
    let payload = Payload { msg: &wrapped[NONCE_LEN..], aad };
    let mut plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::Decrypt)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&plaintext);
    plaintext.zeroize(); // VULN-C2: zeroize heap copy
    Ok(MasterKey::new(&mut arr)) // arr is zeroized inside new()
}

// ---------------------------------------------------------------------------
// Argon2id key derivation for the recovery path (VULN-L5 FIX)
//
// Replaces HKDF-SHA256. Argon2id is memory-hard: ~64 MB RAM, 3 iterations.
// Each trial takes ~100 ms on a single core, making offline brute-force of
// a partially-observed mnemonic infeasible.
// ---------------------------------------------------------------------------

/// Derive a 32-byte MKEK from BIP-39 entropy + salt using Argon2id.
/// `salt` must be at least 8 bytes (the 32-byte recovery_salt satisfies this).
pub fn derive_mkek(input: &[u8], salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    // 64 MB memory, 3 iterations, 1 lane — OWASP recommended minimum
    let params = Params::new(65536, 3, 1, Some(32))
        .map_err(|_| CryptoError::Kdf)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut okm = [0u8; 32];
    argon2
        .hash_password_into(input, salt, &mut okm)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(okm)
}

// ---------------------------------------------------------------------------
// Config HMAC — HMAC-SHA256(MK, canonical_config_bytes)
// Protects config.json against offline tampering.
//
// VULN-X2 FIX: Uses a deterministic struct-based serialization (field order
// is fixed by declaration order) rather than serde_json::json! which depends
// on internal Map ordering that could change with feature flags.
// ---------------------------------------------------------------------------

/// Deterministic serialization of the config fields covered by the HMAC.
/// Fields are in lexicographic order to ensure stability across Rust/serde versions.
fn canonical_config_bytes(cfg: &AppConfig) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Canonical<'a> {
        // Sorted lexicographically by field name:
        recovery_salt: &'a [u8],
        recovery_wrapped_mk: &'a [u8],
        vault_version: u64,
        winhello_dpapi_blob: &'a [u8],
        winhello_key_id: &'a str,
        winhello_wrapped_mk: &'a [u8],
    }
    let c = Canonical {
        recovery_salt: &cfg.recovery_salt,
        recovery_wrapped_mk: &cfg.recovery_wrapped_mk,
        vault_version: cfg.vault_version,
        winhello_dpapi_blob: &cfg.winhello_dpapi_blob,
        winhello_key_id: &cfg.winhello_key_id,
        winhello_wrapped_mk: &cfg.winhello_wrapped_mk,
    };
    serde_json::to_vec(&c).expect("canonical config serialization must not fail")
}

/// Compute HMAC-SHA256(MK, canonical_config_bytes) and store into `cfg.config_hmac`.
pub fn compute_config_hmac(mk: &MasterKey, cfg: &mut AppConfig) {
    let msg = canonical_config_bytes(cfg);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(mk.as_bytes())
        .expect("HMAC accepts any key size");
    mac.update(&msg);
    cfg.config_hmac = mac.finalize().into_bytes().to_vec();
}

/// Verify that `cfg.config_hmac` matches the expected HMAC.
/// Returns `Err(CryptoError::ConfigTampered)` on mismatch.
pub fn verify_config_hmac(mk: &MasterKey, cfg: &AppConfig) -> Result<(), CryptoError> {
    let msg = canonical_config_bytes(cfg);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(mk.as_bytes())
        .expect("HMAC accepts any key size");
    mac.update(&msg);
    mac.verify_slice(&cfg.config_hmac)
        .map_err(|_| CryptoError::ConfigTampered)
}

// ---------------------------------------------------------------------------
// Windows DPAPI — protects a key with the current Windows user's account key.
// The blob is user+machine scoped: only the same user on this machine can
// decrypt it, even with full access to the config file.
// ---------------------------------------------------------------------------

/// Encrypt `data` with Windows DPAPI (user-account scope, not machine scope).
pub fn dpapi_protect(data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use std::ptr;
    use windows::{
        Win32::Foundation::{HLOCAL, LocalFree},
        Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB},
        core::PCWSTR,
    };
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    unsafe {
        CryptProtectData(
            &in_blob,
            PCWSTR(ptr::null()),
            None,
            None,
            None,
            0u32,
            &mut out_blob,
        )
        .map_err(|_| CryptoError::Dpapi)?;
        let result = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        LocalFree(HLOCAL(out_blob.pbData.cast()));
        Ok(result)
    }
}

/// Decrypt a DPAPI blob created by [`dpapi_protect`].
/// Fails if called from a different Windows user account or after OS reinstall.
pub fn dpapi_unprotect(blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    use std::ptr;
    use windows::{
        Win32::Foundation::{HLOCAL, LocalFree},
        Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB},
    };
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    unsafe {
        CryptUnprotectData(
            &in_blob,
            None,
            None,
            None,
            None,
            0u32,
            &mut out_blob,
        )
        .map_err(|_| CryptoError::Dpapi)?;
        let result = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        LocalFree(HLOCAL(out_blob.pbData.cast()));
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_key_length_is_60_bytes() {
        let mk = MasterKey::generate();
        let inner = MasterKey::generate();
        let wrapped = wrap_key(&mk, inner.as_bytes(), AAD_WINHELLO_MK);
        assert_eq!(wrapped.len(), WRAPPED_LEN);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let mk = MasterKey::generate();
        let inner = MasterKey::generate();
        let wrapped = wrap_key(&mk, inner.as_bytes(), AAD_WINHELLO_MK);
        let recovered = unwrap_key(&mk, &wrapped, AAD_WINHELLO_MK).expect("unwrap must succeed");
        assert_eq!(recovered.as_bytes(), inner.as_bytes());
    }

    #[test]
    fn unwrap_with_wrong_key_fails() {
        let mk1 = MasterKey::generate();
        let mk2 = MasterKey::generate();
        let inner = MasterKey::generate();
        let wrapped = wrap_key(&mk1, inner.as_bytes(), AAD_WINHELLO_MK);
        assert!(unwrap_key(&mk2, &wrapped, AAD_WINHELLO_MK).is_err());
    }

    /// Diagnostic test: reads the live config.json from %APPDATA%\SecureNotes
    /// and verifies that DPAPI can decrypt the stored MKEK, then uses it to
    /// unwrap winhello_wrapped_mk.  Run with:
    ///   cargo test dpapi_roundtrip_live -- --nocapture --ignored
    #[test]
    #[ignore]
    fn dpapi_roundtrip_live() {
        use std::env;

        let appdata = env::var("APPDATA").expect("APPDATA must be set");
        let config_path = std::path::Path::new(&appdata)
            .join("SecureNotes")
            .join("config.json");

        println!("Reading config from: {}", config_path.display());
        let raw = std::fs::read(&config_path).expect("cannot read config.json");
        let config: crate::store::notes::AppConfig =
            serde_json::from_slice(&raw).expect("cannot parse config.json");

        println!(
            "winhello_dpapi_blob: {} bytes, winhello_wrapped_mk: {} bytes",
            config.winhello_dpapi_blob.len(),
            config.winhello_wrapped_mk.len()
        );

        let mut mkek_vec = dpapi_unprotect(&config.winhello_dpapi_blob)
            .expect("DPAPI failed — blob may have been created under a different user/context");

        println!("DPAPI returned {} bytes", mkek_vec.len());
        println!("First 4 MKEK bytes (should be non-zero): {:?}", &mkek_vec[..4.min(mkek_vec.len())]);

        assert_eq!(mkek_vec.len(), 32, "MKEK must be 32 bytes — got {}", mkek_vec.len());

        // Check for all-zero MKEK (indicates setup bug where dpapi_protect was
        // called on already-zeroized bytes)
        let all_zero = mkek_vec.iter().all(|&b| b == 0);
        if all_zero {
            panic!(
                "DPAPI returned 32 all-zero bytes — the DPAPI blob was created from zeroized memory. \
                 This is the setup bug: MasterKey::new() zeroized mkek_bytes before dpapi_protect ran. \
                 Fix: FIX THE SETUP CODE ORDER, then clear config.json and re-setup."
            );
        }

        let mut mkek_bytes = [0u8; 32];
        mkek_bytes.copy_from_slice(&mkek_vec);
        mkek_vec.zeroize();
        let mkek = MasterKey::new(&mut mkek_bytes);

        match unwrap_key(&mkek, &config.winhello_wrapped_mk, AAD_WINHELLO_MK) {
            Ok(_) => println!("SUCCESS: unwrap_key passed — Windows Hello unlock should work"),
            Err(e) => panic!(
                "FAILED: unwrap_key error: {e}\n\
                 The MKEK from DPAPI ({} bytes) does not decrypt winhello_wrapped_mk.\n\
                 This means the DPAPI master key has changed since setup.\n\
                 Fix: use the 24-word recovery key to unlock, which will re-enroll Windows Hello.",
                config.winhello_wrapped_mk.len()
            ),
        }
    }

    // ── AAD binding: security regression tests ─────────────────────────────
    //
    // These tests exist to catch any future refactor that accidentally removes
    // AAD from an AES-GCM call.  If AAD is stripped, these tests MUST explode.
    //
    // Threat: attacker swaps a WinHello-wrapped MK blob for a Recovery-wrapped
    // one (or vice-versa) hoping a role-confusion bypass will decrypt it.
    // With AAD bound to role names, the GCM tag verification fails immediately.

    #[test]
    fn winhello_ciphertext_rejected_under_recovery_aad() {
        // Wrap a key under the WinHello AAD ...
        let mk = MasterKey::generate();
        let inner = MasterKey::generate();
        let wrapped = wrap_key(&mk, inner.as_bytes(), AAD_WINHELLO_MK);
        // ... then attempt to open it as if it were a Recovery-wrapped key.
        assert!(
            unwrap_key(&mk, &wrapped, AAD_RECOVERY_MK).is_err(),
            "WinHello ciphertext must be rejected when presented with Recovery AAD \
             — AAD binding is missing or wrong"
        );
    }

    #[test]
    fn recovery_ciphertext_rejected_under_winhello_aad() {
        // Symmetric of the above: Recovery-wrapped key cannot be opened via
        // the WinHello path even when the master key is identical.
        let mk = MasterKey::generate();
        let inner = MasterKey::generate();
        let wrapped = wrap_key(&mk, inner.as_bytes(), AAD_RECOVERY_MK);
        assert!(
            unwrap_key(&mk, &wrapped, AAD_WINHELLO_MK).is_err(),
            "Recovery ciphertext must be rejected when presented with WinHello AAD \
             — AAD binding is missing or wrong"
        );
    }

    #[test]
    fn config_hmac_tamper_detection() {
        use crate::store::notes::AppConfig;
        let mk = MasterKey::generate();
        let mut cfg = AppConfig {
            winhello_key_id: "test-key".into(),
            winhello_dpapi_blob: vec![0u8; 32],
            winhello_wrapped_mk: vec![0u8; WRAPPED_LEN],
            recovery_salt: vec![0u8; 32],
            recovery_wrapped_mk: vec![0u8; WRAPPED_LEN],
            vault_version: 1,
            config_hmac: vec![],
        };
        compute_config_hmac(&mk, &mut cfg);
        verify_config_hmac(&mk, &cfg).expect("HMAC must verify on untampered config");
        cfg.winhello_wrapped_mk[0] ^= 0xFF;
        assert!(verify_config_hmac(&mk, &cfg).is_err(), "HMAC must fail on tampered config");
    }

    #[test]
    fn two_wraps_produce_different_nonces() {
        let mk = MasterKey::generate();
        let inner = MasterKey::generate();
        let w1 = wrap_key(&mk, inner.as_bytes(), AAD_WINHELLO_MK);
        let w2 = wrap_key(&mk, inner.as_bytes(), AAD_WINHELLO_MK);
        assert_ne!(&w1[..NONCE_LEN], &w2[..NONCE_LEN], "nonce reuse detected!");
    }
}
