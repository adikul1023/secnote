use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use zeroize::Zeroize;

use crate::crypto::keys::{unwrap_key, wrap_key, CryptoError, MasterKey};
use crate::store::notes::NotesStore;

const NONCE_LEN: usize = 12;

// ---------------------------------------------------------------------------
// Maximum vault size — defends against allocation-based DoS (VULN-D1).
// A 128 MB limit is astronomically generous for a note-taking app.
// ---------------------------------------------------------------------------
const MAX_VAULT_BYTES: usize = 128 * 1024 * 1024; // 128 MB

// ---------------------------------------------------------------------------
// AAD for the outer vault ciphertext (VULN-C1 FIX)
// This binds the outer notes.enc blob to its role so it cannot be confused
// with a per-note ciphertext even if an attacker swaps files.
// ---------------------------------------------------------------------------
const AAD_OUTER_VAULT: &[u8] = b"secure-notes-v2:outer-vault";

// ---------------------------------------------------------------------------
// Encrypt / decrypt the entire NotesStore
// Wire format: nonce(12) || ciphertext || tag(16)
// ---------------------------------------------------------------------------

/// Serialize `store` to JSON, then AES-256-GCM encrypt with a fresh OsRng nonce.
/// VULN-C1 FIX: Uses outer vault AAD to bind ciphertext to its purpose.
/// VULN-C3 FIX: The intermediate plaintext Vec is zeroized before drop.
/// Returns `nonce(12) || ciphertext || tag(16)`.
pub fn encrypt_store(mk: &MasterKey, store: &NotesStore) -> Result<Vec<u8>, CryptoError> {
    let mut plaintext = serde_json::to_vec(store)
        .map_err(|_| CryptoError::Encrypt)?;

    let aes_key = Key::<Aes256Gcm>::from_slice(mk.as_bytes());
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let payload = Payload { msg: plaintext.as_ref(), aad: AAD_OUTER_VAULT };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| { plaintext.zeroize(); CryptoError::Encrypt })?;

    plaintext.zeroize(); // VULN-C3: do not leave plaintext on heap

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// AES-256-GCM decrypt `data` (format: nonce(12) || ciphertext || tag(16))
/// and deserialise the result into a `NotesStore`.
/// VULN-C1 FIX: Verifies outer vault AAD.
/// VULN-C3 FIX: Zeroizes intermediate plaintext.
/// VULN-D1 FIX: Rejects blobs larger than MAX_VAULT_BYTES.
pub fn decrypt_store(mk: &MasterKey, data: &[u8]) -> Result<NotesStore, CryptoError> {
    // VULN-D1: cap before any allocation
    if data.len() > MAX_VAULT_BYTES {
        return Err(CryptoError::Decrypt);
    }
    if data.len() < NONCE_LEN + 16 {
        return Err(CryptoError::Decrypt);
    }
    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let aes_key = Key::<Aes256Gcm>::from_slice(mk.as_bytes());
    let cipher = Aes256Gcm::new(aes_key);
    let payload = Payload { msg: &data[NONCE_LEN..], aad: AAD_OUTER_VAULT };
    let mut plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::Decrypt)?;

    let result = serde_json::from_slice(&plaintext).map_err(|_| CryptoError::Decrypt);
    plaintext.zeroize(); // VULN-C3: zeroize regardless of parse success/failure
    result
}

// ---------------------------------------------------------------------------
// Per-note encryption helpers
// Each note has its own 32-byte AES-256-GCM key, wrapped under the master key.
// Only the currently-viewed note's body exists in plaintext in memory.
//
// VULN-C1 FIX: The note UUID is passed as AAD for both wrap_key and
// encrypt_note_body.
// - `wrap_key(mk, note_key, note_uuid_bytes)` binds the wrapped key to this note.
// - `encrypt_note_body(nk, body, note_uuid_bytes)` binds the body ciphertext to the note.
// This prevents an attacker from swapping note_key_wrapped or body_enc between
// notes (or between different vaults) without detection.
// ---------------------------------------------------------------------------

/// Generate a fresh per-note key and wrap it under `mk`, bound to `note_id_aad`.
/// `note_id_aad` should be the note's UUID bytes (16 bytes from `Uuid::as_bytes()`).
/// Returns `(note_key, wrapped_bytes)`.
pub fn new_note_key(mk: &MasterKey, note_id_aad: &[u8]) -> (MasterKey, Vec<u8>) {
    let note_key = MasterKey::generate();
    let wrapped = wrap_key(mk, note_key.as_bytes(), note_id_aad);
    (note_key, wrapped)
}

/// Unwrap a per-note key previously created by [`new_note_key`].
/// Must pass the same `note_id_aad` that was used when wrapping.
pub fn unwrap_note_key(mk: &MasterKey, wrapped: &[u8], note_id_aad: &[u8]) -> Result<MasterKey, CryptoError> {
    unwrap_key(mk, wrapped, note_id_aad)
}

/// AES-256-GCM encrypt raw bytes, using `aad` to bind the ciphertext to context.
/// Wire format: nonce(12) || ciphertext || tag(16).
fn encrypt_bytes(mk: &MasterKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let aes_key = Key::<Aes256Gcm>::from_slice(mk.as_bytes());
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let payload = Payload { msg: plaintext, aad };
    let ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| CryptoError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// AES-256-GCM decrypt raw bytes.
fn decrypt_bytes(mk: &MasterKey, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < NONCE_LEN + 16 {
        return Err(CryptoError::Decrypt);
    }
    let nonce = Nonce::from_slice(&data[..NONCE_LEN]);
    let aes_key = Key::<Aes256Gcm>::from_slice(mk.as_bytes());
    let cipher = Aes256Gcm::new(aes_key);
    let payload = Payload { msg: &data[NONCE_LEN..], aad };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::Decrypt)
}

/// Encrypt a note body string under a per-note key, binding it to `note_id_aad`.
pub fn encrypt_note_body(note_key: &MasterKey, body: &str, note_id_aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encrypt_bytes(note_key, body.as_bytes(), note_id_aad)
}

/// Decrypt a note body ciphertext under a per-note key.
/// Must pass the same `note_id_aad` used when encrypting.
/// Returns an empty string for an empty ciphertext (new note).
pub fn decrypt_note_body(note_key: &MasterKey, ciphertext: &[u8], note_id_aad: &[u8]) -> Result<String, CryptoError> {
    if ciphertext.is_empty() {
        return Ok(String::new());
    }
    let bytes = decrypt_bytes(note_key, ciphertext, note_id_aad)?;
    String::from_utf8(bytes).map_err(|_| CryptoError::Decrypt)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::notes::{Note, NotesStore};

    const TEST_AAD: &[u8] = b"test-note-uuid-aad";

    #[test]
    fn encrypt_decrypt_store_roundtrip() {
        let mk = MasterKey::generate();
        let mut store = NotesStore::new();
        let mut note = Note::new(None);
        let (nk, wrapped) = new_note_key(&mk, TEST_AAD);
        note.note_key_wrapped = wrapped;
        note.body_enc = encrypt_note_body(&nk, "Hello, secret world!", TEST_AAD).unwrap();
        store.add_note(note);

        let encrypted = encrypt_store(&mk, &store).expect("encrypt must succeed");
        let recovered = decrypt_store(&mk, &encrypted).expect("decrypt must succeed");
        let nk2 = unwrap_note_key(&mk, &recovered.notes[0].note_key_wrapped, TEST_AAD).unwrap();
        let body = decrypt_note_body(&nk2, &recovered.notes[0].body_enc, TEST_AAD).unwrap();
        assert_eq!(body, "Hello, secret world!");
    }

    #[test]
    fn per_note_encrypt_decrypt_roundtrip() {
        let mk = MasterKey::generate();
        let (nk, wrapped) = new_note_key(&mk, TEST_AAD);
        let ct = encrypt_note_body(&nk, "Secret content", TEST_AAD).unwrap();
        let nk2 = unwrap_note_key(&mk, &wrapped, TEST_AAD).unwrap();
        let body = decrypt_note_body(&nk2, &ct, TEST_AAD).unwrap();
        assert_eq!(body, "Secret content");
    }

    #[test]
    fn note_body_wrong_aad_fails() {
        // VULN-C1 regression: body encrypted with note_A's AAD must not decrypt under note_B's AAD
        let mk = MasterKey::generate();
        let (nk, _) = new_note_key(&mk, b"note-a-uuid");
        let ct = encrypt_note_body(&nk, "Secret", b"note-a-uuid").unwrap();
        assert!(
            decrypt_note_body(&nk, &ct, b"note-b-uuid").is_err(),
            "body from note-A must not decrypt under note-B's AAD"
        );
    }

    #[test]
    fn vault_size_limit_enforced() {
        let mk = MasterKey::generate();
        let huge = vec![0u8; MAX_VAULT_BYTES + 1];
        assert!(decrypt_store(&mk, &huge).is_err());
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let mk1 = MasterKey::generate();
        let mk2 = MasterKey::generate();
        let store = NotesStore::new();
        let encrypted = encrypt_store(&mk1, &store).unwrap();
        assert!(decrypt_store(&mk2, &encrypted).is_err());
    }

    #[test]
    fn nonce_is_randomised_each_call() {
        let mk = MasterKey::generate();
        let store = NotesStore::new();
        let e1 = encrypt_store(&mk, &store).unwrap();
        let e2 = encrypt_store(&mk, &store).unwrap();
        assert_ne!(&e1[..NONCE_LEN], &e2[..NONCE_LEN], "nonce reuse detected!");
    }
}
