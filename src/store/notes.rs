use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Note
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub id: Uuid,
    pub title: String,
    /// Slash-separated folder path, e.g. "Work/Projects". None = root.
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    /// v1 plaintext body — only populated when reading an old vault.
    /// Never written on save (skip_serializing). Migrated to body_enc on first open.
    #[serde(default, skip_serializing, rename = "body")]
    pub body_v1: String,
    /// Per-note 32-byte AES-256-GCM key wrapped under the master key.
    /// nonce(12) || ciphertext(32) || tag(16) = 60 bytes.
    #[serde(default)]
    pub note_key_wrapped: Vec<u8>,
    /// AES-256-GCM ciphertext of the note body.
    /// nonce(12) || ciphertext || tag(16).
    #[serde(default)]
    pub body_enc: Vec<u8>,
}

impl Note {
    pub fn new(folder: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            title: String::from("Untitled"),
            folder,
            tags: Vec::new(),
            created_at: now,
            modified_at: now,
            body_v1: String::new(),
            note_key_wrapped: Vec::new(),
            body_enc: Vec::new(),
        }
    }

    pub fn touch(&mut self) {
        self.modified_at = Utc::now();
    }
}

// ---------------------------------------------------------------------------
// NotesStore — the entire in-memory vault content
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotesStore {
    pub notes: Vec<Note>,
    /// Known folder paths in display order.
    pub folders: Vec<String>,
}

impl NotesStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_note(&mut self, note: Note) {
        self.notes.push(note);
    }

    pub fn remove_note(&mut self, id: Uuid) {
        self.notes.retain(|n| n.id != id);
    }

    pub fn get_mut(&mut self, id: Uuid) -> Option<&mut Note> {
        self.notes.iter_mut().find(|n| n.id == id)
    }

    pub fn notes_in_folder(&self, folder: Option<&str>) -> Vec<&Note> {
        self.notes
            .iter()
            .filter(|n| n.folder.as_deref() == folder)
            .collect()
    }

    pub fn all_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self
            .notes
            .iter()
            .flat_map(|n| n.tags.iter().cloned())
            .collect();
        tags.sort_unstable();
        tags.dedup();
        tags
    }

    pub fn add_folder(&mut self, path: String) {
        if !self.folders.contains(&path) {
            self.folders.push(path);
        }
    }

    pub fn remove_folder(&mut self, path: &str) {
        self.folders.retain(|f| f != path);
        // Move orphaned notes to root
        for note in &mut self.notes {
            if note.folder.as_deref() == Some(path) {
                note.folder = None;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AppConfig — persisted to config.json (no secret values, only wrapped keys)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Name used with KeyCredentialManager
    pub winhello_key_id: String,
    /// Windows DPAPI-protected 32-byte MKEK.
    /// Only decryptable by the current Windows user on this machine — prevents offline extraction.
    pub winhello_dpapi_blob: Vec<u8>,
    /// AES-256-GCM wrapped master key — winhello path: nonce(12)||ct(32)||tag(16)
    pub winhello_wrapped_mk: Vec<u8>,
    /// Random salt for HKDF — recovery path
    pub recovery_salt: Vec<u8>,      // 32 bytes
    /// AES-256-GCM wrapped master key — recovery path: nonce(12)||ct(32)||tag(16)
    pub recovery_wrapped_mk: Vec<u8>,
    /// Monotonic vault version — incremented on every save.
    /// Detects rollback/replay attacks (VULN-S3).
    #[serde(default)]
    pub vault_version: u64,
    /// HMAC-SHA256(MK, canonical_config_bytes) over all fields above.
    /// Detects tampering of config.json.
    pub config_hmac: Vec<u8>,        // 32 bytes
}

// ---------------------------------------------------------------------------
// AppSettings — persisted to settings.json (plaintext, not sensitive)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Minutes of inactivity before auto-lock. 0 = disabled.
    pub idle_lock_minutes: u32,
    /// Lock when the application window loses focus.
    pub lock_on_focus_loss: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            idle_lock_minutes: 5,
            lock_on_focus_loss: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Zeroize impls for sensitive data that may land in NotesStore
// ---------------------------------------------------------------------------

impl Zeroize for Note {
    fn zeroize(&mut self) {
        self.title.zeroize();
        self.body_v1.zeroize();
        for tag in &mut self.tags {
            tag.zeroize();
        }
        // body_enc and note_key_wrapped are ciphertext — zeroize to minimise
        // window during which key material exists in freed memory.
        self.note_key_wrapped.zeroize();
        self.body_enc.zeroize();
    }
}

impl Zeroize for NotesStore {
    fn zeroize(&mut self) {
        for note in &mut self.notes {
            note.zeroize();
        }
    }
}
