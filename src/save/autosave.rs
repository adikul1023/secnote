//! Background auto-save thread with atomic writes and idle-lock detection.
//!
//! The thread wakes on a jittered 800–1400 ms interval to:
//!   1. Write the encrypted store atomically if the dirty flag is set.
//!   2. Check system idle time via `GetLastInputInfo` and lock if threshold
//!      is exceeded.
//!
//! Communication with the UI thread:
//!   - Shared state via `Arc<Mutex<AutoSaveState>>`.
//!   - Lock events sent via `mpsc::Sender<AppEvent>`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::Rng;

use crate::crypto::keys::MasterKey;
use crate::crypto::vault::encrypt_store;
use crate::store::notes::{AppSettings, NotesStore};

// ---------------------------------------------------------------------------
// Shared state between UI thread and autosave thread
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveStatus {
    Idle,
    #[allow(dead_code)]
    Saving,
    Saved,
    Error,
}

pub struct AutoSaveState {
    pub store: NotesStore,
    pub master_key: Option<MasterKey>,
    pub dirty: bool,
    pub status: SaveStatus,
    pub settings: AppSettings,
    /// Path to notes.enc — temp file is created in the same directory.
    pub notes_path: PathBuf,
    /// Path to config.json — updated on each save for vault_version bump.
    pub config_path: PathBuf,
    /// In-memory config — vault_version is incremented on each save.
    pub config: crate::store::notes::AppConfig,
}

impl AutoSaveState {
    pub fn new(
        store: NotesStore,
        master_key: MasterKey,
        notes_path: PathBuf,
        config_path: PathBuf,
        config: crate::store::notes::AppConfig,
        settings: AppSettings,
    ) -> Self {
        Self {
            store,
            master_key: Some(master_key),
            dirty: false,
            status: SaveStatus::Saved,
            settings,
            notes_path,
            config_path,
            config,
        }
    }

    #[allow(dead_code)]
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
        self.status = SaveStatus::Saving;
    }

    /// Zeroize and drop the master key, clear the store.
    /// Called on lock.
    pub fn lock(&mut self) {
        use zeroize::Zeroize;
        if let Some(mut mk) = self.master_key.take() {
            mk.zeroize();
        }
        self.store.zeroize();
        self.store = NotesStore::new();
        self.dirty = false;
        self.status = SaveStatus::Idle;
    }
}

// ---------------------------------------------------------------------------
// Events sent from the autosave thread to the UI thread
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum AppEvent {
    /// The idle timeout was reached — UI should transition to Locked state.
    IdleLock,
    /// A save completed successfully.
    SaveCompleted,
    /// A save failed.
    #[allow(dead_code)]
    SaveFailed(String),
}

// ---------------------------------------------------------------------------
// Background thread launcher
// ---------------------------------------------------------------------------

pub fn start_autosave_thread(
    state: Arc<Mutex<AutoSaveState>>,
    event_tx: std::sync::mpsc::Sender<AppEvent>,
) {
    std::thread::Builder::new()
        .name("autosave".into())
        .spawn(move || autosave_loop(state, event_tx))
        .expect("Failed to spawn autosave thread");
}

// ---------------------------------------------------------------------------
// Loop body
// ---------------------------------------------------------------------------

fn autosave_loop(
    state: Arc<Mutex<AutoSaveState>>,
    event_tx: std::sync::mpsc::Sender<AppEvent>,
) {
    let mut rng = rand::thread_rng();

    loop {
        // Jitter 800–1400 ms to reduce write-pattern side channel
        let sleep_ms: u64 = rng.gen_range(800..=1400);
        std::thread::sleep(Duration::from_millis(sleep_ms));

        // --- Idle lock check ---
        let idle_lock_minutes = {
            let s = state.lock().unwrap();
            s.settings.idle_lock_minutes
        };
        if idle_lock_minutes > 0 {
            let idle_ms = system_idle_ms();
            if idle_ms >= (idle_lock_minutes as u64) * 60_000 {
                // Flush dirty state before locking
                flush_if_dirty(&state, &event_tx);
                // Zeroize & lock
                state.lock().unwrap().lock();
                event_tx.send(AppEvent::IdleLock).ok();
                // After locking, the master key is gone — stop the loop.
                // A new thread will be spawned when the user unlocks.
                return;
            }
        }

        // --- Auto-save ---
        flush_if_dirty(&state, &event_tx);
    }
}

fn flush_if_dirty(
    state: &Arc<Mutex<AutoSaveState>>,
    event_tx: &std::sync::mpsc::Sender<AppEvent>,
) {
    // Prepare everything under a single lock: encrypt store, bump version,
    // compute HMAC, serialise config — then release the lock for I/O.
    let snapshot = {
        let mut s = state.lock().unwrap();
        if !s.dirty {
            return;
        }
        let mk = match &s.master_key {
            Some(mk) => mk,
            None => return, // locked — nothing to save
        };
        let enc = match encrypt_store(mk, &s.store) {
            Ok(b) => b,
            Err(e) => {
                event_tx.send(AppEvent::SaveFailed(e.to_string())).ok();
                return;
            }
        };

        // PENTEST-F1 FIX: bump vault_version + recompute HMAC inside the
        // same critical section that produced the encrypted store.
        s.config.vault_version = s.config.vault_version.saturating_add(1);
        // Clone mk bytes to avoid borrow conflict with config
        let mk_bytes = s.master_key.as_ref().map(|m| *m.as_bytes());
        let config_json = if let Some(mut mb) = mk_bytes {
            let tmp_mk = MasterKey::new(&mut mb);
            crate::crypto::keys::compute_config_hmac(&tmp_mk, &mut s.config);
            serde_json::to_vec_pretty(&s.config).unwrap_or_default()
        } else {
            vec![]
        };

        (enc, s.notes_path.clone(), s.config_path.clone(), config_json)
    };
    // Lock released — perform I/O without holding the mutex.

    let (encrypted, notes_path, config_path, config_json) = snapshot;

    // ── Write order: config.json FIRST, then notes.enc ──────────────
    // This guarantees vault_version is persisted before the data it
    // describes. On crash between the two writes:
    //   • config has version N+1, notes.enc still has version-N data
    //   • App loads fine (no version inside notes.enc yet) and next
    //     save will write version N+2.
    //   • An attacker cannot silently replace notes.enc with an older
    //     copy that was written under version ≤ N and have the version
    //     match, because config already records N+1.

    // 1. config.json (new vault_version + HMAC)
    if !config_json.is_empty() {
        let config_dir = config_path.parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        if let Err(e) = atomic_write(config_dir, &config_path, &config_json) {
            // Config write failed — do NOT proceed to write notes.enc,
            // otherwise version and data would be out of sync.
            let mut s = state.lock().unwrap();
            s.status = SaveStatus::Error;
            // Roll back the in-memory version bump so it retries next cycle
            s.config.vault_version = s.config.vault_version.saturating_sub(1);
            event_tx.send(AppEvent::SaveFailed(format!("config write: {e}"))).ok();
            return;
        }
    }

    // 2. notes.enc
    let dir = notes_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    match atomic_write(dir, &notes_path, &encrypted) {
        Ok(()) => {
            let mut s = state.lock().unwrap();
            s.dirty = false;
            s.status = SaveStatus::Saved;
            event_tx.send(AppEvent::SaveCompleted).ok();
        }
        Err(e) => {
            let mut s = state.lock().unwrap();
            s.status = SaveStatus::Error;
            event_tx.send(AppEvent::SaveFailed(e)).ok();
        }
    }
}

/// Write `data` to `target` atomically:
/// 1. Create a named temp file in the **same directory** as `target`
///    (critical — must be same volume for atomic rename on Windows).
/// 2. Write + flush + sync_all.
/// 3. `persist()` (rename) into place.
///
/// Exposed as `pub` so `app.rs` can call it during the lock flush.
pub fn atomic_write_pub(
    dir: &std::path::Path,
    target: &std::path::Path,
    data: &[u8],
) -> Result<(), String> {
    atomic_write(dir, target, data)
}

/// Reject if `dir` is a reparse point (Windows junction or symlink).
///
/// We use `symlink_metadata` so we examine the directory entry itself rather
/// than following it to its target — the TOCTOU window between this check and
/// `tempfile_in` is already closed by the atomic rename staying on the same
/// volume, but blocking directory reparse tricks eliminates the entire attack
/// surface.
fn check_dir_not_reparse(dir: &std::path::Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(dir)
        .map_err(|e| format!("cannot stat save directory '{}': {e}", dir.display()))?;

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT (0x400) covers both NTFS junctions
        // (IO_REPARSE_TAG_MOUNT_POINT) and symbolic links (IO_REPARSE_TAG_SYMLINK).
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!(
                "save rejected: directory '{}' is a reparse point (junction or symlink); \
                 potential redirect attack",
                dir.display()
            ));
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "save rejected: directory '{}' is a symlink",
                dir.display()
            ));
        }
    }

    Ok(())
}

fn atomic_write(
    dir: &std::path::Path,
    target: &std::path::Path,
    data: &[u8],
) -> Result<(), String> {
    use std::io::Write;
    use tempfile::Builder;

    // Guard: reject if the save directory is itself a reparse point / junction.
    check_dir_not_reparse(dir)?;

    let tmp = Builder::new()
        .prefix(".snote-")
        .suffix(".tmp")
        .tempfile_in(dir)
        .map_err(|e| format!("tempfile create: {e}"))?;

    let (mut file, tmp_path) = tmp.into_parts();

    file.write_all(data)
        .map_err(|e| format!("write: {e}"))?;
    file.flush()
        .map_err(|e| format!("flush: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("sync_all: {e}"))?;

    // Persist (atomic rename on same volume)
    tmp_path.persist(target)
        .map_err(|e| format!("persist/rename: {e}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// System idle time via GetLastInputInfo (Win32)
// ---------------------------------------------------------------------------

/// Returns milliseconds since the last user input event (keyboard or mouse).
#[cfg(target_os = "windows")]
pub fn system_idle_ms() -> u64 {
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    use windows::Win32::System::SystemInformation::GetTickCount;

    unsafe {
        let mut lii = LASTINPUTINFO {
            cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
            dwTime: 0,
        };
        if GetLastInputInfo(&mut lii).as_bool() {
            let now = GetTickCount();
            // both are u32 milliseconds — handle wraparound
            now.wrapping_sub(lii.dwTime) as u64
        } else {
            0
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn system_idle_ms() -> u64 {
    0
}
