//! Application state machine and eframe::App implementation.

use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};

use eframe::egui::{self, FontId, RichText};

use crate::crypto::keys::MasterKey;
use crate::crypto::vault::{encrypt_note_body, encrypt_store, unwrap_note_key};
use crate::save::autosave::{start_autosave_thread, AppEvent, AutoSaveState};
use crate::store::notes::{AppConfig, AppSettings, NotesStore};
use crate::ui::{
    editor::{self, EditorState},
    lock_screen::LockScreen,
    setup::SetupWizard,
    sidebar::{self, SidebarState},
    settings,
};

// ---------------------------------------------------------------------------
// App state machine
// ---------------------------------------------------------------------------

enum AppState {
    /// First run — setup wizard not yet complete.
    Setup(SetupWizard),
    /// Vault locked.
    Locked(LockScreen),
    /// Vault unlocked.
    Unlocked(UnlockedState),
}

struct UnlockedState {
    autosave: Arc<Mutex<AutoSaveState>>,
    event_rx: mpsc::Receiver<AppEvent>,
    sidebar: SidebarState,
    editor: EditorState,
    show_settings: bool,
    #[allow(dead_code)]
    settings_changed: bool,
    config: AppConfig,
    notes_path: PathBuf,
    #[allow(dead_code)]
    config_path: PathBuf,
    settings_path: PathBuf,
}

// ---------------------------------------------------------------------------
// Main App
// ---------------------------------------------------------------------------

pub struct SecureNotesApp {
    state: AppState,
    data_dir: PathBuf,
}

impl SecureNotesApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let data_dir = data_dir();
        std::fs::create_dir_all(&data_dir).ok();

        let config_path = data_dir.join("config.json");
        let notes_path = data_dir.join("notes.enc");
        let settings_path = data_dir.join("settings.json");

        // Load settings (non-sensitive)
        let settings: AppSettings = std::fs::read(&settings_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();

        let state = if is_regular_file(&config_path) && is_regular_file(&notes_path) {
            // Existing vault — show lock screen
            // VULN-L3 FIX: graceful error if config.json is corrupt (don't panic).
            let config: AppConfig = match std::fs::read(&config_path)
                .ok()
                .and_then(|raw| serde_json::from_slice(&raw).ok())
            {
                Some(c) => c,
                None => {
                    // Config is unreadable or corrupt — force re-setup.
                    return Self { state: AppState::Setup(SetupWizard::new()), data_dir };
                }
            };
            let encrypted_notes = std::fs::read(&notes_path).unwrap_or_default();
            AppState::Locked(LockScreen::new(config, settings, encrypted_notes))
        } else {
            // First run
            AppState::Setup(SetupWizard::new())
        };

        Self { state, data_dir }
    }
}

impl eframe::App for SecureNotesApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply a clean dark theme
        ctx.set_visuals(egui::Visuals::dark());

        // Handle focus-loss lock for Unlocked state
        if let AppState::Unlocked(ref mut u) = self.state {
            let focused = ctx.input(|i| i.focused);
            let lock_on_loss = {
                u.autosave.lock().unwrap().settings.lock_on_focus_loss
            };
            if !focused && lock_on_loss {
                self.do_lock(ctx);
                return;
            }

            // Drain AppEvent channel
            while let Ok(evt) = u.event_rx.try_recv() {
                match evt {
                    AppEvent::IdleLock => {
                        self.do_lock(ctx);
                        return;
                    }
                    AppEvent::SaveCompleted | AppEvent::SaveFailed(_) => {}
                }
            }
        }

        // -----------------------------------------------------------------------
        // Top menu bar
        // -----------------------------------------------------------------------
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("🔐 Secure Notes")
                        .font(FontId::proportional(16.0))
                        .strong(),
                );

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let AppState::Unlocked(_) = &self.state {
                        if ui.button("🔒 Lock").clicked() {
                            self.do_lock(ctx);
                            return;
                        }
                        if let AppState::Unlocked(ref mut u) = self.state {
                            if ui.button("⚙ Settings").clicked() {
                                u.show_settings = !u.show_settings;
                            }
                        }
                    }
                });
            });
        });

        // -----------------------------------------------------------------------
        // Central panel — route by state
        // -----------------------------------------------------------------------
        egui::CentralPanel::default().show(ctx, |ui| {
            // Borrow self.state directly
            match &mut self.state {
                AppState::Setup(wizard) => {
                    wizard.show(ui);
                    if wizard.complete.is_some() {
                        self.finish_setup(ctx);
                    }
                }
                AppState::Locked(screen) => {
                    screen.show(ui);
                    if screen.result.is_some() {
                        self.finish_unlock(ctx);
                    }
                }
                AppState::Unlocked(u) => {
                    if u.show_settings {
                        let mut changed = false;
                        let mut new_settings = u.autosave.lock().unwrap().settings.clone();
                        let go_back = settings::show(ui, &mut new_settings, &mut changed);
                        if go_back {
                            u.show_settings = false;
                        }
                        if changed {
                            let settings_path = u.settings_path.clone();
                            u.autosave.lock().unwrap().settings = new_settings.clone();
                            save_settings(&settings_path, &new_settings);
                        }
                    } else {
                        // Main layout: sidebar (left) + editor (right)
                        egui::SidePanel::left("sidebar")
                            .min_width(180.0)
                            .max_width(280.0)
                            .show_inside(ui, |ui| {
                                let mut guard = u.autosave.lock().unwrap();
                                let s = &mut *guard;
                                let mk = s.master_key.as_ref().expect("mk present while unlocked");
                                sidebar::show(ui, &mut s.store, &mut u.sidebar, &mut s.dirty, mk);
                            });

                        egui::CentralPanel::default().show_inside(ui, |ui| {
                            let selected = u.sidebar.selected_note;
                            let save_status = u.autosave.lock().unwrap().status;
                            let mut guard = u.autosave.lock().unwrap();
                            let s = &mut *guard;
                            let mk = s.master_key.as_ref().expect("mk present while unlocked");
                            editor::show(
                                ui,
                                &mut s.store,
                                selected,
                                &mut u.editor,
                                &mut s.dirty,
                                save_status,
                                mk,
                            );
                        });
                    }
                }
            }
        });

        // Request repaint while authenticating (spinner)
        ctx.request_repaint_after(std::time::Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// State transitions
// ---------------------------------------------------------------------------

impl SecureNotesApp {
    fn finish_setup(&mut self, _ctx: &egui::Context) {
        let wizard = match &mut self.state {
            AppState::Setup(w) => w,
            _ => return,
        };
        let complete = wizard.complete.take().expect("complete must exist");

        let config_path = self.data_dir.join("config.json");
        let notes_path = self.data_dir.join("notes.enc");
        let settings_path = self.data_dir.join("settings.json");

        // Write config.json
        save_config(&config_path, &complete.config);
        // Write initial empty notes.enc
        let initial_enc =
            encrypt_store(&complete.master_key, &complete.store).expect("initial encrypt");
        std::fs::write(&notes_path, &initial_enc).expect("write notes.enc");
        // Write settings.json
        save_settings(&settings_path, &complete.settings);

        self.state = build_unlocked_state(
            complete.master_key,
            complete.store,
            complete.config,
            complete.settings,
            notes_path,
            config_path,
            settings_path,
        );
    }

    fn finish_unlock(&mut self, _ctx: &egui::Context) {
        let screen = match &mut self.state {
            AppState::Locked(s) => s,
            _ => return,
        };
        let result = screen.result.take().expect("result must exist");
        let settings = screen.settings.clone();

        let config_path = self.data_dir.join("config.json");
        let notes_path = self.data_dir.join("notes.enc");
        let settings_path = self.data_dir.join("settings.json");

        // Persist updated config (may have been refreshed after recovery)
        save_config(&config_path, &result.config);

        self.state = build_unlocked_state(
            result.master_key,
            result.store,
            result.config,
            settings,
            notes_path,
            config_path,
            settings_path,
        );
    }

    fn do_lock(&mut self, _ctx: &egui::Context) {
        if let AppState::Unlocked(ref mut u) = self.state {
            // Flush active editor body back into its note before locking.
            {
                let mk_bytes_opt = {
                    let s = u.autosave.lock().unwrap();
                    s.master_key.as_ref().map(|m| *m.as_bytes())
                };
                if let (Some(mk_bytes), Some(note_id)) = (mk_bytes_opt, u.editor.active_note_id) {
                    let mut s = u.autosave.lock().unwrap();
                    if let Some(note) = s.store.get_mut(note_id) {
                        if !note.note_key_wrapped.is_empty() {
                            let mut mk_bytes_mut = mk_bytes;
                            let tmp_mk = MasterKey::new(&mut mk_bytes_mut); // VULN-M1: zeroizes mk_bytes_mut
                            let note_aad = note.id.as_bytes().to_vec();
                            if let Ok(nk) = unwrap_note_key(&tmp_mk, &note.note_key_wrapped, &note_aad) {
                                if let Ok(enc) = encrypt_note_body(&nk, &u.editor.active_body, &note_aad) {
                                    note.body_enc = enc;
                                    s.dirty = true;
                                }
                            }
                        }
                    }
                }
                use zeroize::Zeroize;
                u.editor.active_body.zeroize();
                u.editor.active_note_id = None;
            }
            // Force a final flush before locking.
            {
                let mut s = u.autosave.lock().unwrap();
                if s.dirty {
                    if let Some(mk) = &s.master_key {
                        if let Ok(enc) = encrypt_store(mk, &s.store) {
                            let dir = u.notes_path.parent()
                                .unwrap_or_else(|| std::path::Path::new("."));
                            // Best-effort sync on lock
                            let _ = crate::save::autosave::atomic_write_pub(
                                dir,
                                &u.notes_path,
                                &enc,
                            );
                        }
                    }
                    s.dirty = false;
                }
                s.lock();
            }

            let notes_path = u.notes_path.clone();
            let config = u.config.clone();
            let settings = {
                u.autosave.lock().unwrap().settings.clone()
            };

            let encrypted_notes = std::fs::read(&notes_path).unwrap_or_default();
            self.state = AppState::Locked(LockScreen::new(config, settings, encrypted_notes));
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn build_unlocked_state(
    master_key: MasterKey,
    store: NotesStore,
    config: AppConfig,
    settings: AppSettings,
    notes_path: PathBuf,
    config_path: PathBuf,
    settings_path: PathBuf,
) -> AppState {
    let (event_tx, event_rx) = mpsc::channel();
    let autosave_state = AutoSaveState::new(store, master_key, notes_path.clone(), settings);
    let autosave = Arc::new(Mutex::new(autosave_state));

    start_autosave_thread(autosave.clone(), event_tx);

    AppState::Unlocked(UnlockedState {
        autosave,
        event_rx,
        sidebar: SidebarState::default(),
        editor: EditorState::default(),
        show_settings: false,
        settings_changed: false,
        config,
        notes_path,
        config_path,
        settings_path,
    })
}

fn data_dir() -> PathBuf {
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("SecureNotes")
}

/// VULN-S5 FIX: Return true only for real regular files, rejecting symlinks and
/// junctions that could redirect writes to attacker-controlled locations.
fn is_regular_file(path: &std::path::Path) -> bool {
    match path.symlink_metadata() {
        Ok(m) => m.is_file() && !m.file_type().is_symlink(),
        Err(_) => false,
    }
}

fn save_config(path: &std::path::Path, config: &AppConfig) {
    // VULN-S2 FIX: atomic write via temp file + rename so a crash mid-write
    // never leaves config.json in a partially-written state.
    let json = serde_json::to_vec_pretty(config).expect("config serialise");
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    crate::save::autosave::atomic_write_pub(dir, path, &json)
        .expect("write config.json");
}

fn save_settings(path: &std::path::Path, settings: &AppSettings) {
    let json = serde_json::to_vec_pretty(settings).expect("settings serialise");
    std::fs::write(path, json).expect("write settings.json");
}
