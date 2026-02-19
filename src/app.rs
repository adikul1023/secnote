//! Application state machine and eframe::App implementation.

use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};

use eframe::egui::{self, FontId, Key, Modifiers, RichText};
use crate::crypto::keys::MasterKey;
use crate::crypto::vault::{encrypt_note_body, encrypt_store, unwrap_note_key};
use crate::save::autosave::{start_autosave_thread, AppEvent, AutoSaveState};
use crate::store::notes::{AppConfig, AppSettings, NotesStore};
use crate::ui::{
    command_palette::{CommandPalette, PaletteAction},
    editor::{self, EditorState},
    lock_screen::LockScreen,
    setup::SetupWizard,
    sidebar::{self, SidebarState},
    settings::{self, SettingsTab},
    status_bar,
    tabs::TabBar,
    theme,
};

// ---------------------------------------------------------------------------
// App state machine
// ---------------------------------------------------------------------------

enum AppState {
    Setup(SetupWizard),
    Locked(LockScreen),
    Unlocked(Box<UnlockedState>),
}

struct UnlockedState {
    autosave: Arc<Mutex<AutoSaveState>>,
    event_rx: mpsc::Receiver<AppEvent>,
    sidebar: SidebarState,
    editor: EditorState,
    show_settings: bool,
    settings_tab: SettingsTab,
    #[allow(dead_code)]
    settings_changed: bool,
    config: AppConfig,
    notes_path: PathBuf,
    #[allow(dead_code)]
    config_path: PathBuf,
    settings_path: PathBuf,
    // New UI components
    command_palette: CommandPalette,
    tab_bar: TabBar,
    #[allow(dead_code)]
    last_theme: crate::store::notes::ThemeName,
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
        // Apply theme
        if let AppState::Unlocked(ref u) = self.state {
            let settings = u.autosave.lock().unwrap().settings.clone();
            theme::apply_theme_with_font(
                ctx,
                settings.theme,
                settings.font_size,
                matches!(settings.font_family, crate::store::notes::FontFamily::Monospace),
            );
        } else {
            ctx.set_visuals(egui::Visuals::dark());
        }

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
        // Global keyboard shortcuts (Unlocked only)
        // -----------------------------------------------------------------------
        if let AppState::Unlocked(ref mut u) = self.state {
            let (ctrl_p, ctrl_n, ctrl_w, ctrl_comma, ctrl_l, esc) = ctx.input(|i| {
                let ctrl = i.modifiers.matches_logically(Modifiers::CTRL);
                (
                    ctrl && i.key_pressed(Key::P),
                    ctrl && i.key_pressed(Key::N),
                    ctrl && i.key_pressed(Key::W),
                    ctrl && i.key_pressed(Key::Comma),
                    ctrl && i.key_pressed(Key::L),
                    i.key_pressed(Key::Escape),
                )
            });

            if ctrl_p {
                u.command_palette.open();
            }
            if ctrl_comma {
                u.show_settings = !u.show_settings;
            }
            if ctrl_l {
                self.do_lock(ctx);
                return;
            }
            if esc && u.command_palette.visible {
                u.command_palette.close();
            }
            if ctrl_n {
                // Create a new note via sidebar logic
                let mut guard = u.autosave.lock().unwrap();
                let s = &mut *guard;
                if let Some(mk) = s.master_key.as_ref() {
                    let mut note = crate::store::notes::Note::new(u.sidebar.active_folder.clone());
                    let aad = note.id.as_bytes().to_vec();
                    let (nk, wrapped) = crate::crypto::vault::new_note_key(mk, &aad);
                    note.note_key_wrapped = wrapped;
                    note.body_enc = crate::crypto::vault::encrypt_note_body(&nk, "", &aad).unwrap_or_default();
                    let id = note.id;
                    s.store.add_note(note);
                    u.sidebar.selected_note = Some(id);
                    u.tab_bar.push(id);
                    s.dirty = true;
                }
            }
            if ctrl_w {
                // Close active tab
                if let Some(id) = u.sidebar.selected_note {
                    u.tab_bar.remove(id);
                    u.sidebar.selected_note = u.tab_bar.recents.front().copied();
                }
            }
        }

        // -----------------------------------------------------------------------
        // Command palette (rendered before any panel so it's on top)
        // -----------------------------------------------------------------------
        if let AppState::Unlocked(ref mut u) = self.state {
            let current_theme = u.autosave.lock().unwrap().settings.theme;
            let store_snap = u.autosave.lock().unwrap().store.notes.iter()
                .map(|n| (n.id, n.title.clone(), n.folder.clone()))
                .collect::<Vec<_>>();
            // Build a temporary NotesStore view for palette
            let mut palette_store = crate::store::notes::NotesStore::default();
            for (id, title, folder) in store_snap {
                let mut n = crate::store::notes::Note::new(folder);
                n.id = id;
                n.title = title;
                palette_store.notes.push(n);
            }

            if let Some(action) = u.command_palette.show(ctx, &palette_store, current_theme) {
                match action {
                    PaletteAction::OpenNote(id) => {
                        u.sidebar.selected_note = Some(id);
                        u.tab_bar.push(id);
                    }
                    PaletteAction::NewNote => {
                        let mut guard = u.autosave.lock().unwrap();
                        let s = &mut *guard;
                        if let Some(mk) = s.master_key.as_ref() {
                            let mut note = crate::store::notes::Note::new(u.sidebar.active_folder.clone());
                            let aad = note.id.as_bytes().to_vec();
                            let (nk, wrapped) = crate::crypto::vault::new_note_key(mk, &aad);
                            note.note_key_wrapped = wrapped;
                            note.body_enc = crate::crypto::vault::encrypt_note_body(&nk, "", &aad).unwrap_or_default();
                            let id = note.id;
                            s.store.add_note(note);
                            u.sidebar.selected_note = Some(id);
                            u.tab_bar.push(id);
                            s.dirty = true;
                        }
                    }
                    PaletteAction::Lock => {
                        self.do_lock(ctx);
                        return;
                    }
                    PaletteAction::OpenSettings => {
                        if let AppState::Unlocked(ref mut u2) = self.state {
                            u2.show_settings = true;
                        }
                    }
                    PaletteAction::Dismiss => {}
                }
            }
        }

        // -----------------------------------------------------------------------
        // Status bar (bottom panel — before CentralPanel)
        // -----------------------------------------------------------------------
        if let AppState::Unlocked(ref u) = self.state {
            let settings = u.autosave.lock().unwrap().settings.clone();
            if settings.show_status_bar {
                let selected = u.sidebar.selected_note;
                let (note_title, folder_path) = {
                    let guard = u.autosave.lock().unwrap();
                    selected
                        .and_then(|id| guard.store.notes.iter().find(|n| n.id == id))
                        .map(|n| (n.title.clone(), n.folder.clone()))
                        .unwrap_or_default()
                };
                let word_count = u.editor.active_body.split_whitespace().count();
                let char_count = u.editor.active_body.chars().count();
                let idle_secs = crate::save::autosave::system_idle_ms() / 1000;
                let vim_is_normal = u.editor.vim_normal;
                status_bar::show(
                    ctx,
                    &note_title,
                    folder_path.as_deref(),
                    word_count,
                    char_count,
                    "",
                    idle_secs,
                    settings.idle_lock_minutes,
                    settings.vim_mode,
                    vim_is_normal,
                    settings.theme,
                );
            }
        }

        // -----------------------------------------------------------------------
        // Tab bar (top panel, shown inside unlocked + below top bar)
        // -----------------------------------------------------------------------
        if let AppState::Unlocked(ref mut u) = self.state {
            let current_theme = u.autosave.lock().unwrap().settings.theme;
            let selected = u.sidebar.selected_note;
            let store_snap: crate::store::notes::NotesStore = {
                let g = u.autosave.lock().unwrap();
                g.store.clone()
            };
            let tab_resp = u.tab_bar.show(ctx, &store_snap, selected, current_theme);
            if let Some(id) = tab_resp.activated {
                u.sidebar.selected_note = Some(id);
            }
            if let Some(id) = tab_resp.closed {
                u.tab_bar.remove(id);
                if u.sidebar.selected_note == Some(id) {
                    u.sidebar.selected_note = u.tab_bar.recents.front().copied();
                }
            }

            // Push newly selected note to tab bar
            if let Some(id) = selected {
                if u.tab_bar.recents.front() != Some(&id) {
                    u.tab_bar.push(id);
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
                            if ui.button("⌘ Palette (Ctrl+P)").on_hover_text("Open command palette").clicked() {
                                u.command_palette.open();
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
                        let go_back = settings::show(ui, &mut new_settings, &mut changed, &mut u.settings_tab);
                        if go_back {
                            u.show_settings = false;
                        }
                        if changed {
                            let settings_path = u.settings_path.clone();
                            u.autosave.lock().unwrap().settings = new_settings.clone();
                            save_settings(&settings_path, &new_settings);
                        }
                    } else {
                        let settings = u.autosave.lock().unwrap().settings.clone();
                        let sidebar_w = settings.sidebar_width;
                        let current_theme = settings.theme;

                        // Main layout: sidebar (left) + editor (right)
                        egui::SidePanel::left("sidebar")
                            .min_width(sidebar_w)
                            .max_width(400.0)
                            .default_width(sidebar_w)
                            .show_inside(ui, |ui| {
                                let mut guard = u.autosave.lock().unwrap();
                                let s = &mut *guard;
                                let mk = s.master_key.as_ref().expect("mk present while unlocked");
                                sidebar::show(
                                    ui,
                                    &mut s.store,
                                    &mut u.sidebar,
                                    &mut s.dirty,
                                    mk,
                                    current_theme,
                                    sidebar_w,
                                );
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
                                &settings,
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
        // Write initial empty notes.enc (R6 FIX: use atomic write with reparse-point check)
        let initial_enc =
            encrypt_store(&complete.master_key, &complete.store).expect("initial encrypt");
        let dir = notes_path.parent().unwrap_or_else(|| std::path::Path::new("."));
        crate::save::autosave::atomic_write_pub(dir, &notes_path, &initial_enc)
            .expect("write initial notes.enc");
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
                let mut mk_bytes_opt = {
                    let s = u.autosave.lock().unwrap();
                    s.master_key.as_ref().map(|m| *m.as_bytes())
                };
                if let (Some(mut mk_bytes), Some(note_id)) = (mk_bytes_opt, u.editor.active_note_id) {
                    let mut s = u.autosave.lock().unwrap();
                    if let Some(note) = s.store.get_mut(note_id) {
                        if !note.note_key_wrapped.is_empty() {
                            let tmp_mk = MasterKey::new(&mut mk_bytes); // R1 FIX: zeroizes mk_bytes directly
                            let note_aad = note.id.as_bytes().to_vec();
                            if let Ok(nk) = unwrap_note_key(&tmp_mk, &note.note_key_wrapped, &note_aad) {
                                if let Ok(enc) = encrypt_note_body(&nk, &u.editor.active_body, &note_aad) {
                                    note.body_enc = enc;
                                    s.dirty = true;
                                }
                            }
                        }
                    }
                    mk_bytes.zeroize(); // R1 FIX: zeroize on all paths (no-op if MasterKey::new already did)
                }
                use zeroize::Zeroize;
                mk_bytes_opt.zeroize(); // R1 FIX: zeroize the Option copy left behind by if-let on Copy type
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
    let initial_theme = settings.theme;
    let autosave_state = AutoSaveState::new(store, master_key, notes_path.clone(), settings);
    let autosave = Arc::new(Mutex::new(autosave_state));

    start_autosave_thread(autosave.clone(), event_tx);

    AppState::Unlocked(Box::new(UnlockedState {
        autosave,
        event_rx,
        sidebar: SidebarState::default(),
        editor: EditorState::default(),
        show_settings: false,
        settings_tab: SettingsTab::default(),
        settings_changed: false,
        config,
        notes_path,
        config_path,
        settings_path,
        command_palette: CommandPalette::default(),
        tab_bar: TabBar::default(),
        last_theme: initial_theme,
    }))
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
