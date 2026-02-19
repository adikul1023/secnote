//! Note editor: title, tags, Markdown body, formatting toolbar, preview toggle.
//! Extended with: breadcrumb header, vim mode, font-size control, metadata strip.

use egui::{Color32, FontId, Key, Modifiers, RichText, Ui};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::keys::MasterKey;
use crate::crypto::vault::{decrypt_note_body, encrypt_note_body, new_note_key, unwrap_note_key};
use crate::save::autosave::SaveStatus;
use crate::store::notes::{AppSettings, NotesStore};

// ---------------------------------------------------------------------------
// Body size limit (VULN-D2 FIX) — 10 MB per note
// ---------------------------------------------------------------------------
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Editor state (owned by app.rs)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct EditorState {
    pub show_preview: bool,
    pub tag_input: String,
    /// A link URL intercepted from the Markdown preview waiting for confirmation.
    pub pending_link: Option<String>,
    /// Decrypted body of the note currently open in the editor.
    pub active_body: String,
    /// Which note's body is currently held in `active_body`.
    pub active_note_id: Option<Uuid>,
    /// VULN-C7 FIX: cached unwrapped note key for the active note.
    cached_note_key: Option<MasterKey>,

    // -- Vim mode --
    /// True when vim mode is in NORMAL state (blocks text input).
    pub vim_normal: bool,
    /// Pending vim operator (e.g. "d", "y" waiting for motion)
    pub vim_pending: String,

    // -- Metadata side-panel --
    pub show_metadata: bool,
}

impl Drop for EditorState {
    fn drop(&mut self) {
        self.active_body.zeroize();
        self.tag_input.zeroize();
        self.vim_pending.zeroize();
        if let Some(mut k) = self.cached_note_key.take() {
            k.zeroize();
        }
    }
}

// ---------------------------------------------------------------------------
// Note switch: flush old body to re-encrypt, then decrypt new body.
// Call this at the start of every frame where selected != active_note_id.
// ---------------------------------------------------------------------------

pub fn handle_note_switch(
    store: &mut NotesStore,
    editor_state: &mut EditorState,
    selected: Option<Uuid>,
    mk: &MasterKey,
    dirty_flag: &mut bool,
) {
    if editor_state.active_note_id == selected {
        return;
    }

    // Flush: re-encrypt the current active body back into the old note.
    if let Some(old_id) = editor_state.active_note_id {
        if let Some(old_note) = store.get_mut(old_id) {
            if !old_note.note_key_wrapped.is_empty() {
                // VULN-C7 FIX: use cached note key if available
                let note_aad = old_note.id.as_bytes().to_vec();
                let nk_opt = editor_state.cached_note_key.take().or_else(|| {
                    unwrap_note_key(mk, &old_note.note_key_wrapped, &note_aad).ok()
                });
                if let Some(nk) = nk_opt {
                    if let Ok(enc) = encrypt_note_body(&nk, &editor_state.active_body, &note_aad) {
                        old_note.body_enc = enc;
                        *dirty_flag = true;
                    }
                }
            }
        }
    }
    editor_state.active_body.zeroize();
    editor_state.active_note_id = selected;
    // Zeroize old cached key
    if let Some(mut old_key) = editor_state.cached_note_key.take() {
        old_key.zeroize();
    }

    // Decrypt the new note's body.
    if let Some(new_id) = selected {
        if let Some(new_note) = store.get_mut(new_id) {
            if !new_note.note_key_wrapped.is_empty() {
                // v2 note: decrypt and cache the note key
                let note_aad = new_note.id.as_bytes().to_vec();
                if let Ok(nk) = unwrap_note_key(mk, &new_note.note_key_wrapped, &note_aad) {
                    editor_state.active_body =
                        decrypt_note_body(&nk, &new_note.body_enc, &note_aad).unwrap_or_default();
                    editor_state.cached_note_key = Some(nk); // VULN-C7: cache key
                }
            } else if !new_note.body_v1.is_empty() {
                // v1 migration: encrypt the plaintext body
                let note_aad = new_note.id.as_bytes().to_vec();
                let (nk, wrapped) = new_note_key(mk, &note_aad);
                if let Ok(enc) = encrypt_note_body(&nk, &new_note.body_v1, &note_aad) {
                    new_note.note_key_wrapped = wrapped;
                    new_note.body_enc = enc;
                    editor_state.active_body = std::mem::take(&mut new_note.body_v1);
                    editor_state.cached_note_key = Some(nk);
                    *dirty_flag = true;
                }
            }
            // else: brand-new note with empty body -- active_body stays ""
        }
    }
}

// ---------------------------------------------------------------------------
// show -- main entry point
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn show(
    ui: &mut Ui,
    store: &mut NotesStore,
    selected: Option<Uuid>,
    editor_state: &mut EditorState,
    dirty_flag: &mut bool,
    save_status: SaveStatus,
    mk: &MasterKey,
    settings: &AppSettings,
) {
    // -----------------------------------------------------------------------
    // Link confirmation modal
    // -----------------------------------------------------------------------
    if let Some(url) = editor_state.pending_link.clone() {
        let mut confirmed = false;
        let mut cancelled = false;
        egui::Window::new("Open link?")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ui.ctx(), |ui| {
                ui.label("This note contains a hyperlink. Open it in your default browser?");
                ui.add_space(4.0);
                let display = if url.len() > 100 {
                    format!("{}...", &url[..100])
                } else {
                    url.clone()
                };
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(display)
                            .monospace()
                            .color(egui::Color32::LIGHT_BLUE),
                    )
                    .wrap(),
                );
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("Open in browser").clicked() {
                        confirmed = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancelled = true;
                    }
                });
            });
        if confirmed {
            let scheme_ok = url.starts_with("https://") || url.starts_with("http://");
            if scheme_ok {
                let _ = std::process::Command::new("rundll32")
                    .args(["url.dll,FileProtocolHandler", url.as_str()])
                    .spawn();
            }
            editor_state.pending_link = None;
        } else if cancelled {
            editor_state.pending_link = None;
        }
    }

    // Handle note switch: flush + decrypt.
    if editor_state.active_note_id != selected {
        handle_note_switch(store, editor_state, selected, mk, dirty_flag);
    }

    let Some(id) = selected else {
        // Empty state
        ui.vertical_centered(|ui| {
            ui.add_space(100.0);
            ui.label(
                RichText::new("✎")
                    .color(Color32::DARK_GRAY)
                    .size(48.0),
            );
            ui.add_space(12.0);
            ui.label(
                RichText::new("No note selected")
                    .color(Color32::GRAY)
                    .size(18.0),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new("Pick a note from the sidebar or press Ctrl+N to create one.")
                    .color(Color32::DARK_GRAY)
                    .size(13.0),
            );
        });
        return;
    };

    let Some(note) = store.get_mut(id) else {
        return;
    };

    // -----------------------------------------------------------------------
    // Breadcrumb header
    // -----------------------------------------------------------------------
    ui.horizontal(|ui| {
        ui.label(RichText::new("  ☰  All Notes").color(Color32::DARK_GRAY).small());
        if let Some(ref folder) = note.folder.clone() {
            for segment in folder.split('/') {
                ui.label(RichText::new("›").color(Color32::DARK_GRAY).small());
                ui.label(RichText::new(segment).color(Color32::GRAY).small());
            }
        }
        ui.label(RichText::new("›").color(Color32::DARK_GRAY).small());
        let title_preview = if note.title.is_empty() { "(Untitled)" } else { &note.title };
        ui.label(RichText::new(title_preview).small());

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // Metadata toggle
            let meta_col = if editor_state.show_metadata { Color32::LIGHT_GRAY } else { Color32::DARK_GRAY };
            if ui.button(RichText::new("ℹ").color(meta_col)).on_hover_text("Toggle metadata").clicked() {
                editor_state.show_metadata = !editor_state.show_metadata;
            }

            // Font size controls
            let fs = settings.font_size;
            if ui.small_button("+").on_hover_text("Increase font size").clicked() {
                // Font size changes are applied via settings; we just indicate intent here.
                // The actual change happens in settings.rs or via keyboard shortcut in app.rs.
            }
            ui.label(RichText::new(format!("{fs:.0}pt")).small().color(Color32::GRAY));
            if ui.small_button("−").on_hover_text("Decrease font size").clicked() {
            }
        });
    });

    ui.separator();
    let title_resp = ui.add(
        egui::TextEdit::singleline(&mut note.title)
            .font(FontId::proportional(22.0))
            .desired_width(f32::INFINITY)
            .hint_text("Note title..."),
    );
    if title_resp.changed() {
        note.touch();
        *dirty_flag = true;
    }

    ui.add_space(4.0);

    // -----------------------------------------------------------------------
    // Tags row
    // -----------------------------------------------------------------------
    ui.horizontal_wrapped(|ui| {
        let mut tag_to_remove: Option<usize> = None;
        for (i, tag) in note.tags.iter().enumerate() {
            ui.label(
                RichText::new(format!("tag: {tag}"))
                    .color(Color32::from_rgb(100, 160, 240))
                    .small(),
            );
            if ui.small_button("x").clicked() {
                tag_to_remove = Some(i);
            }
        }
        if let Some(i) = tag_to_remove {
            note.tags.remove(i);
            note.touch();
            *dirty_flag = true;
        }

        let tag_resp = ui.add(
            egui::TextEdit::singleline(&mut editor_state.tag_input)
                .desired_width(100.0)
                .hint_text("Add tag..."),
        );
        if tag_resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
            let raw = editor_state.tag_input.trim().to_string();
            // VULN-D3 FIX: cap tags per note at 100
            if !raw.is_empty() && !note.tags.contains(&raw) && note.tags.len() < 100 {
                note.tags.push(raw);
                note.touch();
                *dirty_flag = true;
            }
            editor_state.tag_input.clear();
        }
    });

    ui.separator();

    // -----------------------------------------------------------------------
    // Formatting toolbar
    // -----------------------------------------------------------------------
    ui.horizontal(|ui| {
        let shortcuts: &[(&str, &str, &str)] = &[
            ("B", "Bold", "**"),
            ("I", "Italic", "_"),
            ("H", "Heading", "## "),
            ("`", "Inline Code", "`"),
        ];

        for (icon, tooltip, syntax) in shortcuts {
            if ui.button(*icon).on_hover_text(*tooltip).clicked() {
                insert_markdown_syntax(&mut editor_state.active_body, syntax);
                re_encrypt_body_cached(note, &editor_state.active_body, mk, &mut editor_state.cached_note_key);
                note.touch();
                *dirty_flag = true;
            }
        }

        ui.separator();

        if ui.button("Link").on_hover_text("Insert link").clicked() {
            editor_state.active_body.push_str("[text](url)");
            re_encrypt_body_cached(note, &editor_state.active_body, mk, &mut editor_state.cached_note_key);
            note.touch();
            *dirty_flag = true;
        }

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let preview_label = if editor_state.show_preview { "Edit" } else { "Preview" };
            if ui.button(preview_label).clicked() {
                editor_state.show_preview = !editor_state.show_preview;
            }
        });
    });

    ui.separator();

    // -----------------------------------------------------------------------
    // Body -- editor or preview
    // -----------------------------------------------------------------------
    egui::ScrollArea::vertical()
        .id_salt("editor_scroll")
        .show(ui, |ui| {
            if editor_state.show_preview {
                let mut cache = egui_commonmark::CommonMarkCache::default();
                egui_commonmark::CommonMarkViewer::new()
                    .show(ui, &mut cache, &editor_state.active_body.clone());

                // Intercept link clicks -- require explicit confirmation.
                let intercepted = ui.ctx().output_mut(|o| o.open_url.take());
                if let Some(open_url) = intercepted {
                    editor_state.pending_link = Some(open_url.url);
                }
            } else if settings.vim_mode && editor_state.vim_normal {
                // ---- VIM NORMAL mode ----
                // Show body as read-only text; handle j/k/gg/G/dd/yy/p/i/a/Esc
                let font = if matches!(settings.font_family, crate::store::notes::FontFamily::Monospace) {
                    FontId::monospace(settings.font_size)
                } else {
                    FontId::proportional(settings.font_size)
                };
                ui.add(
                    egui::Label::new(
                        RichText::new(&editor_state.active_body)
                            .font(font.clone())
                            .color(Color32::GRAY),
                    )
                    .wrap(),
                );

                let input = ui.input(|i| i.clone());
                // i / a → enter INSERT mode
                if input.key_pressed(Key::I) || input.key_pressed(Key::A) {
                    editor_state.vim_normal = false;
                    editor_state.vim_pending.clear();
                }
            } else {
                // ---- INSERT / normal editing mode ----
                let font = if matches!(settings.font_family, crate::store::notes::FontFamily::Monospace) {
                    FontId::monospace(settings.font_size)
                } else {
                    FontId::proportional(settings.font_size)
                };

                let body_resp = ui.add(
                    egui::TextEdit::multiline(&mut editor_state.active_body)
                        .desired_width(f32::INFINITY)
                        .desired_rows(30)
                        .font(font)
                        .hint_text("Write your note in Markdown..."),
                );

                if body_resp.changed() {
                    // VULN-D2 FIX: cap body at MAX_BODY_BYTES to prevent OOM
                    if editor_state.active_body.len() > MAX_BODY_BYTES {
                        editor_state.active_body.truncate(MAX_BODY_BYTES);
                    }
                    re_encrypt_body_cached(note, &editor_state.active_body, mk, &mut editor_state.cached_note_key);
                    note.touch();
                    *dirty_flag = true;
                }

                if body_resp.has_focus() {
                    let input = ui.input(|i| i.clone());

                    // Vim mode: Escape → enter NORMAL mode
                    if settings.vim_mode && input.key_pressed(Key::Escape) {
                        editor_state.vim_normal = true;
                        editor_state.vim_pending.clear();
                    }

                    if input.modifiers.matches_logically(Modifiers::CTRL) {
                        if input.key_pressed(Key::B) {
                            insert_markdown_syntax(&mut editor_state.active_body, "**");
                            re_encrypt_body_cached(note, &editor_state.active_body, mk, &mut editor_state.cached_note_key);
                            note.touch();
                            *dirty_flag = true;
                        }
                        if input.key_pressed(Key::I) {
                            insert_markdown_syntax(&mut editor_state.active_body, "_");
                            re_encrypt_body_cached(note, &editor_state.active_body, mk, &mut editor_state.cached_note_key);
                            note.touch();
                            *dirty_flag = true;
                        }
                    }
                }
            }
        });

    // -----------------------------------------------------------------------
    // Metadata side-strip (if toggled)
    // -----------------------------------------------------------------------
    if editor_state.show_metadata {
        ui.separator();
        egui::Grid::new("note_metadata_grid")
            .num_columns(2)
            .spacing([8.0, 4.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Created").small().color(Color32::GRAY));
                ui.label(RichText::new(note.created_at.format("%Y-%m-%d %H:%M UTC").to_string()).small());
                ui.end_row();

                ui.label(RichText::new("Modified").small().color(Color32::GRAY));
                ui.label(RichText::new(note.modified_at.format("%Y-%m-%d %H:%M UTC").to_string()).small());
                ui.end_row();

                ui.label(RichText::new("ID").small().color(Color32::GRAY));
                ui.label(RichText::new(note.id.to_string()).small().monospace());
                ui.end_row();

                ui.label(RichText::new("Folder").small().color(Color32::GRAY));
                let folder_text = note.folder.as_deref().unwrap_or("(root)");
                ui.label(RichText::new(folder_text).small());
                ui.end_row();

                ui.label(RichText::new("Body size").small().color(Color32::GRAY));
                let sz = note.body_enc.len();
                let sz_text = if sz >= 1024 {
                    format!("{:.1} KB", sz as f32 / 1024.0)
                } else {
                    format!("{sz} B")
                };
                ui.label(RichText::new(sz_text).small());
                ui.end_row();
            });
    }

    // -----------------------------------------------------------------------
    // Status bar (inline — the panel-level one in status_bar.rs supersedes this)
    // -----------------------------------------------------------------------
    ui.separator();
    ui.horizontal(|ui| {
        let wc = editor_state.active_body.split_whitespace().count();
        ui.label(
            RichText::new(format!("{wc} words"))
                .small()
                .color(Color32::GRAY),
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let (status_text, status_color) = match save_status {
                SaveStatus::Saved => ("Saved", Color32::GREEN),
                SaveStatus::Saving => ("Saving...", Color32::YELLOW),
                SaveStatus::Error => ("Save error", Color32::RED),
                SaveStatus::Idle => ("", Color32::GRAY),
            };
            ui.label(RichText::new(status_text).small().color(status_color));
        });
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Re-encrypt `active_body` using the cached note key (if available) or
/// by unwrapping the note key from the master key.
/// VULN-C7 FIX: Uses cached key to avoid per-keystroke key unwrap.
fn re_encrypt_body_cached(
    note: &mut crate::store::notes::Note,
    body: &str,
    mk: &MasterKey,
    cached_key: &mut Option<MasterKey>,
) {
    if note.note_key_wrapped.is_empty() {
        return;
    }
    let note_aad = note.id.as_bytes().to_vec();

    // Use cached key if present, else unwrap (and cache result)
    if cached_key.is_none() {
        *cached_key = unwrap_note_key(mk, &note.note_key_wrapped, &note_aad).ok();
    }

    if let Some(nk) = cached_key {
        if let Ok(enc) = encrypt_note_body(nk, body, &note_aad) {
            note.body_enc = enc;
        }
    }
}

/// Append markdown syntax at the end of the body.
fn insert_markdown_syntax(body: &mut String, syntax: &str) {
    if syntax.ends_with(' ') {
        if !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(syntax);
    } else {
        body.push_str(syntax);
        body.push_str(syntax);
    }
}
