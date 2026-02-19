//! Sidebar: folder tree, note list, tag filter, search.

use egui::{Color32, RichText, Ui};
use uuid::Uuid;

use crate::crypto::keys::MasterKey;
use crate::crypto::vault::{encrypt_note_body, new_note_key};
use crate::store::notes::{Note, NotesStore};

// ---------------------------------------------------------------------------
// Size limits (VULN-D3 FIX)
// ---------------------------------------------------------------------------
const MAX_FOLDERS: usize = 1000;
const MAX_TAGS_PER_NOTE: usize = 100;

// ---------------------------------------------------------------------------
// Selection state (owned by app.rs, passed in by &mut ref)
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
pub struct SidebarState {
    pub selected_note: Option<Uuid>,
    pub active_folder: Option<String>, // None = "All Notes"
    pub active_tag: Option<String>,
    pub search_query: String,
    pub new_folder_input: String,
    pub show_new_folder: bool,
    /// True for exactly one frame after the new-folder row appears — used to auto-focus.
    pub new_folder_just_opened: bool,
}

// ---------------------------------------------------------------------------
// Sidebar widget
// ---------------------------------------------------------------------------

pub fn show(
    ui: &mut Ui,
    store: &mut NotesStore,
    state: &mut SidebarState,
    dirty_flag: &mut bool,
    mk: &MasterKey,
) {
    // -----------------------------------------------------------------------
    // Search bar
    // -----------------------------------------------------------------------
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label("🔍");
        ui.text_edit_singleline(&mut state.search_query)
            .on_hover_text("Search notes by title or content");
    });
    ui.separator();

    // -----------------------------------------------------------------------
    // "All Notes" shortcut
    // -----------------------------------------------------------------------
    let all_selected = state.active_folder.is_none() && state.active_tag.is_none();
    if ui
        .selectable_label(all_selected, RichText::new("📋  All Notes").strong())
        .clicked()
    {
        state.active_folder = None;
        state.active_tag = None;
    }

    // -----------------------------------------------------------------------
    // Folder tree
    // -----------------------------------------------------------------------
    ui.add_space(4.0);
    ui.label(RichText::new("FOLDERS").small().color(Color32::GRAY));

    // Collect top-level folder segments
    let mut folders: Vec<String> = store.folders.clone();
    folders.sort();

    let mut folder_to_delete: Option<String> = None;
    for folder_path in &folders {
        let is_selected = state.active_folder.as_deref() == Some(folder_path.as_str());
        let label = folder_display_name(folder_path);

        let resp = ui.selectable_label(
            is_selected,
            format!("📁  {label}"),
        );
        if resp.clicked() {
            state.active_folder = Some(folder_path.clone());
            state.active_tag = None;
        }
        resp.context_menu(|ui| {
            if ui.button("🗑 Delete folder").clicked() {
                folder_to_delete = Some(folder_path.clone());
                ui.close_menu();
            }
        });
    }

    if let Some(f) = folder_to_delete {
        store.remove_folder(&f);
        if state.active_folder.as_deref() == Some(f.as_str()) {
            state.active_folder = None;
        }
        *dirty_flag = true;
    }

    // New folder button
    ui.add_space(2.0);
    if state.show_new_folder {
        ui.horizontal(|ui| {
            let resp = ui.text_edit_singleline(&mut state.new_folder_input);
            // Auto-focus on the first frame the row appears
            if state.new_folder_just_opened {
                resp.request_focus();
                state.new_folder_just_opened = false;
            }
            let enter_pressed =
                resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let confirmed = ui
                .button("Create")
                .on_hover_text("Press Enter or click to create")
                .clicked()
                || enter_pressed;
            if confirmed {
                let name = state.new_folder_input.trim().to_string();
                // VULN-D3: cap folder count
                if !name.is_empty() && store.folders.len() < MAX_FOLDERS {
                    store.add_folder(name.clone());
                    state.active_folder = Some(name);
                    *dirty_flag = true;
                }
                state.show_new_folder = false;
                state.new_folder_input.clear();
            }
            if ui.button("✕").on_hover_text("Cancel").clicked() {
                state.show_new_folder = false;
                state.new_folder_input.clear();
            }
        });
    } else if ui.small_button("＋ New folder").clicked() {
        state.show_new_folder = true;
        state.new_folder_just_opened = true;
    }

    ui.separator();

    // -----------------------------------------------------------------------
    // Tags panel
    // -----------------------------------------------------------------------
    let all_tags = store.all_tags();
    if !all_tags.is_empty() {
        ui.label(RichText::new("TAGS").small().color(Color32::GRAY));
        for tag in &all_tags {
            let is_active = state.active_tag.as_deref() == Some(tag.as_str());
            if ui
                .selectable_label(is_active, format!("🏷  {tag}"))
                .clicked()
            {
                if is_active {
                    state.active_tag = None;
                } else {
                    state.active_tag = Some(tag.clone());
                    state.active_folder = None;
                }
            }
        }
        ui.separator();
    }

    // -----------------------------------------------------------------------
    // Note list
    // -----------------------------------------------------------------------
    ui.label(RichText::new("NOTES").small().color(Color32::GRAY));

    let query = state.search_query.to_lowercase();
    let filtered_notes: Vec<&Note> = store
        .notes
        .iter()
        .filter(|n| {
            // Folder filter
            let folder_ok = state.active_folder.is_none()
                || n.folder.as_deref() == state.active_folder.as_deref();
            // Tag filter
            let tag_ok = state.active_tag.is_none()
                || n.tags
                    .iter()
                    .any(|t| Some(t.as_str()) == state.active_tag.as_deref());
            // Search filter
            let search_ok = query.is_empty()
                || n.title.to_lowercase().contains(&query)
                || n.tags.iter().any(|t| t.to_lowercase().contains(&query));
            folder_ok && tag_ok && search_ok
        })
        .collect();

    let mut note_to_delete: Option<Uuid> = None;

    for note in &filtered_notes {
        let is_selected = state.selected_note == Some(note.id);
        let label = if note.title.is_empty() {
            "(Untitled)".to_string()
        } else {
            note.title.clone()
        };
        let resp = ui.selectable_label(is_selected, &label);
        if resp.clicked() {
            state.selected_note = Some(note.id);
        }
        resp.context_menu(|ui| {
            if ui.button("🗑 Delete note").clicked() {
                note_to_delete = Some(note.id);
                ui.close_menu();
            }
        });
    }

    if let Some(id) = note_to_delete {
        store.remove_note(id);
        if state.selected_note == Some(id) {
            state.selected_note = None;
        }
        *dirty_flag = true;
    }

    ui.add_space(4.0);

    // -----------------------------------------------------------------------
    // New note button
    // -----------------------------------------------------------------------
    if ui.button("+ New Note").clicked() {
        let mut note = Note::new(state.active_folder.clone());
        // Generate a per-note key bound to this note's UUID (VULN-C1)
        let note_aad = note.id.as_bytes().to_vec();
        let (nk, wrapped) = new_note_key(mk, &note_aad);
        note.note_key_wrapped = wrapped;
        note.body_enc = encrypt_note_body(&nk, "", &note_aad).unwrap_or_default();
        let id = note.id;
        store.add_note(note);
        state.selected_note = Some(id);
        *dirty_flag = true;
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn folder_display_name(path: &str) -> String {
    // For nested paths like "Work/Projects", show indented last segment
    let depth = path.matches('/').count();
    let name = path.split('/').last().unwrap_or(path);
    format!("{}{}", "  ".repeat(depth), name)
}
