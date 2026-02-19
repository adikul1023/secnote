//! Sidebar: VS Code-style folder tree, note list, tag filter, search.

use std::collections::HashSet;

use egui::{Color32, Key, RichText, Ui};
use uuid::Uuid;

use crate::crypto::keys::MasterKey;
use crate::crypto::vault::{encrypt_note_body, new_note_key};
use crate::store::notes::{Note, NotesStore, ThemeName};
use crate::ui::theme;

// ---------------------------------------------------------------------------
// Size limits (VULN-D3 FIX)
// ---------------------------------------------------------------------------
const MAX_FOLDERS: usize = 1000;
pub const MAX_FOLDER_DEPTH: usize = 5;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
pub struct SidebarState {
    pub selected_note: Option<Uuid>,
    pub active_folder: Option<String>,
    pub active_tag: Option<String>,
    pub search_query: String,

    // Folder creation
    pub new_folder_input: String,
    pub show_new_folder: bool,
    pub new_folder_just_opened: bool,
    pub new_folder_parent: String,

    // Tree expand/collapse
    pub expanded_folders: HashSet<String>,

    // Inline rename — note
    pub renaming_note: Option<Uuid>,
    pub rename_buffer: String,

    // Inline rename — folder
    pub renaming_folder: Option<String>,
    pub folder_rename_buffer: String,
}

// ---------------------------------------------------------------------------
// Folder tree node
// ---------------------------------------------------------------------------

struct FolderNode {
    path: String,
    name: String,
    children: Vec<FolderNode>,
}

fn build_tree(folders: &[String]) -> Vec<FolderNode> {
    let mut roots: Vec<FolderNode> = Vec::new();
    let mut sorted = folders.to_vec();
    sorted.sort();

    for path in &sorted {
        let segments: Vec<&str> = path.split('/').collect();
        insert_node(&mut roots, &segments, 0);
    }
    roots
}

fn insert_node(nodes: &mut Vec<FolderNode>, segments: &[&str], depth: usize) {
    if depth >= segments.len() {
        return;
    }
    let full = segments[..=depth].join("/");
    if let Some(idx) = nodes.iter().position(|n| n.path == full) {
        insert_node(&mut nodes[idx].children, segments, depth + 1);
    } else {
        nodes.push(FolderNode {
            path: full,
            name: segments[depth].to_string(),
            children: Vec::new(),
        });
        let last = nodes.len() - 1;
        insert_node(&mut nodes[last].children, segments, depth + 1);
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn show(
    ui: &mut Ui,
    store: &mut NotesStore,
    state: &mut SidebarState,
    dirty_flag: &mut bool,
    mk: &MasterKey,
    current_theme: ThemeName,
    sidebar_width: f32,
) {
    let accent = theme::accent_color(current_theme);
    let dim    = theme::dim_color(current_theme);

    ui.set_min_width(sidebar_width);

    // -------------------------------------------------------------------
    // Search bar
    // -------------------------------------------------------------------
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("🔍").color(dim));
        ui.add(
            egui::TextEdit::singleline(&mut state.search_query)
                .hint_text("Search notes…")
                .desired_width(f32::INFINITY),
        );
        if !state.search_query.is_empty() && ui.small_button("✕").clicked() {
            state.search_query.clear();
        }
    });
    ui.add_space(4.0);

    // -------------------------------------------------------------------
    // All Notes row
    // -------------------------------------------------------------------
    let all_selected = state.active_folder.is_none() && state.active_tag.is_none();
    if ui
        .selectable_label(all_selected, RichText::new("  ☰  All Notes").strong())
        .clicked()
    {
        state.active_folder = None;
        state.active_tag = None;
    }

    ui.add_space(6.0);

    // -------------------------------------------------------------------
    // FOLDERS
    // -------------------------------------------------------------------
    ui.label(RichText::new("  FOLDERS").small().color(dim));
    ui.add_space(2.0);

    let tree = build_tree(&store.folders.clone());
    let mut folder_to_delete: Option<String> = None;
    let mut folder_renamed: Option<(String, String)> = None;
    let mut new_subfolder_parent: Option<String> = None;

    for node in &tree {
        render_folder_node(
            ui, node, state, store, accent, dim, 0,
            &mut folder_to_delete, &mut folder_renamed, &mut new_subfolder_parent,
        );
    }

    if let Some((old, new)) = folder_renamed {
        if !new.is_empty() && !store.folders.contains(&new) {
            rename_folder_in_store(store, &old, &new);
            if state.active_folder.as_deref() == Some(&old) {
                state.active_folder = Some(new.clone());
            }
            state.renaming_folder = None;
            *dirty_flag = true;
        }
    }
    if let Some(f) = folder_to_delete {
        store.remove_folder(&f);
        if state.active_folder.as_deref() == Some(f.as_str()) {
            state.active_folder = None;
        }
        *dirty_flag = true;
    }
    if let Some(parent) = new_subfolder_parent {
        state.show_new_folder = true;
        state.new_folder_just_opened = true;
        state.new_folder_parent = parent;
        state.new_folder_input.clear();
    }

    // New folder input
    ui.add_space(2.0);
    if state.show_new_folder {
        ui.horizontal(|ui| {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut state.new_folder_input)
                    .hint_text("Folder name…")
                    .desired_width(110.0),
            );
            if state.new_folder_just_opened {
                resp.request_focus();
                state.new_folder_just_opened = false;
            }
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            if enter || ui.small_button("✓").clicked() {
                let raw = state.new_folder_input.trim().to_string();
                if !raw.is_empty() && store.folders.len() < MAX_FOLDERS {
                    let depth_parent = if state.new_folder_parent.is_empty() {
                        0
                    } else {
                        state.new_folder_parent.matches('/').count() + 1
                    };
                    if depth_parent < MAX_FOLDER_DEPTH {
                        let full = if state.new_folder_parent.is_empty() {
                            raw
                        } else {
                            format!("{}/{}", state.new_folder_parent, raw)
                        };
                        store.add_folder(full.clone());
                        state.active_folder = Some(full);
                        *dirty_flag = true;
                    }
                }
                state.show_new_folder = false;
                state.new_folder_input.clear();
                state.new_folder_parent.clear();
            }
            if ui.small_button("✕").clicked() {
                state.show_new_folder = false;
                state.new_folder_input.clear();
                state.new_folder_parent.clear();
            }
        });
    } else {
        let btn = egui::Button::new(RichText::new("  ＋ New Folder").color(dim).small()).frame(false);
        if ui.add(btn).clicked() {
            state.show_new_folder = true;
            state.new_folder_just_opened = true;
            state.new_folder_parent.clear();
            state.new_folder_input.clear();
        }
    }

    ui.separator();

    // -------------------------------------------------------------------
    // TAGS
    // -------------------------------------------------------------------
    let all_tags = store.all_tags();
    if !all_tags.is_empty() {
        ui.label(RichText::new("  TAGS").small().color(dim));
        ui.add_space(2.0);
        for tag in &all_tags {
            let is_active = state.active_tag.as_deref() == Some(tag.as_str());
            let col = if is_active { accent } else { Color32::PLACEHOLDER };
            let label = RichText::new(format!("  🏷  {tag}")).color(col);
            if ui.selectable_label(is_active, label).clicked() {
                state.active_tag = if is_active { None } else { Some(tag.clone()) };
                if state.active_tag.is_some() {
                    state.active_folder = None;
                }
            }
        }
        ui.separator();
    }

    // -------------------------------------------------------------------
    // NOTES list
    // -------------------------------------------------------------------
    ui.label(RichText::new("  NOTES").small().color(dim));
    ui.add_space(2.0);

    let query = state.search_query.to_lowercase();
    let note_ids: Vec<Uuid> = store
        .notes
        .iter()
        .filter(|n| {
            let folder_ok = state.active_folder.is_none()
                || n.folder.as_deref() == state.active_folder.as_deref();
            let tag_ok = state.active_tag.is_none()
                || n.tags.iter().any(|t| Some(t.as_str()) == state.active_tag.as_deref());
            let search_ok = query.is_empty()
                || n.title.to_lowercase().contains(&query)
                || n.tags.iter().any(|t| t.to_lowercase().contains(&query));
            folder_ok && tag_ok && search_ok
        })
        .map(|n| n.id)
        .collect();

    let mut note_to_delete: Option<Uuid> = None;
    let mut note_rename_done: Option<(Uuid, String)> = None;

    for id in note_ids {
        let (title, _folder) = store
            .notes
            .iter()
            .find(|n| n.id == id)
            .map(|n| (n.title.clone(), n.folder.clone()))
            .unwrap_or_default();

        let is_selected = state.selected_note == Some(id);

        if state.renaming_note == Some(id) {
            ui.horizontal(|ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut state.rename_buffer).desired_width(130.0),
                );
                resp.request_focus();
                let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                let esc   = ui.input(|i| i.key_pressed(Key::Escape));
                if enter {
                    note_rename_done = Some((id, state.rename_buffer.clone()));
                }
                if esc {
                    state.renaming_note = None;
                }
            });
        } else {
            let display = if title.is_empty() { "(Untitled)".to_string() } else { title.clone() };
            let col = if is_selected { accent } else { Color32::PLACEHOLDER };
            let resp = ui.selectable_label(is_selected, RichText::new(format!("  {display}")).color(col));
            if resp.clicked() {
                state.selected_note = Some(id);
            }
            if resp.double_clicked() {
                state.renaming_note = Some(id);
                state.rename_buffer = title.clone();
            }
            resp.context_menu(|ui| {
                if ui.button("✏ Rename").clicked() {
                    state.renaming_note = Some(id);
                    state.rename_buffer = title.clone();
                    ui.close_menu();
                }
                if ui.button("🗑 Delete note").clicked() {
                    note_to_delete = Some(id);
                    ui.close_menu();
                }
            });
        }
    }

    if let Some((id, new_title)) = note_rename_done {
        let trimmed = new_title.trim().to_string();
        if !trimmed.is_empty() {
            if let Some(note) = store.get_mut(id) {
                note.title = trimmed;
                note.touch();
                *dirty_flag = true;
            }
        }
        state.renaming_note = None;
    }
    if let Some(id) = note_to_delete {
        store.remove_note(id);
        if state.selected_note == Some(id) {
            state.selected_note = None;
        }
        *dirty_flag = true;
    }

    ui.add_space(6.0);

    // -------------------------------------------------------------------
    // New Note button
    // -------------------------------------------------------------------
    let btn = egui::Button::new(RichText::new("  ＋  New Note").color(Color32::WHITE).strong())
        .fill(accent)
        .min_size(egui::vec2(sidebar_width - 16.0, 28.0));
    if ui.add(btn).clicked() {
        let mut note = Note::new(state.active_folder.clone());
        let aad = note.id.as_bytes().to_vec();
        let (nk, wrapped) = new_note_key(mk, &aad);
        note.note_key_wrapped = wrapped;
        note.body_enc = encrypt_note_body(&nk, "", &aad).unwrap_or_default();
        let id = note.id;
        store.add_note(note);
        state.selected_note = Some(id);
        *dirty_flag = true;
    }
}

// ---------------------------------------------------------------------------
// Recursive folder node renderer
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn render_folder_node(
    ui: &mut Ui,
    node: &FolderNode,
    state: &mut SidebarState,
    store: &NotesStore,
    accent: Color32,
    dim: Color32,
    depth: usize,
    folder_to_delete: &mut Option<String>,
    folder_renamed: &mut Option<(String, String)>,
    new_subfolder_parent: &mut Option<String>,
) {
    let indent = depth as f32 * 14.0;
    let is_expanded = state.expanded_folders.contains(&node.path);
    let is_selected = state.active_folder.as_deref() == Some(node.path.as_str());
    let note_count = store
        .notes
        .iter()
        .filter(|n| n.folder.as_deref() == Some(&node.path))
        .count();

    // Inline rename row
    if state.renaming_folder.as_deref() == Some(node.path.as_str()) {
        ui.horizontal(|ui| {
            ui.add_space(indent + 4.0);
            let resp = ui.add(
                egui::TextEdit::singleline(&mut state.folder_rename_buffer).desired_width(120.0),
            );
            resp.request_focus();
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
            let esc   = ui.input(|i| i.key_pressed(Key::Escape));
            if enter {
                *folder_renamed = Some((node.path.clone(), state.folder_rename_buffer.trim().to_string()));
            }
            if esc {
                state.renaming_folder = None;
            }
        });
        return;
    }

    let chevron = if node.children.is_empty() {
        "  "
    } else if is_expanded {
        "▾ "
    } else {
        "▸ "
    };

    let count_str = if note_count > 0 { format!(" {note_count}") } else { String::new() };
    let indent_str = "  ".repeat(depth);
    let label_text = format!("{indent_str}{chevron}📁 {}{count_str}", node.name);
    let text = if is_selected {
        RichText::new(label_text).color(accent)
    } else {
        RichText::new(label_text).color(dim)
    };

    ui.horizontal(|ui| {
        ui.add_space(indent);
        let row = ui.selectable_label(is_selected, text);
        if row.clicked() {
            if !node.children.is_empty() {
                if is_expanded {
                    state.expanded_folders.remove(&node.path);
                } else {
                    state.expanded_folders.insert(node.path.clone());
                }
            }
            state.active_folder = Some(node.path.clone());
            state.active_tag = None;
        }
        row.context_menu(|ui| {
            if depth < MAX_FOLDER_DEPTH - 1 && ui.button("📁 New subfolder").clicked() {
                    *new_subfolder_parent = Some(node.path.clone());
                    ui.close_menu();
                }
            if ui.button("✏ Rename").clicked() {
                state.renaming_folder = Some(node.path.clone());
                state.folder_rename_buffer = node.name.clone();
                ui.close_menu();
            }
            if ui.button("🗑 Delete").clicked() {
                *folder_to_delete = Some(node.path.clone());
                ui.close_menu();
            }
        });
    });

    if is_expanded {
        for child in &node.children {
            render_folder_node(
                ui, child, state, store, accent, dim, depth + 1,
                folder_to_delete, folder_renamed, new_subfolder_parent,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rename_folder_in_store(store: &mut NotesStore, old: &str, new: &str) {
    let updated: Vec<String> = store
        .folders
        .iter()
        .map(|f| {
            if f == old {
                new.to_string()
            } else if f.starts_with(&format!("{old}/")) {
                format!("{new}{}", &f[old.len()..])
            } else {
                f.clone()
            }
        })
        .collect();
    store.folders = updated;

    for note in &mut store.notes {
        if let Some(folder) = note.folder.clone() {
            if folder == old {
                note.folder = Some(new.to_string());
            } else if folder.starts_with(&format!("{old}/")) {
                note.folder = Some(format!("{new}{}", &folder[old.len()..]));
            }
        }
    }
}
