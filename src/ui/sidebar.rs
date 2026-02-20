//! Sidebar — VS Code Explorer-style unified tree.
//!
//! All Notes
//!   ▾ folder1
//!       note-a
//!       note-b
//!   ▾ folder2
//!       ▾ subfolder
//!           note-c
//!   note-at-root      ← root-level notes
//!
//! Selected row: transparent accent bg (15-20% alpha) + 2 px left bar.
//! No separate "FOLDERS" / "NOTES" section headers.

use std::collections::HashSet;

use egui::{
    pos2, vec2, Color32, Key, Rect, RichText, Sense, Stroke, Ui,
};
use uuid::Uuid;

use crate::crypto::keys::MasterKey;
use crate::crypto::vault::{encrypt_note_body, new_note_key};
use crate::store::notes::{Note, NotesStore, ThemeName};
use crate::ui::theme;

// ---------------------------------------------------------------------------
const MAX_FOLDERS: usize = 1000;
pub const MAX_FOLDER_DEPTH: usize = 5;
const ROW_H: f32 = 24.0;

// ---------------------------------------------------------------------------
// Public state
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
pub struct SidebarState {
    pub selected_note: Option<Uuid>,
    pub active_folder: Option<String>,
    pub active_tag: Option<String>,
    pub search_query: String,

    pub new_folder_input: String,
    pub show_new_folder: bool,
    pub new_folder_just_opened: bool,
    pub new_folder_parent: String,

    pub expanded_folders: HashSet<String>,

    pub renaming_note: Option<Uuid>,
    pub rename_buffer: String,

    pub renaming_folder: Option<String>,
    pub folder_rename_buffer: String,
}

// ---------------------------------------------------------------------------
// Tree model
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
        let segs: Vec<&str> = path.split('/').collect();
        insert_node(&mut roots, &segs, 0);
    }
    roots
}

fn insert_node(nodes: &mut Vec<FolderNode>, segs: &[&str], depth: usize) {
    if depth >= segs.len() { return; }
    let full = segs[..=depth].join("/");
    if let Some(i) = nodes.iter().position(|n| n.path == full) {
        insert_node(&mut nodes[i].children, segs, depth + 1);
    } else {
        nodes.push(FolderNode {
            path: full,
            name: segs[depth].to_string(),
            children: Vec::new(),
        });
        let last = nodes.len() - 1;
        insert_node(&mut nodes[last].children, segs, depth + 1);
    }
}

// ---------------------------------------------------------------------------
// Entry point
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
    let accent   = theme::accent_color(current_theme);
    let dim      = theme::dim_color(current_theme);
    let row_sel  = theme::row_selected(current_theme);
    let sep_col  = theme::separator_color(current_theme);
    let text_col = theme::text_color(current_theme);

    ui.set_min_width(sidebar_width);

    // ── Search bar ──────────────────────────────────────────────────────────
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        ui.label(RichText::new("⌕").size(14.0).color(dim));
        let search = ui.add(
            egui::TextEdit::singleline(&mut state.search_query)
                .hint_text("Search…")
                .desired_width(f32::INFINITY)
                .frame(false),
        );
        if search.changed() && !state.search_query.is_empty() {
            for f in &store.folders.clone() {
                state.expanded_folders.insert(f.clone());
            }
        }
        if !state.search_query.is_empty()
            && ui.label(RichText::new("✕").small().color(dim))
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
        {
            state.search_query.clear();
        }
    });
    ui.add_space(4.0);
    thin_separator(ui, sep_col);
    ui.add_space(4.0);

    // ── Scrollable tree ─────────────────────────────────────────────────────
    let mut folder_to_delete: Option<String> = None;
    let mut folder_renamed: Option<(String, String)> = None;
    let mut new_subfolder_parent: Option<String> = None;
    let mut note_to_delete: Option<Uuid> = None;
    let mut note_rename_done: Option<(Uuid, String)> = None;
    let mut note_selected: Option<Uuid> = None;
    let mut folder_activated: Option<Option<String>> = None; // None = root, Some(path) = folder

    egui::ScrollArea::vertical()
        .id_salt("sidebar_scroll")
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing = vec2(0.0, 0.0);

            let query = state.search_query.to_lowercase();

            // Root "All Notes" header row
            let root_selected = state.active_folder.is_none()
                && state.active_tag.is_none()
                && state.selected_note.is_none();

            if row_item(ui, 0, "  All Notes", root_selected, false, accent, row_sel, dim, text_col).clicked() {
                folder_activated = Some(None);
                // keep selected_note as is — just filter to all
            }

            let tree = build_tree(&store.folders.clone());

            for node in &tree {
                render_folder_subtree(
                    ui, node, state, store, &query,
                    accent, dim, row_sel, sep_col, text_col,
                    0, sidebar_width,
                    &mut folder_to_delete, &mut folder_renamed,
                    &mut new_subfolder_parent, &mut note_to_delete,
                    &mut note_rename_done, &mut note_selected,
                    &mut folder_activated,
                );
            }

            // Root-level notes (no folder)
            let root_notes: Vec<(Uuid, String)> = store.notes.iter()
                .filter(|n| n.folder.is_none())
                .filter(|n| {
                    query.is_empty()
                        || n.title.to_lowercase().contains(&query)
                        || n.tags.iter().any(|t| t.to_lowercase().contains(&query))
                })
                .map(|n| (n.id, n.title.clone()))
                .collect();

            for (id, title) in root_notes {
                render_note_row(
                    ui, id, &title, 1,
                    state, accent, row_sel, dim, text_col,
                    &mut note_to_delete, &mut note_rename_done, &mut note_selected,
                );
            }

            // New-folder inline input
            if state.show_new_folder {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_space(16.0);
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut state.new_folder_input)
                            .hint_text("Folder name…")
                            .desired_width(sidebar_width - 70.0),
                    );
                    if state.new_folder_just_opened {
                        resp.request_focus();
                        state.new_folder_just_opened = false;
                    }
                    let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                    if enter || ui.small_button("✓").clicked() {
                        let raw = state.new_folder_input.trim().to_string();
                        if !raw.is_empty() && store.folders.len() < MAX_FOLDERS {
                            let parent_depth = if state.new_folder_parent.is_empty() { 0 }
                            else { state.new_folder_parent.matches('/').count() + 1 };
                            if parent_depth < MAX_FOLDER_DEPTH {
                                let full = if state.new_folder_parent.is_empty() { raw }
                                else { format!("{}/{}", state.new_folder_parent, raw) };
                                store.add_folder(full.clone());
                                state.expanded_folders.insert(full.clone());
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
            }

            // Tag chips
            let all_tags = store.all_tags();
            if !all_tags.is_empty() {
                ui.add_space(8.0);
                thin_separator(ui, sep_col);
                ui.add_space(6.0);
                ui.horizontal_wrapped(|ui| {
                    ui.add_space(8.0);
                    for tag in &all_tags {
                        let is_active = state.active_tag.as_deref() == Some(tag.as_str());
                        let chip = egui::Button::new(
                            RichText::new(format!("# {tag}"))
                                .size(11.0)
                                .color(if is_active { accent } else { dim }),
                        )
                        .fill(if is_active { row_sel } else { Color32::TRANSPARENT })
                        .stroke(Stroke::new(0.5, sep_col))
                        .rounding(10.0);
                        if ui.add(chip).clicked() {
                            state.active_tag = if is_active { None } else { Some(tag.clone()) };
                            if state.active_tag.is_some() { state.active_folder = None; }
                        }
                    }
                });
            }
        });

    // ── Mutations ───────────────────────────────────────────────────────────
    if let Some(sel) = note_selected       { state.selected_note = Some(sel); }
    if let Some(fa) = folder_activated    { state.active_folder = fa; state.active_tag = None; }
    if let Some((id, t)) = note_rename_done {
        let trimmed = t.trim().to_string();
        if !trimmed.is_empty() {
            if let Some(note) = store.get_mut(id) { note.title = trimmed; note.touch(); *dirty_flag = true; }
        }
        state.renaming_note = None;
    }
    if let Some(id) = note_to_delete {
        store.remove_note(id);
        if state.selected_note == Some(id) { state.selected_note = None; }
        *dirty_flag = true;
    }
    if let Some((old, new_name)) = folder_renamed {
        // Compose full new path: keep parent prefix, replace only the last segment
        let new_path = if let Some(pos) = old.rfind('/') {
            format!("{}/{}", &old[..pos], new_name)
        } else {
            new_name.clone()
        };
        if !new_name.is_empty() && !store.folders.contains(&new_path) {
            rename_folder_in_store(store, &old, &new_path);
            if state.active_folder.as_deref() == Some(&old) { state.active_folder = Some(new_path); }
            state.renaming_folder = None;
            *dirty_flag = true;
        }
    }
    if let Some(f) = folder_to_delete {
        store.remove_folder(&f);
        if state.active_folder.as_deref() == Some(f.as_str()) { state.active_folder = None; }
        *dirty_flag = true;
    }
    if let Some(parent) = new_subfolder_parent {
        state.show_new_folder = true;
        state.new_folder_just_opened = true;
        state.new_folder_parent = parent;
        state.new_folder_input.clear();
    }

    // ── Bottom action row ───────────────────────────────────────────────────
    thin_separator(ui, sep_col);
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        let nn = egui::Button::new(RichText::new("+ New Note").color(Color32::WHITE))
            .fill(accent)
            .rounding(4.0);
        if ui.add(nn).clicked() {
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
        ui.add_space(4.0);
        let nf = egui::Button::new(RichText::new("📁").color(dim))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::new(1.0, sep_col))
            .rounding(4.0);
        if ui.add(nf).on_hover_text("New folder").clicked() {
            state.show_new_folder = true;
            state.new_folder_just_opened = true;
            state.new_folder_parent.clear();
            state.new_folder_input.clear();
        }
    });
    ui.add_space(6.0);
}

// ---------------------------------------------------------------------------
// Render folder + its children recursively
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments, clippy::only_used_in_recursion)]
fn render_folder_subtree(
    ui: &mut Ui,
    node: &FolderNode,
    state: &mut SidebarState,
    store: &NotesStore,
    query: &str,
    accent: Color32,
    dim: Color32,
    row_sel: Color32,
    sep_col: Color32,
    text_col: Color32,
    depth: usize,
    sidebar_width: f32,
    folder_to_delete: &mut Option<String>,
    folder_renamed: &mut Option<(String, String)>,
    new_subfolder_parent: &mut Option<String>,
    note_to_delete: &mut Option<Uuid>,
    note_rename_done: &mut Option<(Uuid, String)>,
    note_selected: &mut Option<Uuid>,
    folder_activated: &mut Option<Option<String>>,
) {
    let is_expanded   = state.expanded_folders.contains(&node.path);
    let is_sel        = state.active_folder.as_deref() == Some(node.path.as_str());

    let folder_notes: Vec<(Uuid, String)> = store.notes.iter()
        .filter(|n| n.folder.as_deref() == Some(node.path.as_str()))
        .filter(|n| {
            query.is_empty()
                || n.title.to_lowercase().contains(query)
                || n.tags.iter().any(|t| t.to_lowercase().contains(query))
        })
        .map(|n| (n.id, n.title.clone()))
        .collect();

    let has_children = !node.children.is_empty() || !folder_notes.is_empty();
    let chevron = if !has_children { "  " } else if is_expanded { "v " } else { "> " };
    let count_badge = if !folder_notes.is_empty() { format!("  {}", folder_notes.len()) } else { String::new() };
    let label = format!("{chevron}📁 {}{count_badge}", node.name);

    // Inline rename
    if state.renaming_folder.as_deref() == Some(node.path.as_str()) {
        ui.horizontal(|ui| {
            ui.add_space((depth + 1) as f32 * 12.0);
            let r = ui.add(
                egui::TextEdit::singleline(&mut state.folder_rename_buffer)
                    .desired_width(sidebar_width - (depth + 1) as f32 * 12.0 - 30.0),
            );
            r.request_focus();
            if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                *folder_renamed = Some((node.path.clone(), state.folder_rename_buffer.trim().to_string()));
            }
            if ui.input(|i| i.key_pressed(Key::Escape)) { state.renaming_folder = None; }
        });
        return;
    }

    let resp = row_item(ui, depth + 1, &label, is_sel, has_children, accent, row_sel, dim, text_col);

    if resp.clicked() {
        if has_children {
            if is_expanded { state.expanded_folders.remove(&node.path); }
            else { state.expanded_folders.insert(node.path.clone()); }
        }
        *folder_activated = Some(Some(node.path.clone()));
    }

    resp.context_menu(|ui| {
        if depth < MAX_FOLDER_DEPTH - 1 && ui.button("📁 New subfolder").clicked() {
            *new_subfolder_parent = Some(node.path.clone());
            ui.close_menu();
        }
        if ui.button("✏ Rename folder").clicked() {
            state.renaming_folder = Some(node.path.clone());
            state.folder_rename_buffer = node.name.clone();
            ui.close_menu();
        }
        if ui.button("🗑 Delete folder").clicked() {
            *folder_to_delete = Some(node.path.clone());
            ui.close_menu();
        }
    });

    if is_expanded {
        for child in &node.children {
            render_folder_subtree(
                ui, child, state, store, query,
                accent, dim, row_sel, sep_col, text_col,
                depth + 1, sidebar_width,
                folder_to_delete, folder_renamed, new_subfolder_parent,
                note_to_delete, note_rename_done, note_selected, folder_activated,
            );
        }
        for (id, title) in folder_notes {
            render_note_row(
                ui, id, &title, depth + 2,
                state, accent, row_sel, dim, text_col,
                note_to_delete, note_rename_done, note_selected,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Note row
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn render_note_row(
    ui: &mut Ui,
    id: Uuid,
    title: &str,
    depth: usize,
    state: &mut SidebarState,
    accent: Color32,
    row_sel: Color32,
    dim: Color32,
    text_col: Color32,
    note_to_delete: &mut Option<Uuid>,
    note_rename_done: &mut Option<(Uuid, String)>,
    note_selected: &mut Option<Uuid>,
) {
    let is_selected = state.selected_note == Some(id);

    if state.renaming_note == Some(id) {
        ui.horizontal(|ui| {
            ui.add_space(depth as f32 * 12.0 + 4.0);
            let r = ui.add(
                egui::TextEdit::singleline(&mut state.rename_buffer).desired_width(140.0),
            );
            r.request_focus();
            if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                *note_rename_done = Some((id, state.rename_buffer.clone()));
            }
            if ui.input(|i| i.key_pressed(Key::Escape)) { state.renaming_note = None; }
        });
        return;
    }

    let display = if title.is_empty() { "Untitled" } else { title };
    let label = format!("  {display}");
    let resp  = row_item(ui, depth, &label, is_selected, false, accent, row_sel, dim, text_col);

    if resp.clicked()        { *note_selected = Some(id); }
    if resp.double_clicked() { state.renaming_note = Some(id); state.rename_buffer = title.to_string(); }

    resp.context_menu(|ui| {
        if ui.button("✏ Rename").clicked() {
            state.renaming_note = Some(id);
            state.rename_buffer = title.to_string();
            ui.close_menu();
        }
        if ui.button("🗑 Delete note").clicked() {
            *note_to_delete = Some(id);
            ui.close_menu();
        }
    });
}

// ---------------------------------------------------------------------------
// Core row primitive — VS Code-style:
//   [2 px accent bar if selected] [indent] [label text]
//   bg = row_sel when selected, row_sel*0.5 on hover
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn row_item(
    ui: &mut Ui,
    depth: usize,
    label: &str,
    is_selected: bool,
    _has_chevron: bool,
    accent: Color32,
    row_sel: Color32,
    dim: Color32,
    text_col: Color32,
) -> egui::Response {
    let indent = depth as f32 * 12.0;
    let width  = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(vec2(width, ROW_H), Sense::click());

    if ui.is_rect_visible(rect) {
        let painter = ui.painter();
        // Background
        let bg = if is_selected { row_sel }
                 else if resp.hovered() { row_sel.linear_multiply(0.55) }
                 else { Color32::TRANSPARENT };
        painter.rect_filled(rect, 0.0, bg);

        // 2 px left accent bar
        if is_selected {
            painter.rect_filled(
                Rect::from_min_size(rect.left_top(), vec2(2.0, ROW_H)),
                0.0,
                accent,
            );
        }

        // Text
        let col = if is_selected { text_col } else { dim };
        let galley = painter.layout_no_wrap(
            label.to_string(),
            egui::FontId::proportional(13.0),
            col,
        );
        let tp = pos2(
            rect.left() + indent + 6.0,
            rect.center().y - galley.size().y * 0.5,
        );
        painter.galley(tp, galley, col);
    }

    resp
}

// ---------------------------------------------------------------------------
// Thin 1 px separator
// ---------------------------------------------------------------------------

fn thin_separator(ui: &mut Ui, color: Color32) {
    let r = ui.available_rect_before_wrap();
    ui.painter().hline(r.x_range(), r.top(), Stroke::new(1.0, color));
    ui.add_space(1.0);
}

// ---------------------------------------------------------------------------
// Rename folder in store
// ---------------------------------------------------------------------------

fn rename_folder_in_store(store: &mut NotesStore, old: &str, new: &str) {
    store.folders = store.folders.iter().map(|f| {
        if f == old { new.to_string() }
        else if f.starts_with(&format!("{old}/")) { format!("{new}{}", &f[old.len()..]) }
        else { f.clone() }
    }).collect();

    for note in &mut store.notes {
        if let Some(folder) = &note.folder.clone() {
            if folder == old { note.folder = Some(new.to_string()); }
            else if folder.starts_with(&format!("{old}/")) {
                note.folder = Some(format!("{new}{}", &folder[old.len()..]));
            }
        }
    }
}
