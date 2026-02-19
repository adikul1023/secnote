//! Command palette — Ctrl+P floating fuzzy finder (notes + commands).

use std::collections::VecDeque;

use egui::{Color32, Context, Key, RichText, Window};
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use uuid::Uuid;

use crate::store::notes::{NotesStore, ThemeName};
use crate::ui::theme;

// ---------------------------------------------------------------------------
// Public commands the palette can fire
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum PaletteAction {
    OpenNote(Uuid),
    NewNote,
    Lock,
    OpenSettings,
    /// Nothing to do — user dismissed the palette
    Dismiss,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

pub struct CommandPalette {
    pub visible: bool,
    query: String,
    results: Vec<PaletteEntry>,
    selected_idx: usize,
    /// Set to true on the first frame so we can auto-focus the input
    just_opened: bool,
}

#[derive(Clone)]
struct PaletteEntry {
    label: String,
    action: PaletteAction,
    score: i64,
}

#[allow(clippy::derivable_impls)]
impl Default for CommandPalette {
    fn default() -> Self {
        Self {
            visible: false,
            query: String::new(),
            results: Vec::new(),
            selected_idx: 0,
            just_opened: false,
        }
    }
}

impl CommandPalette {
    /// Open the palette and reset state.
    pub fn open(&mut self) {
        self.visible = true;
        self.query.clear();
        self.results.clear();
        self.selected_idx = 0;
        self.just_opened = true;
    }

    pub fn close(&mut self) {
        self.visible = false;
        self.query.clear();
    }

    /// Rebuild the result list from the current query + note store.
    fn rebuild(&mut self, store: &NotesStore) {
        let matcher = SkimMatcherV2::default();
        let q = self.query.trim();

        let mut entries: Vec<PaletteEntry> = Vec::new();

        if q.starts_with('>') {
            // Command mode
            let cmd = q.trim_start_matches('>').trim().to_lowercase();
            let commands: &[(&str, PaletteAction)] = &[
                ("New Note",      PaletteAction::NewNote),
                ("Lock Vault",    PaletteAction::Lock),
                ("Open Settings", PaletteAction::OpenSettings),
            ];
            for (label, action) in commands {
                let score = if cmd.is_empty() {
                    1
                } else {
                    matcher.fuzzy_match(label, &cmd).unwrap_or(0)
                };
                if score > 0 || cmd.is_empty() {
                    entries.push(PaletteEntry {
                        label: format!("> {label}"),
                        action: action.clone(),
                        score,
                    });
                }
            }
        } else {
            // Note search mode
            for note in &store.notes {
                let title = if note.title.is_empty() { "(Untitled)" } else { &note.title };
                let score = if q.is_empty() {
                    1
                } else {
                    matcher.fuzzy_match(title, q).unwrap_or(0)
                };
                if score > 0 || q.is_empty() {
                    entries.push(PaletteEntry {
                        label: title.to_string(),
                        action: PaletteAction::OpenNote(note.id),
                        score,
                    });
                }
            }
            // Sort by score descending, then alphabetically
            entries.sort_by(|a, b| b.score.cmp(&a.score).then(a.label.cmp(&b.label)));

            // Show at most 12 for note mode
            entries.truncate(12);

            // Always show the "New Note" command at the bottom when not in command mode
            entries.push(PaletteEntry {
                label: "> New Note".to_string(),
                action: PaletteAction::NewNote,
                score: 0,
            });
        }

        self.results = entries;
        self.selected_idx = self.selected_idx.min(self.results.len().saturating_sub(1));
    }

    /// Draw the palette and return an action if the user triggered one.
    pub fn show(
        &mut self,
        ctx: &Context,
        store: &NotesStore,
        current_theme: ThemeName,
    ) -> Option<PaletteAction> {
        if !self.visible {
            // Close on Escape even when not shown (just in case)
            return None;
        }

        let accent = theme::accent_color(current_theme);
        let widget_bg = theme::widget_bg(current_theme);
        let dim = theme::dim_color(current_theme);

        // Rebuild on query change
        self.rebuild(store);

        let mut action: Option<PaletteAction> = None;

        // Handle keyboard navigation outside the window closure
        let key_down  = ctx.input(|i| i.key_pressed(Key::ArrowDown));
        let key_up    = ctx.input(|i| i.key_pressed(Key::ArrowUp));
        let key_enter = ctx.input(|i| i.key_pressed(Key::Enter));
        let key_esc   = ctx.input(|i| i.key_pressed(Key::Escape));

        if key_down && !self.results.is_empty() {
            self.selected_idx = (self.selected_idx + 1).min(self.results.len() - 1);
        }
        if key_up && self.selected_idx > 0 {
            self.selected_idx -= 1;
        }
        if key_esc {
            self.close();
            return Some(PaletteAction::Dismiss);
        }
        if key_enter {
            if let Some(entry) = self.results.get(self.selected_idx).cloned() {
                self.close();
                return Some(entry.action);
            }
        }

        let screen_rect = ctx.screen_rect();
        let palette_w = 520.0_f32.min(screen_rect.width() - 40.0);
        let palette_x = screen_rect.center().x - palette_w / 2.0;

        Window::new("##command_palette")
            .title_bar(false)
            .resizable(false)
            .collapsible(false)
            .fixed_pos([palette_x, screen_rect.top() + 80.0])
            .fixed_size([palette_w, 400.0])
            .frame(
                egui::Frame::window(&ctx.style())
                    .fill(widget_bg)
                    .inner_margin(egui::Margin::same(8.0))
                    .rounding(egui::Rounding::same(8.0)),
            )
            .show(ctx, |ui| {
                // Input field
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .hint_text("Search notes or type '>' for commands…")
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Body),
                );
                if self.just_opened {
                    resp.request_focus();
                    self.just_opened = false;
                }

                ui.separator();

                // Results list
                egui::ScrollArea::vertical()
                    .max_height(320.0)
                    .show(ui, |ui| {
                        for (i, entry) in self.results.iter().enumerate() {
                            let is_sel = i == self.selected_idx;
                            let bg = if is_sel {
                                accent.linear_multiply(0.25)
                            } else {
                                Color32::TRANSPARENT
                            };

                            let text = if is_sel {
                                RichText::new(&entry.label).color(accent).strong()
                            } else {
                                RichText::new(&entry.label)
                            };

                            let resp = egui::Frame::none()
                                .fill(bg)
                                .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                                .rounding(egui::Rounding::same(4.0))
                                .show(ui, |ui| {
                                    ui.add(egui::Label::new(text).wrap_mode(egui::TextWrapMode::Truncate))
                                });

                            if resp.response.clicked() || resp.inner.clicked() {
                                action = Some(entry.action.clone());
                            }
                        }

                        if self.results.is_empty() {
                            ui.label(RichText::new("No results").color(dim).italics());
                        }
                    });
            });

        if let Some(act) = action {
            self.close();
            return Some(act);
        }

        None
    }
}

// ---------------------------------------------------------------------------
// Recent notes queue (used by TabBar, shared here for convenience)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub struct RecentQueue {
    pub ids: VecDeque<Uuid>,
    pub max: usize,
}

#[allow(dead_code)]
impl RecentQueue {
    pub fn new(max: usize) -> Self {
        Self { ids: VecDeque::new(), max }
    }

    pub fn push(&mut self, id: Uuid) {
        self.ids.retain(|&x| x != id);
        self.ids.push_front(id);
        while self.ids.len() > self.max {
            self.ids.pop_back();
        }
    }

    pub fn remove(&mut self, id: Uuid) {
        self.ids.retain(|&x| x != id);
    }
}
