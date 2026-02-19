//! Tab bar — compact recent-note tabs (max 8), shown below the toolbar.

use std::collections::VecDeque;

use egui::{Color32, Frame, Margin, Pos2, Sense, TopBottomPanel, Ui, Vec2};
use uuid::Uuid;

use crate::store::notes::{NotesStore, ThemeName};
use crate::ui::theme;

const MAX_TABS: usize = 8;
const TAB_HEIGHT: f32 = 28.0;
const TAB_MIN_WIDTH: f32 = 80.0;
const TAB_MAX_WIDTH: f32 = 180.0;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct TabBar {
    pub recents: VecDeque<Uuid>,
}

impl TabBar {
    /// Push a note to the front (most recent). Evicts oldest if > MAX_TABS.
    pub fn push(&mut self, id: Uuid) {
        self.recents.retain(|&x| x != id);
        self.recents.push_front(id);
        while self.recents.len() > MAX_TABS {
            self.recents.pop_back();
        }
    }

    /// Remove a tab (e.g. after note deletion).
    pub fn remove(&mut self, id: Uuid) {
        self.recents.retain(|&x| x != id);
    }

    /// Draw the tab bar as a top panel. Returns the note id that was clicked (if any).
    /// `close_id` is set to the id of a tab whose × was clicked.
    pub fn show(
        &mut self,
        ctx: &egui::Context,
        store: &NotesStore,
        selected: Option<Uuid>,
        current_theme: ThemeName,
    ) -> TabBarResponse {
        let accent    = theme::accent_color(current_theme);
        let dim       = theme::dim_color(current_theme);
        let widget_bg = theme::widget_bg(current_theme);

        let mut response = TabBarResponse::default();

        if self.recents.is_empty() {
            return response;
        }

        TopBottomPanel::top("tab_bar")
            .frame(Frame::none().fill(widget_bg).inner_margin(Margin::symmetric(4.0, 0.0)))
            .min_height(TAB_HEIGHT)
            .max_height(TAB_HEIGHT)
            .show(ctx, |ui: &mut Ui| {
                egui::ScrollArea::horizontal()
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;

                            let tab_ids: Vec<Uuid> = self.recents.iter().copied().collect();
                            for id in tab_ids {
                                let title = store
                                    .notes
                                    .iter()
                                    .find(|n| n.id == id)
                                    .map(|n| {
                                        if n.title.is_empty() {
                                            "(Untitled)".to_string()
                                        } else {
                                            n.title.clone()
                                        }
                                    })
                                    .unwrap_or_else(|| "(Deleted)".to_string());

                                let is_active = selected == Some(id);
                                let tab_text_col = if is_active { accent } else { dim };

                                // Truncate title so it fits in max width
                                let display_title: String = title.chars().take(20).collect();

                                let tab_w = ((display_title.len() as f32 * 7.5) + 28.0)
                                    .clamp(TAB_MIN_WIDTH, TAB_MAX_WIDTH);

                                let (rect, tab_resp) = ui.allocate_exact_size(
                                    Vec2::new(tab_w, TAB_HEIGHT),
                                    Sense::click(),
                                );

                                if tab_resp.clicked() {
                                    response.activated = Some(id);
                                }

                                // Background
                                let bg = if is_active {
                                    theme::widget_bg(current_theme).linear_multiply(1.2)
                                } else if tab_resp.hovered() {
                                    theme::widget_bg(current_theme)
                                } else {
                                    Color32::TRANSPARENT
                                };
                                ui.painter().rect_filled(rect, 0.0, bg);

                                // Accent underline for active tab
                                if is_active {
                                    let underline = egui::Rect::from_min_size(
                                        Pos2::new(rect.left(), rect.bottom() - 2.0),
                                        Vec2::new(rect.width(), 2.0),
                                    );
                                    ui.painter().rect_filled(underline, 0.0, accent);
                                }

                                // Title label
                                let text_rect = egui::Rect::from_min_size(
                                    Pos2::new(rect.left() + 6.0, rect.top()),
                                    Vec2::new(rect.width() - 22.0, rect.height()),
                                );
                                ui.painter().text(
                                    text_rect.center_top() + Vec2::new(0.0, 6.0),
                                    egui::Align2::CENTER_TOP,
                                    &display_title,
                                    egui::FontId::proportional(12.0),
                                    tab_text_col,
                                );

                                // × close button
                                let close_rect = egui::Rect::from_min_size(
                                    Pos2::new(rect.right() - 18.0, rect.top() + 6.0),
                                    Vec2::splat(16.0),
                                );
                                let close_resp = ui.interact(close_rect, ui.id().with(("tab_close", id)), Sense::click());
                                let close_col = if close_resp.hovered() {
                                    Color32::from_rgb(0xe0, 0x60, 0x60)
                                } else {
                                    dim
                                };
                                ui.painter().text(
                                    close_rect.center(),
                                    egui::Align2::CENTER_CENTER,
                                    "×",
                                    egui::FontId::proportional(14.0),
                                    close_col,
                                );
                                if close_resp.clicked() {
                                    response.closed = Some(id);
                                }
                            }
                        });
                    });
            });

        response
    }
}

// ---------------------------------------------------------------------------
// Response type
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct TabBarResponse {
    /// User clicked a tab to switch to it
    pub activated: Option<Uuid>,
    /// User clicked × on a tab
    pub closed: Option<Uuid>,
}
