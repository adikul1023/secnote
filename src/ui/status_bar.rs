//! Status bar — bottom panel showing breadcrumb, word/char count, save state, idle timer,
//! and vim mode indicator.

use egui::{Color32, Frame, Margin, RichText, TopBottomPanel, Ui};

use crate::store::notes::ThemeName;
use crate::ui::theme;

/// Draw the status bar as a bottom panel.
/// Returns nothing — purely visual.
#[allow(clippy::too_many_arguments)]
pub fn show(
    ctx: &egui::Context,
    note_title: &str,
    folder_path: Option<&str>,
    word_count: usize,
    char_count: usize,
    save_status: &str,
    idle_secs: u64,
    lock_minutes: u32,
    vim_mode_enabled: bool,
    vim_is_normal: bool,
    current_theme: ThemeName,
) {
    let accent = theme::accent_color(current_theme);
    let dim    = theme::dim_color(current_theme);
    let bg     = theme::widget_bg(current_theme);

    TopBottomPanel::bottom("status_bar")
        .frame(Frame::none().fill(bg).inner_margin(Margin::symmetric(8.0, 3.0)))
        .min_height(22.0)
        .max_height(22.0)
        .show(ctx, |ui: &mut Ui| {
            ui.horizontal(|ui| {
                // Left: breadcrumb
                let breadcrumb = build_breadcrumb(folder_path, note_title);
                ui.label(RichText::new(&breadcrumb).small().color(dim));

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Vim mode indicator (rightmost)
                    if vim_mode_enabled {
                        let (label, col) = if vim_is_normal {
                            ("NRM", accent)
                        } else {
                            ("INS", Color32::from_rgb(0x98, 0xbb, 0x6c))
                        };
                        ui.label(RichText::new(label).small().strong().color(col));
                        ui.separator();
                    }

                    // Save indicator
                    ui.label(RichText::new(save_status).small().color(dim));
                    ui.separator();

                    // Idle / lock countdown
                    if lock_minutes > 0 {
                        let lock_secs = (lock_minutes as u64) * 60;
                        let remaining = lock_secs.saturating_sub(idle_secs);
                        let mins = remaining / 60;
                        let secs = remaining % 60;
                        let countdown = format!("🔒 {mins}:{secs:02}");
                        let col = if remaining < 60 {
                            Color32::from_rgb(0xe0, 0x60, 0x60)
                        } else {
                            dim
                        };
                        ui.label(RichText::new(countdown).small().color(col));
                        ui.separator();
                    }

                    // Word / char count
                    let count_text = format!("{word_count}W  {char_count}C");
                    ui.label(RichText::new(count_text).small().color(dim));
                });
            });
        });
}

fn build_breadcrumb(folder_path: Option<&str>, note_title: &str) -> String {
    match folder_path {
        Some(f) if !f.is_empty() => {
            let segments: Vec<&str> = f.split('/').collect();
            let parts = segments.join(" › ");
            format!("{parts} › {note_title}")
        }
        _ => note_title.to_string(),
    }
}
