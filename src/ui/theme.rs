use egui::{Color32, Context, FontId, Rounding, Stroke, Visuals};

use crate::store::notes::ThemeName;

struct Palette {
    bg: Color32,
    bg_panel: Color32,   // sidebar / panels — semi-transparent so Mica shows through
    bg_widget: Color32,  // text inputs, buttons
    bg_editor: Color32,  // editor area — slightly more opaque for readability
    text: Color32,
    text_dim: Color32,
    accent: Color32,
    selection_bg: Color32,
    // VS Code-style selected row: accent at ~15% alpha
    row_selected: Color32,
    // 1-px separator lines
    separator: Color32,
}

fn palette(theme: ThemeName) -> Palette {
    match theme {
        ThemeName::TokyoNight => Palette {
            bg:           Color32::from_rgba_unmultiplied(0x1a, 0x1b, 0x26, 0xb0),
            bg_panel:     Color32::from_rgba_unmultiplied(0x16, 0x17, 0x22, 0xa8),
            bg_widget:    Color32::from_rgba_unmultiplied(0x24, 0x28, 0x3b, 0xc8),
            bg_editor:    Color32::from_rgba_unmultiplied(0x1a, 0x1b, 0x26, 0xd8),
            text:         Color32::from_rgb(0xc0, 0xca, 0xf5),
            text_dim:     Color32::from_rgb(0x56, 0x5f, 0x89),
            accent:       Color32::from_rgb(0x7a, 0xa2, 0xf7),
            selection_bg: Color32::from_rgba_unmultiplied(0x7a, 0xa2, 0xf7, 0x40),
            row_selected: Color32::from_rgba_unmultiplied(0x7a, 0xa2, 0xf7, 0x26),
            separator:    Color32::from_rgba_unmultiplied(0x7a, 0xa2, 0xf7, 0x22),
        },
        ThemeName::CatppuccinMocha => Palette {
            bg:           Color32::from_rgba_unmultiplied(0x1e, 0x1e, 0x2e, 0xb0),
            bg_panel:     Color32::from_rgba_unmultiplied(0x18, 0x18, 0x25, 0xa8),
            bg_widget:    Color32::from_rgba_unmultiplied(0x31, 0x32, 0x44, 0xc8),
            bg_editor:    Color32::from_rgba_unmultiplied(0x1e, 0x1e, 0x2e, 0xd8),
            text:         Color32::from_rgb(0xcd, 0xd6, 0xf4),
            text_dim:     Color32::from_rgb(0x58, 0x5b, 0x70),
            accent:       Color32::from_rgb(0x89, 0xb4, 0xfa),
            selection_bg: Color32::from_rgba_unmultiplied(0x89, 0xb4, 0xfa, 0x40),
            row_selected: Color32::from_rgba_unmultiplied(0x89, 0xb4, 0xfa, 0x26),
            separator:    Color32::from_rgba_unmultiplied(0x89, 0xb4, 0xfa, 0x22),
        },
        ThemeName::Gruvbox => Palette {
            bg:           Color32::from_rgba_unmultiplied(0x28, 0x28, 0x28, 0xb0),
            bg_panel:     Color32::from_rgba_unmultiplied(0x1d, 0x20, 0x21, 0xa8),
            bg_widget:    Color32::from_rgba_unmultiplied(0x3c, 0x38, 0x36, 0xc8),
            bg_editor:    Color32::from_rgba_unmultiplied(0x28, 0x28, 0x28, 0xd8),
            text:         Color32::from_rgb(0xeb, 0xdb, 0xb2),
            text_dim:     Color32::from_rgb(0x92, 0x83, 0x74),
            accent:       Color32::from_rgb(0xfa, 0xbd, 0x2f),
            selection_bg: Color32::from_rgba_unmultiplied(0xfa, 0xbd, 0x2f, 0x35),
            row_selected: Color32::from_rgba_unmultiplied(0xfa, 0xbd, 0x2f, 0x22),
            separator:    Color32::from_rgba_unmultiplied(0xfa, 0xbd, 0x2f, 0x20),
        },
        ThemeName::Nord => Palette {
            bg:           Color32::from_rgba_unmultiplied(0x2e, 0x34, 0x40, 0xb0),
            bg_panel:     Color32::from_rgba_unmultiplied(0x24, 0x27, 0x32, 0xa8),
            bg_widget:    Color32::from_rgba_unmultiplied(0x3b, 0x42, 0x52, 0xc8),
            bg_editor:    Color32::from_rgba_unmultiplied(0x2e, 0x34, 0x40, 0xd8),
            text:         Color32::from_rgb(0xd8, 0xde, 0xe9),
            text_dim:     Color32::from_rgb(0x61, 0x6e, 0x88),
            accent:       Color32::from_rgb(0x88, 0xc0, 0xd0),
            selection_bg: Color32::from_rgba_unmultiplied(0x88, 0xc0, 0xd0, 0x40),
            row_selected: Color32::from_rgba_unmultiplied(0x88, 0xc0, 0xd0, 0x26),
            separator:    Color32::from_rgba_unmultiplied(0x88, 0xc0, 0xd0, 0x22),
        },
        ThemeName::OneDark => Palette {
            bg:           Color32::from_rgba_unmultiplied(0x28, 0x2c, 0x34, 0xb0),
            bg_panel:     Color32::from_rgba_unmultiplied(0x21, 0x25, 0x2b, 0xa8),
            bg_widget:    Color32::from_rgba_unmultiplied(0x3e, 0x44, 0x51, 0xc8),
            bg_editor:    Color32::from_rgba_unmultiplied(0x28, 0x2c, 0x34, 0xd8),
            text:         Color32::from_rgb(0xab, 0xb2, 0xbf),
            text_dim:     Color32::from_rgb(0x5c, 0x63, 0x70),
            accent:       Color32::from_rgb(0x61, 0xaf, 0xef),
            selection_bg: Color32::from_rgba_unmultiplied(0x61, 0xaf, 0xef, 0x40),
            row_selected: Color32::from_rgba_unmultiplied(0x61, 0xaf, 0xef, 0x26),
            separator:    Color32::from_rgba_unmultiplied(0x61, 0xaf, 0xef, 0x22),
        },
    }
}

/// Apply the chosen theme to the egui context. Call once per frame before UI.
pub fn apply_theme(ctx: &Context, theme: ThemeName) {
    let p = palette(theme);

    let mut visuals = Visuals::dark();

    // All panel/window fills are semi-transparent — Mica/Acrylic bleeds through.
    visuals.window_fill                             = p.bg;
    visuals.panel_fill                             = p.bg_panel;
    visuals.extreme_bg_color                       = Color32::TRANSPARENT;
    visuals.faint_bg_color                         = p.bg_widget;

    // Remove default window shadow / stroke noise
    visuals.window_shadow                          = egui::Shadow::NONE;
    visuals.popup_shadow                           = egui::Shadow::NONE;

    // Text
    visuals.override_text_color                    = Some(p.text);

    // Widgets — no borders, rounded, subtle tones
    visuals.widgets.noninteractive.bg_fill         = Color32::TRANSPARENT;
    visuals.widgets.noninteractive.weak_bg_fill    = Color32::TRANSPARENT;
    visuals.widgets.noninteractive.fg_stroke       = Stroke::new(0.0, Color32::TRANSPARENT);
    visuals.widgets.noninteractive.bg_stroke       = Stroke::NONE;
    visuals.widgets.noninteractive.rounding        = Rounding::same(3.0);

    visuals.widgets.inactive.bg_fill               = p.bg_widget;
    visuals.widgets.inactive.weak_bg_fill          = p.bg_widget;
    visuals.widgets.inactive.fg_stroke             = Stroke::new(0.0, p.text);
    visuals.widgets.inactive.bg_stroke             = Stroke::NONE;
    visuals.widgets.inactive.rounding              = Rounding::same(3.0);

    visuals.widgets.hovered.bg_fill                = p.row_selected;
    visuals.widgets.hovered.weak_bg_fill           = p.row_selected;
    visuals.widgets.hovered.fg_stroke              = Stroke::new(0.0, p.accent);
    visuals.widgets.hovered.bg_stroke             = Stroke::NONE;
    visuals.widgets.hovered.rounding               = Rounding::same(3.0);

    visuals.widgets.active.bg_fill                 = p.selection_bg;
    visuals.widgets.active.weak_bg_fill            = p.selection_bg;
    visuals.widgets.active.fg_stroke               = Stroke::new(0.0, p.accent);
    visuals.widgets.active.bg_stroke               = Stroke::NONE;
    visuals.widgets.active.rounding                = Rounding::same(3.0);

    visuals.widgets.open.bg_fill                   = p.bg_widget;
    visuals.widgets.open.fg_stroke                 = Stroke::new(1.0, p.accent);
    visuals.widgets.open.rounding                  = Rounding::same(3.0);

    // Selection
    visuals.selection.bg_fill                      = p.selection_bg;
    visuals.selection.stroke                       = Stroke::new(1.0, p.accent);
    visuals.hyperlink_color                        = p.accent;

    // No visible window border
    visuals.window_stroke                          = Stroke::new(0.0, Color32::TRANSPARENT);
    visuals.window_rounding                        = Rounding::same(8.0);

    // Subtle separators
    visuals.widgets.noninteractive.bg_stroke       = Stroke::new(0.0, p.separator);

    ctx.set_visuals(visuals);

    // Font sizes
    use egui::TextStyle;
    use std::collections::BTreeMap;
    let mut styles = (*ctx.style()).clone();
    let base = 13.0_f32;
    styles.text_styles = BTreeMap::from([
        (TextStyle::Small,     FontId::proportional(base - 1.0)),
        (TextStyle::Body,      FontId::proportional(base)),
        (TextStyle::Monospace, FontId::monospace(base)),
        (TextStyle::Button,    FontId::proportional(base)),
        (TextStyle::Heading,   FontId::proportional(base + 3.0)),
    ]);
    // Tighter spacing
    styles.spacing.item_spacing       = egui::vec2(6.0, 2.0);
    styles.spacing.button_padding     = egui::vec2(6.0, 2.0);
    styles.spacing.window_margin      = egui::Margin::same(0.0);
    styles.spacing.indent             = 12.0;
    ctx.set_style(styles);
}

/// Apply theme with custom font size and family preference.
pub fn apply_theme_with_font(
    ctx: &Context,
    theme: ThemeName,
    font_size: f32,
    monospace: bool,
) {
    apply_theme(ctx, theme);

    use egui::TextStyle;
    use std::collections::BTreeMap;
    let mut styles = (*ctx.style()).clone();
    let body_font = if monospace {
        |sz: f32| FontId::monospace(sz)
    } else {
        |sz: f32| FontId::proportional(sz)
    };
    styles.text_styles = BTreeMap::from([
        (TextStyle::Small,     FontId::proportional(font_size - 2.0)),
        (TextStyle::Body,      body_font(font_size)),
        (TextStyle::Monospace, FontId::monospace(font_size)),
        (TextStyle::Button,    FontId::proportional(font_size - 1.0)),
        (TextStyle::Heading,   FontId::proportional(font_size + 3.0)),
    ]);
    ctx.set_style(styles);
}

pub fn accent_color(theme: ThemeName) -> Color32   { palette(theme).accent }
pub fn dim_color(theme: ThemeName) -> Color32      { palette(theme).text_dim }
pub fn widget_bg(theme: ThemeName) -> Color32      { palette(theme).bg_widget }
pub fn row_selected(theme: ThemeName) -> Color32   { palette(theme).row_selected }
pub fn separator_color(theme: ThemeName) -> Color32 { palette(theme).separator }
#[allow(dead_code)]
pub fn editor_bg(theme: ThemeName) -> Color32      { palette(theme).bg_editor }
pub fn text_color(theme: ThemeName) -> Color32     { palette(theme).text }
