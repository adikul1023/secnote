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
            bg:           Color32::from_rgba_unmultiplied(0x1a, 0x1b, 0x26, 0xa0),
            bg_panel:     Color32::from_rgba_unmultiplied(0x16, 0x17, 0x22, 0x98),
            bg_widget:    Color32::from_rgba_unmultiplied(0x24, 0x28, 0x3b, 0xb8),
            bg_editor:    Color32::from_rgba_unmultiplied(0x1a, 0x1b, 0x26, 0xc8),
            text:         Color32::from_rgb(0xc4, 0xc8, 0xd4),  // desaturated: less purple tint
            text_dim:     Color32::from_rgb(0x68, 0x6d, 0x7a),  // desaturated: less purple
            accent:       Color32::from_rgb(0x7d, 0x9e, 0xd4),  // desaturated blue
            selection_bg: Color32::from_rgba_unmultiplied(0x7d, 0x9e, 0xd4, 0x38),
            row_selected: Color32::from_rgba_unmultiplied(0x7d, 0x9e, 0xd4, 0x22),
            separator:    Color32::from_rgba_unmultiplied(0x7d, 0x9e, 0xd4, 0x1e),
        },
        ThemeName::CatppuccinMocha => Palette {
            bg:           Color32::from_rgba_unmultiplied(0x1e, 0x1e, 0x2e, 0xa0),
            bg_panel:     Color32::from_rgba_unmultiplied(0x18, 0x18, 0x25, 0x98),
            bg_widget:    Color32::from_rgba_unmultiplied(0x31, 0x32, 0x44, 0xb8),
            bg_editor:    Color32::from_rgba_unmultiplied(0x1e, 0x1e, 0x2e, 0xc8),
            text:         Color32::from_rgb(0xcb, 0xce, 0xd8),  // desaturated
            text_dim:     Color32::from_rgb(0x62, 0x64, 0x72),  // desaturated
            accent:       Color32::from_rgb(0x88, 0xaa, 0xd8),  // desaturated blue
            selection_bg: Color32::from_rgba_unmultiplied(0x88, 0xaa, 0xd8, 0x38),
            row_selected: Color32::from_rgba_unmultiplied(0x88, 0xaa, 0xd8, 0x22),
            separator:    Color32::from_rgba_unmultiplied(0x88, 0xaa, 0xd8, 0x1e),
        },
        ThemeName::Gruvbox => Palette {
            bg:           Color32::from_rgba_unmultiplied(0x28, 0x28, 0x28, 0xa0),
            bg_panel:     Color32::from_rgba_unmultiplied(0x1d, 0x20, 0x21, 0x98),
            bg_widget:    Color32::from_rgba_unmultiplied(0x3c, 0x38, 0x36, 0xb8),
            bg_editor:    Color32::from_rgba_unmultiplied(0x28, 0x28, 0x28, 0xc8),
            text:         Color32::from_rgb(0xd8, 0xd2, 0xc0),  // desaturated warm
            text_dim:     Color32::from_rgb(0x8a, 0x84, 0x78),  // desaturated
            accent:       Color32::from_rgb(0xcc, 0xa8, 0x40),  // desaturated gold
            selection_bg: Color32::from_rgba_unmultiplied(0xcc, 0xa8, 0x40, 0x32),
            row_selected: Color32::from_rgba_unmultiplied(0xcc, 0xa8, 0x40, 0x20),
            separator:    Color32::from_rgba_unmultiplied(0xcc, 0xa8, 0x40, 0x1c),
        },
        ThemeName::Nord => Palette {
            bg:           Color32::from_rgba_unmultiplied(0x2e, 0x34, 0x40, 0xa0),
            bg_panel:     Color32::from_rgba_unmultiplied(0x24, 0x27, 0x32, 0x98),
            bg_widget:    Color32::from_rgba_unmultiplied(0x3b, 0x42, 0x52, 0xb8),
            bg_editor:    Color32::from_rgba_unmultiplied(0x2e, 0x34, 0x40, 0xc8),
            text:         Color32::from_rgb(0xd2, 0xd6, 0xdc),  // desaturated
            text_dim:     Color32::from_rgb(0x68, 0x72, 0x84),  // desaturated
            accent:       Color32::from_rgb(0x80, 0xaa, 0xb8),  // desaturated teal
            selection_bg: Color32::from_rgba_unmultiplied(0x80, 0xaa, 0xb8, 0x38),
            row_selected: Color32::from_rgba_unmultiplied(0x80, 0xaa, 0xb8, 0x22),
            separator:    Color32::from_rgba_unmultiplied(0x80, 0xaa, 0xb8, 0x1e),
        },
        ThemeName::OneDark => Palette {
            bg:           Color32::from_rgba_unmultiplied(0x28, 0x2c, 0x34, 0xa0),
            bg_panel:     Color32::from_rgba_unmultiplied(0x21, 0x25, 0x2b, 0x98),
            bg_widget:    Color32::from_rgba_unmultiplied(0x3e, 0x44, 0x51, 0xb8),
            bg_editor:    Color32::from_rgba_unmultiplied(0x28, 0x2c, 0x34, 0xc8),
            text:         Color32::from_rgb(0xb0, 0xb6, 0xbf),  // desaturated
            text_dim:     Color32::from_rgb(0x64, 0x69, 0x72),  // desaturated
            accent:       Color32::from_rgb(0x62, 0xa0, 0xd8),  // desaturated blue
            selection_bg: Color32::from_rgba_unmultiplied(0x62, 0xa0, 0xd8, 0x38),
            row_selected: Color32::from_rgba_unmultiplied(0x62, 0xa0, 0xd8, 0x22),
            separator:    Color32::from_rgba_unmultiplied(0x62, 0xa0, 0xd8, 0x1e),
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

    // Text: set via fg_stroke.color (not override_text_color) so hyperlinks
    // can use their own hyperlink_color without being clobbered.
    // (override_text_color would override ALL text including links.)
    visuals.widgets.noninteractive.bg_fill         = Color32::TRANSPARENT;
    visuals.widgets.noninteractive.weak_bg_fill    = Color32::TRANSPARENT;
    visuals.widgets.noninteractive.fg_stroke       = Stroke::new(0.0, p.text); // width=0 → no border; color → text
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
    // Hyperlinks: amber/orange — distinguishable from any theme's blue/gray text
    visuals.hyperlink_color                        = Color32::from_rgb(0xe0, 0xa8, 0x40);

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
