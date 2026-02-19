use egui::{Color32, Context, FontId, Rounding, Stroke, Visuals};

use crate::store::notes::ThemeName;

struct Palette {
    bg: Color32,
    bg_panel: Color32,
    bg_widget: Color32,
    text: Color32,
    text_dim: Color32,
    accent: Color32,
    selection_bg: Color32,
}

fn palette(theme: ThemeName) -> Palette {
    match theme {
        ThemeName::TokyoNight => Palette {
            bg:           Color32::from_rgb(0x1a, 0x1b, 0x26),
            bg_panel:     Color32::from_rgba_premultiplied(0x16, 0x17, 0x22, 0xf0),
            bg_widget:    Color32::from_rgb(0x24, 0x28, 0x3b),
            text:         Color32::from_rgb(0xc0, 0xca, 0xf5),
            text_dim:     Color32::from_rgb(0x56, 0x5f, 0x89),
            accent:       Color32::from_rgb(0x7a, 0xa2, 0xf7),
            selection_bg: Color32::from_rgba_premultiplied(0x7a, 0xa2, 0xf7, 0x50),
        },
        ThemeName::CatppuccinMocha => Palette {
            bg:           Color32::from_rgb(0x1e, 0x1e, 0x2e),
            bg_panel:     Color32::from_rgba_premultiplied(0x18, 0x18, 0x25, 0xf0),
            bg_widget:    Color32::from_rgb(0x31, 0x32, 0x44),
            text:         Color32::from_rgb(0xcd, 0xd6, 0xf4),
            text_dim:     Color32::from_rgb(0x58, 0x5b, 0x70),
            accent:       Color32::from_rgb(0x89, 0xb4, 0xfa),
            selection_bg: Color32::from_rgba_premultiplied(0x89, 0xb4, 0xfa, 0x50),
        },
        ThemeName::Gruvbox => Palette {
            bg:           Color32::from_rgb(0x28, 0x28, 0x28),
            bg_panel:     Color32::from_rgba_premultiplied(0x1d, 0x20, 0x21, 0xf0),
            bg_widget:    Color32::from_rgb(0x3c, 0x38, 0x36),
            text:         Color32::from_rgb(0xeb, 0xdb, 0xb2),
            text_dim:     Color32::from_rgb(0x92, 0x83, 0x74),
            accent:       Color32::from_rgb(0xfa, 0xbd, 0x2f),
            selection_bg: Color32::from_rgba_premultiplied(0xfa, 0xbd, 0x2f, 0x40),
        },
        ThemeName::Nord => Palette {
            bg:           Color32::from_rgb(0x2e, 0x34, 0x40),
            bg_panel:     Color32::from_rgba_premultiplied(0x24, 0x27, 0x32, 0xf0),
            bg_widget:    Color32::from_rgb(0x3b, 0x42, 0x52),
            text:         Color32::from_rgb(0xd8, 0xde, 0xe9),
            text_dim:     Color32::from_rgb(0x61, 0x6e, 0x88),
            accent:       Color32::from_rgb(0x88, 0xc0, 0xd0),
            selection_bg: Color32::from_rgba_premultiplied(0x88, 0xc0, 0xd0, 0x50),
        },
        ThemeName::OneDark => Palette {
            bg:           Color32::from_rgb(0x28, 0x2c, 0x34),
            bg_panel:     Color32::from_rgba_premultiplied(0x21, 0x25, 0x2b, 0xf0),
            bg_widget:    Color32::from_rgb(0x3e, 0x44, 0x51),
            text:         Color32::from_rgb(0xab, 0xb2, 0xbf),
            text_dim:     Color32::from_rgb(0x5c, 0x63, 0x70),
            accent:       Color32::from_rgb(0x61, 0xaf, 0xef),
            selection_bg: Color32::from_rgba_premultiplied(0x61, 0xaf, 0xef, 0x50),
        },
    }
}

/// Apply the chosen theme to the egui context. Call once per frame before UI.
pub fn apply_theme(ctx: &Context, theme: ThemeName) {
    let p = palette(theme);

    let mut visuals = Visuals::dark();

    // Window / panel backgrounds
    visuals.window_fill                             = p.bg;
    visuals.panel_fill                             = p.bg_panel;
    visuals.extreme_bg_color                       = p.bg;
    visuals.faint_bg_color                         = p.bg_widget;

    // Text
    visuals.override_text_color                    = Some(p.text);

    // Widgets
    visuals.widgets.noninteractive.bg_fill         = p.bg_panel;
    visuals.widgets.noninteractive.fg_stroke       = Stroke::new(0.0, p.text_dim);
    visuals.widgets.noninteractive.rounding        = Rounding::same(4.0);

    visuals.widgets.inactive.bg_fill               = p.bg_widget;
    visuals.widgets.inactive.fg_stroke             = Stroke::new(0.0, p.text);
    visuals.widgets.inactive.rounding              = Rounding::same(4.0);

    visuals.widgets.hovered.bg_fill                = p.accent.linear_multiply(0.2);
    visuals.widgets.hovered.fg_stroke              = Stroke::new(1.0, p.accent);
    visuals.widgets.hovered.rounding               = Rounding::same(4.0);

    visuals.widgets.active.bg_fill                 = p.accent.linear_multiply(0.3);
    visuals.widgets.active.fg_stroke               = Stroke::new(1.0, p.accent);
    visuals.widgets.active.rounding                = Rounding::same(4.0);

    visuals.widgets.open.bg_fill                   = p.bg_widget;
    visuals.widgets.open.fg_stroke                 = Stroke::new(1.0, p.accent);
    visuals.widgets.open.rounding                  = Rounding::same(4.0);

    // Selection / hyperlinks
    visuals.selection.bg_fill                      = p.selection_bg;
    visuals.selection.stroke                       = Stroke::new(1.0, p.accent);
    visuals.hyperlink_color                        = p.accent;

    // Window chrome
    visuals.window_stroke                          = Stroke::new(1.0, p.bg_widget);
    visuals.window_rounding                        = Rounding::same(8.0);

    ctx.set_visuals(visuals);

    // Font sizes
    use egui::TextStyle;
    use std::collections::BTreeMap;
    let mut styles = (*ctx.style()).clone();
    let base = 14.0_f32;
    styles.text_styles = BTreeMap::from([
        (TextStyle::Small,   FontId::monospace(base - 2.0)),
        (TextStyle::Body,    FontId::monospace(base)),
        (TextStyle::Monospace, FontId::monospace(base)),
        (TextStyle::Button,  FontId::monospace(base)),
        (TextStyle::Heading, FontId::proportional(base + 4.0)),
    ]);
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
    let mk = if monospace {
        |sz: f32| FontId::monospace(sz)
    } else {
        |sz: f32| FontId::proportional(sz)
    };
    styles.text_styles = BTreeMap::from([
        (TextStyle::Small,     mk(font_size - 2.0)),
        (TextStyle::Body,      mk(font_size)),
        (TextStyle::Monospace, FontId::monospace(font_size)),
        (TextStyle::Button,    mk(font_size)),
        (TextStyle::Heading,   FontId::proportional(font_size + 4.0)),
    ]);
    ctx.set_style(styles);
}

/// Return the accent color for the current theme (used by tabs, cursors, etc.)
pub fn accent_color(theme: ThemeName) -> Color32 {
    palette(theme).accent
}

/// Return the dim text color for the current theme.
pub fn dim_color(theme: ThemeName) -> Color32 {
    palette(theme).text_dim
}

/// Return the widget background color for the current theme.
pub fn widget_bg(theme: ThemeName) -> Color32 {
    palette(theme).bg_widget
}
