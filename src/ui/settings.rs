//! Settings panel — Appearance / Editor / Security / About sections.

use egui::{RichText, Ui};

use crate::store::notes::{AppSettings, FontFamily, ThemeName};

#[derive(Default, Clone, PartialEq, Eq)]
pub enum SettingsTab {
    #[default]
    Appearance,
    Editor,
    Security,
    About,
}

/// Returns `true` if the user clicked the Back button.
pub fn show(
    ui: &mut Ui,
    settings: &mut AppSettings,
    settings_changed: &mut bool,
    active_tab: &mut SettingsTab,
) -> bool {
    let mut go_back = false;

    // Header
    ui.horizontal(|ui| {
        if ui.button("< Back").clicked() {
            go_back = true;
        }
        ui.heading("Settings");
    });
    ui.separator();
    ui.add_space(4.0);

    // Tab bar
    ui.horizontal(|ui| {
        for (tab, label) in &[
            (SettingsTab::Appearance, "Appearance"),
            (SettingsTab::Editor,     "Editor"),
            (SettingsTab::Security,   "Security"),
            (SettingsTab::About,      "About"),
        ] {
            let selected = active_tab == tab;
            if ui.selectable_label(selected, *label).clicked() {
                *active_tab = tab.clone();
            }
        }
    });
    ui.separator();
    ui.add_space(8.0);

    match active_tab {
        SettingsTab::Appearance => show_appearance(ui, settings, settings_changed),
        SettingsTab::Editor     => show_editor(ui, settings, settings_changed),
        SettingsTab::Security   => show_security(ui, settings, settings_changed),
        SettingsTab::About      => show_about(ui),
    }

    go_back
}

// ---------------------------------------------------------------------------
// Appearance tab
// ---------------------------------------------------------------------------

fn show_appearance(ui: &mut Ui, settings: &mut AppSettings, settings_changed: &mut bool) {
    ui.label(RichText::new("Theme").strong());
    ui.add_space(4.0);

    for &theme in ThemeName::all() {
        let selected = settings.theme == theme;
        if ui.selectable_label(selected, theme.label()).clicked() {
            settings.theme = theme;
            *settings_changed = true;
        }
    }

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    ui.label(RichText::new("Sidebar width").strong());
    if ui
        .add(egui::Slider::new(&mut settings.sidebar_width, 160.0..=400.0).suffix(" px"))
        .changed()
    {
        *settings_changed = true;
    }

    ui.add_space(12.0);
    ui.label(RichText::new("Status bar").strong());
    if ui
        .checkbox(&mut settings.show_status_bar, "Show status bar at the bottom")
        .changed()
    {
        *settings_changed = true;
    }
}

// ---------------------------------------------------------------------------
// Editor tab
// ---------------------------------------------------------------------------

fn show_editor(ui: &mut Ui, settings: &mut AppSettings, settings_changed: &mut bool) {
    ui.label(RichText::new("Font size").strong());
    if ui
        .add(egui::Slider::new(&mut settings.font_size, 10.0..=24.0).suffix(" pt"))
        .changed()
    {
        *settings_changed = true;
    }

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    ui.label(RichText::new("Font family").strong());
    for &family in &[FontFamily::Monospace, FontFamily::Proportional] {
        let selected = settings.font_family == family;
        if ui.selectable_label(selected, family.label()).clicked() {
            settings.font_family = family;
            *settings_changed = true;
        }
    }

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    ui.label(RichText::new("Vim mode").strong());
    ui.label(
        RichText::new(
            "When enabled, the editor starts in NORMAL mode.\n\
             Press i or a to enter INSERT mode, Esc to return to NORMAL.",
        )
        .small()
        .color(egui::Color32::GRAY),
    );
    if ui
        .checkbox(&mut settings.vim_mode, "Enable vim-style keybindings")
        .changed()
    {
        *settings_changed = true;
    }
}

// ---------------------------------------------------------------------------
// Security tab
// ---------------------------------------------------------------------------

fn show_security(ui: &mut Ui, settings: &mut AppSettings, settings_changed: &mut bool) {
    ui.label(RichText::new("Auto-lock").strong());
    egui::ComboBox::from_id_salt("idle_lock")
        .selected_text(idle_label(settings.idle_lock_minutes))
        .show_ui(ui, |ui| {
            for (mins, label) in &[
                (0u32, "Never"),
                (2, "2 minutes"),
                (5, "5 minutes"),
                (15, "15 minutes"),
                (30, "30 minutes"),
            ] {
                if ui
                    .selectable_value(&mut settings.idle_lock_minutes, *mins, *label)
                    .changed()
                {
                    *settings_changed = true;
                }
            }
        });

    ui.add_space(12.0);

    if ui
        .checkbox(&mut settings.lock_on_focus_loss, "Lock when app loses focus")
        .changed()
    {
        *settings_changed = true;
    }

    ui.add_space(16.0);
    ui.separator();
    ui.add_space(8.0);

    ui.label(RichText::new("Security notes").strong());
    ui.add_space(4.0);
    for note in &[
        "The master key is locked in RAM (VirtualLock) and zeroized on lock.",
        "For full disk-at-rest protection, disable hibernation in Windows.",
        "Clipboard contents are not cleared automatically — be mindful.",
        "Windows Hello protects against offline / disk attackers only.",
        "Each note is encrypted with a unique AES-256-GCM per-note key.",
        "Config integrity is enforced with HMAC-SHA256.",
    ] {
        ui.label(RichText::new(format!("• {note}")).small());
    }
}

// ---------------------------------------------------------------------------
// About tab
// ---------------------------------------------------------------------------

fn show_about(ui: &mut Ui) {
    ui.label(RichText::new("Secure Notes").size(20.0).strong());
    ui.add_space(4.0);
    ui.label("Version: 0.2.0");
    ui.add_space(4.0);
    ui.label("An offline, encrypted note-taking app for Windows.");
    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    ui.label(RichText::new("Cryptography").strong());
    ui.label("• AES-256-GCM for note encryption");
    ui.label("• Windows Hello (TPM) as authentication gate");
    ui.label("• BIP-39 24-word recovery key (Argon2id-derived)");
    ui.label("• Windows DPAPI for MKEK at-rest protection");
    ui.label("• HMAC-SHA256 for config integrity");

    ui.add_space(12.0);
    ui.separator();
    ui.add_space(8.0);

    ui.label(RichText::new("Keyboard shortcuts").strong());
    egui::Grid::new("shortcuts_grid")
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            let shortcuts = [
                ("Ctrl+P",   "Open command palette"),
                ("Ctrl+N",   "New note"),
                ("Ctrl+W",   "Close active tab"),
                ("Ctrl+,",   "Open settings"),
                ("Ctrl+L",   "Lock vault"),
                ("Escape",   "Dismiss palette / Vim normal mode"),
                ("Ctrl+B",   "Bold (in editor)"),
                ("Ctrl+I",   "Italic (in editor)"),
            ];
            for (key, desc) in &shortcuts {
                ui.label(RichText::new(*key).monospace().strong());
                ui.label(*desc);
                ui.end_row();
            }
        });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn idle_label(mins: u32) -> &'static str {
    match mins {
        0 => "Never",
        2 => "2 minutes",
        5 => "5 minutes",
        15 => "15 minutes",
        30 => "30 minutes",
        _ => "Custom",
    }
}
