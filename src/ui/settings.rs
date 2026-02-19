//! Settings panel — idle lock timeout and focus-loss lock toggle.

use egui::Ui;

use crate::store::notes::AppSettings;

/// Returns `true` if the user clicked the Back button.
pub fn show(ui: &mut Ui, settings: &mut AppSettings, settings_changed: &mut bool) -> bool {
    let mut go_back = false;

    ui.horizontal(|ui| {
        if ui.button("< Back").clicked() {
            go_back = true;
        }
        ui.heading("Settings");
    });
    ui.separator();
    ui.add_space(8.0);

    ui.label("Auto-lock after idle:");
    egui::ComboBox::from_id_salt("idle_lock")
        .selected_text(idle_label(settings.idle_lock_minutes))
        .show_ui(ui, |ui| {
            for (mins, label) in &[(0u32, "Never"), (2, "2 minutes"), (5, "5 minutes"), (15, "15 minutes")] {
                if ui.selectable_value(&mut settings.idle_lock_minutes, *mins, *label).changed() {
                    *settings_changed = true;
                }
            }
        });

    ui.add_space(8.0);

    if ui
        .checkbox(&mut settings.lock_on_focus_loss, "Lock when app loses focus")
        .changed()
    {
        *settings_changed = true;
    }

    ui.add_space(16.0);
    ui.separator();
    ui.add_space(8.0);

    ui.label(
        egui::RichText::new("Security notes")
            .strong(),
    );
    ui.label("• The master key is locked in RAM (VirtualLock) and zeroized on lock.");
    ui.label("• For full disk-at-rest protection, disable hibernation in Windows.");
    ui.label("• Clipboard contents are not cleared automatically — be mindful.");
    ui.label("• Windows Hello protects against offline/disk attackers only.");

    go_back
}

fn idle_label(mins: u32) -> &'static str {
    match mins {
        0 => "Never",
        2 => "2 minutes",
        5 => "5 minutes",
        15 => "15 minutes",
        _ => "Custom",
    }
}
