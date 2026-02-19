//! Secure Notes — encrypted offline note-taking app.
//!
//! Security properties:
//!   • AES-256-GCM encryption for all notes at rest
//!   • Windows Hello (TPM) as authentication gate — no extra password needed
//!   • 24-word BIP-39 recovery key for PIN-change / Hello reset scenarios
//!   • Master key locked in RAM via VirtualLock (no swap exposure)
//!   • config.json integrity enforced with HMAC-SHA256
//!   • Auto-save with atomic rename — crash-safe
//!   • Auto-lock on idle (default 5 min) and optional lock on focus loss
//!
//! NOT protected against:
//!   • Malware running as the same user
//!   • Admin/SYSTEM memory dumps while unlocked
//!   • Clipboard contents (warn in settings, not auto-cleared in v1)

#![windows_subsystem = "windows"]

mod app;
mod auth;
mod crypto;
mod save;
mod store;
mod ui;

use app::SecureNotesApp;

fn main() -> eframe::Result<()> {
    // Show a MessageBox for any unhandled panic so the user isn't left with
    // a silently-vanishing window (since we have #![windows_subsystem = "windows"]).
    install_panic_hook();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Secure Notes")
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([640.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Secure Notes",
        options,
        Box::new(|cc| Ok(Box::new(SecureNotesApp::new(cc)))),
    )
}

fn install_panic_hook() {
    // VULN-M4 FIX: Only show the source location (file + line) — never the
    // panic message/payload, which could contain key material or partial
    // plaintext that was being processed at the time of the panic.
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".into());
        let msg = format!(
            "Secure Notes encountered an unexpected error and must close.\n\n\
             Location: {location}\n\n\
             If this keeps happening, please report the location above."
        );
        show_error_box(&msg);
    }));
}

#[cfg(target_os = "windows")]
fn show_error_box(msg: &str) {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    let title: Vec<u16> = "Secure Notes — Error"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let body: Vec<u16> = msg
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_ICONERROR | MB_OK,
        );
    }
}

#[cfg(not(target_os = "windows"))]
fn show_error_box(msg: &str) {
    eprintln!("{msg}");
}
