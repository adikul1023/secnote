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
            .with_min_inner_size([640.0, 400.0])
            .with_transparent(true),
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

// ---------------------------------------------------------------------------
// Windows Mica / Acrylic backdrop
// ---------------------------------------------------------------------------

/// Attempt to enable Mica (Windows 11) or Acrylic (Windows 10) backdrop on a
/// window found by its title. Call once after the window is created.
/// Silently no-ops on failure (older Windows, Wine, etc.).
#[cfg(target_os = "windows")]
pub fn try_enable_mica(window_title: &str) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_SYSTEMBACKDROP_TYPE,
    };
    use windows::Win32::UI::WindowsAndMessaging::FindWindowW;

    let title: Vec<u16> = window_title
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let hwnd: HWND = unsafe {
        FindWindowW(windows::core::PCWSTR::null(), windows::core::PCWSTR(title.as_ptr())).unwrap_or_default()
    };

    if hwnd.0.is_null() {
        return;
    }

    // DWMSBT_MAINWINDOW = 2 (Mica), DWMSBT_TRANSIENTWINDOW = 3 (Acrylic)
    let backdrop_type: u32 = 2; // Mica
    unsafe {
        let _ = DwmSetWindowAttribute(
            hwnd,
            DWMWA_SYSTEMBACKDROP_TYPE,
            &backdrop_type as *const u32 as *const std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
        );
    }
}

#[cfg(not(target_os = "windows"))]
pub fn try_enable_mica(_window_title: &str) {}
