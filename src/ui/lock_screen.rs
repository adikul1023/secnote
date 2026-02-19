//! Lock screen — Windows Hello unlock or 24-word recovery key entry.

use std::sync::mpsc;
use std::time::Instant;

use egui::{Color32, FontId, RichText, Ui};
use zeroize::Zeroize;

use crate::auth::windows_hello::{self, HelloResult};
use crate::crypto::keys::{
    derive_mkek, dpapi_protect, dpapi_unprotect, unwrap_key, wrap_key,
    verify_config_hmac, CryptoError, MasterKey, compute_config_hmac,
    AAD_WINHELLO_MK, AAD_RECOVERY_MK,
};
use crate::crypto::vault::decrypt_store;
use crate::store::notes::{AppConfig, AppSettings, NotesStore};

// ---------------------------------------------------------------------------
// Rate limiting constants (VULN-L4 FIX)
// After RECOVERY_MAX_ATTEMPTS failures the lock screen shows only a message.
// Delay doubles per failure: 2s, 4s, 8s, 16s … cap at 60s.
// ---------------------------------------------------------------------------
const RECOVERY_MAX_ATTEMPTS: u32 = 10;
const RECOVERY_BASE_DELAY_SECS: u64 = 2;
const RECOVERY_MAX_DELAY_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Result returned to app.rs on successful unlock
// ---------------------------------------------------------------------------

pub struct UnlockResult {
    pub master_key: MasterKey,
    pub store: NotesStore,
    /// Updated config (may have had config_hmac refreshed after recovery re-enroll)
    pub config: AppConfig,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum LockMode {
    Hello,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    Idle,
    Authenticating,
    Error(String),
    TamperDetected,
    // VULN-L1 FIX: dedicated state for re-enrollment after recovery
    ReEnrolling,
}

pub struct LockScreen {
    mode: LockMode,
    state: State,
    auth_rx: Option<mpsc::Receiver<HelloResult<Vec<u8>>>>,
    /// VULN-L1 FIX: store the re-enrollment receiver so we can check its result
    enroll_rx: Option<mpsc::Receiver<HelloResult<()>>>,
    recovery_input: String,
    recovery_error: Option<String>,
    /// VULN-L4 FIX: count of failed recovery attempts
    recovery_failures: u32,
    /// VULN-L4 FIX: when Some, we are in a cooldown period until this instant
    recovery_locked_until: Option<Instant>,
    /// Set when unlock succeeds — taken by app.rs
    pub result: Option<UnlockResult>,
    /// Encrypted notes blob (loaded from disk before showing lock screen)
    pub encrypted_notes: Vec<u8>,
    pub config: AppConfig,
    pub settings: AppSettings,
}

impl LockScreen {
    pub fn new(config: AppConfig, settings: AppSettings, encrypted_notes: Vec<u8>) -> Self {
        Self {
            mode: LockMode::Hello,
            state: State::Idle,
            auth_rx: None,
            enroll_rx: None,
            recovery_input: String::new(),
            recovery_error: None,
            recovery_failures: 0,
            recovery_locked_until: None,
            result: None,
            encrypted_notes,
            config,
            settings,
        }
    }

    pub fn show(&mut self, ui: &mut Ui) {
        self.poll_channel();

        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.label(
                RichText::new("🔒 Secure Notes")
                    .font(FontId::proportional(28.0))
                    .strong(),
            );
            ui.add_space(24.0);

            match &self.state.clone() {
                State::Idle => {}
                State::Authenticating => {
                    ui.spinner();
                    ui.add_space(8.0);
                    ui.label("Waiting for Windows Hello…");
                    ui.ctx().request_repaint();
                    return;
                }
                // VULN-L1 FIX: show specific message while re-enrolling
                State::ReEnrolling => {
                    ui.spinner();
                    ui.add_space(8.0);
                    ui.label("Re-enrolling Windows Hello credential…");
                    ui.ctx().request_repaint();
                    return;
                }
                State::TamperDetected => {
                    ui.label(
                        RichText::new("⛔ Configuration file has been tampered with.")
                            .color(Color32::RED)
                            .size(16.0),
                    );
                    ui.add_space(8.0);
                    ui.label("Cannot unlock. The encrypted config.json has been modified externally.");
                    return;
                }
                State::Error(e) => {
                    ui.colored_label(Color32::RED, e);
                    ui.add_space(8.0);
                }
            }

            match self.mode {
                LockMode::Hello => self.show_hello_panel(ui),
                LockMode::Recovery => self.show_recovery_panel(ui),
            }
        });
    }

    fn show_hello_panel(&mut self, ui: &mut Ui) {
        if ui
            .button(RichText::new("🪪  Unlock with Windows Hello").size(16.0))
            .clicked()
        {
            self.start_auth();
        }

        ui.add_space(24.0);
        if ui
            .small_button("Use 24-word recovery key instead")
            .clicked()
        {
            self.mode = LockMode::Recovery;
            self.state = State::Idle;
        }
    }

    fn show_recovery_panel(&mut self, ui: &mut Ui) {
        // VULN-L4 FIX: show lockout message if still in cooldown
        if let Some(until) = self.recovery_locked_until {
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.as_secs() > 0 {
                ui.label(
                    RichText::new(format!(
                        "Too many failed attempts. Try again in {}s.",
                        remaining.as_secs() + 1
                    ))
                    .color(Color32::YELLOW),
                );
                ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));
                if ui.small_button("← Back to Windows Hello").clicked() {
                    self.mode = LockMode::Hello;
                    self.state = State::Idle;
                }
                return;
            } else {
                self.recovery_locked_until = None;
            }
        }

        if self.recovery_failures >= RECOVERY_MAX_ATTEMPTS {
            ui.label(
                RichText::new("Maximum recovery attempts reached. Please restart the application.")
                    .color(Color32::RED),
            );
            return;
        }

        ui.label("Enter your 24-word recovery key (space-separated):");
        ui.add_space(8.0);

        ui.add(
            egui::TextEdit::multiline(&mut self.recovery_input)
                .desired_rows(4)
                .desired_width(400.0)
                .hint_text("word1 word2 word3 …"),
        );

        ui.add_space(8.0);

        if let Some(err) = &self.recovery_error {
            ui.colored_label(Color32::RED, err);
            ui.add_space(4.0);
        }

        if ui.button("Unlock with recovery key").clicked() {
            self.try_recovery_unlock();
        }

        ui.add_space(12.0);
        if ui.small_button("← Back to Windows Hello").clicked() {
            self.mode = LockMode::Hello;
            self.state = State::Idle;
            self.recovery_error = None;
            // VULN-M3 FIX: zeroize recovery input when switching away
            self.recovery_input.zeroize();
        }
    }

    // -----------------------------------------------------------------------
    // Windows Hello flow
    // -----------------------------------------------------------------------

    fn start_auth(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.auth_rx = Some(rx);
        windows_hello::authenticate_async(self.config.winhello_key_id.clone(), tx);
        self.state = State::Authenticating;
    }

    fn poll_channel(&mut self) {
        // Poll Windows Hello auth
        if let (State::Authenticating, Some(rx)) = (&self.state, &self.auth_rx) {
            if let Ok(result) = rx.try_recv() {
                self.auth_rx = None;
                match result {
                    Ok(sig) => self.finish_hello_unlock(sig),
                    Err(e) => self.state = State::Error(e.to_string()),
                }
            }
        }

        // VULN-L1 FIX: poll re-enrollment result
        if let (State::ReEnrolling, Some(rx)) = (&self.state, &self.enroll_rx) {
            if let Ok(result) = rx.try_recv() {
                self.enroll_rx = None;
                match result {
                    Ok(()) => {
                        // Re-enrollment succeeded — transition to unlocked
                        // The result was already staged in a pending_result field
                        // during try_recovery_unlock; now yield it.
                        self.state = State::Idle;
                        // result is already set by try_recovery_unlock before spawning
                    }
                    Err(e) => {
                        // Re-enrollment failed is non-fatal for the unlock itself
                        // (the vault is already decrypted). Just log and proceed.
                        eprintln!("[WARN] Windows Hello re-enrollment failed: {e}");
                        self.state = State::Idle;
                    }
                }
            }
        }
    }

    fn finish_hello_unlock(&mut self, _signature: Vec<u8>) {
        // Windows Hello verified the user identity above (the prompt was the gate).
        // Now use DPAPI to recover the MKEK — it is user+machine scoped and
        // cannot be decrypted offline or by any other Windows account.
        let mut mkek_vec = match dpapi_unprotect(&self.config.winhello_dpapi_blob) {
            Ok(b) => b,
            Err(e) => {
                self.state = State::Error(format!("Could not recover key: {e}"));
                return;
            }
        };
        if mkek_vec.len() != 32 {
            mkek_vec.zeroize(); // R2 FIX: zeroize DPAPI output before early return
            self.state = State::Error("Stored MKEK has unexpected length".into());
            return;
        }
        let mut mkek_bytes = [0u8; 32];
        mkek_bytes.copy_from_slice(&mkek_vec);
        mkek_vec.zeroize(); // R2 FIX: zeroize heap copy of MKEK immediately
        let mkek = MasterKey::new(&mut mkek_bytes); // mkek_bytes zeroized inside new()

        // Unwrap the master key (VULN-C1: use winhello AAD)
        let mk = match unwrap_key(&mkek, &self.config.winhello_wrapped_mk, AAD_WINHELLO_MK) {
            Ok(mk) => mk,
            Err(e) => {
                self.state = State::Error(format!("Could not unwrap key: {e}"));
                return;
            }
        };

        // Verify config HMAC — detect tampering
        if let Err(CryptoError::ConfigTampered) = verify_config_hmac(&mk, &self.config) {
            self.state = State::TamperDetected;
            return;
        }

        // Decrypt the notes store
        let store = match decrypt_store(&mk, &self.encrypted_notes) {
            Ok(s) => s,
            Err(e) => {
                self.state = State::Error(format!("Could not decrypt notes: {e}"));
                return;
            }
        };

        self.state = State::Idle;
        self.result = Some(UnlockResult {
            master_key: mk,
            store,
            config: self.config.clone(),
        });
    }

    // -----------------------------------------------------------------------
    // Recovery key flow
    // -----------------------------------------------------------------------

    fn try_recovery_unlock(&mut self) {
        use aes_gcm::aead::OsRng;
        use rand::RngCore;

        let input = self.recovery_input.trim().to_lowercase();

        // Parse + verify BIP-39 checksum
        let mnemonic = match bip39::Mnemonic::parse(&input) {
            Ok(m) => m,
            Err(e) => {
                self.record_recovery_failure(format!("Invalid recovery key: {e}"));
                return;
            }
        };

        // Extract entropy (32 bytes)
        let mut entropy = mnemonic.to_entropy();
        if entropy.len() != 32 {
            // VULN-M3 FIX: zeroize entropy before early return
            entropy.zeroize();
            self.record_recovery_failure("Recovery key entropy must be 32 bytes (24 words).".into());
            return;
        }

        // Derive recovery MKEK (VULN-L5: uses Argon2id now)
        let recovery_mkek_bytes_result = derive_mkek(&entropy, &self.config.recovery_salt);
        entropy.zeroize(); // VULN-M3 FIX: zeroize entropy immediately after use

        let mut recovery_mkek_bytes = match recovery_mkek_bytes_result {
            Ok(b) => b,
            Err(e) => {
                self.record_recovery_failure(e.to_string());
                return;
            }
        };
        let recovery_mkek = MasterKey::new(&mut recovery_mkek_bytes); // R3 FIX: zeroize in-place, no redundant copy

        // Unwrap master key via recovery path (VULN-C1: use recovery AAD)
        let mk = match unwrap_key(&recovery_mkek, &self.config.recovery_wrapped_mk, AAD_RECOVERY_MK) {
            Ok(mk) => mk,
            Err(_) => {
                // VULN-M3: recovery_input zeroized in record_recovery_failure
                self.record_recovery_failure(
                    "Recovery key is incorrect or data is corrupted.".into(),
                );
                return;
            }
        };

        // Verify config HMAC
        if verify_config_hmac(&mk, &self.config).is_err() {
            // VULN-M2 FIX: store is only in encrypted form here; nothing to zeroize
            self.state = State::TamperDetected;
            self.recovery_input.zeroize(); // VULN-M3
            return;
        }

        // Decrypt notes
        let store = match decrypt_store(&mk, &self.encrypted_notes) {
            Ok(s) => s,
            Err(e) => {
                self.record_recovery_failure(format!("Could not decrypt notes: {e}"));
                return;
            }
        };

        // Generate a fresh MKEK, DPAPI-protect it, and re-wrap the master key
        // so that Windows Hello unlock works immediately after recovery.
        let mut new_mkek_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut new_mkek_bytes);
        let new_dpapi_blob = match dpapi_protect(&new_mkek_bytes) {
            Ok(b) => b,
            Err(e) => {
                self.record_recovery_failure(format!("Could not protect new key: {e}"));
                return;
            }
        };
        let new_mkek = MasterKey::new(&mut new_mkek_bytes);
        // VULN-C1: use winhello AAD for the new wrapped MK
        let new_wrapped_mk = wrap_key(&new_mkek, mk.as_bytes(), AAD_WINHELLO_MK);

        let mut updated_config = self.config.clone();
        updated_config.winhello_dpapi_blob = new_dpapi_blob;
        updated_config.winhello_wrapped_mk = new_wrapped_mk;
        // Recompute HMAC over updated config
        compute_config_hmac(&mk, &mut updated_config);

        // VULN-M3 FIX: zeroize recovery input before complete
        self.recovery_input.zeroize();
        self.recovery_error = None;
        self.recovery_failures = 0;

        // VULN-L1 FIX: store the re-enrollment receiver and transition state
        // so we can check whether it succeeded (non-fatal if it fails).
        let (tx, rx) = mpsc::channel();
        self.enroll_rx = Some(rx);
        windows_hello::enroll_async(self.config.winhello_key_id.clone(), tx);
        self.state = State::ReEnrolling;

        // Stage the unlock result — it will be yielded once ReEnrolling resolves.
        self.result = Some(UnlockResult {
            master_key: mk,
            store,
            config: updated_config,
        });
    }

    // -----------------------------------------------------------------------
    // VULN-L4 FIX: record failed recovery attempt and apply backoff
    // -----------------------------------------------------------------------
    fn record_recovery_failure(&mut self, msg: String) {
        // VULN-M3 FIX: clear input buffer on every failure path
        self.recovery_input.zeroize();
        self.recovery_input = String::new(); // allow re-entry

        self.recovery_failures += 1;
        self.recovery_error = Some(msg);

        if self.recovery_failures < RECOVERY_MAX_ATTEMPTS {
            // Exponential backoff: 2^(failures-1) seconds, capped at 60s
            let delay_secs = RECOVERY_BASE_DELAY_SECS
                .checked_shl(self.recovery_failures - 1)
                .unwrap_or(u64::MAX)
                .min(RECOVERY_MAX_DELAY_SECS);
            self.recovery_locked_until =
                Some(Instant::now() + std::time::Duration::from_secs(delay_secs));
        }
    }
}
