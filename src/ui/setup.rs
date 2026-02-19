//! First-run setup wizard.
//!
//! Steps:
//!   1. Check / enroll Windows Hello
//!   2. Generate master key, wrap with Windows Hello MKEK
//!   3. Generate BIP-39 mnemonic (24 words)
//!   4. Show mnemonic + copy button
//!   5. Verify 3 random words (user types them back)
//!   6. Wrap master key with recovery MKEK, compute config HMAC, write config.json
//!   7. Transition to Unlocked

use std::sync::mpsc;

use egui::{Align, Color32, FontId, Layout, RichText, Ui};
use rand::Rng;

use crate::auth::windows_hello::{self, HelloResult};
use crate::crypto::keys::{
    compute_config_hmac, derive_mkek, dpapi_protect, wrap_key, MasterKey,
    AAD_WINHELLO_MK, AAD_RECOVERY_MK,
};
use crate::store::notes::{AppConfig, AppSettings, NotesStore};

// ---------------------------------------------------------------------------
// Result handed back to app.rs when setup completes
// ---------------------------------------------------------------------------

pub struct SetupComplete {
    pub master_key: MasterKey,
    pub store: NotesStore,
    pub config: AppConfig,
    pub settings: AppSettings,
}

// ---------------------------------------------------------------------------
// Wizard steps
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    CheckingHello,
    HelloUnsupported,
    Enrolling,
    EnrollError(String),
    Authenticating,
    AuthError(String),
    ShowMnemonic,
    VerifyMnemonic,
    Saving,
    #[allow(dead_code)]
    SaveError(String),
}

// ---------------------------------------------------------------------------
// SetupWizard widget state
// ---------------------------------------------------------------------------

pub struct SetupWizard {
    step: Step,
    /// Background thread channel
    hello_rx: Option<mpsc::Receiver<HelloResult<()>>>,
    auth_rx: Option<mpsc::Receiver<HelloResult<Vec<u8>>>>,
    support_rx: Option<mpsc::Receiver<HelloResult<bool>>>,
    /// Generated during setup
    master_key: Option<MasterKey>,
    winhello_dpapi_blob: Vec<u8>,
    winhello_wrapped_mk: Vec<u8>,
    /// BIP-39 mnemonic
    mnemonic_words: Vec<String>,
    mnemonic_raw: Vec<u8>, // 32-byte entropy
    /// Verification quiz
    quiz_indices: Vec<usize>,   // 3 word indices (0-based)
    quiz_inputs: [String; 3],
    quiz_error: Option<String>,
    /// Completion result (taken on transition)
    pub complete: Option<SetupComplete>,
}

const KEY_ID: &str = "secure-notes-v1";

impl Default for SetupWizard {
    fn default() -> Self {
        Self::new()
    }
}

impl SetupWizard {
    pub fn new() -> Self {
        // Kick off support check immediately
        let (support_tx, support_rx) = mpsc::channel();
        windows_hello::is_supported_async(support_tx);

        Self {
            step: Step::CheckingHello,
            hello_rx: None,
            auth_rx: None,
            support_rx: Some(support_rx),
            master_key: None,
            winhello_dpapi_blob: Vec::new(),
            winhello_wrapped_mk: Vec::new(),
            mnemonic_words: Vec::new(),
            mnemonic_raw: Vec::new(),
            quiz_indices: Vec::new(),
            quiz_inputs: Default::default(),
            quiz_error: None,
            complete: None,
        }
    }

    pub fn show(&mut self, ui: &mut Ui) {
        self.poll_channels();

        match &self.step.clone() {
            Step::CheckingHello => self.show_checking(ui),
            Step::HelloUnsupported => self.show_unsupported(ui),
            Step::Enrolling => self.show_spinner(ui, "Setting up Windows Hello…"),
            Step::EnrollError(e) => self.show_error(ui, e, "Retry", || Step::Enrolling),
            Step::Authenticating => self.show_spinner(ui, "Waiting for Windows Hello…"),
            Step::AuthError(e) => self.show_error(ui, e, "Retry", || Step::Authenticating),
            Step::ShowMnemonic => self.show_mnemonic(ui),
            Step::VerifyMnemonic => self.show_verify(ui),
            Step::Saving => self.show_spinner(ui, "Saving configuration…"),
            Step::SaveError(e) => self.show_error(ui, e, "Retry", || Step::Saving),
        }
    }

    // -----------------------------------------------------------------------
    // Background channel polling
    // -----------------------------------------------------------------------

    fn poll_channels(&mut self) {
        // Support check
        if let Some(rx) = &self.support_rx {
            if let Ok(result) = rx.try_recv() {
                self.support_rx = None;
                match result {
                    Ok(true) => {
                        // Enroll
                        let (tx, rx) = mpsc::channel();
                        self.hello_rx = Some(rx);
                        windows_hello::enroll_async(KEY_ID.into(), tx);
                        self.step = Step::Enrolling;
                    }
                    Ok(false) => self.step = Step::HelloUnsupported,
                    Err(e) => self.step = Step::EnrollError(e.to_string()),
                }
            }
        }

        // Enrollment result
        if let (Step::Enrolling, Some(rx)) = (&self.step, &self.hello_rx) {
            if let Ok(result) = rx.try_recv() {
                self.hello_rx = None;
                match result {
                    Ok(()) => {
                        // Now authenticate to get signature for MKEK derivation
                        let (tx, rx) = mpsc::channel();
                        self.auth_rx = Some(rx);
                        windows_hello::authenticate_async(KEY_ID.into(), tx);
                        self.step = Step::Authenticating;
                    }
                    Err(e) => self.step = Step::EnrollError(e.to_string()),
                }
            }
        }

        // Authentication result
        if let (Step::Authenticating, Some(rx)) = (&self.step, &self.auth_rx) {
            if let Ok(result) = rx.try_recv() {
                self.auth_rx = None;
                match result {
                    Ok(_) => {
                        self.generate_master_key_and_mnemonic();
                        self.step = Step::ShowMnemonic;
                    }
                    Err(e) => self.step = Step::AuthError(e.to_string()),
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Key + mnemonic generation
    // -----------------------------------------------------------------------

    fn generate_master_key_and_mnemonic(&mut self) {
        use aes_gcm::aead::OsRng;
        use rand::RngCore;
        use zeroize::Zeroize;

        // Generate 32-byte master key
        let mk = MasterKey::generate();

        // Generate a fresh random 32-byte MKEK and protect it with Windows DPAPI.
        // DPAPI binds the MKEK to this Windows user account on this machine, so
        // config.json theft does not expose the master key offline.
        let mut mkek_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut mkek_bytes);
        self.winhello_dpapi_blob = dpapi_protect(&mkek_bytes)
            .expect("Windows DPAPI protect must succeed for current user");
        let mkek = MasterKey::new(&mut mkek_bytes); // mkek_bytes zeroized inside

        // Wrap master key under MKEK (VULN-C1: bind to winhello role)
        self.winhello_wrapped_mk = wrap_key(&mkek, mk.as_bytes(), AAD_WINHELLO_MK);

        // Generate BIP-39 mnemonic from 32 bytes entropy
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        self.mnemonic_raw = entropy.to_vec();

        // bip39 crate: Mnemonic::from_entropy gives us 24 words
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .expect("32-byte entropy must produce valid mnemonic");
        entropy.zeroize(); // R4 FIX: zeroize stack copy of recovery entropy
        self.mnemonic_words = mnemonic
            .words()
            .map(|w| w.to_string())
            .collect();

        // Choose 3 random quiz indices
        let mut rng = rand::thread_rng();
        let mut idx = [0usize; 3];
        idx[0] = rng.gen_range(0..8);
        idx[1] = rng.gen_range(8..16);
        idx[2] = rng.gen_range(16..24);
        self.quiz_indices = idx.to_vec();

        self.master_key = Some(mk);
    }

    // -----------------------------------------------------------------------
    // Finalise config and hand off to app
    // -----------------------------------------------------------------------

    fn finalise(&mut self) {
        use aes_gcm::aead::OsRng;
        use rand::RngCore;
        use zeroize::Zeroize;

        let mk = self.master_key.take().expect("master key must exist");

        // Recovery salt
        let mut recovery_salt = vec![0u8; 32];
        OsRng.fill_bytes(&mut recovery_salt);

        // Derive recovery MKEK from BIP-39 entropy + recovery salt
        let mut recovery_mkek_bytes = derive_mkek(&self.mnemonic_raw, &recovery_salt)
            .expect("Argon2id must not fail");
        let recovery_mkek = MasterKey::new(&mut recovery_mkek_bytes); // zeroized inside
        // VULN-C1: bind recovery-wrapped MK to recovery role
        let recovery_wrapped_mk = wrap_key(&recovery_mkek, mk.as_bytes(), AAD_RECOVERY_MK);

        // Zeroize mnemonic entropy and words from memory
        self.mnemonic_raw.zeroize();
        for word in &mut self.mnemonic_words {
            word.zeroize();
        }
        self.mnemonic_words.clear();
        for input in &mut self.quiz_inputs {
            input.zeroize();
        }

        // Build config (config_hmac computed below)
        let mut config = AppConfig {
            winhello_key_id: KEY_ID.into(),
            winhello_dpapi_blob: self.winhello_dpapi_blob.clone(),
            winhello_wrapped_mk: self.winhello_wrapped_mk.clone(),
            recovery_salt,
            recovery_wrapped_mk,
            vault_version: 0,
            config_hmac: vec![],
        };

        // Compute HMAC over all config fields
        compute_config_hmac(&mk, &mut config);

        self.complete = Some(SetupComplete {
            master_key: mk,
            store: NotesStore::new(),
            config,
            settings: AppSettings::default(),
        });
    }

    // -----------------------------------------------------------------------
    // UI panels
    // -----------------------------------------------------------------------

    fn show_checking(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.label(RichText::new("Checking Windows Hello…").size(16.0));
            ui.add_space(10.0);
            ui.spinner();
        });
    }

    fn show_unsupported(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.label(
                RichText::new("Windows Hello is not available")
                    .size(18.0)
                    .color(Color32::RED),
            );
            ui.add_space(8.0);
            ui.label("Please set up a PIN or biometrics in Windows Settings, then restart this app.");
        });
    }

    fn show_spinner(&mut self, ui: &mut Ui, msg: &str) {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.label(RichText::new(msg).size(16.0));
            ui.add_space(10.0);
            ui.spinner();
        });
        ui.ctx().request_repaint();
    }

    fn show_error(&mut self, ui: &mut Ui, err: &str, btn: &str, next: impl Fn() -> Step) {
        ui.vertical_centered(|ui| {
            ui.add_space(40.0);
            ui.label(RichText::new("Error").size(18.0).color(Color32::RED));
            ui.add_space(8.0);
            ui.label(err);
            ui.add_space(16.0);
            if ui.button(btn).clicked() {
                self.step = next();
            }
        });
    }

    fn show_mnemonic(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label(
                RichText::new("Save Your Recovery Key")
                    .font(FontId::proportional(22.0))
                    .strong(),
            );
            ui.add_space(8.0);
            ui.label("Write these 24 words on paper and keep them in a safe place.");
            ui.label(
                RichText::new("⚠ If you lose this key and forget your Windows Hello PIN, your notes cannot be recovered.")
                    .color(Color32::YELLOW),
            );
            ui.add_space(16.0);

            // Display words in a 4-column grid (6 rows × 4 cols = 24)
            egui::Grid::new("mnemonic_grid")
                .num_columns(4)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    for (i, word) in self.mnemonic_words.iter().enumerate() {
                        ui.label(
                            RichText::new(format!("{:2}. {}", i + 1, word))
                                .font(FontId::monospace(14.0)),
                        );
                        if (i + 1) % 4 == 0 {
                            ui.end_row();
                        }
                    }
                });

            ui.add_space(16.0);

            // VULN-M5 FIX: No "Copy to clipboard" button — the mnemonic must only
            // be written on paper. Clipboard history tools, screen capture software,
            // or remote-access sessions could silently exfiltrate this 256-bit secret.
            ui.label(
                RichText::new("⚠ Write these words on paper only. Do not copy them digitally.")
                    .color(Color32::YELLOW)
                    .small(),
            );

            ui.add_space(16.0);
            if ui.button("I have written my recovery key  →").clicked() {
                self.step = Step::VerifyMnemonic;
            }
        });
    }

    fn show_verify(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label(
                RichText::new("Verify Recovery Key")
                    .font(FontId::proportional(22.0))
                    .strong(),
            );
            ui.add_space(8.0);
            ui.label("Type the words at the requested positions:");
            ui.add_space(16.0);
        });

        // Quiz inputs — displayed out of vertical_centered so TextEdit works
        for (slot, &word_idx) in self.quiz_indices.clone().iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(format!("Word #{:2}:", word_idx + 1));
                let response = ui.text_edit_singleline(&mut self.quiz_inputs[slot]);
                let _ = response;
            });
        }

        ui.add_space(8.0);

        if let Some(err) = &self.quiz_error {
            ui.colored_label(Color32::RED, err);
            ui.add_space(4.0);
        }

        ui.with_layout(Layout::bottom_up(Align::Center), |ui| {
            ui.add_space(16.0);
        });

        if ui.button("Confirm & Finish Setup").clicked() {
            // Verify all three inputs
            let mut ok = true;
            for (slot, &word_idx) in self.quiz_indices.iter().enumerate() {
                if self.quiz_inputs[slot].trim().to_lowercase()
                    != self.mnemonic_words[word_idx].to_lowercase()
                {
                    ok = false;
                    break;
                }
            }
            if ok {
                self.quiz_error = None;
                self.finalise();
            } else {
                self.quiz_error = Some("One or more words are incorrect. Please check and try again.".into());
            }
        }

        if ui.button("← Back (view mnemonic again)").clicked() {
            self.step = Step::ShowMnemonic;
        }
    }
}
