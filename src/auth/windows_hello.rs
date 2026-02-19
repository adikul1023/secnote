//! Windows Hello integration via `KeyCredentialManager` (WinRT).
//!
//! All WinRT calls block the calling thread and must therefore be dispatched
//! from a `std::thread::spawn` context — never from the egui UI thread.
//! Results are communicated back through `std::sync::mpsc` channels.

use std::sync::mpsc;
use rand::RngCore;
use aes_gcm::aead::OsRng;

// ---------------------------------------------------------------------------
// Public API types
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum HelloError {
    /// Windows Hello / biometrics not supported or not enrolled on this device.
    #[allow(dead_code)]
    NotSupported,
    /// The credential was not found — first-run enrollment required.
    NotFound,
    /// The user cancelled the Windows Hello prompt.
    UserCancelled,
    /// Any other OS-level error.
    Os(String),
}

impl std::fmt::Display for HelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSupported => write!(f, "Windows Hello is not available on this device"),
            Self::NotFound => write!(f, "Windows Hello credential not found — re-enroll"),
            Self::UserCancelled => write!(f, "Windows Hello prompt was cancelled"),
            Self::Os(msg) => write!(f, "Windows Hello OS error: {msg}"),
        }
    }
}

pub type HelloResult<T> = Result<T, HelloError>;

// ---------------------------------------------------------------------------
// Async helpers — run blocking WinRT calls on a background thread
// ---------------------------------------------------------------------------

/// Check whether Windows Hello (biometrics/PIN) is supported and provisioned
/// on this device. Returns immediately; calls back through `tx`.
pub fn is_supported_async(tx: mpsc::Sender<HelloResult<bool>>) {
    std::thread::spawn(move || {
        tx.send(is_supported_sync()).ok();
    });
}

/// Enroll (or re-enroll) a new Windows Hello credential with the given `name`.
/// Triggers a Windows Hello UI prompt. Calls back through `tx`.
pub fn enroll_async(name: String, tx: mpsc::Sender<HelloResult<()>>) {
    std::thread::spawn(move || {
        tx.send(enroll_sync(&name)).ok();
    });
}

/// Authenticate using an existing Windows Hello credential.
/// Generates a 32-byte random challenge, signs it with the TPM-backed key,
/// and returns the raw signature bytes (used as HKDF input).
/// Triggers a Windows Hello UI prompt. Calls back through `tx`.
pub fn authenticate_async(name: String, tx: mpsc::Sender<HelloResult<Vec<u8>>>) {
    std::thread::spawn(move || {
        tx.send(authenticate_sync(&name)).ok();
    });
}

// ---------------------------------------------------------------------------
// Synchronous implementations (run on background threads only)
// ---------------------------------------------------------------------------

fn is_supported_sync() -> HelloResult<bool> {
    use windows::Security::Credentials::KeyCredentialManager;
    let op = KeyCredentialManager::IsSupportedAsync()
        .map_err(|e| HelloError::Os(e.to_string()))?;
    let result = op.get()
        .map_err(|e| HelloError::Os(e.to_string()))?;
    Ok(result)
}

fn enroll_sync(name: &str) -> HelloResult<()> {
    use windows::Security::Credentials::{
        KeyCredentialManager, KeyCredentialCreationOption,
        KeyCredentialStatus,
    };
    use windows::core::HSTRING;

    let hname = HSTRING::from(name);
    let op = KeyCredentialManager::RequestCreateAsync(
        &hname,
        KeyCredentialCreationOption::ReplaceExisting,
    ).map_err(|e| HelloError::Os(e.to_string()))?;

    let result = op.get()
        .map_err(|e| HelloError::Os(e.to_string()))?;

    match result.Status()
        .map_err(|e| HelloError::Os(e.to_string()))?
    {
        KeyCredentialStatus::Success => Ok(()),
        KeyCredentialStatus::UserCanceled => Err(HelloError::UserCancelled),
        KeyCredentialStatus::NotFound => Err(HelloError::NotFound),
        s => Err(HelloError::Os(format!("Unexpected credential status: {s:?}"))),
    }
}

fn authenticate_sync(name: &str) -> HelloResult<Vec<u8>> {
    use windows::Security::Credentials::{KeyCredentialManager, KeyCredentialStatus};
    use windows::Storage::Streams::{DataWriter, DataReader};
    use windows::core::HSTRING;

    // Generate a fresh 32-byte challenge — never reuse
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);

    let hname = HSTRING::from(name);
    let open_op = KeyCredentialManager::OpenAsync(&hname)
        .map_err(|e| HelloError::Os(e.to_string()))?;
    let open_result = open_op.get()
        .map_err(|e| HelloError::Os(e.to_string()))?;

    match open_result.Status()
        .map_err(|e| HelloError::Os(e.to_string()))?
    {
        KeyCredentialStatus::Success => {}
        KeyCredentialStatus::NotFound => return Err(HelloError::NotFound),
        KeyCredentialStatus::UserCanceled => return Err(HelloError::UserCancelled),
        s => return Err(HelloError::Os(format!("Open status: {s:?}"))),
    }

    let credential = open_result.Credential()
        .map_err(|e| HelloError::Os(e.to_string()))?;

    // Write challenge bytes into a WinRT IBuffer via DataWriter
    let writer = DataWriter::new()
        .map_err(|e| HelloError::Os(e.to_string()))?;
    writer.WriteBytes(&challenge)
        .map_err(|e| HelloError::Os(e.to_string()))?;
    let ibuffer = writer.DetachBuffer()
        .map_err(|e| HelloError::Os(e.to_string()))?;

    // Sign — this triggers the Windows Hello prompt (PIN / biometric)
    let sign_op = credential.RequestSignAsync(&ibuffer)
        .map_err(|e| HelloError::Os(e.to_string()))?;
    let sign_result = sign_op.get()
        .map_err(|e| HelloError::Os(e.to_string()))?;

    match sign_result.Status()
        .map_err(|e| HelloError::Os(e.to_string()))?
    {
        KeyCredentialStatus::Success => {}
        KeyCredentialStatus::UserCanceled => return Err(HelloError::UserCancelled),
        s => return Err(HelloError::Os(format!("Sign status: {s:?}"))),
    }

    // Read the signature bytes out of the IBuffer
    let sig_buffer = sign_result.Result()
        .map_err(|e| HelloError::Os(e.to_string()))?;
    let len = sig_buffer.Length()
        .map_err(|e| HelloError::Os(e.to_string()))? as usize;
    let reader = DataReader::FromBuffer(&sig_buffer)
        .map_err(|e| HelloError::Os(e.to_string()))?;
    let mut sig_bytes = vec![0u8; len];
    reader.ReadBytes(&mut sig_bytes)
        .map_err(|e| HelloError::Os(e.to_string()))?;

    Ok(sig_bytes)
}
