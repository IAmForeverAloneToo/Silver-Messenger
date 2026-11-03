//! Security keys on Windows. Windows 11's own API speaks WebAuthn's `prf`
//! ([`webauthn`]), and is used where it does (API version 4 and later);
//! it asks for the PIN and the touch in its own window. Windows 10's does
//! not, and hides the key from a process that is not elevated, so there
//! the client starts the elevated helper, `silver-key.exe`, which talks to
//! the key over HID ([`hid`]) and hands back the answer through a pipe
//! ([`helper`]); docs/design/security-key.md, section 5.

pub mod helper;
pub mod hid;
pub mod webauthn;

use crate::{Authenticator, Error, Prompt};

/// Windows strings: UTF-16, NUL-terminated.
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The last Windows error, as text.
pub(crate) fn last_error(what: &str) -> Error {
    Error::Windows(format!("{what}: {}", std::io::Error::last_os_error()))
}

/// The way to the key on this computer.
pub fn platform(prompt: Box<dyn Prompt + Send>) -> Result<Box<dyn Authenticator>, Error> {
    // The prompt is for the routes that ask for the PIN here; both of
    // these ask for it themselves, Windows in its dialog and the helper in
    // its own window.
    let _ = prompt;
    if webauthn::has_prf() {
        return Ok(Box::new(webauthn::WebAuthn));
    }
    let exe = std::env::current_exe()
        .map_err(Error::Io)?
        .with_file_name("silver-key.exe");
    if !exe.exists() {
        return Err(Error::Unavailable(
            "this Windows is too old for its own API to reach a security key, and \
             silver-key.exe, which does it instead, is not beside silver.exe",
        ));
    }
    Ok(Box::new(helper::Helper::new(exe)))
}
