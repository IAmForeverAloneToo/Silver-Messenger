//! Security keys on Windows. Windows 11's own API speaks WebAuthn's `prf`
//! ([`webauthn`]), and is used where it does (API version 4 and later);
//! it asks for the PIN and the touch in its own window. Windows 10's does
//! not, and hides the key from a process that is not elevated, so there
//! the client starts itself elevated in helper mode, which talks to
//! the key over HID ([`hid`]) and hands back the answer through a pipe
//! ([`helper`]); docs/design/security-key.md, section 5. It does that
//! only from a place no program running as the user could change first
//! ([`place`]).

pub mod helper;
pub mod hid;
pub mod place;
pub mod webauthn;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories,
};

use crate::{Authenticator, Direct, Error, Prompt};

/// Windows strings: UTF-16, NUL-terminated.
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The last Windows error, as text.
pub(crate) fn last_error(what: &str) -> Error {
    Error::Windows(format!("{what}: {}", std::io::Error::last_os_error()))
}

/// A handle closed when it goes.
pub(crate) struct Owned(pub(crate) HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: owned, closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// [`crate::harden_dll_search`].
pub(crate) fn harden_dll_search() -> std::io::Result<()> {
    // SAFETY: takes a flag, changes this process's search path.
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The way to the key on this computer.
pub fn platform(prompt: Box<dyn Prompt + Send>) -> Result<Box<dyn Authenticator>, Error> {
    if webauthn::has_prf() {
        // Windows asks for the PIN in its own dialog.
        return Ok(Box::new(webauthn::WebAuthn));
    }
    if place::elevated() {
        // Started as administrator already: the keys are listed to this
        // process, so it talks to them itself and asks for the PIN as
        // Linux does, with no second elevated process to trust.
        return Ok(Box::new(Direct::new(hid::find, prompt)));
    }
    // The program itself, started again elevated in helper mode, which
    // asks for the PIN in its own window: one executable, which an update
    // replaces whole, and only from a place nothing running as the user
    // could have changed.
    let _ = prompt;
    let exe = place::this_executable()?;
    Ok(Box::new(helper::Helper::new(exe)?))
}
