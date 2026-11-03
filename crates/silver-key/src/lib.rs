// Unsafe only in the Windows modules, which call the Windows API.
#![deny(unsafe_code)]
//! Talking to a FIDO2 security key: what Silver Messenger needs to unlock
//! a data directory with one (docs/design/security-key.md), and nothing
//! else.
//!
//! A credential is made on the key with the `hmac-secret` and
//! `credProtect` extensions, and the key later turns a salt into a 32-byte
//! secret that only it can compute, after its PIN and a touch. The salt is
//! passed as WebAuthn's `prf` extension passes it ([`prf_salt`]), so that
//! the same credential gives the same secret through Windows 11's own API.
//!
//! The pieces: [`cbor`], the encoding CTAP2 speaks; [`hid`], how messages
//! cross USB; [`pin`], the PIN protocols; [`Key`], the commands. A
//! [`hid::Device`] is a key on USB (`/dev/hidraw` on Linux, [`hidraw`]),
//! or the software authenticator the tests use ([`soft`]).

pub mod cbor;
mod ctap;
pub mod helper_wire;
pub mod hid;
#[cfg(target_os = "linux")]
pub mod hidraw;
pub mod pin;
mod route;
#[cfg(any(test, feature = "soft"))]
pub mod soft;
#[cfg(test)]
mod soft_tests;
#[cfg(windows)]
#[allow(unsafe_code)]
pub mod windows;

use sha2::{Digest, Sha256};

pub use ctap::{Info, Key};
#[cfg(target_os = "linux")]
pub use route::find_hidraw;
pub use route::{Authenticator, Direct, Enrolled, Prompt, platform, supported};

/// The salt the key is given for the WebAuthn `prf` input `input`:
/// SHA-256 of "WebAuthn PRF", a zero byte, and the input.
pub fn prf_salt(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"WebAuthn PRF");
    h.update([0u8]);
    h.update(input);
    h.finalize().into()
}

/// What can go wrong talking to a key.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the PIN is wrong ({} left before the key locks itself)", tries(*.retries))]
    PinInvalid { retries: Option<u32> },
    #[error("the key's PIN is blocked after too many wrong tries; it needs resetting")]
    PinBlocked,
    #[error("three wrong PINs in a row: unplug the key and plug it back in to try again")]
    PinAuthBlocked,
    #[error("the key has no PIN set")]
    PinNotSet,
    #[error("the key refused the new PIN (too short, or too long)")]
    PinPolicy,
    #[error("this key holds no credential for this directory")]
    NoCredentials,
    #[error("the key was not touched in time")]
    NotTouched,
    #[error("the key refused the operation")]
    Denied,
    #[error("the key does not support {0}")]
    Unsupported(&'static str),
    #[error("the key reported error 0x{0:02x}")]
    Ctap(u8),
    #[error("the key reported transport error 0x{0:02x}")]
    Hid(u8),
    #[error("the key's answer is malformed: {0}")]
    Malformed(&'static str),
    #[error("cancelled")]
    Cancelled,
    /// No way to reach a key here.
    #[error("{0}")]
    Unavailable(&'static str),
    #[error("the security key helper failed; its window said why")]
    Helper,
    #[error("Windows: {0}")]
    Windows(String),
    #[error("the key did not answer in time")]
    Timeout,
    #[error("talking to the key: {0}")]
    Io(#[from] std::io::Error),
}

fn tries(retries: Option<u32>) -> String {
    match retries {
        Some(1) => "1 try".into(),
        Some(n) => format!("{n} tries"),
        None => "some tries".into(),
    }
}

/// CTAP2 status codes this crate tells apart (section 8.2 of CTAP 2.1).
// Some are only sent, by the software authenticator.
#[cfg_attr(not(any(test, feature = "soft")), allow(dead_code))]
pub(crate) mod status {
    pub const INVALID_PARAMETER: u8 = 0x02;
    pub const MISSING_PARAMETER: u8 = 0x14;
    pub const UNSUPPORTED_ALGORITHM: u8 = 0x26;
    pub const OPERATION_DENIED: u8 = 0x27;
    pub const NO_CREDENTIALS: u8 = 0x2e;
    pub const USER_ACTION_TIMEOUT: u8 = 0x2f;
    pub const PIN_INVALID: u8 = 0x31;
    pub const PIN_BLOCKED: u8 = 0x32;
    pub const PIN_AUTH_INVALID: u8 = 0x33;
    pub const PIN_AUTH_BLOCKED: u8 = 0x34;
    pub const PIN_NOT_SET: u8 = 0x35;
    pub const PUAT_REQUIRED: u8 = 0x36;
    pub const PIN_POLICY_VIOLATION: u8 = 0x37;
}

impl Error {
    pub(crate) fn from_ctap(code: u8) -> Error {
        match code {
            status::PIN_INVALID => Error::PinInvalid { retries: None },
            status::PIN_BLOCKED => Error::PinBlocked,
            status::PIN_AUTH_BLOCKED => Error::PinAuthBlocked,
            status::PIN_NOT_SET => Error::PinNotSet,
            status::PIN_POLICY_VIOLATION => Error::PinPolicy,
            status::NO_CREDENTIALS => Error::NoCredentials,
            status::USER_ACTION_TIMEOUT => Error::NotTouched,
            status::OPERATION_DENIED => Error::Denied,
            other => Error::Ctap(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prf_salt_is_webauthns() {
        // SHA-256("WebAuthn PRF" || 0x00 || "silver-messenger"), computed
        // apart from this code.
        let want = "135e46751d2214f2fc3294e5fe45c2bd43f8e59b391586522384c300fa14b86d";
        let got: String = prf_salt(b"silver-messenger")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(got, want);
    }
}
