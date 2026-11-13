//! Where the program runs from, before it starts itself elevated: the
//! rights this user's token is granted on the executable and on every
//! folder above it, which [`crate::helper_place::exposed`] judges. Also
//! whether this process is elevated already, and the one setting that
//! lets the helper run from a place that fails the check.

use core::ptr::null_mut;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    AccessCheck, DACL_SECURITY_INFORMATION, DuplicateToken, GENERIC_MAPPING,
    GROUP_SECURITY_INFORMATION, GetTokenInformation, OWNER_SECURITY_INFORMATION, PRIVILEGE_SET,
    PSECURITY_DESCRIPTOR, SecurityIdentification, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_QUERY,
    TokenElevation,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_SUBKEY_WOW6464KEY, RegGetValueW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::{Owned, last_error, wide};
use crate::Error;
use crate::helper_place::exposed;

/// "Whatever the access list allows": AccessCheck then says what that is.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// The setting that lets the helper start from a place a program running
/// as the user could change: a DWORD of 1 at this value, under
/// `HKEY_LOCAL_MACHINE`. Not an environment variable or a file of the
/// user's: the program it guards against runs as the user and could set
/// those itself, while only an administrator can write here.
pub const OPT_IN_KEY: &str = r"SOFTWARE\Silver Messenger";
pub const OPT_IN_VALUE: &str = "AllowSecurityKeyHelperAnywhere";

/// The executable this process was started from, as a plain drive path
/// with every link and junction on the way resolved: the path that is
/// checked is the path that is started.
pub fn this_executable() -> Result<PathBuf, Error> {
    let exe = std::env::current_exe().map_err(Error::Io)?;
    let canonical = std::fs::canonicalize(&exe).map_err(Error::Io)?;
    let text = canonical.to_string_lossy();
    // `canonicalize` gives `\\?\C:\...`; `ShellExecuteEx` wants `C:\...`.
    // A share (`\\?\UNC\...`) or a volume with no letter is someone
    // else's to change, and is refused.
    let plain = text.strip_prefix(r"\\?\").unwrap_or(&text);
    let bytes = plain.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || &bytes[1..3] != b":\\" {
        return Err(Error::HelperPlace {
            path: text.into_owned(),
            why: "it is not on a local drive",
        });
    }
    Ok(PathBuf::from(plain))
}

/// Refuses `exe` as the helper unless no program running as this user
/// could change what runs there, or an administrator has said to allow
/// it ([`OPT_IN_VALUE`]).
pub fn check(exe: &Path) -> Result<(), Error> {
    let token = identification_token()?;
    let file = granted(exe, &token)?;
    let folders = exe
        .ancestors()
        .skip(1)
        .map(|folder| granted(folder, &token))
        .collect::<Result<Vec<u32>, Error>>()?;
    match exposed(file, &folders) {
        None => Ok(()),
        Some(_) if opted_in() => Ok(()),
        Some(why) => Err(Error::HelperPlace {
            path: exe.display().to_string(),
            why,
        }),
    }
}

/// Whether this process runs elevated already, and so can reach the key
/// itself.
pub fn elevated() -> bool {
    let mut token = null_mut();
    // SAFETY: the token is closed by `Owned`.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return false;
    }
    let token = Owned(token);
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut needed = 0u32;
    // SAFETY: fills one structure of the size given.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&raw mut elevation).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut needed,
        )
    };
    ok != 0 && elevation.TokenIsElevated != 0
}

/// This process's token, as AccessCheck takes one: an impersonation
/// token, at the level that identifies and does nothing else. Not
/// elevated, it is the token of the user as they are, which is what a
/// program running beside this one has too.
fn identification_token() -> Result<Owned, Error> {
    let mut token = null_mut();
    // SAFETY: the token is closed by `Owned`.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        )
    } == 0
    {
        return Err(last_error("reading this process's token"));
    }
    let token = Owned(token);
    let mut duplicate: HANDLE = null_mut();
    // SAFETY: the copy is closed by `Owned`.
    if unsafe { DuplicateToken(token.0, SecurityIdentification, &mut duplicate) } == 0 {
        return Err(last_error("copying this process's token"));
    }
    Ok(Owned(duplicate))
}

/// The rights `token` is granted on the file or folder at `path`. The
/// owner, the group and the access list are read; the integrity label is
/// not, which can only make the answer grant more than Windows would, so
/// a place is refused rather than wrongly let through.
fn granted(path: &Path, token: &Owned) -> Result<u32, Error> {
    let name = wide(&path.to_string_lossy());
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the name is NUL-terminated; the descriptor Windows allocates
    // is freed below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(Error::Windows(format!(
            "reading who may change {}: {}",
            path.display(),
            std::io::Error::from_raw_os_error(status as i32)
        )));
    }
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let mut privileges = PRIVILEGE_SET::default();
    let mut privileges_len = size_of::<PRIVILEGE_SET>() as u32;
    let mut granted = 0u32;
    let mut allowed = 0;
    // SAFETY: the descriptor is the one read above, the token an
    // identification token open for query, and the rest locals.
    let ok = unsafe {
        let ok = AccessCheck(
            descriptor,
            token.0,
            MAXIMUM_ALLOWED,
            &mapping,
            &mut privileges,
            &mut privileges_len,
            &mut granted,
            &mut allowed,
        );
        LocalFree(descriptor);
        ok
    };
    if ok == 0 {
        return Err(last_error(&format!(
            "checking who may change {}",
            path.display()
        )));
    }
    Ok(if allowed != 0 { granted } else { 0 })
}

/// Whether an administrator has set [`OPT_IN_VALUE`] to 1.
fn opted_in() -> bool {
    let key = wide(OPT_IN_KEY);
    let value = wide(OPT_IN_VALUE);
    let mut data = 0u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: the names are NUL-terminated; fills one DWORD.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
            null_mut(),
            (&raw mut data).cast(),
            &mut size,
        )
    };
    status == ERROR_SUCCESS && data == 1
}

#[cfg(test)]
mod tests {
    #[test]
    fn this_executable_is_a_drive_path_and_can_be_judged() {
        let exe = super::this_executable().unwrap();
        assert!(exe.is_absolute());
        assert!(!exe.to_string_lossy().starts_with(r"\\"));
        // The test runner is under target/, the user's own: refused,
        // unless an administrator has said otherwise, or the tests run
        // elevated (when every place is the user's to change).
        let _ = super::check(&exe);
        let _ = super::elevated();
    }
}
