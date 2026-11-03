//! The Windows 10 helper, both ends (docs/design/security-key.md,
//! section 5).
//!
//! The client makes a named pipe only its own user may open, with one
//! instance, starts `silver-key.exe` elevated with the request on its
//! command line (nothing on it is secret), checks that the process at the
//! other end of the pipe is the one it started, and reads one fixed-size
//! answer. The helper asks for the PIN in its own window, talks to the key
//! over HID, writes the answer and exits; it reads nothing else.

use core::ptr::{null, null_mut};
use std::path::PathBuf;
use std::time::Duration;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use zeroize::Zeroizing;

use super::{last_error, wide};
use crate::helper_wire::{ANSWER_LEN, Answer, Request, decode_answer, fresh_pipe_name};
use crate::{Authenticator, Enrolled, Error};

/// How long the person has to answer the UAC prompt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the helper has for the PIN and the touch, after that.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(300);
const SW_SHOWNORMAL: i32 = 1;

/// The route through the helper.
pub struct Helper {
    exe: PathBuf,
}

impl Helper {
    pub fn new(exe: PathBuf) -> Helper {
        Helper { exe }
    }

    fn run(&self, request: &Request) -> Result<Answer, Error> {
        let name = fresh_pipe_name();
        let pipe = Pipe::create(&name)?;
        let process = start_elevated(&self.exe, &request.to_args(&name))?;
        pipe.connect(&process)?;
        // Before a byte is read: the other end is the helper this started,
        // and not something else of this user's that got there first.
        let mut client = 0u32;
        // SAFETY: the pipe is connected; fills one number.
        if unsafe { GetNamedPipeClientProcessId(pipe.handle, &mut client) } == 0 {
            return Err(last_error("asking who opened the pipe"));
        }
        // SAFETY: the process handle ShellExecuteEx returned.
        if client != unsafe { GetProcessId(process.0) } {
            return Err(Error::Windows(
                "a process other than the helper opened its pipe".into(),
            ));
        }
        let bytes = pipe.read_answer(&process)?;
        decode_answer(&bytes)
    }
}

impl Authenticator for Helper {
    fn enroll(&mut self, rp_id: &str, input: &[u8]) -> Result<Enrolled, Error> {
        let answer = self.run(&Request::Enroll {
            rp_id: rp_id.to_owned(),
            input: input.to_vec(),
        })?;
        if answer.credential_id.is_empty() {
            return Err(Error::Malformed("the helper gave no credential"));
        }
        Ok(Enrolled {
            credential_id: answer.credential_id,
            secret: answer.secret,
        })
    }

    fn secret(
        &mut self,
        rp_id: &str,
        candidates: &[(&[u8], &[u8])],
    ) -> Result<(usize, Zeroizing<[u8; 32]>), Error> {
        let answer = self.run(&Request::Secret {
            rp_id: rp_id.to_owned(),
            candidates: candidates
                .iter()
                .map(|(id, input)| (id.to_vec(), input.to_vec()))
                .collect(),
        })?;
        if answer.index >= candidates.len() {
            return Err(Error::Malformed("the helper answered for no candidate"));
        }
        Ok((answer.index, answer.secret))
    }
}

/// A handle closed when it goes.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: owned, closed once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// The current user's SID, as SDDL wants it.
fn user_sid() -> Result<String, Error> {
    let mut token = null_mut();
    // SAFETY: the token is closed by `Owned`.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error("reading this process's token"));
    }
    let token = Owned(token);
    let mut needed = 0u32;
    // SAFETY: asks the size first, then fills an aligned buffer that big.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed) };
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(last_error("reading this process's user"));
    }
    let user = buffer.as_ptr().cast::<TOKEN_USER>();
    let mut text = null_mut();
    // SAFETY: the SID is inside `buffer`; the string is freed below.
    if unsafe { ConvertSidToStringSidW((*user).User.Sid, &mut text) } == 0 {
        return Err(last_error("reading this process's user"));
    }
    // SAFETY: a NUL-terminated string Windows allocated.
    let sid = unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let sid = String::from_utf16_lossy(core::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        sid
    };
    Ok(sid)
}

/// The client's end of the pipe.
struct Pipe {
    handle: HANDLE,
    event: Owned,
}

impl Drop for Pipe {
    fn drop(&mut self) {
        // SAFETY: owned, closed once.
        unsafe { CloseHandle(self.handle) };
    }
}

impl Pipe {
    /// One instance, inbound, local clients only, and a DACL that admits
    /// this user alone: the elevated helper is the same user.
    fn create(name: &str) -> Result<Pipe, Error> {
        let sddl = wide(&format!("D:P(A;;GA;;;{})", user_sid()?));
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: the descriptor is freed below, after the pipe exists.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(last_error("making the pipe's security descriptor"));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let name = wide(name);
        // SAFETY: the name is NUL-terminated; the handle is closed on drop.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                0,
                ANSWER_LEN as u32,
                0,
                &attributes,
            )
        };
        // SAFETY: allocated by the conversion above.
        unsafe { LocalFree(descriptor) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error("making the pipe"));
        }
        // SAFETY: a manual-reset event, closed by `Owned`.
        let event = Owned(unsafe { CreateEventW(null(), 1, 0, null()) });
        if event.0.is_null() {
            // SAFETY: made above.
            unsafe { CloseHandle(handle) };
            return Err(last_error("making an event"));
        }
        Ok(Pipe { handle, event })
    }

    /// Waits for the overlapped operation on `overlapped` to finish, the
    /// helper to exit, or `timeout`; cancels it unless it finished.
    fn wait(
        &self,
        overlapped: &OVERLAPPED,
        process: &Owned,
        timeout: Duration,
    ) -> Result<u32, Error> {
        let handles = [self.event.0, process.0];
        let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: both handles are open for the duration.
        let which = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, ms) };
        let mut done = 0u32;
        // SAFETY: `overlapped` is the one in flight on this pipe.
        unsafe {
            if which == WAIT_OBJECT_0
                && GetOverlappedResult(self.handle, overlapped, &mut done, 0) != 0
            {
                return Ok(done);
            }
            CancelIoEx(self.handle, overlapped);
            let _ = GetOverlappedResult(self.handle, overlapped, &mut done, 1);
        }
        Err(if which == WAIT_OBJECT_0 + 1 {
            // The helper went without a word: closed, or it failed and said
            // so in its window.
            Error::Helper
        } else if which == WAIT_TIMEOUT {
            Error::Timeout
        } else {
            last_error("waiting for the helper")
        })
    }

    fn connect(&self, process: &Owned) -> Result<(), Error> {
        let mut overlapped: OVERLAPPED = unsafe { core::mem::zeroed() };
        overlapped.hEvent = self.event.0;
        // SAFETY: `overlapped` outlives the operation, which `wait` ends.
        unsafe {
            ResetEvent(self.event.0);
            if ConnectNamedPipe(self.handle, &mut overlapped) == 0 {
                match GetLastError() {
                    ERROR_PIPE_CONNECTED => return Ok(()),
                    ERROR_IO_PENDING => {}
                    _ => return Err(last_error("waiting for the helper")),
                }
            } else {
                return Ok(());
            }
        }
        self.wait(&overlapped, process, CONNECT_TIMEOUT).map(|_| ())
    }

    /// Exactly [`ANSWER_LEN`] bytes, or an error.
    fn read_answer(&self, process: &Owned) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut answer = Zeroizing::new(vec![0u8; ANSWER_LEN]);
        let mut got = 0usize;
        while got < ANSWER_LEN {
            let mut overlapped: OVERLAPPED = unsafe { core::mem::zeroed() };
            overlapped.hEvent = self.event.0;
            let mut n = 0u32;
            // SAFETY: the slice and `overlapped` outlive the read, which
            // finishes or is cancelled and waited for before the next.
            let started = unsafe {
                ResetEvent(self.event.0);
                ReadFile(
                    self.handle,
                    answer[got..].as_mut_ptr(),
                    (ANSWER_LEN - got) as u32,
                    &mut n,
                    &mut overlapped,
                )
            };
            let n = if started != 0 {
                n
            } else {
                // SAFETY: reads the thread's last error.
                match unsafe { GetLastError() } {
                    ERROR_IO_PENDING => match self.wait(&overlapped, process, ANSWER_TIMEOUT) {
                        Ok(n) => n,
                        // The helper wrote and exited: what it wrote is
                        // still in the pipe, so read on.
                        Err(Error::Helper) => continue,
                        Err(e) => return Err(e),
                    },
                    ERROR_BROKEN_PIPE => break,
                    _ => return Err(last_error("reading the helper's answer")),
                }
            };
            if n == 0 {
                break;
            }
            got += n as usize;
        }
        if got != ANSWER_LEN {
            return Err(Error::Helper);
        }
        Ok(answer)
    }
}

/// Starts `exe` elevated: one UAC prompt. The person saying no there is a
/// cancellation.
fn start_elevated(exe: &std::path::Path, args: &[String]) -> Result<Owned, Error> {
    let file = wide(&exe.to_string_lossy());
    let verb = wide("runas");
    // Nothing on the command line has a space or a quote in it.
    let params = wide(&args.join(" "));
    let mut info: SHELLEXECUTEINFOW = unsafe { core::mem::zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = params.as_ptr();
    info.nShow = SW_SHOWNORMAL;
    // SAFETY: the strings outlive the call; the process handle is owned.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        // SAFETY: reads the thread's last error.
        return Err(match unsafe { GetLastError() } {
            ERROR_CANCELLED => Error::Cancelled,
            _ => last_error("starting silver-key.exe"),
        });
    }
    if info.hProcess.is_null() {
        return Err(Error::Windows(
            "silver-key.exe started with no process".into(),
        ));
    }
    Ok(Owned(info.hProcess))
}

// --- the helper's own end ---------------------------------------------------

/// The helper's whole work: connect to the client's pipe, do what the
/// command line asks with the key plugged in, write the answer. Returns
/// the error to show in the helper's window, if any.
pub fn serve(args: &[String], prompt: impl crate::Prompt) -> Result<(), Error> {
    let (pipe, request) = Request::from_args(args)?;
    let name = wide(&pipe);
    // SAFETY: the name is NUL-terminated; the handle is closed by `Owned`.
    let handle = Owned(unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            // The client learns who this is from the pipe, not the other
            // way round: it may identify this process and nothing more.
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    });
    if handle.0 == INVALID_HANDLE_VALUE {
        return Err(last_error("opening the client's pipe"));
    }
    let mut auth = crate::Direct::new(super::hid::find, prompt);
    let result = match &request {
        Request::Enroll { rp_id, input } => auth.enroll(rp_id, input).map(|e| Answer {
            index: 0,
            secret: e.secret,
            credential_id: e.credential_id,
        }),
        Request::Secret { rp_id, candidates } => {
            let borrowed: Vec<(&[u8], &[u8])> = candidates
                .iter()
                .map(|(id, input)| (id.as_slice(), input.as_slice()))
                .collect();
            auth.secret(rp_id, &borrowed).map(|(index, secret)| Answer {
                index,
                secret,
                credential_id: Vec::new(),
            })
        }
    };
    let shown = result.as_ref().err().map(|e| e.to_string());
    let answer = crate::helper_wire::encode_answer(result);
    let mut written = 0u32;
    // SAFETY: a synchronous write of the whole answer.
    if unsafe {
        WriteFile(
            handle.0,
            answer.as_ptr(),
            answer.len() as u32,
            &mut written,
            null_mut(),
        )
    } == 0
        || written as usize != answer.len()
    {
        return Err(last_error("writing to the client's pipe"));
    }
    // SAFETY: waits until the client has read it.
    unsafe { FlushFileBuffers(handle.0) };
    match shown {
        Some(text) => Err(Error::Windows(text)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_pipe_admits_this_user() {
        let name = crate::helper_wire::fresh_pipe_name();
        let pipe = super::Pipe::create(&name).unwrap();
        // A second instance under the same name is refused.
        assert!(super::Pipe::create(&name).is_err());
        drop(pipe);
        assert!(super::user_sid().unwrap().starts_with("S-1-"));
    }
}
