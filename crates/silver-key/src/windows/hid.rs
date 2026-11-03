//! FIDO keys over HID on Windows, for the helper: found through SetupAPI
//! by the FIDO usage page, read and written with overlapped I/O so that a
//! read can give up. Windows lists them only to an elevated process.

use core::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::*;
use windows_sys::Win32::Devices::HumanInterfaceDevice::*;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::*;
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent};
use windows_sys::core::GUID;

use super::last_error;
use crate::Error;
use crate::hid::{Device, REPORT};

const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const FIDO_USAGE_CTAPHID: u16 = 0x01;

/// The device paths of the FIDO keys plugged in, NUL-terminated.
pub fn list() -> Result<Vec<Vec<u16>>, Error> {
    let mut guid: GUID = unsafe { core::mem::zeroed() };
    // SAFETY: fills the GUID.
    unsafe { HidD_GetHidGuid(&mut guid) };
    // SAFETY: a device information set, destroyed below.
    let set = unsafe {
        SetupDiGetClassDevsW(
            &guid,
            null(),
            null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    };
    if set == INVALID_HANDLE_VALUE as HDEVINFO {
        return Err(last_error("listing HID devices"));
    }
    let mut keys = Vec::new();
    for index in 0.. {
        let mut data: SP_DEVICE_INTERFACE_DATA = unsafe { core::mem::zeroed() };
        data.cbSize = size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
        // SAFETY: `data` is sized as the call wants.
        if unsafe { SetupDiEnumDeviceInterfaces(set, null(), &guid, index, &mut data) } == 0 {
            break;
        }
        let mut needed = 0u32;
        // SAFETY: asks only how big the detail is.
        unsafe {
            SetupDiGetDeviceInterfaceDetailW(set, &data, null_mut(), 0, &mut needed, null_mut())
        };
        if (needed as usize) < size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() {
            continue;
        }
        // u64s, so the buffer is aligned for the structure.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        let detail = buffer
            .as_mut_ptr()
            .cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
        // SAFETY: the buffer is `needed` bytes and aligned.
        let ok = unsafe {
            (*detail).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
            SetupDiGetDeviceInterfaceDetailW(set, &data, detail, needed, null_mut(), null_mut())
        };
        if ok == 0 {
            continue;
        }
        // SAFETY: a NUL-terminated wide string inside the buffer.
        let path = unsafe {
            let start = (&raw const (*detail).DevicePath).cast::<u16>();
            let max = (needed as usize - 4) / 2;
            let len = (0..max).take_while(|&i| *start.add(i) != 0).count();
            let mut path = core::slice::from_raw_parts(start, len).to_vec();
            path.push(0);
            path
        };
        if is_fido(&path) {
            keys.push(path);
        }
    }
    // SAFETY: made above.
    unsafe { SetupDiDestroyDeviceInfoList(set) };
    Ok(keys)
}

/// Whether the HID device at `path` is a FIDO key, by its usage page.
fn is_fido(path: &[u16]) -> bool {
    // SAFETY: opened with no access, for asking the device what it is.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return false;
    }
    let mut fido = false;
    let mut preparsed: PHIDP_PREPARSED_DATA = 0;
    // SAFETY: preparsed data freed below; caps filled by HidP_GetCaps.
    unsafe {
        if HidD_GetPreparsedData(handle, &mut preparsed) {
            let mut caps: HIDP_CAPS = core::mem::zeroed();
            if HidP_GetCaps(preparsed, &mut caps) == HIDP_STATUS_SUCCESS {
                fido = caps.UsagePage == FIDO_USAGE_PAGE && caps.Usage == FIDO_USAGE_CTAPHID;
            }
            HidD_FreePreparsedData(preparsed);
        }
        CloseHandle(handle);
    }
    fido
}

/// A key opened for reading and writing.
pub struct WinHid {
    handle: HANDLE,
    event: HANDLE,
}

// The handles are used from one thread at a time, through `&mut`.
unsafe impl Send for WinHid {}

impl WinHid {
    pub fn open(path: &[u16]) -> Result<WinHid, Error> {
        // SAFETY: a NUL-terminated path; the handle is closed on drop.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(last_error("opening the security key"));
        }
        // SAFETY: a manual-reset event, closed on drop.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            let e = last_error("making an event");
            // SAFETY: opened above.
            unsafe { CloseHandle(handle) };
            return Err(e);
        }
        Ok(WinHid { handle, event })
    }

    /// One overlapped transfer, waited for up to `timeout`. `Ok(None)` if
    /// it did not finish in time; it is cancelled and its end waited for
    /// either way, so `buffer` is never written after this returns.
    fn transfer(
        &mut self,
        write: bool,
        buffer: &mut [u8; REPORT + 1],
        timeout: Duration,
    ) -> Result<Option<usize>, Error> {
        let mut overlapped: OVERLAPPED = unsafe { core::mem::zeroed() };
        overlapped.hEvent = self.event;
        // SAFETY: `buffer` and `overlapped` outlive the transfer, which is
        // finished or cancelled and waited for before this returns.
        unsafe {
            ResetEvent(self.event);
            let started = if write {
                WriteFile(
                    self.handle,
                    buffer.as_ptr(),
                    buffer.len() as u32,
                    null_mut(),
                    &mut overlapped,
                )
            } else {
                ReadFile(
                    self.handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    null_mut(),
                    &mut overlapped,
                )
            };
            if started == 0 && GetLastError() != ERROR_IO_PENDING {
                return Err(last_error("talking to the security key"));
            }
            let mut done = 0u32;
            let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
            if GetOverlappedResultEx(self.handle, &overlapped, &mut done, ms, 0) != 0 {
                return Ok(Some(done as usize));
            }
            let error = GetLastError();
            CancelIoEx(self.handle, &overlapped);
            let _ = GetOverlappedResult(self.handle, &overlapped, &mut done, 1);
            if error == WAIT_TIMEOUT {
                Ok(None)
            } else {
                Err(Error::Windows(format!(
                    "talking to the security key: {}",
                    std::io::Error::from_raw_os_error(error as i32)
                )))
            }
        }
    }
}

impl Device for WinHid {
    fn write_report(&mut self, report: &[u8; REPORT]) -> Result<(), Error> {
        // Report id 0 first, as on every platform.
        let mut buffer = [0u8; REPORT + 1];
        buffer[1..].copy_from_slice(report);
        match self.transfer(true, &mut buffer, Duration::from_secs(1))? {
            Some(n) if n == buffer.len() => Ok(()),
            Some(_) => Err(Error::Malformed("short write to the key")),
            None => Err(Error::Timeout),
        }
    }

    fn read_report(&mut self, timeout: Duration) -> Result<Option<[u8; REPORT]>, Error> {
        let mut buffer = [0u8; REPORT + 1];
        match self.transfer(false, &mut buffer, timeout)? {
            Some(n) if n == buffer.len() => {
                let mut report = [0u8; REPORT];
                report.copy_from_slice(&buffer[1..]);
                Ok(Some(report))
            }
            Some(_) => Err(Error::Malformed("short report from the key")),
            None => Ok(None),
        }
    }
}

impl Drop for WinHid {
    fn drop(&mut self) {
        // SAFETY: both opened in `open`, closed once.
        unsafe {
            CloseHandle(self.event);
            CloseHandle(self.handle);
        }
    }
}

/// The first FIDO key plugged in.
pub fn find() -> Result<Option<WinHid>, Error> {
    match list()?.first() {
        Some(path) => Ok(Some(WinHid::open(path)?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn listing_the_keys_works_with_or_without_one() {
        // Not elevated, Windows lists none; elevated, the ones plugged in.
        let keys = super::list().unwrap();
        assert!(keys.iter().all(|p| p.last() == Some(&0)));
    }
}
