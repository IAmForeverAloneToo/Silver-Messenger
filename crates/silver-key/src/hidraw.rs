//! Security keys on Linux, through `/dev/hidraw*`: a FIDO key is the HID
//! device whose report descriptor declares the FIDO usage page (0xF1D0)
//! and usage 1. The device node needs read and write access, which the
//! udev rule libfido2's packages install gives the logged-in user.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::Error;
use crate::hid::{Device, REPORT};

const FIDO_USAGE_PAGE: u32 = 0xf1d0;
const FIDO_USAGE_CTAPHID: u32 = 0x01;
/// How often a read is retried while waiting for the key.
const POLL: Duration = Duration::from_millis(5);

/// The device nodes of the FIDO keys plugged in.
pub fn list() -> Result<Vec<PathBuf>, Error> {
    let mut keys = Vec::new();
    let entries = match fs::read_dir("/sys/class/hidraw") {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(keys),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let entry = entry?;
        let Ok(descriptor) = fs::read(entry.path().join("device/report_descriptor")) else {
            continue;
        };
        if is_fido(&descriptor) {
            keys.push(Path::new("/dev").join(entry.file_name()));
        }
    }
    keys.sort();
    Ok(keys)
}

/// Whether a HID report descriptor is a FIDO key's: the usage page and
/// usage of its first top-level collection.
pub fn is_fido(descriptor: &[u8]) -> bool {
    let (mut page, mut usage) = (None, None);
    let mut i = 0;
    while i < descriptor.len() {
        let prefix = descriptor[i];
        if prefix == 0xfe {
            // A long item: its data size is in the next byte.
            let Some(&size) = descriptor.get(i + 1) else {
                return false;
            };
            i += 3 + usize::from(size);
            continue;
        }
        let size = [0, 1, 2, 4][usize::from(prefix & 0x03)];
        let Some(data) = descriptor.get(i + 1..i + 1 + size) else {
            return false;
        };
        let value = data
            .iter()
            .rev()
            .fold(0u32, |acc, b| (acc << 8) | u32::from(*b));
        match prefix & 0xfc {
            0x04 => page = Some(value),                     // Usage Page (global)
            0x08 if usage.is_none() => usage = Some(value), // Usage (local)
            0xa0 => break,                                  // Collection
            _ => {}
        }
        i += 1 + size;
    }
    page == Some(FIDO_USAGE_PAGE) && usage == Some(FIDO_USAGE_CTAPHID)
}

/// A key through its `/dev/hidraw` node.
pub struct Hidraw {
    file: File,
}

impl Hidraw {
    pub fn open(path: &Path) -> Result<Hidraw, Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        Ok(Hidraw { file })
    }
}

impl Device for Hidraw {
    fn write_report(&mut self, report: &[u8; REPORT]) -> Result<(), Error> {
        // Report id 0 first: FIDO keys use unnumbered reports.
        let mut out = [0u8; REPORT + 1];
        out[1..].copy_from_slice(report);
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match self.file.write(&out) {
                Ok(n) if n == out.len() => return Ok(()),
                Ok(_) => return Err(Error::Malformed("short write to the key")),
                Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(POLL)
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn read_report(&mut self, timeout: Duration) -> Result<Option<[u8; REPORT]>, Error> {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; REPORT];
        loop {
            match self.file.read(&mut buf) {
                Ok(REPORT) => return Ok(Some(buf)),
                Ok(_) => return Err(Error::Malformed("short report from the key")),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(POLL);
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fido_descriptor_is_recognised_and_a_keyboard_is_not() {
        // A YubiKey's FIDO interface.
        let fido = [
            0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00,
            0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75,
            0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
        ];
        assert!(is_fido(&fido));
        // A boot keyboard: Generic Desktop, Keyboard.
        let keyboard = [0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0xc0];
        assert!(!is_fido(&keyboard));
        assert!(!is_fido(&[0x06, 0xd0])); // cut short
        assert!(!is_fido(&[]));
    }
}
