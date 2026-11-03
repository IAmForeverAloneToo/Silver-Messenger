//! CTAPHID: how CTAP2 messages travel over USB HID (section 11.2 of the
//! CTAP 2.1 specification). A message is cut into 64-byte reports, the
//! first carrying the command and the length, the rest numbered; each
//! carries the channel the key gave this program at `INIT`, so that two
//! programs talking to one key do not read each other's answers.

use std::time::{Duration, Instant};

use rand::Rng;
use rand::rngs::SysRng;

use crate::Error;
use crate::cbor::{self, Value};

/// The size of a HID report on a FIDO key.
pub const REPORT: usize = 64;

/// A FIDO HID device: whole reports in, whole reports out.
pub trait Device {
    /// Sends one report.
    fn write_report(&mut self, report: &[u8; REPORT]) -> Result<(), Error>;
    /// The next report, or `None` if none came within `timeout`.
    fn read_report(&mut self, timeout: Duration) -> Result<Option<[u8; REPORT]>, Error>;
}

/// A device lent: so that the caller keeps it after a [`crate::Key`] is done.
impl<T: Device> Device for &mut T {
    fn write_report(&mut self, report: &[u8; REPORT]) -> Result<(), Error> {
        (**self).write_report(report)
    }

    fn read_report(&mut self, timeout: Duration) -> Result<Option<[u8; REPORT]>, Error> {
        (**self).read_report(timeout)
    }
}

pub(crate) const CMD_INIT: u8 = 0x86;
pub(crate) const CMD_CBOR: u8 = 0x90;
pub(crate) const CMD_KEEPALIVE: u8 = 0xbb;
pub(crate) const CMD_ERROR: u8 = 0xbf;
pub(crate) const BROADCAST: [u8; 4] = [0xff; 4];
/// The longest message the transport carries: one first report and 128
/// continuations.
pub(crate) const MAX_MESSAGE: usize = 57 + 128 * 59;
/// `CAPABILITY_CBOR` in the answer to `INIT`: the key speaks CTAP2.
pub(crate) const CAPABILITY_CBOR: u8 = 0x04;
/// `KEEPALIVE` with this status: the key is waiting for a touch.
pub(crate) const STATUS_UPNEEDED: u8 = 2;

/// How long to wait for any one report. A key sends a keepalive every
/// tenth of a second while it works or waits for a touch.
const REPORT_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a command may take in all, keepalives included: longer than
/// the 30 seconds a key waits for its touch.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(90);

/// The reports that carry `data` as command `cmd` on channel `cid`.
pub(crate) fn frame(cid: [u8; 4], cmd: u8, data: &[u8]) -> Vec<[u8; REPORT]> {
    assert!(
        data.len() <= MAX_MESSAGE,
        "a CTAPHID message is at most {MAX_MESSAGE} bytes"
    );
    let mut reports = Vec::new();
    let mut first = [0u8; REPORT];
    first[..4].copy_from_slice(&cid);
    first[4] = cmd;
    first[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let n = data.len().min(57);
    first[7..7 + n].copy_from_slice(&data[..n]);
    reports.push(first);
    for (seq, chunk) in data[n..].chunks(59).enumerate() {
        let mut report = [0u8; REPORT];
        report[..4].copy_from_slice(&cid);
        report[4] = seq as u8;
        report[5..5 + chunk.len()].copy_from_slice(chunk);
        reports.push(report);
    }
    reports
}

/// Reassembling one message from the reports that carry it.
pub(crate) struct Assembly {
    /// Read by the software authenticator, which serves channels.
    #[cfg_attr(not(any(test, feature = "soft")), allow(dead_code))]
    pub cid: [u8; 4],
    pub cmd: u8,
    pub len: usize,
    pub data: Vec<u8>,
    next_seq: u8,
}

impl Assembly {
    /// Starts from a first report; `None` if this is not one.
    pub fn start(report: &[u8; REPORT]) -> Result<Option<Assembly>, Error> {
        let cmd = report[4];
        if cmd & 0x80 == 0 {
            return Ok(None);
        }
        let len = usize::from(u16::from_be_bytes([report[5], report[6]]));
        if len > MAX_MESSAGE {
            return Err(Error::Malformed(
                "CTAPHID message longer than the transport allows",
            ));
        }
        let n = len.min(57);
        Ok(Some(Assembly {
            cid: report[..4].try_into().expect("4 bytes"),
            cmd,
            len,
            data: report[7..7 + n].to_vec(),
            next_seq: 0,
        }))
    }

    pub fn complete(&self) -> bool {
        self.data.len() == self.len
    }

    /// Adds a continuation report on the same channel.
    pub fn push(&mut self, report: &[u8; REPORT]) -> Result<(), Error> {
        if report[4] != self.next_seq {
            return Err(Error::Malformed("CTAPHID continuation out of sequence"));
        }
        self.next_seq += 1;
        let n = (self.len - self.data.len()).min(59);
        self.data.extend_from_slice(&report[5..5 + n]);
        Ok(())
    }
}

/// A channel to one key.
pub struct Channel<D> {
    device: D,
    cid: [u8; 4],
}

impl<D: Device> Channel<D> {
    /// Asks the key for a channel of this program's own.
    pub fn open(mut device: D) -> Result<Self, Error> {
        let mut nonce = [0u8; 8];
        random(&mut nonce);
        for report in frame(BROADCAST, CMD_INIT, &nonce) {
            device.write_report(&report)?;
        }
        let deadline = Instant::now() + REPORT_TIMEOUT;
        loop {
            let (cmd, data) = receive(&mut device, BROADCAST, deadline, &mut |_| {})?;
            // Another program's INIT on the broadcast channel: not ours.
            if cmd != CMD_INIT || data.len() < 17 || data[..8] != nonce {
                if cmd == CMD_ERROR {
                    return Err(Error::Hid(data.first().copied().unwrap_or(0)));
                }
                continue;
            }
            let cid: [u8; 4] = data[8..12].try_into().expect("4 bytes");
            if cid == BROADCAST || cid == [0; 4] {
                return Err(Error::Malformed("the key gave a reserved channel"));
            }
            if data[16] & CAPABILITY_CBOR == 0 {
                return Err(Error::Unsupported("CTAP2"));
            }
            return Ok(Channel { device, cid });
        }
    }

    /// Sends CTAP2 command `command` with `params`, and returns the key's
    /// answer: `Null` for an empty one. `on_touch` is called once if the
    /// key says it is waiting for a touch.
    pub fn cbor(
        &mut self,
        command: u8,
        params: Option<&Value>,
        on_touch: &mut dyn FnMut(),
    ) -> Result<Value, Error> {
        let mut message = vec![command];
        if let Some(p) = params {
            message.extend_from_slice(&p.encode());
        }
        if message.len() > MAX_MESSAGE {
            return Err(Error::Malformed("CTAP2 request too long"));
        }
        for report in frame(self.cid, CMD_CBOR, &message) {
            self.device.write_report(&report)?;
        }
        let mut asked = false;
        let mut status = |s: u8| {
            if s == STATUS_UPNEEDED && !asked {
                asked = true;
                on_touch();
            }
        };
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let (cmd, data) = receive(&mut self.device, self.cid, deadline, &mut status)?;
        match cmd {
            CMD_CBOR => match data.split_first() {
                None => Err(Error::Malformed("empty CTAP2 answer")),
                Some((0, [])) => Ok(Value::Null),
                Some((0, rest)) => cbor::decode(rest),
                Some((&code, _)) => Err(Error::from_ctap(code)),
            },
            CMD_ERROR => Err(Error::Hid(data.first().copied().unwrap_or(0))),
            _ => Err(Error::Malformed("unexpected CTAPHID command in the answer")),
        }
    }
}

/// The next whole message on channel `cid`, passing keepalives' status to
/// `on_status` and skipping reports for other channels.
fn receive<D: Device>(
    device: &mut D,
    cid: [u8; 4],
    deadline: Instant,
    on_status: &mut dyn FnMut(u8),
) -> Result<(u8, Vec<u8>), Error> {
    let mut next = || -> Result<[u8; REPORT], Error> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Timeout);
            }
            let wait = (deadline - now).min(REPORT_TIMEOUT);
            match device.read_report(wait)? {
                Some(r) if r[..4] == cid => return Ok(r),
                Some(_) => continue,
                None => return Err(Error::Timeout),
            }
        }
    };
    loop {
        let first = next()?;
        let Some(mut assembly) = Assembly::start(&first)? else {
            continue; // a stray continuation
        };
        while !assembly.complete() {
            assembly.push(&next()?)?;
        }
        if assembly.cmd == CMD_KEEPALIVE {
            on_status(assembly.data.first().copied().unwrap_or(0));
            continue;
        }
        return Ok((assembly.cmd, assembly.data));
    }
}

/// Fills `buf` from the operating system's generator; a failure there is
/// not something to carry on from.
pub(crate) fn random(buf: &mut [u8]) {
    rand::rand_core::UnwrapErr(SysRng).fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_message_is_cut_and_put_back_together() {
        let data: Vec<u8> = (0..300u16).map(|i| i as u8).collect();
        let reports = frame([1, 2, 3, 4], CMD_CBOR, &data);
        assert_eq!(reports.len(), 1 + (300 - 57usize).div_ceil(59));
        let mut a = Assembly::start(&reports[0]).unwrap().unwrap();
        assert_eq!((a.cid, a.cmd, a.len), ([1, 2, 3, 4], CMD_CBOR, 300));
        for r in &reports[1..] {
            a.push(r).unwrap();
        }
        assert!(a.complete());
        assert_eq!(a.data, data);
    }

    #[test]
    fn continuations_out_of_order_are_refused() {
        let reports = frame([1, 2, 3, 4], CMD_CBOR, &[7u8; 200]);
        let mut a = Assembly::start(&reports[0]).unwrap().unwrap();
        assert!(a.push(&reports[2]).is_err());
    }

    #[test]
    fn an_impossible_length_is_refused() {
        let mut r = [0u8; REPORT];
        r[4] = CMD_CBOR;
        r[5..7].copy_from_slice(&0xffffu16.to_be_bytes());
        assert!(Assembly::start(&r).is_err());
    }
}
