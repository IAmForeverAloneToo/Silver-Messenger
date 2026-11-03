//! What the client asks of a security key, whichever way the key is
//! reached: [`Authenticator`]. Directly over HID ([`Direct`]) the PIN is
//! the program's to ask for, through a [`Prompt`]; through Windows' own
//! API, or the Windows 10 helper, the PIN is asked for by them.

use zeroize::Zeroizing;

use crate::hid::Device;
use crate::{Error, Key};

/// Where the person at the computer is asked things.
pub trait Prompt {
    /// The key's PIN. `retries` is what the key says is left, when it
    /// says; `wrong` that the last one was wrong. `None` gives up.
    fn pin(&mut self, retries: Option<u32>, wrong: bool) -> Option<Zeroizing<String>>;
    /// A PIN for a key that has none yet, asked for twice. `None` gives
    /// up.
    fn new_pin(&mut self) -> Option<Zeroizing<String>>;
    /// No key is plugged in: ask for one. `false` gives up.
    fn insert(&mut self) -> bool;
    /// What to call while the key waits to be touched.
    fn touch(&mut self) -> Box<dyn FnMut() + Send>;
}

/// A credential just made, and the secret for the input it was made with.
pub struct Enrolled {
    pub credential_id: Vec<u8>,
    pub secret: Zeroizing<[u8; 32]>,
}

/// What unlocking with a security key needs from one.
pub trait Authenticator {
    /// Makes a credential for `rp_id` that answers only after the PIN and
    /// a touch, and returns it with its secret for `input`.
    fn enroll(&mut self, rp_id: &str, input: &[u8]) -> Result<Enrolled, Error>;

    /// The secret for whichever of `candidates` (a credential id, and the
    /// input that goes with it) the key plugged in holds: its index, and
    /// the 32 bytes.
    fn secret(
        &mut self,
        rp_id: &str,
        candidates: &[(&[u8], &[u8])],
    ) -> Result<(usize, Zeroizing<[u8; 32]>), Error>;
}

/// A key reached over HID by this program itself, the PIN asked for
/// through `prompt`. `find` returns the key plugged in, if any.
pub struct Direct<D, F, P> {
    find: F,
    prompt: P,
    _device: std::marker::PhantomData<fn() -> D>,
}

impl<D, F, P> Direct<D, F, P>
where
    D: Device,
    F: FnMut() -> Result<Option<D>, Error>,
    P: Prompt,
{
    pub fn new(find: F, prompt: P) -> Self {
        Direct {
            find,
            prompt,
            _device: std::marker::PhantomData,
        }
    }

    fn open(&mut self) -> Result<Key<D>, Error> {
        loop {
            if let Some(device) = (self.find)()? {
                let mut key = Key::open(device)?;
                key.on_touch(self.prompt.touch());
                return Ok(key);
            }
            if !self.prompt.insert() {
                return Err(Error::Cancelled);
            }
        }
    }

    /// Runs `f` with the PIN, asking again while it is wrong.
    fn with_pin<T>(
        &mut self,
        key: &mut Key<D>,
        mut f: impl FnMut(&mut Key<D>, &str) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut wrong = false;
        let mut retries = key.pin_retries().ok();
        loop {
            let pin = self.prompt.pin(retries, wrong).ok_or(Error::Cancelled)?;
            match f(key, &pin) {
                Err(Error::PinInvalid { retries: left }) => {
                    wrong = true;
                    retries = left;
                }
                other => return other,
            }
        }
    }
}

impl<D, F, P> Authenticator for Direct<D, F, P>
where
    D: Device,
    F: FnMut() -> Result<Option<D>, Error>,
    P: Prompt,
{
    fn enroll(&mut self, rp_id: &str, input: &[u8]) -> Result<Enrolled, Error> {
        let mut key = self.open()?;
        key.info().check()?;
        if key.info().client_pin == Some(false) {
            let pin = self.prompt.new_pin().ok_or(Error::Cancelled)?;
            key.set_pin(&pin)?;
        }
        self.with_pin(&mut key, |key, pin| {
            let credential_id = key.register(rp_id, pin)?;
            let (_, secret) = key.prf(rp_id, &[(&credential_id, input)], pin)?;
            Ok(Enrolled {
                credential_id,
                secret,
            })
        })
    }

    fn secret(
        &mut self,
        rp_id: &str,
        candidates: &[(&[u8], &[u8])],
    ) -> Result<(usize, Zeroizing<[u8; 32]>), Error> {
        let mut key = self.open()?;
        key.info().check()?;
        if key.info().client_pin == Some(false) {
            // A key with no PIN cannot hold a credential made here.
            return Err(Error::NoCredentials);
        }
        self.with_pin(&mut key, |key, pin| key.prf(rp_id, candidates, pin))
    }
}

/// The first FIDO key plugged in, on Linux.
#[cfg(target_os = "linux")]
pub fn find_hidraw() -> Result<Option<crate::hidraw::Hidraw>, Error> {
    match crate::hidraw::list()?.first() {
        Some(path) => Ok(Some(crate::hidraw::Hidraw::open(path)?)),
        None => Ok(None),
    }
}

/// The way to the key on this system.
pub fn platform(prompt: Box<dyn Prompt + Send>) -> Result<Box<dyn Authenticator>, Error> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(Direct::new(find_hidraw, prompt)))
    }
    #[cfg(windows)]
    {
        crate::windows::platform(prompt)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = prompt;
        Err(Error::Unavailable(
            "security keys are not supported on this system yet, only on Linux and Windows",
        ))
    }
}

impl<P: Prompt + ?Sized> Prompt for Box<P> {
    fn pin(&mut self, retries: Option<u32>, wrong: bool) -> Option<Zeroizing<String>> {
        (**self).pin(retries, wrong)
    }
    fn new_pin(&mut self) -> Option<Zeroizing<String>> {
        (**self).new_pin()
    }
    fn insert(&mut self) -> bool {
        (**self).insert()
    }
    fn touch(&mut self) -> Box<dyn FnMut() + Send> {
        (**self).touch()
    }
}
