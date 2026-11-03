//! A software authenticator, for tests: it answers CTAPHID and CTAP2 as a
//! key does, from a fixed seed, so that registering, the PIN and the
//! `hmac-secret` secret are tested on every platform without hardware.
//! It keeps no credentials: an id carries its own MAC under the seed, as
//! real keys do, and the secret behind it is derived from the seed too, so
//! two `SoftKey`s with one seed are the same key.
//!
//! Never part of a release build (the `soft` feature).

use std::collections::VecDeque;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use p256::SecretKey;
use sha2::{Digest, Sha256};

use crate::Error;
use crate::cbor::{self, Value};
use crate::hid::{
    Assembly, BROADCAST, CAPABILITY_CBOR, CMD_CBOR, CMD_ERROR, CMD_INIT, CMD_KEEPALIVE, Device,
    REPORT, STATUS_UPNEEDED, frame,
};
use crate::pin::{Protocol, cose_key, cose_key_with_alg, fresh_secret_key, parse_cose_key};
use crate::status::*;

const CHANNEL: [u8; 4] = [0x51, 0x4c, 0x56, 0x52];
const MAX_RETRIES: u8 = 8;

/// What the key does when asked for a touch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Touch {
    Given,
    /// Nobody touches it: the key gives up (USER_ACTION_TIMEOUT).
    NotGiven,
}

/// A software security key.
pub struct SoftKey {
    seed: [u8; 32],
    protocols: Vec<Protocol>,
    pin_uv_auth_token: bool,
    hmac_secret: bool,
    pin_hash: Option<[u8; 16]>,
    retries: u8,
    wrong_in_a_row: u8,
    agreement: SecretKey,
    token: Option<Token>,
    pub touch: Touch,
    touches: u32,
    counter: u32,
    incoming: Option<Assembly>,
    outgoing: VecDeque<[u8; REPORT]>,
}

struct Token {
    value: [u8; 32],
    permissions: i64,
    rp_id: Option<String>,
}

impl SoftKey {
    /// A CTAP 2.1 key with PIN protocols 2 and 1 and no PIN set.
    pub fn new(seed: [u8; 32]) -> SoftKey {
        SoftKey {
            seed,
            protocols: vec![Protocol::Two, Protocol::One],
            pin_uv_auth_token: true,
            hmac_secret: true,
            pin_hash: None,
            retries: MAX_RETRIES,
            wrong_in_a_row: 0,
            agreement: fresh_secret_key(),
            token: None,
            touch: Touch::Given,
            touches: 0,
            counter: 0,
            incoming: None,
            outgoing: VecDeque::new(),
        }
    }

    /// With `pin` already set.
    pub fn with_pin(mut self, pin: &str) -> SoftKey {
        self.pin_hash = Some(pin_hash(pin.as_bytes()));
        self
    }

    /// A CTAP 2.0 key: PIN protocol 1, no PIN token permissions.
    pub fn ctap_2_0(mut self) -> SoftKey {
        self.protocols = vec![Protocol::One];
        self.pin_uv_auth_token = false;
        self
    }

    /// A key without the `hmac-secret` extension.
    pub fn without_hmac_secret(mut self) -> SoftKey {
        self.hmac_secret = false;
        self
    }

    /// How many times the key has been touched.
    pub fn touches(&self) -> u32 {
        self.touches
    }

    pub fn retries(&self) -> u8 {
        self.retries
    }

    /// Unplugged and plugged back in: the key agreement key and the token
    /// go, and three wrong PINs in a row may be tried again.
    pub fn replug(&mut self) {
        self.agreement = fresh_secret_key();
        self.token = None;
        self.wrong_in_a_row = 0;
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.seed).expect("any key");
        for p in parts {
            mac.update(p);
        }
        mac.finalize().into_bytes().into()
    }

    fn send(&mut self, cmd: u8, data: &[u8]) {
        self.outgoing.extend(frame(CHANNEL, cmd, data));
    }

    fn handle(&mut self, cid: [u8; 4], cmd: u8, data: &[u8]) {
        match cmd {
            CMD_INIT if cid == BROADCAST && data.len() == 8 => {
                let mut answer = data.to_vec();
                answer.extend_from_slice(&CHANNEL);
                answer.extend_from_slice(&[2, 5, 8, 0, CAPABILITY_CBOR | 0x08]);
                self.outgoing.extend(frame(BROADCAST, CMD_INIT, &answer));
            }
            CMD_CBOR if cid == CHANNEL && !data.is_empty() => {
                let answer = match self.ctap(data[0], &data[1..]) {
                    Ok(Some(v)) => [&[0u8][..], &v.encode()].concat(),
                    Ok(None) => vec![0],
                    Err(code) => vec![code],
                };
                self.send(CMD_CBOR, &answer);
            }
            _ => self.send(CMD_ERROR, &[0x01]),
        }
    }

    /// Waits for the touch, telling the program so as a real key does.
    fn ask_for_touch(&mut self) -> Result<(), u8> {
        self.send(CMD_KEEPALIVE, &[STATUS_UPNEEDED]);
        match self.touch {
            Touch::Given => {
                self.touches += 1;
                Ok(())
            }
            Touch::NotGiven => Err(USER_ACTION_TIMEOUT),
        }
    }

    fn ctap(&mut self, command: u8, params: &[u8]) -> Result<Option<Value>, u8> {
        let params = if params.is_empty() {
            Value::Null
        } else {
            cbor::decode(params).map_err(|_| 0x12)?
        };
        match command {
            0x04 => Ok(Some(self.get_info())),
            0x06 => self.client_pin(&params),
            0x01 => self.make_credential(&params).map(Some),
            0x02 => self.get_assertion(&params).map(Some),
            _ => Err(0x01),
        }
    }

    fn get_info(&self) -> Value {
        let mut extensions = vec![Value::from("credProtect")];
        if self.hmac_secret {
            extensions.push(Value::from("hmac-secret"));
        }
        let versions = if self.pin_uv_auth_token {
            vec![Value::from("FIDO_2_0"), Value::from("FIDO_2_1")]
        } else {
            vec![Value::from("FIDO_2_0")]
        };
        Value::map([
            (1, Value::Array(versions)),
            (2, Value::Array(extensions)),
            (3, Value::Bytes(vec![0x5e; 16])),
            (
                4,
                Value::map([
                    ("rk", Value::Bool(true)),
                    ("up", Value::Bool(true)),
                    ("clientPin", Value::Bool(self.pin_hash.is_some())),
                    ("pinUvAuthToken", Value::Bool(self.pin_uv_auth_token)),
                ]),
            ),
            (5, Value::Int(1200)),
            (
                6,
                Value::Array(
                    self.protocols
                        .iter()
                        .map(|p| Value::Int(p.number()))
                        .collect(),
                ),
            ),
        ])
    }

    fn protocol(&self, value: Option<&Value>) -> Result<Protocol, u8> {
        let protocol = value
            .and_then(Value::as_int)
            .and_then(Protocol::from_number)
            .ok_or(MISSING_PARAMETER)?;
        if !self.protocols.contains(&protocol) {
            return Err(INVALID_PARAMETER);
        }
        Ok(protocol)
    }

    fn client_pin(&mut self, p: &Value) -> Result<Option<Value>, u8> {
        let protocol = self.protocol(p.get(1))?;
        let sub = p.get(2).and_then(Value::as_int).ok_or(MISSING_PARAMETER)?;
        let shared = || -> Result<_, u8> {
            let peer = parse_cose_key(p.get(3).ok_or(MISSING_PARAMETER)?)
                .map_err(|_| INVALID_PARAMETER)?;
            Ok(protocol.shared(&self.agreement, &peer))
        };
        match sub {
            0x01 => Ok(Some(Value::map([(3, Value::Int(i64::from(self.retries)))]))),
            0x02 => Ok(Some(Value::map([(
                1,
                cose_key(&self.agreement.public_key()),
            )]))),
            0x03 => {
                if self.pin_hash.is_some() {
                    return Err(PIN_AUTH_INVALID);
                }
                let shared = shared()?;
                let new_pin_enc = p
                    .get(5)
                    .and_then(Value::as_bytes)
                    .ok_or(MISSING_PARAMETER)?;
                let auth = p
                    .get(4)
                    .and_then(Value::as_bytes)
                    .ok_or(MISSING_PARAMETER)?;
                if shared.authenticate(new_pin_enc) != auth {
                    return Err(PIN_AUTH_INVALID);
                }
                let padded = shared.decrypt(new_pin_enc).map_err(|_| PIN_AUTH_INVALID)?;
                if padded.len() != 64 {
                    return Err(PIN_POLICY_VIOLATION);
                }
                let pin: Vec<u8> = padded.iter().copied().take_while(|b| *b != 0).collect();
                if pin.len() < 4 {
                    return Err(PIN_POLICY_VIOLATION);
                }
                self.pin_hash = Some(pin_hash(&pin));
                self.retries = MAX_RETRIES;
                Ok(None)
            }
            0x05 | 0x09 => {
                let Some(want) = self.pin_hash else {
                    return Err(PIN_NOT_SET);
                };
                if self.retries == 0 {
                    return Err(PIN_BLOCKED);
                }
                if self.wrong_in_a_row >= 3 {
                    return Err(PIN_AUTH_BLOCKED);
                }
                let (permissions, rp_id) = if sub == 0x09 {
                    if !self.pin_uv_auth_token {
                        return Err(0x01);
                    }
                    let perms = p.get(9).and_then(Value::as_int).ok_or(MISSING_PARAMETER)?;
                    if perms == 0 {
                        return Err(INVALID_PARAMETER);
                    }
                    (perms, p.get(10).and_then(Value::as_text).map(str::to_owned))
                } else {
                    (PERMISSIONS_ALL, None)
                };
                let shared = shared()?;
                let sealed = p
                    .get(6)
                    .and_then(Value::as_bytes)
                    .ok_or(MISSING_PARAMETER)?;
                let given = shared.decrypt(sealed).map_err(|_| PIN_AUTH_INVALID)?;
                self.retries -= 1;
                if given.as_slice() != want {
                    self.agreement = fresh_secret_key();
                    self.wrong_in_a_row += 1;
                    return Err(if self.retries == 0 {
                        PIN_BLOCKED
                    } else if self.wrong_in_a_row >= 3 {
                        PIN_AUTH_BLOCKED
                    } else {
                        PIN_INVALID
                    });
                }
                self.retries = MAX_RETRIES;
                self.wrong_in_a_row = 0;
                let mut value = [0u8; 32];
                crate::hid::random(&mut value);
                self.token = Some(Token {
                    value,
                    permissions,
                    rp_id,
                });
                Ok(Some(Value::map([(
                    2,
                    Value::Bytes(shared.encrypt(&value)),
                )])))
            }
            _ => Err(INVALID_PARAMETER),
        }
    }

    /// Whether `param` proves the PIN token over `message` for `permission`
    /// on `rp_id`. `Ok(false)` when there is no param.
    fn verified(
        &self,
        param: Option<&Value>,
        protocol: Option<&Value>,
        message: &[u8],
        permission: i64,
        rp_id: &str,
    ) -> Result<bool, u8> {
        let Some(param) = param else {
            return if self.pin_hash.is_some() && permission == PERMISSION_MC {
                Err(PUAT_REQUIRED)
            } else {
                Ok(false)
            };
        };
        let protocol = self.protocol(protocol)?;
        let token = self.token.as_ref().ok_or(PIN_AUTH_INVALID)?;
        if param.as_bytes() != Some(&protocol.authenticate(&token.value, message)[..])
            || token.permissions & permission == 0
            || token.rp_id.as_deref().is_some_and(|r| r != rp_id)
        {
            return Err(PIN_AUTH_INVALID);
        }
        Ok(true)
    }

    fn credential_id(&self, rp_hash: &[u8], nonce: &[u8; 16], level: u8) -> Vec<u8> {
        let tag = self.mac(&[b"id", rp_hash, nonce, &[level]]);
        [&nonce[..], &[level], &tag[..16]].concat()
    }

    /// The protection level of `id` if it is one of this key's for
    /// `rp_hash`.
    fn open_credential(&self, rp_hash: &[u8], id: &[u8]) -> Option<u8> {
        if id.len() != 33 {
            return None;
        }
        let nonce: [u8; 16] = id[..16].try_into().ok()?;
        (self.credential_id(rp_hash, &nonce, id[16]) == id).then_some(id[16])
    }

    fn make_credential(&mut self, p: &Value) -> Result<Value, u8> {
        let cdh = p
            .get(1)
            .and_then(Value::as_bytes)
            .ok_or(MISSING_PARAMETER)?;
        let rp_id = p
            .get(2)
            .and_then(|r| r.get("id"))
            .and_then(Value::as_text)
            .ok_or(MISSING_PARAMETER)?;
        p.get(3)
            .and_then(|u| u.get("id"))
            .and_then(Value::as_bytes)
            .ok_or(MISSING_PARAMETER)?;
        let algs = p
            .get(4)
            .and_then(Value::as_array)
            .ok_or(MISSING_PARAMETER)?;
        if !algs
            .iter()
            .any(|a| a.get("alg").and_then(Value::as_int) == Some(-7))
        {
            return Err(UNSUPPORTED_ALGORITHM);
        }
        let uv = self.verified(p.get(8), p.get(9), cdh, PERMISSION_MC, rp_id)?;
        self.ask_for_touch()?;
        let ext = p.get(6);
        let hmac_secret = self.hmac_secret
            && ext
                .and_then(|e| e.get("hmac-secret"))
                .and_then(Value::as_bool)
                == Some(true);
        let level = ext
            .and_then(|e| e.get("credProtect"))
            .and_then(Value::as_int)
            .unwrap_or(1);
        let level = u8::try_from(level)
            .ok()
            .filter(|l| (1..=3).contains(l))
            .ok_or(INVALID_PARAMETER)?;
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let mut nonce = [0u8; 16];
        crate::hid::random(&mut nonce);
        let id = self.credential_id(&rp_hash, &nonce, level);
        let mut out_ext = vec![("credProtect", Value::Int(i64::from(level)))];
        if hmac_secret {
            out_ext.push(("hmac-secret", Value::Bool(true)));
        }
        self.counter += 1;
        let mut auth_data = rp_hash.to_vec();
        auth_data.push(0x01 | if uv { 0x04 } else { 0 } | 0x40 | 0x80);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        auth_data.extend_from_slice(&[0x5e; 16]);
        auth_data.extend_from_slice(&(id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&id);
        // A stand-in for the credential's public key: nothing checks it.
        auth_data.extend_from_slice(&cose_key_with_alg(&self.agreement.public_key(), -7).encode());
        auth_data.extend_from_slice(&Value::map(out_ext).encode());
        Ok(Value::map([
            (1, Value::from("none")),
            (2, Value::Bytes(auth_data)),
            (3, Value::Map(vec![])),
        ]))
    }

    fn get_assertion(&mut self, p: &Value) -> Result<Value, u8> {
        let rp_id = p.get(1).and_then(Value::as_text).ok_or(MISSING_PARAMETER)?;
        let cdh = p
            .get(2)
            .and_then(Value::as_bytes)
            .ok_or(MISSING_PARAMETER)?;
        let uv = self.verified(p.get(6), p.get(7), cdh, PERMISSION_GA, rp_id)?;
        let rp_hash = Sha256::digest(rp_id.as_bytes());
        let allow = p.get(3).and_then(Value::as_array).unwrap_or_default();
        let id = allow
            .iter()
            .filter_map(|c| c.get("id").and_then(Value::as_bytes))
            .find(|id| {
                self.open_credential(&rp_hash, id)
                    .is_some_and(|level| level < 3 || uv)
            })
            .ok_or(NO_CREDENTIALS)?
            .to_vec();
        self.ask_for_touch()?;
        let mut flags = 0x01 | if uv { 0x04 } else { 0 };
        let mut extensions = None;
        if let Some(hs) = p.get(4).and_then(|e| e.get("hmac-secret")) {
            if !self.hmac_secret {
                return Err(0x2c);
            }
            let protocol = match hs.get(4) {
                None => Protocol::One,
                some => self.protocol(some)?,
            };
            let peer = parse_cose_key(hs.get(1).ok_or(MISSING_PARAMETER)?)
                .map_err(|_| INVALID_PARAMETER)?;
            let shared = protocol.shared(&self.agreement, &peer);
            let salt_enc = hs
                .get(2)
                .and_then(Value::as_bytes)
                .ok_or(MISSING_PARAMETER)?;
            let salt_auth = hs
                .get(3)
                .and_then(Value::as_bytes)
                .ok_or(MISSING_PARAMETER)?;
            if shared.authenticate(salt_enc) != salt_auth {
                return Err(0x2c);
            }
            let salts = shared.decrypt(salt_enc).map_err(|_| INVALID_PARAMETER)?;
            if salts.len() != 32 && salts.len() != 64 {
                return Err(INVALID_PARAMETER);
            }
            let cred_random = self.mac(&[if uv { b"uv" } else { b"--" }, &id]);
            let mut output = Vec::new();
            for salt in salts.chunks(32) {
                let mut mac =
                    <Hmac<Sha256> as KeyInit>::new_from_slice(&cred_random).expect("any key");
                mac.update(salt);
                output.extend_from_slice(&mac.finalize().into_bytes());
            }
            extensions = Some(Value::map([(
                "hmac-secret",
                Value::Bytes(shared.encrypt(&output)),
            )]));
            flags |= 0x80;
        }
        self.counter += 1;
        let mut auth_data = rp_hash.to_vec();
        auth_data.push(flags);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        if let Some(e) = extensions {
            auth_data.extend_from_slice(&e.encode());
        }
        Ok(Value::map([
            (
                1,
                Value::map([
                    ("id", Value::Bytes(id)),
                    ("type", Value::from("public-key")),
                ]),
            ),
            (2, Value::Bytes(auth_data)),
            (3, Value::Bytes(vec![0; 64])),
        ]))
    }
}

const PERMISSION_MC: i64 = 0x01;
const PERMISSION_GA: i64 = 0x02;
const PERMISSIONS_ALL: i64 = 0x03;

fn pin_hash(pin: &[u8]) -> [u8; 16] {
    Sha256::digest(pin)[..16].try_into().expect("16 bytes")
}

impl Device for SoftKey {
    fn write_report(&mut self, report: &[u8; REPORT]) -> Result<(), Error> {
        match Assembly::start(report)? {
            Some(a) => self.incoming = Some(a),
            None => match self.incoming.as_mut() {
                Some(a) if a.cid == report[..4] => a.push(report)?,
                _ => return Ok(()),
            },
        }
        if self.incoming.as_ref().is_some_and(Assembly::complete) {
            let a = self.incoming.take().expect("just checked");
            self.handle(a.cid, a.cmd, &a.data);
        }
        Ok(())
    }

    fn read_report(&mut self, _timeout: Duration) -> Result<Option<[u8; REPORT]>, Error> {
        Ok(self.outgoing.pop_front())
    }
}

/// One software key shared between the [`crate::Key`]s opened on it, as one
/// key plugged in is shared between the program's runs.
impl Device for std::sync::Arc<std::sync::Mutex<SoftKey>> {
    fn write_report(&mut self, report: &[u8; REPORT]) -> Result<(), Error> {
        self.lock()
            .unwrap_or_else(|e| e.into_inner())
            .write_report(report)
    }

    fn read_report(&mut self, timeout: Duration) -> Result<Option<[u8; REPORT]>, Error> {
        self.lock()
            .unwrap_or_else(|e| e.into_inner())
            .read_report(timeout)
    }
}

/// A [`Prompt`](crate::Prompt) that answers with one PIN every time, for
/// tests. `None` is a key nobody types a PIN for.
#[derive(Clone)]
pub struct FixedPin(pub Option<String>);

impl crate::Prompt for FixedPin {
    fn pin(&mut self, _retries: Option<u32>, wrong: bool) -> Option<zeroize::Zeroizing<String>> {
        if wrong {
            return None;
        }
        self.0.clone().map(zeroize::Zeroizing::new)
    }

    fn new_pin(&mut self) -> Option<zeroize::Zeroizing<String>> {
        self.0.clone().map(zeroize::Zeroizing::new)
    }

    fn insert(&mut self) -> bool {
        false
    }

    fn touch(&mut self) -> Box<dyn FnMut() + Send> {
        Box::new(|| {})
    }
}

/// An [`Authenticator`](crate::Authenticator) on `key`, the PIN prompt
/// answering with `pin` (and giving up once it was wrong).
pub fn authenticator(
    key: std::sync::Arc<std::sync::Mutex<SoftKey>>,
    pin: &str,
) -> impl crate::Authenticator {
    let pin = FixedPin(Some(pin.to_owned()));
    crate::Direct::new(move || Ok(Some(key.clone())), pin)
}
