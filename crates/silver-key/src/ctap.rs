//! The CTAP2 commands: what the key is, its PIN, making a credential, and
//! the `hmac-secret` assertion that gives the secret.

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::cbor::Value;
use crate::hid::{Channel, Device, random};
use crate::pin::{Protocol, Shared, parse_cose_key};
use crate::{Error, prf_salt};

const MAKE_CREDENTIAL: u8 = 0x01;
const GET_ASSERTION: u8 = 0x02;
const GET_INFO: u8 = 0x04;
const CLIENT_PIN: u8 = 0x06;

const PIN_GET_RETRIES: i64 = 0x01;
const PIN_GET_KEY_AGREEMENT: i64 = 0x02;
const PIN_SET: i64 = 0x03;
const PIN_GET_TOKEN: i64 = 0x05;
const PIN_GET_TOKEN_WITH_PERMISSIONS: i64 = 0x09;

/// pinUvAuthToken permissions: makeCredential, getAssertion.
const PERMISSION_MC: i64 = 0x01;
const PERMISSION_GA: i64 = 0x02;

/// credProtect level 3: the credential is used only with user
/// verification, and does not even show it exists without.
const CRED_PROTECT_UV_REQUIRED: i64 = 3;

/// Authenticator data flags.
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

/// ES256, the one signature algorithm asked for; the credential's own key
/// signs nothing this program checks, but makeCredential needs one.
const ES256: i64 = -7;

/// What a key says about itself (authenticatorGetInfo).
#[derive(Clone, Debug, Default)]
pub struct Info {
    pub versions: Vec<String>,
    pub extensions: Vec<String>,
    pub aaguid: Vec<u8>,
    /// `Some(true)`: a PIN is set; `Some(false)`: the key can have one but
    /// has none; `None`: no PIN at all.
    pub client_pin: Option<bool>,
    /// The key has getPinUvAuthTokenUsingPinWithPermissions (CTAP 2.1).
    pub pin_uv_auth_token: bool,
    pub pin_protocols: Vec<i64>,
    pub min_pin_length: Option<u32>,
}

impl Info {
    fn parse(v: &Value) -> Result<Info, Error> {
        let texts = |k: i64| -> Vec<String> {
            v.get(k)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_text)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        let versions = texts(1);
        if versions.is_empty() {
            return Err(Error::Malformed("getInfo without versions"));
        }
        let options = v.get(4);
        let option = |name: &str| options.and_then(|o| o.get(name)).and_then(Value::as_bool);
        Ok(Info {
            versions,
            extensions: texts(2),
            aaguid: v
                .get(3)
                .and_then(Value::as_bytes)
                .unwrap_or_default()
                .to_vec(),
            client_pin: option("clientPin"),
            pin_uv_auth_token: option("pinUvAuthToken") == Some(true),
            pin_protocols: v
                .get(6)
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_int).collect())
                .unwrap_or_default(),
            min_pin_length: v
                .get(0x0d)
                .and_then(Value::as_int)
                .and_then(|n| u32::try_from(n).ok()),
        })
    }

    pub fn has_extension(&self, name: &str) -> bool {
        self.extensions.iter().any(|e| e == name)
    }

    /// The PIN protocol to use: 2 if the key lists it, wherever in its
    /// list, else 1, which every CTAP 2.0 key has whether it lists it or
    /// not. The key's own order of preference is not followed: protocol 1
    /// has no IV and a MAC cut to 16 bytes.
    pub fn protocol(&self) -> Option<Protocol> {
        if self.pin_protocols.contains(&2) {
            Some(Protocol::Two)
        } else if self.pin_protocols.is_empty() || self.pin_protocols.contains(&1) {
            Some(Protocol::One)
        } else {
            None
        }
    }

    /// Whether the key has what unlocking needs: CTAP2, `hmac-secret`,
    /// `credProtect`, a PIN (set or settable), a PIN protocol known here.
    pub fn check(&self) -> Result<(), Error> {
        if !self.versions.iter().any(|v| v.starts_with("FIDO_2_")) {
            return Err(Error::Unsupported("CTAP2"));
        }
        if !self.has_extension("hmac-secret") {
            return Err(Error::Unsupported("the hmac-secret extension"));
        }
        if !self.has_extension("credProtect") {
            return Err(Error::Unsupported("the credProtect extension"));
        }
        if self.client_pin.is_none() {
            return Err(Error::Unsupported("a PIN"));
        }
        if self.protocol().is_none() {
            return Err(Error::Unsupported("a PIN protocol this program knows"));
        }
        Ok(())
    }
}

/// A security key, open.
pub struct Key<D> {
    channel: Channel<D>,
    info: Info,
    on_touch: Box<dyn FnMut() + Send>,
}

impl<D: Device> Key<D> {
    /// Opens a channel to the key and asks what it is.
    pub fn open(device: D) -> Result<Key<D>, Error> {
        let mut channel = Channel::open(device)?;
        let info = Info::parse(&channel.cbor(GET_INFO, None, &mut || {})?)?;
        Ok(Key {
            channel,
            info,
            on_touch: Box::new(|| {}),
        })
    }

    /// What to do when the key waits for a touch: tell the user.
    pub fn on_touch(&mut self, f: impl FnMut() + Send + 'static) {
        self.on_touch = Box::new(f);
    }

    pub fn info(&self) -> &Info {
        &self.info
    }

    fn command(&mut self, command: u8, params: &Value) -> Result<Value, Error> {
        let on_touch = &mut self.on_touch;
        self.channel.cbor(command, Some(params), &mut || on_touch())
    }

    fn protocol(&self) -> Result<Protocol, Error> {
        self.info
            .protocol()
            .ok_or(Error::Unsupported("a PIN protocol this program knows"))
    }

    /// How many wrong PINs the key will still take.
    pub fn pin_retries(&mut self) -> Result<u32, Error> {
        let protocol = self.protocol()?;
        let answer = self.command(
            CLIENT_PIN,
            &Value::map([
                (1, Value::Int(protocol.number())),
                (2, Value::Int(PIN_GET_RETRIES)),
            ]),
        )?;
        answer
            .get(3)
            .and_then(Value::as_int)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(Error::Malformed("getPINRetries without a count"))
    }

    /// A key agreement with the key: a secret shared for this exchange,
    /// and this program's half to send along.
    fn agree(&mut self) -> Result<(Value, Shared), Error> {
        let protocol = self.protocol()?;
        let answer = self.command(
            CLIENT_PIN,
            &Value::map([
                (1, Value::Int(protocol.number())),
                (2, Value::Int(PIN_GET_KEY_AGREEMENT)),
            ]),
        )?;
        let theirs = parse_cose_key(
            answer
                .get(1)
                .ok_or(Error::Malformed("no key agreement key"))?,
        )?;
        Ok(protocol.encapsulate(&theirs))
    }

    /// Sets the PIN of a key that has none. The key checks its own length
    /// rules too; these are the specification's: four characters at
    /// least, 63 bytes at most.
    pub fn set_pin(&mut self, pin: &str) -> Result<(), Error> {
        let pin = normalise(pin);
        let min = self.info.min_pin_length.unwrap_or(4).max(4) as usize;
        if pin.chars().count() < min || pin.len() > 63 {
            return Err(Error::PinPolicy);
        }
        let (ours, shared) = self.agree()?;
        let mut padded = Zeroizing::new([0u8; 64]);
        padded[..pin.len()].copy_from_slice(pin.as_bytes());
        let new_pin_enc = shared.encrypt(padded.as_slice());
        let auth = shared.authenticate(&new_pin_enc);
        self.command(
            CLIENT_PIN,
            &Value::map([
                (1, Value::Int(shared.protocol().number())),
                (2, Value::Int(PIN_SET)),
                (3, ours),
                (4, Value::Bytes(auth)),
                (5, Value::Bytes(new_pin_enc)),
            ]),
        )?;
        self.info.client_pin = Some(true);
        Ok(())
    }

    /// A PIN token for `permissions` on `rp_id`, under the shared secret
    /// `shared` (whose half `ours` the key is sent).
    fn pin_token(
        &mut self,
        pin: &str,
        permissions: i64,
        rp_id: &str,
        ours: &Value,
        shared: &Shared,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let pin = normalise(pin);
        let hash = Zeroizing::new(Sha256::digest(pin.as_bytes()));
        let pin_hash_enc = shared.encrypt(&hash[..16]);
        let mut params = vec![
            (1, Value::Int(shared.protocol().number())),
            (3, ours.clone()),
            (6, Value::Bytes(pin_hash_enc)),
        ];
        if self.info.pin_uv_auth_token {
            params.push((2, Value::Int(PIN_GET_TOKEN_WITH_PERMISSIONS)));
            params.push((9, Value::Int(permissions)));
            params.push((10, Value::from(rp_id)));
        } else {
            params.push((2, Value::Int(PIN_GET_TOKEN)));
        }
        let answer = match self.command(CLIENT_PIN, &Value::map(params)) {
            Err(Error::PinInvalid { .. }) => {
                return Err(Error::PinInvalid {
                    retries: self.pin_retries().ok(),
                });
            }
            other => other?,
        };
        let sealed = answer
            .get(2)
            .and_then(Value::as_bytes)
            .ok_or(Error::Malformed("no PIN token"))?;
        let token = shared.decrypt(sealed)?;
        if !matches!(token.len(), 16 | 32) {
            return Err(Error::Malformed("PIN token of the wrong length"));
        }
        Ok(token)
    }

    /// Makes a credential for `rp_id` that only gives its secret after
    /// the PIN and a touch, and returns its id. Not discoverable: the id
    /// is kept by the program, not on the key.
    pub fn register(&mut self, rp_id: &str, pin: &str) -> Result<Vec<u8>, Error> {
        self.info.check()?;
        let (ours, shared) = self.agree()?;
        let token = self.pin_token(pin, PERMISSION_MC, rp_id, &ours, &shared)?;
        let protocol = shared.protocol();
        let mut client_data_hash = [0u8; 32];
        random(&mut client_data_hash);
        let mut user_id = [0u8; 16];
        random(&mut user_id);
        let params = Value::map([
            (1, Value::Bytes(client_data_hash.to_vec())),
            (
                2,
                Value::map([
                    ("id", Value::from(rp_id)),
                    ("name", Value::from("Silver Messenger")),
                ]),
            ),
            (
                3,
                Value::map([
                    ("id", Value::Bytes(user_id.to_vec())),
                    ("name", Value::from("Silver Messenger")),
                    ("displayName", Value::from("Silver Messenger")),
                ]),
            ),
            (
                4,
                Value::Array(vec![Value::map([
                    ("alg", Value::Int(ES256)),
                    ("type", Value::from("public-key")),
                ])]),
            ),
            (
                6,
                Value::map([
                    ("hmac-secret", Value::Bool(true)),
                    ("credProtect", Value::Int(CRED_PROTECT_UV_REQUIRED)),
                ]),
            ),
            (
                8,
                Value::Bytes(protocol.authenticate(&token, &client_data_hash)),
            ),
            (9, Value::Int(protocol.number())),
        ]);
        let answer = self.command(MAKE_CREDENTIAL, &params)?;
        let auth_data = answer
            .get(2)
            .and_then(Value::as_bytes)
            .ok_or(Error::Malformed("no authenticator data"))?;
        let parsed = AuthData::parse(auth_data, rp_id)?;
        if parsed.flags & (FLAG_UP | FLAG_UV) != FLAG_UP | FLAG_UV {
            return Err(Error::Malformed("credential made without touch and PIN"));
        }
        let credential_id = parsed
            .credential_id
            .ok_or(Error::Malformed("no credential in the answer"))?;
        let extensions = parsed.extensions.unwrap_or(Value::Null);
        if extensions.get("hmac-secret").and_then(Value::as_bool) != Some(true) {
            return Err(Error::Unsupported("the hmac-secret extension"));
        }
        if extensions.get("credProtect").and_then(Value::as_int) != Some(CRED_PROTECT_UV_REQUIRED) {
            return Err(Error::Unsupported("the credProtect extension"));
        }
        Ok(credential_id)
    }

    /// The secret for one of `candidates`, each a credential id and the
    /// WebAuthn `prf` input that goes with it: whichever this key holds,
    /// its index and the 32 bytes. One PIN token, then each credential in
    /// turn until the key knows one; the touch is asked for only then.
    pub fn prf(
        &mut self,
        rp_id: &str,
        candidates: &[(&[u8], &[u8])],
        pin: &str,
    ) -> Result<(usize, Zeroizing<[u8; 32]>), Error> {
        self.info.check()?;
        if candidates.is_empty() {
            return Err(Error::NoCredentials);
        }
        let (ours, shared) = self.agree()?;
        let token = self.pin_token(pin, PERMISSION_GA, rp_id, &ours, &shared)?;
        for (index, (id, input)) in candidates.iter().enumerate() {
            match self.assert_one(rp_id, id, input, &ours, &shared, &token) {
                Err(Error::NoCredentials) => continue,
                other => return other.map(|secret| (index, secret)),
            }
        }
        Err(Error::NoCredentials)
    }

    fn assert_one(
        &mut self,
        rp_id: &str,
        id: &[u8],
        input: &[u8],
        ours: &Value,
        shared: &Shared,
        token: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, Error> {
        let protocol = shared.protocol();
        let salt_enc = shared.encrypt(&prf_salt(input));
        let salt_auth = shared.authenticate(&salt_enc);
        let mut hmac_secret = vec![
            (1, ours.clone()),
            (2, Value::Bytes(salt_enc)),
            (3, Value::Bytes(salt_auth)),
        ];
        if protocol == Protocol::Two {
            hmac_secret.push((4, Value::Int(2)));
        }
        let mut client_data_hash = [0u8; 32];
        random(&mut client_data_hash);
        let allow = Value::Array(vec![Value::map([
            ("id", Value::Bytes(id.to_vec())),
            ("type", Value::from("public-key")),
        ])]);
        let params = Value::map([
            (1, Value::from(rp_id)),
            (2, Value::Bytes(client_data_hash.to_vec())),
            (3, allow),
            (4, Value::map([("hmac-secret", Value::map(hmac_secret))])),
            (
                6,
                Value::Bytes(protocol.authenticate(token, &client_data_hash)),
            ),
            (7, Value::Int(protocol.number())),
        ]);
        let answer = self.command(GET_ASSERTION, &params)?;
        // The credential may be left out, the allow list having had one.
        if let Some(answered) = answer
            .get(1)
            .and_then(|c| c.get("id"))
            .and_then(Value::as_bytes)
            && answered != id
        {
            return Err(Error::Malformed("another credential answered"));
        }
        let auth_data = answer
            .get(2)
            .and_then(Value::as_bytes)
            .ok_or(Error::Malformed("no authenticator data"))?;
        let parsed = AuthData::parse(auth_data, rp_id)?;
        if parsed.flags & (FLAG_UP | FLAG_UV) != FLAG_UP | FLAG_UV {
            return Err(Error::Malformed("assertion without touch and PIN"));
        }
        let sealed = parsed
            .extensions
            .as_ref()
            .and_then(|e| e.get("hmac-secret"))
            .and_then(Value::as_bytes)
            .ok_or(Error::Unsupported("the hmac-secret extension"))?;
        let output = shared.decrypt(sealed)?;
        if output.len() != 32 {
            return Err(Error::Malformed("hmac-secret output of the wrong length"));
        }
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&output);
        Ok(out)
    }
}

/// The PIN as the key compares it: Unicode NFC, as CTAP 2.1 asks.
fn normalise(pin: &str) -> Zeroizing<String> {
    Zeroizing::new(pin.nfc().collect())
}

/// Authenticator data (section 6.1 of WebAuthn level 2).
struct AuthData {
    flags: u8,
    credential_id: Option<Vec<u8>>,
    extensions: Option<Value>,
}

impl AuthData {
    fn parse(data: &[u8], rp_id: &str) -> Result<AuthData, Error> {
        let short = Error::Malformed("authenticator data cut short");
        if data.len() < 37 {
            return Err(short);
        }
        if data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
            return Err(Error::Malformed(
                "authenticator data for another relying party",
            ));
        }
        let flags = data[32];
        let mut rest = &data[37..];
        let mut credential_id = None;
        if flags & FLAG_AT != 0 {
            if rest.len() < 18 {
                return Err(short);
            }
            let len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
            rest = &rest[18..];
            if rest.len() < len {
                return Err(short);
            }
            credential_id = Some(rest[..len].to_vec());
            rest = &rest[len..];
            let (_public_key, used) = crate::cbor::decode_prefix(rest)?;
            rest = &rest[used..];
        }
        let extensions = if flags & FLAG_ED != 0 {
            Some(crate::cbor::decode(rest)?)
        } else if rest.is_empty() {
            None
        } else {
            return Err(Error::Malformed("bytes after the authenticator data"));
        };
        Ok(AuthData {
            flags,
            credential_id,
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_two_is_used_whenever_the_key_lists_it() {
        let info = |protocols: &[i64]| Info {
            pin_protocols: protocols.to_vec(),
            ..Info::default()
        };
        assert_eq!(info(&[2]).protocol(), Some(Protocol::Two));
        assert_eq!(info(&[1, 2]).protocol(), Some(Protocol::Two));
        assert_eq!(info(&[2, 1]).protocol(), Some(Protocol::Two));
        assert_eq!(info(&[3, 2, 1]).protocol(), Some(Protocol::Two));
        assert_eq!(info(&[1]).protocol(), Some(Protocol::One));
        assert_eq!(info(&[]).protocol(), Some(Protocol::One));
        assert_eq!(info(&[3]).protocol(), None);
    }
}
