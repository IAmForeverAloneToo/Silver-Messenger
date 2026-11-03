//! The PIN/UV auth protocols (section 6.5 of the CTAP 2.1 specification):
//! an ECDH on P-256 with the key gives a shared secret, under which the
//! PIN travels encrypted, the key's answers come back encrypted, and the
//! program proves it holds the PIN token. Protocol 2 is the one in use;
//! protocol 1 is what CTAP 2.0 keys know.

use aes::Aes256;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use p256::elliptic_curve::point::AffineCoordinates;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;
use crate::cbor::Value;
use crate::hid::random;

type Encryptor = cbc::Encryptor<Aes256>;
type Decryptor = cbc::Decryptor<Aes256>;

/// A PIN/UV auth protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    One,
    Two,
}

impl Protocol {
    pub fn number(self) -> i64 {
        match self {
            Protocol::One => 1,
            Protocol::Two => 2,
        }
    }

    pub fn from_number(n: i64) -> Option<Protocol> {
        match n {
            1 => Some(Protocol::One),
            2 => Some(Protocol::Two),
            _ => None,
        }
    }

    /// A fresh key pair of this program's own, its public half as COSE,
    /// and the secret shared with `peer`.
    pub fn encapsulate(self, peer: &PublicKey) -> (Value, Shared) {
        let ours = fresh_secret_key();
        let cose = cose_key(&ours.public_key());
        (cose, self.shared(&ours, peer))
    }

    /// The secret shared between `ours` and `peer`.
    pub fn shared(self, ours: &SecretKey, peer: &PublicKey) -> Shared {
        let point = (peer.to_projective() * *ours.to_nonzero_scalar()).to_affine();
        let z = Zeroizing::new(<[u8; 32]>::from(point.x()));
        let secret = match self {
            Protocol::One => Zeroizing::new(Sha256::digest(*z).to_vec()),
            Protocol::Two => {
                let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), z.as_slice());
                let mut out = Zeroizing::new(vec![0u8; 64]);
                hk.expand(b"CTAP2 HMAC key", &mut out[..32])
                    .expect("32 bytes");
                hk.expand(b"CTAP2 AES key", &mut out[32..])
                    .expect("32 bytes");
                out
            }
        };
        Shared {
            protocol: self,
            secret,
        }
    }

    /// `authenticate(key, message)`: HMAC-SHA-256, cut to 16 bytes under
    /// protocol 1. `key` is a PIN token here, or a shared secret's HMAC
    /// half through [`Shared::authenticate`].
    pub fn authenticate(self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key");
        mac.update(message);
        let tag = mac.finalize().into_bytes().to_vec();
        match self {
            Protocol::One => tag[..16].to_vec(),
            Protocol::Two => tag,
        }
    }
}

/// A secret shared with a key for one exchange.
pub struct Shared {
    protocol: Protocol,
    /// Protocol 1: the AES and HMAC key, both. Protocol 2: the HMAC key,
    /// then the AES key.
    secret: Zeroizing<Vec<u8>>,
}

impl Shared {
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    fn aes_key(&self) -> &[u8] {
        match self.protocol {
            Protocol::One => &self.secret,
            Protocol::Two => &self.secret[32..],
        }
    }

    fn hmac_key(&self) -> &[u8] {
        match self.protocol {
            Protocol::One => &self.secret,
            Protocol::Two => &self.secret[..32],
        }
    }

    /// `plain` (whole blocks) encrypted: under protocol 1 with an all-zero
    /// IV, under protocol 2 with a random one in front.
    pub fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
        let mut iv = [0u8; 16];
        if self.protocol == Protocol::Two {
            random(&mut iv);
        }
        self.encrypt_with_iv(&iv, plain)
    }

    pub(crate) fn encrypt_with_iv(&self, iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
        assert!(plain.len() % 16 == 0, "whole AES blocks only");
        let body = Encryptor::new_from_slices(self.aes_key(), iv)
            .expect("32-byte key, 16-byte IV")
            .encrypt_padded_vec::<NoPadding>(plain);
        match self.protocol {
            Protocol::One => body,
            Protocol::Two => [iv.as_slice(), &body].concat(),
        }
    }

    pub fn decrypt(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let (iv, body) = match self.protocol {
            Protocol::One => ([0u8; 16], sealed),
            Protocol::Two => {
                if sealed.len() < 16 {
                    return Err(Error::Malformed("encrypted value shorter than its IV"));
                }
                (sealed[..16].try_into().expect("16 bytes"), &sealed[16..])
            }
        };
        if body.is_empty() || body.len() % 16 != 0 {
            return Err(Error::Malformed(
                "encrypted value that is not whole AES blocks",
            ));
        }
        let plain = Decryptor::new_from_slices(self.aes_key(), &iv)
            .expect("32-byte key, 16-byte IV")
            .decrypt_padded_vec::<NoPadding>(body)
            .map_err(|_| Error::Malformed("encrypted value that is not whole AES blocks"))?;
        Ok(Zeroizing::new(plain))
    }

    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        self.protocol.authenticate(self.hmac_key(), message)
    }
}

/// A P-256 secret key from the operating system's generator.
pub(crate) fn fresh_secret_key() -> SecretKey {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        random(bytes.as_mut_slice());
        // Fails only for a value at or past the group order, about one
        // draw in 2^32.
        if let Ok(key) = SecretKey::from_slice(bytes.as_slice()) {
            return key;
        }
    }
}

/// A P-256 public key as COSE, the way the key agreement wants it: EC2,
/// "ECDH-ES+HKDF-256" (-25), P-256.
pub fn cose_key(key: &PublicKey) -> Value {
    cose_key_with_alg(key, -25)
}

pub(crate) fn cose_key_with_alg(key: &PublicKey, alg: i64) -> Value {
    let point = key.to_encoded_point(false);
    Value::map([
        (1, Value::Int(2)),
        (3, Value::Int(alg)),
        (-1, Value::Int(1)),
        (-2, Value::Bytes(point.x().expect("uncompressed").to_vec())),
        (-3, Value::Bytes(point.y().expect("uncompressed").to_vec())),
    ])
}

/// A P-256 public key out of COSE; refused if it is not one, or not on
/// the curve.
pub fn parse_cose_key(value: &Value) -> Result<PublicKey, Error> {
    let bad = Error::Malformed("key agreement key that is not a P-256 point");
    if value.get(1).and_then(Value::as_int) != Some(2)
        || value.get(-1).and_then(Value::as_int) != Some(1)
    {
        return Err(bad);
    }
    let x = value
        .get(-2)
        .and_then(Value::as_bytes)
        .ok_or(Error::Malformed("no x"))?;
    let y = value
        .get(-3)
        .and_then(Value::as_bytes)
        .ok_or(Error::Malformed("no y"))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(bad);
    }
    let sec1 = [&[0x04][..], x, y].concat();
    PublicKey::from_sec1_bytes(&sec1).map_err(|_| bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    // The values below were computed apart from this code, with Python's
    // `cryptography` package: ECDH between the secret keys [0x11; 32] and
    // [0x22; 32], HKDF and AES-256-CBC as section 6.5 has them.

    #[test]
    fn protocol_two_derives_and_encrypts_as_the_specification_says() {
        let shared = Protocol::Two.shared(&key(0x11), &key(0x22).public_key());
        let other = Protocol::Two.shared(&key(0x22), &key(0x11).public_key());
        assert_eq!(*shared.secret, *other.secret);
        assert_eq!(shared.hmac_key(), hex(PROTOCOL_TWO_HMAC_KEY));
        assert_eq!(shared.aes_key(), hex(PROTOCOL_TWO_AES_KEY));
        let sealed = shared.encrypt_with_iv(&[0x33; 16], &[0x44; 32]);
        assert_eq!(sealed, hex(PROTOCOL_TWO_SEALED));
        assert_eq!(*shared.decrypt(&sealed).unwrap(), [0x44; 32]);
        assert_eq!(shared.authenticate(b"silver"), hex(PROTOCOL_TWO_TAG));
    }

    #[test]
    fn protocol_one_derives_and_encrypts_as_the_specification_says() {
        let shared = Protocol::One.shared(&key(0x11), &key(0x22).public_key());
        assert_eq!(*shared.secret, hex(PROTOCOL_ONE_SECRET));
        let sealed = shared.encrypt(&[0x44; 32]);
        assert_eq!(sealed, hex(PROTOCOL_ONE_SEALED));
        assert_eq!(*shared.decrypt(&sealed).unwrap(), [0x44; 32]);
        assert_eq!(shared.authenticate(b"silver").len(), 16);
    }

    #[test]
    fn a_cose_key_goes_both_ways_and_a_bad_one_is_refused() {
        let public = key(0x11).public_key();
        let cose = cose_key(&public);
        assert_eq!(parse_cose_key(&cose).unwrap(), public);
        let off_curve = Value::map([
            (1, Value::Int(2)),
            (3, Value::Int(-25)),
            (-1, Value::Int(1)),
            (-2, Value::Bytes(vec![1; 32])),
            (-3, Value::Bytes(vec![2; 32])),
        ]);
        assert!(parse_cose_key(&off_curve).is_err());
        assert!(parse_cose_key(&Value::Null).is_err());
    }

    const PROTOCOL_TWO_HMAC_KEY: &str =
        "abc3809533cb07b6ae481ea05b28ac708ffed9777147a09aabc8ab58e167ba0e";
    const PROTOCOL_TWO_AES_KEY: &str =
        "aecad75245932defecf4cd0d93420fcd05d99403d09a49655fed76fa64c2cf82";
    const PROTOCOL_TWO_SEALED: &str = "33333333333333333333333333333333ea8ecc8311b2ddd722de079b08a9d1e023c3fbddcff20c2f556e607a45fc5257";
    const PROTOCOL_TWO_TAG: &str =
        "c66b63f66e02861199c2071f53255c6aa5a1254bb8aa5b4c5f62939ce7d4fbff";
    const PROTOCOL_ONE_SECRET: &str =
        "98f5bf15dbc72627acd9a8ab61ce21349ea3496d79136adf08ad381cc9c0fa25";
    const PROTOCOL_ONE_SEALED: &str =
        "e6b5c150b293a9521b0a05366b8c361ec77a05d316f43ed7fab2f03c8c05cd86";
}
