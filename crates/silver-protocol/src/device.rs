//! Devices under an identity (`docs/PROTOCOL.md` section 14,
//! `docs/design/devices.md`).
//!
//! A device is a key pair of its own, certified by the identity key: a
//! [`DeviceCertificate`] binds a device key to an account, a
//! [`DeviceRevocation`] ends it. The account's bundle carries the list of
//! its devices signed as a whole ([`crate::bundle::KeyBundle::with_devices`]),
//! and a device's bundle carries its certificate. Linking a device sends
//! it, through the relay, a provisioning message sealed under a key
//! derived from a one-time secret the device printed ([`link_key`],
//! [`seal_provision`]). Devices of one account keep each other informed
//! with [`Sync`] content.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::ProtocolError;
use crate::bundle::KeyBundle;
use crate::encoding::{b64, b64_array, b64_array_opt};
use crate::envelope::Content;
use crate::identity::{Identity, UserId};

/// Domain of the identity key's signature over a device certificate.
pub const DEVICE_DOMAIN: &[u8] = b"silver-messenger/v5/device";
/// Domain of the *device* key's signature over its own certificate.
///
/// A domain of its own so the two signatures over the same bytes cannot
/// be mistaken for one another: neither key's signature can be lifted
/// into the other's place.
pub const DEVICE_COUNTERSIGNATURE_DOMAIN: &[u8] = b"silver-messenger/v5/device-countersignature";
/// Domain of the identity key's signature over its device list.
pub const DEVICE_LIST_DOMAIN: &[u8] = b"silver-messenger/v5/device-list";
/// Domain of the identity key's signature over a device revocation.
pub const DEVICE_REVOCATION_DOMAIN: &[u8] = b"silver-messenger/v5/device-revocation";
/// HKDF info of the key a provisioning message is sealed under.
pub const LINK_KEY_INFO: &[u8] = b"silver-messenger/v5/link";
/// Domain of the associated data a provisioning message is sealed with.
pub const PROVISION_DOMAIN: &[u8] = b"silver-messenger/v5/provision";
/// Most linked devices an account lists.
pub const MAX_DEVICES: usize = 8;
/// Longest device name, in bytes of UTF-8.
pub const MAX_DEVICE_NAME_BYTES: usize = 32;
/// Bytes of the one-time secret a link carries.
pub const LINK_SECRET_BYTES: usize = 16;
/// Largest provisioning plaintext.
pub const MAX_PROVISION_BYTES: usize = 8 * 1024 * 1024;

/// The identity key's word that a device key belongs to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    pub account: UserId,
    pub device: UserId,
    pub created_at_ms: u64,
    /// The owner's name for the device, shown to the owner's devices only.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
    /// The device's own signature over the same bytes, under
    /// [`DEVICE_COUNTERSIGNATURE_DOMAIN`].
    ///
    /// The account's signature proves the account meant to enroll *a*
    /// device; it does not prove the device agreed, because an account
    /// can certify any public key it can name. The device adds this when
    /// it accepts the provisioning message, and presents the
    /// counter-signed certificate from then on, so an account cannot
    /// enroll a key its holder never offered.
    ///
    /// Optional for one release: a certificate minted before this existed
    /// carries none, and verifies on the account's signature alone.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "b64_array_opt"
    )]
    pub device_signature: Option<[u8; 64]>,
}

/// The check a name must pass when a device is named for the first time.
/// Stricter than [`check_name`], which every reader applies: the invisible
/// characters a reaction already refuses (zero-width spaces, the bidi
/// embeddings and overrides, word joiners, the byte-order mark) are
/// refused here too, since a device name is shown in the device list and
/// beside every message. It is not refused on the reading side: a name
/// certified by an older version would stop verifying, and the signature
/// covers the bytes as they were written.
pub fn check_new_name(name: &str) -> Result<(), ProtocolError> {
    check_name(name)?;
    if name.chars().any(crate::envelope::is_invisible) {
        return Err(ProtocolError::Malformed(
            "invisible character in device name".into(),
        ));
    }
    Ok(())
}

fn check_name(name: &str) -> Result<(), ProtocolError> {
    if name.len() > MAX_DEVICE_NAME_BYTES {
        return Err(ProtocolError::Malformed("device name too long".into()));
    }
    if name.chars().any(char::is_control) {
        return Err(ProtocolError::Malformed(
            "control character in device name".into(),
        ));
    }
    Ok(())
}

impl DeviceCertificate {
    /// `account (32) || device (32) || created_at_ms (8 BE) || name length (1) || name`.
    fn signed_bytes(account: &UserId, device: &UserId, created_at_ms: u64, name: &str) -> Vec<u8> {
        // The length goes in one byte, and a name is at most
        // `MAX_DEVICE_NAME_BYTES`. `encode` is reachable from
        // `transparency_leaf` on a bundle nothing has verified yet, so
        // rather than truncate a name that cannot legally be this long,
        // the length is clamped: the bytes then differ from any name that
        // verifies, the signature fails, and no leaf is quietly wrong.
        let len = u8::try_from(name.len()).unwrap_or(u8::MAX);
        let mut v = Vec::with_capacity(73 + name.len());
        v.extend_from_slice(account.as_bytes());
        v.extend_from_slice(device.as_bytes());
        v.extend_from_slice(&created_at_ms.to_be_bytes());
        v.push(len);
        v.extend_from_slice(name.as_bytes());
        v
    }

    /// Verify the account's signature, the device's when there is one,
    /// and the shape.
    pub fn verify(&self) -> Result<(), ProtocolError> {
        check_name(&self.name)?;
        if self.account == self.device {
            return Err(ProtocolError::Malformed(
                "a device certificate must name a key other than the account's".into(),
            ));
        }
        let signed =
            Self::signed_bytes(&self.account, &self.device, self.created_at_ms, &self.name);
        self.account
            .verify(DEVICE_DOMAIN, &signed, &self.signature)?;
        // Present from the release that added it; a certificate from
        // before carries none and stands on the account's signature
        // alone. One that carries a *wrong* one is refused, so a
        // certificate cannot be dressed up with somebody else's.
        if let Some(countersignature) = &self.device_signature {
            self.device
                .verify(DEVICE_COUNTERSIGNATURE_DOMAIN, &signed, countersignature)?;
        }
        Ok(())
    }

    /// Whether the device this names has said the certificate is its own.
    pub fn is_countersigned(&self) -> bool {
        self.device_signature.is_some()
    }

    /// [`verify`](Self::verify), and the device's own signature must be
    /// there. For a certificate a device *presents* as its own — the
    /// `device_of` in its bundle, the `device` in a body it sends — which
    /// from 0.17.0 has to carry both halves (section 14.1).
    ///
    /// Not for the account's copies of the same certificate: its signed
    /// device list, a provisioning message, a `sync`. The account cannot
    /// produce the device's signature, so those verify with
    /// [`verify`](Self::verify) alone; and not for the MLS leaf, whose
    /// encoding never carried it and whose own signature by the device
    /// key proves the same thing.
    pub fn verify_presented(&self) -> Result<(), ProtocolError> {
        self.verify()?;
        if !self.is_countersigned() {
            return Err(ProtocolError::Malformed(
                "the device certificate carries no signature by the device".into(),
            ));
        }
        Ok(())
    }

    /// The certificate as bytes, for the MLS leaf extension
    /// ([`crate::group::EXTENSION_DEVICE`]): the signed bytes followed by
    /// the signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Self::signed_bytes(&self.account, &self.device, self.created_at_ms, &self.name);
        v.extend_from_slice(&self.signature);
        v
    }

    /// Parse [`DeviceCertificate::encode`]'s output; the shape is checked,
    /// the signature is not (call [`DeviceCertificate::verify`]).
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let malformed =
            |what: &str| ProtocolError::Malformed(format!("device certificate: {what}"));
        if bytes.len() < 73 + 64 {
            return Err(malformed("truncated"));
        }
        let account = UserId::from_bytes(bytes[..32].try_into().expect("32 bytes"))?;
        let device = UserId::from_bytes(bytes[32..64].try_into().expect("32 bytes"))?;
        let created_at_ms = u64::from_be_bytes(bytes[64..72].try_into().expect("8 bytes"));
        let name_len = usize::from(bytes[72]);
        let rest = &bytes[73..];
        if rest.len() != name_len + 64 {
            return Err(malformed("length"));
        }
        let name = std::str::from_utf8(&rest[..name_len])
            .map_err(|_| malformed("name is not UTF-8"))?
            .to_owned();
        check_name(&name)?;
        let signature: [u8; 64] = rest[name_len..].try_into().expect("64 bytes");
        Ok(Self {
            account,
            device,
            created_at_ms,
            name,
            signature,
            // The MLS leaf extension carries the account's signature
            // only. A leaf says which account a member belongs to; the
            // device's own word about its enrollment travels with the
            // certificate itself, and adding it here would change an
            // extension every member already parses.
            device_signature: None,
        })
    }
}

/// The identity key's word that a device is no longer its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRevocation {
    pub account: UserId,
    pub device: UserId,
    pub created_at_ms: u64,
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

impl DeviceRevocation {
    /// `account (32) || device (32) || created_at_ms (8 BE)`.
    pub(crate) fn signed_bytes(account: &UserId, device: &UserId, created_at_ms: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(72);
        v.extend_from_slice(account.as_bytes());
        v.extend_from_slice(device.as_bytes());
        v.extend_from_slice(&created_at_ms.to_be_bytes());
        v
    }

    pub fn verify(&self) -> Result<(), ProtocolError> {
        if self.account == self.device {
            return Err(ProtocolError::Malformed(
                "a device revocation must name a key other than the account's".into(),
            ));
        }
        self.account.verify(
            DEVICE_REVOCATION_DOMAIN,
            &Self::signed_bytes(&self.account, &self.device, self.created_at_ms),
            &self.signature,
        )
    }

    /// Verify the statement as `account`'s word about one of its devices:
    /// the signature, and that the account it names is the one the reader
    /// knows the device under.
    ///
    /// [`DeviceRevocation::verify`] alone proves only that *some* key
    /// signed about *some* id, so nothing should be dropped or cut off on
    /// a bare `verify`: the caller passes the account whose device it
    /// knows this one to be (the certificate in the device's own bundle,
    /// or the account whose signed list carries it), and a statement from
    /// anyone else is not about that device at all.
    pub fn verify_for(&self, account: &UserId) -> Result<(), ProtocolError> {
        if self.account != *account {
            return Err(ProtocolError::Malformed(
                "a device revocation by another account".into(),
            ));
        }
        self.verify()
    }
}

impl Identity {
    /// Certify `device` as this identity's, named `name`.
    pub fn certify_device(
        &self,
        device: &UserId,
        name: &str,
        created_at_ms: u64,
    ) -> Result<DeviceCertificate, ProtocolError> {
        check_new_name(name)?;
        let account = self.user_id();
        if account == *device {
            return Err(ProtocolError::Malformed(
                "an identity does not certify itself as a device".into(),
            ));
        }
        Ok(DeviceCertificate {
            signature: self.sign(
                DEVICE_DOMAIN,
                &DeviceCertificate::signed_bytes(&account, device, created_at_ms, name),
            ),
            account,
            device: *device,
            created_at_ms,
            name: name.to_owned(),
            // The account cannot produce this: only the device's key can,
            // which is the point. The device adds it on acceptance.
            device_signature: None,
        })
    }

    /// Sign `certificate` as the device it names, saying that this device
    /// really did offer its key.
    ///
    /// Refuses a certificate for another key, so a device cannot vouch
    /// for an enrollment that is not its own.
    pub fn countersign_device(
        &self,
        certificate: &DeviceCertificate,
    ) -> Result<DeviceCertificate, ProtocolError> {
        if certificate.device != self.user_id() {
            return Err(ProtocolError::Malformed(
                "a device signs only its own certificate".into(),
            ));
        }
        certificate.verify()?;
        let signed = DeviceCertificate::signed_bytes(
            &certificate.account,
            &certificate.device,
            certificate.created_at_ms,
            &certificate.name,
        );
        Ok(DeviceCertificate {
            device_signature: Some(self.sign(DEVICE_COUNTERSIGNATURE_DOMAIN, &signed)),
            ..certificate.clone()
        })
    }

    /// Revoke `device`, one of this identity's.
    pub fn revoke_device(&self, device: &UserId, created_at_ms: u64) -> DeviceRevocation {
        let account = self.user_id();
        DeviceRevocation {
            signature: self.sign(
                DEVICE_REVOCATION_DOMAIN,
                &DeviceRevocation::signed_bytes(&account, device, created_at_ms),
            ),
            account,
            device: *device,
            created_at_ms,
        }
    }
}

/// What the identity signs to vouch for its device list, bound to the
/// bundle by its Diffie–Hellman key:
/// `dh_public (32) || count (2 BE) || (device (32) || created_at_ms (8 BE))*`
/// over the devices in ascending device id order.
pub(crate) fn device_list_signed_bytes(
    dh_public: &[u8; 32],
    devices: &[DeviceCertificate],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(34 + 40 * devices.len());
    v.extend_from_slice(dh_public);
    v.extend_from_slice(&(devices.len() as u16).to_be_bytes());
    for device in devices {
        v.extend_from_slice(device.device.as_bytes());
        v.extend_from_slice(&device.created_at_ms.to_be_bytes());
    }
    v
}

/// Check a device list's shape against its account: at most
/// [`MAX_DEVICES`], ascending device ids without duplicates, each
/// certificate valid and naming `account`, none naming the account's own
/// key.
pub(crate) fn check_device_list(
    account: &UserId,
    devices: &[DeviceCertificate],
) -> Result<(), ProtocolError> {
    if devices.len() > MAX_DEVICES {
        return Err(ProtocolError::Malformed("too many devices".into()));
    }
    if devices.windows(2).any(|w| w[0].device >= w[1].device) {
        return Err(ProtocolError::Malformed(
            "device list not in ascending order".into(),
        ));
    }
    for device in devices {
        device.verify()?;
        if device.account != *account {
            return Err(ProtocolError::Malformed(
                "a listed device is certified by another account".into(),
            ));
        }
    }
    Ok(())
}

/// The key a provisioning message is sealed under, from the secret the
/// link carries: `HKDF-SHA256(salt = none, ikm = secret, info = "silver-messenger/v5/link")`,
/// 32 bytes.
pub fn link_key(secret: &[u8; LINK_SECRET_BYTES]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut key = [0u8; 32];
    hk.expand(LINK_KEY_INFO, &mut key)
        .expect("32 bytes is a valid HKDF length");
    key
}

/// A provisioning message as it travels inside a session to the new
/// device: sealed under the link key, so only the device that printed the
/// link reads it, whoever else was handed its id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provision {
    #[serde(with = "b64_array")]
    pub nonce: [u8; 24],
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

fn provision_aad(device: &UserId) -> Vec<u8> {
    let mut v = Vec::with_capacity(PROVISION_DOMAIN.len() + 32);
    v.extend_from_slice(PROVISION_DOMAIN);
    v.extend_from_slice(device.as_bytes());
    v
}

/// Seal `plaintext` for `device` under `key` ([`link_key`]):
/// XChaCha20-Poly1305 with a random nonce and the associated data
/// `"silver-messenger/v5/provision" || device (32)`.
pub fn seal_provision(
    key: &[u8; 32],
    device: &UserId,
    plaintext: &[u8],
) -> Result<Provision, ProtocolError> {
    seal_provision_with_rng(key, device, plaintext, &mut OsRng)
}

/// [`seal_provision`] drawing the nonce from `rng`; for test vectors.
pub fn seal_provision_with_rng<R: RngCore + CryptoRng>(
    key: &[u8; 32],
    device: &UserId,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Provision, ProtocolError> {
    if plaintext.len() > MAX_PROVISION_BYTES {
        return Err(ProtocolError::TooLarge(plaintext.len()));
    }
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &provision_aad(device),
            },
        )
        .map_err(|_| ProtocolError::Malformed("provisioning seal failed".into()))?;
    Ok(Provision { nonce, ciphertext })
}

/// Open a provisioning message meant for `device`.
pub fn open_provision(
    key: &[u8; 32],
    device: &UserId,
    provision: &Provision,
) -> Result<Vec<u8>, ProtocolError> {
    if provision.ciphertext.len() > MAX_PROVISION_BYTES + 16 {
        return Err(ProtocolError::TooLarge(provision.ciphertext.len()));
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(&provision.nonce),
            Payload {
                msg: &provision.ciphertext,
                aad: &provision_aad(device),
            },
        )
        .map_err(|_| ProtocolError::DecryptFailed)
}

/// What one of an account's devices tells the others (`Content::Sync`).
/// Accepted only from a device certified for one's own account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Sync {
    /// A copy of a message this device sent to `peer`.
    Sent {
        peer: UserId,
        id: String,
        sent_at_ms: u64,
        content: Box<Content>,
    },
    /// A copy of a message received from `from` by a sender that did not
    /// address the other devices (a client before 0.9.0).
    Received {
        from: UserId,
        id: String,
        sent_at_ms: u64,
        content: Box<Content>,
    },
    /// Messages from `peer` this device showed, so the others need not
    /// send read receipts for them, and so a disappearing message's clock
    /// starts on every device from the same moment (`at_ms`, absent from
    /// a device before 0.10.0).
    Read {
        peer: UserId,
        ids: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at_ms: Option<u64>,
    },
    /// Messages this device removed for itself ("delete for me"), which
    /// the others remove too: `peer`'s conversation or `group`'s, one of
    /// the two.
    Remove {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        peer: Option<UserId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<crate::group::GroupId>,
        ids: Vec<String>,
    },
    /// A change to the contact list.
    Contact {
        #[serde(flatten)]
        action: ContactAction,
    },
    /// The account's device list as the primary now publishes it, and the
    /// revocations it has issued.
    Devices {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        devices: Vec<DeviceCertificate>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        revoked: Vec<DeviceRevocation>,
    },
    /// This device asks to be unlinked: the primary revokes it on receipt.
    /// Sent by a device that is wiping itself; the other devices ignore
    /// it.
    Leave,
}

/// A contact list change, as one device tells the others.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ContactAction {
    Add {
        user: UserId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alias: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bundle: Option<Box<KeyBundle>>,
    },
    Remove {
        user: UserId,
    },
    Alias {
        user: UserId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        alias: Option<String>,
    },
    Verify {
        user: UserId,
        verified: bool,
    },
    Block {
        user: UserId,
    },
    Unblock {
        user: UserId,
    },
    Files {
        user: UserId,
        auto: bool,
    },
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_device_is_named_without_invisible_characters() {
        let account = Identity::generate();
        let device = Identity::generate().user_id();
        // A name shown in the device list and beside every message: the
        // characters that would let one pretend to be another are refused
        // when the name is chosen.
        for bad in ["laptop\u{200B}", "\u{202E}potpal", "a\u{FEFF}b"] {
            assert!(
                account.certify_device(&device, bad, 1).is_err(),
                "{bad:?} names a device"
            );
        }
        assert!(account.certify_device(&device, "laptop", 1).is_ok());

        // A certificate written by an older version still verifies: the
        // signature covers the bytes as they were, and refusing it on the
        // reading side would cut off a device already linked.
        let mut old = account.certify_device(&device, "laptop", 1).unwrap();
        old.name = "laptop\u{200B}".into();
        assert!(check_name(&old.name).is_ok(), "the reader's rule is looser");
        assert!(check_new_name(&old.name).is_err());
    }
    use super::*;

    #[test]
    fn a_certificate_is_signed_by_the_account_and_tamper_evident() {
        let account = Identity::generate();
        let device = Identity::generate();
        let cert = account
            .certify_device(&device.user_id(), "laptop", 1000)
            .unwrap();
        assert!(cert.verify().is_ok());
        assert_eq!(cert.account, account.user_id());
        assert_eq!(cert.device, device.user_id());

        let mut other = cert.clone();
        other.device = Identity::generate().user_id();
        assert_eq!(other.verify(), Err(ProtocolError::InvalidSignature));
        let mut renamed = cert.clone();
        renamed.name = "phone".into();
        assert_eq!(renamed.verify(), Err(ProtocolError::InvalidSignature));
        let mut moved = cert.clone();
        moved.created_at_ms = 1001;
        assert_eq!(moved.verify(), Err(ProtocolError::InvalidSignature));
        let mut forged = cert.clone();
        forged.signature = Identity::generate().sign(
            DEVICE_DOMAIN,
            &DeviceCertificate::signed_bytes(&cert.account, &cert.device, 1000, "laptop"),
        );
        assert_eq!(forged.verify(), Err(ProtocolError::InvalidSignature));
        // Naming itself is malformed; so is a bad name.
        assert!(account.certify_device(&account.user_id(), "me", 1).is_err());
        assert!(
            account
                .certify_device(&device.user_id(), "a\nb", 1)
                .is_err()
        );
        assert!(
            account
                .certify_device(&device.user_id(), &"x".repeat(33), 1)
                .is_err()
        );

        let json = serde_json::to_string(&cert).unwrap();
        assert_eq!(
            serde_json::from_str::<DeviceCertificate>(&json).unwrap(),
            cert
        );
        let unnamed = account.certify_device(&device.user_id(), "", 5).unwrap();
        assert!(!serde_json::to_string(&unnamed).unwrap().contains("name"));
    }

    /// Where a device presents a certificate as its own, both halves are
    /// required (section 14.1, from 0.17.0); `verify` alone goes on
    /// serving the account's copies, which cannot carry the second.
    #[test]
    fn a_presented_certificate_carries_both_signatures() {
        let account = Identity::generate();
        let device = Identity::generate();
        let minted = account
            .certify_device(&device.user_id(), "mine", 1)
            .unwrap();
        assert!(minted.verify().is_ok(), "the account's copy verifies");
        let err = minted.verify_presented().unwrap_err();
        assert!(
            matches!(&err, ProtocolError::Malformed(m) if m.contains("no signature by the device")),
            "{err:?}"
        );
        let presented = device.countersign_device(&minted).unwrap();
        presented.verify_presented().unwrap();
        // A wrong second signature is refused by both, so it cannot be
        // dressed up for the presented check either.
        let mut wrong = presented.clone();
        wrong.device_signature.as_mut().unwrap()[0] ^= 1;
        assert!(wrong.verify().is_err());
        assert!(wrong.verify_presented().is_err());
    }

    /// The account's signature says the account meant to enroll *a*
    /// device; it says nothing about whether the device agreed, because
    /// an account can certify any public key it can name. The device's
    /// own signature is what says the key was offered.
    #[test]
    fn a_device_signs_its_own_certificate_and_no_other() {
        let account = Identity::generate();
        let device = Identity::generate();
        let stranger = Identity::generate();

        // What the account can make on its own: an enrollment of a key
        // whose holder has said nothing.
        let minted = account
            .certify_device(&stranger.user_id(), "not mine", 1)
            .unwrap();
        assert!(minted.verify().is_ok(), "the account's signature stands");
        assert!(
            !minted.is_countersigned(),
            "and it is not the stranger's word"
        );

        // The stranger cannot be made to agree, and nobody else can agree
        // on their behalf.
        assert!(
            device.countersign_device(&minted).is_err(),
            "a device signs only its own certificate"
        );
        let signed = stranger.countersign_device(&minted).unwrap();
        assert!(signed.is_countersigned());
        assert!(signed.verify().is_ok());

        // A signature lifted from elsewhere does not pass: the device's
        // is over its own bytes under its own domain.
        let mine = account
            .certify_device(&device.user_id(), "mine", 2)
            .unwrap();
        let forged = DeviceCertificate {
            device_signature: signed.device_signature,
            ..mine.clone()
        };
        assert!(
            forged.verify().is_err(),
            "another device's signature must not pass as this one's"
        );
        // Nor the account's own, over the same bytes: the domains differ.
        let lifted = DeviceCertificate {
            device_signature: Some(mine.signature),
            ..mine
        };
        assert!(
            lifted.verify().is_err(),
            "the account's signature must not pass as the device's"
        );
    }

    /// The transition the design note asks for: a certificate minted
    /// before the field existed carries none and still verifies.
    #[test]
    fn a_certificate_without_the_devices_signature_still_verifies() {
        let account = Identity::generate();
        let device = Identity::generate();
        let cert = account.certify_device(&device.user_id(), "old", 3).unwrap();
        assert!(cert.device_signature.is_none());
        assert!(cert.verify().is_ok());
        // And a JSON body from such a version, which does not write the
        // field at all, parses to the same thing.
        let json = serde_json::to_string(&cert).unwrap();
        assert!(!json.contains("device_signature"));
        assert_eq!(
            serde_json::from_str::<DeviceCertificate>(&json).unwrap(),
            cert
        );
    }

    #[test]
    fn a_certificate_encodes_and_decodes() {
        let account = Identity::generate();
        let device = Identity::generate();
        let cert = account
            .certify_device(&device.user_id(), "büro", 7)
            .unwrap();
        let bytes = cert.encode();
        assert_eq!(bytes.len(), 73 + "büro".len() + 64);
        let back = DeviceCertificate::decode(&bytes).unwrap();
        assert_eq!(back, cert);
        assert!(back.verify().is_ok());
        assert!(DeviceCertificate::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(DeviceCertificate::decode(&longer).is_err());
        let mut bad_name = bytes.clone();
        bad_name[73] = 0x07;
        assert!(DeviceCertificate::decode(&bad_name).is_err());
    }

    #[test]
    fn a_revocation_is_signed_by_the_account() {
        let account = Identity::generate();
        let device = Identity::generate().user_id();
        let rev = account.revoke_device(&device, 9);
        assert!(rev.verify().is_ok());
        let mut other = rev.clone();
        other.device = Identity::generate().user_id();
        assert_eq!(other.verify(), Err(ProtocolError::InvalidSignature));
        let mut moved = rev.clone();
        moved.created_at_ms = 10;
        assert_eq!(moved.verify(), Err(ProtocolError::InvalidSignature));
        let self_rev = account.revoke_device(&account.user_id(), 9);
        assert!(matches!(
            self_rev.verify(),
            Err(ProtocolError::Malformed(_))
        ));
        let json = serde_json::to_string(&rev).unwrap();
        assert_eq!(
            serde_json::from_str::<DeviceRevocation>(&json).unwrap(),
            rev
        );
    }

    #[test]
    fn a_provisioning_message_opens_only_for_its_device_under_its_key() {
        let secret = [7u8; LINK_SECRET_BYTES];
        let key = link_key(&secret);
        assert_ne!(key, link_key(&[8u8; LINK_SECRET_BYTES]));
        let device = Identity::generate().user_id();
        let sealed = seal_provision(&key, &device, b"contacts and all").unwrap();
        assert_eq!(
            open_provision(&key, &device, &sealed).unwrap(),
            b"contacts and all"
        );
        assert_eq!(
            open_provision(&link_key(&[8u8; 16]), &device, &sealed),
            Err(ProtocolError::DecryptFailed)
        );
        assert_eq!(
            open_provision(&key, &Identity::generate().user_id(), &sealed),
            Err(ProtocolError::DecryptFailed)
        );
        let mut damaged = sealed.clone();
        damaged.ciphertext[3] ^= 1;
        assert_eq!(
            open_provision(&key, &device, &damaged),
            Err(ProtocolError::DecryptFailed)
        );
        let json = serde_json::to_string(&sealed).unwrap();
        assert_eq!(serde_json::from_str::<Provision>(&json).unwrap(), sealed);
        assert!(matches!(
            seal_provision(&key, &device, &vec![0u8; MAX_PROVISION_BYTES + 1]),
            Err(ProtocolError::TooLarge(_))
        ));
    }

    #[test]
    fn sync_content_round_trips_as_json() {
        let peer = Identity::generate().user_id();
        let cases = vec![
            Sync::Sent {
                peer,
                id: "m1".into(),
                sent_at_ms: 3,
                content: Box::new(Content::text("hi")),
            },
            Sync::Received {
                from: peer,
                id: "m2".into(),
                sent_at_ms: 4,
                content: Box::new(Content::text("yo")),
            },
            Sync::Read {
                peer,
                ids: vec!["m1".into()],
                at_ms: None,
            },
            Sync::Read {
                peer,
                ids: vec!["m1".into()],
                at_ms: Some(5),
            },
            Sync::Remove {
                peer: Some(peer),
                group: None,
                ids: vec!["m1".into()],
            },
            Sync::Remove {
                peer: None,
                group: Some(crate::group::GroupId([9u8; 32])),
                ids: vec!["g1".into()],
            },
            Sync::Contact {
                action: ContactAction::Alias {
                    user: peer,
                    alias: Some("bob".into()),
                },
            },
            Sync::Contact {
                action: ContactAction::Files {
                    user: peer,
                    auto: true,
                },
            },
            Sync::Devices {
                devices: Vec::new(),
                revoked: Vec::new(),
            },
            Sync::Leave,
        ];
        for sync in cases {
            let content = Content::Sync(sync.clone());
            let json = serde_json::to_string(&content).unwrap();
            assert!(json.starts_with("{\"type\":\"sync\",\"kind\":\""), "{json}");
            assert_eq!(serde_json::from_str::<Content>(&json).unwrap(), content);
        }
        let json = serde_json::to_string(&Content::Sync(Sync::Contact {
            action: ContactAction::Block { user: peer },
        }))
        .unwrap();
        assert!(json.contains("\"action\":\"block\""), "{json}");
        // A read without a moment is what a device before 0.10.0 sends.
        let json = serde_json::to_string(&Sync::Read {
            peer,
            ids: vec!["m1".into()],
            at_ms: None,
        })
        .unwrap();
        assert!(!json.contains("at_ms"), "{json}");
    }
}
