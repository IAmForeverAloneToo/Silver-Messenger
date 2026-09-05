//! Signed public-key bundles that relays store and hand out.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;
use crate::device::{
    DEVICE_LIST_DOMAIN, DeviceCertificate, check_device_list, device_list_signed_bytes,
};
use crate::encoding::{b64_array, b64_opt_array};
use crate::identity::{DhPublic, Identity, UserId};
use crate::prekey::Prekeys;

pub const BUNDLE_DOMAIN: &[u8] = b"silver-messenger/v1/key-bundle";
/// Domain for the signature over a bundle's capability list.
pub const BUNDLE_CAPS_DOMAIN: &[u8] = b"silver-messenger/v4/bundle-caps";

/// Capabilities a client advertises in its published bundle, so a peer
/// knows what protocol features it will accept before the first message.
/// Unlike the in-body [`capability`](crate::envelope::capability) list,
/// these are signed, so the relay cannot add or strip one undetected.
pub mod capability {
    /// The client reads protocol-v4 ratchet bodies: the post-quantum
    /// ratchet, and the deniable body without the inner signature.
    pub const PQ_RATCHET: &str = "pq_ratchet";
    /// The client takes part in groups (`docs/PROTOCOL.md` section 13): it
    /// keeps key packages on deposit at its relay, reads v5 bodies, and can
    /// be added to a group. Advertised only while a deposit exists, so a
    /// contact whose bundle lacks it is not looked up for a key package.
    pub const GROUPS: &str = "groups";
    /// The client reads `sync` content from its own devices and may be
    /// sent to per device (`docs/PROTOCOL.md` section 14): it is a primary
    /// on 0.10.0 or later, or a linked device. A sender treats an account
    /// whose bundle lacks it as one device, the bundle's own.
    pub const DEVICES: &str = "devices";
}

/// A user's X25519 public key, signed by their identity key, plus (for
/// clients that speak protocol v2) their prekeys.
///
/// The v1 fields and their signature are unchanged from the first release,
/// so a relay or client that predates prekeys still verifies and uses the
/// bundle; it simply does not see the `prekeys` field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBundle {
    pub user_id: UserId,
    pub dh_public: DhPublic,
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prekeys: Option<Prekeys>,
    /// Signed protocol capabilities (protocol v4); empty on clients before
    /// 0.8.0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
    /// The identity key's signature over `caps`; present whenever `caps` is.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "b64_opt_array"
    )]
    pub caps_signature: Option<[u8; 64]>,
    /// The account's linked devices (section 14), in ascending device id
    /// order, signed as a whole by `devices_signature`. Empty on a bundle
    /// without devices and on one a relay before 0.10.0 served.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<DeviceCertificate>,
    /// The identity key's signature over `devices`; present whenever
    /// `devices` is.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "b64_opt_array"
    )]
    pub devices_signature: Option<[u8; 64]>,
    /// On a linked device's bundle: whose device it is, by the account's
    /// own signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_of: Option<DeviceCertificate>,
}

impl KeyBundle {
    /// The bytes an identity signs to vouch for a capability list: the
    /// owner's Diffie–Hellman key (to bind the caps to this bundle) and the
    /// capabilities in order, newline-separated.
    pub(crate) fn caps_signed_bytes(dh_public: &DhPublic, caps: &[String]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&dh_public.0);
        v.extend_from_slice(caps.join("\n").as_bytes());
        v
    }

    /// Check that `dh_public`, the signed prekey (if any), the capabilities
    /// (if any) and the device list (if any) were really signed by
    /// `user_id`, and that a `device_of` certificate names this key and
    /// verifies against the account it claims.
    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.user_id
            .verify(BUNDLE_DOMAIN, &self.dh_public.0, &self.signature)?;
        if let Some(prekeys) = &self.prekeys {
            prekeys.verify(&self.user_id)?;
        }
        if !self.caps.is_empty() {
            let signature = self.caps_signature.ok_or(ProtocolError::InvalidSignature)?;
            self.user_id.verify(
                BUNDLE_CAPS_DOMAIN,
                &Self::caps_signed_bytes(&self.dh_public, &self.caps),
                &signature,
            )?;
        }
        if !self.devices.is_empty() {
            check_device_list(&self.user_id, &self.devices)?;
            let signature = self
                .devices_signature
                .ok_or(ProtocolError::InvalidSignature)?;
            self.user_id.verify(
                DEVICE_LIST_DOMAIN,
                &device_list_signed_bytes(&self.dh_public.0, &self.devices),
                &signature,
            )?;
        }
        if let Some(certificate) = &self.device_of {
            certificate.verify()?;
            if certificate.device != self.user_id {
                return Err(ProtocolError::Malformed(
                    "the device certificate names another key".into(),
                ));
            }
            if !self.devices.is_empty() {
                return Err(ProtocolError::Malformed(
                    "a linked device lists no devices of its own".into(),
                ));
            }
        }
        Ok(())
    }

    /// The same bundle listing `devices` as this identity's, signed.
    /// `identity` must own the bundle; the list is sorted here.
    pub fn with_devices(
        mut self,
        identity: &Identity,
        mut devices: Vec<DeviceCertificate>,
    ) -> Result<Self, ProtocolError> {
        devices.sort_by(|a, b| a.device.cmp(&b.device));
        if devices.is_empty() {
            self.devices = Vec::new();
            self.devices_signature = None;
            return Ok(self);
        }
        check_device_list(&self.user_id, &devices)?;
        self.devices_signature = Some(identity.sign(
            DEVICE_LIST_DOMAIN,
            &device_list_signed_bytes(&self.dh_public.0, &devices),
        ));
        self.devices = devices;
        Ok(self)
    }

    /// The same bundle marked as a linked device's, by the account's
    /// certificate for this key.
    pub fn as_device_of(mut self, certificate: DeviceCertificate) -> Self {
        self.device_of = Some(certificate);
        self
    }

    /// The account this bundle's owner is a linked device of, if it is one.
    pub fn account(&self) -> Option<&UserId> {
        self.device_of.as_ref().map(|c| &c.account)
    }

    /// Whether the owner can be talked to with forward-secret sessions.
    pub fn supports_sessions(&self) -> bool {
        self.prekeys.is_some()
    }

    /// Whether a session started from this bundle is post-quantum.
    pub fn supports_post_quantum(&self) -> bool {
        self.prekeys
            .as_ref()
            .is_some_and(Prekeys::supports_post_quantum)
    }

    /// Whether the owner advertises capability `cap`.
    pub fn advertises(&self, cap: &str) -> bool {
        self.caps.iter().any(|c| c == cap)
    }

    /// Whether a session started from this bundle can run the post-quantum
    /// ratchet (protocol v4): the owner has published ML-KEM keys and
    /// advertises the capability.
    pub fn supports_pq_ratchet(&self) -> bool {
        self.supports_post_quantum() && self.advertises(capability::PQ_RATCHET)
    }

    /// The same bundle without its prekeys.
    pub fn without_prekeys(&self) -> Self {
        Self {
            prekeys: None,
            ..self.clone()
        }
    }

    /// Add a signed capability list to this bundle. `identity` must own it.
    pub fn with_caps(mut self, identity: &Identity, caps: Vec<String>) -> Self {
        if caps.is_empty() {
            self.caps = Vec::new();
            self.caps_signature = None;
            return self;
        }
        self.caps_signature = Some(identity.sign(
            BUNDLE_CAPS_DOMAIN,
            &Self::caps_signed_bytes(&self.dh_public, &caps),
        ));
        self.caps = caps;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use crate::pq::PqPrekeySecret;
    use crate::prekey::{PrekeySecret, Prekeys};

    #[test]
    fn bundle_verifies_and_detects_tampering() {
        let id = Identity::generate();
        let bundle = id.key_bundle();
        assert!(bundle.verify().is_ok());
        assert!(!bundle.supports_sessions());

        let mut swapped = bundle.clone();
        swapped.dh_public = Identity::generate().dh_public();
        assert!(swapped.verify().is_err());

        let mut impostor = bundle.clone();
        impostor.user_id = Identity::generate().user_id();
        assert!(impostor.verify().is_err());

        let json = serde_json::to_string(&bundle).unwrap();
        assert!(!json.contains("prekeys"));
        let back: KeyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, bundle);
    }

    #[test]
    fn prekeys_are_covered_by_verification() {
        let id = Identity::generate();
        let signed = PrekeySecret::generate(1, 5);
        let mut bundle = id.key_bundle_with(Prekeys::classical(
            signed.signed_by(&id),
            vec![PrekeySecret::generate(2, 5).one_time()],
        ));
        assert!(bundle.verify().is_ok());
        assert!(bundle.supports_sessions());
        assert!(!bundle.supports_post_quantum());

        let mut forged = bundle.clone();
        forged.prekeys.as_mut().unwrap().signed = signed.signed_by(&Identity::generate());
        assert_eq!(forged.verify(), Err(ProtocolError::InvalidSignature));

        // ML-KEM keys are covered too, the one-time ones included.
        let prekeys = bundle.prekeys.as_mut().unwrap();
        prekeys.pq_signed = Some(PqPrekeySecret::generate(3, 5).signed_by(&id));
        prekeys.pq_one_time = vec![PqPrekeySecret::generate(4, 5).signed_by(&id)];
        assert!(bundle.verify().is_ok());
        assert!(bundle.supports_post_quantum());
        let mut forged = bundle.clone();
        forged.prekeys.as_mut().unwrap().pq_one_time[0] =
            PqPrekeySecret::generate(4, 5).signed_by(&Identity::generate());
        assert_eq!(forged.verify(), Err(ProtocolError::InvalidSignature));
        let mut forged = bundle.clone();
        forged
            .prekeys
            .as_mut()
            .unwrap()
            .pq_signed
            .as_mut()
            .unwrap()
            .id = 5;
        assert_eq!(forged.verify(), Err(ProtocolError::InvalidSignature));

        let json = serde_json::to_string(&bundle).unwrap();
        assert_eq!(serde_json::from_str::<KeyBundle>(&json).unwrap(), bundle);
        assert_eq!(bundle.without_prekeys(), id.key_bundle());
    }

    #[test]
    fn a_v1_reader_accepts_a_v2_bundle() {
        // What clients and relays before prekeys deserialize.
        #[derive(Deserialize)]
        struct OldBundle {
            user_id: UserId,
            dh_public: DhPublic,
            #[serde(with = "b64_array")]
            signature: [u8; 64],
        }
        let id = Identity::generate();
        let bundle = id.key_bundle_with(Prekeys::classical(
            PrekeySecret::generate(1, 0).signed_by(&id),
            Vec::new(),
        ));
        let old: OldBundle =
            serde_json::from_str(&serde_json::to_string(&bundle).unwrap()).unwrap();
        assert_eq!(old.user_id, bundle.user_id);
        assert_eq!(old.dh_public, bundle.dh_public);
        assert!(
            old.user_id
                .verify(BUNDLE_DOMAIN, &old.dh_public.0, &old.signature)
                .is_ok()
        );
    }
}
