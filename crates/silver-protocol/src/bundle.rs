//! Signed public-key bundles that relays store and hand out.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;
use crate::encoding::b64_array;
use crate::identity::{DhPublic, UserId};
use crate::prekey::Prekeys;

pub const BUNDLE_DOMAIN: &[u8] = b"silver-messenger/v1/key-bundle";

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
}

impl KeyBundle {
    /// Check that `dh_public` (and the signed prekey, if any) were really
    /// signed by `user_id`.
    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.user_id
            .verify(BUNDLE_DOMAIN, &self.dh_public.0, &self.signature)?;
        if let Some(prekeys) = &self.prekeys {
            prekeys.verify(&self.user_id)?;
        }
        Ok(())
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

    /// The same bundle without its prekeys.
    pub fn without_prekeys(&self) -> Self {
        Self {
            prekeys: None,
            ..self.clone()
        }
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
