//! Signed public-key bundles that relays store and hand out.

use serde::{Deserialize, Serialize};

use crate::ProtocolError;
use crate::encoding::b64_array;
use crate::identity::{DhPublic, UserId};

pub const BUNDLE_DOMAIN: &[u8] = b"silver-message/v1/key-bundle";

/// A user's X25519 public key, signed by their identity key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyBundle {
    pub user_id: UserId,
    pub dh_public: DhPublic,
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

impl KeyBundle {
    /// Check that `dh_public` was really signed by `user_id`.
    pub fn verify(&self) -> Result<(), ProtocolError> {
        self.user_id
            .verify(BUNDLE_DOMAIN, &self.dh_public.0, &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use crate::Identity;

    #[test]
    fn bundle_verifies_and_detects_tampering() {
        let id = Identity::generate();
        let bundle = id.key_bundle();
        assert!(bundle.verify().is_ok());

        let mut swapped = bundle.clone();
        swapped.dh_public = Identity::generate().dh_public();
        assert!(swapped.verify().is_err());

        let mut impostor = bundle.clone();
        impostor.user_id = Identity::generate().user_id();
        assert!(impostor.verify().is_err());

        let json = serde_json::to_string(&bundle).unwrap();
        let back: super::KeyBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back, bundle);
    }
}
