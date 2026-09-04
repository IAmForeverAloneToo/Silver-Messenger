//! Prekeys: medium-term and one-time X25519 keys a client publishes so that
//! someone can start a forward-secret session with it while it is offline.
//!
//! A *signed prekey* is rotated every few days and carries a signature by the
//! identity key, so a relay cannot substitute it. *One-time prekeys* are
//! unsigned; the relay hands each out once and the owner deletes its private
//! half after use, which gives the first message of a session forward secrecy
//! too. Both are optional additions to a [`KeyBundle`](crate::KeyBundle):
//! clients that do not publish them are talked to with protocol v1.

use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ProtocolError;
use crate::encoding::b64_array;
use crate::identity::{DhPublic, Identity, UserId};

pub const SIGNED_PREKEY_DOMAIN: &[u8] = b"silver-messenger/v2/signed-prekey";

/// A signed medium-term X25519 public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPrekey {
    pub id: u32,
    pub public: DhPublic,
    pub created_at_ms: u64,
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

impl SignedPrekey {
    fn signed_bytes(id: u32, public: &DhPublic, created_at_ms: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + 32 + 8);
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&public.0);
        v.extend_from_slice(&created_at_ms.to_be_bytes());
        v
    }

    /// Check that `owner` signed this prekey.
    pub fn verify(&self, owner: &UserId) -> Result<(), ProtocolError> {
        owner.verify(
            SIGNED_PREKEY_DOMAIN,
            &Self::signed_bytes(self.id, &self.public, self.created_at_ms),
            &self.signature,
        )
    }
}

/// An unsigned X25519 public key meant to be used exactly once.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePrekey {
    pub id: u32,
    pub public: DhPublic,
}

/// The public prekeys published in a key bundle. On a `Publish` the list of
/// one-time keys is everything the client still holds; on a `LookupResult`
/// the relay includes at most one, which it then forgets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prekeys {
    pub signed: SignedPrekey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_time: Vec<OneTimePrekey>,
}

impl Prekeys {
    pub fn verify(&self, owner: &UserId) -> Result<(), ProtocolError> {
        self.signed.verify(owner)
    }
}

/// The private half of a prekey, as kept on the owning client.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PrekeySecret {
    pub id: u32,
    #[serde(with = "b64_array")]
    secret: [u8; 32],
    pub created_at_ms: u64,
}

impl PrekeySecret {
    pub fn generate(id: u32, created_at_ms: u64) -> Self {
        Self {
            id,
            secret: StaticSecret::random_from_rng(rand::rngs::OsRng).to_bytes(),
            created_at_ms,
        }
    }

    pub fn public(&self) -> DhPublic {
        DhPublic(PublicKey::from(&self.x25519()).to_bytes())
    }

    pub(crate) fn x25519(&self) -> StaticSecret {
        StaticSecret::from(self.secret)
    }

    /// The signed public form of this key.
    pub fn signed_by(&self, identity: &Identity) -> SignedPrekey {
        let public = self.public();
        SignedPrekey {
            id: self.id,
            public,
            created_at_ms: self.created_at_ms,
            signature: identity.sign(
                SIGNED_PREKEY_DOMAIN,
                &SignedPrekey::signed_bytes(self.id, &public, self.created_at_ms),
            ),
        }
    }

    pub fn one_time(&self) -> OneTimePrekey {
        OneTimePrekey {
            id: self.id,
            public: self.public(),
        }
    }
}

impl std::fmt::Debug for PrekeySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrekeySecret")
            .field("id", &self.id)
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_prekey_verifies_and_detects_tampering() {
        let id = Identity::generate();
        let secret = PrekeySecret::generate(7, 1000);
        let signed = secret.signed_by(&id);
        assert!(signed.verify(&id.user_id()).is_ok());
        assert!(signed.verify(&Identity::generate().user_id()).is_err());

        let mut other_id = signed.clone();
        other_id.id = 8;
        assert!(other_id.verify(&id.user_id()).is_err());
        let mut other_key = signed.clone();
        other_key.public = PrekeySecret::generate(7, 1000).public();
        assert!(other_key.verify(&id.user_id()).is_err());
        let mut other_time = signed.clone();
        other_time.created_at_ms = 1001;
        assert!(other_time.verify(&id.user_id()).is_err());

        let json = serde_json::to_string(&signed).unwrap();
        assert_eq!(serde_json::from_str::<SignedPrekey>(&json).unwrap(), signed);
    }

    #[test]
    fn secrets_serialize_without_exposing_more_than_needed() {
        let secret = PrekeySecret::generate(1, 0);
        let json = serde_json::to_string(&secret).unwrap();
        let back: PrekeySecret = serde_json::from_str(&json).unwrap();
        assert_eq!(back.public(), secret.public());
        assert_eq!(back.one_time().id, 1);
        assert!(!format!("{secret:?}").contains("secret\":"));
    }
}
