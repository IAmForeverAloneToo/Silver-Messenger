//! Long-term identity: an Ed25519 signing key (whose public half is the user
//! id) and an X25519 key for Diffie–Hellman.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ProtocolError;
use crate::bundle::{BUNDLE_DOMAIN, KeyBundle};
use crate::encoding::{b64_array, to_base64};
use crate::prekey::Prekeys;

/// A user's public identity: the raw Ed25519 verifying key.
///
/// Displayed and parsed as base58, e.g. `9sX2...`. Because the id *is* the
/// public key, comparing ids out of band is the same as verifying a
/// fingerprint.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId([u8; 32]);

impl UserId {
    /// Wrap raw key bytes, rejecting anything that is not a valid Ed25519 point.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ProtocolError> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| ProtocolError::InvalidKey)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey::from_bytes(&self.0).expect("validated on construction")
    }

    /// Verify `signature` over `domain || message`.
    pub fn verify(
        &self,
        domain: &[u8],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<(), ProtocolError> {
        let sig = Signature::from_bytes(signature);
        self.verifying_key()
            .verify_strict(&domain_tagged(domain, message), &sig)
            .map_err(|_| ProtocolError::InvalidSignature)
    }

    /// A short prefix of the base58 form, for compact display.
    pub fn short(&self) -> String {
        self.to_string().chars().take(8).collect()
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&bs58::encode(self.0).into_string())
    }
}

impl fmt::Debug for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserId({self})")
    }
}

impl FromStr for UserId {
    type Err = ProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = bs58::decode(s.trim())
            .into_vec()
            .map_err(|_| ProtocolError::InvalidKey)?;
        let bytes: [u8; 32] = v.try_into().map_err(|_| ProtocolError::InvalidKey)?;
        Self::from_bytes(bytes)
    }
}

impl Serialize for UserId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for UserId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// An X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize)]
pub struct DhPublic(#[serde(with = "b64_array")] pub [u8; 32]);

impl DhPublic {
    pub fn as_x25519(&self) -> PublicKey {
        PublicKey::from(self.0)
    }
}

impl fmt::Debug for DhPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DhPublic({})", to_base64(&self.0))
    }
}

/// Secret key material in a form suitable for at-rest storage.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecrets {
    #[serde(with = "b64_array")]
    pub signing_seed: [u8; 32],
    #[serde(with = "b64_array")]
    pub dh_secret: [u8; 32],
}

/// A full identity with private keys. Never leaves the client.
pub struct Identity {
    signing: SigningKey,
    dh: StaticSecret,
}

impl Identity {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
            dh: StaticSecret::random_from_rng(OsRng),
        }
    }

    pub fn from_secrets(secrets: &IdentitySecrets) -> Self {
        Self {
            signing: SigningKey::from_bytes(&secrets.signing_seed),
            dh: StaticSecret::from(secrets.dh_secret),
        }
    }

    pub fn to_secrets(&self) -> IdentitySecrets {
        IdentitySecrets {
            signing_seed: self.signing.to_bytes(),
            dh_secret: self.dh.to_bytes(),
        }
    }

    pub fn user_id(&self) -> UserId {
        UserId(self.signing.verifying_key().to_bytes())
    }

    pub fn dh_public(&self) -> DhPublic {
        DhPublic(PublicKey::from(&self.dh).to_bytes())
    }

    /// Sign `domain || message` with the identity key.
    pub fn sign(&self, domain: &[u8], message: &[u8]) -> [u8; 64] {
        self.signing
            .sign(&domain_tagged(domain, message))
            .to_bytes()
    }

    pub(crate) fn dh_secret(&self) -> &StaticSecret {
        &self.dh
    }

    /// The signed public key bundle to publish on a relay, without prekeys
    /// (protocol v1 only).
    pub fn key_bundle(&self) -> KeyBundle {
        let dh_public = self.dh_public();
        KeyBundle {
            user_id: self.user_id(),
            dh_public,
            signature: self.sign(BUNDLE_DOMAIN, &dh_public.0),
            prekeys: None,
        }
    }

    /// The bundle with prekeys, so peers can start forward-secret sessions.
    pub fn key_bundle_with(&self, prekeys: Prekeys) -> KeyBundle {
        KeyBundle {
            prekeys: Some(prekeys),
            ..self.key_bundle()
        }
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("user_id", &self.user_id())
            .finish_non_exhaustive()
    }
}

fn domain_tagged(domain: &[u8], message: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + 1 + message.len());
    v.extend_from_slice(domain);
    v.push(0);
    v.extend_from_slice(message);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_round_trips_through_base58_and_json() {
        let id = Identity::generate().user_id();
        let text = id.to_string();
        assert_eq!(text.parse::<UserId>().unwrap(), id);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{text}\""));
        assert_eq!(serde_json::from_str::<UserId>(&json).unwrap(), id);
    }

    #[test]
    fn user_id_rejects_garbage() {
        assert!("not base58!".parse::<UserId>().is_err());
        assert!(
            bs58::encode([0u8; 16])
                .into_string()
                .parse::<UserId>()
                .is_err()
        );
    }

    #[test]
    fn identity_survives_secret_round_trip() {
        let id = Identity::generate();
        let restored = Identity::from_secrets(&id.to_secrets());
        assert_eq!(id.user_id(), restored.user_id());
        assert_eq!(id.dh_public(), restored.dh_public());
    }

    #[test]
    fn signatures_are_domain_separated() {
        let id = Identity::generate();
        let sig = id.sign(b"a", b"msg");
        assert!(id.user_id().verify(b"a", b"msg", &sig).is_ok());
        assert_eq!(
            id.user_id().verify(b"b", b"msg", &sig),
            Err(ProtocolError::InvalidSignature)
        );
        assert!(
            Identity::generate()
                .user_id()
                .verify(b"a", b"msg", &sig)
                .is_err()
        );
    }
}
