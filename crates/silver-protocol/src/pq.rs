//! Post-quantum prekeys: ML-KEM-768 (FIPS 203) encapsulation keys a client
//! publishes next to its X25519 prekeys, so that a session's secret also
//! depends on a key agreement that a quantum computer cannot undo.
//!
//! The classical prekeys stay as they are; these are additions to
//! [`Prekeys`](crate::prekey::Prekeys). A *signed* ML-KEM key (Signal's
//! "last-resort" key) is always published and rotated like the signed X25519
//! prekey; *one-time* ML-KEM keys are handed out once by the relay. Both
//! kinds carry a signature by the identity key. An X25519 one-time key can go
//! unsigned because a substitute only costs the extra forward secrecy it
//! would have added; a substituted ML-KEM key would let whoever planted it
//! compute the post-quantum half of the secret, so the relay must not be
//! able to swap one in.
//!
//! The private half is kept as the 64-byte seed the key pair expands from
//! (FIPS 203 section 7.1), the form the standard recommends for storage; the
//! expanded key is derived when it is used and wiped afterwards.

use ml_kem::{
    Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, KeyExport, MlKem768, Seed,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ProtocolError;
use crate::encoding::{b64, b64_array, to_base64};
use crate::identity::{Identity, UserId};

pub const PQ_PREKEY_DOMAIN: &[u8] = b"silver-messenger/v3/pq-prekey";
/// Bytes in an ML-KEM-768 encapsulation key.
pub const KEM_PUBLIC_LEN: usize = 1184;
/// Bytes in an ML-KEM-768 ciphertext.
pub const KEM_CIPHERTEXT_LEN: usize = 1088;
/// Bytes in the shared secret both sides end up with.
pub const KEM_SECRET_LEN: usize = 32;

/// An ML-KEM-768 encapsulation key. Anyone can use it to make a secret
/// that only the holder of the matching seed can recover.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct KemPublic(#[serde(with = "b64")] pub Vec<u8>);

impl KemPublic {
    fn key(&self) -> Result<EncapsulationKey<MlKem768>, ProtocolError> {
        let bytes: &ml_kem::Key<EncapsulationKey<MlKem768>> =
            self.0.as_slice().try_into().map_err(|_| {
                ProtocolError::Malformed(format!("ML-KEM key of {} bytes", self.0.len()))
            })?;
        EncapsulationKey::<MlKem768>::new(bytes)
            .map_err(|_| ProtocolError::Malformed("ML-KEM key is not well formed".into()))
    }

    /// A fresh shared secret for the key's owner, and the ciphertext that
    /// lets them recover it.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Zeroizing<[u8; KEM_SECRET_LEN]>), ProtocolError> {
        let (ciphertext, mut shared) = self.key()?.encapsulate();
        let mut secret = Zeroizing::new([0u8; KEM_SECRET_LEN]);
        secret.copy_from_slice(shared.as_slice());
        shared.as_mut_slice().zeroize();
        Ok((ciphertext.to_vec(), secret))
    }
}

impl std::fmt::Debug for KemPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let head = to_base64(&self.0[..self.0.len().min(6)]);
        write!(f, "KemPublic({head}…, {} bytes)", self.0.len())
    }
}

/// A signed ML-KEM-768 encapsulation key, either the medium-term one or
/// one meant to be used once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPqPrekey {
    pub id: u32,
    pub public: KemPublic,
    pub created_at_ms: u64,
    #[serde(with = "b64_array")]
    pub signature: [u8; 64],
}

impl SignedPqPrekey {
    fn signed_bytes(id: u32, public: &KemPublic, created_at_ms: u64) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + public.0.len() + 8);
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&public.0);
        v.extend_from_slice(&created_at_ms.to_be_bytes());
        v
    }

    /// Check that `owner` signed this key and that it has the right size.
    pub fn verify(&self, owner: &UserId) -> Result<(), ProtocolError> {
        if self.public.0.len() != KEM_PUBLIC_LEN {
            return Err(ProtocolError::Malformed(format!(
                "ML-KEM key of {} bytes",
                self.public.0.len()
            )));
        }
        owner.verify(
            PQ_PREKEY_DOMAIN,
            &Self::signed_bytes(self.id, &self.public, self.created_at_ms),
            &self.signature,
        )
    }
}

/// The private half of a post-quantum prekey, as kept on the owning
/// client: the seed its key pair expands from.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PqPrekeySecret {
    pub id: u32,
    #[serde(with = "b64_array")]
    seed: [u8; 64],
    pub created_at_ms: u64,
}

impl PqPrekeySecret {
    pub fn generate(id: u32, created_at_ms: u64) -> Self {
        let mut seed = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self {
            id,
            seed,
            created_at_ms,
        }
    }

    fn decapsulation_key(&self) -> DecapsulationKey<MlKem768> {
        DecapsulationKey::from_seed(Seed::from(self.seed))
    }

    pub fn public(&self) -> KemPublic {
        KemPublic(
            self.decapsulation_key()
                .encapsulation_key()
                .to_bytes()
                .to_vec(),
        )
    }

    /// The signed public form of this key.
    pub fn signed_by(&self, identity: &Identity) -> SignedPqPrekey {
        let public = self.public();
        SignedPqPrekey {
            id: self.id,
            created_at_ms: self.created_at_ms,
            signature: identity.sign(
                PQ_PREKEY_DOMAIN,
                &SignedPqPrekey::signed_bytes(self.id, &public, self.created_at_ms),
            ),
            public,
        }
    }

    /// Recover the shared secret from a ciphertext made for this key. A
    /// ciphertext of the right size always yields *a* secret (ML-KEM rejects
    /// a forged one implicitly, by giving a secret the sender does not
    /// share), so what proves the handshake is the first message decrypting.
    pub fn decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; KEM_SECRET_LEN]>, ProtocolError> {
        let mut shared = self
            .decapsulation_key()
            .decapsulate_slice(ciphertext)
            .map_err(|_| {
                ProtocolError::Malformed(format!("ML-KEM ciphertext of {} bytes", ciphertext.len()))
            })?;
        let mut secret = Zeroizing::new([0u8; KEM_SECRET_LEN]);
        secret.copy_from_slice(shared.as_slice());
        shared.as_mut_slice().zeroize();
        Ok(secret)
    }
}

impl std::fmt::Debug for PqPrekeySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqPrekeySecret")
            .field("id", &self.id)
            .field("created_at_ms", &self.created_at_ms)
            .finish_non_exhaustive()
    }
}

/// An ephemeral ML-KEM-768 key pair for one turn of the post-quantum
/// ratchet (protocol v4). Unlike a prekey it carries no id and is never
/// signed: the ratchet's own AEAD authenticates it, so the relay cannot
/// substitute it undetected, and each is used for a single ratchet step and
/// then replaced. Stored as its 64-byte seed, like a prekey.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KemRatchetKey {
    #[serde(with = "b64_array")]
    seed: [u8; 64],
}

impl KemRatchetKey {
    pub fn generate() -> Self {
        let mut seed = [0u8; 64];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self { seed }
    }

    fn decapsulation_key(&self) -> DecapsulationKey<MlKem768> {
        DecapsulationKey::from_seed(Seed::from(self.seed))
    }

    /// The public half, to hand to the peer so it can encapsulate to us.
    pub fn public(&self) -> KemPublic {
        KemPublic(
            self.decapsulation_key()
                .encapsulation_key()
                .to_bytes()
                .to_vec(),
        )
    }

    /// Recover the secret from a ciphertext a peer encapsulated to us.
    pub fn decapsulate(
        &self,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; KEM_SECRET_LEN]>, ProtocolError> {
        let mut shared = self
            .decapsulation_key()
            .decapsulate_slice(ciphertext)
            .map_err(|_| {
                ProtocolError::Malformed(format!("ML-KEM ciphertext of {} bytes", ciphertext.len()))
            })?;
        let mut secret = Zeroizing::new([0u8; KEM_SECRET_LEN]);
        secret.copy_from_slice(shared.as_slice());
        shared.as_mut_slice().zeroize();
        Ok(secret)
    }
}

impl std::fmt::Debug for KemRatchetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KemRatchetKey(…)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_made_for_a_key_is_recovered_by_its_owner_only() {
        let owner = PqPrekeySecret::generate(1, 0);
        let public = owner.public();
        assert_eq!(public.0.len(), KEM_PUBLIC_LEN);
        let (ciphertext, secret) = public.encapsulate().unwrap();
        assert_eq!(ciphertext.len(), KEM_CIPHERTEXT_LEN);
        assert_eq!(*owner.decapsulate(&ciphertext).unwrap(), *secret);

        let other = PqPrekeySecret::generate(2, 0);
        assert_ne!(*other.decapsulate(&ciphertext).unwrap(), *secret);
        let mut damaged = ciphertext.clone();
        damaged[7] ^= 0x10;
        assert_ne!(*owner.decapsulate(&damaged).unwrap(), *secret);
        assert!(owner.decapsulate(&ciphertext[..100]).is_err());

        // The same seed gives the same key pair after a reload.
        let json = serde_json::to_string(&owner).unwrap();
        let reloaded: PqPrekeySecret = serde_json::from_str(&json).unwrap();
        assert_eq!(reloaded.public(), public);
        assert_eq!(*reloaded.decapsulate(&ciphertext).unwrap(), *secret);
        assert!(!format!("{owner:?}").contains("seed"));
    }

    #[test]
    fn signed_keys_verify_and_malformed_ones_are_refused() {
        let id = Identity::generate();
        let secret = PqPrekeySecret::generate(9, 1000);
        let signed = secret.signed_by(&id);
        assert!(signed.verify(&id.user_id()).is_ok());
        assert!(signed.verify(&Identity::generate().user_id()).is_err());

        let mut other_id = signed.clone();
        other_id.id = 10;
        assert!(other_id.verify(&id.user_id()).is_err());
        let mut other_key = signed.clone();
        other_key.public = PqPrekeySecret::generate(9, 1000).public();
        assert!(other_key.verify(&id.user_id()).is_err());
        let mut short = signed.clone();
        short.public.0.truncate(100);
        assert!(matches!(
            short.verify(&id.user_id()),
            Err(ProtocolError::Malformed(_))
        ));
        // Bytes that are not an ML-KEM key (coefficients out of range) fail
        // to encapsulate rather than yielding a secret nobody can recover.
        let mut garbage = signed.public.clone();
        garbage.0[..3].copy_from_slice(&[0xff, 0xff, 0xff]);
        assert!(matches!(
            garbage.encapsulate(),
            Err(ProtocolError::Malformed(_))
        ));

        let json = serde_json::to_string(&signed).unwrap();
        assert_eq!(
            serde_json::from_str::<SignedPqPrekey>(&json).unwrap(),
            signed
        );
        assert!(format!("{signed:?}").contains("1184 bytes"));
    }
}
