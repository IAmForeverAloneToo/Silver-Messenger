//! Long-term identity: an Ed25519 signing key (whose public half is the user
//! id) and an X25519 key for Diffie–Hellman.

use std::fmt;
use std::str::FromStr;
use std::sync::RwLock;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ProtocolError;
use crate::bundle::{BUNDLE_DOMAIN, KeyBundle};
use crate::encoding::{b64_array, to_base64};
use crate::prekey::Prekeys;

/// The most base58 characters a 32-byte id can take: 44. Longer text is
/// refused before it is decoded, since decoding costs time quadratic in
/// the length ([`UserId::from_str`], [`crate::group::GroupId::from_str`]).
pub const MAX_ID_CHARS: usize = 44;

/// A user's public identity: the raw Ed25519 verifying key.
///
/// Displayed and parsed as base58, e.g. `9sX2...`. Because the id *is* the
/// public key, comparing ids out of band is the same as verifying a
/// fingerprint.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId([u8; 32]);

/// Whether the `y` coordinate of a compressed Edwards point is written
/// canonically: less than the field prime 2^255 - 19, with the sign bit
/// (the top bit of the last byte) not part of the number.
fn is_canonical_y(bytes: &[u8; 32]) -> bool {
    // p, little-endian, without the sign bit.
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    let mut y = *bytes;
    y[31] &= 0x7f;
    for i in (0..32).rev() {
        if y[i] != p[i] {
            return y[i] < p[i];
        }
    }
    false // y == p is not less than p
}

impl UserId {
    /// Wrap raw key bytes, rejecting anything that is not a valid Ed25519 point.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, ProtocolError> {
        // Decompression reduces `y` modulo the field prime, so a handful
        // of points (those with `y` below 19) have a second encoding,
        // `y + p`, that decompresses to the same key: two ids for one
        // identity. None of them has a usable private key and
        // `verify_strict` refuses the small-order points anyway, but an id
        // is a public key written down and there is one way to write each.
        if !is_canonical_y(&bytes) {
            return Err(ProtocolError::InvalidKey);
        }
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
        let s = s.trim();
        // The length first: base58 decoding is a big-integer conversion,
        // quadratic in the input, and this runs on every frame field that
        // carries an id, before a relay has authenticated anyone. A
        // 32-byte value is at most 44 characters, so nothing longer can
        // be an id and none of it needs decoding.
        if s.len() > MAX_ID_CHARS {
            return Err(ProtocolError::InvalidKey);
        }
        let v = bs58::decode(s)
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
///
/// # What serializing this gives you
///
/// Plaintext: the signing seed and the Diffie–Hellman secret as base64
/// in JSON. Whoever holds that output *is* this identity — they sign as
/// it, start sessions as it, and link and revoke its devices — and no
/// rotation or lock takes that back, only a revocation does.
///
/// "Suitable for at-rest storage" means suitable to be *encrypted* and
/// stored: `silver-client` writes it through the vault and nowhere else.
/// A client that writes it as it comes has put the whole account in a
/// file. The same holds for [`crate::Session`] and the prekey secrets.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecrets {
    #[serde(with = "b64_array")]
    pub signing_seed: [u8; 32],
    #[serde(with = "b64_array")]
    pub dh_secret: [u8; 32],
    /// The Diffie–Hellman key this identity replaced, kept until
    /// `until_ms` so what was sealed to it still opens
    /// (`docs/design/dh-rotation.md` section 5). Absent when there is
    /// none, so a file written here reads in a version that knows no
    /// such thing, which then simply has no grace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_dh: Option<PreviousDhSecret>,
}

/// A replaced Diffie–Hellman secret and when it is to be forgotten.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PreviousDhSecret {
    #[serde(with = "b64_array")]
    pub dh_secret: [u8; 32],
    /// Unix milliseconds. Not a secret, but zeroized with the rest for
    /// simplicity.
    pub until_ms: u64,
}

/// How long a replaced Diffie–Hellman key goes on opening what was
/// sealed to it: 30 days, which is how long a relay keeps a message for
/// a recipient who has not fetched it (`silver-relay`'s
/// `DEFAULT_MESSAGE_TTL`, which a test there holds equal to this), so it
/// is the longest an envelope sealed to the old key can still arrive.
/// The two constants are one number in two crates; the relay's test is
/// what keeps them so.
pub const DH_ROTATION_GRACE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// The Diffie–Hellman keys an identity holds: the one it publishes, and
/// for a while the one it published before.
struct DhKeys {
    current: StaticSecret,
    previous: Option<(StaticSecret, u64)>,
}

/// Which of an identity's Diffie–Hellman keys an operation uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhKey {
    /// The key the identity publishes.
    Current,
    /// The key it published before its last rekey, while that is still
    /// held (`Identity::previous_dh_public`).
    Previous,
}

/// A full identity with private keys. Never leaves the client.
///
/// The Diffie–Hellman key sits behind a lock because it can be replaced
/// while the identity is in use ([`Identity::rotate_dh`]): the
/// connection task, the front end and the group engine share one
/// identity, and the key each reads is the one that was current at that
/// instant. The signing key never changes; a new one is a new identity.
pub struct Identity {
    signing: SigningKey,
    dh: RwLock<DhKeys>,
}

impl Identity {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
            dh: RwLock::new(DhKeys {
                current: StaticSecret::random_from_rng(OsRng),
                previous: None,
            }),
        }
    }

    pub fn from_secrets(secrets: &IdentitySecrets) -> Self {
        Self {
            signing: SigningKey::from_bytes(&secrets.signing_seed),
            dh: RwLock::new(DhKeys {
                current: StaticSecret::from(secrets.dh_secret),
                previous: secrets
                    .previous_dh
                    .as_ref()
                    .map(|p| (StaticSecret::from(p.dh_secret), p.until_ms)),
            }),
        }
    }

    pub fn to_secrets(&self) -> IdentitySecrets {
        let dh = self.dh();
        IdentitySecrets {
            signing_seed: self.signing.to_bytes(),
            dh_secret: dh.current.to_bytes(),
            previous_dh: dh
                .previous
                .as_ref()
                .map(|(secret, until_ms)| PreviousDhSecret {
                    dh_secret: secret.to_bytes(),
                    until_ms: *until_ms,
                }),
        }
    }

    pub fn user_id(&self) -> UserId {
        UserId(self.signing.verifying_key().to_bytes())
    }

    pub fn dh_public(&self) -> DhPublic {
        DhPublic(PublicKey::from(&self.dh().current).to_bytes())
    }

    /// The public half of the key this identity published before its last
    /// rekey, while it is still held.
    pub fn previous_dh_public(&self) -> Option<DhPublic> {
        self.dh()
            .previous
            .as_ref()
            .map(|(secret, _)| DhPublic(PublicKey::from(secret).to_bytes()))
    }

    /// Replace the Diffie–Hellman key (`docs/design/dh-rotation.md`). The
    /// key being replaced is kept until `now_ms + DH_ROTATION_GRACE_MS`
    /// for what was sealed to it; a key already kept from an earlier
    /// rekey goes at once, since one previous key is held, not a history.
    /// Returns the new public key. The caller writes the secrets to disk
    /// before publishing the key, never after.
    pub fn rotate_dh(&self, now_ms: u64) -> DhPublic {
        let fresh = StaticSecret::random_from_rng(OsRng);
        let mut dh = self.dh_mut();
        let old = std::mem::replace(&mut dh.current, fresh);
        dh.previous = Some((old, now_ms.saturating_add(DH_ROTATION_GRACE_MS)));
        DhPublic(PublicKey::from(&dh.current).to_bytes())
    }

    /// Undo a [`Self::rotate_dh`] that could not be written to disk: the
    /// previous key becomes current again and the fresh one is dropped.
    /// Only meaningful right after a rotation, before anything was
    /// published under the new key. Returns whether there was one to undo.
    pub fn unrotate_dh(&self) -> bool {
        let mut dh = self.dh_mut();
        match dh.previous.take() {
            Some((old, _)) => {
                dh.current = old;
                true
            }
            None => false,
        }
    }

    /// Forget the previous key once its grace has run out. Returns whether
    /// anything changed, so the caller knows to write the secrets again.
    pub fn expire_previous_dh(&self, now_ms: u64) -> bool {
        let mut dh = self.dh_mut();
        match dh.previous {
            Some((_, until_ms)) if until_ms <= now_ms => {
                dh.previous = None;
                true
            }
            _ => false,
        }
    }

    /// Sign `domain || message` with the identity key.
    pub fn sign(&self, domain: &[u8], message: &[u8]) -> [u8; 64] {
        self.signing
            .sign(&domain_tagged(domain, message))
            .to_bytes()
    }

    /// The current Diffie–Hellman secret, copied out from under the lock:
    /// a scalar is 32 bytes, and a copy the operation owns cannot be
    /// swapped out from under it half way through a handshake.
    pub(crate) fn dh_secret(&self) -> StaticSecret {
        self.dh().current.clone()
    }

    /// The secret and public halves of `which`, or `None` for a previous
    /// key that is not held.
    pub(crate) fn dh_pair(&self, which: DhKey) -> Option<(StaticSecret, DhPublic)> {
        let dh = self.dh();
        let secret = match which {
            DhKey::Current => dh.current.clone(),
            DhKey::Previous => dh.previous.as_ref()?.0.clone(),
        };
        let public = DhPublic(PublicKey::from(&secret).to_bytes());
        Some((secret, public))
    }

    fn dh(&self) -> std::sync::RwLockReadGuard<'_, DhKeys> {
        self.dh.read().unwrap_or_else(|e| e.into_inner())
    }

    fn dh_mut(&self) -> std::sync::RwLockWriteGuard<'_, DhKeys> {
        self.dh.write().unwrap_or_else(|e| e.into_inner())
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
            caps: Vec::new(),
            caps_signature: None,
            devices: Vec::new(),
            devices_signature: None,
            device_of: None,
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

    #[test]
    fn an_id_is_the_canonical_encoding_of_its_key() {
        // A real id round-trips.
        let id = Identity::generate().user_id();
        assert!(UserId::from_bytes(*id.as_bytes()).is_ok());

        // y = p decompresses to the same point as y = 0, so it would be a
        // second id for one key. p, little-endian, sign bit clear.
        let mut alias = [0xffu8; 32];
        alias[0] = 0xed;
        alias[31] = 0x7f;
        assert!(
            ed25519_dalek::VerifyingKey::from_bytes(&alias).is_ok(),
            "the curve accepts it, which is why the check is here"
        );
        assert!(UserId::from_bytes(alias).is_err());

        // The same value with the sign bit set is the other alias.
        let mut signed = alias;
        signed[31] |= 0x80;
        assert!(UserId::from_bytes(signed).is_err());

        // One below p is canonical, whether or not it is on the curve.
        let mut below = alias;
        below[0] = 0xec;
        assert_eq!(
            UserId::from_bytes(below).is_ok(),
            ed25519_dalek::VerifyingKey::from_bytes(&below).is_ok(),
            "canonical: the curve alone decides"
        );
    }
    /// Base58 decoding is a big-integer conversion, quadratic in the
    /// input, and an id is parsed on every frame field that carries one,
    /// before a relay has authenticated anybody. The length is checked
    /// first, so a frame full of base58 characters costs nothing.
    #[test]
    fn an_overlong_id_costs_nothing_to_refuse() {
        use std::time::{Duration, Instant};
        let long = "z".repeat(128 * 1024);
        let started = Instant::now();
        assert!(long.parse::<UserId>().is_err());
        assert!(
            "z".repeat(MAX_ID_CHARS + 1).parse::<UserId>().is_err(),
            "one character past what an id can be"
        );
        let took = started.elapsed();
        assert!(
            took < Duration::from_secs(1),
            "refused in {took:?}: the length is not being checked before the decoding"
        );
        // What an id really is still parses.
        let id = super::Identity::generate().user_id();
        assert_eq!(id.to_string().parse::<UserId>().unwrap(), id);
    }

    use super::*;

    /// `docs/design/dh-rotation.md` sections 2 and 5: a rekey replaces
    /// the Diffie–Hellman key and keeps the old one for the grace window;
    /// the identity key, and so the user id, does not move.
    #[test]
    fn a_rekey_replaces_the_dh_key_and_keeps_the_old_one_for_a_while() {
        let me = Identity::generate();
        let id = me.user_id();
        let old = me.dh_public();
        assert!(me.previous_dh_public().is_none());

        let new = me.rotate_dh(1_000);
        assert_eq!(me.user_id(), id, "the safety number does not move");
        assert_eq!(me.dh_public(), new);
        assert_ne!(new, old);
        assert_eq!(me.previous_dh_public(), Some(old));
        assert_eq!(me.dh_pair(DhKey::Previous).map(|(_, p)| p), Some(old));
        // The bundle carries the new key under a valid signature.
        let bundle = me.key_bundle();
        assert_eq!(bundle.dh_public, new);
        bundle.verify().unwrap();

        // Not yet; then, at the hour, gone.
        assert!(!me.expire_previous_dh(1_000 + DH_ROTATION_GRACE_MS - 1));
        assert_eq!(me.previous_dh_public(), Some(old));
        assert!(me.expire_previous_dh(1_000 + DH_ROTATION_GRACE_MS));
        assert!(me.previous_dh_public().is_none());
        assert!(me.dh_pair(DhKey::Previous).is_none());
        assert!(!me.expire_previous_dh(u64::MAX), "nothing left to expire");

        // Two rekeys inside the window: one previous key, the newer.
        let second = me.rotate_dh(2_000);
        let third = me.rotate_dh(3_000);
        assert_eq!(me.dh_public(), third);
        assert_eq!(me.previous_dh_public(), Some(second));
    }

    /// Section 7: a rotation whose secrets could not be written is put
    /// back, and nothing was published under the fresh key.
    #[test]
    fn an_unwritten_rekey_is_put_back() {
        let me = Identity::generate();
        let old = me.dh_public();
        assert!(!me.unrotate_dh(), "nothing to undo yet");
        me.rotate_dh(1);
        assert!(me.unrotate_dh());
        assert_eq!(me.dh_public(), old);
        assert!(me.previous_dh_public().is_none());
    }

    /// The secrets round-trip with and without a previous key, and the
    /// field is absent from the JSON when there is none, so a file written
    /// here reads in a version that does not know it.
    #[test]
    fn secrets_round_trip_with_and_without_a_previous_key() {
        let me = Identity::generate();
        let json = serde_json::to_string(&me.to_secrets()).unwrap();
        assert!(!json.contains("previous_dh"));
        let back = Identity::from_secrets(&serde_json::from_str(&json).unwrap());
        assert_eq!(back.user_id(), me.user_id());
        assert_eq!(back.dh_public(), me.dh_public());
        assert!(back.previous_dh_public().is_none());

        let old = me.dh_public();
        let new = me.rotate_dh(5_000);
        let json = serde_json::to_string(&me.to_secrets()).unwrap();
        assert!(json.contains("previous_dh"));
        let back = Identity::from_secrets(&serde_json::from_str(&json).unwrap());
        assert_eq!(back.dh_public(), new);
        assert_eq!(back.previous_dh_public(), Some(old));
        assert!(back.expire_previous_dh(5_000 + DH_ROTATION_GRACE_MS));
        assert!(
            !serde_json::to_string(&back.to_secrets())
                .unwrap()
                .contains("previous_dh")
        );
    }

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
