//! Forward-secret sessions: an X3DH handshake against a peer's published
//! prekeys, then a Double Ratchet for every message after that.
//!
//! The initiator ("Alice") fetches the peer's bundle, combines her long-term
//! Diffie–Hellman key and a fresh ephemeral key with the peer's identity key,
//! signed prekey and (when available) one one-time prekey, and derives the
//! session's root key from the results. Everything she needs to tell the
//! peer rides in an [`InitHeader`] alongside her first messages. The
//! responder ("Bob") recomputes the same root key from his private prekeys.
//!
//! From there both sides run the Double Ratchet: a new Diffie–Hellman ratchet
//! step whenever the direction of conversation changes, and a symmetric
//! chain of message keys within one direction. A message key is derived,
//! used once and discarded, so a stolen device reveals nothing about
//! messages that were already read; keys for messages that arrive late are
//! kept for a while so reordering is tolerated.
//!
//! This module is pure state and cryptography; which session to use for a
//! peer, and where sessions are stored, is the client's business.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::ProtocolError;
use crate::bundle::KeyBundle;
use crate::encoding::{b64, b64_array, b64_opt};
use crate::identity::{DhPublic, Identity, UserId};
use crate::pq::{KEM_SECRET_LEN, PqPrekeySecret};
use crate::prekey::PrekeySecret;

const X3DH_INFO: &[u8] = b"silver-messenger/v2/x3dh";
/// The hybrid handshake: the same inputs plus an ML-KEM shared secret.
const PQXDH_INFO: &[u8] = b"silver-messenger/v3/pqxdh";
const SESSION_ID_DOMAIN: &[u8] = b"silver-messenger/v2/session-id";
const ROOT_INFO: &[u8] = b"silver-messenger/v2/ratchet-root";
const MESSAGE_INFO: &[u8] = b"silver-messenger/v2/ratchet-message";

/// How far ahead in a receiving chain a message may be. Keys for the
/// messages in between are kept so they can still be read when they arrive.
pub const MAX_SKIP: u32 = 1000;
/// How many such keys one session keeps in total; the oldest go first.
pub const MAX_SKIPPED_KEYS: usize = 2000;

/// Identifies a session on both sides; derived from the handshake keys.
pub type SessionId = [u8; 16];

/// What the initiator has to tell the responder so it can derive the same
/// session. Sent with every message until the responder answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitHeader {
    /// The initiator's long-term Diffie–Hellman key.
    pub identity_dh: DhPublic,
    /// The initiator's ephemeral key for this handshake.
    pub ephemeral: DhPublic,
    pub signed_prekey_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_time_prekey_id: Option<u32>,
    /// Which of the responder's ML-KEM keys `kem_ciphertext` was made for
    /// (protocol v3); absent from a classical handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_prekey_id: Option<u32>,
    /// The ML-KEM ciphertext the responder decapsulates to get its half of
    /// the post-quantum secret.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub kem_ciphertext: Option<Vec<u8>>,
}

impl InitHeader {
    /// Whether this handshake carries the post-quantum secret.
    pub fn is_post_quantum(&self) -> bool {
        self.kem_ciphertext.is_some()
    }
}

/// The unencrypted part of a ratchet message: which ratchet key it was sent
/// under and its position in the chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetHeader {
    pub dh: DhPublic,
    /// Length of the previous sending chain.
    pub pn: u32,
    /// Position in the current sending chain.
    pub n: u32,
}

impl RatchetHeader {
    fn bytes(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..32].copy_from_slice(&self.dh.0);
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..].copy_from_slice(&self.n.to_be_bytes());
        out
    }
}

/// A message encrypted under a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetMessage {
    pub header: RatchetHeader,
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

/// A 32-byte secret that is base64 on disk and wiped from memory on drop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Key32(#[serde(with = "b64_array")] [u8; 32]);

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SkippedKey {
    #[serde(with = "b64_array")]
    dh: [u8; 32],
    n: u32,
    key: Key32,
}

/// One side's Double Ratchet state for one session. Serializable so a
/// client can persist it; every secret inside is wiped on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Session {
    #[serde(with = "b64_array")]
    id: SessionId,
    /// Associated data binding both identities, from the handshake.
    #[serde(with = "b64")]
    ad: Vec<u8>,
    dh_self: Key32,
    #[serde(with = "b64_array")]
    dh_self_public: [u8; 32],
    dh_remote: Option<DhPublic>,
    root_key: Key32,
    chain_send: Option<Key32>,
    chain_recv: Option<Key32>,
    n_send: u32,
    n_recv: u32,
    pn: u32,
    skipped: Vec<SkippedKey>,
    /// The handshake mixed in an ML-KEM secret.
    #[serde(default)]
    post_quantum: bool,
}

impl Session {
    /// Start a session with `peer`, who must have published prekeys. Returns
    /// the session and the header the peer needs to derive it.
    pub fn initiate(me: &Identity, peer: &KeyBundle) -> Result<(Self, InitHeader), ProtocolError> {
        let prekeys = peer.prekeys.as_ref().ok_or(ProtocolError::MissingPrekeys)?;
        prekeys.verify(&peer.user_id)?;
        let spk = prekeys.signed.public.as_x25519();
        let opk = prekeys.one_time.first();

        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = DhPublic(PublicKey::from(&ephemeral).to_bytes());
        let dh1 = me.dh_secret().diffie_hellman(&spk);
        let dh2 = ephemeral.diffie_hellman(&peer.dh_public.as_x25519());
        let dh3 = ephemeral.diffie_hellman(&spk);
        let dh4 = opk.map(|o| ephemeral.diffie_hellman(&o.public.as_x25519()));
        // Post-quantum half, when the peer published ML-KEM keys: a secret
        // only the holder of that key can recover from the ciphertext.
        let kem = match prekeys.pq_key() {
            Some(key) => {
                let (ciphertext, secret) = key.public.encapsulate()?;
                Some((key.id, ciphertext, secret))
            }
            None => None,
        };
        let secret = x3dh_secret(
            &dh1,
            &dh2,
            &dh3,
            dh4.as_ref(),
            kem.as_ref().map(|(_, _, secret)| &**secret),
        )?;
        let ad = x3dh_ad(
            &me.user_id(),
            &me.dh_public(),
            &peer.user_id,
            &peer.dh_public,
        );
        let id = session_id(&ephemeral_public, &prekeys.signed.public);

        // First ratchet step, against the peer's signed prekey.
        let ratchet = StaticSecret::random_from_rng(OsRng);
        let ratchet_public = PublicKey::from(&ratchet).to_bytes();
        let shared = ratchet.diffie_hellman(&spk);
        if !shared.was_contributory() {
            return Err(ProtocolError::WeakKey);
        }
        let (root_key, chain_send) = kdf_root(&secret, shared.as_bytes());

        let session = Self {
            id,
            ad,
            dh_self: Key32(ratchet.to_bytes()),
            dh_self_public: ratchet_public,
            dh_remote: Some(prekeys.signed.public),
            root_key,
            chain_send: Some(chain_send),
            chain_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: Vec::new(),
            post_quantum: kem.is_some(),
        };
        let (pq_prekey_id, kem_ciphertext) = match kem {
            Some((id, ciphertext, _)) => (Some(id), Some(ciphertext)),
            None => (None, None),
        };
        let header = InitHeader {
            identity_dh: me.dh_public(),
            ephemeral: ephemeral_public,
            signed_prekey_id: prekeys.signed.id,
            one_time_prekey_id: opk.map(|o| o.id),
            pq_prekey_id,
            kem_ciphertext,
        };
        Ok((session, header))
    }

    /// Derive the session an initiator described in `init`, using our own
    /// private prekeys. `one_time` must be given exactly when the header
    /// names one, and `pq` exactly when the header carries an ML-KEM
    /// ciphertext, with the id the header names.
    pub fn respond(
        me: &Identity,
        initiator: &UserId,
        signed: &PrekeySecret,
        one_time: Option<&PrekeySecret>,
        pq: Option<&PqPrekeySecret>,
        init: &InitHeader,
    ) -> Result<Self, ProtocolError> {
        if init.one_time_prekey_id.is_some() != one_time.is_some() {
            return Err(ProtocolError::Malformed(
                "one-time prekey given does not match the header".into(),
            ));
        }
        let kem = match (&init.kem_ciphertext, init.pq_prekey_id, pq) {
            (None, None, None) => None,
            (Some(ciphertext), Some(id), Some(secret)) if secret.id == id => {
                Some(secret.decapsulate(ciphertext)?)
            }
            _ => {
                return Err(ProtocolError::Malformed(
                    "post-quantum prekey given does not match the header".into(),
                ));
            }
        };
        let spk = signed.x25519();
        let ephemeral = init.ephemeral.as_x25519();
        let dh1 = spk.diffie_hellman(&init.identity_dh.as_x25519());
        let dh2 = me.dh_secret().diffie_hellman(&ephemeral);
        let dh3 = spk.diffie_hellman(&ephemeral);
        let dh4 = one_time.map(|o| o.x25519().diffie_hellman(&ephemeral));
        let secret = x3dh_secret(&dh1, &dh2, &dh3, dh4.as_ref(), kem.as_deref())?;
        let ad = x3dh_ad(initiator, &init.identity_dh, &me.user_id(), &me.dh_public());
        let id = session_id(&init.ephemeral, &signed.public());

        Ok(Self {
            id,
            ad,
            dh_self: Key32(spk.to_bytes()),
            dh_self_public: signed.public().0,
            dh_remote: None,
            root_key: secret,
            chain_send: None,
            chain_recv: None,
            n_send: 0,
            n_recv: 0,
            pn: 0,
            skipped: Vec::new(),
            post_quantum: kem.is_some(),
        })
    }

    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// Whether the handshake mixed in an ML-KEM secret, so that breaking
    /// X25519 alone does not open the session.
    pub fn is_post_quantum(&self) -> bool {
        self.post_quantum
    }

    /// Whether this side can send yet. A responder cannot until it has
    /// received the initiator's first message.
    pub fn can_send(&self) -> bool {
        self.chain_send.is_some()
    }

    /// Messages sent in the current chain (diagnostics).
    pub fn sent_in_chain(&self) -> u32 {
        self.n_send
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, ProtocolError> {
        let chain = self
            .chain_send
            .as_ref()
            .ok_or(ProtocolError::SessionNotReady)?;
        let (next, message_key) = kdf_chain(chain);
        let header = RatchetHeader {
            dh: DhPublic(self.dh_self_public),
            pn: self.pn,
            n: self.n_send,
        };
        let ciphertext = aead_encrypt(&message_key, plaintext, &self.aad(&header))?;
        self.chain_send = Some(next);
        self.n_send += 1;
        Ok(RatchetMessage { header, ciphertext })
    }

    /// Decrypt a message. The state only advances if decryption succeeds, so
    /// a forged or damaged message leaves the session intact.
    pub fn decrypt(
        &mut self,
        message: &RatchetMessage,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let mut trial = self.clone();
        let plaintext = trial.decrypt_advancing(message)?;
        *self = trial;
        Ok(plaintext)
    }

    fn decrypt_advancing(
        &mut self,
        message: &RatchetMessage,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        let header = &message.header;
        let aad = self.aad(header);
        if let Some(key) = self.take_skipped(header) {
            return aead_decrypt(&key, &message.ciphertext, &aad);
        }
        if self.dh_remote.as_ref() != Some(&header.dh) {
            self.skip_message_keys(header.pn)?;
            self.dh_ratchet(header)?;
        }
        self.skip_message_keys(header.n)?;
        let chain = self
            .chain_recv
            .as_ref()
            .ok_or(ProtocolError::SessionNotReady)?;
        let (next, message_key) = kdf_chain(chain);
        let plaintext = aead_decrypt(&message_key, &message.ciphertext, &aad)?;
        self.chain_recv = Some(next);
        self.n_recv += 1;
        Ok(plaintext)
    }

    fn aad(&self, header: &RatchetHeader) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.ad.len() + 16 + 40);
        v.extend_from_slice(&self.ad);
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&header.bytes());
        v
    }

    fn take_skipped(&mut self, header: &RatchetHeader) -> Option<Key32> {
        let at = self
            .skipped
            .iter()
            .position(|s| s.dh == header.dh.0 && s.n == header.n)?;
        Some(self.skipped.remove(at).key.clone())
    }

    /// Derive and set aside the keys for messages `n_recv..until` in the
    /// current receiving chain, so they can be read if they arrive later.
    fn skip_message_keys(&mut self, until: u32) -> Result<(), ProtocolError> {
        if self.n_recv.saturating_add(MAX_SKIP) < until {
            return Err(ProtocolError::TooManySkipped);
        }
        let Some(chain) = self.chain_recv.take() else {
            return Ok(());
        };
        let Some(remote) = self.dh_remote else {
            self.chain_recv = Some(chain);
            return Ok(());
        };
        let mut chain = chain;
        while self.n_recv < until {
            let (next, key) = kdf_chain(&chain);
            self.skipped.push(SkippedKey {
                dh: remote.0,
                n: self.n_recv,
                key,
            });
            chain = next;
            self.n_recv += 1;
        }
        if self.skipped.len() > MAX_SKIPPED_KEYS {
            let excess = self.skipped.len() - MAX_SKIPPED_KEYS;
            self.skipped.drain(..excess);
        }
        self.chain_recv = Some(chain);
        Ok(())
    }

    /// The peer moved to a new ratchet key: derive our receiving chain for
    /// it, then a fresh key pair and sending chain of our own.
    fn dh_ratchet(&mut self, header: &RatchetHeader) -> Result<(), ProtocolError> {
        self.pn = self.n_send;
        self.n_send = 0;
        self.n_recv = 0;
        self.dh_remote = Some(header.dh);
        let remote = header.dh.as_x25519();

        let ours = StaticSecret::from(self.dh_self.0);
        let shared = ours.diffie_hellman(&remote);
        if !shared.was_contributory() {
            return Err(ProtocolError::WeakKey);
        }
        let (root, chain_recv) = kdf_root(&self.root_key, shared.as_bytes());
        self.root_key = root;
        self.chain_recv = Some(chain_recv);

        let fresh = StaticSecret::random_from_rng(OsRng);
        let shared = fresh.diffie_hellman(&remote);
        if !shared.was_contributory() {
            return Err(ProtocolError::WeakKey);
        }
        let (root, chain_send) = kdf_root(&self.root_key, shared.as_bytes());
        self.dh_self_public = PublicKey::from(&fresh).to_bytes();
        self.dh_self = Key32(fresh.to_bytes());
        self.root_key = root;
        self.chain_send = Some(chain_send);
        Ok(())
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &crate::encoding::to_base64(&self.id))
            .field("n_send", &self.n_send)
            .field("n_recv", &self.n_recv)
            .field("skipped", &self.skipped.len())
            .finish_non_exhaustive()
    }
}

/// Both sides derive the same id from the handshake's public keys.
pub fn session_id(ephemeral: &DhPublic, signed_prekey: &DhPublic) -> SessionId {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_ID_DOMAIN);
    hasher.update([0u8]);
    hasher.update(ephemeral.0);
    hasher.update(signed_prekey.0);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

/// The session secret from the handshake's Diffie–Hellman outputs and, in
/// the hybrid (v3) handshake, the ML-KEM shared secret. Without `kem` this
/// is exactly the v2 derivation, so classical peers are unaffected.
fn x3dh_secret(
    dh1: &SharedSecret,
    dh2: &SharedSecret,
    dh3: &SharedSecret,
    dh4: Option<&SharedSecret>,
    kem: Option<&[u8; KEM_SECRET_LEN]>,
) -> Result<Key32, ProtocolError> {
    for dh in [dh1, dh2, dh3].into_iter().chain(dh4) {
        if !dh.was_contributory() {
            return Err(ProtocolError::WeakKey);
        }
    }
    // X3DH prepends 32 bytes of 0xFF for X25519 so the input cannot be
    // confused with an encoded point.
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 6));
    ikm.extend_from_slice(&[0xFF; 32]);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(dh4) = dh4 {
        ikm.extend_from_slice(dh4.as_bytes());
    }
    let info = match kem {
        Some(secret) => {
            ikm.extend_from_slice(secret);
            PQXDH_INFO
        }
        None => X3DH_INFO,
    };
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut out = Key32([0u8; 32]);
    hk.expand(info, &mut out.0)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Ok(out)
}

fn x3dh_ad(
    initiator: &UserId,
    initiator_dh: &DhPublic,
    responder: &UserId,
    responder_dh: &DhPublic,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    v.extend_from_slice(initiator.as_bytes());
    v.extend_from_slice(&initiator_dh.0);
    v.extend_from_slice(responder.as_bytes());
    v.extend_from_slice(&responder_dh.0);
    v
}

/// Root KDF: a new root key and a chain key from the current root key and a
/// Diffie–Hellman output.
fn kdf_root(root: &Key32, dh_out: &[u8; 32]) -> (Key32, Key32) {
    let hk = Hkdf::<Sha256>::new(Some(&root.0), dh_out);
    let mut out = Zeroizing::new([0u8; 64]);
    hk.expand(ROOT_INFO, out.as_mut_slice())
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    let mut new_root = Key32([0u8; 32]);
    let mut chain = Key32([0u8; 32]);
    new_root.0.copy_from_slice(&out[..32]);
    chain.0.copy_from_slice(&out[32..]);
    (new_root, chain)
}

/// Chain KDF: the next chain key and this step's message key.
fn kdf_chain(chain: &Key32) -> (Key32, Key32) {
    (hmac_byte(chain, 0x02), hmac_byte(chain, 0x01))
}

fn hmac_byte(key: &Key32, input: u8) -> Key32 {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&key.0).expect("HMAC accepts any key length");
    mac.update(&[input]);
    let mut out = Key32([0u8; 32]);
    out.0.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// A message key expands into an AEAD key and nonce.
fn message_key_material(message_key: &Key32) -> Zeroizing<[u8; 56]> {
    let hk = Hkdf::<Sha256>::new(None, &message_key.0);
    let mut out = Zeroizing::new([0u8; 56]);
    hk.expand(MESSAGE_INFO, out.as_mut_slice())
        .expect("56 bytes is a valid HKDF-SHA256 output length");
    out
}

fn aead_encrypt(
    message_key: &Key32,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let material = message_key_material(message_key);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&material[..32]));
    cipher
        .encrypt(
            XNonce::from_slice(&material[32..]),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ProtocolError::Malformed("encryption failed".into()))
}

fn aead_decrypt(
    message_key: &Key32,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let material = message_key_material(message_key);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&material[..32]));
    cipher
        .decrypt(
            XNonce::from_slice(&material[32..]),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| ProtocolError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prekey::Prekeys;

    /// What a peer publishes: `Classical` is a client before 0.7.0.
    #[derive(Clone, Copy, PartialEq)]
    enum Keys {
        Classical,
        /// ML-KEM keys, the signed one only (one-time keys ran out).
        PqSigned,
        /// ML-KEM keys with a one-time key handed out.
        PqOneTime,
    }

    struct Peer {
        identity: Identity,
        signed: PrekeySecret,
        one_time: PrekeySecret,
        pq_signed: PqPrekeySecret,
        pq_one_time: PqPrekeySecret,
    }

    impl Peer {
        fn new() -> Self {
            Self {
                identity: Identity::generate(),
                signed: PrekeySecret::generate(1, 0),
                one_time: PrekeySecret::generate(100, 0),
                pq_signed: PqPrekeySecret::generate(200, 0),
                pq_one_time: PqPrekeySecret::generate(300, 0),
            }
        }

        fn bundle(&self, with_one_time: bool) -> KeyBundle {
            self.bundle_with(with_one_time, Keys::Classical)
        }

        fn bundle_with(&self, with_one_time: bool, keys: Keys) -> KeyBundle {
            let one_time = if with_one_time {
                vec![self.one_time.one_time()]
            } else {
                Vec::new()
            };
            let mut prekeys = Prekeys::classical(self.signed.signed_by(&self.identity), one_time);
            if keys != Keys::Classical {
                prekeys.pq_signed = Some(self.pq_signed.signed_by(&self.identity));
            }
            if keys == Keys::PqOneTime {
                prekeys.pq_one_time = vec![self.pq_one_time.signed_by(&self.identity)];
            }
            self.identity.key_bundle_with(prekeys)
        }

        fn pq_secret(&self, id: u32) -> Option<&PqPrekeySecret> {
            [&self.pq_signed, &self.pq_one_time]
                .into_iter()
                .find(|k| k.id == id)
        }

        fn respond(&self, initiator: &UserId, init: &InitHeader) -> Session {
            let one_time = init.one_time_prekey_id.map(|_| &self.one_time);
            let pq = init.pq_prekey_id.and_then(|id| self.pq_secret(id));
            Session::respond(&self.identity, initiator, &self.signed, one_time, pq, init).unwrap()
        }
    }

    fn handshake(with_one_time: bool) -> (Session, Session, InitHeader) {
        handshake_with(with_one_time, Keys::Classical)
    }

    fn handshake_with(with_one_time: bool, keys: Keys) -> (Session, Session, InitHeader) {
        let alice = Identity::generate();
        let bob = Peer::new();
        let (alice_session, init) =
            Session::initiate(&alice, &bob.bundle_with(with_one_time, keys)).unwrap();
        let bob_session = bob.respond(&alice.user_id(), &init);
        (alice_session, bob_session, init)
    }

    #[test]
    fn a_post_quantum_handshake_uses_the_one_time_key_first() {
        for (keys, with_one_time) in [
            (Keys::PqOneTime, true),
            (Keys::PqOneTime, false),
            (Keys::PqSigned, true),
            (Keys::PqSigned, false),
        ] {
            let (mut a, mut b, init) = handshake_with(with_one_time, keys);
            assert_eq!(a.id(), b.id());
            assert!(a.is_post_quantum() && b.is_post_quantum());
            assert!(init.is_post_quantum());
            assert_eq!(
                init.pq_prekey_id,
                Some(if keys == Keys::PqOneTime { 300 } else { 200 })
            );
            assert_eq!(
                init.kem_ciphertext.as_ref().map(Vec::len),
                Some(crate::pq::KEM_CIPHERTEXT_LEN)
            );
            let m = a.encrypt(b"pq hello").unwrap();
            assert_eq!(b.decrypt(&m).unwrap().as_slice(), b"pq hello");
            let r = b.encrypt(b"pq hi").unwrap();
            assert_eq!(a.decrypt(&r).unwrap().as_slice(), b"pq hi");
        }
        // A classical handshake says so, and its header is the v2 one: no
        // post-quantum fields for an older responder to trip over.
        let (a, b, init) = handshake(true);
        assert!(!a.is_post_quantum() && !b.is_post_quantum() && !init.is_post_quantum());
        let json = serde_json::to_string(&init).unwrap();
        assert!(!json.contains("pq_prekey_id") && !json.contains("kem_ciphertext"));
    }

    #[test]
    fn a_tampered_or_mismatched_post_quantum_handshake_fails_cleanly() {
        let alice = Identity::generate();
        let bob = Peer::new();
        let bundle = bob.bundle_with(true, Keys::PqOneTime);
        let (mut a, init) = Session::initiate(&alice, &bundle).unwrap();
        let m = a.encrypt(b"x").unwrap();

        // A damaged ciphertext gives the responder a different secret: the
        // handshake completes but nothing decrypts.
        let mut damaged = init.clone();
        damaged.kem_ciphertext.as_mut().unwrap()[10] ^= 0x01;
        let mut b = bob.respond(&alice.user_id(), &damaged);
        assert_eq!(b.decrypt(&m), Err(ProtocolError::DecryptFailed));
        // The wrong ML-KEM key, likewise.
        let mut wrong = Session::respond(
            &bob.identity,
            &alice.user_id(),
            &bob.signed,
            Some(&bob.one_time),
            Some(&PqPrekeySecret::generate(300, 0)),
            &init,
        )
        .unwrap();
        assert_eq!(wrong.decrypt(&m), Err(ProtocolError::DecryptFailed));
        // The header and the keys given must agree.
        let mismatch = |pq: Option<&PqPrekeySecret>, init: &InitHeader| {
            Session::respond(
                &bob.identity,
                &alice.user_id(),
                &bob.signed,
                Some(&bob.one_time),
                pq,
                init,
            )
            .is_err()
        };
        assert!(mismatch(None, &init));
        assert!(mismatch(Some(&bob.pq_signed), &init));
        let mut short = init.clone();
        short.kem_ciphertext.as_mut().unwrap().truncate(50);
        assert!(mismatch(Some(&bob.pq_one_time), &short));
        let mut classical = init.clone();
        classical.kem_ciphertext = None;
        classical.pq_prekey_id = None;
        assert!(mismatch(Some(&bob.pq_one_time), &classical));

        // A bundle whose ML-KEM key is not the owner's is refused outright.
        let mut forged = bundle.clone();
        forged.prekeys.as_mut().unwrap().pq_one_time[0] =
            PqPrekeySecret::generate(300, 0).signed_by(&Identity::generate());
        assert_eq!(
            Session::initiate(&alice, &forged).err(),
            Some(ProtocolError::InvalidSignature)
        );
    }

    #[test]
    fn both_sides_derive_the_same_session_and_talk_both_ways() {
        for with_one_time in [true, false] {
            let (mut a, mut b, init) = handshake(with_one_time);
            assert_eq!(a.id(), b.id());
            assert_eq!(init.one_time_prekey_id.is_some(), with_one_time);
            assert!(a.can_send() && !b.can_send());

            let m1 = a.encrypt(b"hello bob").unwrap();
            assert_eq!(b.decrypt(&m1).unwrap().as_slice(), b"hello bob");
            assert!(b.can_send());
            let m2 = b.encrypt(b"hi alice").unwrap();
            assert_eq!(a.decrypt(&m2).unwrap().as_slice(), b"hi alice");
            // A few more turns force several DH ratchet steps.
            for i in 0..5u8 {
                let ma = a.encrypt(&[i]).unwrap();
                assert_eq!(b.decrypt(&ma).unwrap().as_slice(), &[i]);
                let mb = b.encrypt(&[i, i]).unwrap();
                assert_eq!(a.decrypt(&mb).unwrap().as_slice(), &[i, i]);
            }
        }
    }

    #[test]
    fn keys_differ_per_message_and_ciphertext_hides_plaintext() {
        let (mut a, _, _) = handshake(true);
        let m1 = a.encrypt(b"same").unwrap();
        let m2 = a.encrypt(b"same").unwrap();
        assert_ne!(m1.ciphertext, m2.ciphertext);
        assert_eq!(m1.header.n, 0);
        assert_eq!(m2.header.n, 1);
        assert!(!serde_json::to_string(&m1).unwrap().contains("same"));
    }

    #[test]
    fn out_of_order_delivery_and_replays() {
        let (mut a, mut b, _) = handshake(true);
        let m0 = a.encrypt(b"0").unwrap();
        let m1 = a.encrypt(b"1").unwrap();
        let m2 = a.encrypt(b"2").unwrap();
        assert_eq!(b.decrypt(&m2).unwrap().as_slice(), b"2");
        assert_eq!(b.decrypt(&m0).unwrap().as_slice(), b"0");
        // A replay finds its key gone.
        assert_eq!(b.decrypt(&m0), Err(ProtocolError::DecryptFailed));
        assert_eq!(b.decrypt(&m1).unwrap().as_slice(), b"1");

        // Skipped keys survive a DH ratchet step in between.
        let m3 = a.encrypt(b"3").unwrap();
        let m4 = a.encrypt(b"4").unwrap();
        assert_eq!(b.decrypt(&m4).unwrap().as_slice(), b"4");
        let r0 = b.encrypt(b"reply").unwrap();
        assert_eq!(a.decrypt(&r0).unwrap().as_slice(), b"reply");
        let m5 = a.encrypt(b"5").unwrap();
        assert_eq!(b.decrypt(&m5).unwrap().as_slice(), b"5");
        assert_eq!(b.decrypt(&m3).unwrap().as_slice(), b"3");
    }

    #[test]
    fn tampering_is_rejected_without_disturbing_the_session() {
        let (mut a, mut b, _) = handshake(true);
        let good = a.encrypt(b"fine").unwrap();
        let mut bad = good.clone();
        let last = bad.ciphertext.len() - 1;
        bad.ciphertext[last] ^= 1;
        assert_eq!(b.decrypt(&bad), Err(ProtocolError::DecryptFailed));
        let mut wrong_header = good.clone();
        wrong_header.header.n = 7;
        assert_eq!(b.decrypt(&wrong_header), Err(ProtocolError::DecryptFailed));
        // The failed attempts left no trace: the real message still reads.
        assert_eq!(b.decrypt(&good).unwrap().as_slice(), b"fine");
    }

    #[test]
    fn too_large_a_jump_is_refused() {
        let (mut a, mut b, _) = handshake(true);
        for _ in 0..=MAX_SKIP {
            a.encrypt(b"x").unwrap();
        }
        let far = a.encrypt(b"far").unwrap();
        assert_eq!(far.header.n, MAX_SKIP + 1);
        assert_eq!(b.decrypt(&far), Err(ProtocolError::TooManySkipped));
    }

    #[test]
    fn mismatched_one_time_prekey_is_an_error() {
        let alice = Identity::generate();
        let bob = Peer::new();
        let (_, init) = Session::initiate(&alice, &bob.bundle(true)).unwrap();
        assert!(
            Session::respond(
                &bob.identity,
                &alice.user_id(),
                &bob.signed,
                None,
                None,
                &init
            )
            .is_err()
        );
        // The wrong one-time key derives a different session: messages fail.
        let other = PrekeySecret::generate(101, 0);
        let mut wrong = Session::respond(
            &bob.identity,
            &alice.user_id(),
            &bob.signed,
            Some(&other),
            None,
            &init,
        )
        .unwrap();
        let (mut a, _) = Session::initiate(&alice, &bob.bundle(true)).unwrap();
        assert!(wrong.decrypt(&a.encrypt(b"x").unwrap()).is_err());
    }

    #[test]
    fn a_bundle_without_prekeys_cannot_start_a_session() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        assert_eq!(
            Session::initiate(&alice, &bob.key_bundle()).err(),
            Some(ProtocolError::MissingPrekeys)
        );
    }

    #[test]
    fn sessions_survive_serialization_mid_conversation() {
        let (mut a, mut b, _) = handshake(false);
        let m = a.encrypt(b"before").unwrap();
        b.decrypt(&m).unwrap();
        let r = b.encrypt(b"reply").unwrap();

        let a_json = serde_json::to_string(&a).unwrap();
        let b_json = serde_json::to_string(&b).unwrap();
        let mut a2: Session = serde_json::from_str(&a_json).unwrap();
        let mut b2: Session = serde_json::from_str(&b_json).unwrap();
        assert_eq!(a2.decrypt(&r).unwrap().as_slice(), b"reply");
        let m2 = a2.encrypt(b"after").unwrap();
        assert_eq!(b2.decrypt(&m2).unwrap().as_slice(), b"after");
        // Nothing but base64 for the secrets, and the debug form shows none.
        assert!(a_json.contains("\"root_key\":\""));
        assert!(!format!("{a:?}").contains("root_key"));
    }
}
