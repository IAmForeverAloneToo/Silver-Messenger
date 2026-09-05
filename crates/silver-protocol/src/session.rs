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
use crate::pq::{KEM_SECRET_LEN, KemPublic, KemRatchetKey, PqPrekeySecret};
use crate::prekey::PrekeySecret;

const X3DH_INFO: &[u8] = b"silver-messenger/v2/x3dh";
/// The hybrid handshake: the same inputs plus an ML-KEM shared secret.
const PQXDH_INFO: &[u8] = b"silver-messenger/v3/pqxdh";
const SESSION_ID_DOMAIN: &[u8] = b"silver-messenger/v2/session-id";
const ROOT_INFO: &[u8] = b"silver-messenger/v2/ratchet-root";
/// Root KDF for the post-quantum ratchet (protocol v4): the same as
/// [`ROOT_INFO`] but for the chain where an ML-KEM secret is mixed in
/// beside the Diffie–Hellman output.
const ROOT_INFO_V4: &[u8] = b"silver-messenger/v4/ratchet-root";
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
    /// The initiator's identity-key signature over `identity_dh` (the same
    /// signature its key bundle carries). A protocol-v4 body is not signed
    /// at the sealed-sender layer, so this is what ties `identity_dh` to the
    /// sender's identity; without it a third party could substitute its own
    /// key and impersonate the sender. Absent from v2/v3 handshakes, whose
    /// envelope signature does the same job.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::encoding::b64_opt_array"
    )]
    pub identity_dh_signature: Option<[u8; 64]>,
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
    /// The sender's current ML-KEM ratchet key (protocol v4); present on
    /// every message of a post-quantum-ratchet session, absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kem: Option<KemPublic>,
    /// The ML-KEM ciphertext for the current sending chain, encapsulated to
    /// the peer's last ratchet key. Absent on the first chain of each
    /// direction (which has no peer key to encapsulate to yet) and on
    /// classical sessions.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub kem_ct: Option<Vec<u8>>,
}

impl RatchetHeader {
    /// The header as associated data: the fixed 40 bytes, then the ML-KEM
    /// public key and ciphertext when present, so both are bound into the
    /// message's AEAD and cannot be swapped by the relay.
    fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&self.dh.0);
        out.extend_from_slice(&self.pn.to_be_bytes());
        out.extend_from_slice(&self.n.to_be_bytes());
        if let Some(kem) = &self.kem {
            out.extend_from_slice(&kem.0);
        }
        if let Some(ct) = &self.kem_ct {
            out.extend_from_slice(ct);
        }
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
    /// The session runs the post-quantum ratchet (protocol v4): every DH
    /// ratchet step also does an ML-KEM step, so healing after a compromise
    /// is post-quantum too. False for v2/v3 sessions.
    #[serde(default)]
    pq_ratchet: bool,
    /// Our current ML-KEM ratchet key, for decapsulating the peer's next
    /// ciphertext. `None` on a classical session and until the first step.
    #[serde(default)]
    kem_self: Option<KemRatchetKey>,
    /// `kem_self`'s public half, cached so it need not be recomputed for
    /// every message header.
    #[serde(default)]
    kem_self_public: Option<KemPublic>,
    /// The peer's current ML-KEM ratchet key, to encapsulate to.
    #[serde(default)]
    kem_remote: Option<KemPublic>,
    /// The ciphertext attached to every message of the current sending
    /// chain, so the peer can rebuild the chain from any of them.
    #[serde(default, with = "b64_opt")]
    kem_ct_send: Option<Vec<u8>>,
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

        // The post-quantum ratchet runs when the handshake is post-quantum
        // and the peer advertises that it reads v4 bodies.
        let pq_ratchet = kem.is_some() && peer.supports_pq_ratchet();
        let (kem_self, kem_self_public) = if pq_ratchet {
            let key = KemRatchetKey::generate();
            let public = key.public();
            (Some(key), Some(public))
        } else {
            (None, None)
        };

        // First ratchet step, against the peer's signed prekey. Our first
        // sending chain has no ML-KEM step: the handshake secret is already
        // post-quantum, and there is no peer ratchet key to encapsulate to
        // yet. The ratchet becomes post-quantum on the next round trip.
        let ratchet = StaticSecret::random_from_rng(OsRng);
        let ratchet_public = PublicKey::from(&ratchet).to_bytes();
        let shared = ratchet.diffie_hellman(&spk);
        if !shared.was_contributory() {
            return Err(ProtocolError::WeakKey);
        }
        let (root_key, chain_send) = kdf_root(&secret, shared.as_bytes(), None, pq_ratchet);

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
            pq_ratchet,
            kem_self,
            kem_self_public,
            kem_remote: None,
            kem_ct_send: None,
        };
        let (pq_prekey_id, kem_ciphertext) = match kem {
            Some((id, ciphertext, _)) => (Some(id), Some(ciphertext)),
            None => (None, None),
        };
        // On a v4 handshake the sealed layer is unsigned, so the initiator
        // vouches for its Diffie–Hellman key here, with the same signature
        // its bundle carries; the responder checks it against the sender.
        let identity_dh_signature =
            pq_ratchet.then(|| me.sign(crate::bundle::BUNDLE_DOMAIN, &me.dh_public().0));
        let header = InitHeader {
            identity_dh: me.dh_public(),
            ephemeral: ephemeral_public,
            signed_prekey_id: prekeys.signed.id,
            one_time_prekey_id: opk.map(|o| o.id),
            pq_prekey_id,
            kem_ciphertext,
            identity_dh_signature,
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
        pq_ratchet: bool,
    ) -> Result<Self, ProtocolError> {
        if init.one_time_prekey_id.is_some() != one_time.is_some() {
            return Err(ProtocolError::Malformed(
                "one-time prekey given does not match the header".into(),
            ));
        }
        if pq_ratchet && init.kem_ciphertext.is_none() {
            return Err(ProtocolError::Malformed(
                "the post-quantum ratchet needs a post-quantum handshake".into(),
            ));
        }
        // A v4 handshake is not signed at the sealed layer, so the
        // initiator's key-binding signature is what proves `identity_dh`
        // belongs to the claimed sender. Require and check it.
        if pq_ratchet {
            let signature = init.identity_dh_signature.ok_or_else(|| {
                ProtocolError::Malformed("a v4 handshake carries no key-binding signature".into())
            })?;
            initiator.verify(
                crate::bundle::BUNDLE_DOMAIN,
                &init.identity_dh.0,
                &signature,
            )?;
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
            pq_ratchet,
            // The responder makes its ratchet key on its first step, once it
            // knows the initiator's from that first message's header.
            kem_self: None,
            kem_self_public: None,
            kem_remote: None,
            kem_ct_send: None,
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

    /// Whether the ratchet, and not only the handshake, is post-quantum
    /// (protocol v4): every ratchet step also does an ML-KEM step, so a
    /// compromise heals against a quantum adversary too.
    pub fn is_pq_ratchet(&self) -> bool {
        self.pq_ratchet
    }

    /// The body version this session's messages are: 4 for the post-quantum
    /// (and deniable) ratchet, 2 otherwise.
    pub fn body_version(&self) -> u32 {
        if self.pq_ratchet { 4 } else { 2 }
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
            kem: self.kem_self_public.clone(),
            kem_ct: self.kem_ct_send.clone(),
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
    /// it, then a fresh key pair and sending chain of our own. On a
    /// post-quantum-ratchet session each half also does an ML-KEM step: the
    /// receiving chain mixes in the secret from the peer's ciphertext, the
    /// sending chain a fresh secret we encapsulate to the peer's key.
    fn dh_ratchet(&mut self, header: &RatchetHeader) -> Result<(), ProtocolError> {
        self.pn = self.n_send;
        self.n_send = 0;
        self.n_recv = 0;
        self.dh_remote = Some(header.dh);
        let remote = header.dh.as_x25519();

        // Receiving chain: our current keys against the peer's new ones.
        let ours = StaticSecret::from(self.dh_self.0);
        let shared = ours.diffie_hellman(&remote);
        if !shared.was_contributory() {
            return Err(ProtocolError::WeakKey);
        }
        let recv_ss = if self.pq_ratchet {
            match (&header.kem_ct, &self.kem_self) {
                (Some(ct), Some(key)) => Some(key.decapsulate(ct)?),
                // The peer had no ratchet key of ours to encapsulate to yet
                // (its first chain): a Diffie–Hellman-only step, as ours was.
                (None, _) => None,
                (Some(_), None) => {
                    return Err(ProtocolError::Malformed(
                        "a post-quantum ratchet message arrived before we have a ratchet key"
                            .into(),
                    ));
                }
            }
        } else {
            None
        };
        let (root, chain_recv) = kdf_root(
            &self.root_key,
            shared.as_bytes(),
            recv_ss.as_deref(),
            self.pq_ratchet,
        );
        self.root_key = root;
        self.chain_recv = Some(chain_recv);
        if self.pq_ratchet {
            self.kem_remote = header.kem.clone();
        }

        // Sending chain: a fresh key pair, and a fresh ML-KEM secret
        // encapsulated to the peer's latest ratchet key.
        let fresh = StaticSecret::random_from_rng(OsRng);
        let shared = fresh.diffie_hellman(&remote);
        if !shared.was_contributory() {
            return Err(ProtocolError::WeakKey);
        }
        let send_ss = if self.pq_ratchet {
            let key = KemRatchetKey::generate();
            self.kem_self_public = Some(key.public());
            self.kem_self = Some(key);
            match &self.kem_remote {
                Some(peer) => {
                    let (ciphertext, secret) = peer.encapsulate()?;
                    self.kem_ct_send = Some(ciphertext);
                    Some(secret)
                }
                None => {
                    self.kem_ct_send = None;
                    None
                }
            }
        } else {
            None
        };
        let (root, chain_send) = kdf_root(
            &self.root_key,
            shared.as_bytes(),
            send_ss.as_deref(),
            self.pq_ratchet,
        );
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

/// Root KDF: a new root key and a chain key from the current root key, a
/// Diffie–Hellman output, and (on the post-quantum ratchet) an ML-KEM
/// secret. Without `kem` and with `pq` false this is exactly the v2
/// derivation, so classical sessions are byte-for-byte unchanged.
fn kdf_root(root: &Key32, dh_out: &[u8; 32], kem: Option<&[u8; 32]>, pq: bool) -> (Key32, Key32) {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(dh_out);
    if let Some(kem) = kem {
        ikm.extend_from_slice(kem);
    }
    let info = if pq { ROOT_INFO_V4 } else { ROOT_INFO };
    let hk = Hkdf::<Sha256>::new(Some(&root.0), &ikm);
    let mut out = Zeroizing::new([0u8; 64]);
    hk.expand(info, out.as_mut_slice())
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

    /// What a peer publishes: `Classical` is a client before 0.6.0.
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

        /// A post-quantum bundle that also advertises the v4 ratchet.
        fn bundle_pq_ratchet(&self, with_one_time: bool) -> KeyBundle {
            let keys = if with_one_time {
                Keys::PqOneTime
            } else {
                Keys::PqSigned
            };
            self.bundle_with(with_one_time, keys).with_caps(
                &self.identity,
                vec![crate::bundle::capability::PQ_RATCHET.to_owned()],
            )
        }

        fn pq_secret(&self, id: u32) -> Option<&PqPrekeySecret> {
            [&self.pq_signed, &self.pq_one_time]
                .into_iter()
                .find(|k| k.id == id)
        }

        fn respond(&self, initiator: &UserId, init: &InitHeader, pq_ratchet: bool) -> Session {
            let one_time = init.one_time_prekey_id.map(|_| &self.one_time);
            let pq = init.pq_prekey_id.and_then(|id| self.pq_secret(id));
            Session::respond(
                &self.identity,
                initiator,
                &self.signed,
                one_time,
                pq,
                init,
                pq_ratchet,
            )
            .unwrap()
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
        let bob_session = bob.respond(&alice.user_id(), &init, false);
        (alice_session, bob_session, init)
    }

    /// A handshake where both sides run the post-quantum ratchet.
    fn handshake_pq_ratchet(with_one_time: bool) -> (Session, Session) {
        let alice = Identity::generate();
        let bob = Peer::new();
        let (alice_session, init) =
            Session::initiate(&alice, &bob.bundle_pq_ratchet(with_one_time)).unwrap();
        let bob_session = bob.respond(&alice.user_id(), &init, true);
        (alice_session, bob_session)
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
        let mut b = bob.respond(&alice.user_id(), &damaged, false);
        assert_eq!(b.decrypt(&m), Err(ProtocolError::DecryptFailed));
        // The wrong ML-KEM key, likewise.
        let mut wrong = Session::respond(
            &bob.identity,
            &alice.user_id(),
            &bob.signed,
            Some(&bob.one_time),
            Some(&PqPrekeySecret::generate(300, 0)),
            &init,
            false,
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
                false,
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
    fn the_post_quantum_ratchet_heals_every_step_and_stays_post_quantum() {
        for with_one_time in [true, false] {
            let (mut a, mut b) = handshake_pq_ratchet(with_one_time);
            assert_eq!(a.id(), b.id());
            assert!(a.is_pq_ratchet() && b.is_pq_ratchet());
            assert_eq!(a.body_version(), 4);
            assert!(a.is_post_quantum() && b.is_post_quantum());

            // The initiator's first message carries its ratchet key but no
            // ciphertext (no peer key to encapsulate to yet).
            let m1 = a.encrypt(b"hello").unwrap();
            assert!(m1.header.kem.is_some() && m1.header.kem_ct.is_none());
            assert_eq!(b.decrypt(&m1).unwrap().as_slice(), b"hello");

            // Every message the responder sends does a full ML-KEM step.
            let r1 = b.encrypt(b"hi").unwrap();
            assert!(r1.header.kem.is_some() && r1.header.kem_ct.is_some());
            assert_eq!(a.decrypt(&r1).unwrap().as_slice(), b"hi");

            // And from the next chain on, the initiator does too.
            let m2 = a.encrypt(b"again").unwrap();
            assert!(m2.header.kem.is_some() && m2.header.kem_ct.is_some());
            assert_eq!(b.decrypt(&m2).unwrap().as_slice(), b"again");

            // Several turns of back-and-forth keep working.
            for i in 0..5u8 {
                let ma = a.encrypt(&[i]).unwrap();
                assert!(ma.header.kem_ct.is_some());
                assert_eq!(b.decrypt(&ma).unwrap().as_slice(), &[i]);
                let mb = b.encrypt(&[i, i]).unwrap();
                assert!(mb.header.kem_ct.is_some());
                assert_eq!(a.decrypt(&mb).unwrap().as_slice(), &[i, i]);
            }
        }
    }

    #[test]
    fn a_post_quantum_ratchet_message_authenticates_its_ml_kem_fields() {
        let (mut a, mut b) = handshake_pq_ratchet(true);
        let m1 = a.encrypt(b"hi").unwrap();
        b.decrypt(&m1).unwrap();
        let r = b.encrypt(b"reply").unwrap();

        // Tampering with the ML-KEM public key or ciphertext in the header
        // makes the message fail: the ciphertext decapsulates to a different
        // secret (or is rejected), the public key is bound into the AEAD, and
        // a flip that stops either parsing is refused outright. Whichever
        // way, the message does not read and the session is left untouched.
        let mut bad_kem = r.clone();
        bad_kem.header.kem.as_mut().unwrap().0[10] ^= 0x01;
        assert!(a.clone().decrypt(&bad_kem).is_err());
        let mut bad_ct = r.clone();
        bad_ct.header.kem_ct.as_mut().unwrap()[10] ^= 0x01;
        assert!(a.clone().decrypt(&bad_ct).is_err());
        // The real one still reads, on the untouched session.
        assert_eq!(a.decrypt(&r).unwrap().as_slice(), b"reply");
    }

    #[test]
    fn a_v4_session_survives_serialization_mid_conversation() {
        let (mut a, mut b) = handshake_pq_ratchet(true);
        let m = a.encrypt(b"before").unwrap();
        b.decrypt(&m).unwrap();
        let r = b.encrypt(b"reply").unwrap();
        let a_json = serde_json::to_string(&a).unwrap();
        let b_json = serde_json::to_string(&b).unwrap();
        let mut a2: Session = serde_json::from_str(&a_json).unwrap();
        let mut b2: Session = serde_json::from_str(&b_json).unwrap();
        assert!(a2.is_pq_ratchet());
        assert_eq!(a2.decrypt(&r).unwrap().as_slice(), b"reply");
        let m2 = a2.encrypt(b"after a reload").unwrap();
        assert!(m2.header.kem_ct.is_some());
        assert_eq!(b2.decrypt(&m2).unwrap().as_slice(), b"after a reload");
    }

    #[test]
    fn the_ratchet_is_classical_when_the_peer_does_not_advertise_v4() {
        // Post-quantum keys but no capability: the handshake is post-quantum,
        // the ratchet is not, and the header carries no ML-KEM fields for an
        // older peer to trip over.
        let (a, b, _) = handshake_with(true, Keys::PqOneTime);
        assert!(a.is_post_quantum() && !a.is_pq_ratchet());
        assert_eq!(a.body_version(), 2);
        let mut a = a;
        let m = a.encrypt(b"x").unwrap();
        assert!(m.header.kem.is_none() && m.header.kem_ct.is_none());
        let _ = b;
    }

    #[test]
    fn a_v4_handshake_without_its_key_binding_signature_is_refused() {
        let alice = Identity::generate();
        let bob = Peer::new();
        let (_, init) = Session::initiate(&alice, &bob.bundle_pq_ratchet(true)).unwrap();
        assert!(init.identity_dh_signature.is_some());
        // Missing the signature.
        let mut no_sig = init.clone();
        no_sig.identity_dh_signature = None;
        assert!(matches!(
            Session::respond(
                &bob.identity,
                &alice.user_id(),
                &bob.signed,
                Some(&bob.one_time),
                bob.pq_secret(init.pq_prekey_id.unwrap()),
                &no_sig,
                true,
            ),
            Err(ProtocolError::Malformed(_))
        ));
        // A signature that is not the sender's (an impersonator supplying
        // its own key and its own signature) is refused.
        let mallory = Identity::generate();
        let mut forged = init.clone();
        forged.identity_dh = mallory.dh_public();
        forged.identity_dh_signature =
            Some(mallory.sign(crate::bundle::BUNDLE_DOMAIN, &mallory.dh_public().0));
        assert_eq!(
            Session::respond(
                &bob.identity,
                &alice.user_id(),
                &bob.signed,
                Some(&bob.one_time),
                bob.pq_secret(init.pq_prekey_id.unwrap()),
                &forged,
                true,
            )
            .err(),
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
                &init,
                false
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
            false,
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
