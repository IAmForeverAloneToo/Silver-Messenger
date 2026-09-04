//! Sealing and opening end-to-end encrypted envelopes.
//!
//! The envelope is the "sealed sender" layer: a fresh ephemeral key, a
//! Diffie–Hellman with the recipient's long-term key, and an AEAD over
//! `sender id || signature || body`. The relay sees only the recipient.
//!
//! The body inside is one of two things ([`Body`]): a plain v1 body (the
//! message itself), or a v2 ratchet body carrying a message encrypted once
//! more under a forward-secret [`Session`](crate::session::Session). The
//! sealed layer is the same for both, so relays and v1 clients cannot tell
//! them apart from the outside.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::ProtocolError;
use crate::blob::BlobKey;
use crate::bundle::KeyBundle;
use crate::encoding::{b64, b64_array};
use crate::identity::{DhPublic, Identity, UserId};
use crate::session::{InitHeader, RatchetMessage, SessionId};

pub const ENVELOPE_DOMAIN: &[u8] = b"silver-messenger/v1/envelope";
const KDF_INFO: &[u8] = b"silver-messenger/v1/xchacha20poly1305";

/// Upper bound on the serialized plaintext body.
pub const MAX_BODY_BYTES: usize = 32 * 1024;
/// Upper bound on ciphertext a relay or client will accept.
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_BODY_BYTES + 96 + 16 + 1024;

/// What the relay sees: an opaque blob addressed to a recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Random id used for acknowledgements and de-duplication.
    pub id: String,
    pub to: UserId,
    pub ephemeral_public: DhPublic,
    #[serde(with = "b64_array")]
    pub nonce: [u8; 24],
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

/// The kinds of content a message can carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Content {
    Text {
        body: String,
    },
    /// Acknowledges the messages with these ids. Only sent to peers whose
    /// messages advertised the `receipts` capability.
    Receipt {
        kind: ReceiptKind,
        ids: Vec<String>,
    },
    /// A file parked on the relay as an encrypted blob; everything needed
    /// to fetch and read it. Only sent to peers that advertised `files`.
    File {
        name: String,
        size: u64,
        blob: String,
        key: BlobKey,
        chunks: u32,
        #[serde(with = "b64_array")]
        sha256: [u8; 32],
    },
}

/// How far a message got on the recipient's side. Ordered: read implies
/// delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    /// Decrypted and stored by the recipient's client.
    Delivered,
    /// Shown to the recipient.
    Read,
}

/// Capability names a client may advertise in the bodies it sends.
pub mod capability {
    /// The client understands `Content::Receipt` and would like to get them.
    pub const RECEIPTS: &str = "receipts";
    /// The client understands `Content::File` and fetches blobs.
    pub const FILES: &str = "files";
    /// The client reads files whose last chunk was padded to a whole chunk
    /// (it cuts them to `size`), so the relay sees file sizes in 64 KiB
    /// steps only.
    pub const PADDED_FILES: &str = "padded_files";
}

/// Bodies are padded to a multiple of this many bytes, so a relay sees
/// sizes in steps: a receipt, a short and a long message look alike.
pub const PAD_BLOCK: usize = 160;

/// Pad an encoded body with trailing spaces, which JSON ignores, to the
/// next multiple of [`PAD_BLOCK`]. Clients before 0.6.0 read padded bodies
/// as they are, and unpadded bodies from them still decode.
pub fn pad(bytes: &mut Vec<u8>) {
    let target = bytes.len().div_ceil(PAD_BLOCK).max(1) * PAD_BLOCK;
    bytes.resize(target, b' ');
}

/// Position of a message in the sender's stream to one recipient.
///
/// `seq` counts up by one per message; `epoch` is a random value chosen when
/// a client starts counting from scratch (a fresh installation), so a reset
/// is distinguishable from a replay. Both live inside the encrypted body and
/// let the recipient detect replayed, missing or reordered messages. A zero
/// `seq` means the sender does not number messages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sequence {
    pub epoch: u64,
    pub seq: u64,
}

/// The v1 body: the message itself.
#[derive(Serialize, Deserialize)]
struct PlainBody {
    sent_at_ms: u64,
    #[serde(default)]
    epoch: u64,
    #[serde(default)]
    seq: u64,
    content: Content,
    /// What the sending client understands beyond text; see [`capability`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    caps: Vec<String>,
}

/// The v2 body: a plain body encrypted again under a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetBody {
    /// Always 2; absent from v1 bodies.
    pub v: u32,
    #[serde(with = "b64_array")]
    pub session: SessionId,
    /// Present until the initiator hears back from the responder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<InitHeader>,
    pub message: RatchetMessage,
}

/// Everything the sealed layer can carry.
pub enum Body {
    Plain {
        sent_at_ms: u64,
        sequence: Sequence,
        content: Content,
        caps: Vec<String>,
    },
    Ratchet(RatchetBody),
}

/// Peek at the version before choosing how to parse.
#[derive(Deserialize)]
struct Version {
    #[serde(default)]
    v: u32,
}

impl Body {
    pub fn plain(content: Content, sent_at_ms: u64, sequence: Sequence) -> Self {
        Self::plain_with_caps(content, sent_at_ms, sequence, &[])
    }

    /// A plain body that also advertises capabilities.
    pub fn plain_with_caps(
        content: Content,
        sent_at_ms: u64,
        sequence: Sequence,
        caps: &[&str],
    ) -> Self {
        Self::Plain {
            sent_at_ms,
            sequence,
            content,
            caps: caps.iter().map(|c| (*c).to_owned()).collect(),
        }
    }

    /// The body as bytes, padded to a multiple of [`PAD_BLOCK`].
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut bytes = match self {
            Self::Plain {
                sent_at_ms,
                sequence,
                content,
                caps,
            } => serde_json::to_vec(&PlainBody {
                sent_at_ms: *sent_at_ms,
                epoch: sequence.epoch,
                seq: sequence.seq,
                content: content.clone(),
                caps: caps.clone(),
            }),
            Self::Ratchet(body) => serde_json::to_vec(body),
        }
        .map_err(|e| ProtocolError::Malformed(e.to_string()))?;
        pad(&mut bytes);
        if bytes.len() > MAX_BODY_BYTES {
            return Err(ProtocolError::TooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let malformed = |e: serde_json::Error| ProtocolError::Malformed(e.to_string());
        let version: Version = serde_json::from_slice(bytes).map_err(malformed)?;
        match version.v {
            0 | 1 => {
                let body: PlainBody = serde_json::from_slice(bytes).map_err(malformed)?;
                Ok(Self::Plain {
                    sent_at_ms: body.sent_at_ms,
                    sequence: Sequence {
                        epoch: body.epoch,
                        seq: body.seq,
                    },
                    content: body.content,
                    caps: body.caps,
                })
            }
            2 => Ok(Self::Ratchet(
                serde_json::from_slice(bytes).map_err(malformed)?,
            )),
            other => Err(ProtocolError::Malformed(format!(
                "unsupported body version {other}"
            ))),
        }
    }
}

/// A decrypted and authenticated message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub id: String,
    pub from: UserId,
    pub to: UserId,
    pub sent_at_ms: u64,
    pub sequence: Sequence,
    pub content: Content,
    /// Encrypted under a forward-secret session (protocol v2) rather than
    /// only the recipient's long-term key.
    pub forward_secret: bool,
    /// Capabilities the sender advertised; see [`capability`].
    pub caps: Vec<String>,
}

/// The sealed layer of an envelope, opened: who sent it and the raw body.
pub struct Opened {
    pub id: String,
    pub from: UserId,
    pub to: UserId,
    pub body: Zeroizing<Vec<u8>>,
}

/// Encrypt and sign `content` from `sender` to `recipient`, without a
/// sequence number. Prefer [`seal_with`].
pub fn seal(
    sender: &Identity,
    recipient: &KeyBundle,
    content: Content,
    sent_at_ms: u64,
) -> Result<Envelope, ProtocolError> {
    seal_with(sender, recipient, content, sent_at_ms, Sequence::default())
}

/// Encrypt and sign `content` from `sender` to `recipient` as a v1 body,
/// numbered with `sequence` so the recipient can spot replays and gaps.
pub fn seal_with(
    sender: &Identity,
    recipient: &KeyBundle,
    content: Content,
    sent_at_ms: u64,
    sequence: Sequence,
) -> Result<Envelope, ProtocolError> {
    let body = Body::plain(content, sent_at_ms, sequence).encode()?;
    seal_bytes(sender, recipient, &body)
}

/// Seal an already encoded [`Body`] for `recipient`.
pub fn seal_bytes(
    sender: &Identity,
    recipient: &KeyBundle,
    body: &[u8],
) -> Result<Envelope, ProtocolError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(ProtocolError::TooLarge(body.len()));
    }

    let ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&recipient.dh_public.as_x25519());
    if !shared.was_contributory() {
        return Err(ProtocolError::WeakKey);
    }
    let key = derive_key(shared.as_bytes(), &ephemeral_public, &recipient.dh_public.0);

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let signature = sender.sign(
        ENVELOPE_DOMAIN,
        &signed_bytes(&recipient.user_id, &ephemeral_public, &nonce, body),
    );

    let mut plaintext = Zeroizing::new(Vec::with_capacity(96 + body.len()));
    plaintext.extend_from_slice(sender.user_id().as_bytes());
    plaintext.extend_from_slice(&signature);
    plaintext.extend_from_slice(body);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad(&recipient.user_id, &ephemeral_public),
            },
        )
        .map_err(|_| ProtocolError::Malformed("encryption failed".into()))?;

    Ok(Envelope {
        id: uuid::Uuid::new_v4().to_string(),
        to: recipient.user_id,
        ephemeral_public: DhPublic(ephemeral_public),
        nonce,
        ciphertext,
    })
}

/// Decrypt a v1 envelope addressed to `recipient` and verify the sender's
/// signature. Fails on a v2 body; use [`open_bytes`] and [`Body::decode`]
/// to handle both.
pub fn open(recipient: &Identity, envelope: &Envelope) -> Result<Message, ProtocolError> {
    let opened = open_bytes(recipient, envelope)?;
    match Body::decode(&opened.body)? {
        Body::Plain {
            sent_at_ms,
            sequence,
            content,
            caps,
        } => Ok(Message {
            id: opened.id,
            from: opened.from,
            to: opened.to,
            sent_at_ms,
            sequence,
            content,
            forward_secret: false,
            caps,
        }),
        Body::Ratchet(_) => Err(ProtocolError::Malformed(
            "body is encrypted under a session".into(),
        )),
    }
}

/// Open the sealed layer: verify we are the recipient, decrypt, and check
/// the sender's signature. The body is returned undecoded.
pub fn open_bytes(recipient: &Identity, envelope: &Envelope) -> Result<Opened, ProtocolError> {
    if envelope.to != recipient.user_id() {
        return Err(ProtocolError::WrongRecipient);
    }
    if envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(ProtocolError::TooLarge(envelope.ciphertext.len()));
    }

    let shared = recipient
        .dh_secret()
        .diffie_hellman(&envelope.ephemeral_public.as_x25519());
    if !shared.was_contributory() {
        return Err(ProtocolError::WeakKey);
    }
    let key = derive_key(
        shared.as_bytes(),
        &envelope.ephemeral_public.0,
        &recipient.dh_public().0,
    );

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad(&envelope.to, &envelope.ephemeral_public.0),
                },
            )
            .map_err(|_| ProtocolError::DecryptFailed)?,
    );

    if plaintext.len() < 96 {
        return Err(ProtocolError::Malformed("plaintext too short".into()));
    }
    let from_bytes: [u8; 32] = plaintext[..32].try_into().expect("length checked");
    let from = UserId::from_bytes(from_bytes)?;
    let signature: [u8; 64] = plaintext[32..96].try_into().expect("length checked");
    let body = &plaintext[96..];

    from.verify(
        ENVELOPE_DOMAIN,
        &signed_bytes(
            &envelope.to,
            &envelope.ephemeral_public.0,
            &envelope.nonce,
            body,
        ),
        &signature,
    )?;

    Ok(Opened {
        id: envelope.id.clone(),
        from,
        to: envelope.to,
        body: Zeroizing::new(body.to_vec()),
    })
}

fn derive_key(
    shared: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_dh: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut info = Vec::with_capacity(KDF_INFO.len() + 64);
    info.extend_from_slice(KDF_INFO);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_dh);
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(&info, key.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn aad(to: &UserId, ephemeral_public: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(to.as_bytes());
    v.extend_from_slice(ephemeral_public);
    v
}

fn signed_bytes(
    to: &UserId,
    ephemeral_public: &[u8; 32],
    nonce: &[u8; 24],
    body: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + 32 + 24 + body.len());
    v.extend_from_slice(to.as_bytes());
    v.extend_from_slice(ephemeral_public);
    v.extend_from_slice(nonce);
    v.extend_from_slice(body);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prekey::{PrekeySecret, Prekeys};
    use crate::session::Session;

    fn text(s: &str) -> Content {
        Content::Text { body: s.into() }
    }

    #[test]
    fn sequence_travels_inside_the_body() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let sequence = Sequence { epoch: 42, seq: 7 };
        let env = seal_with(&alice, &bob.key_bundle(), text("x"), 0, sequence).unwrap();
        assert_eq!(open(&bob, &env).unwrap().sequence, sequence);
        // The relay-visible bytes do not reveal it.
        assert!(!serde_json::to_string(&env).unwrap().contains("\"seq\""));
        // Unnumbered senders read as sequence zero.
        let legacy = seal(&alice, &bob.key_bundle(), text("x"), 0).unwrap();
        assert_eq!(open(&bob, &legacy).unwrap().sequence, Sequence::default());
    }

    #[test]
    fn seal_then_open_round_trips() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let env = seal(&alice, &bob.key_bundle(), text("hello bob"), 1234).unwrap();
        let msg = open(&bob, &env).unwrap();
        assert_eq!(msg.from, alice.user_id());
        assert_eq!(msg.to, bob.user_id());
        assert_eq!(msg.sent_at_ms, 1234);
        assert_eq!(msg.content, text("hello bob"));
        assert_eq!(msg.id, env.id);
        assert!(!msg.forward_secret);
    }

    #[test]
    fn relay_visible_bytes_contain_no_plaintext_or_sender() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let env = seal(&alice, &bob.key_bundle(), text("secret words"), 0).unwrap();
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("secret words"));
        assert!(!json.contains(&alice.user_id().to_string()));
        assert!(json.contains(&bob.user_id().to_string()));
        let back: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn only_the_recipient_can_open() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let eve = Identity::generate();
        let env = seal(&alice, &bob.key_bundle(), text("x"), 0).unwrap();
        assert_eq!(open(&eve, &env), Err(ProtocolError::WrongRecipient));
        assert_eq!(open(&alice, &env), Err(ProtocolError::WrongRecipient));
    }

    #[test]
    fn tampering_is_detected() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let env = seal(&alice, &bob.key_bundle(), text("x"), 0).unwrap();

        let mut flipped = env.clone();
        let last = flipped.ciphertext.len() - 1;
        flipped.ciphertext[last] ^= 1;
        assert_eq!(open(&bob, &flipped), Err(ProtocolError::DecryptFailed));

        let mut nonce = env.clone();
        nonce.nonce[0] ^= 1;
        assert_eq!(open(&bob, &nonce), Err(ProtocolError::DecryptFailed));

        let mut eph = env.clone();
        eph.ephemeral_public = Identity::generate().dh_public();
        assert_eq!(open(&bob, &eph), Err(ProtocolError::DecryptFailed));
    }

    #[test]
    fn envelope_cannot_be_readdressed() {
        // Even a recipient who knows the key cannot re-address an envelope to
        // someone else: the AAD and the signature both bind `to`.
        let alice = Identity::generate();
        let bob = Identity::generate();
        let carol = Identity::generate();
        let mut env = seal(&alice, &bob.key_bundle(), text("x"), 0).unwrap();
        env.to = carol.user_id();
        assert_eq!(open(&carol, &env), Err(ProtocolError::DecryptFailed));
    }

    #[test]
    fn oversized_body_is_rejected() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let big = "a".repeat(MAX_BODY_BYTES + 1);
        assert!(matches!(
            seal(&alice, &bob.key_bundle(), text(&big), 0),
            Err(ProtocolError::TooLarge(_))
        ));
    }

    #[test]
    fn plain_body_encoding_is_v1_json_padded_with_spaces() {
        let bytes = Body::plain(text("hi"), 5, Sequence { epoch: 1, seq: 2 })
            .encode()
            .unwrap();
        let json = String::from_utf8(bytes.clone()).unwrap();
        assert_eq!(
            json.trim_end(),
            r#"{"sent_at_ms":5,"epoch":1,"seq":2,"content":{"type":"text","body":"hi"}}"#
        );
        assert_eq!(bytes.len(), PAD_BLOCK);
        assert!(matches!(Body::decode(&bytes), Ok(Body::Plain { .. })));
        // Unpadded bodies (from clients before 0.6.0) still decode.
        assert!(matches!(
            Body::decode(json.trim_end().as_bytes()),
            Ok(Body::Plain { .. })
        ));
        assert!(Body::decode(br#"{"v":9}"#).is_err());
        assert!(Body::decode(b"nonsense").is_err());
    }

    #[test]
    fn bodies_come_in_size_steps() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let size = |s: &str| {
            seal(&alice, &bob.key_bundle(), text(s), 0)
                .unwrap()
                .ciphertext
                .len()
        };
        // A short and a somewhat longer message are the same size on the
        // wire; a receipt too.
        assert_eq!(size("hi"), size("see you at eight, bring the papers"));
        let receipt = seal(
            &alice,
            &bob.key_bundle(),
            Content::Receipt {
                kind: ReceiptKind::Read,
                ids: vec!["0".repeat(36)],
            },
            0,
        )
        .unwrap();
        assert_eq!(receipt.ciphertext.len(), size("hi"));
        // Every body is a whole number of blocks, plus the envelope's fixed
        // overhead (sender id, signature, tag).
        for n in [1, 100, 200, 1000] {
            let len = size(&"x".repeat(n));
            assert_eq!((len - 96 - 16) % PAD_BLOCK, 0, "{n} chars gave {len} bytes");
        }
        assert!(size(&"x".repeat(1000)) > size("hi"));
    }

    #[test]
    fn ratchet_bodies_ride_inside_the_sealed_layer() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let signed = PrekeySecret::generate(1, 0);
        let bob_bundle =
            bob.key_bundle_with(Prekeys::classical(signed.signed_by(&bob), Vec::new()));
        let (mut alice_session, init) = Session::initiate(&alice, &bob_bundle).unwrap();
        let inner = Body::plain(text("ratcheted"), 9, Sequence { epoch: 3, seq: 1 })
            .encode()
            .unwrap();
        let message = alice_session.encrypt(&inner).unwrap();
        let body = Body::Ratchet(RatchetBody {
            v: 2,
            session: *alice_session.id(),
            init: Some(init.clone()),
            message,
        });
        let env = seal_bytes(&alice, &bob_bundle, &body.encode().unwrap()).unwrap();

        // The v1 opener refuses it; the raw opener hands the body over.
        assert!(open(&bob, &env).is_err());
        let opened = open_bytes(&bob, &env).unwrap();
        assert_eq!(opened.from, alice.user_id());
        let Body::Ratchet(ratchet) = Body::decode(&opened.body).unwrap() else {
            panic!("expected a ratchet body");
        };
        assert_eq!(ratchet.init, Some(init.clone()));
        let mut bob_session =
            Session::respond(&bob, &alice.user_id(), &signed, None, None, &init).unwrap();
        let plain = bob_session.decrypt(&ratchet.message).unwrap();
        let Body::Plain {
            content, sequence, ..
        } = Body::decode(&plain).unwrap()
        else {
            panic!("expected a plain body inside");
        };
        assert_eq!(content, text("ratcheted"));
        assert_eq!(sequence.seq, 1);
    }
}
