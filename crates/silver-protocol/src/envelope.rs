//! Sealing and opening end-to-end encrypted envelopes.

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
use crate::bundle::KeyBundle;
use crate::encoding::{b64, b64_array};
use crate::identity::{DhPublic, Identity, UserId};

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
    Text { body: String },
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

/// The encrypted, signed body of an envelope.
#[derive(Serialize, Deserialize)]
struct Body {
    sent_at_ms: u64,
    #[serde(default)]
    epoch: u64,
    #[serde(default)]
    seq: u64,
    content: Content,
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

/// Encrypt and sign `content` from `sender` to `recipient`, numbered with
/// `sequence` so the recipient can spot replays and gaps.
pub fn seal_with(
    sender: &Identity,
    recipient: &KeyBundle,
    content: Content,
    sent_at_ms: u64,
    sequence: Sequence,
) -> Result<Envelope, ProtocolError> {
    let body = serde_json::to_vec(&Body {
        sent_at_ms,
        epoch: sequence.epoch,
        seq: sequence.seq,
        content,
    })
    .map_err(|e| ProtocolError::Malformed(e.to_string()))?;
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
        &signed_bytes(&recipient.user_id, &ephemeral_public, &nonce, &body),
    );

    let mut plaintext = Zeroizing::new(Vec::with_capacity(96 + body.len()));
    plaintext.extend_from_slice(sender.user_id().as_bytes());
    plaintext.extend_from_slice(&signature);
    plaintext.extend_from_slice(&body);

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

/// Decrypt an envelope addressed to `recipient` and verify the sender's
/// signature. Succeeds only if the envelope is intact, addressed to us, and
/// really signed by the identity it claims to come from.
pub fn open(recipient: &Identity, envelope: &Envelope) -> Result<Message, ProtocolError> {
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

    let body: Body =
        serde_json::from_slice(body).map_err(|e| ProtocolError::Malformed(e.to_string()))?;

    Ok(Message {
        id: envelope.id.clone(),
        from,
        to: envelope.to,
        sent_at_ms: body.sent_at_ms,
        sequence: Sequence {
            epoch: body.epoch,
            seq: body.seq,
        },
        content: body.content,
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
}
