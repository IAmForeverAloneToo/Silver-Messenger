#![forbid(unsafe_code)]
//! Shared types and end-to-end cryptography for Silver Messenger.
//!
//! Everything a relay is allowed to see lives in [`wire`] and [`Envelope`].
//! Everything a relay must never see is produced and consumed only by the
//! sealing functions and [`session::Session`], which run on the two
//! endpoints. The full wire format is written up in `docs/PROTOCOL.md`.
//!
//! ## Cryptographic design
//!
//! * **Identity** – an Ed25519 signing key (its public half *is* the
//!   [`UserId`]) plus a long-term X25519 key for Diffie–Hellman.
//! * **Key bundle** – the X25519 public key, signed by the identity key, so a
//!   relay can hand it out without being able to forge it. Clients that speak
//!   protocol v2 add [`prekey::Prekeys`]: a signed medium-term key and a batch
//!   of one-time keys.
//! * **Envelope** (the sealed-sender layer, v1) – per message the sender
//!   generates a fresh X25519 ephemeral key, derives a key with HKDF-SHA256
//!   from `DH(ephemeral, recipient)`, and encrypts `from || signature || body`
//!   with XChaCha20-Poly1305. The signature covers the recipient, the
//!   ephemeral key, the nonce and the body, so an envelope cannot be
//!   re-addressed or replayed to someone else. The sender's identity travels
//!   *inside* the ciphertext, so the envelope names only the recipient.
//! * **Sessions** (v2) – when the recipient has published prekeys, the body
//!   is not the message but a [`session::RatchetMessage`]: an X3DH handshake
//!   against those prekeys establishes a [`session::Session`], and a Double
//!   Ratchet encrypts every message under a key that is used once and then
//!   discarded. That gives forward secrecy and healing after a compromise for
//!   everything after the handshake; the sealed layer above it keeps the
//!   sender hidden from the relay. A recipient without prekeys is sent a v1
//!   body instead, so old and new clients interoperate.
//! * **Post-quantum handshake** (v3) – a recipient that also publishes
//!   [`pq::SignedPqPrekey`]s (ML-KEM-768) gets a hybrid handshake: the
//!   initiator encapsulates a secret to one of them and mixes it into the
//!   session key next to the Diffie–Hellman outputs, so a recording of the
//!   traffic stays closed even to a quantum computer that breaks X25519.
//!
//! What is deliberately not provided: deniability (messages are signed)
//! and cover traffic.

pub mod blob;
pub mod bundle;
pub mod encoding;
pub mod envelope;
mod error;
pub mod identity;
pub mod pq;
pub mod prekey;
pub mod session;
pub mod verify;
pub mod wire;

pub use blob::BlobKey;
pub use bundle::KeyBundle;
pub use envelope::{
    Body, Content, Envelope, MAX_BODY_BYTES, MAX_CIPHERTEXT_BYTES, Message, Opened, RatchetBody,
    Sequence, open, open_bytes, seal, seal_bytes, seal_with,
};
pub use error::ProtocolError;
pub use identity::{DhPublic, Identity, IdentitySecrets, UserId};
pub use pq::{KemPublic, PqPrekeySecret, SignedPqPrekey};
pub use prekey::{OneTimePrekey, PrekeySecret, Prekeys, SignedPrekey};
pub use session::{InitHeader, RatchetHeader, RatchetMessage, Session, SessionId};
pub use verify::safety_number;
pub use wire::{ClientFrame, ErrorCode, ServerFrame};

/// Milliseconds since the Unix epoch, used for `sent_at_ms` timestamps.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
