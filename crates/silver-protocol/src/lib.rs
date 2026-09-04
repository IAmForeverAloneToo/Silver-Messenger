//! Shared types and end-to-end cryptography for Silver Messenger.
//!
//! Everything a relay is allowed to see lives in [`wire`] and [`Envelope`].
//! Everything a relay must never see is produced and consumed only by
//! [`seal`] / [`open`], which run on the two endpoints.
//!
//! ## Cryptographic design (v1)
//!
//! * **Identity** – an Ed25519 signing key (its public half *is* the
//!   [`UserId`]) plus a long-term X25519 key for Diffie–Hellman.
//! * **Key bundle** – the X25519 public key, signed by the identity key, so a
//!   relay can hand it out without being able to forge it.
//! * **Envelope** – per message the sender generates a fresh X25519 ephemeral
//!   key, derives a key with HKDF-SHA256 from `DH(ephemeral, recipient)`, and
//!   encrypts `from || signature || body` with XChaCha20-Poly1305. The
//!   signature covers the recipient, the ephemeral key, the nonce and the body,
//!   so an envelope cannot be re-addressed or replayed to someone else.
//!   The sender's identity travels *inside* the ciphertext ("sealed sender"),
//!   so the envelope names only the recipient. (The relay can still see which
//!   authenticated connection submitted it; see docs/THREAT_MODEL.md.)
//!
//! What v1 deliberately does not provide yet: forward secrecy against
//! compromise of the recipient's long-term key (needs a ratchet), and
//! deniability (messages are signed). Both are tracked in the project README.

pub mod bundle;
pub mod encoding;
pub mod envelope;
mod error;
pub mod identity;
pub mod wire;

pub use bundle::KeyBundle;
pub use envelope::{
    Content, Envelope, MAX_BODY_BYTES, MAX_CIPHERTEXT_BYTES, Message, Sequence, open, seal,
    seal_with,
};
pub use error::ProtocolError;
pub use identity::{DhPublic, Identity, IdentitySecrets, UserId};
pub use wire::{ClientFrame, ErrorCode, ServerFrame};

/// Milliseconds since the Unix epoch, used for `sent_at_ms` timestamps.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
