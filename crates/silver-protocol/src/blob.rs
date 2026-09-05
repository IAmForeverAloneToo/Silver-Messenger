//! Encrypted file chunks ("blobs") parked on a relay for the recipient to
//! fetch.
//!
//! A file is encrypted on the sender's machine under a random key, chunk by
//! chunk, and the chunks are uploaded under a random blob id. The key, the
//! id and the file's hash travel to the recipient inside an ordinary
//! end-to-end encrypted message ([`Content::File`](crate::Content)), so the
//! relay stores bytes it cannot read for a recipient it cannot name.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ProtocolError;
use crate::encoding::b64_array;

/// Plaintext bytes per chunk.
pub const CHUNK_BYTES: usize = 64 * 1024;
/// Largest ciphertext chunk a relay or client accepts.
pub const MAX_CHUNK_CIPHERTEXT: usize = CHUNK_BYTES + 16;
/// Largest file a client will send or fetch.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// Chunks in the largest file.
pub const MAX_CHUNKS: u32 = (MAX_FILE_BYTES / CHUNK_BYTES as u64) as u32;
const CHUNK_DOMAIN: &[u8] = b"silver-messenger/v1/blob-chunk";

/// The key one file is encrypted under; travels inside the message.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct BlobKey {
    #[serde(with = "b64_array")]
    key: [u8; 32],
    #[serde(with = "b64_array")]
    nonce: [u8; 24],
}

impl BlobKey {
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);
        Self { key, nonce }
    }

    /// A key from fixed parts, for reproducible test vectors.
    pub fn from_parts(key: [u8; 32], nonce: [u8; 24]) -> Self {
        Self { key, nonce }
    }

    /// The chunk's nonce: the file nonce with the index folded into its
    /// last four bytes.
    fn chunk_nonce(&self, index: u32) -> [u8; 24] {
        let mut nonce = self.nonce;
        for (n, b) in nonce[20..].iter_mut().zip(index.to_be_bytes()) {
            *n ^= b;
        }
        nonce
    }
}

impl std::fmt::Debug for BlobKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlobKey(..)")
    }
}

/// A fresh random blob id: 32 hex characters.
pub fn new_blob_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What a relay accepts as a blob id.
pub fn is_valid_blob_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// How many chunks a file of `size` bytes takes (at least one).
pub fn chunk_count(size: u64) -> u32 {
    size.div_ceil(CHUNK_BYTES as u64).max(1) as u32
}

fn aad(blob: &str, index: u32, total: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(CHUNK_DOMAIN.len() + blob.len() + 8);
    v.extend_from_slice(CHUNK_DOMAIN);
    v.extend_from_slice(blob.as_bytes());
    v.extend_from_slice(&index.to_be_bytes());
    v.extend_from_slice(&total.to_be_bytes());
    v
}

/// Encrypt chunk `index` of `total` for blob `blob`.
pub fn seal_chunk(
    key: &BlobKey,
    blob: &str,
    index: u32,
    total: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if plaintext.len() > CHUNK_BYTES {
        return Err(ProtocolError::TooLarge(plaintext.len()));
    }
    XChaCha20Poly1305::new(Key::from_slice(&key.key))
        .encrypt(
            XNonce::from_slice(&key.chunk_nonce(index)),
            Payload {
                msg: plaintext,
                aad: &aad(blob, index, total),
            },
        )
        .map_err(|_| ProtocolError::Malformed("encryption failed".into()))
}

/// Decrypt and authenticate chunk `index` of `total` of blob `blob`.
pub fn open_chunk(
    key: &BlobKey,
    blob: &str,
    index: u32,
    total: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if ciphertext.len() > MAX_CHUNK_CIPHERTEXT {
        return Err(ProtocolError::TooLarge(ciphertext.len()));
    }
    XChaCha20Poly1305::new(Key::from_slice(&key.key))
        .decrypt(
            XNonce::from_slice(&key.chunk_nonce(index)),
            Payload {
                msg: ciphertext,
                aad: &aad(blob, index, total),
            },
        )
        .map_err(|_| ProtocolError::DecryptFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_round_trip_and_are_bound_to_their_place() {
        let key = BlobKey::generate();
        let blob = new_blob_id();
        assert!(is_valid_blob_id(&blob));
        assert!(!is_valid_blob_id("../etc/passwd"));
        let c0 = seal_chunk(&key, &blob, 0, 2, b"first").unwrap();
        let c1 = seal_chunk(&key, &blob, 1, 2, b"second").unwrap();
        assert_eq!(open_chunk(&key, &blob, 0, 2, &c0).unwrap(), b"first");
        assert_eq!(open_chunk(&key, &blob, 1, 2, &c1).unwrap(), b"second");
        // Swapped, re-counted, or moved to another blob: refused.
        assert!(open_chunk(&key, &blob, 1, 2, &c0).is_err());
        assert!(open_chunk(&key, &blob, 0, 3, &c0).is_err());
        assert!(open_chunk(&key, &new_blob_id(), 0, 2, &c0).is_err());
        assert!(open_chunk(&BlobKey::generate(), &blob, 0, 2, &c0).is_err());
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(serde_json::from_str::<BlobKey>(&json).unwrap(), key);
    }

    #[test]
    fn chunk_counts() {
        assert_eq!(chunk_count(0), 1);
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK_BYTES as u64), 1);
        assert_eq!(chunk_count(CHUNK_BYTES as u64 + 1), 2);
        assert_eq!(chunk_count(MAX_FILE_BYTES), MAX_CHUNKS);
        assert!(seal_chunk(&BlobKey::generate(), "x", 0, 1, &vec![0; CHUNK_BYTES + 1]).is_err());
    }
}
