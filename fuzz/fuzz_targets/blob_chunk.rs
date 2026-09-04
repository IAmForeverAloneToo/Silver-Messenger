//! Encrypted file chunks as a recipient opens them: the first bytes pick
//! the chunk's position, the rest is the ciphertext.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_protocol::blob::{BlobKey, chunk_count, is_valid_blob_id, open_chunk};

fuzz_target!(|data: &[u8]| {
    let key = BlobKey::generate();
    let (head, body) = data.split_at(data.len().min(8));
    let index = head.first().copied().unwrap_or(0) as u32;
    let total = head.get(1).copied().unwrap_or(1) as u32;
    let _ = open_chunk(&key, "fuzz", index, total, body);
    let _ = is_valid_blob_id(&String::from_utf8_lossy(head));
    let size = u64::from_le_bytes(head.iter().copied().chain(std::iter::repeat(0)).take(8).collect::<Vec<u8>>().try_into().unwrap());
    let _ = chunk_count(size);
});
