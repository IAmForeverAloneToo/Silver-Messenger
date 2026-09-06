//! ML-KEM decapsulation on crafted ciphertexts, on both keys that hold
//! one: a prekey and a ratchet key.
//!
//! The ML-KEM implementation the project depends on says of itself that it
//! has never been independently audited, and the hybrid design means a
//! flaw in it cannot take a session below its classical strength. What it
//! could still do is panic on a ciphertext someone chose, which would take
//! a client or a relay down; decapsulation is reachable from the wire on
//! every handshake and every post-quantum ratchet step. So it is fuzzed:
//! a ciphertext of any length, and a real one with bytes flipped.
//!
//! Nothing here asserts a secret: ML-KEM rejects a forged ciphertext
//! implicitly, by returning a secret the sender does not share, and that
//! is the design. What is asserted is that the call returns.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_protocol::pq::{KEM_CIPHERTEXT_LEN, KemRatchetKey, PqPrekeySecret};

/// The keys are made once; every run decapsulates against them.
fn keys() -> &'static (PqPrekeySecret, KemRatchetKey) {
    static KEYS: std::sync::OnceLock<(PqPrekeySecret, KemRatchetKey)> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| (PqPrekeySecret::generate(1, 0), KemRatchetKey::generate()))
}

fuzz_target!(|data: &[u8]| {
    let (prekey, ratchet) = keys();

    // Whatever the input is, taken as a ciphertext. Most lengths are
    // refused; the right length is decapsulated and yields some secret.
    let _ = prekey.decapsulate(data);
    let _ = ratchet.decapsulate(data);

    // A real ciphertext with bytes flipped where the input says: the
    // interesting shape, since it parses and reaches the arithmetic.
    let (mut ciphertext, _) = prekey.public().encapsulate().unwrap();
    assert_eq!(ciphertext.len(), KEM_CIPHERTEXT_LEN);
    for (i, byte) in data.iter().enumerate().take(8) {
        let at = (*byte as usize + i * 31) % ciphertext.len();
        ciphertext[at] ^= data.get(i + 8).copied().unwrap_or(1);
    }
    let _ = prekey.decapsulate(&ciphertext);
});
