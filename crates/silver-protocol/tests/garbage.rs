//! Everything that parses bytes from the network, fed bytes nobody meant:
//! random ones, and real structures with bytes flipped. Nothing may panic,
//! and a damaged message may not disturb a session. The same checks run
//! for much longer under libfuzzer (`fuzz/`); this keeps them on stable.

use silver_protocol::blob::{BlobKey, chunk_count, is_valid_blob_id, open_chunk, seal_chunk};
use silver_protocol::envelope::{Envelope, open, seal};
use silver_protocol::identity::IdentitySecrets;
use silver_protocol::prekey::{PrekeySecret, Prekeys};
use silver_protocol::session::{RatchetMessage, Session};
use silver_protocol::wire::{ClientFrame, ServerFrame};
use silver_protocol::{Content, Identity};

/// A small deterministic generator, so a failure can be replayed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = (self.next() % (max as u64 + 1)) as usize;
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn damage(&mut self, bytes: &mut [u8]) {
        if bytes.is_empty() {
            return;
        }
        let flips = 1 + self.next() % 4;
        for _ in 0..flips {
            let at = (self.next() as usize) % bytes.len();
            bytes[at] ^= 1 << (self.next() % 8);
        }
    }
}

fn identity(seed: u8) -> Identity {
    Identity::from_secrets(&IdentitySecrets {
        signing_seed: [seed; 32],
        dh_secret: [seed.wrapping_add(100); 32],
    })
}

#[test]
fn random_bytes_never_panic() {
    let me = identity(1);
    let key = BlobKey::generate();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..3000 {
        let data = rng.bytes(300);
        if let Ok(text) = std::str::from_utf8(&data) {
            let _ = ClientFrame::decode(text);
            let _ = ServerFrame::decode(text);
        }
        if let Ok(envelope) = serde_json::from_slice::<Envelope>(&data) {
            let _ = open(&me, &envelope);
        }
        let index = data.first().copied().unwrap_or(0) as u32;
        let _ = open_chunk(&key, "blob", index, 3, &data);
        let _ = is_valid_blob_id(&String::from_utf8_lossy(&data));
        let _ = chunk_count(rng.next());
    }
}

#[test]
fn damaged_envelopes_and_chunks_are_refused_without_panicking() {
    let alice = identity(1);
    let bob = identity(2);
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    let sealed = seal(
        &alice,
        &bob.key_bundle(),
        Content::Text {
            body: "hello".into(),
        },
        1_700_000_000_000,
    )
    .unwrap();
    let bytes = serde_json::to_vec(&sealed).unwrap();
    assert!(open(&bob, &serde_json::from_slice::<Envelope>(&bytes).unwrap()).is_ok());
    let key = BlobKey::generate();
    let chunk = seal_chunk(&key, "blob", 0, 1, b"some file bytes").unwrap();
    assert!(open_chunk(&key, "blob", 0, 1, &chunk).is_ok());
    let mut opened = 0;
    for _ in 0..2000 {
        let mut damaged = bytes.clone();
        rng.damage(&mut damaged);
        if let Ok(envelope) = serde_json::from_slice::<Envelope>(&damaged) {
            // Flips inside base64 padding or JSON whitespace can leave the
            // envelope intact; any that decode must still authenticate.
            if let Ok(message) = open(&bob, &envelope) {
                assert_eq!(message.from, alice.user_id());
                opened += 1;
            }
        }
        let mut damaged = chunk.clone();
        rng.damage(&mut damaged);
        if let Ok(plain) = open_chunk(&key, "blob", 0, 1, &damaged) {
            assert_eq!(plain, b"some file bytes");
        }
    }
    assert!(opened < 2000, "damage never had an effect");
}

#[test]
fn damaged_ratchet_messages_do_not_disturb_the_session() {
    let alice = identity(3);
    let bob = identity(4);
    let signed = PrekeySecret::generate(1, 0);
    let bundle = bob.key_bundle_with(Prekeys {
        signed: signed.signed_by(&bob),
        one_time: Vec::new(),
    });
    let (mut alice_session, init) = Session::initiate(&alice, &bundle).unwrap();
    let mut bob_session = Session::respond(&bob, &alice.user_id(), &signed, None, &init).unwrap();
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for round in 0..300u32 {
        let text = format!("message {round}");
        let real = alice_session.encrypt(text.as_bytes()).unwrap();
        let mut json = serde_json::to_vec(&real).unwrap();
        rng.damage(&mut json);
        if let Ok(message) = serde_json::from_slice::<RatchetMessage>(&json) {
            let _ = bob_session.decrypt(&message);
        }
        let garbage = rng.bytes(200);
        if let Ok(message) = serde_json::from_slice::<RatchetMessage>(&garbage) {
            let _ = bob_session.decrypt(&message);
        }
        assert_eq!(
            bob_session.decrypt(&real).unwrap().as_slice(),
            text.as_bytes(),
            "round {round}: the real message no longer decrypts"
        );
    }
}
