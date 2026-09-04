//! Ratchet messages as a session decrypts them: bytes that were never a
//! message, and real messages with bytes flipped.

#![no_main]

use libfuzzer_sys::fuzz_target;
use silver_protocol::Identity;
use silver_protocol::identity::IdentitySecrets;
use silver_protocol::prekey::{PrekeySecret, Prekeys};
use silver_protocol::session::{RatchetMessage, Session};

/// The handshake is done once; every run starts from a copy of it.
fn sessions() -> &'static (Session, Session) {
    static SESSIONS: std::sync::OnceLock<(Session, Session)> = std::sync::OnceLock::new();
    SESSIONS.get_or_init(|| {
        let alice = Identity::from_secrets(&IdentitySecrets {
            signing_seed: [1; 32],
            dh_secret: [2; 32],
        });
        let bob = Identity::from_secrets(&IdentitySecrets {
            signing_seed: [3; 32],
            dh_secret: [4; 32],
        });
        let signed = PrekeySecret::generate(1, 0);
        let bundle = bob.key_bundle_with(Prekeys::classical(signed.signed_by(&bob), Vec::new()));
        let (alice_session, init) = Session::initiate(&alice, &bundle).unwrap();
        let bob_session =
            Session::respond(&bob, &alice.user_id(), &signed, None, None, &init).unwrap();
        (alice_session, bob_session)
    })
}

fuzz_target!(|data: &[u8]| {
    let (mut alice_session, mut bob_session) = sessions().clone();

    // Bytes that claim to be a message.
    if let Ok(message) = serde_json::from_slice::<RatchetMessage>(data) {
        let _ = bob_session.decrypt(&message);
    }
    // A real message, damaged where the input says.
    let real = alice_session.encrypt(b"hello bob").unwrap();
    let mut json = serde_json::to_vec(&real).unwrap();
    for (i, byte) in data.iter().enumerate().take(8) {
        let at = (*byte as usize + i * 31) % json.len();
        json[at] ^= data.get(i + 8).copied().unwrap_or(1);
    }
    // Damage that only touched JSON formatting leaves the message intact,
    // and then it is consumed here; otherwise the real one must still
    // decrypt afterwards: a bad message must not disturb the session.
    let consumed = serde_json::from_slice::<RatchetMessage>(&json)
        .ok()
        .is_some_and(|message| bob_session.decrypt(&message).is_ok());
    if !consumed {
        assert_eq!(bob_session.decrypt(&real).unwrap().as_slice(), b"hello bob");
    }
});
