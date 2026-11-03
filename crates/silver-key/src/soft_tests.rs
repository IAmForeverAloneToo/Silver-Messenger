//! The whole path, client to software authenticator and back: CTAPHID
//! framing, the PIN protocols, registering, and the secret.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::soft::{SoftKey, Touch};
use crate::{Error, Key};

const RP: &str = "silver-messenger.local";
const PIN: &str = "4831";
const SEED: [u8; 32] = [0x5a; 32];

fn register(soft: &mut SoftKey) -> Vec<u8> {
    Key::open(soft).unwrap().register(RP, PIN).unwrap()
}

fn secret(
    soft: &mut SoftKey,
    ids: &[Vec<u8>],
    input: &[u8],
    pin: &str,
) -> Result<(usize, [u8; 32]), Error> {
    Key::open(soft)?
        .prf(RP, ids, input, pin)
        .map(|(i, s)| (i, *s))
}

#[test]
fn the_same_input_gives_the_same_secret_and_another_input_another() {
    for make in [SoftKey::new, |s| SoftKey::new(s).ctap_2_0()] {
        let mut soft = make(SEED).with_pin(PIN);
        let id = register(&mut soft);
        let a = secret(&mut soft, std::slice::from_ref(&id), b"salt one", PIN).unwrap();
        let b = secret(&mut soft, std::slice::from_ref(&id), b"salt one", PIN).unwrap();
        let c = secret(&mut soft, std::slice::from_ref(&id), b"salt two", PIN).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.0, 0);
        assert_ne!(a.1, c.1);
        assert_ne!(a.1, [0; 32]);
        // One touch to register, one per secret.
        assert_eq!(soft.touches(), 4);
        // The same key unplugged and plugged back in, or another program
        // on it: the same secret.
        soft.replug();
        assert_eq!(
            secret(&mut soft, std::slice::from_ref(&id), b"salt one", PIN).unwrap(),
            a
        );
        let mut twin = make(SEED).with_pin(PIN);
        assert_eq!(secret(&mut twin, &[id], b"salt one", PIN).unwrap(), a);
    }
}

#[test]
fn the_secret_is_the_one_webauthn_prf_gives() {
    // What the software key computes, HMAC-SHA-256 of the salt under the
    // credential's secret, with the salt as WebAuthn's prf makes it: a
    // key reached through Windows 11's API with prf gives the same.
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let mut soft = SoftKey::new(SEED).with_pin(PIN);
    let id = register(&mut soft);
    let (_, got) = secret(&mut soft, std::slice::from_ref(&id), b"input", PIN).unwrap();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&SEED).unwrap();
    mac.update(b"uv");
    mac.update(&id);
    let cred_random = mac.finalize().into_bytes();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&cred_random).unwrap();
    mac.update(&crate::prf_salt(b"input"));
    assert_eq!(got[..], mac.finalize().into_bytes()[..]);
}

#[test]
fn the_key_answers_for_its_own_credential_among_several() {
    let mut mine = SoftKey::new(SEED).with_pin(PIN);
    let mut other = SoftKey::new([0x11; 32]).with_pin(PIN);
    let theirs = register(&mut other);
    let ours = register(&mut mine);
    let ids = [theirs.clone(), ours.clone()];
    let (index, s) = secret(&mut mine, &ids, b"x", PIN).unwrap();
    assert_eq!(index, 1);
    assert_eq!(s, secret(&mut mine, &[ours], b"x", PIN).unwrap().1);
    let (index, _) = secret(&mut other, &ids, b"x", PIN).unwrap();
    assert_eq!(index, 0);
}

#[test]
fn a_key_that_holds_none_of_them_says_so() {
    let mut a = SoftKey::new(SEED).with_pin(PIN);
    let mut b = SoftKey::new([0x11; 32]).with_pin(PIN);
    let id = register(&mut a);
    assert!(matches!(
        secret(&mut b, &[id], b"x", PIN),
        Err(Error::NoCredentials)
    ));
    // Nor the right key under another relying party.
    let id = register(&mut a);
    let r = Key::open(&mut a)
        .unwrap()
        .prf("example.org", &[id], b"x", PIN);
    assert!(matches!(r, Err(Error::NoCredentials)));
}

#[test]
fn a_wrong_pin_counts_down_and_three_in_a_row_need_a_replug() {
    let mut soft = SoftKey::new(SEED).with_pin(PIN);
    let id = register(&mut soft);
    let ids = [id];
    match secret(&mut soft, &ids, b"x", "0000") {
        Err(Error::PinInvalid { retries: Some(7) }) => {}
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        secret(&mut soft, &ids, b"x", "0000"),
        Err(Error::PinInvalid { retries: Some(6) })
    ));
    assert!(matches!(
        secret(&mut soft, &ids, b"x", "0000"),
        Err(Error::PinAuthBlocked)
    ));
    assert!(matches!(
        secret(&mut soft, &ids, b"x", PIN),
        Err(Error::PinAuthBlocked)
    ));
    soft.replug();
    // The right PIN puts the count back.
    secret(&mut soft, &ids, b"x", PIN).unwrap();
    assert_eq!(soft.retries(), 8);
}

#[test]
fn eight_wrong_pins_block_the_key() {
    let mut soft = SoftKey::new(SEED).with_pin(PIN);
    let ids = [register(&mut soft)];
    let mut last = None;
    for i in 0..8 {
        if i % 3 == 0 {
            soft.replug();
        }
        last = Some(secret(&mut soft, &ids, b"x", "0000"));
    }
    assert!(matches!(last, Some(Err(Error::PinBlocked))));
    assert!(matches!(
        secret(&mut soft, &ids, b"x", PIN),
        Err(Error::PinBlocked)
    ));
}

#[test]
fn no_touch_no_secret() {
    let mut soft = SoftKey::new(SEED).with_pin(PIN);
    let ids = [register(&mut soft)];
    soft.touch = Touch::NotGiven;
    assert!(matches!(
        secret(&mut soft, &ids, b"x", PIN),
        Err(Error::NotTouched)
    ));
}

#[test]
fn the_touch_is_announced_once_per_command() {
    let mut soft = SoftKey::new(SEED).with_pin(PIN);
    let asked = Arc::new(AtomicU32::new(0));
    let mut key = Key::open(&mut soft).unwrap();
    let counter = asked.clone();
    key.on_touch(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    let id = key.register(RP, PIN).unwrap();
    key.prf(RP, &[id], b"x", PIN).unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

#[test]
fn a_key_without_a_pin_gets_one_and_then_works() {
    let mut soft = SoftKey::new(SEED);
    let mut key = Key::open(&mut soft).unwrap();
    assert_eq!(key.info().client_pin, Some(false));
    assert!(matches!(key.register(RP, PIN), Err(Error::PinNotSet)));
    assert!(matches!(key.set_pin("12"), Err(Error::PinPolicy)));
    key.set_pin(PIN).unwrap();
    assert_eq!(key.info().client_pin, Some(true));
    let id = key.register(RP, PIN).unwrap();
    key.prf(RP, &[id], b"x", PIN).unwrap();
}

#[test]
fn the_pin_is_compared_in_nfc() {
    // "é" composed and decomposed are one PIN.
    let mut soft = SoftKey::new(SEED);
    let mut key = Key::open(&mut soft).unwrap();
    key.set_pin("caf\u{e9}1").unwrap();
    let id = key.register(RP, "cafe\u{301}1").unwrap();
    key.prf(RP, &[id], b"x", "caf\u{e9}1").unwrap();
}

#[test]
fn a_key_without_hmac_secret_is_refused_before_anything_is_made() {
    let mut soft = SoftKey::new(SEED).with_pin(PIN).without_hmac_secret();
    let mut key = Key::open(&mut soft).unwrap();
    assert!(matches!(key.register(RP, PIN), Err(Error::Unsupported(_))));
    drop(key);
    assert_eq!(soft.touches(), 0);
}

#[test]
fn without_the_pin_the_credential_does_not_answer_at_all() {
    // credProtect 3: an assertion without user verification does not
    // even find the credential, let alone give its secret.
    use crate::cbor::Value;
    use crate::hid::Channel;
    let mut soft = SoftKey::new(SEED).with_pin(PIN);
    let id = register(&mut soft);
    let mut channel = Channel::open(&mut soft).unwrap();
    let params = Value::map([
        (1, Value::from(RP)),
        (2, Value::Bytes(vec![0; 32])),
        (
            3,
            Value::Array(vec![Value::map([
                ("id", Value::Bytes(id)),
                ("type", Value::from("public-key")),
            ])]),
        ),
    ]);
    let r = channel.cbor(0x02, Some(&params), &mut || {});
    assert!(matches!(r, Err(Error::NoCredentials)), "{r:?}");
}
