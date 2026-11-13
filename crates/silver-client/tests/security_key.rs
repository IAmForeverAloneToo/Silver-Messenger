//! Unlocking the data directory with a security key
//! (docs/design/security-key.md), against the software authenticator:
//! enrolling over each earlier protection, unlocking with the key or the
//! recovery passphrase, a second key, removing keys, and the version 2
//! vault on disk.

use std::fs;
use std::sync::{Arc, Mutex};

use silver_client::VaultError;
use silver_client::store::{Contact, Direction, HistoryEntry, Missing, Protection, Store};
use silver_client::vault::{Kdf, VaultFile};
use silver_key::soft::{SoftKey, authenticator};
use silver_key::{Authenticator, Error as KeyError};
use silver_protocol::Identity;

const PIN: &str = "4831";
const RECOVERY: &str = "the recovery passphrase";

fn key(seed: u8) -> Arc<Mutex<SoftKey>> {
    Arc::new(Mutex::new(SoftKey::new([seed; 32]).with_pin(PIN)))
}

fn auth(key: &Arc<Mutex<SoftKey>>) -> impl Authenticator {
    authenticator(key.clone(), PIN)
}

/// A directory with an identity, a contact and a line of history.
fn populated(store: &Store) -> Identity {
    let (identity, _) = store.load_or_create_identity().unwrap();
    let peer = Identity::generate();
    store
        .save_contacts(&[Contact::new(peer.user_id())])
        .unwrap();
    store
        .append_history(
            &peer.user_id(),
            &HistoryEntry::new("1", Direction::Sent, 1, "the first line"),
        )
        .unwrap();
    identity
}

fn vault(dir: &std::path::Path) -> VaultFile {
    serde_json::from_str(&fs::read_to_string(dir.join("vault.json")).unwrap()).unwrap()
}

fn enroll(store: &mut Store, key: &Arc<Mutex<SoftKey>>, label: &str, recovery: Option<&str>) {
    store
        .add_security_key_with(&mut auth(key), label, recovery, Kdf::fast())
        .unwrap();
}

fn never(_: &str, e: &anyhow::Error) -> Missing {
    panic!("no key should have gone missing: {e:#}")
}

#[test]
fn a_plain_directory_is_sealed_under_a_key_and_opens_with_it_or_the_recovery_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let identity = populated(&store);
    let yubikey = key(1);

    // The first key needs the recovery passphrase.
    assert!(
        store
            .add_security_key_with(&mut auth(&yubikey), "YubiKey", None, Kdf::fast())
            .is_err()
    );
    assert_eq!(store.protection(), Protection::None);
    enroll(&mut store, &yubikey, "YubiKey", Some(RECOVERY));
    assert_eq!(store.protection(), Protection::SecurityKey);
    assert_eq!(store.security_keys().unwrap(), ["YubiKey"]);

    // Everything is sealed; the vault is version 2 with two slots.
    let raw = fs::read(dir.path().join("identity.json")).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("signing_seed"));
    let v = vault(dir.path());
    assert_eq!(v.version, 2);
    assert_eq!(v.slots.len(), 2);
    let text = fs::read_to_string(dir.path().join("vault.json")).unwrap();
    assert!(text.contains("\"kind\": \"fido2\"") && text.contains("\"kind\": \"passphrase\""));
    assert!(text.contains("silver-messenger.local"));

    // The key opens it.
    let mut again = Store::open(dir.path()).unwrap();
    assert!(again.is_locked());
    again.unlock_with_security_key(&mut auth(&yubikey)).unwrap();
    assert_eq!(
        again.load_or_create_identity().unwrap().0.user_id(),
        identity.user_id()
    );
    assert_eq!(again.load_contacts().unwrap().len(), 1);

    // So does the recovery passphrase, and nothing else does.
    let mut by_recovery = Store::open(dir.path()).unwrap();
    assert!(matches!(
        by_recovery.unlock("not it"),
        Err(VaultError::WrongPassphrase)
    ));
    by_recovery.unlock(RECOVERY).unwrap();
    assert_eq!(by_recovery.load_contacts().unwrap().len(), 1);

    // Another key, never enrolled, opens nothing and says why.
    let stranger = key(2);
    let mut by_stranger = Store::open(dir.path()).unwrap();
    let err = by_stranger
        .unlock_with_security_key(&mut auth(&stranger))
        .unwrap_err();
    assert!(
        matches!(
            err.downcast_ref::<KeyError>(),
            Some(KeyError::NoCredentials)
        ),
        "{err:#}"
    );
    assert!(by_stranger.is_locked());
}

#[test]
fn a_passphrase_directory_moves_to_a_fresh_data_key_and_the_old_passphrase_opens_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    populated(&store);
    store
        .set_passphrase_with("old passphrase", Kdf::fast())
        .unwrap();
    let old_vault = fs::read(dir.path().join("vault.json")).unwrap();

    let yubikey = key(1);
    enroll(&mut store, &yubikey, "YubiKey", Some(RECOVERY));
    assert_eq!(store.protection(), Protection::SecurityKey);
    store.save_contacts(&[]).unwrap();

    // The old vault, put back, with the old passphrase: it unlocks the old
    // data key, which no longer opens what is on disk.
    let mut old = Store::open(dir.path()).unwrap();
    assert!(old.unlock("old passphrase").is_err());
    let current = fs::read(dir.path().join("vault.json")).unwrap();
    fs::write(dir.path().join("vault.json"), &old_vault).unwrap();
    let mut copy = Store::open(dir.path()).unwrap();
    let opened = copy.unlock("old passphrase");
    assert!(
        opened.is_err() || copy.load_contacts().is_err(),
        "the old passphrase still opens what was written after the change"
    );
    fs::write(dir.path().join("vault.json"), &current).unwrap();

    let mut again = Store::open(dir.path()).unwrap();
    again.unlock_with_security_key(&mut auth(&yubikey)).unwrap();
    assert!(again.load_contacts().unwrap().is_empty());
}

#[test]
fn either_of_two_keys_opens_it_and_removing_one_leaves_it_opening_nothing_new() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    populated(&store);
    let (first, second) = (key(1), key(2));
    enroll(&mut store, &first, "first", Some(RECOVERY));
    // A second key needs no recovery passphrase, and the name is its own.
    assert!(
        store
            .add_security_key_with(&mut auth(&second), "first", None, Kdf::fast())
            .is_err()
    );
    enroll(&mut store, &second, "second", None);
    assert_eq!(store.security_keys().unwrap(), ["first", "second"]);
    assert_eq!(vault(dir.path()).slots.len(), 3);

    for k in [&first, &second] {
        let mut s = Store::open(dir.path()).unwrap();
        s.unlock_with_security_key(&mut auth(k)).unwrap();
        assert_eq!(s.load_contacts().unwrap().len(), 1);
    }

    // The first key is lost. The second is asked once, with a fresh salt.
    let before = vault(dir.path());
    let removed = store
        .rekey_security_keys(
            Some("first"),
            &mut auth(&second),
            RECOVERY,
            RECOVERY,
            &mut never,
            Kdf::fast(),
        )
        .unwrap();
    assert_eq!(removed, Protection::SecurityKey);
    assert_eq!(store.security_keys().unwrap(), ["second"]);
    let after = vault(dir.path());
    assert_eq!(after.slots.len(), 2);
    assert!(
        after.previous_key.is_none(),
        "the rotation was left half done"
    );
    let salt = |v: &VaultFile| format!("{:?}", v.security_key_slots().last().unwrap().1.kind);
    assert_ne!(salt(&before), salt(&after), "the salt did not change");
    store.save_contacts(&[]).unwrap();

    // The lost key opens nothing, even with the old vault put back: what
    // is on disk now is under a data key it never wrapped.
    let mut by_first = Store::open(dir.path()).unwrap();
    assert!(
        by_first
            .unlock_with_security_key(&mut auth(&first))
            .is_err()
    );
    let current = fs::read(dir.path().join("vault.json")).unwrap();
    fs::write(
        dir.path().join("vault.json"),
        serde_json::to_vec(&before).unwrap(),
    )
    .unwrap();
    let mut copy = Store::open(dir.path()).unwrap();
    let opened = copy.unlock_with_security_key(&mut auth(&first));
    assert!(opened.is_err() || copy.load_contacts().is_err());
    fs::write(dir.path().join("vault.json"), &current).unwrap();

    let mut by_second = Store::open(dir.path()).unwrap();
    by_second
        .unlock_with_security_key(&mut auth(&second))
        .unwrap();
    assert!(by_second.load_contacts().unwrap().is_empty());
    let mut by_recovery = Store::open(dir.path()).unwrap();
    by_recovery.unlock(RECOVERY).unwrap();
}

#[test]
fn removing_needs_the_recovery_passphrase_and_the_last_key_leaves_a_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    populated(&store);
    let yubikey = key(1);
    enroll(&mut store, &yubikey, "YubiKey", Some(RECOVERY));

    let wrong = store.rekey_security_keys(
        Some("YubiKey"),
        &mut auth(&yubikey),
        "not it",
        "not it",
        &mut never,
        Kdf::fast(),
    );
    assert!(wrong.is_err());
    assert!(
        store
            .rekey_security_keys(
                Some("nobody"),
                &mut auth(&yubikey),
                RECOVERY,
                RECOVERY,
                &mut never,
                Kdf::fast()
            )
            .is_err()
    );
    assert_eq!(store.protection(), Protection::SecurityKey);

    let left = store
        .rekey_security_keys(
            Some("YubiKey"),
            &mut auth(&yubikey),
            RECOVERY,
            RECOVERY,
            &mut never,
            Kdf::fast(),
        )
        .unwrap();
    assert_eq!(left, Protection::Passphrase);
    assert_eq!(store.protection(), Protection::Passphrase);
    let v = vault(dir.path());
    assert_eq!(
        v.version,
        silver_client::vault::BOUND_VAULT_VERSION,
        "no key left: back to a single-wrap vault"
    );
    assert!(v.slots.is_empty());

    let mut again = Store::open(dir.path()).unwrap();
    again.unlock(RECOVERY).unwrap();
    assert_eq!(again.load_contacts().unwrap().len(), 1);
}

#[test]
fn a_key_that_cannot_be_had_is_retried_dropped_or_the_change_given_up() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    populated(&store);
    let (first, second, third) = (key(1), key(2), key(3));
    enroll(&mut store, &first, "first", Some(RECOVERY));
    enroll(&mut store, &second, "second", None);
    enroll(&mut store, &third, "third", None);

    // Removing "first", with only "third" to hand: "second" does not
    // answer. Giving up changes nothing.
    let mut asked = Vec::new();
    let cancelled = store.rekey_security_keys(
        Some("first"),
        &mut auth(&third),
        RECOVERY,
        RECOVERY,
        &mut |label, _| {
            asked.push(label.to_owned());
            Missing::Cancel
        },
        Kdf::fast(),
    );
    assert!(cancelled.is_err());
    assert_eq!(asked, ["second"]);
    assert_eq!(store.security_keys().unwrap(), ["first", "second", "third"]);

    // Dropping it leaves "third" and the recovery passphrase.
    store
        .rekey_security_keys(
            Some("first"),
            &mut auth(&third),
            RECOVERY,
            RECOVERY,
            &mut |_, _| Missing::Drop,
            Kdf::fast(),
        )
        .unwrap();
    assert_eq!(store.security_keys().unwrap(), ["third"]);
    let mut s = Store::open(dir.path()).unwrap();
    assert!(s.unlock_with_security_key(&mut auth(&second)).is_err());
    s.unlock_with_security_key(&mut auth(&third)).unwrap();
}

#[test]
fn changing_the_recovery_passphrase_asks_each_key_and_the_old_one_stops_working() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    populated(&store);
    let yubikey = key(1);
    enroll(&mut store, &yubikey, "YubiKey", Some(RECOVERY));
    store
        .rekey_security_keys(
            None,
            &mut auth(&yubikey),
            RECOVERY,
            "a new one",
            &mut never,
            Kdf::fast(),
        )
        .unwrap();
    let mut old = Store::open(dir.path()).unwrap();
    assert!(matches!(
        old.unlock(RECOVERY),
        Err(VaultError::WrongPassphrase)
    ));
    let mut new = Store::open(dir.path()).unwrap();
    new.unlock("a new one").unwrap();
    let mut by_key = Store::open(dir.path()).unwrap();
    by_key
        .unlock_with_security_key(&mut auth(&yubikey))
        .unwrap();
}

#[test]
fn a_slot_moved_onto_another_does_not_open() {
    // Two keys' slots with their wrappings swapped: each key's output
    // makes a key-encryption key bound to its own credential and salt, so
    // neither opens the other's wrapping.
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    populated(&store);
    let (first, second) = (key(1), key(2));
    enroll(&mut store, &first, "first", Some(RECOVERY));
    enroll(&mut store, &second, "second", None);
    let mut v = vault(dir.path());
    let a = v.slots[0].wrapped_key.clone();
    v.slots[0].wrapped_key = v.slots[2].wrapped_key.clone();
    v.slots[2].wrapped_key = a;
    fs::write(
        dir.path().join("vault.json"),
        serde_json::to_vec(&v).unwrap(),
    )
    .unwrap();
    for k in [&first, &second] {
        let mut s = Store::open(dir.path()).unwrap();
        assert!(s.unlock_with_security_key(&mut auth(k)).is_err());
    }
}

#[test]
fn a_version_2_vault_is_refused_by_what_only_speaks_version_1() {
    // What 0.21.0 reads vault.json into: version, kdf and wrapped_key are
    // required there, and a version 2 file has none of the last two.
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct OldVault {
        version: u32,
        kdf: serde_json::Value,
        wrapped_key: String,
    }
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    populated(&store);
    enroll(&mut store, &key(1), "YubiKey", Some(RECOVERY));
    let text = fs::read_to_string(dir.path().join("vault.json")).unwrap();
    assert!(serde_json::from_str::<OldVault>(&text).is_err());
}

#[test]
fn a_cancelled_or_missing_key_changes_nothing_at_enrolment() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    populated(&store);
    let k = key(1);
    // Nobody types a PIN.
    let mut nobody = silver_key::Direct::new(
        {
            let k = k.clone();
            move || Ok(Some(k.clone()))
        },
        silver_key::soft::FixedPin(None),
    );
    let err = store
        .add_security_key_with(&mut nobody, "YubiKey", Some(RECOVERY), Kdf::fast())
        .unwrap_err();
    assert!(matches!(
        err.downcast_ref::<KeyError>(),
        Some(KeyError::Cancelled)
    ));
    assert_eq!(store.protection(), Protection::None);
    assert!(!dir.path().join("vault.json").exists());
}

// --- the version 2 directory pinned ------------------------------------

/// The software key the fixture was enrolled with: the same seed is the
/// same key, so it opens the fixture in every later version.
const FIXTURE_SEED: [u8; 32] = [0x67; 32];
const FIXTURE_RECOVERY: &str = "the fixture's recovery passphrase";

fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/security-key")
}

/// What the test checks the fixture against.
#[derive(serde::Serialize, serde::Deserialize)]
struct Fixture {
    identity: silver_protocol::UserId,
    peer: silver_protocol::UserId,
}

/// Writes `tests/fixtures/security-key/`, once:
/// `cargo test -p silver-client --test security_key -- --ignored write_fixture`.
#[test]
#[ignore = "writes the fixture; run by hand"]
fn write_fixture() {
    let out = fixture_dir();
    assert!(
        !out.exists(),
        "{} exists; fixtures are written once",
        out.display()
    );
    let dir = out.join("directory");
    let mut store = Store::open(&dir).unwrap();
    let (identity, _) = store.load_or_create_identity().unwrap();
    let peer = Identity::generate();
    store
        .save_contacts(&[Contact::new(peer.user_id())])
        .unwrap();
    store
        .append_history(
            &peer.user_id(),
            &HistoryEntry::new("1", Direction::Sent, 1, "under a security key"),
        )
        .unwrap();
    let key = Arc::new(Mutex::new(SoftKey::new(FIXTURE_SEED).with_pin(PIN)));
    enroll(&mut store, &key, "fixture key", Some(FIXTURE_RECOVERY));
    fs::write(
        out.join("fixture.json"),
        serde_json::to_vec_pretty(&Fixture {
            identity: identity.user_id(),
            peer: peer.user_id(),
        })
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn the_pinned_version_2_directory_opens_by_its_key_and_its_recovery_passphrase() {
    let fixture: Fixture =
        serde_json::from_slice(&fs::read(fixture_dir().join("fixture.json")).unwrap()).unwrap();
    let key = Arc::new(Mutex::new(SoftKey::new(FIXTURE_SEED).with_pin(PIN)));
    for by_key in [true, false] {
        let work = tempfile::tempdir().unwrap();
        copy_dir(&fixture_dir().join("directory"), work.path());
        let mut store = Store::open(work.path()).unwrap();
        assert_eq!(store.protection(), Protection::SecurityKey);
        assert_eq!(store.security_keys().unwrap(), ["fixture key"]);
        if by_key {
            store.unlock_with_security_key(&mut auth(&key)).unwrap();
        } else {
            store.unlock(FIXTURE_RECOVERY).unwrap();
        }
        let (identity, created) = store.load_or_create_identity().unwrap();
        assert!(!created);
        assert_eq!(identity.user_id(), fixture.identity);
        assert_eq!(store.load_contacts().unwrap().len(), 1);
        let history = store.load_history(&fixture.peer).unwrap();
        assert_eq!(history.last().unwrap().text, "under a security key");
        // And it goes on being written.
        store.save_contacts(&[]).unwrap();
    }
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
