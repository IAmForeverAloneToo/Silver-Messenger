//! The real key store of this computer, which every other test keeps away
//! from (`keystore::use_mock_store`). Run by hand where there is one, after
//! a change to `src/keystore.rs` or its backends:
//! `cargo test -p silver-client --test keystore -- --ignored`. It makes one
//! entry under a name of its own and removes it again.

use silver_client::keystore;

#[test]
#[ignore = "touches this computer's key store"]
fn the_real_store_keeps_replaces_and_forgets() {
    assert!(keystore::available(), "no key store on this computer");
    let name = format!("test-{}", std::process::id());
    assert!(keystore::load(&name).unwrap().is_none());

    let first = keystore::create(&name).unwrap();
    assert_eq!(keystore::load(&name).unwrap().unwrap(), first);

    // A second key under the same name replaces the first, rather than
    // leaving two entries the next read would refuse to choose between.
    let second = keystore::create(&name).unwrap();
    assert_ne!(first, second);
    assert_eq!(keystore::load(&name).unwrap().unwrap(), second);

    keystore::delete(&name).unwrap();
    assert!(keystore::load(&name).unwrap().is_none());
    keystore::delete(&name).unwrap();
}
