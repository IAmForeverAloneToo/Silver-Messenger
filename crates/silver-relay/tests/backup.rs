//! Backups as an operator takes them: through the running relay's socket,
//! and restored into another data directory.

use std::sync::Arc;

use silver_protocol::{Content, Identity, PrekeySecret, Prekeys, seal};
use silver_relay::{BanTarget, Limits, Policy, RelayState, Store, backup};

/// A data directory with one identity, its prekeys and a queued message.
fn populate(dir: &std::path::Path) -> Identity {
    let bob = Identity::generate();
    let store = Store::open(&backup::database_path(dir)).unwrap();
    let signed = PrekeySecret::generate(1, 0);
    store
        .put_bundle(&bob.key_bundle_with(Prekeys::classical(signed.signed_by(&bob), Vec::new())))
        .unwrap();
    store
        .set_one_time_prekeys(&bob.user_id(), &[PrekeySecret::generate(2, 0).one_time()])
        .unwrap();
    let alice = Identity::generate();
    let envelope = seal(&alice, &bob.key_bundle(), Content::text("kept"), 0).unwrap();
    store.enqueue(&envelope, 1, Limits::default()).unwrap();
    bob
}

#[cfg(unix)]
#[tokio::test]
async fn a_live_backup_restores_into_a_fresh_relay() {
    use silver_relay::admin;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let bob = populate(&source);
    let state = RelayState::open_with(
        &backup::database_path(&source),
        Limits::default(),
        Policy::default(),
    )
    .unwrap();
    state.set_invite_token(Some("kept".into())).unwrap();
    state
        .ban(&BanTarget::Address("203.0.113.5".parse().unwrap()), "flood")
        .unwrap();
    let socket = dir.path().join("admin.sock");
    let server = tokio::spawn(admin::serve_unix(socket.clone(), Arc::clone(&state), None));
    for _ in 0..50 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // While the relay runs, its database is its own.
    let file = dir.path().join("relay.backup");
    let err = backup::offline(&source, &file, 1).unwrap_err();
    assert!(err.to_string().contains("running"), "{err}");

    // Through the socket, then.
    let (header, summary) = admin::download(&socket, &file).await.unwrap();
    assert_eq!(header.schema, silver_relay::SCHEMA_VERSION);
    assert_eq!((summary.identities, summary.messages), (1, 1));
    assert_eq!(std::fs::metadata(&file).unwrap().len(), summary.bytes);
    assert!(!dir.path().join("relay.backup.part").exists());
    let (checked, verified) = backup::verify(std::fs::File::open(&file).unwrap()).unwrap();
    assert_eq!((checked, verified), (header, summary));

    // Into another data directory, which then serves the same relay.
    let target = dir.path().join("target");
    let restored = backup::restore(&target, &file, false, 7).unwrap();
    assert_eq!(restored.summary, summary);
    let again = RelayState::open_with(
        &backup::database_path(&target),
        Limits::default(),
        Policy::default(),
    )
    .unwrap();
    let rows = again.identities().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].messages, rows[0].one_time_prekeys), (1, 1));
    assert!(again.resolve(&bob.user_id().to_string()).unwrap().is_some());
    assert!(again.address_banned("203.0.113.5".parse().unwrap()));
    assert_eq!(again.invite_token().as_deref(), Some("kept"));

    server.abort();
    let err = admin::download(&dir.path().join("nowhere.sock"), &file)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("connecting"), "{err:#}");
}

#[test]
fn a_stopped_relay_is_backed_up_from_its_directory() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let bob = populate(&source);
    let file = dir.path().join("relay.backup");
    let (_, summary) = backup::offline(&source, &file, 3).unwrap();
    assert_eq!((summary.identities, summary.messages), (1, 1));
    let target = dir.path().join("target");
    backup::restore(&target, &file, false, 4).unwrap();
    let store = Store::open(&backup::database_path(&target)).unwrap();
    assert_eq!(store.queued(&bob.user_id()).unwrap().len(), 1);
}
