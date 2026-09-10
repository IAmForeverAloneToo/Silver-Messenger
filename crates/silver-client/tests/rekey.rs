//! Replacing the Diffie–Hellman key under the same identity, over an
//! in-process relay (`docs/design/dh-rotation.md`): a peer that rekeys is
//! taken by contacts once the relay confirms the new key; a session on
//! the key already pinned is delivered without a lookup; and a message
//! sealed to the key a peer has replaced still opens while the old key is
//! within its grace.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use silver_client::connection::SharedContactKeys;
use silver_client::{Client, ClientEvent, ConnectOptions, SessionStore, SharedSessions};
use silver_protocol::{Content, Identity, Sequence};
use silver_relay::RelayState;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

async fn start_relay() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(silver_relay::serve(
        listener,
        RelayState::new(),
        std::future::pending(),
    ));
    format!("ws://{addr}/ws")
}

async fn wait_for(
    rx: &mut mpsc::Receiver<ClientEvent>,
    what: &str,
    mut pred: impl FnMut(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .unwrap_or_else(|| panic!("client stopped while waiting for {what}"));
        if pred(&ev) {
            return ev;
        }
    }
}

async fn connected(rx: &mut mpsc::Receiver<ClientEvent>, who: &str) {
    wait_for(rx, &format!("{who} connected"), |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
}

fn text_of(ev: &ClientEvent) -> Option<String> {
    match ev {
        ClientEvent::Message(m) => match &m.content {
            Content::Text { body, .. } => Some(body.clone()),
            _ => None,
        },
        _ => None,
    }
}

fn with_sessions(sessions: &SharedSessions, keys: Option<SharedContactKeys>) -> ConnectOptions {
    ConnectOptions {
        sessions: Some(sessions.clone()),
        contact_keys: keys,
        ..Default::default()
    }
}

/// A peer that rekeys is taken by a contact once the relay confirms the
/// new key, and a session on the very key already pinned is delivered
/// without a lookup at all.
#[tokio::test]
async fn a_rekeyed_peer_is_taken_when_the_relay_confirms_it() {
    let url = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());

    let alice_sessions = SessionStore::ephemeral(alice.user_id()).shared();
    let bob_sessions = SessionStore::ephemeral(bob.user_id()).shared();
    // Bob has pinned alice's key: the one she publishes now.
    let bob_keys: SharedContactKeys = Arc::new(Mutex::new(HashMap::from([(
        alice.user_id(),
        alice.dh_public(),
    )])));

    let (alice_c, mut alice_ev) = Client::spawn(
        url.clone(),
        alice.clone(),
        with_sessions(&alice_sessions, None),
    )
    .unwrap();
    let (bob_c, mut bob_ev) = Client::spawn(
        url.clone(),
        bob.clone(),
        with_sessions(&bob_sessions, Some(bob_keys.clone())),
    )
    .unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;

    // A session on the pinned key: delivered at once, reported with no
    // published check (`docs/design/dh-rotation.md` section 4.2, step 1).
    let before = alice_c
        .send_message(
            bob.user_id(),
            None,
            "before the rekey".into(),
            Sequence::default(),
        )
        .await
        .unwrap();
    assert!(before.forward_secret);
    let established = wait_for(
        &mut bob_ev,
        "bob's first session",
        |e| matches!(e, ClientEvent::SessionEstablished { peer, .. } if *peer == alice.user_id()),
    )
    .await;
    assert!(
        matches!(established, ClientEvent::SessionEstablished { published: None, identity_dh: Some(dh), .. } if dh == alice.dh_public()),
        "a session on the pinned key is delivered without a lookup"
    );
    let got = wait_for(&mut bob_ev, "before message", |e| text_of(e).is_some()).await;
    assert_eq!(text_of(&got).unwrap(), "before the rekey");

    // Alice rekeys: a fresh key, republished, and her sessions retired so
    // her next message hands bob a new handshake — retired, not
    // forgotten: what bob sends on the old session meanwhile still reads.
    let old_key = alice.dh_public();
    let new_key = alice.rotate_dh(silver_protocol::now_ms());
    assert_ne!(new_key, old_key);
    alice_c.republish().await.unwrap();
    assert_eq!(alice_c.retire_sessions(), vec![bob.user_id()]);
    bob_c
        .send_message(
            alice.user_id(),
            None,
            "still on the old session".into(),
            Sequence { epoch: 0, seq: 1 },
        )
        .await
        .unwrap();
    let got = wait_for(&mut alice_ev, "bob's message on the old session", |e| {
        text_of(e).is_some()
    })
    .await;
    assert_eq!(text_of(&got).unwrap(), "still on the old session");

    // Bob still has the old key pinned. Alice's next message claims the
    // new one: bob defers, looks alice up, and the relay confirms the new
    // key, so the session stands and carries `published == claimed`.
    alice_c
        .send_message(
            bob.user_id(),
            None,
            "after the rekey".into(),
            Sequence { epoch: 1, seq: 0 },
        )
        .await
        .unwrap();
    let established = wait_for(&mut bob_ev, "bob's session after the rekey", |e| {
        matches!(e, ClientEvent::SessionEstablished { peer, published: Some(_), .. } if *peer == alice.user_id())
    })
    .await;
    let ClientEvent::SessionEstablished {
        identity_dh,
        published,
        ..
    } = established
    else {
        unreachable!()
    };
    assert_eq!(
        identity_dh,
        Some(new_key),
        "the handshake claimed the new key"
    );
    assert_eq!(
        published.map(|b| b.dh_public),
        Some(new_key),
        "the relay confirmed the new key, so it is a legitimate key change, not an attack"
    );
    let got = wait_for(&mut bob_ev, "after message", |e| text_of(e).is_some()).await;
    assert_eq!(text_of(&got).unwrap(), "after the rekey");

    alice_c.shutdown().await;
}

/// A message sealed to the key a peer has replaced still opens while the
/// old key is inside its grace, so nothing already in flight is lost to a
/// rekey (`docs/design/dh-rotation.md` section 5).
#[tokio::test]
async fn a_message_sealed_to_the_replaced_key_still_opens() {
    let url = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let carol = Arc::new(Identity::generate());
    let alice_sessions = SessionStore::ephemeral(alice.user_id()).shared();
    let carol_sessions = SessionStore::ephemeral(carol.user_id()).shared();

    // Carol looks alice up once and pins the bundle she publishes now.
    let (carol_c, mut carol_ev) = Client::spawn(
        url.clone(),
        carol.clone(),
        with_sessions(&carol_sessions, None),
    )
    .unwrap();
    let (alice_c, mut alice_ev) = Client::spawn(
        url.clone(),
        alice.clone(),
        with_sessions(&alice_sessions, None),
    )
    .unwrap();
    connected(&mut carol_ev, "carol").await;
    connected(&mut alice_ev, "alice").await;
    let alice_old = carol_c
        .lookup(alice.user_id())
        .await
        .unwrap()
        .expect("alice has a bundle");
    assert_eq!(alice_old.dh_public, alice.dh_public());

    // Alice rekeys and republishes; the old key is kept for the grace.
    let new_key = alice.rotate_dh(silver_protocol::now_ms());
    alice_c.republish().await.unwrap();
    assert_ne!(new_key, alice_old.dh_public);

    // Carol, not having seen the change, seals to the key she pinned —
    // the old one. Alice opens it under the retained previous key.
    carol_c
        .send_message(
            alice.user_id(),
            Some(alice_old.clone()),
            "sealed to your old key".into(),
            Sequence::default(),
        )
        .await
        .unwrap();
    let got = wait_for(&mut alice_ev, "the message on the old key", |e| {
        text_of(e).is_some()
    })
    .await;
    assert_eq!(text_of(&got).unwrap(), "sealed to your old key");

    carol_c.shutdown().await;
    alice_c.shutdown().await;
}
