//! End-to-end: two clients talk through an in-process relay.

use std::sync::Arc;
use std::time::Duration;

use silver_client::{Client, ClientEvent};
use silver_protocol::{Content, Identity};
use silver_relay::RelayState;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

async fn start_relay() -> (String, Arc<RelayState>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = RelayState::new();
    tokio::spawn(silver_relay::serve(
        listener,
        state.clone(),
        std::future::pending(),
    ));
    (format!("ws://{addr}/ws"), state)
}

async fn wait_for(
    rx: &mut mpsc::Receiver<ClientEvent>,
    what: &str,
    mut pred: impl FnMut(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
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

fn body(ev: &ClientEvent) -> Option<(&silver_protocol::UserId, &str)> {
    match ev {
        ClientEvent::Message(m) => match &m.content {
            Content::Text { body } => Some((&m.from, body.as_str())),
        },
        _ => None,
    }
}

#[tokio::test]
async fn alice_and_bob_exchange_messages_through_the_relay() {
    let (url, state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());

    let (alice_c, mut alice_ev) = Client::spawn(url.clone(), alice.clone());
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone());
    wait_for(&mut alice_ev, "alice connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    wait_for(&mut bob_ev, "bob connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    assert_eq!(state.online_count(), 2);

    // Alice discovers Bob's key through the relay.
    let bob_bundle = alice_c
        .lookup(bob.user_id())
        .await
        .unwrap()
        .expect("bob published");
    assert_eq!(bob_bundle.dh_public, bob.dh_public());
    assert!(
        alice_c
            .lookup(Identity::generate().user_id())
            .await
            .unwrap()
            .is_none()
    );

    let env = alice_c
        .send_text(&bob_bundle, "hello bob".into())
        .await
        .unwrap();
    // The relay only ever holds ciphertext.
    let wire = serde_json::to_string(&env).unwrap();
    assert!(!wire.contains("hello bob"));
    assert!(!wire.contains(&alice.user_id().to_string()));

    wait_for(
        &mut alice_ev,
        "sent ack",
        |e| matches!(e, ClientEvent::Sent { id } if *id == env.id),
    )
    .await;
    let got = wait_for(&mut bob_ev, "bob's message", |e| body(e).is_some()).await;
    let (from, text) = body(&got).unwrap();
    assert_eq!(*from, alice.user_id());
    assert_eq!(text, "hello bob");

    // Bob acks, so the relay forgets the envelope.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.queued_for(&bob.user_id()), 0);

    // And back the other way.
    let alice_bundle = bob_c.lookup(alice.user_id()).await.unwrap().unwrap();
    bob_c
        .send_text(&alice_bundle, "hi alice".into())
        .await
        .unwrap();
    let got = wait_for(&mut alice_ev, "alice's message", |e| body(e).is_some()).await;
    assert_eq!(body(&got).unwrap(), (&bob.user_id(), "hi alice"));

    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

#[tokio::test]
async fn offline_messages_wait_in_the_mailbox() {
    let (url, state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());

    // Bob registers once so his key is discoverable, then goes offline.
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone());
    wait_for(&mut bob_ev, "bob connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    bob_c.shutdown().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.online_count(), 0);

    let (alice_c, mut alice_ev) = Client::spawn(url.clone(), alice.clone());
    wait_for(&mut alice_ev, "alice connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    let bob_bundle = alice_c.lookup(bob.user_id()).await.unwrap().unwrap();
    for i in 0..3 {
        alice_c
            .send_text(&bob_bundle, format!("queued {i}"))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.queued_for(&bob.user_id()), 3);

    // Bob comes back and receives everything, in order.
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone());
    let mut texts = Vec::new();
    while texts.len() < 3 {
        let ev = wait_for(&mut bob_ev, "queued message", |e| body(e).is_some()).await;
        texts.push(body(&ev).unwrap().1.to_owned());
    }
    assert_eq!(texts, ["queued 0", "queued 1", "queued 2"]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.queued_for(&bob.user_id()), 0);

    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

#[tokio::test]
async fn client_reconnects_after_relay_restart() {
    // The first relay lives on its own runtime so we can tear it down hard,
    // dropping every open WebSocket the way a crashed process would.
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let addr = std_listener.local_addr().unwrap();
    let url = format!("ws://{addr}/ws");
    let first = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    first.spawn(async move {
        let listener = TcpListener::from_std(std_listener).unwrap();
        silver_relay::serve(listener, RelayState::new(), std::future::pending()).await
    });

    let alice = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) = Client::spawn(url.clone(), alice.clone());
    wait_for(&mut alice_ev, "first connect", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;

    // Kill the relay; the client should notice and start backing off.
    first.shutdown_background();
    wait_for(&mut alice_ev, "disconnect", |e| {
        matches!(e, ClientEvent::Disconnected { .. })
    })
    .await;
    assert!(matches!(
        alice_c.lookup(alice.user_id()).await,
        Err(silver_client::ClientError::NotConnected)
    ));

    // Bring it back on the same port; the client reconnects within backoff.
    let listener = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(silver_relay::serve(
        listener,
        RelayState::new(),
        std::future::pending(),
    ));
    wait_for(&mut alice_ev, "reconnect", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    assert!(alice_c.lookup(alice.user_id()).await.unwrap().is_some());
    alice_c.shutdown().await;
}
