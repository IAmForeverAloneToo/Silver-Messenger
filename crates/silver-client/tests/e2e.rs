//! End-to-end: two clients talk through an in-process relay.

use std::sync::Arc;
use std::time::Duration;

use silver_client::{
    Client, ClientError, ClientEvent, ConnectOptions, LogStore, SessionStore, SharedSessions,
    Store, TransparencyEvent,
};
use silver_protocol::{Content, Identity, Sequence};
use silver_relay::{Limits, RelayState};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Options for a client that keeps forward-secret sessions in memory.
fn with_sessions(identity: &Identity) -> ConnectOptions {
    ConnectOptions {
        sessions: Some(SessionStore::ephemeral(identity.user_id()).shared()),
        ..Default::default()
    }
}

fn reuse_sessions(sessions: &SharedSessions) -> ConnectOptions {
    ConnectOptions {
        sessions: Some(sessions.clone()),
        ..Default::default()
    }
}

async fn connected(rx: &mut mpsc::Receiver<ClientEvent>, who: &str) {
    wait_for(rx, &format!("{who} connected"), |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
}

fn message(ev: &ClientEvent) -> Option<&silver_protocol::Message> {
    match ev {
        ClientEvent::Message(m) => Some(m),
        _ => None,
    }
}

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
    // Generous: the event comes within a second on an idle machine, but
    // a CI runner shares its cores among every test of this binary.
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

fn body(ev: &ClientEvent) -> Option<(&silver_protocol::UserId, &str)> {
    match ev {
        ClientEvent::Message(m) => match &m.content {
            Content::Text { body, .. } => Some((&m.from, body.as_str())),
            _ => None,
        },
        _ => None,
    }
}

#[tokio::test]
async fn alice_and_bob_exchange_messages_through_the_relay() {
    let (url, state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());

    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), ConnectOptions::default()).unwrap();
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), ConnectOptions::default()).unwrap();
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
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), ConnectOptions::default()).unwrap();
    wait_for(&mut bob_ev, "bob connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    bob_c.shutdown().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.online_count(), 0);

    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), ConnectOptions::default()).unwrap();
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
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), ConnectOptions::default()).unwrap();
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
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), ConnectOptions::default()).unwrap();
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
    // The old runtime releases its socket asynchronously, so retry the bind.
    let listener = loop {
        match TcpListener::bind(addr).await {
            Ok(l) => break l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("rebind failed: {e}"),
        }
    };
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

#[tokio::test]
async fn relay_restart_keeps_queued_messages() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("relay.redb");
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let addr = std_listener.local_addr().unwrap();
    let url = format!("ws://{addr}/ws");

    // A file-backed relay on its own runtime, so it can be torn down hard.
    let first = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let db_for_first = db.clone();
    first.spawn(async move {
        let state = RelayState::open(&db_for_first, Limits::default()).unwrap();
        let listener = TcpListener::from_std(std_listener).unwrap();
        silver_relay::serve(listener, state, std::future::pending()).await
    });

    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());

    // Bob publishes his key, then goes offline.
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), ConnectOptions::default()).unwrap();
    wait_for(&mut bob_ev, "bob connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    bob_c.shutdown().await;

    // Alice queues two messages for him and the relay confirms both.
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), ConnectOptions::default()).unwrap();
    wait_for(&mut alice_ev, "alice connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    let bundle = alice_c.lookup(bob.user_id()).await.unwrap().unwrap();
    for i in 0..2 {
        let env = alice_c
            .send_text(&bundle, format!("durable {i}"))
            .await
            .unwrap();
        wait_for(
            &mut alice_ev,
            "sent",
            |e| matches!(e, ClientEvent::Sent { id } if *id == env.id),
        )
        .await;
    }
    alice_c.shutdown().await;

    // Kill the relay process-style, then start a fresh one on the same
    // database file and port.
    tokio::task::spawn_blocking(move || first.shutdown_timeout(Duration::from_secs(5)))
        .await
        .unwrap();
    let listener = loop {
        match TcpListener::bind(addr).await {
            Ok(l) => break l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("rebind failed: {e}"),
        }
    };
    let state = loop {
        match RelayState::open(&db, Limits::default()) {
            Ok(s) => break s,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    };
    assert_eq!(state.queued_for(&bob.user_id()), 2);
    tokio::spawn(silver_relay::serve(
        listener,
        state.clone(),
        std::future::pending(),
    ));

    // Bob comes back and receives both, in order.
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), ConnectOptions::default()).unwrap();
    let mut texts = Vec::new();
    while texts.len() < 2 {
        let ev = wait_for(&mut bob_ev, "durable message", |e| body(e).is_some()).await;
        texts.push(body(&ev).unwrap().1.to_owned());
    }
    assert_eq!(texts, ["durable 0", "durable 1"]);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(state.queued_for(&bob.user_id()), 0);
    bob_c.shutdown().await;
}

async fn stop_runtime(rt: tokio::runtime::Runtime) {
    tokio::task::spawn_blocking(move || rt.shutdown_timeout(Duration::from_secs(5)))
        .await
        .unwrap();
}

async fn rebind(addr: std::net::SocketAddr) -> TcpListener {
    loop {
        match TcpListener::bind(addr).await {
            Ok(l) => return l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("rebind failed: {e}"),
        }
    }
}

#[tokio::test]
async fn messages_written_while_offline_go_out_on_reconnect() {
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
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), ConnectOptions::default()).unwrap();
    let (_bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), ConnectOptions::default()).unwrap();
    wait_for(&mut alice_ev, "alice connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    wait_for(&mut bob_ev, "bob connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    let bundle = alice_c.lookup(bob.user_id()).await.unwrap().unwrap();

    // The relay dies; Alice writes anyway.
    stop_runtime(first).await;
    wait_for(&mut alice_ev, "alice offline", |e| {
        matches!(e, ClientEvent::Disconnected { .. })
    })
    .await;
    let env = alice_c
        .send_text(&bundle, "queued while offline".into())
        .await
        .unwrap();
    assert_eq!(alice_c.pending_count(), 1);
    assert_eq!(alice_c.pending_ids(), vec![env.id.clone()]);

    // The relay returns; the outbox drains and Bob (who reconnects too) gets it.
    let listener = rebind(addr).await;
    tokio::spawn(silver_relay::serve(
        listener,
        RelayState::new(),
        std::future::pending(),
    ));
    wait_for(
        &mut alice_ev,
        "queued message sent",
        |e| matches!(e, ClientEvent::Sent { id } if *id == env.id),
    )
    .await;
    assert_eq!(alice_c.pending_count(), 0);
    let got = wait_for(&mut bob_ev, "bob's message", |e| body(e).is_some()).await;
    assert_eq!(body(&got).unwrap().1, "queued while offline");
}

#[tokio::test]
async fn outbox_survives_a_client_restart() {
    let dir = tempfile::tempdir().unwrap();
    let outbox = dir.path().join("outbox.json");
    // A port nobody listens on yet.
    let addr = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let url = format!("ws://{addr}/ws");
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let options = || ConnectOptions {
        outbox_path: Some(outbox.clone()),
        ..Default::default()
    };

    // Written with no relay reachable, then the client exits.
    let (alice_c, _alice_ev) = Client::spawn(url.clone(), alice.clone(), options()).unwrap();
    let env = alice_c
        .send_text(&bob.key_bundle(), "survives restart".into())
        .await
        .unwrap();
    assert_eq!(alice_c.pending_count(), 1);
    alice_c.shutdown().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A new client with the same data still holds it, and delivers once a
    // relay appears.
    let (alice_c, mut alice_ev) = Client::spawn(url.clone(), alice.clone(), options()).unwrap();
    assert_eq!(alice_c.pending_ids(), vec![env.id.clone()]);
    let listener = rebind(addr).await;
    tokio::spawn(silver_relay::serve(
        listener,
        RelayState::new(),
        std::future::pending(),
    ));
    wait_for(
        &mut alice_ev,
        "sent after restart",
        |e| matches!(e, ClientEvent::Sent { id } if *id == env.id),
    )
    .await;
    assert_eq!(alice_c.pending_count(), 0);

    let (_bob_c, mut bob_ev) = Client::spawn(url, bob, ConnectOptions::default()).unwrap();
    let got = wait_for(&mut bob_ev, "bob's message", |e| body(e).is_some()).await;
    assert_eq!(body(&got).unwrap().1, "survives restart");
}

#[tokio::test]
async fn rejected_envelopes_leave_the_outbox() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let state = RelayState::with_store(
        silver_relay::Store::in_memory().unwrap(),
        Limits {
            max_messages: 1,
            max_bytes: u64::MAX,
        },
    );
    tokio::spawn(silver_relay::serve(listener, state, std::future::pending()));

    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), ConnectOptions::default()).unwrap();
    wait_for(&mut bob_ev, "bob connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    bob_c.shutdown().await;

    let (alice_c, mut alice_ev) = Client::spawn(url, alice, ConnectOptions::default()).unwrap();
    wait_for(&mut alice_ev, "alice connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    let bundle = alice_c.lookup(bob.user_id()).await.unwrap().unwrap();
    let first = alice_c.send_text(&bundle, "fits".into()).await.unwrap();
    let second = alice_c
        .send_text(&bundle, "does not fit".into())
        .await
        .unwrap();
    wait_for(
        &mut alice_ev,
        "first sent",
        |e| matches!(e, ClientEvent::Sent { id } if *id == first.id),
    )
    .await;
    let ev = wait_for(
        &mut alice_ev,
        "second rejected",
        |e| matches!(e, ClientEvent::Rejected { id, .. } if *id == second.id),
    )
    .await;
    let ClientEvent::Rejected { reason, .. } = ev else {
        unreachable!()
    };
    assert!(reason.contains("mailbox is full"), "{reason}");
    assert_eq!(alice_c.pending_count(), 0);
}

#[tokio::test]
async fn rate_limited_sends_stay_queued_and_retry_later() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let state = RelayState::with_store_and_policy(
        silver_relay::Store::in_memory().unwrap(),
        Limits::default(),
        silver_relay::Policy {
            sends_per_minute: 2,
            anonymous_sends_per_minute: 2,
            ..Default::default()
        },
    );
    tokio::spawn(silver_relay::serve(listener, state, std::future::pending()));

    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (_bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), ConnectOptions::default()).unwrap();
    wait_for(&mut bob_ev, "bob connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    let (alice_c, mut alice_ev) = Client::spawn(url, alice, ConnectOptions::default()).unwrap();
    wait_for(&mut alice_ev, "alice connected", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    let bundle = alice_c.lookup(bob.user_id()).await.unwrap().unwrap();

    let mut ids = Vec::new();
    for i in 0..3 {
        ids.push(
            alice_c
                .send_text(&bundle, format!("burst {i}"))
                .await
                .unwrap()
                .id,
        );
    }
    wait_for(
        &mut alice_ev,
        "first sent",
        |e| matches!(e, ClientEvent::Sent { id } if *id == ids[0]),
    )
    .await;
    wait_for(
        &mut alice_ev,
        "second sent",
        |e| matches!(e, ClientEvent::Sent { id } if *id == ids[1]),
    )
    .await;
    let ev = wait_for(&mut alice_ev, "rate limit notice", |e| {
        matches!(e, ClientEvent::Error(_))
    })
    .await;
    let ClientEvent::Error(text) = ev else {
        unreachable!()
    };
    assert!(text.contains("rate limiting"), "{text}");
    // The third message is kept for a later retry, not dropped.
    assert_eq!(alice_c.pending_ids(), vec![ids[2].clone()]);
}

#[tokio::test]
async fn invite_token_gates_registration_of_new_identities() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let state = RelayState::with_store_and_policy(
        silver_relay::Store::in_memory().unwrap(),
        Limits::default(),
        silver_relay::Policy {
            invite_token: Some("secret".into()),
            ..Default::default()
        },
    );
    tokio::spawn(silver_relay::serve(listener, state, std::future::pending()));
    let alice = Arc::new(Identity::generate());

    // Without the token the relay refuses to register the identity.
    let (c, mut ev) = Client::spawn(url.clone(), alice.clone(), ConnectOptions::default()).unwrap();
    let ev1 = wait_for(&mut ev, "refusal", |e| {
        matches!(e, ClientEvent::Disconnected { .. })
    })
    .await;
    let ClientEvent::Disconnected { reason, .. } = ev1 else {
        unreachable!()
    };
    assert!(reason.contains("invite"), "{reason}");
    c.shutdown().await;

    // With it, registration works.
    let options = ConnectOptions {
        invite_token: Some("secret".into()),
        ..Default::default()
    };
    let (c, mut ev) = Client::spawn(url.clone(), alice.clone(), options).unwrap();
    wait_for(&mut ev, "connected with token", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    c.shutdown().await;

    // A known identity no longer needs it.
    let (c, mut ev) = Client::spawn(url, alice, ConnectOptions::default()).unwrap();
    wait_for(&mut ev, "known identity connects", |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    c.shutdown().await;
}

// --- protocol v2: sessions and anonymous submission ------------------------

#[tokio::test]
async fn clients_with_prekeys_talk_over_forward_secret_sessions() {
    let (url, state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_sessions(&alice)).unwrap();
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone(), with_sessions(&bob)).unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;

    // The relay holds Bob's prekeys; the stored bundle carries no one-time
    // keys itself, they are handed out one per lookup.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.one_time_prekeys_left(&bob.user_id()), 20);
    let stored = state.bundle(&bob.user_id()).unwrap();
    assert!(stored.supports_sessions());
    assert!(stored.prekeys.unwrap().one_time.is_empty());

    let delivery = alice_c
        .send_message(
            bob.user_id(),
            None,
            "hello under a session".into(),
            Sequence { epoch: 1, seq: 1 },
        )
        .await
        .unwrap();
    assert!(delivery.forward_secret && !delivery.key_changed);
    assert_eq!(delivery.bundle.prekeys.as_ref().unwrap().one_time.len(), 1);
    assert_eq!(state.one_time_prekeys_left(&bob.user_id()), 19);
    // The sealed layer is as opaque as before.
    let wire = serde_json::to_string(&delivery.envelope).unwrap();
    assert!(!wire.contains("hello") && !wire.contains(&alice.user_id().to_string()));

    wait_for(&mut alice_ev, "alice's session", |e| {
        matches!(e, ClientEvent::SessionEstablished { peer, initiated_by_us: true } if *peer == bob.user_id())
    })
    .await;
    wait_for(&mut bob_ev, "bob's session", |e| {
        matches!(e, ClientEvent::SessionEstablished { peer, initiated_by_us: false } if *peer == alice.user_id())
    })
    .await;
    let got = wait_for(&mut bob_ev, "bob's message", |e| message(e).is_some()).await;
    let m = message(&got).unwrap();
    assert_eq!(m.from, alice.user_id());
    assert_eq!(m.content, Content::text("hello under a session"));
    assert_eq!(m.sequence, Sequence { epoch: 1, seq: 1 });
    assert!(m.forward_secret);
    // Both clients advertise the v4 ratchet, so the session runs it and the
    // message is deniable: it carried no sealed-layer signature.
    assert!(!m.signed, "a v4 body is deniable");
    assert!(
        bob_c
            .session_info(&alice.user_id())
            .is_some_and(|s| !s.initiated_by_us && s.post_quantum && s.pq_ratchet)
    );

    // Bob answers on the same session.
    let reply = bob_c
        .send_message(
            alice.user_id(),
            None,
            "back under it".into(),
            Sequence::default(),
        )
        .await
        .unwrap();
    assert!(reply.forward_secret);
    let got = wait_for(&mut alice_ev, "alice's message", |e| message(e).is_some()).await;
    let reply_msg = message(&got).unwrap();
    assert!(reply_msg.forward_secret && !reply_msg.signed);
    assert!(
        alice_c
            .session_info(&bob.user_id())
            .is_some_and(|s| s.initiated_by_us
                && !s.awaiting_reply
                && s.post_quantum
                && s.pq_ratchet)
    );

    // Both envelopes went in on connections that never authenticated.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(state.anonymous_submission_count(), 2);
    assert_eq!(state.online_count(), 2);
    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

#[tokio::test]
async fn everyday_kinds_travel_under_a_session_and_advertise_what_they_need() {
    let (url, _state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_sessions(&alice)).unwrap();
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone(), with_sessions(&bob)).unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;

    // A text first; every body says what this client reads.
    let sent = alice_c
        .send_message(
            bob.user_id(),
            None,
            "hello".into(),
            Sequence { epoch: 1, seq: 1 },
        )
        .await
        .unwrap();
    let got = wait_for(&mut bob_ev, "bob's text", |e| message(e).is_some()).await;
    let m = message(&got).unwrap();
    assert_eq!(m.id, sent.envelope.id);
    for cap in ["edits", "reactions", "timers"] {
        assert!(m.caps.iter().any(|c| c == cap), "{cap} in {:?}", m.caps);
    }
    // Then an edit of it, a reaction to it, its deletion and a timer,
    // each a body under the same session, as a text is.
    let kinds = [
        Content::Edit {
            id: sent.envelope.id.clone(),
            body: "hello, bob".into(),
        },
        Content::Reaction {
            id: sent.envelope.id.clone(),
            emoji: "👋".into(),
        },
        Content::Delete {
            ids: vec![sent.envelope.id.clone()],
        },
        Content::Timer { seconds: 86_400 },
    ];
    for (n, content) in kinds.iter().enumerate() {
        let delivery = alice_c
            .send_content(
                bob.user_id(),
                Some(sent.bundle.clone()),
                content.clone(),
                Sequence {
                    epoch: 1,
                    seq: 2 + n as u64,
                },
            )
            .await
            .unwrap();
        assert!(delivery.forward_secret);
        let got = wait_for(&mut bob_ev, "bob's next", |e| message(e).is_some()).await;
        let m = message(&got).unwrap();
        assert_eq!(m.from, alice.user_id());
        assert_eq!(&m.content, content);
        assert!(m.forward_secret && !m.signed);
    }
    // A reply names the message answered and asks nothing of the reader.
    let reply = Content::Text {
        body: "and to you".into(),
        reply_to: Some(sent.envelope.id.clone()),
    };
    bob_c
        .send_content(alice.user_id(), None, reply.clone(), Sequence::default())
        .await
        .unwrap();
    let got = wait_for(&mut alice_ev, "alice's reply", |e| message(e).is_some()).await;
    assert_eq!(message(&got).unwrap().content, reply);
    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

#[tokio::test]
async fn a_peer_without_prekeys_is_sent_v1_and_understood() {
    let (url, _state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_sessions(&alice)).unwrap();
    // Bob is an older client: no session store, so no prekeys.
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), ConnectOptions::default()).unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;

    let delivery = alice_c
        .send_message(
            bob.user_id(),
            None,
            "plain for bob".into(),
            Sequence::default(),
        )
        .await
        .unwrap();
    assert!(!delivery.forward_secret);
    assert!(!delivery.bundle.supports_sessions());
    let got = wait_for(&mut bob_ev, "bob's message", |e| message(e).is_some()).await;
    assert_eq!(body(&got).unwrap().1, "plain for bob");
    assert!(!message(&got).unwrap().forward_secret);

    // Bob's v1 reply to Alice's v2 bundle is read as plain too.
    let alice_bundle = bob_c.lookup(alice.user_id()).await.unwrap().unwrap();
    assert!(alice_bundle.supports_sessions());
    bob_c
        .send_text(&alice_bundle, "plain back".into())
        .await
        .unwrap();
    let got = wait_for(&mut alice_ev, "alice's message", |e| message(e).is_some()).await;
    assert_eq!(body(&got).unwrap().1, "plain back");
    assert!(!message(&got).unwrap().forward_secret);
    assert!(alice_c.session_info(&bob.user_id()).is_none());
}

#[tokio::test]
async fn handshakes_wait_in_the_mailbox_and_sessions_survive_restarts() {
    let (url, state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let bob_sessions = SessionStore::ephemeral(bob.user_id()).shared();
    let alice_dir = tempfile::tempdir().unwrap();
    let alice_store = Store::open(alice_dir.path()).unwrap();

    // Bob deposits prekeys, then goes offline.
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), reuse_sessions(&bob_sessions)).unwrap();
    connected(&mut bob_ev, "bob").await;
    bob_c.shutdown().await;

    // Alice, with sessions on disk, writes to him twice.
    let alice_options = || ConnectOptions {
        sessions: Some(
            SessionStore::load(&alice_store, alice.user_id())
                .unwrap()
                .shared(),
        ),
        outbox_path: Some(alice_dir.path().join("outbox.json")),
        ..Default::default()
    };
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), alice_options()).unwrap();
    connected(&mut alice_ev, "alice").await;
    let mut pinned = None;
    for text in ["first while away", "second while away"] {
        let d = alice_c
            .send_message(
                bob.user_id(),
                pinned.clone(),
                text.into(),
                Sequence::default(),
            )
            .await
            .unwrap();
        assert!(d.forward_secret);
        pinned = Some(d.bundle);
        wait_for(
            &mut alice_ev,
            "sent",
            |e| matches!(e, ClientEvent::Sent { id } if *id == d.envelope.id),
        )
        .await;
    }
    assert_eq!(state.queued_for(&bob.user_id()), 2);
    alice_c.shutdown().await;

    // Bob returns: the handshake in the first message sets the session up,
    // the second continues it.
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), reuse_sessions(&bob_sessions)).unwrap();
    let mut texts = Vec::new();
    let mut established = 0;
    while texts.len() < 2 {
        let ev = wait_for(&mut bob_ev, "queued message", |e| {
            message(e).is_some() || matches!(e, ClientEvent::SessionEstablished { .. })
        })
        .await;
        match ev {
            ClientEvent::SessionEstablished { .. } => established += 1,
            ClientEvent::Message(m) => {
                assert!(m.forward_secret);
                let Content::Text { body, .. } = m.content else {
                    panic!("expected text");
                };
                texts.push(body);
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(texts, ["first while away", "second while away"]);
    assert_eq!(established, 1);

    // Alice restarts from disk and the session carries on both ways.
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), alice_options()).unwrap();
    connected(&mut alice_ev, "alice again").await;
    assert!(alice_c.session_info(&bob.user_id()).is_some());
    let d = alice_c
        .send_message(
            bob.user_id(),
            pinned.clone(),
            "third, after restart".into(),
            Sequence::default(),
        )
        .await
        .unwrap();
    assert!(d.forward_secret);
    let got = wait_for(&mut bob_ev, "third message", |e| message(e).is_some()).await;
    assert_eq!(body(&got).unwrap().1, "third, after restart");
    let d = bob_c
        .send_message(
            alice.user_id(),
            None,
            "reply to the restarted client".into(),
            Sequence::default(),
        )
        .await
        .unwrap();
    assert!(d.forward_secret);
    let got = wait_for(&mut alice_ev, "reply", |e| message(e).is_some()).await;
    assert_eq!(body(&got).unwrap().1, "reply to the restarted client");
    assert!(message(&got).unwrap().forward_secret);
    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

#[tokio::test]
async fn a_lost_session_store_is_reported_and_recovered_by_writing_back() {
    let (url, _state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_sessions(&alice)).unwrap();
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone(), with_sessions(&bob)).unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;
    let d = alice_c
        .send_message(bob.user_id(), None, "one".into(), Sequence::default())
        .await
        .unwrap();
    let pinned = Some(d.bundle);
    wait_for(&mut bob_ev, "one", |e| message(e).is_some()).await;
    bob_c
        .send_message(alice.user_id(), None, "two".into(), Sequence::default())
        .await
        .unwrap();
    wait_for(&mut alice_ev, "two", |e| message(e).is_some()).await;

    // Bob reinstalls without his sessions: Alice's next message is
    // unreadable, and says so.
    bob_c.shutdown().await;
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone(), with_sessions(&bob)).unwrap();
    connected(&mut bob_ev, "bob again").await;
    alice_c
        .send_message(
            bob.user_id(),
            pinned.clone(),
            "three".into(),
            Sequence::default(),
        )
        .await
        .unwrap();
    let ev = wait_for(&mut bob_ev, "undecryptable notice", |e| {
        matches!(e, ClientEvent::Undecryptable { .. })
    })
    .await;
    let ClientEvent::Undecryptable { from, reason, .. } = ev else {
        unreachable!()
    };
    assert_eq!(from, alice.user_id());
    assert!(reason.contains("session"), "{reason}");

    // Writing back starts a fresh session, which Alice follows.
    bob_c
        .send_message(
            alice.user_id(),
            None,
            "start over".into(),
            Sequence::default(),
        )
        .await
        .unwrap();
    let got = wait_for(&mut alice_ev, "start over", |e| message(e).is_some()).await;
    assert_eq!(body(&got).unwrap().1, "start over");
    assert!(
        alice_c
            .session_info(&bob.user_id())
            .is_some_and(|s| !s.initiated_by_us)
    );
    alice_c
        .send_message(bob.user_id(), pinned, "four".into(), Sequence::default())
        .await
        .unwrap();
    let got = wait_for(&mut bob_ev, "four", |e| message(e).is_some()).await;
    assert_eq!(body(&got).unwrap().1, "four");
    assert!(message(&got).unwrap().forward_secret);
}

#[tokio::test]
async fn submission_uses_the_authenticated_connection_when_it_must() {
    // A relay that does not offer anonymous submission.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let state = RelayState::with_store_and_policy(
        silver_relay::Store::in_memory().unwrap(),
        Limits::default(),
        silver_relay::Policy {
            anonymous_sends_per_minute: 0,
            ..Default::default()
        },
    );
    tokio::spawn(silver_relay::serve(
        listener,
        state.clone(),
        std::future::pending(),
    ));
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_sessions(&alice)).unwrap();
    let (_bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), with_sessions(&bob)).unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;
    alice_c
        .send_message(bob.user_id(), None, "over auth".into(), Sequence::default())
        .await
        .unwrap();
    let got = wait_for(&mut bob_ev, "bob's message", |e| message(e).is_some()).await;
    assert_eq!(body(&got).unwrap().1, "over auth");
    assert_eq!(state.anonymous_submission_count(), 0);

    // And a client told to stay on its authenticated connection.
    let (url, state) = start_relay().await;
    let carol = Arc::new(Identity::generate());
    let options = ConnectOptions {
        submit_authenticated: true,
        ..with_sessions(&carol)
    };
    let (carol_c, mut carol_ev) = Client::spawn(url.clone(), carol.clone(), options).unwrap();
    let (_bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), with_sessions(&bob)).unwrap();
    connected(&mut carol_ev, "carol").await;
    connected(&mut bob_ev, "bob").await;
    let d = carol_c
        .send_message(
            bob.user_id(),
            None,
            "also over auth".into(),
            Sequence::default(),
        )
        .await
        .unwrap();
    wait_for(
        &mut carol_ev,
        "sent",
        |e| matches!(e, ClientEvent::Sent { id } if *id == d.envelope.id),
    )
    .await;
    assert_eq!(state.anonymous_submission_count(), 0);
}

// --- attachments --------------------------------------------------------------

#[tokio::test]
async fn padded_files_show_the_relay_whole_chunks_only() {
    let (url, state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_sessions(&alice)).unwrap();
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone(), with_sessions(&bob)).unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;

    // Just over a chunk and a half: the relay is shown two whole chunks.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.txt");
    let data: Vec<u8> = (0..100_001u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(&path, &data).unwrap();
    let info = alice_c.upload_file(&path, true, None).await.unwrap();
    assert_eq!((info.chunks, info.size), (2, 100_001));
    let chunk = 65_536 + 16;
    assert_eq!(state.stats().blob_bytes as usize, 2 * chunk);

    // An empty file padded is one whole chunk too, and reads back empty.
    let empty = dir.path().join("empty");
    std::fs::write(&empty, b"").unwrap();
    let empty_info = alice_c.upload_file(&empty, true, None).await.unwrap();
    assert_eq!((empty_info.chunks, empty_info.size), (1, 0));
    assert_eq!(state.stats().blob_bytes as usize, 3 * chunk);

    for info in [&info, &empty_info] {
        alice_c
            .send_content(
                bob.user_id(),
                None,
                info.clone().into_content(),
                Sequence::default(),
            )
            .await
            .unwrap();
        let got = wait_for(
            &mut bob_ev,
            "file message",
            |e| matches!(e, ClientEvent::Message(m) if matches!(m.content, Content::File { .. })),
        )
        .await;
        let ClientEvent::Message(m) = got else {
            unreachable!()
        };
        assert!(m.caps.iter().any(|c| c == "padded_files"));
        let received = silver_client::FileInfo::from_content(&m.content).unwrap();
        let saved = bob_c
            .download_file(&received, &dir.path().join("downloads"), None, None)
            .await
            .unwrap();
        let expected = if received.size == 0 {
            Vec::new()
        } else {
            data.clone()
        };
        assert_eq!(std::fs::read(&saved).unwrap(), expected);
    }
    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

#[tokio::test]
async fn files_travel_as_encrypted_blobs() {
    let (url, state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_sessions(&alice)).unwrap();
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone(), with_sessions(&bob)).unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;
    assert!(alice_c.relay_supports(silver_protocol::wire::feature::BLOBS));

    // Four chunks' worth of pseudo-random bytes.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.bin");
    let data: Vec<u8> = (0..200_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    std::fs::write(&path, &data).unwrap();

    let (ptx, mut prx) = mpsc::channel(64);
    let info = alice_c.upload_file(&path, false, Some(ptx)).await.unwrap();
    assert_eq!((info.chunks, info.size), (4, 200_000));
    let mut last = None;
    while let Ok(p) = prx.try_recv() {
        last = Some(p);
    }
    assert_eq!(last.map(|p| (p.done, p.total)), Some((4, 4)));
    assert_eq!(state.stats().blobs, 1);
    // The relay holds ciphertext only.
    let stored = state.stats().blob_bytes as usize;
    assert!(stored > data.len() && stored < data.len() + 4 * 32);

    alice_c
        .send_content(
            bob.user_id(),
            None,
            info.clone().into_content(),
            Sequence::default(),
        )
        .await
        .unwrap();
    let got = wait_for(
        &mut bob_ev,
        "file message",
        |e| matches!(e, ClientEvent::Message(m) if matches!(m.content, Content::File { .. })),
    )
    .await;
    let ClientEvent::Message(m) = got else {
        unreachable!()
    };
    let received = silver_client::FileInfo::from_content(&m.content).unwrap();
    assert_eq!(received, info);
    assert!(m.caps.iter().any(|c| c == "files"));

    let saved = bob_c
        .download_file(&received, &dir.path().join("downloads"), None, None)
        .await
        .unwrap();
    assert_eq!(saved, dir.path().join("downloads").join("data.bin"));
    assert_eq!(std::fs::read(&saved).unwrap(), data);
    // Fetched again, it lands next to the first copy rather than over it.
    let again = bob_c
        .download_file(&received, &dir.path().join("downloads"), None, None)
        .await
        .unwrap();
    assert_eq!(again, dir.path().join("downloads").join("data (2).bin"));

    // A blob the relay does not have fails cleanly.
    let mut missing = received.clone();
    missing.blob = silver_protocol::blob::new_blob_id();
    let err = bob_c
        .download_file(&missing, dir.path(), None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, silver_client::ClientError::Blob(_)), "{err}");
    // A file the sender lied about is refused after fetching, and nothing
    // of it is written.
    let mut lying = received.clone();
    lying.sha256[0] ^= 1;
    let lying_dir = dir.path().join("lying");
    let err = bob_c
        .download_file(&lying, &lying_dir, None, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("hash"), "{err}");
    assert!(
        !lying_dir.exists() || std::fs::read_dir(&lying_dir).unwrap().next().is_none(),
        "a failed fetch left something behind"
    );
    // A size or chunk count the sender made up is refused before any chunk
    // is asked for.
    let mut huge = received.clone();
    huge.size = 1 << 40;
    let err = bob_c
        .download_file(&huge, dir.path(), None, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, silver_client::ClientError::File(_)) && err.to_string().contains("cap"),
        "{err}"
    );
    let mut odd = received.clone();
    odd.chunks += 1;
    let err = bob_c
        .download_file(&odd, dir.path(), None, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("chunk"), "{err}");
    // A downloads quota the file would pass is refused before fetching.
    let quota_dir = dir.path().join("small");
    let err = bob_c
        .download_file(&received, &quota_dir, Some(data.len() as u64 - 1), None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("quota"), "{err}");
    assert!(!quota_dir.exists());
    let fits = bob_c
        .download_file(&received, &quota_dir, Some(data.len() as u64), None)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&fits).unwrap(), data);
    // Neither the message nor the chunks went through the authenticated
    // connections.
    assert_eq!(state.anonymous_submission_count(), 1);
}

#[tokio::test]
async fn a_file_sent_while_the_recipient_is_offline_is_fetched_on_arrival() {
    let (url, state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    // Bob registers once so his key is discoverable, then goes offline,
    // keeping his prekeys for when he returns.
    let bob_sessions = SessionStore::ephemeral(bob.user_id()).shared();
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), reuse_sessions(&bob_sessions)).unwrap();
    connected(&mut bob_ev, "bob").await;
    bob_c.shutdown().await;
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_sessions(&alice)).unwrap();
    connected(&mut alice_ev, "alice").await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("late.bin");
    let data: Vec<u8> = (0..100_000u32).map(|i| (i * 7 % 251) as u8).collect();
    std::fs::write(&path, &data).unwrap();
    let info = alice_c.upload_file(&path, false, None).await.unwrap();
    alice_c
        .send_content(
            bob.user_id(),
            None,
            info.clone().into_content(),
            Sequence::default(),
        )
        .await
        .unwrap();
    wait_for(&mut alice_ev, "sent", |e| {
        matches!(e, ClientEvent::Sent { .. })
    })
    .await;

    // Bob connects now. The relay replays his mailbox before it has taken
    // his bundle, and his client asks for the file at once: the fetch must
    // wait for the connection to be ready rather than fail.
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), reuse_sessions(&bob_sessions)).unwrap();
    let got = wait_for(
        &mut bob_ev,
        "file message",
        |e| matches!(e, ClientEvent::Message(m) if matches!(m.content, Content::File { .. })),
    )
    .await;
    let ClientEvent::Message(m) = got else {
        unreachable!()
    };
    let received = silver_client::FileInfo::from_content(&m.content).unwrap();
    let saved = bob_c
        .download_file(&received, &dir.path().join("dl"), None, None)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&saved).unwrap(), data);
    connected(&mut bob_ev, "bob").await;
    // The chunks went over the anonymous connection, not the authenticated
    // one that was still being set up.
    assert_eq!(state.anonymous_submission_count(), 1);
    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

#[tokio::test]
async fn a_relay_without_file_storage_says_so() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let state = RelayState::with_store_and_policy(
        silver_relay::Store::in_memory().unwrap(),
        Limits::default(),
        silver_relay::Policy {
            max_blob_mib: 0,
            ..Default::default()
        },
    );
    tokio::spawn(silver_relay::serve(listener, state, std::future::pending()));
    let alice = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_sessions(&alice)).unwrap();
    connected(&mut alice_ev, "alice").await;
    assert!(!alice_c.relay_supports(silver_protocol::wire::feature::BLOBS));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("note.txt");
    std::fs::write(&path, b"hello").unwrap();
    let err = alice_c.upload_file(&path, false, None).await.unwrap_err();
    assert!(err.to_string().contains("does not store files"), "{err}");
}

/// Look `who` up on `client` repeatedly until `rx` yields a matching lifecycle
/// event, so the test does not race the relay storing the statement.
async fn poll_for<T>(
    client: &Client,
    rx: &mut mpsc::Receiver<ClientEvent>,
    who: silver_protocol::UserId,
    what: &str,
    mut pick: impl FnMut(&ClientEvent) -> Option<T>,
) -> T {
    for _ in 0..40 {
        let _ = client.lookup(who).await;
        while let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
            if let Some(found) = pick(&ev) {
                return found;
            }
        }
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn a_revocation_reaches_a_contact_and_ends_the_identity() {
    let (url, _state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_sessions(&alice)).unwrap();
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone(), with_sessions(&bob)).unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;

    // Alice retires her identity with the pre-signed certificate.
    let revocation = alice.revocation(silver_protocol::now_ms());
    alice_c.revoke(revocation).await.unwrap();

    // Bob, looking Alice up, is told she is revoked.
    let seen = poll_for(
        &bob_c,
        &mut bob_ev,
        alice.user_id(),
        "bob learns of the revocation",
        |e| match e {
            ClientEvent::PeerRevoked { revocation } => Some(revocation.clone()),
            _ => None,
        },
    )
    .await;
    assert_eq!(seen.identity, alice.user_id());
    assert!(seen.verify().is_ok());

    // The dead identity can never publish again: Alice's client reconnects,
    // tries to republish, and the relay refuses it.
    let refusal = wait_for(
        &mut alice_ev,
        "alice refused as revoked",
        |e| matches!(e, ClientEvent::Disconnected { reason, .. } if reason.contains("revoked")),
    )
    .await;
    let ClientEvent::Disconnected { reason, .. } = refusal else {
        unreachable!()
    };
    assert!(reason.contains("revoked"), "{reason}");

    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

#[tokio::test]
async fn a_succession_reaches_a_contact_through_the_relay() {
    let (url, _state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let alice_next = Identity::generate();
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_sessions(&alice)).unwrap();
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone(), with_sessions(&bob)).unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;

    // Alice hands over to her new identity, cross-signed by both keys.
    let succession = alice.succeed_to(&alice_next, silver_protocol::now_ms());
    alice_c.succeed(succession).await.unwrap();
    // A round-trip on Alice's own connection guarantees the relay has applied
    // the succession (frames are processed in order) before Bob looks up.
    let _ = alice_c.lookup(alice.user_id()).await;

    let seen = poll_for(
        &bob_c,
        &mut bob_ev,
        alice.user_id(),
        "bob learns of the succession",
        |e| match e {
            ClientEvent::PeerSucceeded { succession } => Some(succession.clone()),
            _ => None,
        },
    )
    .await;
    assert_eq!(seen.old, alice.user_id());
    assert_eq!(seen.new, alice_next.user_id());
    assert!(seen.verify().is_ok());

    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

/// Options for a client that keeps sessions and tails the relay's key log.
fn with_log(identity: &Identity) -> ConnectOptions {
    ConnectOptions {
        sessions: Some(SessionStore::ephemeral(identity.user_id()).shared()),
        transparency: Some(LogStore::ephemeral().shared()),
        ..Default::default()
    }
}

/// Every complaint the key-log check has raised so far, without waiting.
fn complaints(rx: &mut mpsc::Receiver<ClientEvent>) -> Vec<TransparencyEvent> {
    let mut found = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        if let ClientEvent::Transparency(t) = ev
            && !matches!(t, TransparencyEvent::Synced { .. })
        {
            found.push(t);
        }
    }
    found
}

#[tokio::test]
async fn clients_tail_the_key_log_and_gossip_its_head() {
    let (url, _state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_log(&alice)).unwrap();
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone(), with_log(&bob)).unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;
    assert!(bob_c.relay_supports(silver_protocol::wire::feature::TRANSPARENCY));

    // A lookup is checked against the log, replayed up to the head the
    // answer came with: both bundles are in it by now.
    let bundle = bob_c
        .lookup(alice.user_id())
        .await
        .unwrap()
        .expect("alice published");
    wait_for(&mut bob_ev, "bob synced", |e| {
        matches!(e, ClientEvent::Transparency(TransparencyEvent::Synced { head }) if head.index >= 2)
    })
    .await;

    // The head travels inside every message, and the other side compares
    // it with its own chain without a word when they agree.
    bob_c.send_text(&bundle, "hello".into()).await.unwrap();
    let got = wait_for(&mut alice_ev, "alice's message", |e| body(e).is_some()).await;
    let ClientEvent::Message(m) = got else {
        unreachable!()
    };
    assert!(m.head.is_some(), "the head travels inside the message");
    let alice_view = alice_c.lookup(bob.user_id()).await.unwrap().unwrap();
    alice_c.send_text(&alice_view, "hi".into()).await.unwrap();
    let got = wait_for(&mut bob_ev, "bob's message", |e| body(e).is_some()).await;
    let ClientEvent::Message(m) = got else {
        unreachable!()
    };
    assert!(m.head.is_some());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(complaints(&mut alice_ev).is_empty());
    assert!(complaints(&mut bob_ev).is_empty());

    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

#[tokio::test]
async fn a_key_the_relay_did_not_log_is_refused() {
    let (url, state) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (alice_c, mut alice_ev) =
        Client::spawn(url.clone(), alice.clone(), with_log(&alice)).unwrap();
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone(), with_log(&bob)).unwrap();
    connected(&mut alice_ev, "alice").await;
    connected(&mut bob_ev, "bob").await;

    // The relay swaps in another (validly signed) key for Alice without
    // logging it, as a relay lying to Bob would. Bob's lookup is refused
    // and he is told; a client without the log would have taken it.
    state
        .store()
        .put_bundle_unlogged(&alice.key_bundle())
        .unwrap();
    let err = bob_c.lookup(alice.user_id()).await.unwrap_err();
    assert!(matches!(err, ClientError::Transparency(_)), "{err}");
    let ev = wait_for(&mut bob_ev, "bob's complaint", |e| {
        matches!(
            e,
            ClientEvent::Transparency(TransparencyEvent::Lookup { .. })
        )
    })
    .await;
    let ClientEvent::Transparency(TransparencyEvent::Lookup { who, problem }) = ev else {
        unreachable!()
    };
    assert_eq!(who, alice.user_id());
    assert!(problem.contains("not the latest"), "{problem}");
    let (plain_c, mut plain_ev) = Client::spawn(
        url.clone(),
        Arc::new(Identity::generate()),
        ConnectOptions::default(),
    )
    .unwrap();
    connected(&mut plain_ev, "plain").await;
    assert!(plain_c.lookup(alice.user_id()).await.unwrap().is_some());

    alice_c.shutdown().await;
    bob_c.shutdown().await;
    plain_c.shutdown().await;
}
