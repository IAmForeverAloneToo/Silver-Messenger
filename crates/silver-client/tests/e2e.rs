//! End-to-end: two clients talk through an in-process relay.

use std::sync::Arc;
use std::time::Duration;

use silver_client::{Client, ClientEvent, ConnectOptions};
use silver_protocol::{Content, Identity};
use silver_relay::{Limits, RelayState};
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
