//! Devices between clients through an in-process relay (`docs/PROTOCOL.md`
//! section 14): a message reaching every device of an account and a copy
//! every device of the sender's own, a linked device's messages
//! attributed to its account, an older sender's message passed on by the
//! primary, a revoked device dropped by everyone, and `sync` taken from
//! one's own devices alone.

use std::sync::Arc;
use std::time::Duration;

use silver_client::{Client, ClientEvent, ConnectOptions, DeviceState, Linked, SessionStore};
use silver_protocol::device::Sync;
use silver_protocol::envelope::ReceiptKind;
use silver_protocol::{Content, DeviceCertificate, Identity, Sequence, UserId, now_ms};
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

async fn connected(rx: &mut mpsc::Receiver<ClientEvent>, who: &str) {
    wait_for(rx, &format!("{who} connected"), |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
}

/// Options for a client that keeps sessions and a device state: a primary
/// with `devices` linked, or, with `linked`, a linked device.
fn options(
    identity: &Identity,
    linked: Option<Linked>,
    devices: Vec<DeviceCertificate>,
) -> ConnectOptions {
    let mut state = DeviceState::ephemeral(identity.user_id(), linked).unwrap();
    for certificate in devices {
        state.link(certificate).unwrap();
    }
    ConnectOptions {
        sessions: Some(SessionStore::ephemeral(identity.user_id()).shared()),
        devices: Some(state.shared()),
        ..Default::default()
    }
}

/// A text as the front end sees it: from whom, from which of their
/// devices, under which id, saying what.
fn text_of(ev: &ClientEvent) -> Option<(UserId, Option<UserId>, String, String)> {
    match ev {
        ClientEvent::Message(m) => match &m.content {
            Content::Text { body } => Some((
                m.from,
                m.device.as_ref().map(|c| c.device),
                m.id.clone(),
                body.clone(),
            )),
            _ => None,
        },
        _ => None,
    }
}

fn receipt_of(ev: &ClientEvent) -> Option<(UserId, Vec<String>)> {
    match ev {
        ClientEvent::Message(m) => match &m.content {
            Content::Receipt { ids, .. } => Some((m.from, ids.clone())),
            _ => None,
        },
        _ => None,
    }
}

fn sync_of(ev: &ClientEvent) -> Option<(UserId, Sync)> {
    match ev {
        ClientEvent::Sync { device, sync } => Some((*device, (**sync).clone())),
        _ => None,
    }
}

/// Alice's primary and her laptop, linked and connected: the primary
/// lists the laptop, the laptop's bundle carries the certificate.
struct Household {
    alice: Arc<Identity>,
    laptop: Arc<Identity>,
    alice_c: Client,
    alice_ev: mpsc::Receiver<ClientEvent>,
    laptop_c: Client,
    laptop_ev: mpsc::Receiver<ClientEvent>,
}

async fn household(url: &str) -> Household {
    let alice = Arc::new(Identity::generate());
    let laptop = Arc::new(Identity::generate());
    let certificate = alice
        .certify_device(&laptop.user_id(), "laptop", now_ms())
        .unwrap();
    // The account registers first: the relay checks a device's claim
    // against it.
    let (alice_c, mut alice_ev) = Client::spawn(
        url.to_owned(),
        alice.clone(),
        options(&alice, None, vec![certificate.clone()]),
    )
    .unwrap();
    connected(&mut alice_ev, "alice").await;
    let linked = Linked {
        account: alice.user_id(),
        certificate,
    };
    let (laptop_c, mut laptop_ev) = Client::spawn(
        url.to_owned(),
        laptop.clone(),
        options(&laptop, Some(linked), Vec::new()),
    )
    .unwrap();
    connected(&mut laptop_ev, "the laptop").await;
    Household {
        alice,
        laptop,
        alice_c,
        alice_ev,
        laptop_c,
        laptop_ev,
    }
}

fn seq(epoch: u64, seq: u64) -> Sequence {
    Sequence { epoch, seq }
}

fn text(body: &str) -> Content {
    Content::Text { body: body.into() }
}

#[tokio::test]
async fn a_message_reaches_every_device_and_a_copy_every_sibling() {
    let (url, _state) = start_relay().await;
    let mut h = household(&url).await;
    let bob = Arc::new(Identity::generate());
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), options(&bob, None, Vec::new())).unwrap();
    connected(&mut bob_ev, "bob").await;

    // Bob to Alice: her primary gets the message and her laptop a copy
    // under the same id; Bob hears "sent" once, for the message.
    let delivery = bob_c
        .send_content(h.alice.user_id(), None, text("hello alice"), seq(1, 1))
        .await
        .unwrap();
    assert_eq!(
        delivery.bundle.devices.len(),
        1,
        "the list came with the bundle"
    );
    assert_eq!(delivery.copies.len(), 1, "one copy, for the laptop");
    let alice_bundle = delivery.bundle.clone();
    let id = delivery.envelope.id.clone();
    assert_ne!(delivery.copies[0].id, id, "its own envelope");
    wait_for(
        &mut bob_ev,
        "bob's message sent",
        |e| matches!(e, ClientEvent::Sent { id: i } if *i == id),
    )
    .await;
    let got = wait_for(&mut h.alice_ev, "alice's primary gets it", |e| {
        text_of(e).is_some()
    })
    .await;
    let (from, device, got_id, body) = text_of(&got).unwrap();
    assert_eq!(
        (from, device, got_id.as_str(), body.as_str()),
        (bob.user_id(), None, id.as_str(), "hello alice")
    );
    let got = wait_for(&mut h.laptop_ev, "the laptop gets its copy", |e| {
        text_of(e).is_some()
    })
    .await;
    let (from, device, got_id, body) = text_of(&got).unwrap();
    assert_eq!(
        (from, device, got_id.as_str(), body.as_str()),
        (bob.user_id(), None, id.as_str(), "hello alice"),
        "the copy goes by the message's id"
    );

    // Alice's primary to Bob: Bob gets it, and the laptop a sync copy of
    // what was sent, under the message's id.
    let delivery = h
        .alice_c
        .send_content(bob.user_id(), None, text("hi bob"), seq(2, 1))
        .await
        .unwrap();
    assert_eq!(delivery.copies.len(), 1, "a sync copy for the laptop");
    let id = delivery.envelope.id.clone();
    let got = wait_for(&mut bob_ev, "bob's message", |e| text_of(e).is_some()).await;
    assert_eq!(text_of(&got).unwrap().0, h.alice.user_id());
    let got = wait_for(&mut h.laptop_ev, "the laptop's sync copy", |e| {
        sync_of(e).is_some()
    })
    .await;
    let (device, sync) = sync_of(&got).unwrap();
    assert_eq!(device, h.alice.user_id());
    match sync {
        Sync::Sent {
            peer,
            id: copied,
            content,
            ..
        } => {
            assert_eq!(peer, bob.user_id());
            assert_eq!(copied, id);
            assert_eq!(*content, text("hi bob"));
        }
        other => panic!("not a sent copy: {other:?}"),
    }
    wait_for(
        &mut h.alice_ev,
        "alice's message sent",
        |e| matches!(e, ClientEvent::Sent { id: i } if *i == id),
    )
    .await;

    // The laptop to Bob: Bob sees a message from Alice, from her laptop;
    // the primary gets the sync copy.
    let delivery = h
        .laptop_c
        .send_content(bob.user_id(), None, text("hi from the laptop"), seq(3, 1))
        .await
        .unwrap();
    assert_eq!(delivery.copies.len(), 1, "a sync copy for the primary");
    let got = wait_for(&mut bob_ev, "bob's message from the laptop", |e| {
        text_of(e).is_some()
    })
    .await;
    let (from, device, _, body) = text_of(&got).unwrap();
    assert_eq!(
        (from, device, body.as_str()),
        (
            h.alice.user_id(),
            Some(h.laptop.user_id()),
            "hi from the laptop"
        )
    );
    let got = wait_for(&mut h.alice_ev, "the primary's sync copy", |e| {
        sync_of(e).is_some()
    })
    .await;
    let (device, sync) = sync_of(&got).unwrap();
    assert_eq!(device, h.laptop.user_id());
    assert!(matches!(sync, Sync::Sent { peer, .. } if peer == bob.user_id()));

    // Bob's receipt for "hi bob" reaches both of Alice's devices, naming
    // the message's id, and no device of Bob's.
    let delivery = bob_c
        .send_content(
            h.alice.user_id(),
            Some(alice_bundle),
            Content::Receipt {
                kind: ReceiptKind::Delivered,
                ids: vec![id.clone()],
            },
            seq(1, 2),
        )
        .await
        .unwrap();
    assert_eq!(delivery.copies.len(), 1);
    for (rx, who) in [(&mut h.alice_ev, "alice"), (&mut h.laptop_ev, "the laptop")] {
        let got = wait_for(rx, &format!("{who}'s receipt"), |e| receipt_of(e).is_some()).await;
        assert_eq!(receipt_of(&got).unwrap(), (bob.user_id(), vec![id.clone()]));
    }

    bob_c.shutdown().await;
    h.alice_c.shutdown().await;
    h.laptop_c.shutdown().await;
}

#[tokio::test]
async fn an_older_sender_is_passed_on_by_the_primary() {
    let (url, _state) = start_relay().await;
    let mut h = household(&url).await;
    // Carol keeps no device state: she seals to the account alone and
    // advertises no `devices`, as a client before 0.9.0 does.
    let carol = Arc::new(Identity::generate());
    let (carol_c, mut carol_ev) = Client::spawn(
        url.clone(),
        carol.clone(),
        ConnectOptions {
            sessions: Some(SessionStore::ephemeral(carol.user_id()).shared()),
            ..Default::default()
        },
    )
    .unwrap();
    connected(&mut carol_ev, "carol").await;

    let delivery = carol_c
        .send_content(
            h.alice.user_id(),
            None,
            text("from an older client"),
            seq(1, 1),
        )
        .await
        .unwrap();
    assert!(delivery.copies.is_empty(), "she knows of no devices");
    let id = delivery.envelope.id.clone();
    let got = wait_for(&mut h.alice_ev, "alice's primary gets it", |e| {
        text_of(e).is_some()
    })
    .await;
    assert_eq!(text_of(&got).unwrap().3, "from an older client");
    // The primary passes it on: the laptop hears from the primary what
    // Carol sent, under the message's id.
    let got = wait_for(&mut h.laptop_ev, "the laptop's copy", |e| {
        sync_of(e).is_some()
    })
    .await;
    let (device, sync) = sync_of(&got).unwrap();
    assert_eq!(device, h.alice.user_id());
    match sync {
        Sync::Received {
            from,
            id: copied,
            content,
            ..
        } => {
            assert_eq!(from, carol.user_id());
            assert_eq!(copied, id);
            assert_eq!(*content, text("from an older client"));
        }
        other => panic!("not a received copy: {other:?}"),
    }

    // Her receipt is hers to the primary alone: nothing is passed on.
    carol_c
        .send_content(
            h.alice.user_id(),
            Some(delivery.bundle.clone()),
            Content::Receipt {
                kind: ReceiptKind::Read,
                ids: vec![id],
            },
            seq(1, 2),
        )
        .await
        .unwrap();
    wait_for(&mut h.alice_ev, "alice's primary gets the receipt", |e| {
        receipt_of(e).is_some()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    while let Ok(ev) = h.laptop_ev.try_recv() {
        assert!(sync_of(&ev).is_none(), "a receipt was passed on: {ev:?}");
    }

    carol_c.shutdown().await;
    h.alice_c.shutdown().await;
    h.laptop_c.shutdown().await;
}

#[tokio::test]
async fn a_revoked_device_is_dropped_by_everyone() {
    let (url, state) = start_relay().await;
    let mut h = household(&url).await;
    let bob = Arc::new(Identity::generate());
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), options(&bob, None, Vec::new())).unwrap();
    connected(&mut bob_ev, "bob").await;
    let first = bob_c
        .send_content(h.alice.user_id(), None, text("one"), seq(1, 1))
        .await
        .unwrap();
    assert_eq!(first.copies.len(), 1);
    wait_for(&mut h.laptop_ev, "the laptop's copy", |e| {
        text_of(e).is_some()
    })
    .await;

    // Alice unlinks the laptop.
    let revocation = h.alice_c.revoke_device(h.laptop.user_id()).await.unwrap();
    assert!(revocation.verify().is_ok());
    assert_eq!(revocation.device, h.laptop.user_id());
    assert!(
        h.alice_c
            .devices()
            .unwrap()
            .lock()
            .unwrap()
            .siblings()
            .is_empty()
    );
    assert!(
        state
            .store()
            .is_device_revoked(&h.laptop.user_id())
            .unwrap()
    );
    // The laptop is cut off: told why, closed, and refused at its next login.
    wait_for(
        &mut h.laptop_ev,
        "the laptop refused",
        |e| matches!(e, ClientEvent::Disconnected { reason, .. } if reason.contains("revoked")),
    )
    .await;

    // Bob, with the list as he pinned it an hour ago at most, still seals a
    // copy for the laptop; the relay refuses it, Bob learns the device is
    // gone, and the message still counts as sent.
    let second = bob_c
        .send_content(
            h.alice.user_id(),
            Some(first.bundle.clone()),
            text("two"),
            seq(1, 2),
        )
        .await
        .unwrap();
    assert_eq!(second.copies.len(), 1);
    let gone = wait_for(&mut bob_ev, "bob learns the laptop is gone", |e| {
        matches!(e, ClientEvent::DeviceGone { .. })
    })
    .await;
    assert!(matches!(
        gone,
        ClientEvent::DeviceGone { account, device }
            if account == h.alice.user_id() && device == h.laptop.user_id()
    ));
    let id = second.envelope.id.clone();
    wait_for(
        &mut bob_ev,
        "bob's second message sent",
        |e| matches!(e, ClientEvent::Sent { id: i } if *i == id),
    )
    .await;
    // The list is fetched again for the next message, and comes with the
    // revocation: no copy any more.
    let third = bob_c
        .send_content(
            h.alice.user_id(),
            Some(first.bundle.clone()),
            text("three"),
            seq(1, 3),
        )
        .await
        .unwrap();
    assert!(third.copies.is_empty());
    wait_for(
        &mut bob_ev,
        "bob is told of the revocation",
        |e| matches!(e, ClientEvent::DeviceRevoked { revocation: r } if *r == revocation),
    )
    .await;
    let lookup = bob_c.lookup_full(h.alice.user_id()).await.unwrap();
    assert_eq!(lookup.device_revocations, vec![revocation]);
    assert!(lookup.device_bundles.is_empty());

    bob_c.shutdown().await;
    h.alice_c.shutdown().await;
    h.laptop_c.shutdown().await;
}

#[tokio::test]
async fn sync_is_taken_from_ones_own_devices_only() {
    let (url, _state) = start_relay().await;
    let mut h = household(&url).await;
    let bob = Arc::new(Identity::generate());
    let (bob_c, mut bob_ev) =
        Client::spawn(url.clone(), bob.clone(), options(&bob, None, Vec::new())).unwrap();
    connected(&mut bob_ev, "bob").await;

    // Bob says "read" as if he were one of Alice's devices: dropped.
    let alice_bundle = bob_c.lookup(h.alice.user_id()).await.unwrap().unwrap();
    bob_c
        .send_content_sequenced(
            &alice_bundle,
            Content::Sync(Sync::Read {
                peer: bob.user_id(),
                ids: vec!["x".into()],
            }),
            Sequence::default(),
        )
        .await
        .unwrap();
    // The laptop says the same: taken.
    let sent = h
        .laptop_c
        .send_sync(Sync::Read {
            peer: bob.user_id(),
            ids: vec!["y".into()],
        })
        .await
        .unwrap();
    assert_eq!(sent.len(), 1, "one envelope, to the primary");
    let got = wait_for(&mut h.alice_ev, "the laptop's read mark", |e| {
        sync_of(e).is_some() || matches!(e, ClientEvent::Message(_))
    })
    .await;
    let (device, sync) = sync_of(&got).expect("a sync, not a message");
    assert_eq!(device, h.laptop.user_id());
    assert!(matches!(sync, Sync::Read { ids, .. } if ids == vec!["y".to_owned()]));

    bob_c.shutdown().await;
    h.alice_c.shutdown().await;
    h.laptop_c.shutdown().await;
}
