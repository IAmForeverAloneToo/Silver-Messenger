//! What a client does when the relay, or somebody using it, works against
//! it: a lookup answer altered on the way, a revoked device still writing
//! in its account's name, an answer withheld so the client falls back on
//! what it knew, the anonymous connection taken away from a client told
//! never to do without it, an entry logged under the client's own id that
//! it did not make, a log head from a stranger, and acknowledgements for
//! chunks that were never sent.
//!
//! The relay here is the real one; what works against the client is a
//! WebSocket proxy in front of it that can rewrite, drop or repeat what
//! the relay says and can refuse the anonymous connection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use silver_client::connection::SharedContactKeys;
use silver_client::{
    Client, ClientError, ClientEvent, ConnectOptions, DeviceState, LogStore, SessionStore, Store,
    TransparencyEvent,
};
use silver_protocol::transparency::LogHead;
use silver_protocol::{
    Body, Content, DeviceCertificate, DhPublic, Identity, KeyBundle, Sequence, UserId, now_ms,
    seal_bytes,
};
use silver_relay::RelayState;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

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

/// What the proxy does to each frame the relay sends a client: the frames
/// to pass on in its place (none to drop it, several to repeat it).
type Rewrite = Arc<dyn Fn(Value) -> Vec<Value> + Send + Sync>;

/// A proxy in front of the relay. It records every frame a client sends,
/// with whether the connection it came on had logged in, and passes the
/// relay's frames through `rewrite`.
struct Proxy {
    url: String,
    /// (logged in, frame type) for every frame a client sent.
    seen: Arc<Mutex<Vec<(bool, String)>>>,
    /// While set, a connection that does not log in (the anonymous
    /// submission connection) is cut as soon as it sends anything.
    refuse_anonymous: Arc<AtomicBool>,
}

async fn proxy(upstream: String, rewrite: Rewrite) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let refuse_anonymous = Arc::new(AtomicBool::new(false));
    let (seen2, refuse2) = (seen.clone(), refuse_anonymous.clone());
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let upstream = upstream.clone();
            let rewrite = rewrite.clone();
            let seen = seen2.clone();
            let refuse = refuse2.clone();
            tokio::spawn(async move {
                let Ok(client) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let Ok((server, _)) = tokio_tungstenite::connect_async(upstream.as_str()).await
                else {
                    return;
                };
                let (mut c_tx, mut c_rx) = client.split();
                let (mut s_tx, mut s_rx) = server.split();
                let up = async move {
                    let mut logged_in = None;
                    while let Some(Ok(m)) = c_rx.next().await {
                        if let WsMessage::Text(t) = &m {
                            let v: Value = serde_json::from_str(t.as_str()).unwrap();
                            let kind = v["type"].as_str().unwrap_or_default().to_owned();
                            let authenticated = *logged_in.get_or_insert(kind == "auth");
                            if !authenticated && refuse.load(Ordering::SeqCst) {
                                return;
                            }
                            seen.lock().unwrap().push((authenticated, kind));
                        }
                        if s_tx.send(m).await.is_err() {
                            return;
                        }
                    }
                };
                let down = async move {
                    while let Some(Ok(m)) = s_rx.next().await {
                        let out = match m {
                            WsMessage::Text(t) => {
                                let v: Value = serde_json::from_str(t.as_str()).unwrap();
                                rewrite(v)
                                    .into_iter()
                                    .map(|v| WsMessage::Text(v.to_string().into()))
                                    .collect()
                            }
                            other => vec![other],
                        };
                        for m in out {
                            if c_tx.send(m).await.is_err() {
                                return;
                            }
                        }
                    }
                };
                tokio::select! { _ = up => {}, _ = down => {} }
            });
        }
    });
    Proxy {
        url: format!("ws://{addr}/ws"),
        seen,
        refuse_anonymous,
    }
}

fn pass() -> Rewrite {
    Arc::new(|v| vec![v])
}

async fn wait_for(
    rx: &mut mpsc::Receiver<ClientEvent>,
    what: &str,
    mut pred: impl FnMut(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
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

/// Every event that arrives within `within`.
async fn drain(rx: &mut mpsc::Receiver<ClientEvent>, within: Duration) -> Vec<ClientEvent> {
    let deadline = tokio::time::Instant::now() + within;
    let mut out = Vec::new();
    while let Ok(Some(ev)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        out.push(ev);
    }
    out
}

fn text_of(ev: &ClientEvent) -> Option<&str> {
    match ev {
        ClientEvent::Message(m) => match &m.content {
            Content::Text { body, .. } => Some(body.as_str()),
            _ => None,
        },
        _ => None,
    }
}

fn options(
    identity: &Identity,
    linked: Option<silver_client::Linked>,
    devices: Vec<DeviceCertificate>,
) -> ConnectOptions {
    let mut state = DeviceState::ephemeral(identity.user_id(), linked).unwrap();
    for c in devices {
        state.link(c).unwrap();
    }
    ConnectOptions {
        sessions: Some(SessionStore::ephemeral(identity.user_id()).shared()),
        devices: Some(state.shared()),
        ..Default::default()
    }
}

async fn spawn(
    url: &str,
    identity: &Arc<Identity>,
    options: ConnectOptions,
    who: &str,
) -> (Client, mpsc::Receiver<ClientEvent>) {
    let (client, mut events) = Client::spawn(url.to_owned(), identity.clone(), options).unwrap();
    wait_for(&mut events, who, |e| {
        matches!(e, ClientEvent::Connected { .. })
    })
    .await;
    (client, events)
}

/// A relay that adds a device of its own to the bundle it serves for a
/// contact gets nowhere: the answer to the key check a new session makes
/// does not verify and is not handed on to be pinned, a pin altered that
/// way is not sealed to or fanned out over, and a device bundle looked up
/// on its own is not taken for a device of somebody else's account.
#[tokio::test]
async fn a_device_added_to_a_served_bundle_reads_nothing() {
    let (real, _) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let operator = Arc::new(Identity::generate());
    let planted = Arc::new(Identity::generate());
    let armed = Arc::new(AtomicBool::new(false));
    let (victim, device, on) = (alice.user_id(), planted.user_id(), armed.clone());
    let rewrite: Rewrite = Arc::new(move |mut v: Value| {
        if on.load(Ordering::SeqCst)
            && v["type"] == "lookup_result"
            && v["user_id"] == victim.to_string()
            && v["bundle"].is_object()
        {
            let zeros = format!("{}==", "A".repeat(86));
            v["bundle"]["devices"] = serde_json::json!([{
                "account": victim.to_string(),
                "device": device.to_string(),
                "created_at_ms": 1,
                "signature": zeros,
            }]);
            v["bundle"]["devices_signature"] = serde_json::json!(zeros);
        }
        vec![v]
    });
    let hostile = proxy(real, rewrite).await;

    let (alice_c, mut alice_ev) =
        spawn(&hostile.url, &alice, options(&alice, None, vec![]), "alice").await;
    let pins: SharedContactKeys = Arc::new(Mutex::new(HashMap::<UserId, DhPublic>::new()));
    let mut bob_options = options(&bob, None, vec![]);
    bob_options.contact_keys = Some(pins.clone());
    let (bob_c, mut bob_ev) = spawn(&hostile.url, &bob, bob_options, "bob").await;
    // The operator's own account and linked device, registered like
    // anybody's.
    let certificate = operator
        .certify_device(&planted.user_id(), "x", now_ms())
        .unwrap();
    let (_operator_c, _operator_ev) = spawn(
        &hostile.url,
        &operator,
        options(&operator, None, vec![certificate.clone()]),
        "the operator's account",
    )
    .await;
    let linked = silver_client::Linked {
        account: operator.user_id(),
        certificate: planted.countersign_device(&certificate).unwrap(),
    };
    let (_planted_c, mut planted_ev) = spawn(
        &hostile.url,
        &planted,
        options(&planted, Some(linked), vec![]),
        "the operator's device",
    )
    .await;

    // An ordinary conversation; bob pins alice's verified bundle.
    let first = bob_c
        .send_content(
            alice.user_id(),
            None,
            Content::text("hello"),
            Sequence { epoch: 1, seq: 1 },
        )
        .await
        .unwrap();
    let pinned = first.bundle.clone();
    assert!(pinned.verify().is_ok());
    pins.lock()
        .unwrap()
        .insert(alice.user_id(), pinned.dh_public);
    wait_for(&mut alice_ev, "alice gets hello", |e| text_of(e).is_some()).await;

    // Alice rekeys and writes under the new key; the relay alters the
    // answer to bob's key check.
    alice.rotate_dh(now_ms());
    alice_c.republish().await.unwrap();
    alice_c.retire_sessions();
    armed.store(true, Ordering::SeqCst);
    alice_c
        .send_content(
            bob.user_id(),
            None,
            Content::text("I rekeyed"),
            Sequence { epoch: 5, seq: 1 },
        )
        .await
        .unwrap();
    let established = wait_for(&mut bob_ev, "bob's key check", |e| {
        matches!(
            e,
            ClientEvent::SessionEstablished {
                initiated_by_us: false,
                ..
            }
        )
    })
    .await;
    let ClientEvent::SessionEstablished { published, .. } = established else {
        unreachable!()
    };
    assert!(
        published.is_none(),
        "an answer that does not verify is no answer: nothing to pin"
    );

    // A pin altered the same way, as a front end that took the answer
    // would have kept it, is neither sealed to nor fanned out over.
    let mut poisoned = pinned.clone();
    poisoned.devices = vec![DeviceCertificate {
        account: alice.user_id(),
        ..certificate.clone()
    }];
    assert!(poisoned.verify().is_err());
    // And the operator's device, looked up on its own, is not kept for
    // anyone's account but the operator's.
    let _ = bob_c.lookup_full(planted.user_id()).await;
    armed.store(false, Ordering::SeqCst);
    for seq in 2..4 {
        let delivery = bob_c
            .send_content(
                alice.user_id(),
                Some(poisoned.clone()),
                Content::text("the meeting is at nine"),
                Sequence { epoch: 1, seq },
            )
            .await
            .unwrap();
        assert!(delivery.copies.is_empty(), "no copy for a planted device");
        assert!(delivery.bundle.verify().is_ok());
        assert!(delivery.bundle.devices.is_empty());
    }
    let read = drain(&mut planted_ev, Duration::from_secs(2)).await;
    assert!(
        !read.iter().any(|e| matches!(e, ClientEvent::Message(_))),
        "the operator's device read nothing"
    );
    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

/// A linked device writes as its account until the account revokes it;
/// after that what it seals in the account's name is refused, including
/// after a restart with the relay saying nothing at all. A session such a
/// device starts is checked against the key the relay publishes for the
/// device itself.
#[tokio::test]
async fn a_revoked_device_no_longer_writes_as_its_account() {
    let (real, state) = start_relay().await;
    let silent = Arc::new(AtomicBool::new(false));
    let alice = Arc::new(Identity::generate());
    let quiet = (silent.clone(), alice.user_id().to_string());
    let rewrite: Rewrite = Arc::new(move |v: Value| {
        if quiet.0.load(Ordering::SeqCst) && v["type"] == "lookup_result" && v["user_id"] == quiet.1
        {
            return Vec::new();
        }
        vec![v]
    });
    let relay = proxy(real, rewrite).await;
    let laptop = Arc::new(Identity::generate());
    let certificate = alice
        .certify_device(&laptop.user_id(), "laptop", now_ms())
        .unwrap();
    let (alice_c, _alice_ev) = spawn(
        &relay.url,
        &alice,
        options(&alice, None, vec![certificate.clone()]),
        "alice",
    )
    .await;
    let presented = laptop.countersign_device(&certificate).unwrap();
    let linked = silver_client::Linked {
        account: alice.user_id(),
        certificate: presented.clone(),
    };
    let (laptop_c, laptop_ev) = spawn(
        &relay.url,
        &laptop,
        options(&laptop, Some(linked), vec![]),
        "laptop",
    )
    .await;

    // Bob keeps his sessions on disk, as a real client does.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (bob, _) = store.load_or_create_identity().unwrap();
    let bob = Arc::new(bob);
    let bob_options = |store: &Store| ConnectOptions {
        sessions: Some(SessionStore::load(store, bob.user_id()).unwrap().shared()),
        devices: Some(
            DeviceState::ephemeral(bob.user_id(), None)
                .unwrap()
                .shared(),
        ),
        ..Default::default()
    };
    let (bob_c, mut bob_ev) = spawn(&relay.url, &bob, bob_options(&store), "bob").await;

    // The laptop writes first, starting a session as itself: the key it
    // claims is checked against the laptop's own published bundle, and the
    // message is alice's.
    laptop_c
        .send_content(
            bob.user_id(),
            None,
            Content::text("from the laptop"),
            Sequence { epoch: 1, seq: 1 },
        )
        .await
        .unwrap();
    let established = wait_for(&mut bob_ev, "the laptop's session", |e| {
        matches!(e, ClientEvent::SessionEstablished { peer, initiated_by_us: false, .. } if *peer == laptop.user_id())
    })
    .await;
    assert!(matches!(
        established,
        ClientEvent::SessionEstablished { published: Some(ref b), identity_dh: Some(dh), .. }
            if b.user_id == laptop.user_id() && b.dh_public == dh
    ));
    let got = wait_for(&mut bob_ev, "the laptop's message", |e| {
        text_of(e).is_some()
    })
    .await;
    let ClientEvent::Message(m) = got else {
        unreachable!()
    };
    assert_eq!(m.from, alice.user_id());
    assert_eq!(m.content, Content::text("from the laptop"));

    // Alice revokes the laptop; bob learns of it from his next lookup.
    let revocation = alice_c.revoke_device(laptop.user_id()).await.unwrap();
    assert!(state.store().is_device_revoked(&laptop.user_id()).unwrap());
    let lookup = bob_c.lookup_full(alice.user_id()).await.unwrap();
    assert_eq!(lookup.device_revocations, vec![revocation.clone()]);
    wait_for(
        &mut bob_ev,
        "bob is told of the revocation",
        |e| matches!(e, ClientEvent::DeviceRevoked { revocation: r } if *r == revocation),
    )
    .await;
    drop(laptop_ev);

    // Whoever holds the laptop's keys seals a plain body in alice's name
    // and hands it in on any connection.
    let thief = |n: u64| {
        let body = Body::plain(
            Content::text(format!("it's alice, new account number {n}")),
            now_ms(),
            Sequence { epoch: 99, seq: n },
        )
        .with_device(Some(presented.clone()))
        .encode()
        .unwrap();
        let bob_bundle = bob.key_bundle();
        seal_bytes(&laptop, &bob_bundle, &body).unwrap()
    };
    let mallory = Arc::new(Identity::generate());
    let (mallory_c, _mallory_ev) = spawn(
        &relay.url,
        &mallory,
        options(&mallory, None, vec![]),
        "mallory",
    )
    .await;
    mallory_c.submit_envelope(thief(1)).await.unwrap();
    let refused = wait_for(&mut bob_ev, "the revoked device's message", |e| {
        text_of(e).is_some() || matches!(e, ClientEvent::Error(m) if m.contains("revoked"))
    })
    .await;
    assert!(
        matches!(refused, ClientEvent::Error(_)),
        "not shown: {refused:?}"
    );

    // Bob restarts, and the relay now answers no lookup of alice at all:
    // the revocation he saw is remembered.
    bob_c.shutdown().await;
    drop(bob_ev);
    silent.store(true, Ordering::SeqCst);
    let (bob_c, mut bob_ev) = spawn(&relay.url, &bob, bob_options(&store), "bob again").await;
    mallory_c.submit_envelope(thief(2)).await.unwrap();
    let refused = wait_for(
        &mut bob_ev,
        "the revoked device's message after a restart",
        |e| text_of(e).is_some() || matches!(e, ClientEvent::Error(m) if m.contains("revoked")),
    )
    .await;
    assert!(
        matches!(refused, ClientEvent::Error(_)),
        "not shown: {refused:?}"
    );

    bob_c.shutdown().await;
    alice_c.shutdown().await;
    laptop_c.shutdown().await;
}

/// When the relay does not answer, the client falls back on the key it
/// knows only if the log it replayed does not say that key was replaced.
#[tokio::test]
async fn an_unanswered_lookup_does_not_fall_back_past_the_log() {
    let (real, _) = start_relay().await;
    let alice = Arc::new(Identity::generate());
    let silent = Arc::new(AtomicBool::new(false));
    let quiet = (silent.clone(), alice.user_id().to_string());
    let rewrite: Rewrite = Arc::new(move |v: Value| {
        if quiet.0.load(Ordering::SeqCst) && v["type"] == "lookup_result" && v["user_id"] == quiet.1
        {
            return Vec::new();
        }
        vec![v]
    });
    let relay = proxy(real, rewrite).await;
    let bob = Arc::new(Identity::generate());
    let carol = Arc::new(Identity::generate());
    let (alice_c, _alice_ev) =
        spawn(&relay.url, &alice, options(&alice, None, vec![]), "alice").await;
    let (_carol_c, _carol_ev) =
        spawn(&relay.url, &carol, options(&carol, None, vec![]), "carol").await;
    let mut bob_options = options(&bob, None, vec![]);
    bob_options.transparency = Some(LogStore::ephemeral().shared());
    let (bob_c, _bob_ev) = spawn(&relay.url, &bob, bob_options, "bob").await;

    let first = bob_c
        .send_content(
            alice.user_id(),
            None,
            Content::text("one"),
            Sequence { epoch: 1, seq: 1 },
        )
        .await
        .unwrap();
    let pinned: KeyBundle = first.bundle;

    // Alice replaces her key; bob's log learns of it from the next
    // answer he checks, a lookup of somebody else.
    alice.rotate_dh(now_ms());
    alice_c.republish().await.unwrap();
    bob_c.lookup(carol.user_id()).await.unwrap();

    // Now the relay stops answering for alice. With no session to carry
    // the message, bob would start one against the pinned key.
    bob_c.forget_sessions(&alice.user_id());
    silent.store(true, Ordering::SeqCst);
    let sent = bob_c
        .send_content(
            alice.user_id(),
            Some(pinned),
            Content::text("two"),
            Sequence { epoch: 1, seq: 2 },
        )
        .await;
    assert!(
        matches!(sent, Err(ClientError::Transparency(_))),
        "sealed to a key the log shows replaced: {sent:?}"
    );
    alice_c.shutdown().await;
    bob_c.shutdown().await;
}

/// With --require-anonymous nothing goes out on the logged-in connection,
/// a group sequencer frame included, however often the anonymous one is
/// taken away.
#[tokio::test]
async fn a_required_anonymous_connection_is_never_replaced() {
    let (real, _) = start_relay().await;
    let relay = proxy(real, pass()).await;
    relay.refuse_anonymous.store(true, Ordering::SeqCst);
    let alice = Arc::new(Identity::generate());
    let bob = Arc::new(Identity::generate());
    let (_alice_c, _alice_ev) =
        spawn(&relay.url, &alice, options(&alice, None, vec![]), "alice").await;
    let mut bob_options = options(&bob, None, vec![]);
    bob_options.require_anonymous = true;
    let (bob_c, _bob_ev) = spawn(&relay.url, &bob, bob_options, "bob").await;

    // A message first: the anonymous connection, if it is up by now, is
    // cut as soon as it carries it, so what follows finds it down.
    let _ = bob_c
        .send_content(
            alice.user_id(),
            None,
            Content::text("hidden"),
            Sequence { epoch: 1, seq: 1 },
        )
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let created = bob_c
        .group_create(silver_client::groups::Created {
            group: silver_protocol::group::GroupId::generate(),
            epoch: 0,
            next: [7; 32],
        })
        .await;
    assert!(created.is_err(), "nothing answered it: {created:?}");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let leaked: Vec<_> = relay
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(authenticated, kind)| {
            *authenticated && matches!(kind.as_str(), "send" | "group_create" | "group_commit")
        })
        .cloned()
        .collect();
    assert!(leaked.is_empty(), "sent as bob: {leaked:?}");
    bob_c.shutdown().await;
}

/// The key owner audits its own entries: a bundle logged under its id by
/// somebody with a copy of its identity key is reported; its own
/// publishing is not.
#[tokio::test]
async fn an_entry_under_ones_own_id_one_did_not_make_is_reported() {
    let (url, _) = start_relay().await;
    let bob = Arc::new(Identity::generate());
    let carol = Arc::new(Identity::generate());
    let (_carol_c, _carol_ev) = spawn(&url, &carol, options(&carol, None, vec![]), "carol").await;
    let mut bob_options = options(&bob, None, vec![]);
    bob_options.transparency = Some(LogStore::ephemeral().shared());
    let (bob_c, mut bob_ev) = spawn(&url, &bob, bob_options, "bob").await;
    bob_c.lookup(carol.user_id()).await.unwrap();
    let quiet = drain(&mut bob_ev, Duration::from_millis(500)).await;
    assert!(
        !quiet.iter().any(|e| matches!(
            e,
            ClientEvent::Transparency(TransparencyEvent::Lookup { .. })
        )),
        "its own publishing is not reported: {quiet:?}"
    );

    // A copy of bob's identity key, publishing a bundle of its own.
    let copy = Arc::new(Identity::from_secrets(&bob.to_secrets()));
    let (copy_c, _copy_ev) = spawn(&url, &copy, options(&copy, None, vec![]), "the copy").await;
    // The relay may have let the copy's login replace bob's; either the
    // next lookup or bob's next login replays the log to the copy's entry.
    let _ = bob_c.lookup(carol.user_id()).await;
    wait_for(&mut bob_ev, "the alarm", |e| {
        matches!(e, ClientEvent::Transparency(TransparencyEvent::Lookup { who, .. }) if *who == bob.user_id())
    })
    .await;
    copy_c.shutdown().await;
    bob_c.shutdown().await;
}

/// A log head carried in a stranger's message is not compared: anybody can
/// write, and a head that is not on the chain raises an alarm about the
/// relay. A contact's is.
#[tokio::test]
async fn only_a_contacts_log_head_is_compared() {
    let (url, _) = start_relay().await;
    let bob = Arc::new(Identity::generate());
    let mallory = Arc::new(Identity::generate());
    // Mallory first, so the log has an entry when bob logs in and he
    // replays it.
    let (mallory_c, _mallory_ev) =
        spawn(&url, &mallory, options(&mallory, None, vec![]), "mallory").await;
    let contacts: SharedContactKeys = Arc::new(Mutex::new(HashMap::new()));
    let mut bob_options = options(&bob, None, vec![]);
    bob_options.transparency = Some(LogStore::ephemeral().shared());
    bob_options.contact_keys = Some(contacts.clone());
    let (bob_c, mut bob_ev) = Client::spawn(url.clone(), bob.clone(), bob_options).unwrap();
    wait_for(&mut bob_ev, "bob synced", |e| {
        matches!(
            e,
            ClientEvent::Transparency(TransparencyEvent::Synced { .. })
        )
    })
    .await;
    let bob_bundle = mallory_c.lookup(bob.user_id()).await.unwrap().unwrap();
    let forged = |n: u64| {
        let body = Body::plain_with_caps_and_head(
            Content::text(format!("head {n}")),
            now_ms(),
            Sequence { epoch: 1, seq: n },
            &[],
            Some(LogHead {
                index: 1,
                hash: [7; 32],
            }),
        )
        .encode()
        .unwrap();
        seal_bytes(&mallory, &bob_bundle, &body).unwrap()
    };

    mallory_c.submit_envelope(forged(1)).await.unwrap();
    let mut forked = false;
    wait_for(&mut bob_ev, "the stranger's message", |e| {
        forked |= matches!(e, ClientEvent::Transparency(TransparencyEvent::Fork { .. }));
        text_of(e) == Some("head 1")
    })
    .await;
    forked |= drain(&mut bob_ev, Duration::from_millis(500))
        .await
        .iter()
        .any(|e| matches!(e, ClientEvent::Transparency(TransparencyEvent::Fork { .. })));
    assert!(!forked, "a stranger's head raised an alarm");

    contacts
        .lock()
        .unwrap()
        .insert(mallory.user_id(), mallory.dh_public());
    mallory_c.submit_envelope(forged(2)).await.unwrap();
    wait_for(&mut bob_ev, "the contact's head compared", |e| {
        matches!(e, ClientEvent::Transparency(TransparencyEvent::Fork { peer: Some(p), .. }) if *p == mallory.user_id())
    })
    .await;
    mallory_c.shutdown().await;
    bob_c.shutdown().await;
}

/// Acknowledgements for chunks that were never sent do not upset the
/// upload.
#[tokio::test]
async fn extra_chunk_acknowledgements_are_ignored() {
    let (real, _) = start_relay().await;
    let rewrite: Rewrite = Arc::new(|v: Value| {
        if v["type"] == "blob_ack" {
            vec![v.clone(), v.clone(), v]
        } else {
            vec![v]
        }
    });
    let relay = proxy(real, rewrite).await;
    let alice = Arc::new(Identity::generate());
    let (alice_c, _alice_ev) =
        spawn(&relay.url, &alice, options(&alice, None, vec![]), "alice").await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    let data: Vec<u8> = (0..600_000u32).map(|i| (i * 13 % 251) as u8).collect();
    std::fs::write(&path, &data).unwrap();
    let info = alice_c.upload_file(&path, false, None).await;
    assert!(info.is_ok(), "{info:?}");
    // The connection task is still there to answer.
    assert!(alice_c.lookup(alice.user_id()).await.is_ok());
    alice_c.shutdown().await;
}
